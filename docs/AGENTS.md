# Agent Guide — sn-patterns-mcp

You (Claude / Codex / any AI agent) have access to 25 tools that give you expert understanding of ServiceNow Discovery patterns and the ability to surgically edit them. This document tells you when to use which tool, what to expect back, and how to chain them.

## Mental model

A ServiceNow **pattern** is a structured procedure expressed in **NDL** (Network Discovery Language) that tells the MID server how to identify and inventory a CI (Configuration Item). Patterns are stored in `sa_pattern` and are composed of:

- **metadata** — name, target CI type, OS family, sys_id
- **identification sections** — steps that figure out what the target IS (e.g. "is this Apache or nginx?")
- **connection sections** — steps that find related CIs ("what databases does this app server connect to?")
- **steps** — each step runs an **operation** (a *closure* in the Java code) like `runcmd_to_var`, `parse_file`, `set_attr`, `if`, `refid` (library reference), etc.

The repo indexes 1227 real ServiceNow patterns plus a registry of 117 closure types with semantic descriptors (top-level operations plus the predicate / parse-strategy / table / variable-access blocks they nest). The tools below let you query, understand, validate, and author patterns against this knowledge base.

## Tool selection guide

| User intent | Tool | Why |
|---|---|---|
| "What does pattern X do?" | `pattern_analyze` | Step-by-step structured breakdown |
| "Find patterns about Y" / "How does discovery do Z?" | `pattern_search` | Semantic + substring search |
| "Why is pattern X failing?" / "Returns no CIs" | `pattern_debug` | Operation-aware debug plan + log queries |
| "What runs alongside pattern X?" / "What triggers it?" | `pattern_resolve` | Libraries + classifiers + pre/post + commands |
| "How do A and B differ?" | `pattern_compare` | Structural diff (two indexed patterns) |
| "Explain this NDL [paste]" | `ndl_explain` | Parses arbitrary text |
| "Create a pattern that does Z" | `pattern_create` then `pattern_validate` | Synthesis context, then verify draft |
| "Is this NDL valid?" / "Will ServiceNow accept it?" | `pattern_validate` | Local Tier-1 check |
| "Will SN accept this NDL on save?" / "Compile-test this draft" | `pattern_test_compile` | Tier-2: real PDI compile check (sandboxed) |
| "What changes will this push to PDI?" / "Diff my edit vs live" | `pattern_diff_against_live` | Pull live version + diff before push |
| "What's OID 1.3.6.1.4.1.9.9.13.1.3.1.3?" / "What's sysName?" | `oid_lookup` | Resolve dotted OID or short name → MIB + syntax + description + vendor |
| "What's in ifTable?" / "What columns does HOST-RESOURCES-MIB::hrStorageTable have?" | `oid_walk_explain` | Show the full sub-tree under any OID prefix |
| "Find OIDs about BGP session state" / "Which counter tracks interface errors?" | `oid_search` | Natural-language semantic + FTS5 search across the whole corpus |
| "Audit this pattern's SNMP usage" / "Is this pattern vendor-locked?" | `pattern_snmp_audit` | Per-step OID resolution + vendor lock-in detection |
| "Where does this pattern fit?" / "Connect the dots" / "What runs around it?" | `pattern_lineage` | Libraries (recursive) + extensions + classifiers + pre/post + variable provenance |
| "What is this pattern actually collecting?" / "What data does it touch?" | `pattern_data_sources` | Per-pattern: WMI / shell / registry / SNMP / file / HTTP enumeration with classification |
| "What data is available on a Windows server?" / "What does Win32_Service give me?" | `pattern_data_sources_lookup` | Browse the bundled data-source catalog (Windows / Linux / F5 / Cisco) |
| "Clone X and customize it" / "Add a guard before this step" / "Fix this hardcoded path" | `pattern_open_draft` → `draft_*` | Surgical-edit harness — see "Surgical-edit workflow" below |
| "What can run_wmi_query_to_var NOT do, and how do I work around it?" | `closure_capability` | Closure limitations + parameterized recipe library |

## Surgical-edit workflow (the v0.3 flagship)

When a user wants to **clone-and-customize a shipping pattern** — wrap a step in a guard, swap a hardcoded path for a variable, broaden a filter, fix a column ref, or fork a library to fix problematic steps inside it — use the draft harness. This is the single highest-volume workflow: roughly 80% of real ITOM-forum threads about pattern pain are surgical edits, not new patterns from scratch.

### Mental model

A **Draft** is a mutable AST of one pattern (or library). You open a draft, locate steps with predicates, apply edit ops by name, validate, then finalize. Draft state lives in the MCP server process — sessions die on server restart.

Drafts can have **child drafts** when you `clone_library`. The cross-draft validator walks parent → child redirect chains and flags dropped-var consumers downstream. This is the safety net for "I cleaned up the cluster library and the rest of the pattern silently broke."

### The 8 draft tools

| Tool | What it does |
|---|---|
| `pattern_open_draft` | Open an existing pattern (or library) as a mutable Draft. Returns `draft_id`. |
| `draft_locate_steps` | Find steps matching a predicate. Returns opaque locators (`draft_id` + `step_uid`). |
| `draft_apply` | Apply an edit op by name. Each op validates before mutating. |
| `draft_validate` | Tier-1 + cross-draft var-flow validation of the current state. |
| `draft_diff` | Unified textual diff: original vs current. |
| `draft_finalize` | Materialize the draft. Modes: `serialize_only` / `sandbox` / `push_live` (last is intentionally not implemented). |
| `draft_abandon` | Drop a draft and all child drafts. |
| `closure_capability` | Describe a closure: required inputs, outputs, semantics, AND the **recipe library** of tested NDL fragments addressing its known limitations. |

### Edit ops (passed to `draft_apply`)

| Op | Use it for |
|---|---|
| `clone_library` | Fork a library by sys_id; auto-generates new sys_id, sandbox-prefixes name, opens as child draft. Required when fixing problematic steps inside a shared library you can't skip. |
| `wrap_in_guard` | Wrap a step's operation in `if { condition; on_true=<orig>; on_false=nop }`. Idempotent. |
| `insert_step_before` / `insert_step_after` | Insert a step relative to a target. Prefer **recipes** over raw `ndl_fragment` — they're parameterized, tested, and tied to closure-level limitations. |
| `redirect_ref` | Change a `ref { refid = X }` step to point at Y. Used after `clone_library` to swap the parent's call site to the cloned library. |
| `modify_closure_attr` | Mutate one attribute on a step's operation tree (e.g. replace a WMI query string, broaden a filter condition, swap a parsing strategy). |
| `remove_step` | Delete a step. By default refuses if downstream steps read vars this one writes (without guards). Pass `force=true` to override after manual review. |

### Recipes (used with `insert_step_*`)

Recipes are tested NDL fragments attached to specific closures, addressing known limitations. **Use recipes — don't hand-write the NDL fragment** when one applies. Discover available recipes via `closure_capability(<closure>)`.

Currently shipping:

| Closure | Recipe | What it solves |
|---|---|---|
| `run_wmi_query_to_var` | `namespace_existence_probe` | WMI namespace existence is not validated; querying a non-existent namespace blocks for the WMI default timeout. Probe with PowerShell first. |
| `run_wmi_query_to_var` | `wmi_query_with_where_optimization` | Unbounded result sets on heavily-populated providers (Win32_Printer on a print server). Push WHERE-clause filtering into the WMI query. |
| `runcmd_to_var` | `exit_status_capture` | The closure does not expose `$?`. Append `; echo $?` and parse the trailing line. |

### Worked example — Windows MSCluster (forum thread #1)

The OOB Windows OS - Servers pattern crashes WMI on non-cluster servers because step 1 calls `Windows - General Pattern Variables`, which queries `Root\MSCluster` cold. You can't skip the library — downstream needs `isVIP`, `MSCluster_Cluster`, etc. Must clone and edit inside the clone.

```
1. pattern_open_draft("Windows OS - Servers")
   → draft_id D
2. draft_locate_steps(D, {"ref_to_refid": "<general-vars-lib-sys-id>"})
   → outer ref locator
3. closure_capability("run_wmi_query_to_var")
   → discover namespace_existence_probe recipe
4. draft_apply(D, "clone_library",
       {"source_library_sys_id": "<general-vars>", "new_name": "...(custom)"})
   → child_draft_id C, new_refid R
5. draft_locate_steps(C, {"closure_keyword": "run_wmi_query_to_var",
                          "attr_contains": ["namespace", "MSCluster"]})
   → list of MSCluster step locators
6. draft_apply(C, "insert_step_before",
       {"target": <first-locator>,
        "closure": "run_wmi_query_to_var",
        "recipe": "namespace_existence_probe",
        "params": {"namespace": "MSCluster", "out_var": "hasMSClusterNs"}})
7. for each MSCluster locator:
       draft_apply(C, "wrap_in_guard",
           {"target": <locator>,
            "condition_ndl": "is_not_empty {get_attr {\"hasMSClusterNs\"}}"})
8. draft_apply(D, "redirect_ref",
       {"target": <outer-ref-locator>, "new_refid": R})
9. draft_validate(D)
   → cross-draft var-flow check; expect ok=true
10. draft_diff(D)
   → unified diff for user review
11. draft_finalize(D, mode="serialize_only")
   → final NDL — user uploads via SN UI / sandbox
```

### Predicate fields for `draft_locate_steps`

All optional, all AND'd:

- `name_contains` / `name_equals` — match step name
- `closure_keyword` — operation keyword (e.g. `"ref"`, `"run_wmi_query_to_var"`, `"runcmd_to_var"`)
- `ref_to_refid` — for `ref` / `refid` steps targeting a specific library sys_id
- `attr_eq` — `[attr_name, exact_value]`
- `attr_contains` — `[attr_name, substring]`
- `section` — `"identification"` | `"connection"` | `"extension"` | `"library"`

### Locator stability

Locators are opaque (`draft_id` + `step_uid`). They survive content mutations (wrap, redirect, modify-attr) because UIDs are anchored to step `_Block` object identity, not content signatures. They also survive insertions of other steps (existing UIDs keep, new step gets fresh UID). They are invalidated only by `remove_step` of the same step.

You may re-locate after each edit if you want fresh data, but the same locator should still resolve unless you removed that specific step.

### When to use surgical edit vs `pattern_create`

Use `pattern_open_draft` + draft ops:
- modifying a shipping OOB pattern
- fixing a regression in a vendor pattern after a Yokohama/etc. upgrade
- forking a library and adjusting steps inside it
- adding guards / filters / row-count gates

Use `pattern_create` + `pattern_validate`:
- net-new pattern for a device/app SN doesn't ship a pattern for (Dell Unity, NetBackup, custom appliance)
- token-based REST authentication (basic-auth-only OOB classifiers won't help)

The two surfaces are complementary, not competing.

## The authoring loop (most important workflow)

This is how you draft a new pattern end-to-end. The five-step loop is the reason this MCP exists:

```
User: "Create a pattern that discovers RabbitMQ on Linux"
   ↓
1. RESEARCH: pattern_create(intent="RabbitMQ broker discovery on Linux",
                            ci_type="cmdb_ci_app_server_rabbitmq",
                            os_family="cmdb_ci_linux_server")
   → 3 nearest neighbor patterns with full NDL snippets + relevant closures
     (runcmd_to_var, parse_text_file_to_var, set_attr, ...) + a skeleton.
   ↓
2. SYNTHESIZE: You adapt the nearest neighbors to RabbitMQ's specifics
   (rabbitmqctl commands, /etc/rabbitmq/rabbitmq.conf parsing, etc.)
   ↓
3. LOCAL VALIDATE: pattern_validate(ndl=your_draft)
   → ERROR/WARN/INFO findings. Fix all ERRORs; address WARNs you can.
   Iterate steps 2-3 until no errors.
   ↓
4. PDI COMPILE TEST (optional, requires PDI + pattern_designer role):
   pattern_test_compile(ndl=your_draft)
   → ServiceNow compiles the NDL in a sandbox sa_pattern row.
     ACCEPTED or REJECTED. If REJECTED, the SN error message tells you
     the server-side issue (unknown CI type, dictionary violation, etc.) —
     fix and re-try.
   ↓
5. SHIP: Show the validated NDL to the user. They upload it via SN UI or REST.
```

`pattern_create` does NOT write NDL for you — it gives you the structured context to write NDL well. `pattern_validate` is your local safety net. `pattern_test_compile` is your server-side safety net.

### Updating an existing pattern

```
User: "Modify Apache on UNIX to also detect httpd-foreground processes"
   ↓
1. pattern_analyze("Apache on UNIX based OS")
   → Step-by-step breakdown — find the find_process_to_var step.
   ↓
2. You edit the NDL (or ask the user for their edit).
   ↓
3. pattern_validate(ndl=edit) → no errors.
   ↓
4. pattern_diff_against_live(name_or_sys_id="Apache on UNIX based OS",
                              local_ndl=edit)
   → Shows exactly what changes (added ops, removed vars, textual diff).
     User reviews this BEFORE pushing.
   ↓
5. Optional: pattern_test_compile(ndl=edit) to verify SN still accepts it.
   ↓
6. User pushes the edit via SN UI / REST.
```

### Tier-2 (PDI compile harness) — what you must know

`pattern_test_compile` and the `create_pattern`/`update_pattern`/`delete_pattern` paths in `PdiClient` enforce a **hard sandbox prefix** (`_sandbox_snmcp_`). They REFUSE to write to any pattern whose name doesn't start with this prefix. This is non-bypassable from inside the MCP — you cannot accidentally edit a real pattern via these tools.

`pattern_test_compile` automatically rewrites the user's draft to use a generated sandbox name, uploads it, observes the result, and (by default) deletes the sandbox row. The `cleanup=False` option lets the user inspect the row in the SN UI; if cleanup fails, a record lands in `~/.sn_patterns_mcp/sandbox_runs.json` so the user can clean up later.

**Permissions:** `sa_pattern` writes require the `pattern_designer` role. The first time `pattern_test_compile` hits a 403, it auto-grants the role to the configured user and retries — no manual setup needed. If the retry still fails (genuinely wrong password = 401, or admin lacks role-grant permission), the failure surfaces clearly.

## Output formats

All tools return plain text capped at 8000 characters. Truncated output ends with `... [truncated to 8000 chars]`. None raise exceptions — failures arrive as `ERROR:` prefixed responses you can read and react to.

### `pattern_analyze` output

```
Pattern: Apache HTTP Server On Unix
  sys_id: <hex>
  CI type: cmdb_ci_apache_web_server
  OS family: cmdb_ci_unix_server
  Type: HORIZONTAL

IDENTIFICATIONS: 1
  [1] Apache HTTPD identification  strategy=LISTENING_PORT
    Step 1: find httpd process — find_process_to_var
        > Find a process matching a pattern; capture pid, exe, cmdline.
        var_names = process_list
    Step 2: read main config — runcmd_to_var
        > Run a shell/SSH command, capture stdout into a variable.
        cmd = "cat /etc/httpd/conf/httpd.conf"
        var_names = conf
    ...

CONNECTIONS: 6
  ...
```

### `pattern_resolve` output (with source tags!)

```
Resolve: Apache HTTP Server On Unix  (sys_id=...)

SHARED LIBRARIES REFERENCED (3):
  - <hex>  (Apache populate web applications)
  ...

CLASSIFIERS (12)  (source: pdi):
  - Apache classifier  [discovery_classy_pattern]
  ...

PRE/POST SCRIPTS (4)  (source: local; PDI failed: PdiUnavailable: PDI auth failed (401)):
  - [pre] Set discovery hint
       script preview...
  ...
```

The `(source: ...)` tag tells you whether each section came from the live PDI, the local cache, or a heuristic fallback. **If you see "PDI failed:" in the source tag, the user's PDI credentials may be wrong or expired — surface this to the user, don't pretend the data is authoritative.**

### `pattern_search` output

```
Search: Tomcat web server on Linux  [backend: chroma-semantic]
Top 3 result(s):

- Tomcat  [cmdb_ci_app_server_tomcat]  sys_id=...  (distance=1.205)
    ops: all,any,attribute,best_match,cmdline_java_parsing,...
- Tomcat populate web applications  [cmdb_ci_appl_generic]  sys_id=...  (distance=1.145)
    ...
```

The `[backend: ...]` tag tells you whether the result came from semantic search (Chroma) or substring fallback (manifest). Lower `distance` = more similar.

### `pattern_validate` output

```
Status: VALID
Errors: 0 / Warnings: 3
Pattern: Apache HTTP Server On Unix (citype=cmdb_ci_apache_web_server)

Findings: 0 ERROR, 3 WARN, 0 INFO

WARN   var.read_before_write     Variable 'configs' is read before being written. [connection[1].step[0] 'verify virtual directories exist']
...
```

Severity levels:
- `ERROR` — pattern won't parse / will be rejected by ServiceNow. Must fix.
- `WARN` — likely runtime bug (undefined var, unresolved refid, missing metadata). Should fix.
- `INFO` — style / portability hint. Suppressed by default; pass `verbose=true` to see.

Finding codes:
- `syntax` — NDL parse error
- `roundtrip` — parser/writer disagree (rare; means a parser/writer bug, not your pattern)
- `metadata.id` / `metadata.name` / `metadata.citype` — required field missing
- `var.read_before_write` — variable read before any step writes it (most common false positive: closures we haven't yet catalogued as writers)
- `closure.unknown` — operation keyword not in the registry (analysis will be shallow but pattern still parses)
- `refid.unresolved` — `refid` step references a library sys_id not in the index
- `step.name` — step has no name (hurts log readability)
- `validator-bug` — internal crash in the validator itself; please report

### `oid_lookup` output

```
OID: 1.3.6.1.2.1.2.2.1.5
Name: IF-MIB::ifSpeed
  Syntax: Gauge32
  Access: read-only
  [COLUMNAR — instance is appended after this OID]

Description: An estimate of the interface's current bandwidth in bits per second...

Parent: IF-MIB::ifEntry  (1.3.6.1.2.1.2.2.1)

Children (1):
  ...
```

For an unknown enterprise OID, the response identifies the vendor:

```
OID: 1.3.6.1.4.1.9.999.999  (no exact match in registry)
Vendor (by enterprise prefix): Cisco Systems
  prefix: 1.3.6.1.4.1.9
  description: Cisco network devices
This is a vendor-private OID. The MIB defining it is not in the bundled corpus.
```

### `pattern_snmp_audit` output

```
SNMP audit: NetGear Switch Discovery  (sys_id=...)

SNMP operations: 6

- step 'get system name': run_snmp_to_var  oid=1.3.6.1.2.1.1.5
    → SNMPv2-MIB::sysName  (DisplayString (SIZE (0..255)))
      An administratively-assigned name for this managed node...
- step 'get interfaces': run_snmp_to_var  oid=1.3.6.1.2.1.2.2 [TABLE]
    → IF-MIB::ifTable  (SEQUENCE OF IfEntry)
      A list of interface entries...
- step 'cisco specific': run_snmp_to_var  oid=1.3.6.1.4.1.9.9.13.1.3.1.3
    → CISCO-ENVMON-MIB::ciscoEnvMonTemperatureValue  ...

VENDOR DEPENDENCIES:
  - Cisco Systems: 1 step(s)
  → This pattern is vendor-locked. It will only work against these device families.
```

When a step uses `oid = "$variable"`, audit reports `[DYNAMIC — variable substitution at runtime]`.

### `pattern_test_compile` output

```
Pattern: TomcatRabbit  (ci_type: cmdb_ci_app_server_tomcat)
Sandbox name: _sandbox_snmcp_1714242000_a3f29c

Local validation: PASSED
PDI compile: ACCEPTED  (sys_id=00112233445566778899aabbccddeeff)
Cleanup: DELETED  (sandbox sys_id=00112233445566778899aabbccddeeff removed)
```

Possible terminal states:
- `PDI compile: ACCEPTED` — ServiceNow saved the NDL. Safe to ship.
- `PDI compile: REJECTED  (HTTP 400)` followed by the error message — fix and retry.
- `PDI compile: ERROR  (PdiUnavailable: PDI auth failed (403))` — PDI user lacks `pattern_designer` role.
- `Status: LOCAL_VALIDATION_FAILED` — local Tier-1 caught it; PDI not contacted.

### `pattern_diff_against_live` output

```
Diff: live PDI version vs local draft of 'Apache on UNIX based OS'
  live  sys_id: 28d607dbfead4be3887c843814455100
  live  name:   Apache on UNIX based OS  (citype: cmdb_ci_apache_web_server)
  local name:   Apache on UNIX based OS  (citype: cmdb_ci_apache_web_server)

OPERATION KEYWORDS:
  added in local:   ['regex_parsing']
  removed in local: -

VARIABLES:
  added in local:   ['workers']
  removed in local: -

LIBRARY REFS:
  added in local:   -
  removed in local: -

STEP COUNTS:
  identifications: live=2  local=2
  connections:     live=10  local=10

TEXTUAL DIFF (live → local, first 80 lines of changes):
--- live
+++ local
@@ ...
+        step {
+            name = "find worker pool"
+            runcmd_to_var { ... }
+        }
```

If the diff says `(live and local NDL are byte-identical)`, the user's edit didn't actually change anything semantically — usually this means they edited whitespace only, or the edit reverted to baseline.

### `pattern_create` output

```
Intent: RabbitMQ broker discovery on Linux
Target CI type: cmdb_ci_app_server_rabbitmq
OS family: cmdb_ci_linux_server

=== NEAREST EXISTING PATTERNS (use as templates) ===
- ActiveMQ  [cmdb_ci_app_server_activemq] sys_id=...
    distance: 1.085
    ops: all,attribute,...
    --- NDL snippet ---
    pattern { metadata { id = "..." name = "ActiveMQ" ... } ... }
    ---

- Kafka Broker  [cmdb_ci_app_server_kafka] sys_id=...
    ...

=== RELEVANT CLOSURES ===
- runcmd_to_var (command): Run a shell/SSH command, parse stdout into a variable.
    inputs: command, parsing_strategy
    outputs: variable_name
- parse_text_file_to_var (parse): Parse a text file from the target into a variable.
    ...

=== SKELETON ===
pattern {
    metadata {
        id = "<32-char hex sys_id>"
        name = "<pattern name>"
        citype = "cmdb_ci_app_server_rabbitmq"
        apply_to_os_families = "cmdb_ci_linux_server"
    }
    identification {
        ...
    }
}

After drafting, call pattern_validate(ndl_text=...) to check.
```

### `pattern_lineage` output

```
Lineage: Apache HTTP Server On Unix  (sys_id=...)

SECTIONS:
  2 identification section(s)
  10 connection section(s)
  0 extension section(s) (built-in)

SHARED LIBRARIES REFERENCED (3):
  - <hex_id>  (Apache populate web applications)
    - <hex_id>  (parse common http.conf directives)
  - <hex_id>  (Linux process detection)
  - <hex_id>  (already shown)

EXTENSIONS TARGETING THIS PATTERN (1):
  - Apache mod_jk extension  sys_id=...

CLASSIFIERS ROUTING TO THIS PATTERN (3, source: pdi):
  - Apache HTTPD classifier  table=discovery_classy_pattern
  ...

PRE/POST SCRIPTS: 1 pre, 0 post
  Variables injected by pre-scripts: ['discovery_type', 'g_signal_state']
  pre[1]: 8 lines; sets=['discovery_type'] reads=[]

VARIABLE PROVENANCE:
  $process_list                   <- in-pattern (set_attr / runcmd_to_var / etc.)
  $conf                           <- in-pattern (set_attr / runcmd_to_var / etc.)
  $vhost_table                    <- in-pattern (set_attr / runcmd_to_var / etc.)
  $discovery_type                 <- pre-script CTX.setAttribute
  $computer_system.primaryHostname <- discovery context (always available)
  ...
```

The "VARIABLE PROVENANCE" section is the crown jewel here — it answers "where does $foo come from?" with one of: discovery context (always available) / process scope / pre-script CTX.setAttribute / in-pattern / UNKNOWN [WARN].

### `pattern_data_sources` output

```
Data sources used by: .NET Application
  ci_type: cmdb_ci_appl_dot_net

WMI queries (3):
  - step 'find process info': namespace=root\cimv2
      WQL: SELECT Name, ProcessId, CommandLine FROM Win32_Process WHERE Name='w3wp.exe'
  ...

PowerShell / shell commands (5):
  - step 'find .NET version'  [Windows PowerShell]
      cmd: "ildasm" /TEXT "<path>" | findstr /I "metadata version:"
  ...

Registry reads (2):
  - step 'get mssql aliases': HKLM\SOFTWARE\Microsoft\MSSQLServer\Client\ConnectTo  (default)

SNMP gets / walks (0):

File parses (10):
  - step 'extract wellknown urls'  [parse_xml_file_to_var]
      path: <web.config path>

HTTP / REST calls (0):

Other (3):
  - step 'put disassembler': put_file ILDisassembler (uploads MID-side file to target)
```

Each operation type is bucketed. The bracket tag in commands (`[Windows PowerShell]`, `[F5 tmsh]`, `[Cisco CLI]`, `[Linux shell]`) is heuristic but reliable for known idioms.

### `pattern_data_sources_lookup` output

```
Data sources for target=windows:  33 known data points
  - Win32_OperatingSystem  (wmi)  -> run_wmi_query_to_var
  - Win32_ComputerSystem  (wmi)  -> run_wmi_query_to_var
  - Win32_BIOS  (wmi)  -> run_wmi_query_to_var
  - Win32_Service  (wmi)  -> run_wmi_query_to_var
  ...
  - HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion  (registry)  -> find_registry_val_to_var
  - Get-ComputerInfo  (powershell)  -> runcmd_to_var
  - systeminfo  (command)  -> runcmd_to_var
  - \Processor(_Total)\% Processor Time  (perf_counter)  -> runcmd_to_var
```

Or with a query:

```
Data-source search: query='SSL certificate', target=any

- [f5] tmsh list sys file ssl-cert  via tmsh -> runcmd_to_var
    Installed SSL certificates with expiry, common name, issuer.
    typical CI: cmdb_ci_certificate

- [f5] /mgmt/tm/sys/file/ssl-cert  via rest -> http_invoke
    SSL certificates via REST.
    typical CI: cmdb_ci_certificate
```

### `oid_search` output

```
OID search: 'BGP peer hold time'
  [backend: sqlite-fts5, 5 hits]

- 1.3.6.1.4.1.40310.4.3.1.20  BGP4-MIB::bgpPeerHoldTimeConfigured [COLUMNAR]
    Time interval (in seconds) for the Hold Time configured for this BGP speaker with this peer...
- 1.3.6.1.4.1.43.45.1.5.25.177.1.1.6.1.8  HUAWEI-BGP-VPN-MIB::hwBgpPeerSessionReason [COLUMNAR]
    Bgp peer down reason including: 1: Configuration lead peer down(1) 2: Receive notification(2)...
```

The `[backend: ...]` tag tells you which engine produced the result. **Prefer SQLite-FTS5 hits** — they're keyword matches over the actual MIB definitions. Chroma fallback fires only when FTS5 returns zero hits and is suitable for descriptive natural-language queries that don't share keywords with the target OID.

## Things you should NOT do

- **Don't make up sys_ids.** They're 32-char hex strings; ask the user or use `pattern_search` to find a real one.
- **Don't try to upload real patterns via this MCP.** `pattern_test_compile` only writes to sandbox rows (name prefix `_sandbox_snmcp_`) — it cannot push to existing real patterns. To deploy a new pattern, show the user the NDL; they upload via SN UI or REST.
- **Don't trust offline-only output silently.** If `pattern_resolve` says `(source: local-heuristic)`, the classifier match is a name-substring guess, not authoritative.
- **Don't paste back the full pattern_create output to the user.** Use it; synthesize NDL; show the user the final result.
- **Don't ignore `pattern_validate` ERRORs.** They mean ServiceNow will reject the pattern at save time.
- **Don't skip `pattern_diff_against_live` before edits go upstream.** It catches "I forgot a step" and "this changes more than I expected." A 30-second diff prevents an hour of "why did discovery stop working?"
- **Don't bypass the sandbox prefix.** It exists to make destructive mistakes structurally impossible. If you find yourself wanting to edit a real pattern via this MCP, you're trying to do something the design says no to.

## Things you SHOULD do

- **Use `pattern_search` before `pattern_analyze`.** If the user says "the Apache pattern", search first to disambiguate (there are usually multiple — `Apache on UNIX based OS`, `Apache On Windows`, `Apache HTTP Server`, `Apache basic identification`, `Apache populate web applications`).
- **Chain `pattern_create` → `pattern_validate` for authoring.** Always.
- **Surface PDI/Chroma backend failures to the user.** When you see `PDI failed: ...` or `Chroma error: ...` in tool output, mention it. The user may need to wake their PDI or rebuild Chroma.
- **Use `pattern_compare` for "what changed?"** When the user has two pattern names or sys_ids and wants to know the diff.
- **Use `ndl_explain` for tutoring.** When the user pastes NDL and wants to understand it without searching the corpus.

## Cost and quality model

- `pattern_search`, `pattern_analyze`, `pattern_compare`, `ndl_explain`, `pattern_validate`, `pattern_create` — all local. Free and fast (<100ms).
- `pattern_resolve` — local-first; calls PDI for classifiers and pre/post if PDI is configured. Adds ~500ms when hitting PDI. Falls back to local-heuristic on PDI failure (clearly marked).
- `pattern_debug` — local NDL analysis + offline pre/post script lookup. Returns query templates for the user to run, not actual log results.
- `pattern_test_compile` — local validate then 1 POST + 1 DELETE to PDI. ~1-2 seconds. Self-heals first-run permission gaps.
- `pattern_diff_against_live` — 1-2 GETs from PDI. ~500ms-1s.
- `pattern_lineage` — local; recursive library walk caps at depth 3. Single-call replacement for analyze + resolve + debug for "show me everything" queries.
- `pattern_data_sources` — pure local NDL walk. Free and fast.
- `pattern_data_sources_lookup` — small in-memory catalog scan. <1ms.
- `oid_lookup`, `oid_walk_explain` — first call triggers SQLite open (~30ms one-time); subsequent calls <1ms. The OID DB is loaded lazily.
- `oid_search` — FTS5 ~6ms across 847K OIDs. Falls back to ChromaDB (~50-200ms) when FTS5 returns zero.
- `pattern_snmp_audit` — pure local NDL + OID resolution. <50ms.

There are no per-call billing concerns; the cost is your context window. Outputs cap at 8000 chars to stay manageable.

## Variables in NDL — quick reference

When reading NDL, you'll see three variable forms:

- `$var` — bare reference (e.g. `cmd = concat { "process " $pid }`)
- `${var}` — braced (disambiguates in tight contexts)
- `${var.field}` / `${var[*].field}` — table/list field access

Every variable is either a **CI attribute** of the target table (matches a column name) or a **temporary** (transient working storage). The validator's `var.read_before_write` warning catches temporaries used before they're written; CI attributes can be read at any time (they're populated by the runtime).

## Closure categories (operation kinds)

Closures are grouped by what they DO. The category enum in `sn_patterns_mcp/closures/registry.py`:

| Category | Examples | What it does |
|---|---|---|
| `command` | `runcmd_to_var`, `run_wmi_query_to_var`, `run_snmp_to_var`, `http_invoke`, `ldap_query` | Execute on the target / external service, capture output |
| `parse` | `parse_text_file_to_var`, `parse_xml_file_to_var`, `parse_var_to_var` | Parse content into structured variables |
| `parse_strategy` | `delimited_parsing`, `regex_parsing`, `xml_parsing_strategy` | Strategy nested inside a parse closure |
| `table` | `transform_table`, `filter_table`, `merge_table` | Manipulate result tables |
| `control` | `if`, `alternatives`, `terminate`, `nop` | Flow control |
| `eval` | `EVAL`, `custom_operation` | JavaScript inline |
| `variable` | `set_attr`, `get_attr` | Variable read/write |
| `match` | `match`, `match_strategy` | Regex/keyword match |
| `library` | `refid` | Reference a shared library by sys_id |
| `relationship` | `create_connection`, `credentials` | CI-to-CI relationships, credential picks |
| `http` | `http_invoke` | Outbound HTTP from MID |
| `ldap` | `ldap_query` | LDAP from MID |
| `attribute` | `attribute`, `attributes` | Attribute targeting helpers |
| `file` | `put_file`, `get_files_by_filter` | File transfer |
| `meta` | (rare meta-closures) | Pattern self-reference |

When `pattern_analyze` shows you a step, the descriptor's `category`, `inputs`, `outputs`, and `failure_modes` come from this registry. Use them when answering "what could go wrong here?"

## Index state and degraded modes

Three index states determine what tools can do:

| Index state | What's available | What's not |
|---|---|---|
| **Empty** (no `manifest.json`) | `pattern_validate`, `ndl_explain` (don't need the index) | Everything else returns "Pattern not found" |
| **Metadata-only** (offline ingest, no NDL) | + `pattern_search`, basic `pattern_resolve`, basic `pattern_debug` | `pattern_analyze` returns metadata-only; `pattern_compare` says "NDL not cached" |
| **Full** (live PDI export) | All 8 tools fully functional | — |

You can ask the user to check by reading the server's stderr log on startup — it prints e.g. `index=1227 patterns, pdi=active`. If they say "0 patterns", they need to run the export script (see README).
