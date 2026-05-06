# sn-patterns-mcp

> Pattern-intelligence MCP server for ServiceNow Discovery. Gives any AI agent the ability to read, search, validate, author, surgically edit, and reason about ServiceNow Discovery patterns — including the NDL grammar, 117 cataloged operation closures, the SNMP OIDs they touch, the WMI / shell / registry / REST data sources they ingest, the libraries / extensions / pre-post scripts that surround them, and Tier-3 sidecar emulator blueprints for behavioral testing without real targets.

[![tests](https://img.shields.io/badge/tests-251%2F251-green)]()
[![ruff](https://img.shields.io/badge/lint-ruff%20clean-green)]()
[![python](https://img.shields.io/badge/python-3.10%2B-blue)]()
[![license](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

## What it does

ServiceNow Discovery patterns are procedural definitions written in **NDL** (Network Discovery Language) that tell the MID Server how to identify, classify, and inventory configuration items (CIs). This project gives AI agents a comprehensive understanding of those patterns through 28 stdio MCP tools:

- **Read & explain** — step-by-step breakdown of any pattern, with operation-level semantics, inline OID resolution for SNMP steps, and source-tagged data (PDI live vs local index).
- **Search** — semantic search across the pattern corpus by intent ("Tomcat on Linux") and across the 847K-OID MIB knowledge base by keyword or natural language.
- **Validate** — Tier-1 local checks (syntax, parser/writer roundtrip, metadata, refids, closure required-inputs, variable read-before-write with discovery-context awareness) and Tier-2 PDI compile testing in a sandboxed `sa_pattern` row with self-healing role grants.
- **Plan target emulation** — Tier-3 sidecar emulator catalog and pattern-specific blueprints: exact TCP/UDP listeners, WMI / command / registry / SNMP / file / HTTP / LDAP fixtures, and MIB-backed OID responses for Windows, Unix/Linux, F5, NetScaler, Cisco, ESXi, and generic SNMP devices.
- **Author** — research nearest-neighbor patterns + relevant closures + a skeleton, draft NDL, validate locally, compile-test against PDI, then push.
- **Surgically edit shipping patterns** — open any pattern as a mutable Draft, locate steps via predicates, apply AST-level edit ops (clone library, wrap-in-guard, redirect ref, modify closure attribute, insert recipe, remove step), and the cross-draft validator catches dropped-var consumers before you push. Designed for the most common real workflow: clone-and-customize an OOB pattern (e.g. Windows Server with an unguarded MSCluster WMI step) without breaking downstream readers.
- **Trace lineage** — full dependency graph: shared libraries (recursive), extensions, classifiers routing to the pattern, pre/post scripts and the variables they inject, and provenance of every variable the pattern reads.
- **Inventory data sources** — for any pattern, list every WMI class, shell command, registry key, SNMP OID, file path, or HTTP endpoint it touches, classified by target (Windows / Linux / F5 / Cisco) and cross-referenced against a 90-entry catalog showing which closure ingests each and what CMDB attribute it typically populates.

## Quick start

```bash
git clone https://github.com/hans6883/sn-patterns-mcp.git
cd sn-patterns-mcp
python -m venv .venv
.venv/Scripts/activate     # Windows; or `source .venv/bin/activate`
pip install -e .[dev]
pytest -q                   # 251/251 should pass
```

The 28 tools work immediately against bundled fixtures. To enable the full corpus:

```bash
# 1. (Optional) Build the OID/MIB knowledge base — ~15 min the first time
python scripts/build_oid_index.py

# 2. (Optional) Hydrate the pattern index from your ServiceNow instance
export SN_INSTANCE=https://your-instance.service-now.com
export SN_USERNAME=admin
export SN_PASSWORD=...
python scripts/export_patterns.py --limit 2000 --populate-chroma
```

Without step 1, the four OID tools (`oid_lookup`, `oid_walk_explain`, `oid_search`, `pattern_snmp_audit`) operate against a small bundled seed set instead of the full 847K-OID corpus. Without step 2, pattern search and analysis run against fixtures only.

## Tools

| Tool | What it does | Use when |
|------|---|---|
| `pattern_analyze` | Step-by-step breakdown with operation-level detail. | User names a known pattern. |
| `pattern_resolve` | Shared libs + classifiers + pre/post scripts + commands. | User asks "what runs alongside X?" |
| `pattern_debug` | Operation-aware debug plan with log queries. | User reports a failing pattern. |
| `pattern_search` | Semantic + substring search over the corpus. | User describes intent, not name. |
| `ndl_explain` | Parse arbitrary NDL paste and explain. | User pastes NDL inline. |
| `pattern_compare` | Structural diff of two patterns. | User asks "how do A and B differ?" |
| `pattern_validate` | Local Tier-1 validation of NDL text. | After drafting NDL, before upload. |
| `pattern_create` | Synthesis context (neighbors + closures + skeleton). | User asks to *create* a pattern. |
| `pattern_test_compile` | Tier-2: upload to sandbox `sa_pattern`, observe SN accept/reject, cleanup. | After local validation passes. |
| `pattern_diff_against_live` | Fetch live PDI version, structural + textual diff against local draft. | Before pushing edits. |
| `oid_lookup` | Resolve any SNMP OID (dotted or by name) — name, MIB, syntax, description, vendor. | Reading SNMP discovery patterns. |
| `oid_walk_explain` | Show structure under an OID prefix (table columns, group leaves) + iteration hint. | Understanding what an SNMP walk returns. |
| `oid_search` | Natural-language search across the full corpus (FTS5 primary, ChromaDB fallback). | "Find OIDs about BGP session state". |
| `pattern_snmp_audit` | For each `run_snmp_*` step, resolve OID → MIB → vendor; flag unresolved + vendor-lock. | Reviewing or porting an SNMP pattern. |
| `pattern_lineage` | Full dependency graph: libraries, extensions, classifiers, pre/post, variable provenance. | "Where does this pattern fit?" |
| `pattern_data_sources` | Per-pattern: WMI / shell / registry / SNMP / file / HTTP enumeration. | "What is this pattern actually collecting?" |
| `pattern_data_sources_lookup` | Browse data-source catalog: Windows WMI, Linux, F5 tmsh, Cisco show. | "What data is on a Windows server?" |
| `emulator_catalog` | Browse target-emulator profiles with exact protocols and ports. | "What systems can the sidecar emulate?" |
| `emulator_blueprint` | Generate a sidecar emulator contract for a target, pattern, raw NDL, or OID list. | Before Tier-3 behavioral testing. |
| `pattern_open_draft` | Open a pattern (or library) as a mutable Draft with stable step locators. | Starting any clone-and-customize workflow. |
| `draft_locate_steps` | Find steps by predicate (name / closure / refid / attr). | Before applying an edit op. |
| `draft_apply` | Apply an edit op: `clone_library`, `wrap_in_guard`, `insert_step_before`/`_after`, `redirect_ref`, `modify_closure_attr`, `remove_step`. | Mutating the draft. |
| `draft_validate` | Tier-1 + cross-draft var-flow validation (parent reads vs cloned-child exports). | After every significant edit. |
| `draft_diff` | Unified textual diff: original vs current draft. | Reviewing before finalize. |
| `draft_finalize` | Materialize: `serialize_only` / `sandbox` / `push_live`. | Done editing. |
| `draft_abandon` | Drop a draft and its child drafts. | Starting over / cleanup. |
| `closure_capability` | Per-closure: signature + recipes addressing known limitations (e.g. `run_wmi_query_to_var.namespace_existence_probe`). | Discovering how to work around closure-level gaps. |
| `pattern_ingest_ndl` | Add a pattern (or library) to the in-memory index for this session, flagged `not_authoritative=true`. | User pastes a community / forum / decommissioned-pattern NDL the indexed corpus doesn't have. |

All tools return plain text capped at 8000 chars and never raise — failures arrive as `ERROR:` prefixed responses with the reason.

`pattern_analyze` automatically inline-resolves SNMP OIDs in `run_snmp_*` steps, so you see `1.3.6.1.2.1.1.5 → SNMPv2-MIB::sysName` next to the step without calling `oid_lookup` separately.

> **For AI agents using these tools:** start with [docs/AGENTS.md](docs/AGENTS.md) — it tells you when to call which tool, when to use the surgical-edit harness vs from-scratch authoring, and what to expect back.

## Register with an MCP-aware client

Add to `.mcp.json` (project-local) or `~/.mcp.json` (global):

```json
{
  "mcpServers": {
    "sn-patterns": {
      "command": "python",
      "args": ["-m", "sn_patterns_mcp.server"],
      "transport": "stdio",
      "env": {
        "SN_PATTERNS_INDEX_ROOT": "/abs/path/to/sn-patterns-mcp/sn_patterns_mcp/pattern_index",
        "SN_PATTERNS_CHROMA_DIR": "/abs/path/to/.sn_patterns_mcp/chroma",
        "SN_INSTANCE": "https://your-instance.service-now.com",
        "SN_USERNAME": "admin",
        "SN_PASSWORD": "your-pdi-password",
        "SN_PATTERNS_LOG_LEVEL": "INFO"
      }
    }
  }
}
```

PDI credentials are optional — the server runs offline (no Tier-2 PDI compile / live diff) without them. Logs go to stderr; never to stdout (which would corrupt the MCP JSON-RPC protocol).

## Direct Python usage (no MCP)

```python
from sn_patterns_mcp.pattern_index import PatternIndex
from sn_patterns_mcp.tools import pattern_analyze, pattern_search, pattern_validate

INDEX = PatternIndex.load("/abs/path/to/sn_patterns_mcp/pattern_index")

print(pattern_analyze("Apache HTTP Server On Unix", index=INDEX, pdi=None))
print(pattern_search("Tomcat on Linux", index=INDEX, chroma=None))
print(pattern_validate(my_ndl_string))
```

## Architecture

```
sn_patterns_mcp/
├── ndl_parser.py            Recursive-descent NDL parser
├── ndl_writer.py            NDL serializer (canonical block layout)
├── pattern_model.py         Dataclasses: Pattern, Step, Operation, Identification, ...
├── closures/
│   ├── registry.py          117 ClosureDescriptors with semantics, inputs, outputs
│   └── recipes/             Per-closure tested NDL fragments addressing known limitations
├── validator.py             Tier-1 validation (syntax, roundtrip, refids, var ordering)
├── prepost.py               Pre/post script analyzer (CTX.setAttribute extraction)
├── pattern_index.py         On-disk JSON cache + manifest with semantic facets
├── chroma_index.py          ChromaDB sn_patterns_structured collection wrapper
├── pdi_client.py            ServiceNow REST client (with sysparm_query injection guard)
├── local_data.py            Offline auxiliary data (prepost / classifiers / extensions)
├── data_sources/            Catalog of data points per target (Windows / Linux / F5 / Cisco)
├── oids/                    SQLite-backed OID/MIB knowledge base + Chroma semantic index
├── drafts/
│   ├── store.py             Draft + DraftStore (in-memory, parent/child relationships)
│   ├── locator.py           StepLocator + StepPredicate (object-identity-anchored)
│   ├── ops/                 7 edit ops (clone_library, wrap_in_guard, redirect_ref, ...)
│   ├── validator.py         Cross-draft var-flow validator
│   └── mcp_tools.py         JSON-returning MCP tool wrappers for the harness
├── tools.py                 Read/search/analyze/validate MCP tool implementations
└── server.py                stdio MCP server entry point + tool descriptions
```

### Three-tier testing strategy

This project tests patterns at three tiers because pattern testing without real targets is the actual problem:

| Tier | What it validates | Implementation |
|------|---|---|
| **Tier 1** | Syntax, parser/writer agreement, refids, var ordering, metadata, required closure inputs. **Zero PDI dependency.** | `validator.py` → `pattern_validate` tool |
| **Tier 2** | ServiceNow accepts the NDL on save (server-side semantic checks, dictionary validation). **No execution.** | `pattern_test_compile` tool — uploads to a sandbox `sa_pattern` row (name prefix `_sandbox_snmcp_`), observes accept/reject, cleans up |
| **Tier 3** | Pattern logic against synthetic device responses. | `emulator_catalog` + `emulator_blueprint` define the sidecar/helper MCP contract: target profile, exact ports, protocol fixtures, MIB-backed OID responses, strict deterministic behavior |

`pattern_test_compile` self-heals first-run permission gaps (auto-grants the role required for `sa_pattern` writes and retries on 403) so it works out of the box.

### Sidecar target emulator option

Tier 3 is modeled as a separate helper MCP, not as hidden logic inside this server. This server now owns the catalog and contract:

- `emulator_catalog` lists emulatable target profiles and their protocol surfaces: Windows, Linux/Unix, F5 BIG-IP, Citrix ADC/NetScaler, Cisco IOS/NX-OS, VMware ESXi, and generic SNMP.
- `emulator_blueprint` turns a pattern, raw NDL, explicit target, or OID list into a deterministic test contract: exact TCP/UDP listeners, fixture obligations, OID/MIB resolution, and strict behavior rules.
- The sidecar MCP's single job is to bind those listeners, serve those fixtures, and record interactions. It should not author patterns, write to ServiceNow, or guess pass/fail from incomplete data.

Example:

```python
from sn_patterns_mcp.tools import emulator_blueprint

print(emulator_blueprint(target="netscaler", oids=["1.3.6.1.4.1.5951.1"]))
```

### Surgical-edit harness (the v0.3 flagship)

The `drafts/` subsystem is the answer to "I want to clone-and-customize a shipping pattern" — the highest-volume real workflow. Sessions follow a fixed shape: open a draft, locate steps with a predicate, apply named edit ops, validate, diff, finalize.

Architectural commitments:
- **AST-level edit ops, not NDL regeneration.** The LLM picks an op (`wrap_in_guard`, `redirect_ref`, etc.) by name and parameter; the tool guarantees correctness over the parsed `_Block` tree. The agent never holds the raw NDL after-state in its context, eliminating the failure mode where an LLM "rewrites" a 22 KB pattern and silently corrupts a step it didn't mean to touch.
- **Object-identity-anchored locators.** `step_uid → id(_Block)`. Locators survive content mutations (wrap, redirect, modify-attr) and step insertions; only `remove_step` invalidates a UID for that specific step.
- **Closure capability matrix + recipe library.** When a closure has a known limitation (`run_wmi_query_to_var` doesn't validate WMI namespace existence; `runcmd_to_var` doesn't expose `$?`), the workaround lives as a parameterized, tested NDL fragment attached to the closure. Recipes are closure-level, not thread-level — a `namespace_existence_probe` recipe handles MSCluster, virtualization\v2, and any other WMI namespace gap with the same template.
- **Cross-draft var-flow validation.** When `clone_library` produces a child draft and `redirect_ref` swaps the parent's call site, the validator walks parent reads against child exports and flags any var the cloned library no longer writes that the parent still reads — ERROR if unguarded, WARN if behind `is_not_empty`.

See [docs/AGENTS.md](docs/AGENTS.md) for the complete tool surface, predicate fields, and a worked example (Windows MSCluster fix from forum thread #1).

### OID / MIB knowledge base

`sn_patterns_mcp/oids/` is a SQLite-backed OID/MIB index with 847K+ entries across 6,800+ MIBs. Cold start <50ms, sub-millisecond indexed lookups, FTS5 keyword search across name + description, ChromaDB semantic fallback for natural-language queries.

The harvester (`scripts/build_oid_index.py`) pulls MIB definitions from seven public GitHub repositories and resolves their cross-references locally. Build locally:

```bash
python scripts/build_oid_index.py                   # full multi-source build (~15 min)
python scripts/build_oid_index.py --sources librenms # one source only
python scripts/build_oid_index.py --max-files 500   # smoke test
python scripts/build_oid_index.py --refresh         # ignore cache
```

> **License note for the OID build:** the harvester pulls MIB definitions from seven public GitHub repositories, each with its own license (Apache 2.0, MIT, BSD, or unspecified). When you run the harvester, files land in your local cache (`~/.sn_patterns_mcp/mib_cache/`) and you become subject to each upstream license. This project does not redistribute any MIB content — the cache and the resulting `oids.db` are gitignored.

At runtime the loader orders authoritative IETF MIBs (`SNMPv2-MIB`, `IF-MIB`, `HOST-RESOURCES-MIB`, etc.) before vendor MIBs and applies first-write-wins on OID conflicts. Cross-authority children are filtered at `walk()` time so the standard tree returns clean results.

## Verification

```bash
pytest -q                                     # 251/251
python scripts/export_patterns.py --limit 5   # smoke test PDI fetch
python -m sn_patterns_mcp.server               # stdio server boots; ^C to exit
```

Quick health check:

```python
from sn_patterns_mcp.pattern_index import PatternIndex
from sn_patterns_mcp.validator import PatternValidator
import json

index = PatternIndex.load("sn_patterns_mcp/pattern_index")
print(f"{index.size()} patterns")

sys_id = next(iter(index.manifest))
src = json.loads((index.root / "patterns" / f"{sys_id}.json").read_text())["source_ndl"]
result = PatternValidator().validate(src)
assert result.is_valid
```

## License

[MIT](LICENSE) — see also [CONTRIBUTING.md](CONTRIBUTING.md).

ServiceNow, the ServiceNow logo, and "ServiceNow Discovery" are trademarks of ServiceNow, Inc. This project is not affiliated with or endorsed by ServiceNow.
