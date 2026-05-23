# 60-second demo — surgical edit of a shipping pattern

This is the canonical "watch sn-patterns-mcp do something real" walk-through. An AI agent (Claude / Codex / Continue / any MCP-aware client) clones a shipping Windows pattern, wraps a broken WMI call in a guard so it stops crashing non-cluster servers, validates, and shows the diff.

This document has two parts:
1. **The conversation** — the full walk-through. Requires a *hydrated pattern index* (one-time setup, ~5 min against a ServiceNow PDI; see "Enable the full corpus" in the [README](../README.md)).
2. **Headless smoke test** — works zero-config on a fresh `pip install sn-patterns-mcp` against the bundled example NDL. Use this if you don't have a PDI yet.

## Why this scenario matters

The OOB *Windows OS - Servers* pattern calls `Windows - General Pattern Variables` on every Windows server it discovers. That library queries `Root\MSCluster` cold. On a non-cluster server, the namespace doesn't exist, so the WMI call blocks until the timeout fires. Discovery stalls; nothing in the SN UI tells you why.

You can't just skip the library — downstream consumers in the parent pattern need `isVIP`, `MSCluster_Cluster`, and friends. The fix is to **fork the library, probe for the namespace, guard the MSCluster reads, and redirect the parent's call site at the fork**. That sequence is the surgical-edit harness.

## Setup

```bash
pip install sn-patterns-mcp
claude mcp add sn-patterns sn-patterns-mcp
```

Then open Claude Code (or any MCP-aware client) and ask:

> *"Open the OOB Windows OS - Servers pattern and add a namespace-existence guard around the MSCluster WMI calls inside the general-variables library it depends on. Show me the diff before anything goes upstream."*

What follows is the tool sequence the agent runs, and what comes back. Each block is one MCP tool call written in the exact argument shape the server expects. (Reply blocks are abbreviated to the load-bearing keys; real responses include more metadata.)

## The conversation

### 1. Locate the parent pattern and the library it depends on

```
tool:  pattern_resolve
args:  { "name": "Windows OS - Servers" }
```

The response lists the libraries referenced by the pattern, classifiers routing to it, and pre/post scripts that wrap it. The agent picks out the sys_id of `Windows - General Pattern Variables` — the library it needs to fork.

### 2. Open the parent pattern as a mutable draft

```
tool:  pattern_open_draft
args:  { "name_or_sys_id": "Windows OS - Servers" }
reply: { "draft_id": "d_abc…", "source_sys_id": "…", "name": "Windows OS - Servers",
         "is_library": false, "step_count": 27 }
```

`d_abc…` is the parent draft id. The original `sa_pattern` row is untouched.

### 3. Discover the recipe library for the broken closure

```
tool:  closure_capability
args:  { "closure_keyword": "run_wmi_query_to_var" }
reply: {
  "closure": "run_wmi_query_to_var",
  "known":   true,
  "registry": { "class_name": "…", "category": "command", "summary": "…",
                "inputs": [...], "outputs": [...], "failure_modes": [...] },
  "recipes": [
    { "name": "namespace_existence_probe",
      "purpose": "Probe a WMI namespace before querying it",
      "addresses_limitation": "WMI namespace existence is not validated …",
      "parameters": { "namespace": "...", "out_var": "..." },
      "requires_vars": [...], "declares_vars": [...] },
    { "name": "wmi_query_with_where_optimization", "addresses_limitation": "…" }
  ]
}
```

The recipe is a **tested, parameterized NDL fragment** attached to the closure that documents the limitation. The agent is going to insert it before each MSCluster step.

### 4. Find the ref step in the parent that targets the general-vars library

```
tool:  draft_locate_steps
args:  { "draft_id": "d_abc…", "predicate": { "ref_to_refid": "<general-vars sys_id>" } }
reply: { "draft_id": "d_abc…",
         "matches": [ { "locator": { "draft_id": "d_abc…", "step_uid": 8123… },
                        "name": "load general variables",
                        "operation": "ref" } ] }
```

### 5. Clone the library — get a child draft

```
tool:  draft_apply
args:  {
  "draft_id": "d_abc…",
  "op_name":  "clone_library",
  "params": {
    "source_library_sys_id": "<general-vars sys_id>",
    "new_name": "Windows - General Pattern Variables (mscluster-guarded)"
  }
}
reply: { "ok": true, "op_name": "clone_library", "issues": [], "new_locators": {},
         "extra": { "child_draft_id": "d_xyz…",
                    "new_refid":      "abcd1234…",
                    "new_name":       "_sandbox_snmcp_Windows - General Pattern Variables (mscluster-guarded)" } }
```

The child draft id and the new refid live under `extra`. The cloned library has a fresh 32-char hex sys_id and the mandatory `_sandbox_snmcp_` name prefix — it can never collide with the OOB library.

### 6. Locate every MSCluster WMI step inside the clone

```
tool:  draft_locate_steps
args:  {
  "draft_id":  "d_xyz…",
  "predicate": {
    "closure_keyword": "run_wmi_query_to_var",
    "attr_contains":   ["namespace", "MSCluster"]
  }
}
reply: { "draft_id": "d_xyz…", "matches": [ … 4 entries … ] }
```

### 7. Insert the namespace-existence probe before the first MSCluster step

```
tool:  draft_apply
args:  {
  "draft_id": "d_xyz…",
  "op_name":  "insert_step_before",
  "params": {
    "target":  <first MSCluster locator from step 6>,
    "closure": "run_wmi_query_to_var",
    "recipe":  "namespace_existence_probe",
    "params":  { "namespace": "MSCluster", "out_var": "hasMSClusterNs" }
  }
}
```

### 8. Wrap each MSCluster step in a guard on `$hasMSClusterNs`

```
tool:  draft_apply  (× 4, one per locator from step 6)
args:  {
  "draft_id": "d_xyz…",
  "op_name":  "wrap_in_guard",
  "params": {
    "target":        <locator>,
    "condition_ndl": "is_not_empty {get_attr {\"hasMSClusterNs\"}}"
  }
}
```

### 9. Redirect the parent's call site at the cloned library

```
tool:  draft_apply
args:  {
  "draft_id": "d_abc…",
  "op_name":  "redirect_ref",
  "params": { "target": <parent ref locator from step 4>, "new_refid": "abcd1234…" }
}
```

### 10. Validate the parent → child tree

```
tool:  draft_validate
args:  { "draft_id": "d_abc…" }
reply: { "draft_id": "d_abc…", "ok": true, "error_count": 0, "warning_count": 0, "issues": [] }
```

This is the cross-draft var-flow walker. If the clone no longer writes a var the parent still reads (unguarded), it surfaces as an ERROR in `issues`. Zero errors = the fork is safe.

### 11. Diff for human review

```
tool:  draft_diff
args:  { "draft_id": "d_abc…" }
reply: <unified-diff text>
--- Windows OS - Servers (original)
+++ Windows OS - Servers (draft d_abc…)
@@ … one new probe step, four wrapped steps, one redirected ref @@
```

The reply is a plain unified-diff text (not JSON). If the draft is unchanged, the server returns `(no changes in draft d_abc…)` instead. The user reads the diff. If they like it, the agent calls:

```
tool:  draft_finalize
args:  { "draft_id": "d_abc…", "mode": "serialize_only" }
reply: <final NDL text>
```

— and shows the final NDL. The user uploads it via the ServiceNow UI or REST. The OOB pattern is never overwritten.

## What just happened

In eleven tool calls, the agent:

1. Opened a shipping OOB pattern as a mutable AST without touching the live `sa_pattern` row.
2. Forked a problematic shared library, automatically getting a new sys_id and a sandbox-prefixed name.
3. Looked up a closure's known limitations and applied a tested, parameterized recipe.
4. Performed four AST-level edit ops (`clone_library`, `insert_step_before`, `wrap_in_guard` × 4, `redirect_ref`) with object-identity-anchored locators that survive content mutations.
5. Validated the whole parent → child tree with a cross-draft var-flow walker that catches "I dropped a var the parent still reads."
6. Got a unified diff for human review before anything ships.

Total context consumed: a few thousand tokens. No raw 22 KB pattern NDL was ever held in the agent's context window — every edit was an AST op chosen by name and validated by the tool.

## Headless smoke test (no MCP client, no PDI, no hydrated corpus)

Works on a fresh `pip install sn-patterns-mcp` — proves the entire pipeline is wired up:

```python
import importlib.resources as pkg
import json
import tempfile
import os

from sn_patterns_mcp.pattern_index import PatternIndex
from sn_patterns_mcp.drafts.store import DRAFTS
from sn_patterns_mcp.drafts import mcp_tools as dt
from sn_patterns_mcp import tools

# Build an empty index (mirrors what a bare PyPI install gets)
with tempfile.TemporaryDirectory() as tmp:
    os.makedirs(os.path.join(tmp, "patterns"), exist_ok=True)
    with open(os.path.join(tmp, "manifest.json"), "w") as f:
        json.dump({}, f)
    INDEX = PatternIndex.load(tmp)
    DRAFTS.index = INDEX  # type: ignore[attr-defined]
    DRAFTS.pdi = None     # type: ignore[attr-defined]

    # Ingest the bundled example NDL into the session
    ndl = (pkg.files("sn_patterns_mcp.examples") / "apache_on_unix.ndl").read_text()
    ingest = json.loads(tools.pattern_ingest_ndl(
        name="Apache on Unix (fixture)", ndl=ndl, index=INDEX,
    ))
    print("ingested:", ingest["name"], "ops:", ingest["operation_count"])

    # Analyze it — corpus tools work on the ingested pattern
    print(tools.pattern_analyze("Apache on Unix (fixture)", index=INDEX, pdi=None)[:200])

    # Open as a draft — surgical-edit harness is live
    opened = json.loads(dt.pattern_open_draft(
        "Apache on Unix (fixture)", store=DRAFTS, index=INDEX, pdi=None,
    ))
    print("opened draft:", opened["draft_id"], "steps:", opened["step_count"])

    # Validate the draft
    val = json.loads(dt.draft_validate(opened["draft_id"], store=DRAFTS))
    print("validates clean:", val.get("ok"))
```

Expected: four success lines (`ingested`, an analyzer header, `opened draft`, `validates clean: True`). If all four print, the install is sound and the agent harness is ready to drive.

## Recording this as a GIF / video

For a 60-second asciinema:

```bash
asciinema rec sn-patterns-mcp-demo.cast
# inside the recorded shell, run Claude Code with the prompt from "The conversation"
asciinema upload sn-patterns-mcp-demo.cast
```

For a GIF (using [vhs](https://github.com/charmbracelet/vhs)):

```text
# demo.tape
Set FontSize 14
Set Width 1280
Set Height 720
Type 'claude' Enter
Sleep 1s
Type 'Open the OOB Windows OS - Servers pattern and add a namespace-existence guard around the MSCluster WMI calls inside the general-variables library it depends on. Show me the diff.' Enter
Sleep 30s
Output demo.gif
```

```bash
vhs demo.tape
```

The output GIF belongs at the top of the README.
