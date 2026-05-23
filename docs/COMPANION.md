# `sn-target-emulator-mcp` — the Tier-3 sandbox companion

`sn-patterns-mcp` always shipped `emulator_blueprint`, a tool that emits a deterministic JSON contract describing what a sandbox would need to bind and serve to test a ServiceNow Discovery pattern without a real target. **This document covers the companion that consumes that contract** — boots an SNMPv2c sandbox responder, serves fixture values back to the pattern, and records every interaction for regression testing.

The companion ships in the same wheel. After `pip install sn-patterns-mcp`, two new console entry points exist:

- `sn-target-emulator-mcp` — stdio MCP server an AI agent registers and drives.
- `sn-target-emulator` — standalone CLI for human debugging.

## Why a companion (not more tools in the main server)?

The Tier-3 sandbox is a *side process*: it binds UDP sockets, owns long-lived state (active sessions, recordings), and runs forever until torn down. The main `sn-patterns-mcp` server is a stateless pattern-intelligence broker. Mixing the two in one stdio MCP server hides lifecycle bugs and makes the bind-failure / port-conflict surface invisible to the agent. Two servers, one wheel: install once, register both with `claude mcp add`.

## Phase 2 scope

The companion implements SNMPv2c only — GET, GETNEXT, and the v2c exception varbinds (`noSuchObject`, `noSuchInstance`, `endOfMibView`). That alone unlocks the killer demo for ServiceNow Discovery: the **broad class of patterns that touch network gear** (Cisco, F5, NetScaler, Arista, Juniper, generic SNMP) can now be exercised against a fake target on `127.0.0.1:<port>` without ever touching real hardware.

Out of scope for Phase 2 (by intent):

- GetBulkRequest — Phase 3 may add when needed for table walks.
- SetRequest / InformRequest / Trap — sandbox is read-only by design.
- SNMPv1 / SNMPv3 — community-string v2c is the SN Discovery default.
- WMI / SSH / HTTP responders — Phase 4+ candidates. SNMP alone proves the contract and unlocks the regression-testing story.

## MCP tools

| Tool | Purpose |
|---|---|
| `emulator_serve` | Start an SNMPv2c responder from a blueprint. Returns a `session_id`. |
| `emulator_status` | Bind address, fixture count, recorded interaction count for one session. |
| `emulator_recording` | Read the in-memory recording for a session (with pagination). |
| `emulator_stop` | Tear down a session's listener. JSONL recording on disk persists. |
| `emulator_list_sessions` | List all active sessions. |

## End-to-end demo

The full chain — generate a blueprint from a pattern, start a sandbox that serves it, run pattern logic against the sandbox, read the recording — fits on one screen.

### 1. Register both servers

```bash
claude mcp add sn-patterns         sn-patterns-mcp
claude mcp add sn-target-emulator  sn-target-emulator-mcp
```

### 2. Ask Claude to drive it

> *"Generate an emulator blueprint for OID 1.3.6.1.2.1.1.5 (sysName) plus a few interface counters; spin up the sandbox; verify it answers a sysName GET; show me the recording."*

The conversation:

```
tool:  emulator_blueprint                               # sn-patterns-mcp
args:  { "oids": ["1.3.6.1.2.1.1.5", "1.3.6.1.2.1.2.2.1.10.1",
                  "1.3.6.1.2.1.2.2.1.16.1"] }
reply: { ...blueprint with fixtures.snmp = [3 entries]... }

tool:  emulator_serve                                   # sn-target-emulator-mcp
args:  { "blueprint": <the blueprint above> }
reply: { "ok": true, "session_id": "emu_a1b2c3d4",
         "bind": { "host": "127.0.0.1", "port": 50523, "protocol": "udp" },
         "fixtures": { "fixture_count": 3, ... } }
```

The agent (or you, manually) now points anything that speaks SNMPv2c at `127.0.0.1:50523` with community `public` and gets deterministic responses to GET and GETNEXT.

```
tool:  emulator_recording                               # sn-target-emulator-mcp
args:  { "session_id": "emu_a1b2c3d4" }
reply: { "total": N, "interactions": [
   { "ts": "...", "proto": "snmp",
     "request":  { "type": "GetRequest", "oids": ["1.3.6.1.2.1.1.5.0"], ... },
     "response": { "type": "Response", "varbinds": [...] } },
   ...
] }

tool:  emulator_stop
args:  { "session_id": "emu_a1b2c3d4" }
```

### 3. Standalone CLI (without an AI client)

```bash
# Step 1: get a blueprint via the parent's CLI (or by saving the MCP output)
python -c "from sn_patterns_mcp.tools import emulator_blueprint; \
           print(emulator_blueprint(oids=['1.3.6.1.2.1.1.5']))" > bp.json

# Step 2: serve  (--verbose goes AFTER the subcommand)
sn-target-emulator serve --blueprint bp.json --recording session.jsonl --verbose
# (logs bind address; Ctrl-C to stop)

# Step 3: inspect the recording after stop
sn-target-emulator inspect --recording session.jsonl
```

## Determinism contract

Every byte the responder emits is reproducible from `(blueprint, request)`. There are no timestamps, source ports, or random nonces in the SNMP response stream — the wire output for the same GET against the same blueprint is byte-identical across runs. This is the property Phase 3 (record/replay regression harness) relies on: a baseline recording from today and a fresh recording from a post-upgrade ServiceNow MID run should diff cleanly. Any non-zero diff means the pattern's behavior changed.

## Fixture value inference

When a blueprint entry has its `value` field set to the placeholder `<scenario-value>` (the default `emulator_blueprint` output for OIDs it can resolve but can't make up a value for), the runtime substitutes a deterministic stub based on the declared MIB SYNTAX:

| SYNTAX | Stub value |
|---|---|
| `DisplayString` | `"stub-display"` |
| `OCTET STRING` | `"<stub>"` |
| `Integer32` / `INTEGER` | `0` |
| `Counter32` / `Counter64` / `Gauge32` / `Unsigned32` / `TimeTicks` | `0` |
| `IpAddress` | `"0.0.0.0"` |
| `OBJECT IDENTIFIER` | `"0.0"` |

Override any of these by supplying an explicit `value` in the blueprint's `fixtures.snmp` entry. The MCP tool `emulator_serve` accepts arbitrary blueprint JSON, so you can hand-author or modify the fixtures before serving.

## Recording format

JSONL — one self-contained JSON object per line. Stable schema:

```json
{
  "ts":     "2026-05-23T19:00:00.123456+00:00",
  "proto":  "snmp",
  "client": "127.0.0.1:54321",
  "request": {
    "type":       "GetRequest" | "GetNextRequest",
    "request_id": 42,
    "community":  "public",
    "oids":       ["1.3.6.1.2.1.1.5.0"]
  },
  "response": {
    "type":         "Response",
    "request_id":   42,
    "error_status": 0,
    "error_index":  0,
    "varbinds": [
      { "oid": "1.3.6.1.2.1.1.5.0", "value_hex": "0400" }
    ]
  },
  "error": null
}
```

Phase 3 will define a replay tool that consumes this and asserts a fresh emulator session produces matching `value_hex` byte sequences. The hex representation is intentional: a diff at the wire level is the strongest possible regression signal.

## Registering with Claude Code

```jsonc
// .mcp.json
{
  "mcpServers": {
    "sn-patterns":        { "command": "sn-patterns-mcp",        "transport": "stdio" },
    "sn-target-emulator": { "command": "sn-target-emulator-mcp", "transport": "stdio" }
  }
}
```

The companion server is fully offline — no network access required beyond binding loopback UDP. It has zero ServiceNow dependencies; the only shared surface with the main project is the blueprint JSON schema.
