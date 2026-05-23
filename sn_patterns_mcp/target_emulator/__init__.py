"""Tier-3 sidecar emulator companion to sn-patterns-mcp.

Consumes blueprints emitted by `sn_patterns_mcp.emulator.blueprint(...)`,
binds the declared listeners, serves fixture data deterministically, and
records every interaction as JSONL for downstream replay.

Phase 2 scope: SNMPv2c GET / GETNEXT only. Other protocols (WMI, HTTP, SSH)
are deferred — SNMP alone unlocks the upgrade-regression-survival story for
the broad class of SN Discovery patterns that touch network gear.

Public surface:
    from sn_patterns_mcp.target_emulator.runtime import EmulatorRuntime
    rt = EmulatorRuntime.from_blueprint(blueprint_json, recording_path=...)
    await rt.start()
    # ... drive patterns against rt.snmp_address() ...
    await rt.stop()
    interactions = rt.recording.all()

The MCP server in `server.py` exposes the runtime over stdio so AI agents
can orchestrate emulator sessions end-to-end.
"""
from sn_patterns_mcp.target_emulator.fixtures import (
    SnmpFixtureEntry,
    fixtures_from_blueprint,
    infer_default,
)
from sn_patterns_mcp.target_emulator.recording import Interaction, Recorder
from sn_patterns_mcp.target_emulator.runtime import EmulatorRuntime

__all__ = [
    "EmulatorRuntime",
    "Interaction",
    "Recorder",
    "SnmpFixtureEntry",
    "fixtures_from_blueprint",
    "infer_default",
]
