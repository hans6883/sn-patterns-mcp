"""MCP stdio server for the Tier-3 target emulator companion.

CRITICAL: stdout is reserved for MCP JSON-RPC. All logging must go to stderr.

Environment variables:
    SN_TARGET_EMU_LOG_LEVEL  Override stderr log level (default INFO)
    SN_TARGET_EMU_DEBUG      Set to 1 to include tracebacks in tool output

Exposed tools (Phase 2):
    emulator_serve         — start an SNMPv2c responder from a blueprint
    emulator_status        — current session info (bind addr, fixture count, recording size)
    emulator_recording     — read the in-memory recording for a session
    emulator_stop          — tear down a session
    emulator_list_sessions — list all active sessions

The emulator is single-process and holds its sessions in memory for the
lifetime of this server. The recording also writes to a JSONL file path
supplied at serve time; Phase 3 (record/replay regression harness) consumes
those files to diff a new run against a stored baseline.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import secrets
import sys
import traceback
from pathlib import Path
from typing import Any

from sn_patterns_mcp.target_emulator.replay import (
    diff_files,
)
from sn_patterns_mcp.target_emulator.replay import (
    replay_against_session as _replay_against_session_func,
)
from sn_patterns_mcp.target_emulator.runtime import (
    DEFAULT_BIND_HOST,
    EmulatorRuntime,
)

log = logging.getLogger(__name__)

MAX_OUTPUT_CHARS = 8000


def configure_logging() -> None:
    level_name = os.environ.get("SN_TARGET_EMU_LOG_LEVEL", "INFO").upper()
    level = getattr(logging, level_name, logging.INFO)
    handler = logging.StreamHandler(stream=sys.stderr)
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)-7s %(name)s: %(message)s"))
    root = logging.getLogger()
    root.setLevel(level)
    root.handlers = [handler]


# ---------------------------------------------------------------------------
# Tool descriptions — written for AI-agent consumption.
# ---------------------------------------------------------------------------

TOOL_DESCRIPTIONS = {
    "emulator_serve": (
        "Start an SNMPv2c sandbox responder that serves the fixtures declared in a blueprint. "
        "Inputs: blueprint (required — JSON object from sn-patterns-mcp's emulator_blueprint tool, "
        "OR an object with fixtures.snmp = [{oid, syntax, value?}, ...]), "
        "community (default 'public'), bind_host (default 127.0.0.1), bind_port (default 0 = "
        "OS-assigned), recording_path (optional file path for JSONL persistence). "
        "Returns: session_id (use with every other emulator_* tool), bind address, fixture summary."
    ),
    "emulator_status": (
        "Report the current state of one emulator session: bind address, fixture count, recorded "
        "interaction count. Inputs: session_id (required)."
    ),
    "emulator_recording": (
        "Read back the recorded interactions for a session. Inputs: session_id (required), "
        "limit (optional, default 50), offset (optional, default 0). Returns JSON with the "
        "recording slice and pagination metadata."
    ),
    "emulator_stop": (
        "Tear down a session's UDP listener and drop the session from the in-memory table. "
        "The session_id becomes invalid immediately — subsequent emulator_recording calls "
        "return ERROR: unknown session_id. If you want the recording, call emulator_recording "
        "BEFORE stop, or supply a recording_path on serve so the JSONL file persists on disk "
        "after stop. Inputs: session_id."
    ),
    "emulator_list_sessions": (
        "List every active emulator session. No inputs."
    ),
    "replay_diff": (
        "Diff two JSONL recordings produced by the emulator. Use this AFTER a ServiceNow "
        "family upgrade or pattern edit to assert behavioral regression survival: produces "
        "a structured drift report keyed on (request_type, oid). Empty drift = MATCH (safe). "
        "Non-empty drift = exact bytes that changed, ready for human review. "
        "Inputs: baseline_path (required), current_path (required). Returns JSON with "
        "verdict (MATCH / DRIFT) and per-key drift buckets (value_diff, missing_in_current, "
        "added_in_current, error_diff)."
    ),
    "replay_against_session": (
        "Re-issue every GET / GETNEXT recorded in a baseline JSONL against a live emulator "
        "session, comparing response bytes. Useful for verifying the emulator itself is "
        "byte-deterministic across runs and for catching fixture drift introduced by a "
        "blueprint change. Inputs: baseline_path (required), session_id (required), "
        "community (default 'public'), request_timeout_seconds (default 2). Returns JSON "
        "with per-request match/mismatch results."
    ),
}


# ---------------------------------------------------------------------------
# Session table
# ---------------------------------------------------------------------------

class _Session:
    __slots__ = ("id", "runtime", "recording_path")

    def __init__(self, sid: str, runtime: EmulatorRuntime, recording_path: Path | None) -> None:
        self.id = sid
        self.runtime = runtime
        self.recording_path = recording_path


def _clip(s: str) -> str:
    if len(s) <= MAX_OUTPUT_CHARS:
        return s
    return s[: MAX_OUTPUT_CHARS - 60] + "\n\n... [truncated to 8000 chars]"


def _err(msg: str) -> str:
    return f"ERROR: {msg}"


def _ok_json(payload: dict[str, Any]) -> str:
    return _clip(json.dumps(payload, indent=2))


def _is_loopback(host: str) -> bool:
    """True for IPv4/IPv6 loopback addresses and the localhost alias."""
    host_l = (host or "").strip().lower()
    if host_l in ("localhost", "127.0.0.1", "::1"):
        return True
    return host_l.startswith("127.")


# ---------------------------------------------------------------------------
# Server
# ---------------------------------------------------------------------------

class SnTargetEmulatorServer:
    def __init__(self) -> None:
        self.sessions: dict[str, _Session] = {}
        self._debug = os.environ.get("SN_TARGET_EMU_DEBUG", "").lower() in ("1", "true", "yes")
        log.info("sn-target-emulator-mcp initialized — debug=%s", self._debug)

    # -------------------------------------------------- tools
    async def emulator_serve(self, arguments: dict) -> str:
        blueprint = arguments.get("blueprint")
        if not isinstance(blueprint, dict):
            return _err("blueprint must be a JSON object (got "
                        f"{type(blueprint).__name__})")
        community = arguments.get("community", "public")
        bind_host = arguments.get("bind_host", DEFAULT_BIND_HOST)
        bind_port = int(arguments.get("bind_port", 0))
        rec_path_raw = arguments.get("recording_path") or None
        recording_path = Path(rec_path_raw) if rec_path_raw else None
        if not _is_loopback(bind_host):
            log.warning(
                "binding sandbox on non-loopback host %r — the sandbox has no "
                "rate limiting and silently drops wrong-community traffic; only "
                "use a non-loopback bind on trusted networks", bind_host,
            )
        try:
            runtime = EmulatorRuntime.from_blueprint(
                blueprint,
                community=community,
                bind_host=bind_host,
                bind_port=bind_port,
                recording_path=recording_path,
            )
            await runtime.start()
        except OSError as e:
            return _err(f"failed to bind {bind_host}:{bind_port}: {e}")
        except Exception as e:
            log.exception("serve failed")
            return _err(f"failed to start emulator: {e}")
        sid = f"emu_{secrets.token_hex(4)}"
        self.sessions[sid] = _Session(sid, runtime, recording_path)
        host, port = runtime.snmp_address()
        return _ok_json({
            "ok": True,
            "session_id": sid,
            "bind": {"host": host, "port": port, "protocol": "udp"},
            "fixtures": runtime.fixture_summary(),
            "recording_path": str(recording_path) if recording_path else None,
        })

    async def emulator_status(self, arguments: dict) -> str:
        sid = arguments.get("session_id", "")
        sess = self.sessions.get(sid)
        if sess is None:
            return _err(f"unknown session_id: {sid!r}")
        return _ok_json({
            "ok": True,
            "session_id": sid,
            "summary": sess.runtime.fixture_summary(),
            "recording_path": str(sess.recording_path) if sess.recording_path else None,
        })

    async def emulator_recording(self, arguments: dict) -> str:
        sid = arguments.get("session_id", "")
        sess = self.sessions.get(sid)
        if sess is None:
            return _err(f"unknown session_id: {sid!r}")
        try:
            limit = int(arguments.get("limit", 50))
            offset = int(arguments.get("offset", 0))
        except (TypeError, ValueError):
            return _err("limit/offset must be integers")
        if limit < 0 or offset < 0:
            return _err("limit/offset must be non-negative")
        all_interactions = sess.runtime.recording.all()
        slice_ = all_interactions[offset:offset + limit]
        return _ok_json({
            "ok": True,
            "session_id": sid,
            "total": len(all_interactions),
            "offset": offset,
            "limit": limit,
            "interactions": [
                {
                    "ts": i.ts, "proto": i.proto, "client": i.client,
                    "request": i.request, "response": i.response, "error": i.error,
                }
                for i in slice_
            ],
        })

    async def emulator_stop(self, arguments: dict) -> str:
        sid = arguments.get("session_id", "")
        sess = self.sessions.get(sid)
        if sess is None:
            return _err(f"unknown session_id: {sid!r}")
        try:
            await sess.runtime.stop()
        except Exception as e:
            log.exception("stop failed for %s", sid)
            return _err(f"failed to stop session: {e}")
        # Remove from active table but keep last recording reachable via load() if persisted
        del self.sessions[sid]
        return _ok_json({
            "ok": True,
            "session_id": sid,
            "stopped": True,
            "final_recording_size": sess.runtime.recording.count(),
            "recording_path": str(sess.recording_path) if sess.recording_path else None,
        })

    async def replay_diff(self, arguments: dict) -> str:
        baseline_path = arguments.get("baseline_path")
        current_path = arguments.get("current_path")
        if not isinstance(baseline_path, str) or not baseline_path:
            return _err("baseline_path (string) is required")
        if not isinstance(current_path, str) or not current_path:
            return _err("current_path (string) is required")
        baseline = Path(baseline_path)
        current = Path(current_path)
        if not baseline.is_file():
            return _err(f"baseline_path does not exist: {baseline_path!r}")
        if not current.is_file():
            return _err(f"current_path does not exist: {current_path!r}")
        try:
            report = diff_files(baseline, current)
        except Exception as e:
            log.exception("replay_diff failed")
            return _err(f"diff failed: {e}")
        return _ok_json(report.to_dict())

    async def replay_against_session(self, arguments: dict) -> str:
        baseline_path = arguments.get("baseline_path")
        sid = arguments.get("session_id", "")
        if not isinstance(baseline_path, str) or not baseline_path:
            return _err("baseline_path (string) is required")
        sess = self.sessions.get(sid)
        if sess is None:
            return _err(f"unknown session_id: {sid!r}")
        baseline = Path(baseline_path)
        if not baseline.is_file():
            return _err(f"baseline_path does not exist: {baseline_path!r}")
        community = arguments.get("community", "public")
        try:
            timeout = float(arguments.get("request_timeout_seconds", 2.0))
        except (TypeError, ValueError):
            return _err("request_timeout_seconds must be a number")
        host, port = sess.runtime.snmp_address()
        try:
            results = await _replay_against_session_func(
                baseline, host, port,
                community=community,
                request_timeout=timeout,
            )
        except Exception as e:
            log.exception("replay_against_session failed")
            return _err(f"replay failed: {e}")
        mismatched = [r for r in results if not r.matches]
        return _ok_json({
            "ok": True,
            "session_id": sid,
            "summary": {
                "verdict": "MATCH" if not mismatched else "DRIFT",
                "replayed": len(results),
                "matched": len(results) - len(mismatched),
                "mismatched": len(mismatched),
            },
            "results": [
                {
                    "request_type": r.request_type,
                    "oid": r.oid,
                    "matches": r.matches,
                    "baseline_value_hex": r.baseline_value_hex,
                    "current_value_hex": r.current_value_hex,
                }
                for r in results
            ],
        })

    async def emulator_list_sessions(self, _arguments: dict) -> str:
        out = []
        for sid, sess in self.sessions.items():
            host, port = sess.runtime.snmp_address()
            out.append({
                "session_id": sid,
                "bind": f"{host}:{port}",
                "fixture_count": len(sess.runtime.entries),
                "recorded": sess.runtime.recording.count(),
                "recording_path": str(sess.recording_path) if sess.recording_path else None,
            })
        return _ok_json({"ok": True, "sessions": out})

    # -------------------------------------------------- dispatch
    async def _dispatch(self, name: str, arguments: dict) -> str:
        handler = {
            "emulator_serve": self.emulator_serve,
            "emulator_status": self.emulator_status,
            "emulator_recording": self.emulator_recording,
            "emulator_stop": self.emulator_stop,
            "emulator_list_sessions": self.emulator_list_sessions,
            "replay_diff": self.replay_diff,
            "replay_against_session": self.replay_against_session,
        }.get(name)
        if handler is None:
            return _err(f"unknown tool: {name!r}")
        try:
            return await handler(arguments or {})
        except Exception as e:
            log.exception("tool %s raised", name)
            out = _err(f"{type(e).__name__}: {e}")
            if self._debug:
                out += "\n\nTRACEBACK:\n" + traceback.format_exc()
            return out

    async def run(self) -> None:
        from mcp.server.lowlevel import Server
        from mcp.server.stdio import stdio_server
        from mcp.types import TextContent, Tool

        def _input(properties: dict, required: list[str]) -> dict:
            return {
                "type": "object",
                "properties": properties,
                "required": required,
                "additionalProperties": False,
            }

        tools = [
            Tool(name="emulator_serve",
                 description=TOOL_DESCRIPTIONS["emulator_serve"],
                 inputSchema=_input({
                     "blueprint": {"type": "object", "additionalProperties": True,
                                   "description": "Blueprint JSON from emulator_blueprint or an "
                                                  "object with fixtures.snmp"},
                     "community": {"type": "string", "default": "public"},
                     "bind_host": {"type": "string", "default": DEFAULT_BIND_HOST},
                     "bind_port": {"type": "integer", "default": 0, "minimum": 0, "maximum": 65535},
                     "recording_path": {"type": "string",
                                        "description": "Optional file path for JSONL persistence"},
                 }, ["blueprint"])),
            Tool(name="emulator_status",
                 description=TOOL_DESCRIPTIONS["emulator_status"],
                 inputSchema=_input({"session_id": {"type": "string"}}, ["session_id"])),
            Tool(name="emulator_recording",
                 description=TOOL_DESCRIPTIONS["emulator_recording"],
                 inputSchema=_input({
                     "session_id": {"type": "string"},
                     "limit": {"type": "integer", "default": 50, "minimum": 0, "maximum": 1000},
                     "offset": {"type": "integer", "default": 0, "minimum": 0},
                 }, ["session_id"])),
            Tool(name="emulator_stop",
                 description=TOOL_DESCRIPTIONS["emulator_stop"],
                 inputSchema=_input({"session_id": {"type": "string"}}, ["session_id"])),
            Tool(name="emulator_list_sessions",
                 description=TOOL_DESCRIPTIONS["emulator_list_sessions"],
                 inputSchema=_input({}, [])),
            Tool(name="replay_diff",
                 description=TOOL_DESCRIPTIONS["replay_diff"],
                 inputSchema=_input({
                     "baseline_path": {"type": "string",
                                       "description": "Path to a JSONL recording from a known-good run"},
                     "current_path": {"type": "string",
                                      "description": "Path to a JSONL recording to compare against the baseline"},
                 }, ["baseline_path", "current_path"])),
            Tool(name="replay_against_session",
                 description=TOOL_DESCRIPTIONS["replay_against_session"],
                 inputSchema=_input({
                     "baseline_path": {"type": "string"},
                     "session_id": {"type": "string"},
                     "community": {"type": "string", "default": "public"},
                     "request_timeout_seconds": {"type": "number",
                                                 "default": 2.0, "minimum": 0.1, "maximum": 30.0},
                 }, ["baseline_path", "session_id"])),
        ]

        server: Server = Server("sn-target-emulator-mcp")

        @server.list_tools()
        async def _list_tools() -> list[Tool]:
            return tools

        @server.call_tool()
        async def _call_tool(name: str, arguments: dict | None) -> list[TextContent]:
            out = await self._dispatch(name, arguments or {})
            return [TextContent(type="text", text=out)]

        async with stdio_server() as (reader, writer):
            await server.run(reader, writer, server.create_initialization_options())


def main() -> None:
    configure_logging()
    asyncio.run(SnTargetEmulatorServer().run())


if __name__ == "__main__":
    main()
