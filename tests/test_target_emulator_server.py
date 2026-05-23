"""Tests for sn_patterns_mcp.target_emulator.server (the MCP companion server).

We test the dispatcher methods directly (not via the MCP transport) — same
strategy the parent project's tests use. The MCP wire layer is one thin
adapter; the behavior worth verifying is the tool implementations.
"""
from __future__ import annotations

import asyncio
import json
import socket

import pytest
import pytest_asyncio

from sn_patterns_mcp.target_emulator import snmp_v2c as s
from sn_patterns_mcp.target_emulator.server import SnTargetEmulatorServer


@pytest_asyncio.fixture
async def server():
    srv = SnTargetEmulatorServer()
    yield srv
    # Cleanup: stop every still-running session
    for sid in list(srv.sessions):
        try:
            await srv.emulator_stop({"session_id": sid})
        except Exception:
            pass


@pytest.mark.asyncio
async def test_serve_requires_blueprint_object(server):
    out = await server.emulator_serve({})
    assert out.startswith("ERROR:")
    assert "blueprint must be a JSON object" in out


@pytest.mark.asyncio
async def test_serve_starts_and_status_reports(server):
    blueprint = {"fixtures": {"snmp": [
        {"oid": "1.3.6.1.2.1.1.5.0", "syntax": "DisplayString"},
    ]}}
    out = await server.emulator_serve({"blueprint": blueprint})
    body = json.loads(out)
    assert body["ok"] is True
    assert body["session_id"].startswith("emu_")
    assert body["bind"]["protocol"] == "udp"
    assert body["fixtures"]["fixture_count"] == 1

    status = json.loads(await server.emulator_status({"session_id": body["session_id"]}))
    assert status["ok"] is True
    assert status["summary"]["fixture_count"] == 1


@pytest.mark.asyncio
async def test_status_rejects_unknown_session(server):
    out = await server.emulator_status({"session_id": "emu_does_not_exist"})
    assert out.startswith("ERROR:")
    assert "unknown session_id" in out


@pytest.mark.asyncio
async def test_serve_query_record_stop(server, tmp_path):
    rec_path = tmp_path / "session.jsonl"
    blueprint = {"fixtures": {"snmp": [
        {"oid": "1.3.6.1.2.1.1.5.0", "syntax": "DisplayString", "value": "demo-router"},
    ]}}
    serve_out = json.loads(await server.emulator_serve({
        "blueprint": blueprint,
        "recording_path": str(rec_path),
    }))
    sid = serve_out["session_id"]
    host, port = serve_out["bind"]["host"], serve_out["bind"]["port"]

    # Fire one real SNMP GET against the bound port
    request = s.encode_message(s.SnmpMessage(
        version=s.SNMP_V2C_VERSION,
        community="public",
        pdu_type=s.T_GET_REQUEST,
        request_id=7,
        error_status=0,
        error_index=0,
        varbinds=[s.VarBind.null("1.3.6.1.2.1.1.5.0")],
    ))
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setblocking(False)
    loop = asyncio.get_running_loop()
    try:
        await loop.sock_connect(sock, (host, port))
        await loop.sock_sendall(sock, request)
        reply = await asyncio.wait_for(loop.sock_recv(sock, 65535), timeout=1.0)
    finally:
        sock.close()
    response = s.decode_message(reply)
    assert response.varbinds[0].value_bytes == s.enc_octet_string("demo-router")

    # Read the recording back via the MCP tool
    rec_out = json.loads(await server.emulator_recording({"session_id": sid}))
    assert rec_out["ok"] is True
    assert rec_out["total"] == 1
    assert rec_out["interactions"][0]["request"]["type"] == "GetRequest"

    # Stop
    stop_out = json.loads(await server.emulator_stop({"session_id": sid}))
    assert stop_out["ok"] is True and stop_out["stopped"] is True

    # After stop the session is gone
    bad = await server.emulator_status({"session_id": sid})
    assert bad.startswith("ERROR:")

    # And the JSONL file remains on disk for Phase 3 replay
    assert rec_path.exists()
    lines = [line for line in rec_path.read_text().splitlines() if line.strip()]
    assert len(lines) == 1


@pytest.mark.asyncio
async def test_list_sessions_reflects_active_sessions(server):
    bp = {"fixtures": {"snmp": [{"oid": "1.3.6.1.2.1.1.5.0", "syntax": "DisplayString"}]}}
    a = json.loads(await server.emulator_serve({"blueprint": bp}))
    b = json.loads(await server.emulator_serve({"blueprint": bp}))
    listing = json.loads(await server.emulator_list_sessions({}))
    sids = {row["session_id"] for row in listing["sessions"]}
    assert a["session_id"] in sids
    assert b["session_id"] in sids


@pytest.mark.asyncio
async def test_recording_pagination(server):
    bp = {"fixtures": {"snmp": [
        {"oid": "1.3.6.1.2.1.1.5.0", "syntax": "DisplayString"},
    ]}}
    sid = json.loads(await server.emulator_serve({"blueprint": bp}))["session_id"]
    # Directly poke 5 fake interactions through the recorder for the pagination check
    srv_runtime = server.sessions[sid].runtime
    for i in range(5):
        srv_runtime.recording.append(
            proto="snmp", client="127.0.0.1:1234",
            request={"type": "GetRequest", "oids": [f"1.3.6.1.2.1.1.{i}.0"]},
            response={"type": "Response"},
        )
    out = json.loads(await server.emulator_recording({"session_id": sid, "limit": 2, "offset": 1}))
    assert out["total"] == 5
    assert out["offset"] == 1
    assert out["limit"] == 2
    assert len(out["interactions"]) == 2


@pytest.mark.asyncio
async def test_recording_rejects_negative_limit(server):
    bp = {"fixtures": {"snmp": [{"oid": "1.3.6.1.2.1.1.5.0", "syntax": "DisplayString"}]}}
    sid = json.loads(await server.emulator_serve({"blueprint": bp}))["session_id"]
    out = await server.emulator_recording({"session_id": sid, "limit": -1})
    assert out.startswith("ERROR:")
