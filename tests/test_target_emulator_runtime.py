"""End-to-end tests for the Tier-3 emulator runtime.

These tests bind a real UDP listener on 127.0.0.1:<random-port>, send a
real SNMP message via a raw socket, and assert the response is correct
and the recording captured the interaction.

No external network: everything is on loopback, port 0 = OS-assigned.
"""
from __future__ import annotations

import asyncio
import socket

import pytest

from sn_patterns_mcp.target_emulator import snmp_v2c as s
from sn_patterns_mcp.target_emulator.fixtures import (
    fixtures_from_blueprint,
    infer_default,
)
from sn_patterns_mcp.target_emulator.runtime import EmulatorRuntime

# ---------------------------------------------------------------------------
# fixtures_from_blueprint
# ---------------------------------------------------------------------------

def test_infer_default_octet_string_with_size():
    v, t = infer_default("OCTET STRING (SIZE (0..255))")
    assert t == "OCTET STRING"
    assert v == "<stub>"


def test_infer_default_displaystring_specialized():
    v, t = infer_default("DisplayString")
    assert t == "OCTET STRING"
    assert v == "stub-display"


def test_infer_default_counter32():
    v, t = infer_default("Counter32")
    assert t == "Counter32"
    assert v == 0


def test_fixtures_skip_dynamic_oids():
    bp = {"fixtures": {"snmp": [
        {"oid": "1.3.6.1.2.1.1.5.0", "syntax": "DisplayString"},
        {"oid": "$dynamic_oid", "syntax": "Integer32"},
        {"oid": "", "syntax": "Integer32"},
    ]}}
    out = fixtures_from_blueprint(bp)
    assert len(out) == 1
    assert out[0].oid == "1.3.6.1.2.1.1.5.0"


def test_fixtures_honor_explicit_value():
    bp = {"fixtures": {"snmp": [
        {"oid": "1.3.6.1.2.1.1.5.0", "syntax": "DisplayString", "value": "my-router"},
        {"oid": "1.3.6.1.2.1.1.3.0", "syntax": "TimeTicks", "value": "<scenario-value>"},
    ]}}
    out = fixtures_from_blueprint(bp)
    assert out[0].value == "my-router"
    assert out[1].value == 0  # placeholder → fall through to syntax default


# ---------------------------------------------------------------------------
# Live UDP round-trip
# ---------------------------------------------------------------------------

async def _send_and_recv(host: str, port: int, payload: bytes, timeout: float = 1.0) -> bytes:
    """Send a UDP datagram and await one reply. Returns the reply bytes."""
    loop = asyncio.get_running_loop()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setblocking(False)
    try:
        await loop.sock_connect(sock, (host, port))
        await loop.sock_sendall(sock, payload)
        return await asyncio.wait_for(loop.sock_recv(sock, 65535), timeout)
    finally:
        sock.close()


def _build_get_request(oid: str, *, request_id: int = 1, community: str = "public") -> bytes:
    msg = s.SnmpMessage(
        version=s.SNMP_V2C_VERSION,
        community=community,
        pdu_type=s.T_GET_REQUEST,
        request_id=request_id,
        error_status=0,
        error_index=0,
        varbinds=[s.VarBind.null(oid)],
    )
    return s.encode_message(msg)


def _build_getnext_request(oid: str, *, request_id: int = 1, community: str = "public") -> bytes:
    msg = s.SnmpMessage(
        version=s.SNMP_V2C_VERSION,
        community=community,
        pdu_type=s.T_GETNEXT_REQUEST,
        request_id=request_id,
        error_status=0,
        error_index=0,
        varbinds=[s.VarBind.null(oid)],
    )
    return s.encode_message(msg)


def _extract_first_varbind_value(reply: bytes) -> tuple[str, bytes]:
    parsed = s.decode_message(reply)
    assert parsed.pdu_type == s.T_RESPONSE
    assert len(parsed.varbinds) == 1
    return parsed.varbinds[0].oid, parsed.varbinds[0].value_bytes


@pytest.mark.asyncio
async def test_get_returns_fixture_octet_string():
    rt = EmulatorRuntime.from_oid_value_map({
        "1.3.6.1.2.1.1.5.0": ("demo-router-01", "OCTET STRING"),
    })
    await rt.start()
    try:
        host, port = rt.snmp_address()
        reply = await _send_and_recv(host, port, _build_get_request("1.3.6.1.2.1.1.5.0"))
        oid, value_bytes = _extract_first_varbind_value(reply)
        assert oid == "1.3.6.1.2.1.1.5.0"
        assert value_bytes == s.enc_octet_string("demo-router-01")
        assert rt.recording.count() == 1
        rec = rt.recording.all()[0]
        assert rec.proto == "snmp"
        assert rec.request["type"] == "GetRequest"
        assert rec.response["type"] == "Response"
    finally:
        await rt.stop()


@pytest.mark.asyncio
async def test_get_unknown_oid_returns_no_such_object():
    rt = EmulatorRuntime.from_oid_value_map({
        "1.3.6.1.2.1.1.5.0": ("demo", "OCTET STRING"),
    })
    await rt.start()
    try:
        host, port = rt.snmp_address()
        reply = await _send_and_recv(host, port, _build_get_request("1.3.6.1.4.1.99.99.99.0"))
        parsed = s.decode_message(reply)
        # varbind value is the [0] context-tagged NULL (noSuchObject)
        assert parsed.varbinds[0].value_bytes == s.enc_no_such_object()
    finally:
        await rt.stop()


@pytest.mark.asyncio
async def test_getnext_returns_lexicographic_successor():
    rt = EmulatorRuntime.from_oid_value_map({
        "1.3.6.1.2.1.1.1.0": ("desc", "OCTET STRING"),
        "1.3.6.1.2.1.1.5.0": ("name", "OCTET STRING"),
        "1.3.6.1.2.1.2.2.1.5.1": (1000000, "Gauge32"),
    })
    await rt.start()
    try:
        host, port = rt.snmp_address()
        # Walking from the system group → first hit is sysDescr.0
        reply = await _send_and_recv(host, port, _build_getnext_request("1.3.6.1.2.1.1"))
        oid, vb = _extract_first_varbind_value(reply)
        assert oid == "1.3.6.1.2.1.1.1.0"

        # Continue from sysDescr.0 → sysName.0
        reply = await _send_and_recv(host, port, _build_getnext_request(oid))
        oid2, _ = _extract_first_varbind_value(reply)
        assert oid2 == "1.3.6.1.2.1.1.5.0"

        # Continue → interface gauge
        reply = await _send_and_recv(host, port, _build_getnext_request(oid2))
        oid3, vb3 = _extract_first_varbind_value(reply)
        assert oid3 == "1.3.6.1.2.1.2.2.1.5.1"
        assert vb3 == s.enc_gauge32(1000000)

        # Continue from the last fixture → endOfMibView
        reply = await _send_and_recv(host, port, _build_getnext_request(oid3))
        parsed = s.decode_message(reply)
        assert parsed.varbinds[0].value_bytes == s.enc_end_of_mib_view()
    finally:
        await rt.stop()


@pytest.mark.asyncio
async def test_wrong_community_is_silently_dropped_and_recorded_as_error():
    rt = EmulatorRuntime.from_oid_value_map({
        "1.3.6.1.2.1.1.5.0": ("demo", "OCTET STRING"),
    }, community="public")
    await rt.start()
    try:
        host, port = rt.snmp_address()
        try:
            await _send_and_recv(
                host, port,
                _build_get_request("1.3.6.1.2.1.1.5.0", community="wrong"),
                timeout=0.5,
            )
            raise AssertionError("expected timeout: server should drop wrong-community traffic")
        except asyncio.TimeoutError:
            pass
        recs = rt.recording.all()
        assert len(recs) == 1
        assert recs[0].error is not None and "community_mismatch" in recs[0].error
    finally:
        await rt.stop()


@pytest.mark.asyncio
async def test_blueprint_drives_a_real_responder(tmp_path):
    blueprint = {
        "fixtures": {
            "snmp": [
                {"oid": "1.3.6.1.2.1.1.5.0", "syntax": "DisplayString", "name": "sysName"},
                {"oid": "1.3.6.1.2.1.1.3.0", "syntax": "TimeTicks", "name": "sysUpTime"},
                {"oid": "1.3.6.1.2.1.2.2.1.6.1", "syntax": "OCTET STRING", "value": "00:11:22:33:44:55"},
                {"oid": "$dynamic", "syntax": "Integer32"},
            ]
        }
    }
    rec_path = tmp_path / "session.jsonl"
    rt = EmulatorRuntime.from_blueprint(blueprint, recording_path=rec_path)
    await rt.start()
    try:
        host, port = rt.snmp_address()
        # The dynamic OID was filtered out; we should have 3 fixtures.
        assert len(rt.entries) == 3

        # Explicit value honoured
        reply = await _send_and_recv(host, port, _build_get_request("1.3.6.1.2.1.2.2.1.6.1"))
        _, vb = _extract_first_varbind_value(reply)
        assert vb == s.enc_octet_string("00:11:22:33:44:55")

        # Inferred default for DisplayString
        reply = await _send_and_recv(host, port, _build_get_request("1.3.6.1.2.1.1.5.0"))
        _, vb = _extract_first_varbind_value(reply)
        assert vb == s.enc_octet_string("stub-display")

        # The recording file should now have JSONL entries
        assert rec_path.exists()
        lines = [line for line in rec_path.read_text().splitlines() if line.strip()]
        assert len(lines) == 2
    finally:
        await rt.stop()
