"""Record/replay regression-harness tests."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from sn_patterns_mcp.target_emulator import snmp_v2c as s
from sn_patterns_mcp.target_emulator.recording import Interaction, Recorder
from sn_patterns_mcp.target_emulator.replay import (
    diff_files,
    diff_interactions,
    replay_against_session,
)
from sn_patterns_mcp.target_emulator.runtime import EmulatorRuntime

# ---------------------------------------------------------------------------
# diff_interactions — set-based per-(type, oid) bucket comparison
# ---------------------------------------------------------------------------

def _interaction(
    *,
    rtype: str = "GetRequest",
    oid: str = "1.3.6.1.2.1.1.5.0",
    value_hex: str = "0400",
    error: str | None = None,
) -> Interaction:
    return Interaction(
        ts="2026-05-23T00:00:00+00:00",
        proto="snmp",
        client="127.0.0.1:1234",
        request={"type": rtype, "oids": [oid]},
        response={"type": "Response",
                  "varbinds": [{"oid": oid, "value_hex": value_hex}]},
        error=error,
    )


def test_identical_recordings_produce_match_verdict():
    base = [_interaction(value_hex="0400")]
    curr = [_interaction(value_hex="0400")]
    r = diff_interactions(base, curr)
    assert r.verdict == "MATCH"
    assert not r.value_diff
    assert not r.missing_in_current
    assert not r.added_in_current


def test_value_drift_detected():
    base = [_interaction(value_hex="040400746869730a")]  # "this\n"
    curr = [_interaction(value_hex="04047468617421")]    # "that!"
    r = diff_interactions(base, curr)
    assert r.verdict == "DRIFT"
    assert len(r.value_diff) == 1
    vd = r.value_diff[0]
    assert vd.oid == "1.3.6.1.2.1.1.5.0"
    assert "040400746869730a" in vd.baseline_values
    assert "04047468617421" in vd.current_values


def test_missing_in_current_detected():
    base = [
        _interaction(oid="1.3.6.1.2.1.1.5.0"),
        _interaction(oid="1.3.6.1.2.1.1.1.0"),
    ]
    curr = [_interaction(oid="1.3.6.1.2.1.1.5.0")]
    r = diff_interactions(base, curr)
    assert r.verdict == "DRIFT"
    assert len(r.missing_in_current) == 1
    assert r.missing_in_current[0].oid == "1.3.6.1.2.1.1.1.0"


def test_added_in_current_detected():
    base = [_interaction(oid="1.3.6.1.2.1.1.5.0")]
    curr = [
        _interaction(oid="1.3.6.1.2.1.1.5.0"),
        _interaction(oid="1.3.6.1.2.1.2.2.1.10.1"),
    ]
    r = diff_interactions(base, curr)
    assert r.verdict == "DRIFT"
    assert len(r.added_in_current) == 1
    assert r.added_in_current[0].oid == "1.3.6.1.2.1.2.2.1.10.1"


def test_error_diff_detected():
    base = [_interaction(value_hex="0400")]
    curr = [_interaction(value_hex="", error="community_mismatch: foo")]
    r = diff_interactions(base, curr)
    assert r.verdict == "DRIFT"
    assert len(r.error_diff) == 1
    assert "community_mismatch: foo" in r.error_diff[0].current_errors


def test_same_oid_different_request_type_treated_as_separate_keys():
    base = [_interaction(rtype="GetRequest", oid="1.3.6.1.2.1.1.5.0")]
    curr = [_interaction(rtype="GetNextRequest", oid="1.3.6.1.2.1.1.5.0")]
    r = diff_interactions(base, curr)
    assert r.verdict == "DRIFT"
    # The GetRequest is missing, the GetNextRequest is added
    assert len(r.missing_in_current) == 1
    assert len(r.added_in_current) == 1


def test_repeated_identical_requests_collapse_to_single_key():
    base = [_interaction() for _ in range(5)]
    curr = [_interaction() for _ in range(3)]
    r = diff_interactions(base, curr)
    # Bucket dedupe collapses 5×same-value and 3×same-value to {one_value} each
    assert r.verdict == "MATCH"
    assert r.baseline_total == 5
    assert r.current_total == 3
    assert r.baseline_keys == 1
    assert r.current_keys == 1


def test_to_dict_shape():
    base = [_interaction(value_hex="0400")]
    curr = [_interaction(value_hex="0401")]
    d = diff_interactions(base, curr).to_dict()
    assert d["ok"] is True
    assert d["summary"]["verdict"] == "DRIFT"
    assert d["summary"]["drift_counts"]["value_diff"] == 1
    assert "drift" in d
    assert "value_diff" in d["drift"]


# ---------------------------------------------------------------------------
# diff_files — JSONL round-trip
# ---------------------------------------------------------------------------

def test_diff_files_reads_jsonl_and_diffs(tmp_path: Path):
    base_path = tmp_path / "baseline.jsonl"
    curr_path = tmp_path / "current.jsonl"
    base_path.write_text(_interaction(value_hex="0400").to_json_line() + "\n", encoding="utf-8")
    curr_path.write_text(_interaction(value_hex="0401").to_json_line() + "\n", encoding="utf-8")
    r = diff_files(base_path, curr_path)
    assert r.verdict == "DRIFT"


def test_diff_files_handles_blank_lines_and_malformed_lines(tmp_path: Path):
    base_path = tmp_path / "baseline.jsonl"
    curr_path = tmp_path / "current.jsonl"
    base_path.write_text(
        _interaction(value_hex="0400").to_json_line() + "\n"
        + "\n"           # blank line
        + "not valid json\n"      # malformed — should be skipped
        + _interaction(value_hex="0400").to_json_line() + "\n",
        encoding="utf-8",
    )
    curr_path.write_text(_interaction(value_hex="0400").to_json_line() + "\n", encoding="utf-8")
    r = diff_files(base_path, curr_path)
    # 2 interactions in baseline (the 2 valid lines), 1 in current
    assert r.baseline_total == 2
    assert r.current_total == 1
    assert r.verdict == "MATCH"


# ---------------------------------------------------------------------------
# replay_against_session — drive baseline traffic against a live emulator
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_replay_against_session_all_matches(tmp_path: Path):
    """Record a baseline against a sandbox, immediately replay against the
    same sandbox — every request should produce the same bytes."""
    rt = EmulatorRuntime.from_oid_value_map({
        "1.3.6.1.2.1.1.5.0": ("router-A", "OCTET STRING"),
        "1.3.6.1.2.1.1.1.0": ("Linux box", "OCTET STRING"),
    }, recording_path=tmp_path / "baseline.jsonl")
    await rt.start()
    try:
        host, port = rt.snmp_address()
        # Build baseline traffic by sending two real requests
        import asyncio
        import socket
        loop = asyncio.get_running_loop()
        for oid in ("1.3.6.1.2.1.1.5.0", "1.3.6.1.2.1.1.1.0"):
            req = s.encode_message(s.SnmpMessage(
                version=s.SNMP_V2C_VERSION, community="public",
                pdu_type=s.T_GET_REQUEST,
                request_id=1, error_status=0, error_index=0,
                varbinds=[s.VarBind.null(oid)],
            ))
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setblocking(False)
            try:
                await loop.sock_connect(sock, (host, port))
                await loop.sock_sendall(sock, req)
                await asyncio.wait_for(loop.sock_recv(sock, 65535), timeout=1.0)
            finally:
                sock.close()
        # Now replay against the same session
        results = await replay_against_session(tmp_path / "baseline.jsonl", host, port)
        assert len(results) == 2
        assert all(r.matches for r in results)
    finally:
        await rt.stop()


@pytest.mark.asyncio
async def test_replay_against_modified_blueprint_surfaces_drift(tmp_path: Path):
    """Record a baseline against one fixture set, then replay against a
    sandbox that has a DIFFERENT value for the same OID. Expect every
    matching OID to surface as a mismatch."""
    # Phase 1: record baseline
    rt1 = EmulatorRuntime.from_oid_value_map({
        "1.3.6.1.2.1.1.5.0": ("baseline-name", "OCTET STRING"),
    }, recording_path=tmp_path / "baseline.jsonl")
    await rt1.start()
    try:
        host1, port1 = rt1.snmp_address()
        import asyncio
        import socket
        loop = asyncio.get_running_loop()
        req = s.encode_message(s.SnmpMessage(
            version=s.SNMP_V2C_VERSION, community="public",
            pdu_type=s.T_GET_REQUEST, request_id=1,
            error_status=0, error_index=0,
            varbinds=[s.VarBind.null("1.3.6.1.2.1.1.5.0")],
        ))
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setblocking(False)
        try:
            await loop.sock_connect(sock, (host1, port1))
            await loop.sock_sendall(sock, req)
            await asyncio.wait_for(loop.sock_recv(sock, 65535), timeout=1.0)
        finally:
            sock.close()
    finally:
        await rt1.stop()

    # Phase 2: start a new session with a DIFFERENT value for the same OID
    rt2 = EmulatorRuntime.from_oid_value_map({
        "1.3.6.1.2.1.1.5.0": ("post-upgrade-name", "OCTET STRING"),
    })
    await rt2.start()
    try:
        host2, port2 = rt2.snmp_address()
        results = await replay_against_session(tmp_path / "baseline.jsonl", host2, port2)
        assert len(results) == 1
        assert results[0].matches is False
        assert "post-upgrade" in bytes.fromhex(results[0].current_value_hex).decode("utf-8", errors="replace")
    finally:
        await rt2.stop()
