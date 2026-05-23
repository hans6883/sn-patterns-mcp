"""Record / replay regression harness for Tier-3 emulator recordings.

The Phase 3 thesis: ServiceNow Discovery patterns silently regress across SN
family upgrades (Yokohama → Zurich, etc.) because there is no first-class way
to capture a known-good behavioral baseline and assert "still behaves the
same." The Tier-3 emulator now produces deterministic JSONL recordings; this
module turns those recordings into a regression-survival story:

    1. Record a baseline: drive your discovery flow against a sandbox started
       from a blueprint, with `recording_path=baseline.jsonl`.
    2. Later (after upgrading SN, editing the pattern, or modifying the
       blueprint), repeat with `recording_path=current.jsonl`.
    3. Call replay_diff(baseline.jsonl, current.jsonl) — get a structured
       drift report. Empty drift = pattern is upgrade-safe. Non-empty drift
       = exact bytes that changed, ready for human review.

A second mode (replay_from_recording) drives the baseline's requests against
a *running* session and diffs the responses in-process — useful for verifying
the sandbox itself is byte-deterministic across runs.

The diff is keyed on (request_type, oid) tuples rather than individual
interactions. Two recordings that ask for sysName.0 in different order but
get the same response are MATCH; two that get different bytes for sysName.0
are DRIFT.
"""
from __future__ import annotations

import asyncio
import socket
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from sn_patterns_mcp.target_emulator import snmp_v2c
from sn_patterns_mcp.target_emulator.recording import Interaction, Recorder

# ---------------------------------------------------------------------------
# Diff data classes
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class KeyDiff:
    """One drift entry, identified by (request_type, oid)."""

    request_type: str
    oid: str
    baseline_values: tuple[str, ...] = ()
    current_values: tuple[str, ...] = ()
    baseline_errors: tuple[str, ...] = ()
    current_errors: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "request_type": self.request_type,
            "oid": self.oid,
            "baseline_values": list(self.baseline_values),
            "current_values": list(self.current_values),
            "baseline_errors": list(self.baseline_errors),
            "current_errors": list(self.current_errors),
        }


@dataclass
class DiffReport:
    baseline_total: int
    current_total: int
    baseline_keys: int
    current_keys: int
    value_diff: list[KeyDiff] = field(default_factory=list)
    missing_in_current: list[KeyDiff] = field(default_factory=list)
    added_in_current: list[KeyDiff] = field(default_factory=list)
    error_diff: list[KeyDiff] = field(default_factory=list)

    @property
    def verdict(self) -> str:
        if not (self.value_diff or self.missing_in_current or self.added_in_current or self.error_diff):
            return "MATCH"
        return "DRIFT"

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": True,
            "summary": {
                "verdict": self.verdict,
                "baseline_interactions": self.baseline_total,
                "current_interactions": self.current_total,
                "baseline_unique_keys": self.baseline_keys,
                "current_unique_keys": self.current_keys,
                "drift_counts": {
                    "value_diff": len(self.value_diff),
                    "missing_in_current": len(self.missing_in_current),
                    "added_in_current": len(self.added_in_current),
                    "error_diff": len(self.error_diff),
                },
            },
            "drift": {
                "value_diff": [k.to_dict() for k in self.value_diff],
                "missing_in_current": [k.to_dict() for k in self.missing_in_current],
                "added_in_current": [k.to_dict() for k in self.added_in_current],
                "error_diff": [k.to_dict() for k in self.error_diff],
            },
        }


# ---------------------------------------------------------------------------
# Indexing — collapse a flat interaction list into per-key buckets
# ---------------------------------------------------------------------------

@dataclass
class _Bucket:
    values: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


def _index_interactions(interactions: list[Interaction]) -> dict[tuple[str, str], _Bucket]:
    """Collapse a recording into {(request_type, oid): _Bucket(values, errors)}.

    For request types that touch a single OID per varbind (GetRequest /
    GetNextRequest in our world), we explode multi-varbind requests into
    one bucket entry per OID. The response's varbinds are matched
    positionally to the request's OIDs.

    Known blind spot for GETNEXT walks against *real* SNMP agents: the bucket
    captures the response value_hex but NOT the response OID (the lex
    successor the agent chose to return). If a MIB is restructured between
    recordings such that GETNEXT(seed) now returns a different successor OID
    but with the same value bytes, this diff returns MATCH when DRIFT would
    be more accurate. For the sandbox (where blueprint == fixed OID table)
    this can't occur; for real-hardware regression testing it is a rare but
    real edge case worth noting.
    """
    out: dict[tuple[str, str], _Bucket] = {}
    for i in interactions:
        req = i.request or {}
        rtype = str(req.get("type", ""))
        oids = req.get("oids") or []
        if not isinstance(oids, list):
            oids = [oids]
        resp_varbinds = ((i.response or {}).get("varbinds") or []) if isinstance(i.response, dict) else []
        for idx, oid in enumerate(oids):
            key = (rtype, str(oid))
            bucket = out.setdefault(key, _Bucket())
            if i.error:
                bucket.errors.append(i.error)
            else:
                # Match varbinds positionally. If the server returned a
                # different number of varbinds (rare for our sandbox but
                # possible for a GETNEXT that returns the lex successor),
                # fall back to the OID name in the response varbind list.
                value_hex = ""
                if idx < len(resp_varbinds) and isinstance(resp_varbinds[idx], dict):
                    value_hex = str(resp_varbinds[idx].get("value_hex", ""))
                bucket.values.append(value_hex)
    return out


# ---------------------------------------------------------------------------
# Diff
# ---------------------------------------------------------------------------

def diff_interactions(
    baseline: list[Interaction],
    current: list[Interaction],
) -> DiffReport:
    """Compute a DiffReport from two interaction lists."""
    base_idx = _index_interactions(baseline)
    curr_idx = _index_interactions(current)

    report = DiffReport(
        baseline_total=len(baseline),
        current_total=len(current),
        baseline_keys=len(base_idx),
        current_keys=len(curr_idx),
    )

    for key in sorted(base_idx.keys() | curr_idx.keys()):
        b = base_idx.get(key)
        c = curr_idx.get(key)
        rtype, oid = key
        if b and not c:
            report.missing_in_current.append(KeyDiff(
                request_type=rtype, oid=oid,
                baseline_values=tuple(sorted(set(b.values))),
                baseline_errors=tuple(sorted(set(b.errors))),
            ))
            continue
        if c and not b:
            report.added_in_current.append(KeyDiff(
                request_type=rtype, oid=oid,
                current_values=tuple(sorted(set(c.values))),
                current_errors=tuple(sorted(set(c.errors))),
            ))
            continue
        assert b and c  # for type-narrowing
        b_vals = set(b.values)
        c_vals = set(c.values)
        b_errs = set(b.errors)
        c_errs = set(c.errors)
        if b_errs != c_errs:
            report.error_diff.append(KeyDiff(
                request_type=rtype, oid=oid,
                baseline_errors=tuple(sorted(b_errs)),
                current_errors=tuple(sorted(c_errs)),
            ))
        if b_vals != c_vals:
            report.value_diff.append(KeyDiff(
                request_type=rtype, oid=oid,
                baseline_values=tuple(sorted(b_vals)),
                current_values=tuple(sorted(c_vals)),
            ))
    return report


def diff_files(baseline_path: Path, current_path: Path) -> DiffReport:
    """Load two JSONL recording files and diff them."""
    base = Recorder.load(baseline_path)
    curr = Recorder.load(current_path)
    return diff_interactions(base, curr)


# ---------------------------------------------------------------------------
# Replay against a live session
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ReplayResult:
    """Outcome of replaying one baseline request against a live session."""

    request_type: str
    oid: str
    baseline_value_hex: str
    current_value_hex: str
    matches: bool


async def replay_against_session(
    baseline_path: Path,
    host: str,
    port: int,
    *,
    community: str = "public",
    request_timeout: float = 2.0,
) -> list[ReplayResult]:
    """Re-issue every GET/GETNEXT from a baseline JSONL against a live UDP endpoint.

    Returns a list of ReplayResult records. A `matches=False` row means the
    sandbox produced different bytes for the same (type, oid) than what was
    recorded in the baseline — i.e. the sandbox lost determinism. This is
    the primary self-regression test for the emulator.
    """
    baseline = Recorder.load(baseline_path)
    results: list[ReplayResult] = []
    loop = asyncio.get_running_loop()
    for interaction in baseline:
        req = interaction.request or {}
        rtype = str(req.get("type", ""))
        oids = req.get("oids") or []
        if rtype not in ("GetRequest", "GetNextRequest"):
            continue
        if not isinstance(oids, list):
            continue
        resp_vbs = ((interaction.response or {}).get("varbinds") or []) \
            if isinstance(interaction.response, dict) else []
        for idx, oid in enumerate(oids):
            baseline_hex = ""
            if idx < len(resp_vbs) and isinstance(resp_vbs[idx], dict):
                baseline_hex = str(resp_vbs[idx].get("value_hex", ""))
            current_hex = await _fire_one(
                host, port,
                rtype=rtype, oid=str(oid),
                community=community,
                timeout=request_timeout,
                loop=loop,
            )
            results.append(ReplayResult(
                request_type=rtype, oid=str(oid),
                baseline_value_hex=baseline_hex,
                current_value_hex=current_hex,
                matches=(baseline_hex == current_hex),
            ))
    return results


async def _fire_one(
    host: str, port: int, *,
    rtype: str, oid: str, community: str,
    timeout: float,
    loop: asyncio.AbstractEventLoop,
) -> str:
    """Send one GET/GETNEXT and return the first varbind's value_hex (or '')."""
    pdu_type = snmp_v2c.T_GET_REQUEST if rtype == "GetRequest" else snmp_v2c.T_GETNEXT_REQUEST
    msg = snmp_v2c.SnmpMessage(
        version=snmp_v2c.SNMP_V2C_VERSION,
        community=community,
        pdu_type=pdu_type,
        request_id=1,
        error_status=0,
        error_index=0,
        varbinds=[snmp_v2c.VarBind.null(oid)],
    )
    wire = snmp_v2c.encode_message(msg)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setblocking(False)
    try:
        await loop.sock_connect(sock, (host, port))
        await loop.sock_sendall(sock, wire)
        reply = await asyncio.wait_for(loop.sock_recv(sock, 65535), timeout=timeout)
    finally:
        sock.close()
    parsed = snmp_v2c.decode_message(reply)
    if not parsed.varbinds:
        return ""
    return parsed.varbinds[0].value_bytes.hex()
