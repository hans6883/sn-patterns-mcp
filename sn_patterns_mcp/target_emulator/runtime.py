"""EmulatorRuntime — the in-process Tier-3 sandbox.

Owns:
    * The fixture table built from a blueprint
    * The asyncio UDP listener bound to a configurable port
    * The Recorder capturing every interaction
    * The lexicographically-sorted OID index that powers GETNEXT

Lifecycle:
    rt = EmulatorRuntime.from_blueprint(blueprint, recording_path=...)
    await rt.start()                  # binds the listener
    addr = rt.snmp_address()          # ("127.0.0.1", 16100)
    # ...drive ServiceNow patterns or test traffic against `addr`...
    await rt.stop()                   # cancels listener; recorder still readable
    interactions = rt.recording.all()

This class is asyncio-native because UDP servers belong on an event loop.
The MCP server module wraps it in a running loop so an AI agent can manage
multiple emulator sessions over stdio.
"""
from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sn_patterns_mcp.target_emulator import snmp_v2c
from sn_patterns_mcp.target_emulator.fixtures import (
    SnmpFixtureEntry,
    fixtures_from_blueprint,
)
from sn_patterns_mcp.target_emulator.recording import Recorder

log = logging.getLogger(__name__)

DEFAULT_BIND_HOST = "127.0.0.1"


def _oid_tuple(oid: str) -> tuple[int, ...]:
    return tuple(int(p) for p in oid.strip().split(".") if p != "")


def _format_oid(parts: tuple[int, ...]) -> str:
    return ".".join(str(p) for p in parts)


@dataclass
class _SnmpEntry:
    """Internal table row: (parsed-OID, value-bytes ready to put in a varbind)."""

    oid_tuple: tuple[int, ...]
    oid_str: str
    snmp_type: str
    value_bytes: bytes
    name: str


def _entries_from_fixtures(fixtures: list[SnmpFixtureEntry]) -> list[_SnmpEntry]:
    rows: list[_SnmpEntry] = []
    for f in fixtures:
        try:
            ot = _oid_tuple(f.oid)
        except ValueError:
            log.warning("skipping fixture with malformed OID: %r", f.oid)
            continue
        try:
            vb = snmp_v2c.encode_value(f.snmp_type, f.value)
        except Exception as e:
            log.warning("skipping fixture %s: encoding failed (%s)", f.oid, e)
            continue
        rows.append(_SnmpEntry(
            oid_tuple=ot, oid_str=_format_oid(ot),
            snmp_type=f.snmp_type, value_bytes=vb,
            name=f.name,
        ))
    rows.sort(key=lambda r: r.oid_tuple)
    return rows


class _SnmpDatagramProtocol(asyncio.DatagramProtocol):
    """Owns the UDP transport and dispatches PDUs to the runtime resolver."""

    def __init__(self, runtime: EmulatorRuntime) -> None:
        self.runtime = runtime
        self.transport: asyncio.DatagramTransport | None = None

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.transport = transport  # type: ignore[assignment]

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        client = f"{addr[0]}:{addr[1]}"
        try:
            request = snmp_v2c.decode_message(data)
        except snmp_v2c.SnmpDecodeError as e:
            self.runtime.recording.append(
                proto="snmp", client=client,
                request={"raw_hex": data.hex()}, error=f"decode_error: {e}",
            )
            return
        if request.community != self.runtime.community:
            self.runtime.recording.append(
                proto="snmp", client=client,
                request={
                    "type": _pdu_name(request.pdu_type),
                    "request_id": request.request_id,
                    "community": request.community,
                    "oids": [vb.oid for vb in request.varbinds],
                },
                error=f"community_mismatch: expected={self.runtime.community!r}",
            )
            return
        response = snmp_v2c.build_response(request, resolver=self.runtime._resolver)
        try:
            wire = snmp_v2c.encode_message(response)
        except Exception as e:
            log.exception("response encode failed")
            self.runtime.recording.append(
                proto="snmp", client=client,
                request={
                    "type": _pdu_name(request.pdu_type),
                    "request_id": request.request_id,
                    "oids": [vb.oid for vb in request.varbinds],
                },
                error=f"encode_error: {e}",
            )
            return

        # Record after the wire has been formed; record the *resolved* OIDs the
        # client will see, not the raw requested ones. Phase 3 replay uses these.
        self.runtime.recording.append(
            proto="snmp", client=client,
            request={
                "type": _pdu_name(request.pdu_type),
                "request_id": request.request_id,
                "community": request.community,
                "oids": [vb.oid for vb in request.varbinds],
            },
            response={
                "type": "Response",
                "request_id": response.request_id,
                "error_status": response.error_status,
                "error_index": response.error_index,
                "varbinds": [
                    {"oid": vb.oid, "value_hex": vb.value_bytes.hex()}
                    for vb in response.varbinds
                ],
            },
        )
        if self.transport is not None:
            self.transport.sendto(wire, addr)


def _pdu_name(tag: int) -> str:
    return {
        snmp_v2c.T_GET_REQUEST: "GetRequest",
        snmp_v2c.T_GETNEXT_REQUEST: "GetNextRequest",
        snmp_v2c.T_RESPONSE: "Response",
    }.get(tag, f"unknown(0x{tag:02x})")


class EmulatorRuntime:
    """The Tier-3 sandbox runtime. One instance per emulated target."""

    def __init__(
        self,
        entries: list[_SnmpEntry],
        *,
        community: str = "public",
        bind_host: str = DEFAULT_BIND_HOST,
        bind_port: int = 0,
        recording_path: Path | None = None,
    ) -> None:
        self.entries = entries
        self.community = community
        self.bind_host = bind_host
        self.bind_port = bind_port
        self.recording = Recorder(recording_path)
        self._transport: asyncio.DatagramTransport | None = None
        self._protocol: _SnmpDatagramProtocol | None = None
        self._oid_index: dict[tuple[int, ...], _SnmpEntry] = {
            e.oid_tuple: e for e in entries
        }
        self._sorted_keys: list[tuple[int, ...]] = [e.oid_tuple for e in entries]

    @classmethod
    def from_blueprint(
        cls,
        blueprint: dict[str, Any],
        *,
        community: str = "public",
        bind_host: str = DEFAULT_BIND_HOST,
        bind_port: int = 0,
        recording_path: Path | None = None,
    ) -> EmulatorRuntime:
        fixtures = fixtures_from_blueprint(blueprint)
        entries = _entries_from_fixtures(fixtures)
        return cls(
            entries=entries,
            community=community,
            bind_host=bind_host,
            bind_port=bind_port,
            recording_path=recording_path,
        )

    @classmethod
    def from_oid_value_map(
        cls,
        oid_value_map: dict[str, tuple[Any, str]],
        *,
        community: str = "public",
        bind_host: str = DEFAULT_BIND_HOST,
        bind_port: int = 0,
        recording_path: Path | None = None,
    ) -> EmulatorRuntime:
        """Build directly from an {oid: (value, snmp_type)} dict — handy for tests."""
        fixtures = [
            SnmpFixtureEntry(oid=oid, value=v, snmp_type=t)
            for oid, (v, t) in oid_value_map.items()
        ]
        return cls(
            entries=_entries_from_fixtures(fixtures),
            community=community,
            bind_host=bind_host,
            bind_port=bind_port,
            recording_path=recording_path,
        )

    async def start(self) -> None:
        if self._transport is not None:
            return
        loop = asyncio.get_running_loop()
        transport, protocol = await loop.create_datagram_endpoint(
            lambda: _SnmpDatagramProtocol(self),
            local_addr=(self.bind_host, self.bind_port),
            family=0,  # let the OS pick AF_INET vs AF_INET6 based on bind_host
        )
        self._transport = transport
        self._protocol = protocol
        # OS-assigned port writeback so callers can discover it
        sock = transport.get_extra_info("socket")
        if sock is not None:
            self.bind_host, self.bind_port = sock.getsockname()[:2]

    async def stop(self) -> None:
        if self._transport is not None:
            self._transport.close()
            self._transport = None
            self._protocol = None

    def snmp_address(self) -> tuple[str, int]:
        return (self.bind_host, self.bind_port)

    def fixture_summary(self) -> dict[str, Any]:
        return {
            "fixture_count": len(self.entries),
            "first_oid": self.entries[0].oid_str if self.entries else None,
            "last_oid": self.entries[-1].oid_str if self.entries else None,
            "community": self.community,
            "bind": f"{self.bind_host}:{self.bind_port}",
            "interactions_recorded": self.recording.count(),
        }

    # ------------------------------------------------------------------ resolver
    def _resolver(self, pdu_type: int, oid: str) -> tuple[str | None, bytes]:
        try:
            requested = _oid_tuple(oid)
        except ValueError:
            return (None, snmp_v2c.enc_no_such_object())

        if pdu_type == snmp_v2c.T_GET_REQUEST:
            entry = self._oid_index.get(requested)
            if entry is None:
                # In SNMPv2c convention, missing scalar = noSuchObject;
                # missing instance under a known scalar prefix = noSuchInstance.
                # We don't track scalar prefixes separately here, so we always
                # emit noSuchObject. That's acceptable for the sandbox use case
                # (a pattern getting noSuchObject vs noSuchInstance behaves the
                # same way in practice for our patterns).
                return (None, snmp_v2c.enc_no_such_object())
            return (entry.oid_str, entry.value_bytes)

        # GETNEXT: strict lexicographic successor
        next_entry = self._strict_successor(requested)
        if next_entry is None:
            return (None, snmp_v2c.enc_end_of_mib_view())
        return (next_entry.oid_str, next_entry.value_bytes)

    def _strict_successor(self, requested: tuple[int, ...]) -> _SnmpEntry | None:
        # Linear scan is fine for fixture-scale corpora (typical SN pattern
        # touches <100 OIDs). Binary search is a 2-liner upgrade if needed.
        for key in self._sorted_keys:
            if key > requested:
                return self._oid_index[key]
        return None
