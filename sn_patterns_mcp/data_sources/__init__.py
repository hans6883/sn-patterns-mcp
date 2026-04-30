"""Data-source knowledge base — what data is available on each managed
target type, and how ServiceNow Discovery patterns ingest it.

Catalogs:
    Windows server   → WMI classes, registry hives, PowerShell, perf counters
    Linux server     → /proc, /sys, /etc files, common shell commands
    F5 BIG-IP        → tmsh CLI, iControl REST, SNMP F5-BIGIP-* MIBs
    Cisco IOS/NX-OS  → show CLI, SNMP CISCO-* MIBs, NETCONF
    VMware ESXi      → vim-cmd, esxcli, REST API, SNMP VMWARE-* MIBs
    Generic SNMP     → standard IETF MIBs (already in oids/)

Each data point catalogs:
    name            short identifier (e.g. "Win32_OperatingSystem")
    target          os/device family it lives on
    access_method   how to query it (wmi, registry, command, file, snmp, rest)
    closure         which SN NDL closure typically ingests it
    typical_ci      what CI table/attribute it usually populates
    description     human-readable
    example_query   example invocation (e.g. WMI WQL or CLI command)
"""
from __future__ import annotations

import json
import logging
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path

log = logging.getLogger(__name__)

_DATA_DIR = Path(__file__).parent / "data"


@dataclass(frozen=True)
class DataPoint:
    name: str
    target: str           # 'windows' | 'linux' | 'f5' | 'cisco-ios' | 'esxi' | 'generic'
    access_method: str    # 'wmi' | 'registry' | 'command' | 'file' | 'snmp' | 'rest' | 'tmsh' | 'powershell'
    closure: str          # NDL closure that typically ingests this (e.g. 'run_wmi_query_to_var')
    description: str
    typical_ci: str = ""           # 'cmdb_ci_win_server.os_version' or 'cmdb_ci_lb_service'
    example_query: str = ""        # WQL / CLI / OID / API path
    fields: tuple[str, ...] = ()   # subfields/columns this data point exposes

    @property
    def key(self) -> str:
        return f"{self.target}:{self.name}"


@dataclass
class DataSourceRegistry:
    """In-memory catalog of every documented data point across all target types."""
    by_key: dict[str, DataPoint] = field(default_factory=dict)
    by_target: dict[str, list[DataPoint]] = field(default_factory=dict)
    by_closure: dict[str, list[DataPoint]] = field(default_factory=dict)
    by_name_prefix: dict[str, list[DataPoint]] = field(default_factory=dict)

    def add(self, dp: DataPoint) -> None:
        self.by_key[dp.key] = dp
        self.by_target.setdefault(dp.target, []).append(dp)
        self.by_closure.setdefault(dp.closure, []).append(dp)

    def lookup(self, query: str, target: str | None = None) -> list[DataPoint]:
        """Match a data-point name (e.g. 'Win32_Service' or 'tmsh list ltm virtual')
        against the catalog. Optional target filter."""
        q = query.strip().lower()
        out: list[DataPoint] = []
        for dp in self.by_key.values():
            if target and dp.target != target:
                continue
            if q in dp.name.lower() or q in dp.example_query.lower() or q in dp.description.lower():
                out.append(dp)
        return out

    def for_target(self, target: str) -> list[DataPoint]:
        return self.by_target.get(target, [])

    def for_closure(self, closure: str) -> list[DataPoint]:
        return self.by_closure.get(closure, [])

    def size(self) -> int:
        return len(self.by_key)

    def iter_all(self) -> Iterator[DataPoint]:
        yield from self.by_key.values()


def _load() -> DataSourceRegistry:
    reg = DataSourceRegistry()
    if not _DATA_DIR.exists():
        log.warning("data-sources data dir missing: %s", _DATA_DIR)
        return reg
    for path in sorted(_DATA_DIR.glob("*.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as e:
            log.warning("Skipping malformed data-source file %s: %s", path, e)
            continue
        target = data.get("target", path.stem)
        for raw in data.get("data_points", []):
            try:
                dp = DataPoint(
                    name=raw["name"],
                    target=raw.get("target", target),
                    access_method=raw["access_method"],
                    closure=raw["closure"],
                    description=raw.get("description", ""),
                    typical_ci=raw.get("typical_ci", ""),
                    example_query=raw.get("example_query", ""),
                    fields=tuple(raw.get("fields", ())),
                )
            except KeyError as e:
                log.warning("Skipping data-point in %s missing %s", path, e)
                continue
            reg.add(dp)
    log.info("Data-source registry: %d data points across %d target families",
             reg.size(), len(reg.by_target))
    return reg


# Lazy registry — built on first access (small, but consistent with OID lazy-load)
class _LazyDataSources:
    __slots__ = ("_real",)

    def __init__(self) -> None:
        self._real: DataSourceRegistry | None = None

    def _ensure(self) -> DataSourceRegistry:
        if self._real is None:
            self._real = _load()
        return self._real

    def lookup(self, query: str, target: str | None = None) -> list[DataPoint]:
        return self._ensure().lookup(query, target)

    def for_target(self, target: str) -> list[DataPoint]:
        return self._ensure().for_target(target)

    def for_closure(self, closure: str) -> list[DataPoint]:
        return self._ensure().for_closure(closure)

    def size(self) -> int:
        return self._ensure().size()

    def iter_all(self) -> Iterator[DataPoint]:
        return self._ensure().iter_all()


REGISTRY: _LazyDataSources = _LazyDataSources()


def lookup(query: str, target: str | None = None) -> list[DataPoint]:
    return REGISTRY.lookup(query, target)


def for_target(target: str) -> list[DataPoint]:
    return REGISTRY.for_target(target)


def for_closure(closure: str) -> list[DataPoint]:
    return REGISTRY.for_closure(closure)


__all__ = ["DataPoint", "DataSourceRegistry", "REGISTRY", "lookup", "for_target", "for_closure"]
