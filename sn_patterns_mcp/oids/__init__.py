"""OID / MIB knowledge base — gives AI agents semantic understanding of SNMP OIDs.

Lookup paths (all O(1) or sub-millisecond):
    lookup("1.3.6.1.2.1.1.5.0")       -> OidEntry(name="sysName", ...)
    lookup("sysName")                 -> OidEntry(...)
    walk("1.3.6.1.2.1.2.2", recursive=True) -> [ifEntry, ifIndex, ifDescr, ...]
    identify_vendor("1.3.6.1.4.1.9.1.516")  -> VendorPrefix(vendor="Cisco")
    fts_search("interface error counter")    -> [OidEntry, ...]   # full-text

Backends:
  - SQLite (preferred): oids.db built by scripts/build_oid_index.py.
    Cold start <50ms, RAM <20MB, FTS5 keyword search.
  - In-memory dicts (fallback): loads JSON files in data/. Slower but works
    without the build pipeline.

Build / refresh the corpus:
    python scripts/build_oid_index.py            # multi-source GitHub harvest
    python scripts/build_oid_index.py --refresh  # ignore cache
"""
from __future__ import annotations

import json
import logging
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path

log = logging.getLogger(__name__)

_DATA_DIR = Path(__file__).parent / "data"
_DB_PATH = Path(__file__).parent / "oids.db"


@dataclass(frozen=True)
class OidEntry:
    """A single MIB object — equivalent to one OBJECT-TYPE definition."""
    oid: str            # dotted-decimal: "1.3.6.1.2.1.1.5"
    name: str           # short name: "sysName"
    mib: str            # parent MIB: "SNMPv2-MIB"
    syntax: str         # SMI syntax: "DisplayString", "INTEGER", "Counter32", ...
    access: str         # "read-only" / "read-write" / "not-accessible" / "read-create"
    description: str    # human-readable description
    is_table: bool = False       # True for ifTable, hrStorageTable, etc.
    is_columnar: bool = False    # True for entries inside a table

    @property
    def full_name(self) -> str:
        return f"{self.mib}::{self.name}"

    @property
    def parent_oid(self) -> str:
        return self.oid.rsplit(".", 1)[0] if "." in self.oid else ""


@dataclass(frozen=True)
class VendorPrefix:
    """Enterprise OID prefix → vendor name. 1.3.6.1.4.1.<num> is the enterprise root."""
    prefix: str
    vendor: str
    description: str = ""


# Enterprise OID prefixes — used to identify the vendor of an unknown OID
# without needing the full vendor MIB. Sourced from IANA enterprise numbers.
VENDOR_PREFIXES: tuple[VendorPrefix, ...] = (
    VendorPrefix("1.3.6.1.4.1.9", "Cisco Systems", "Cisco network devices"),
    VendorPrefix("1.3.6.1.4.1.2636", "Juniper Networks", "Juniper routers/switches"),
    VendorPrefix("1.3.6.1.4.1.3375", "F5 Networks", "F5 BIG-IP"),
    VendorPrefix("1.3.6.1.4.1.789", "NetApp", "NetApp storage"),
    VendorPrefix("1.3.6.1.4.1.311", "Microsoft", "Microsoft / Windows SNMP"),
    VendorPrefix("1.3.6.1.4.1.318", "APC", "APC UPS / PDU"),
    VendorPrefix("1.3.6.1.4.1.232", "HP / HPE", "HP servers, ProLiant, iLO"),
    VendorPrefix("1.3.6.1.4.1.11", "HP", "HP printers, switches (legacy)"),
    VendorPrefix("1.3.6.1.4.1.674", "Dell", "Dell PowerEdge / iDRAC"),
    VendorPrefix("1.3.6.1.4.1.2", "IBM", "IBM hardware"),
    VendorPrefix("1.3.6.1.4.1.8072", "net-snmp", "net-snmp agent (Linux/BSD)"),
    VendorPrefix("1.3.6.1.4.1.6876", "VMware", "VMware ESXi / vCenter"),
    VendorPrefix("1.3.6.1.4.1.14988", "MikroTik", "MikroTik RouterOS"),
    VendorPrefix("1.3.6.1.4.1.25461", "Palo Alto", "Palo Alto firewalls"),
    VendorPrefix("1.3.6.1.4.1.12356", "Fortinet", "FortiGate / FortiOS"),
    VendorPrefix("1.3.6.1.4.1.30065", "Arista", "Arista EOS"),
    VendorPrefix("1.3.6.1.4.1.4526", "Netgear", "Netgear switches"),
    VendorPrefix("1.3.6.1.4.1.4413", "Brocade", "Brocade fibre channel"),
    VendorPrefix("1.3.6.1.4.1.1588", "Brocade Communications", "Brocade FC switches"),
    VendorPrefix("1.3.6.1.4.1.1991", "Foundry / Brocade IP", "Brocade IP routers"),
    VendorPrefix("1.3.6.1.4.1.43", "3Com / HP A-Series", "Legacy 3Com / HP A-series"),
    VendorPrefix("1.3.6.1.4.1.171", "D-Link", "D-Link switches"),
    VendorPrefix("1.3.6.1.4.1.2620", "Check Point", "Check Point firewalls"),
    VendorPrefix("1.3.6.1.4.1.5951", "Citrix NetScaler", "Citrix ADC / NetScaler"),
    VendorPrefix("1.3.6.1.4.1.42", "Sun / Oracle", "Sun/Oracle servers"),
)


# Authoritative IETF / IRTF MIBs — these claim OIDs in the standard tree
# (1.3.6.1.2.1.*) and must take priority over vendor MIBs that mis-redefine them.
_STANDARD_MIBS: frozenset[str] = frozenset({
    "SNMPv2-MIB", "SNMPv2-SMI", "SNMPv2-TC", "SNMPv2-CONF", "RFC1213-MIB",
    "IF-MIB", "IF-INVERTED-STACK-MIB", "EtherLike-MIB", "MAU-MIB",
    "HOST-RESOURCES-MIB", "HOST-RESOURCES-TYPES",
    "ENTITY-MIB", "ENTITY-SENSOR-MIB", "ENTITY-STATE-MIB", "ENTITY-STATE-TC-MIB",
    "IP-MIB", "IP-FORWARD-MIB", "IPV6-MIB", "IPV6-TC", "IPV6-ICMP-MIB", "IPV6-FLOW-LABEL-MIB",
    "TCP-MIB", "UDP-MIB", "ICMP-MIB",
    "BRIDGE-MIB", "Q-BRIDGE-MIB", "P-BRIDGE-MIB", "RSTP-MIB", "MSTP-MIB",
    "RMON-MIB", "RMON2-MIB", "DSMON-MIB", "TOKEN-RING-RMON-MIB", "HCNUM-TC",
    "DISMAN-EVENT-MIB", "DISMAN-SCHEDULE-MIB",
    "SNMP-FRAMEWORK-MIB", "SNMP-MPD-MIB", "SNMP-TARGET-MIB", "SNMP-NOTIFICATION-MIB",
    "SNMP-USER-BASED-SM-MIB", "SNMP-VIEW-BASED-ACM-MIB", "SNMP-COMMUNITY-MIB",
    "INET-ADDRESS-MIB", "IANA-ADDRESS-FAMILY-NUMBERS-MIB", "IANAifType-MIB",
    "IANA-LANGUAGE-MIB", "IANA-RTPROTO-MIB", "IANA-MAU-MIB", "IANA-CHARSET-MIB",
    "DIFFSERV-MIB", "DIFFSERV-CONFIG-MIB",
    "POWER-ETHERNET-MIB", "TUNNEL-MIB", "DOT3-EPON-MIB", "DOT3-OAM-MIB",
    "LLDP-MIB", "LLDP-EXT-DOT1-MIB", "LLDP-EXT-DOT3-MIB",
    "TRANSPORT-ADDRESS-MIB", "DIRECTORY-SERVER-MIB",
    "AGENTX-MIB", "FRAME-RELAY-DTE-MIB", "OSPF-MIB", "OSPFV3-MIB", "BGP4-MIB",
    "ATM-MIB", "FDDI-SMT73-MIB", "DOCS-CABLE-DEVICE-MIB",
})


def _is_compatible_authority(parent_mib: str | None, child_mib: str | None) -> bool:
    """A child should appear in walk(parent) only if it shares the parent's authority.

    Standard MIBs cross-reference each other freely. Vendor MIBs that illegally claim
    children of standard-tree parents (real corpus pollution) are filtered out.
    """
    if parent_mib is None or child_mib is None:
        return True
    if parent_mib == child_mib:
        return True
    if parent_mib in _STANDARD_MIBS and child_mib in _STANDARD_MIBS:
        return True
    return False


# ---------------------------------------------------------------------------
# OidRegistry — backend-polymorphic facade. SQLite preferred, dicts as fallback.
# ---------------------------------------------------------------------------

class OidRegistry:
    """Public facade for OID/MIB lookups.

    Two backends, chosen at construction:
      - SQLite (preferred): reads from oids.db. Cold start <50ms, RAM <20MB.
      - In-memory dicts (fallback): loads JSON files from data/. Slower but
        works without the build pipeline.

    Backwards-compatible API: lookup, walk, identify_vendor, iter_all, size.
    """

    def __init__(self, backend: _BaseBackend | None = None) -> None:
        # Default to an empty dict backend so tests can do `OidRegistry()` then
        # call `.add(entry)` to populate.
        self._backend = backend if backend is not None else _DictBackend()

    def add(self, entry: OidEntry) -> None:
        """Programmatic insert. Only works on a dict backend."""
        if not isinstance(self._backend, _DictBackend):
            raise TypeError("add() is only supported on in-memory dict-backed registries")
        self._backend.add(entry)

    def size(self) -> int:
        return self._backend.size()

    def stats(self) -> dict[str, int]:
        return self._backend.stats()

    def lookup(self, oid_or_name: str) -> OidEntry | None:
        if not oid_or_name:
            return None
        s = oid_or_name.strip()
        if s.startswith("."):
            s = s[1:]
        if _looks_like_oid(s):
            entry = self._backend.get_by_oid(s)
            if entry:
                return entry
            if s.endswith(".0"):
                entry = self._backend.get_by_oid(s[:-2])
                if entry:
                    return entry
            return self._walk_up(s)
        # Name lookup — accept "MIB::Name" or just "Name"
        if "::" in s:
            mib, name = s.split("::", 1)
            return self._backend.get_by_full_name(mib, name)
        return self._backend.get_by_name(s)

    def walk(self, prefix_oid: str, recursive: bool = False) -> list[OidEntry]:
        if not prefix_oid:
            return []
        if prefix_oid.startswith("."):
            prefix_oid = prefix_oid[1:]
        parent = self._backend.get_by_oid(prefix_oid)
        parent_mib = parent.mib if parent else None
        out: list[OidEntry] = []
        for child in self._backend.children(prefix_oid):
            if not _is_compatible_authority(parent_mib, child.mib):
                continue
            out.append(child)
            if recursive:
                out.extend(self.walk(child.oid, recursive=True))
        out.sort(key=lambda e: _oid_sort_key(e.oid))
        return out

    def identify_vendor(self, oid: str) -> VendorPrefix | None:
        if not oid:
            return None
        if oid.startswith("."):
            oid = oid[1:]
        best: VendorPrefix | None = None
        for vp in VENDOR_PREFIXES:
            if oid == vp.prefix or oid.startswith(vp.prefix + "."):
                if best is None or len(vp.prefix) > len(best.prefix):
                    best = vp
        return best

    def fts_search(self, query: str, limit: int = 25) -> list[OidEntry]:
        return self._backend.fts_search(query, limit)

    def iter_all(self) -> Iterator[OidEntry]:
        return self._backend.iter_all()

    def _walk_up(self, oid: str) -> OidEntry | None:
        """Walk up the OID hierarchy until we find a known ancestor.

        For e.g. 1.3.6.1.2.1.2.2.1.5.3 (ifSpeed for instance 3), this returns ifSpeed.
        """
        parts = oid.split(".")
        for i in range(len(parts) - 1, 0, -1):
            ancestor = ".".join(parts[:i])
            entry = self._backend.get_by_oid(ancestor)
            if entry:
                return entry
        return None


def _looks_like_oid(s: str) -> bool:
    return bool(s) and "." in s and all(p.isdigit() for p in s.split("."))


def _oid_sort_key(oid: str) -> tuple[int, ...]:
    return tuple(int(p) for p in oid.split(".") if p.isdigit())


# ---------------------------------------------------------------------------
# Backend protocol — both SQLite and dict implementations conform to this.
# ---------------------------------------------------------------------------

class _BaseBackend:
    def size(self) -> int: raise NotImplementedError
    def stats(self) -> dict[str, int]: raise NotImplementedError
    def get_by_oid(self, oid: str) -> OidEntry | None: raise NotImplementedError
    def get_by_name(self, name: str) -> OidEntry | None: raise NotImplementedError
    def get_by_full_name(self, mib: str, name: str) -> OidEntry | None: raise NotImplementedError
    def children(self, parent_oid: str) -> list[OidEntry]: raise NotImplementedError
    def fts_search(self, query: str, limit: int) -> list[OidEntry]: raise NotImplementedError
    def iter_all(self) -> Iterator[OidEntry]: raise NotImplementedError


class _SqliteBackend(_BaseBackend):
    """SQLite-backed: queries hit oids.db. Preferred at runtime."""

    def __init__(self, db_path: Path) -> None:
        from sn_patterns_mcp.oids.db import OidStore
        self._store = OidStore(db_path)

    def size(self) -> int:
        return self._store.size()

    def stats(self) -> dict[str, int]:
        return self._store.stats()

    def get_by_oid(self, oid: str) -> OidEntry | None:
        row = self._store.get_by_oid(oid)
        return _row_to_entry(row) if row else None

    def get_by_name(self, name: str) -> OidEntry | None:
        row = self._store.get_by_name(name)
        return _row_to_entry(row) if row else None

    def get_by_full_name(self, mib: str, name: str) -> OidEntry | None:
        row = self._store.get_by_full_name(mib, name)
        return _row_to_entry(row) if row else None

    def children(self, parent_oid: str) -> list[OidEntry]:
        return [_row_to_entry(r) for r in self._store.children(parent_oid)]

    def fts_search(self, query: str, limit: int) -> list[OidEntry]:
        return [_row_to_entry(r) for r in self._store.fts_search(query, limit)]

    def iter_all(self) -> Iterator[OidEntry]:
        for r in self._store.iter_all():
            yield _row_to_entry(r)


def _row_to_entry(row) -> OidEntry:
    """Convert a db.OidRow to the public OidEntry (same fields)."""
    return OidEntry(
        oid=row.oid, name=row.name, mib=row.mib,
        syntax=row.syntax, access=row.access, description=row.description,
        is_table=row.is_table, is_columnar=row.is_columnar,
    )


@dataclass
class _DictBackend(_BaseBackend):
    """Legacy in-memory dict backend. Used when oids.db is absent.

    Kept for backwards compatibility and for tests that build registries
    programmatically (e.g. TestOidRegistryUnits).
    """
    entries_by_oid: dict[str, OidEntry] = field(default_factory=dict)
    entries_by_name: dict[str, OidEntry] = field(default_factory=dict)
    children_by_parent: dict[str, list[str]] = field(default_factory=dict)
    _children_seen: dict[str, set[str]] = field(default_factory=dict)

    def add(self, entry: OidEntry) -> None:
        if entry.oid not in self.entries_by_oid:
            self.entries_by_oid[entry.oid] = entry
        self.entries_by_name.setdefault(entry.name, entry)
        self.entries_by_name[entry.full_name] = entry
        if entry.parent_oid:
            seen = self._children_seen.setdefault(entry.parent_oid, set())
            if entry.oid not in seen:
                seen.add(entry.oid)
                self.children_by_parent.setdefault(entry.parent_oid, []).append(entry.oid)

    def size(self) -> int:
        return len(self.entries_by_oid)

    def stats(self) -> dict[str, int]:
        return {"mibs": len({e.mib for e in self.entries_by_oid.values()}),
                "entries": len(self.entries_by_oid)}

    def get_by_oid(self, oid: str) -> OidEntry | None:
        return self.entries_by_oid.get(oid)

    def get_by_name(self, name: str) -> OidEntry | None:
        return self.entries_by_name.get(name)

    def get_by_full_name(self, mib: str, name: str) -> OidEntry | None:
        return self.entries_by_name.get(f"{mib}::{name}")

    def children(self, parent_oid: str) -> list[OidEntry]:
        oids = self.children_by_parent.get(parent_oid, [])
        return [self.entries_by_oid[o] for o in oids if o in self.entries_by_oid]

    def fts_search(self, query: str, limit: int) -> list[OidEntry]:
        # Fallback: substring match across name + description
        ql = query.lower()
        out: list[OidEntry] = []
        for e in self.entries_by_oid.values():
            if ql in e.name.lower() or ql in e.description.lower():
                out.append(e)
                if len(out) >= limit:
                    break
        return out

    def iter_all(self) -> Iterator[OidEntry]:
        yield from self.entries_by_oid.values()


# ---------------------------------------------------------------------------
# Loaders + module-level singleton
# ---------------------------------------------------------------------------

def _load_dict_backend() -> _DictBackend:
    """Legacy loader: scan data/*.json. Used only when oids.db is absent."""
    backend = _DictBackend()
    if not _DATA_DIR.exists():
        log.warning("OID data dir not found: %s — registry will be empty", _DATA_DIR)
        return backend

    all_files = sorted(_DATA_DIR.glob("*.json"))

    def _normalize_stem(p: Path) -> str:
        return p.stem.upper().replace("_", "-")

    standard_files = [p for p in all_files if _normalize_stem(p) in {m.upper() for m in _STANDARD_MIBS}]
    other_files = [p for p in all_files if p not in standard_files]

    for path in standard_files + other_files:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as e:
            log.warning("Skipping malformed OID data file %s: %s", path, e)
            continue
        mib = data.get("mib", path.stem)
        for raw in data.get("entries", []):
            try:
                entry = OidEntry(
                    oid=raw["oid"], name=raw["name"],
                    mib=raw.get("mib", mib) or mib,
                    syntax=raw.get("syntax", "") or "",
                    access=raw.get("access", "") or "",
                    description=raw.get("description", "") or "",
                    is_table=bool(raw.get("is_table", False)),
                    is_columnar=bool(raw.get("is_columnar", False)),
                )
            except KeyError as e:
                log.warning("Skipping OID entry in %s missing %s", path, e)
                continue
            backend.add(entry)
    log.info("Dict backend: %d OID entries from %d JSON files", backend.size(), len(all_files))
    return backend


def _make_registry() -> OidRegistry:
    """Pick the best available backend and return an OidRegistry."""
    if _DB_PATH.exists():
        try:
            backend = _SqliteBackend(_DB_PATH)
            stats = backend.stats()
            log.info("OID SQLite backend: %s entries across %s MIBs (%s standard)",
                     stats.get("entries", "?"), stats.get("mibs", "?"),
                     stats.get("standard_mibs", "?"))
            return OidRegistry(backend)
        except Exception as e:
            log.warning("Failed to open SQLite backend at %s: %s — falling back to dicts", _DB_PATH, e)
    return OidRegistry(_load_dict_backend())


# ---------------------------------------------------------------------------
# Lazy registry singleton — paying SQLite-open cost only when an OID lookup
# actually happens. The 14 MCP tools that don't touch OIDs (pattern_*, ndl_explain,
# etc.) get a free MCP server startup.
# ---------------------------------------------------------------------------

class _LazyRegistry:
    """Stand-in for OidRegistry that builds the real registry on first attribute access."""
    __slots__ = ("_real",)

    def __init__(self) -> None:
        self._real: OidRegistry | None = None

    def _ensure(self) -> OidRegistry:
        if self._real is None:
            self._real = _make_registry()
        return self._real

    def __getattr__(self, name: str):
        # Called only when self._real is missing — delegate to real registry
        return getattr(self._ensure(), name)

    # Explicit forwarders for IDE/type-checker friendliness on common methods
    def lookup(self, oid_or_name: str) -> OidEntry | None:
        return self._ensure().lookup(oid_or_name)

    def walk(self, prefix_oid: str, recursive: bool = False) -> list[OidEntry]:
        return self._ensure().walk(prefix_oid, recursive=recursive)

    def identify_vendor(self, oid: str) -> VendorPrefix | None:
        return self._ensure().identify_vendor(oid)

    def fts_search(self, query: str, limit: int = 25) -> list[OidEntry]:
        return self._ensure().fts_search(query, limit)

    def iter_all(self) -> Iterator[OidEntry]:
        return self._ensure().iter_all()

    def size(self) -> int:
        return self._ensure().size()


# Module-level lazy singleton — actual init deferred until first call
REGISTRY: _LazyRegistry = _LazyRegistry()


# ---------------------------------------------------------------------------
# Top-level convenience functions
# ---------------------------------------------------------------------------

def lookup(oid_or_name: str) -> OidEntry | None:
    return REGISTRY.lookup(oid_or_name)


def walk(prefix_oid: str, recursive: bool = False) -> list[OidEntry]:
    return REGISTRY.walk(prefix_oid, recursive=recursive)


def identify_vendor(oid: str) -> VendorPrefix | None:
    return REGISTRY.identify_vendor(oid)


def fts_search(query: str, limit: int = 25) -> list[OidEntry]:
    return REGISTRY.fts_search(query, limit)


def all_entries() -> Iterator[OidEntry]:
    return REGISTRY.iter_all()


def reload() -> int:
    """Re-instantiate the registry (e.g., after a fresh build_oid_index run)."""
    global REGISTRY
    REGISTRY = _LazyRegistry()
    # Force a build immediately so callers see fresh data
    return REGISTRY.size()


# ---------------------------------------------------------------------------
# Programmatic registry construction (used by tests + ad-hoc scripts)
# ---------------------------------------------------------------------------

def make_dict_registry(*entries: OidEntry) -> OidRegistry:
    """Build an in-memory registry from a list of OidEntry objects."""
    backend = _DictBackend()
    for e in entries:
        backend.add(e)
    return OidRegistry(backend)


__all__ = [
    "OidEntry", "VendorPrefix", "OidRegistry",
    "REGISTRY", "VENDOR_PREFIXES",
    "lookup", "walk", "identify_vendor", "fts_search", "all_entries", "reload",
    "make_dict_registry",
]
