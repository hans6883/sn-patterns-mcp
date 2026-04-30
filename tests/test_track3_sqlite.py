"""SQLite-backed OID store: schema, writer, reader, FTS5 search."""
from __future__ import annotations

from pathlib import Path

import pytest

from sn_patterns_mcp.oids import OidEntry, OidRegistry, _SqliteBackend
from sn_patterns_mcp.oids.db import OidStore, build_db

# Fixture: a small synthetic corpus exercising every interesting case
SYNTHETIC_ENTRIES = {
    "SNMPv2-MIB": [
        {"oid": "1.3.6.1.2.1.1", "name": "system", "syntax": "OBJECT IDENTIFIER",
         "access": "not-accessible", "description": "System group root."},
        {"oid": "1.3.6.1.2.1.1.1", "name": "sysDescr", "syntax": "DisplayString",
         "access": "read-only", "description": "Textual description of the entity."},
        {"oid": "1.3.6.1.2.1.1.5", "name": "sysName", "syntax": "DisplayString",
         "access": "read-write", "description": "Administratively-assigned name."},
    ],
    "IF-MIB": [
        {"oid": "1.3.6.1.2.1.2.2", "name": "ifTable", "syntax": "SEQUENCE OF IfEntry",
         "access": "not-accessible", "description": "Interface table.", "is_table": True},
        {"oid": "1.3.6.1.2.1.2.2.1", "name": "ifEntry", "syntax": "IfEntry",
         "access": "not-accessible", "description": "An interface entry."},
        {"oid": "1.3.6.1.2.1.2.2.1.5", "name": "ifSpeed", "syntax": "Gauge32",
         "access": "read-only", "description": "Interface bandwidth in bits per second.",
         "is_columnar": True},
        {"oid": "1.3.6.1.2.1.2.2.1.14", "name": "ifInErrors", "syntax": "Counter32",
         "access": "read-only", "description": "Inbound packet errors that prevented delivery.",
         "is_columnar": True},
    ],
    "VENDOR-WEIRD-MIB": [
        # Real corpus pollution: vendor mis-claims a child of sysName
        {"oid": "1.3.6.1.2.1.1.5.0", "name": "vendorTrap", "syntax": "Integer32",
         "access": "read-only", "description": "Vendor's misuse of standard tree."},
    ],
}

SYNTHETIC_VENDORS = [
    ("1.3.6.1.4.1.9", "Cisco Systems", "Cisco network devices"),
    ("1.3.6.1.4.1.2636", "Juniper Networks", "Juniper routers"),
]


@pytest.fixture
def db_path(tmp_path: Path) -> Path:
    """Build a fresh synthetic SQLite DB for each test."""
    p = tmp_path / "oids.db"
    build_db(
        db_path=p,
        entries_by_mib=SYNTHETIC_ENTRIES,
        vendor_prefixes=SYNTHETIC_VENDORS,
        standard_mibs={"SNMPv2-MIB", "IF-MIB"},
        mib_imports={"IF-MIB": ["SNMPv2-SMI", "SNMPv2-TC"]},
    )
    return p


# ---------------------------------------------------------------------------
# Writer
# ---------------------------------------------------------------------------

class TestBuildDb:
    def test_db_file_created(self, db_path: Path) -> None:
        assert db_path.exists()
        assert db_path.stat().st_size > 0

    def test_rows_inserted(self, db_path: Path) -> None:
        store = OidStore(db_path)
        stats = store.stats()
        assert stats["mibs"] == 3
        assert stats["entries"] == 8
        assert stats["standard_mibs"] == 2

    def test_idempotent_rebuild(self, tmp_path: Path) -> None:
        """Building twice over the same path yields the same DB."""
        p = tmp_path / "oids.db"
        for _ in range(2):
            build_db(p, SYNTHETIC_ENTRIES, SYNTHETIC_VENDORS, {"SNMPv2-MIB", "IF-MIB"})
        store = OidStore(p)
        assert store.stats()["entries"] == 8


# ---------------------------------------------------------------------------
# OidStore (low-level reads)
# ---------------------------------------------------------------------------

class TestOidStore:
    def test_get_by_oid(self, db_path: Path) -> None:
        row = OidStore(db_path).get_by_oid("1.3.6.1.2.1.1.5")
        assert row is not None
        assert row.name == "sysName"
        assert row.mib == "SNMPv2-MIB"

    def test_get_by_oid_missing_returns_none(self, db_path: Path) -> None:
        assert OidStore(db_path).get_by_oid("9.9.9.9") is None

    def test_get_by_name_prefers_standard_mib(self, tmp_path: Path) -> None:
        p = tmp_path / "oids.db"
        build_db(
            db_path=p,
            entries_by_mib={
                "SNMPv2-MIB": [{"oid": "1.3.6.1.2.1.1.5", "name": "sysName",
                                "syntax": "", "access": "", "description": "standard"}],
                "VENDOR-MIB": [{"oid": "1.3.6.1.4.1.999.1", "name": "sysName",
                                "syntax": "", "access": "", "description": "vendor"}],
            },
            vendor_prefixes=[],
            standard_mibs={"SNMPv2-MIB"},
        )
        # Name lookup should prefer the standard MIB
        row = OidStore(p).get_by_name("sysName")
        assert row is not None
        assert row.mib == "SNMPv2-MIB"

    def test_children_returns_all(self, db_path: Path) -> None:
        kids = OidStore(db_path).children("1.3.6.1.2.1.2.2.1")
        # ifEntry has 2 columns in our fixture: ifSpeed, ifInErrors
        names = {k.name for k in kids}
        assert "ifSpeed" in names
        assert "ifInErrors" in names

    def test_fts_search_finds_by_description(self, db_path: Path) -> None:
        hits = OidStore(db_path).fts_search("inbound packet errors")
        names = {h.name for h in hits}
        assert "ifInErrors" in names

    def test_fts_search_finds_by_name_word(self, db_path: Path) -> None:
        hits = OidStore(db_path).fts_search("ifSpeed")
        assert any(h.name == "ifSpeed" for h in hits)

    def test_fts_search_empty_query_returns_empty(self, db_path: Path) -> None:
        assert OidStore(db_path).fts_search("") == []
        assert OidStore(db_path).fts_search("   ") == []

    def test_iter_all_yields_every_row(self, db_path: Path) -> None:
        rows = list(OidStore(db_path).iter_all())
        assert len(rows) == 8


# ---------------------------------------------------------------------------
# OidRegistry on a SQLite backend
# ---------------------------------------------------------------------------

class TestSqliteBackedRegistry:
    def _registry(self, db_path: Path) -> OidRegistry:
        return OidRegistry(_SqliteBackend(db_path))

    def test_lookup_by_oid(self, db_path: Path) -> None:
        e = self._registry(db_path).lookup("1.3.6.1.2.1.1.5")
        assert e is not None
        assert e.name == "sysName"

    def test_lookup_by_name(self, db_path: Path) -> None:
        e = self._registry(db_path).lookup("sysName")
        assert e is not None
        assert e.oid == "1.3.6.1.2.1.1.5"

    def test_lookup_columnar_walks_up(self, db_path: Path) -> None:
        # 1.3.6.1.2.1.2.2.1.5.42 → ifSpeed for instance 42
        e = self._registry(db_path).lookup("1.3.6.1.2.1.2.2.1.5.42")
        assert e is not None
        assert e.name == "ifSpeed"

    def test_lookup_strips_leading_dot(self, db_path: Path) -> None:
        e = self._registry(db_path).lookup(".1.3.6.1.2.1.1.5")
        assert e is not None and e.name == "sysName"

    def test_walk_filters_cross_authority(self, db_path: Path) -> None:
        """Vendor MIB illegally claiming child of sysName must NOT appear in walk(sysName)."""
        kids = self._registry(db_path).walk("1.3.6.1.2.1.1.5")
        assert all(k.mib != "VENDOR-WEIRD-MIB" for k in kids)

    def test_walk_recursive_iftable(self, db_path: Path) -> None:
        descendants = self._registry(db_path).walk("1.3.6.1.2.1.2.2", recursive=True)
        names = {e.name for e in descendants}
        assert "ifEntry" in names
        assert "ifSpeed" in names
        assert "ifInErrors" in names

    def test_fts_via_registry(self, db_path: Path) -> None:
        hits = self._registry(db_path).fts_search("interface bandwidth")
        assert any(h.name == "ifSpeed" for h in hits)

    def test_size_matches_corpus(self, db_path: Path) -> None:
        assert self._registry(db_path).size() == 8


# ---------------------------------------------------------------------------
# Cross-backend equivalence — dict and SQLite must give same results
# ---------------------------------------------------------------------------

class TestBackendEquivalence:
    def _entries(self) -> list[OidEntry]:
        return [
            OidEntry("1.3.6.1.2.1.1.5", "sysName", "SNMPv2-MIB", "DisplayString", "read-write",
                     "Hostname.", is_columnar=False),
            OidEntry("1.3.6.1.2.1.2.2.1.5", "ifSpeed", "IF-MIB", "Gauge32", "read-only",
                     "Interface bandwidth.", is_columnar=True),
        ]

    def test_lookup_results_match(self, tmp_path: Path) -> None:
        # Build SQLite version
        db = tmp_path / "oids.db"
        build_db(
            db_path=db,
            entries_by_mib={
                "SNMPv2-MIB": [{"oid": "1.3.6.1.2.1.1.5", "name": "sysName",
                                "syntax": "DisplayString", "access": "read-write",
                                "description": "Hostname."}],
                "IF-MIB": [{"oid": "1.3.6.1.2.1.2.2.1.5", "name": "ifSpeed",
                            "syntax": "Gauge32", "access": "read-only",
                            "description": "Interface bandwidth.", "is_columnar": True}],
            },
            vendor_prefixes=[],
            standard_mibs={"SNMPv2-MIB", "IF-MIB"},
        )
        sqlite_reg = OidRegistry(_SqliteBackend(db))
        # Build dict version
        dict_reg = OidRegistry()
        for e in self._entries():
            dict_reg.add(e)

        # Both must resolve sysName to the same entry
        s1 = sqlite_reg.lookup("sysName")
        s2 = dict_reg.lookup("sysName")
        assert s1 is not None and s2 is not None
        assert s1.oid == s2.oid
        assert s1.name == s2.name
        assert s1.mib == s2.mib
        # Both must walk-up columnar instances the same way
        assert sqlite_reg.lookup("1.3.6.1.2.1.2.2.1.5.42").name == "ifSpeed"
        assert dict_reg.lookup("1.3.6.1.2.1.2.2.1.5.42").name == "ifSpeed"
