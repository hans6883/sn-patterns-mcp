"""Track 3: OID/MIB intelligence — registry, lookup, walk, vendor identification, tools."""
from __future__ import annotations

from pathlib import Path

import pytest

from sn_patterns_mcp import oids
from sn_patterns_mcp.oids import OidEntry, OidRegistry, VendorPrefix
from sn_patterns_mcp.tools import (
    oid_lookup,
    oid_walk_explain,
    pattern_snmp_audit,
)

# ---------------------------------------------------------------------------
# Registry primitives — independent of bundled data
# ---------------------------------------------------------------------------

class TestOidRegistryUnits:
    def _registry_with(self, *entries: OidEntry) -> OidRegistry:
        reg = OidRegistry()
        for e in entries:
            reg.add(e)
        return reg

    def test_lookup_by_oid(self) -> None:
        reg = self._registry_with(
            OidEntry("1.3.6.1.2.1.1.5", "sysName", "SNMPv2-MIB", "DisplayString", "read-write", "Hostname."),
        )
        e = reg.lookup("1.3.6.1.2.1.1.5")
        assert e is not None and e.name == "sysName"

    def test_lookup_strips_leading_dot(self) -> None:
        reg = self._registry_with(
            OidEntry("1.3.6.1.2.1.1.5", "sysName", "SNMPv2-MIB", "DisplayString", "read-write", ""),
        )
        assert reg.lookup(".1.3.6.1.2.1.1.5") is not None

    def test_lookup_strips_trailing_zero_for_scalar(self) -> None:
        reg = self._registry_with(
            OidEntry("1.3.6.1.2.1.1.5", "sysName", "SNMPv2-MIB", "DisplayString", "read-write", ""),
        )
        # SNMP scalars have a trailing .0 instance — registry stores the column OID
        e = reg.lookup("1.3.6.1.2.1.1.5.0")
        assert e is not None and e.name == "sysName"

    def test_lookup_walks_up_to_columnar_parent(self) -> None:
        # Real example: 1.3.6.1.2.1.2.2.1.5.3 is ifSpeed for ifIndex=3
        reg = self._registry_with(
            OidEntry("1.3.6.1.2.1.2.2.1.5", "ifSpeed", "IF-MIB", "Gauge32", "read-only",
                     "Estimate of bandwidth in bits per second.", is_columnar=True),
        )
        e = reg.lookup("1.3.6.1.2.1.2.2.1.5.3")
        assert e is not None and e.name == "ifSpeed"

    def test_lookup_by_short_name(self) -> None:
        reg = self._registry_with(
            OidEntry("1.3.6.1.2.1.1.5", "sysName", "SNMPv2-MIB", "DisplayString", "read-write", ""),
        )
        e = reg.lookup("sysName")
        assert e is not None and e.oid == "1.3.6.1.2.1.1.5"

    def test_lookup_by_full_qualified_name(self) -> None:
        reg = self._registry_with(
            OidEntry("1.3.6.1.2.1.1.5", "sysName", "SNMPv2-MIB", "DisplayString", "read-write", ""),
        )
        assert reg.lookup("SNMPv2-MIB::sysName") is not None

    def test_lookup_unknown_returns_none(self) -> None:
        reg = OidRegistry()
        assert reg.lookup("9.9.9.9.9") is None
        assert reg.lookup("nonexistentName") is None
        assert reg.lookup("") is None

    def test_walk_returns_immediate_children_sorted(self) -> None:
        reg = self._registry_with(
            OidEntry("1.3.6.1.2.1.1.1", "sysDescr", "SNMPv2-MIB", "", "", ""),
            OidEntry("1.3.6.1.2.1.1.5", "sysName", "SNMPv2-MIB", "", "", ""),
            OidEntry("1.3.6.1.2.1.1.3", "sysUpTime", "SNMPv2-MIB", "", "", ""),
            OidEntry("1.3.6.1.2.1.1.7", "sysServices", "SNMPv2-MIB", "", "", ""),
        )
        kids = reg.walk("1.3.6.1.2.1.1")
        assert [k.name for k in kids] == ["sysDescr", "sysUpTime", "sysName", "sysServices"]

    def test_walk_recursive(self) -> None:
        reg = self._registry_with(
            OidEntry("1.3.6.1.2.1.2.2", "ifTable", "IF-MIB", "", "", "", is_table=True),
            OidEntry("1.3.6.1.2.1.2.2.1", "ifEntry", "IF-MIB", "", "", ""),
            OidEntry("1.3.6.1.2.1.2.2.1.1", "ifIndex", "IF-MIB", "", "", "", is_columnar=True),
            OidEntry("1.3.6.1.2.1.2.2.1.2", "ifDescr", "IF-MIB", "", "", "", is_columnar=True),
        )
        all_descs = reg.walk("1.3.6.1.2.1.2.2", recursive=True)
        names = [e.name for e in all_descs]
        assert "ifEntry" in names
        assert "ifIndex" in names
        assert "ifDescr" in names

    def test_walk_filters_cross_authority_children(self) -> None:
        """A vendor MIB illegally claiming a child of a standard-tree parent
        must NOT appear in walk() output of that parent."""
        reg = self._registry_with(
            OidEntry("1.3.6.1.2.1.1.5", "sysName", "RFC1213-MIB", "DisplayString", "read-write", ""),
            # Real corpus pollution: a vendor MIB declared `flashTrap ::= { sysName 0 }`
            OidEntry("1.3.6.1.2.1.1.5.0", "flashTrap", "VENDOR-PROPRIETARY-MIB", "", "", ""),
            # A legitimate sibling from a standard MIB
            OidEntry("1.3.6.1.2.1.1.6", "sysLocation", "RFC1213-MIB", "DisplayString", "read-write", ""),
        )
        # walk(system) — should include sysName and sysLocation but NOT flashTrap
        # (that's filtered because parent is sysName but flashTrap's parent should be sysName-as-RFC1213, not as sysName-the-vendor-anchor)
        # And walk(sysName) should NOT include the vendor flashTrap
        kids_of_sysname = reg.walk("1.3.6.1.2.1.1.5")
        assert all(k.mib != "VENDOR-PROPRIETARY-MIB" for k in kids_of_sysname)

    def test_identify_vendor_longest_prefix_wins(self) -> None:
        reg = OidRegistry()
        # 1.3.6.1.4.1.9 is Cisco
        v = reg.identify_vendor("1.3.6.1.4.1.9.1.516")
        assert v is not None and v.vendor == "Cisco Systems"

    def test_identify_vendor_strips_leading_dot(self) -> None:
        reg = OidRegistry()
        v = reg.identify_vendor(".1.3.6.1.4.1.9.1.1")
        assert v is not None and v.vendor == "Cisco Systems"

    def test_identify_vendor_unknown_returns_none(self) -> None:
        reg = OidRegistry()
        assert reg.identify_vendor("1.3.6.1.4.1.99999.99") is None
        assert reg.identify_vendor("1.3.6.1.2.1.1.5") is None  # standard, not enterprise


# ---------------------------------------------------------------------------
# Bundled data — these tests assume the seed JSONs exist (they ship with the repo)
# ---------------------------------------------------------------------------

class TestBundledMibs:
    def test_sysname_resolvable_by_oid(self) -> None:
        e = oids.lookup("1.3.6.1.2.1.1.5")
        assert e is not None
        assert e.name == "sysName"
        # Either RFC1213-MIB (original) or SNMPv2-MIB (re-publication) is correct.
        assert e.mib in ("SNMPv2-MIB", "RFC1213-MIB")

    def test_sysname_resolvable_by_name(self) -> None:
        e = oids.lookup("sysName")
        assert e is not None
        assert e.oid == "1.3.6.1.2.1.1.5"

    def test_ifspeed_columnar_instance_walks_up(self) -> None:
        e = oids.lookup("1.3.6.1.2.1.2.2.1.5.42")
        assert e is not None
        assert e.name == "ifSpeed"

    def test_iftable_marked_as_table(self) -> None:
        e = oids.lookup("1.3.6.1.2.1.2.2")
        assert e is not None
        assert e.is_table

    def test_walk_iftable_finds_columns(self) -> None:
        # ifTable → ifEntry → columns
        descendants = oids.walk("1.3.6.1.2.1.2.2", recursive=True)
        names = {e.name for e in descendants}
        # Core ifEntry columns must be present
        assert "ifIndex" in names
        assert "ifDescr" in names
        assert "ifSpeed" in names

    def test_cisco_oid_identified(self) -> None:
        v = oids.identify_vendor("1.3.6.1.4.1.9.5.1.3.1.1.1.1")
        assert v is not None and v.vendor == "Cisco Systems"

    def test_juniper_oid_identified(self) -> None:
        v = oids.identify_vendor("1.3.6.1.4.1.2636.3.1.2.0")
        assert v is not None and "Juniper" in v.vendor


# ---------------------------------------------------------------------------
# oid_lookup tool
# ---------------------------------------------------------------------------

class TestOidLookupTool:
    def test_returns_full_descriptor_for_known_oid(self) -> None:
        out = oid_lookup("1.3.6.1.2.1.1.5")
        assert "sysName" in out
        # Either RFC1213-MIB (original 1991) or SNMPv2-MIB (1996 update) is correct.
        assert ("SNMPv2-MIB" in out) or ("RFC1213-MIB" in out)

    def test_lookup_by_name_works(self) -> None:
        out = oid_lookup("sysName")
        assert "1.3.6.1.2.1.1.5" in out

    def test_unknown_enterprise_oid_returns_vendor(self) -> None:
        # Cisco-private OID we don't have in registry
        out = oid_lookup("1.3.6.1.4.1.9.999.999.999")
        assert "Cisco Systems" in out

    def test_completely_unknown_oid_returns_not_found(self) -> None:
        out = oid_lookup("9.9.9.9")
        assert "not found" in out.lower()

    def test_empty_input_returns_error(self) -> None:
        out = oid_lookup("")
        assert "ERROR" in out

    def test_columnar_lookup_walks_up(self) -> None:
        out = oid_lookup("1.3.6.1.2.1.2.2.1.5.42")
        assert "ifSpeed" in out


class TestOidWalkExplainTool:
    def test_walk_iftable_lists_columns(self) -> None:
        out = oid_walk_explain("1.3.6.1.2.1.2.2")
        assert "ifIndex" in out
        assert "ifDescr" in out

    def test_walk_unknown_returns_no_children(self) -> None:
        out = oid_walk_explain("9.9.9.9.9")
        assert "No children" in out or "not in registry" in out

    def test_walk_table_includes_iteration_hint(self) -> None:
        out = oid_walk_explain("1.3.6.1.2.1.2.2")
        assert "GET-NEXT" in out or "walk" in out.lower()


# ---------------------------------------------------------------------------
# pattern_snmp_audit tool — operates on a parsed Pattern
# ---------------------------------------------------------------------------

SNMP_PATTERN_NDL = '''pattern {
    metadata {
        id = "00000000000000000000000000000099"
        name = "TestSnmpPattern"
        citype = "cmdb_ci_netgear"
    }
    identification {
        name = "i"
        find_process_strategy {strategy = NONE}
        step {
            name = "get sysName"
            run_snmp_to_var {
                oid = "1.3.6.1.2.1.1.5"
                var_names = "hostname"
            }
        }
        step {
            name = "get sysDescr"
            run_snmp_to_var {
                oid = "1.3.6.1.2.1.1.1"
                var_names = "descr"
            }
        }
        step {
            name = "get unknown vendor OID"
            run_snmp_to_var {
                oid = "1.3.6.1.4.1.9.999.999"
                var_names = "vendor_data"
            }
        }
    }
}'''


class TestPatternSnmpAudit:
    def test_resolves_each_snmp_op(self) -> None:
        # Build a fake index that returns the pattern when asked
        from sn_patterns_mcp.ndl_parser import NdlParser
        parsed = NdlParser().parse(SNMP_PATTERN_NDL)

        class FakeIndex:
            local = None
            def get(self, key):
                return parsed
            def metadata_for(self, key):
                return {"name": "TestSnmpPattern", "ci_type": "cmdb_ci_netgear", "sys_id": parsed.metadata.id}
            manifest = {parsed.metadata.id: {"name": "TestSnmpPattern"}}
            def resolve_sys_id(self, key):
                return parsed.metadata.id
            def has_ndl_cache(self, sys_id):
                return False

        out = pattern_snmp_audit("TestSnmpPattern", index=FakeIndex(), pdi=None)
        # Should resolve the two standard OIDs
        assert "sysName" in out
        assert "sysDescr" in out
        # Should identify Cisco for the vendor-private OID
        assert "Cisco" in out
        # Should report vendor dependency
        assert "VENDOR DEPENDENCIES" in out

    def test_pattern_with_no_snmp_ops(self) -> None:
        from sn_patterns_mcp.ndl_parser import NdlParser
        non_snmp = '''pattern {
            metadata {id = "x" name = "NonSnmp" citype = "cmdb_ci_appl"}
            identification {
                name = "i"
                find_process_strategy {strategy = LISTENING_PORT}
                step {name = "s" set_attr {"name" "literal"}}
            }
        }'''
        parsed = NdlParser().parse(non_snmp)

        class FakeIndex:
            local = None
            manifest = {parsed.metadata.id: {"name": "NonSnmp"}}
            def get(self, key):
                return parsed
            def metadata_for(self, key):
                return {"name": "NonSnmp", "ci_type": "cmdb_ci_appl", "sys_id": parsed.metadata.id}
            def resolve_sys_id(self, key):
                return parsed.metadata.id
            def has_ndl_cache(self, sys_id):
                return False

        out = pattern_snmp_audit("NonSnmp", index=FakeIndex(), pdi=None)
        assert "No SNMP operations" in out

    def test_pattern_not_found(self) -> None:
        class FakeIndex:
            local = None
            manifest = {}
            def get(self, key):
                return None
            def metadata_for(self, key):
                return None
            def resolve_sys_id(self, key):
                return None
            def has_ndl_cache(self, sys_id):
                return False

        out = pattern_snmp_audit("Nonexistent", index=FakeIndex(), pdi=None)
        assert "Pattern not found" in out
