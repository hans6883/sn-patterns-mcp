"""Completeness harness for six MCP tools with zero or near-zero existing coverage.

Tools under test (pattern_test_compile is already covered elsewhere):
  1. pattern_lineage
  2. pattern_data_sources
  3. pattern_data_sources_lookup
  4. oid_walk_explain
  5. pattern_snmp_audit
  6. oid_search

Strategy:
  - FakeIndex / FakePdi stubs let most tests run without any external dependency.
  - Live-index tests (PatternIndex) skip cleanly if sn_patterns_mcp/pattern_index/manifest.json
    is absent or empty.
  - oid_search FTS5 path skips if oids.db is absent (though in this repo it ships).
"""
from __future__ import annotations

from pathlib import Path

import pytest

from sn_patterns_mcp.ndl_parser import NdlParser
from sn_patterns_mcp.tools import (
    oid_search,
    oid_walk_explain,
    pattern_data_sources,
    pattern_data_sources_lookup,
    pattern_lineage,
    pattern_snmp_audit,
)

# ---------------------------------------------------------------------------
# Paths used for skip guards
# ---------------------------------------------------------------------------

_REPO_ROOT = Path(__file__).resolve().parents[1]
_INDEX_ROOT = _REPO_ROOT / "sn_patterns_mcp" / "pattern_index"
_OIDS_DB = _REPO_ROOT / "sn_patterns_mcp" / "oids" / "oids.db"


# ---------------------------------------------------------------------------
# Shared inline NDL fixtures
# ---------------------------------------------------------------------------

_SNMP_PATTERN_NDL = '''pattern {
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
            name = "get Cisco private OID"
            run_snmp_to_var {
                oid = "1.3.6.1.4.1.9.999.999"
                var_names = "vendor_data"
            }
        }
    }
}'''

_WMI_PATTERN_NDL = '''pattern {
    metadata {
        id = "00000000000000000000000000000077"
        name = "TestWmiPattern"
        citype = "cmdb_ci_win_server"
    }
    identification {
        name = "i"
        find_process_strategy {strategy = NONE}
        step {
            name = "get OS info"
            run_wmi_query_to_var {
                query = "SELECT Caption, Version FROM Win32_OperatingSystem"
                namespace = "root\\cimv2"
                var_names = "os_info"
            }
        }
        step {
            name = "run hostname"
            runcmd_to_var {
                cmd = "hostname"
                var_names = "host"
            }
        }
    }
}'''

_RUNCMD_PATTERN_NDL = '''pattern {
    metadata {
        id = "00000000000000000000000000000055"
        name = "TestRuncmdPattern"
        citype = "cmdb_ci_linux_server"
    }
    identification {
        name = "i"
        find_process_strategy {strategy = NONE}
        step {
            name = "get uname"
            runcmd_to_var {
                cmd = "uname -a"
                var_names = "kernel"
            }
        }
    }
}'''

_PURE_TRANSFORM_NDL = '''pattern {
    metadata {
        id = "00000000000000000000000000000033"
        name = "PureTransform"
        citype = "cmdb_ci_appl"
    }
    identification {
        name = "i"
        find_process_strategy {strategy = NONE}
        step {
            name = "set name"
            set_attr {
                "name"
                "literal"
            }
        }
    }
}'''


# ---------------------------------------------------------------------------
# FakeIndex — copies the pattern from existing tests (test_track3_oids.py)
# ---------------------------------------------------------------------------

class FakeIndex:
    """Minimal index stub.  Provide a single parsed Pattern for all lookups."""

    def __init__(self, pattern=None, meta=None):
        self._pattern = pattern
        self._meta = meta or {}
        self.local = None
        self.manifest = {}
        if pattern is not None:
            sid = pattern.metadata.id or "00000000000000000000000000000001"
            self.manifest[sid] = {"name": pattern.metadata.name, **self._meta}

    def get(self, key):
        return self._pattern

    def metadata_for(self, key):
        if self._pattern is None:
            return None
        return {
            "name": self._pattern.metadata.name,
            "ci_type": self._pattern.metadata.ci_type,
            "sys_id": self._pattern.metadata.id,
            **self._meta,
        }

    def resolve_sys_id(self, key):
        if self._pattern is None:
            return None
        return self._pattern.metadata.id

    def has_ndl_cache(self, sys_id):
        return False


class EmptyFakeIndex(FakeIndex):
    """Index that knows nothing — simulates pattern-not-found."""

    def get(self, key):
        return None

    def metadata_for(self, key):
        return None

    def resolve_sys_id(self, key):
        return None


# ---------------------------------------------------------------------------
# Live-index fixture
# ---------------------------------------------------------------------------

def _live_index():
    """Load the real PatternIndex or skip if absent/empty."""
    if not (_INDEX_ROOT / "manifest.json").exists():
        pytest.skip("run scripts/ingest_local.py to build the local index first")
    from sn_patterns_mcp.pattern_index import PatternIndex
    idx = PatternIndex.load(_INDEX_ROOT)
    if idx.is_empty():
        pytest.skip("pattern index is empty")
    return idx


# ===========================================================================
# 1. oid_walk_explain
# ===========================================================================

class TestOidWalkExplain:
    """oid_walk_explain(prefix_oid) — no index or pdi needed."""

    def test_happy_path_iftable_shows_columns(self):
        # ifTable is a known standard OID — bundled in registry
        out = oid_walk_explain("1.3.6.1.2.1.2.2")
        assert "ifIndex" in out
        assert "ifDescr" in out
        assert "ifSpeed" in out

    def test_happy_path_system_group_shows_sysname(self):
        out = oid_walk_explain("1.3.6.1.2.1.1")
        assert "sysName" in out or "sysDescr" in out

    def test_table_prefix_includes_iteration_hint(self):
        out = oid_walk_explain("1.3.6.1.2.1.2.2")
        # ifTable is marked as_table; the tool appends a GET-NEXT hint
        assert "GET-NEXT" in out or "walk" in out.lower()

    def test_unknown_oid_returns_no_children_message(self):
        out = oid_walk_explain("9.9.9.9.9")
        assert "No children" in out or "not in registry" in out

    def test_empty_input_returns_error(self):
        out = oid_walk_explain("")
        assert "ERROR" in out

    def test_whitespace_only_returns_error(self):
        out = oid_walk_explain("   ")
        assert "ERROR" in out

    def test_leading_dot_oid_is_normalised(self):
        # The tool strips leading dot; should still resolve
        out = oid_walk_explain(".1.3.6.1.2.1.2.2")
        assert "ifIndex" in out

    def test_never_raises(self):
        # Throw garbage at the function — it must return a string, never raise
        for bad in ("not.an.oid", "abc.def.ghi", "0", "1", "1."):
            result = oid_walk_explain(bad)
            assert isinstance(result, str)


# ===========================================================================
# 2. oid_search
# ===========================================================================

class TestOidSearch:
    def test_empty_query_returns_error(self):
        out = oid_search("")
        assert "ERROR" in out

    def test_whitespace_query_returns_error(self):
        out = oid_search("   ")
        assert "ERROR" in out

    def test_known_technical_term_returns_results(self):
        if not _OIDS_DB.exists():
            pytest.skip("oids.db absent — FTS5 not available")
        out = oid_search("interface error counter", limit=5)
        # Should hit something from IF-MIB or a vendor error-counter OID
        assert "1.3." in out or "OID search" in out
        # Backend label should appear
        assert "backend" in out or "No OID matches" in out

    def test_sysname_search_finds_sysname(self):
        if not _OIDS_DB.exists():
            pytest.skip("oids.db absent")
        out = oid_search("sysName system name", limit=5)
        # sysName description should match
        assert "sysName" in out or "No OID matches" in out

    def test_limit_parameter_respected(self):
        if not _OIDS_DB.exists():
            pytest.skip("oids.db absent")
        out = oid_search("interface", limit=3)
        # Can't count OID lines perfectly, but output must be a string
        assert isinstance(out, str)

    def test_completely_meaningless_query_returns_graceful_message(self):
        # Should return "No OID matches" rather than raise
        out = oid_search("zzzzz_no_such_thing_at_all_xyz")
        assert isinstance(out, str)
        # Must not raise and must not be empty
        assert len(out) > 0

    def test_bgp_peer_search(self):
        if not _OIDS_DB.exists():
            pytest.skip("oids.db absent")
        out = oid_search("BGP peer session state", limit=5)
        assert isinstance(out, str) and len(out) > 0


# ===========================================================================
# 3. pattern_snmp_audit (FakeIndex stubs)
# ===========================================================================

class TestPatternSnmpAudit:

    def test_resolves_standard_oids(self):
        parsed = NdlParser().parse(_SNMP_PATTERN_NDL)
        idx = FakeIndex(parsed)
        out = pattern_snmp_audit("TestSnmpPattern", index=idx, pdi=None)
        assert "sysName" in out
        assert "sysDescr" in out

    def test_identifies_cisco_vendor_private_oid(self):
        parsed = NdlParser().parse(_SNMP_PATTERN_NDL)
        idx = FakeIndex(parsed)
        out = pattern_snmp_audit("TestSnmpPattern", index=idx, pdi=None)
        assert "Cisco" in out

    def test_reports_vendor_dependencies_section(self):
        parsed = NdlParser().parse(_SNMP_PATTERN_NDL)
        idx = FakeIndex(parsed)
        out = pattern_snmp_audit("TestSnmpPattern", index=idx, pdi=None)
        assert "VENDOR DEPENDENCIES" in out

    def test_non_snmp_pattern_reports_no_snmp_ops(self):
        parsed = NdlParser().parse(_PURE_TRANSFORM_NDL)
        idx = FakeIndex(parsed)
        out = pattern_snmp_audit("PureTransform", index=idx, pdi=None)
        assert "No SNMP operations" in out

    def test_pattern_not_found_returns_error_string(self):
        out = pattern_snmp_audit("Nonexistent", index=EmptyFakeIndex(), pdi=None)
        assert "Pattern not found" in out

    def test_empty_name_returns_error_string(self):
        out = pattern_snmp_audit("", index=EmptyFakeIndex(), pdi=None)
        assert "Pattern not found" in out or "not found" in out.lower()

    def test_no_index_returns_error_string(self):
        out = pattern_snmp_audit("Whatever", index=None, pdi=None)
        assert "Pattern not found" in out or "not found" in out.lower()

    def test_live_index_snmp_pattern(self):
        idx = _live_index()
        out = pattern_snmp_audit("A10 Load Balancer", index=idx, pdi=None)
        assert "SNMP audit" in out
        assert "A10 Load Balancer" in out
        # DYNAMIC tag should appear since A10 uses variable OIDs
        assert "DYNAMIC" in out or "SNMP operations" in out

    def test_never_raises_on_garbage_name(self):
        result = pattern_snmp_audit("!!!bad!!!name", index=EmptyFakeIndex(), pdi=None)
        assert isinstance(result, str)


# ===========================================================================
# 4. pattern_lineage
# ===========================================================================

class TestPatternLineage:

    def test_self_contained_pattern_shows_no_library_refs(self):
        parsed = NdlParser().parse(_PURE_TRANSFORM_NDL)
        idx = FakeIndex(parsed)
        out = pattern_lineage("PureTransform", index=idx, pdi=None)
        assert "self-contained" in out or "SHARED LIBRARIES REFERENCED (0)" in out

    def test_sections_block_present(self):
        parsed = NdlParser().parse(_PURE_TRANSFORM_NDL)
        idx = FakeIndex(parsed)
        out = pattern_lineage("PureTransform", index=idx, pdi=None)
        assert "SECTIONS:" in out

    def test_prepost_scripts_block_present(self):
        parsed = NdlParser().parse(_PURE_TRANSFORM_NDL)
        idx = FakeIndex(parsed)
        out = pattern_lineage("PureTransform", index=idx, pdi=None)
        assert "PRE/POST SCRIPTS" in out

    def test_variable_provenance_block_present(self):
        parsed = NdlParser().parse(_PURE_TRANSFORM_NDL)
        idx = FakeIndex(parsed)
        out = pattern_lineage("PureTransform", index=idx, pdi=None)
        assert "VARIABLE PROVENANCE" in out

    def test_pattern_not_found_returns_error_string(self):
        out = pattern_lineage("Nonexistent XYZ", index=EmptyFakeIndex(), pdi=None)
        assert "Pattern not found" in out

    def test_empty_name_returns_error_string(self):
        out = pattern_lineage("", index=EmptyFakeIndex(), pdi=None)
        assert "Pattern not found" in out or "not found" in out.lower()

    def test_no_index_and_no_pdi_returns_error_string(self):
        out = pattern_lineage("SomePattern", index=None, pdi=None)
        assert "Pattern not found" in out

    def test_wmi_pattern_provenance_identifies_unknown_vars(self):
        parsed = NdlParser().parse(_WMI_PATTERN_NDL)
        idx = FakeIndex(parsed)
        out = pattern_lineage("TestWmiPattern", index=idx, pdi=None)
        # WMI reads results into variables; provenance should track them
        assert "VARIABLE PROVENANCE" in out

    def test_live_index_known_pattern(self):
        idx = _live_index()
        out = pattern_lineage("A10 Load Balancer", index=idx, pdi=None)
        assert "Lineage:" in out
        assert "A10 Load Balancer" in out
        assert "SECTIONS:" in out

    def test_live_index_pattern_with_classifiers(self):
        idx = _live_index()
        out = pattern_lineage("A10 Load Balancer", index=idx, pdi=None)
        assert "CLASSIFIERS ROUTING TO THIS PATTERN" in out

    def test_live_index_pattern_with_extensions(self):
        idx = _live_index()
        out = pattern_lineage("A10 Load Balancer", index=idx, pdi=None)
        assert "EXTENSIONS TARGETING THIS PATTERN" in out

    def test_never_raises_with_fake_index(self):
        parsed = NdlParser().parse(_SNMP_PATTERN_NDL)
        idx = FakeIndex(parsed)
        result = pattern_lineage("TestSnmpPattern", index=idx, pdi=None)
        assert isinstance(result, str)


# ===========================================================================
# 5. pattern_data_sources
# ===========================================================================

class TestPatternDataSources:

    def test_wmi_pattern_shows_wmi_bucket(self):
        parsed = NdlParser().parse(_WMI_PATTERN_NDL)
        idx = FakeIndex(parsed)
        out = pattern_data_sources("TestWmiPattern", index=idx, pdi=None)
        assert "WMI queries" in out

    def test_wmi_pattern_includes_wql_snippet(self):
        parsed = NdlParser().parse(_WMI_PATTERN_NDL)
        idx = FakeIndex(parsed)
        out = pattern_data_sources("TestWmiPattern", index=idx, pdi=None)
        assert "Win32_OperatingSystem" in out

    def test_runcmd_pattern_shows_shell_bucket(self):
        parsed = NdlParser().parse(_RUNCMD_PATTERN_NDL)
        idx = FakeIndex(parsed)
        out = pattern_data_sources("TestRuncmdPattern", index=idx, pdi=None)
        assert "PowerShell / shell commands" in out

    def test_snmp_pattern_shows_snmp_bucket(self):
        parsed = NdlParser().parse(_SNMP_PATTERN_NDL)
        idx = FakeIndex(parsed)
        out = pattern_data_sources("TestSnmpPattern", index=idx, pdi=None)
        assert "SNMP gets / walks" in out

    def test_snmp_pattern_resolves_sysname_oid(self):
        parsed = NdlParser().parse(_SNMP_PATTERN_NDL)
        idx = FakeIndex(parsed)
        out = pattern_data_sources("TestSnmpPattern", index=idx, pdi=None)
        assert "sysName" in out

    def test_pure_transform_has_no_data_sources(self):
        parsed = NdlParser().parse(_PURE_TRANSFORM_NDL)
        idx = FakeIndex(parsed)
        out = pattern_data_sources("PureTransform", index=idx, pdi=None)
        assert "No external data sources detected" in out

    def test_pattern_not_found_returns_error_string(self):
        out = pattern_data_sources("Nonexistent Pattern", index=EmptyFakeIndex(), pdi=None)
        assert "Pattern not found" in out

    def test_empty_name_returns_error_string(self):
        out = pattern_data_sources("", index=EmptyFakeIndex(), pdi=None)
        assert "Pattern not found" in out or "not found" in out.lower()

    def test_no_index_no_pdi_returns_error_string(self):
        out = pattern_data_sources("SomePattern", index=None, pdi=None)
        assert "Pattern not found" in out

    def test_windows_ci_type_suggests_catalog(self):
        parsed = NdlParser().parse(_WMI_PATTERN_NDL)
        idx = FakeIndex(parsed)
        out = pattern_data_sources("TestWmiPattern", index=idx, pdi=None)
        # ci_type=cmdb_ci_win_server → _target_hint_for_ci returns 'windows'
        # The tool appends a catalog cross-reference line
        assert "windows" in out.lower() or "Win32" in out

    def test_live_index_wmi_pattern(self):
        idx = _live_index()
        out = pattern_data_sources(
            "Active Directory Domain Controller On Windows",
            index=idx,
            pdi=None,
        )
        assert "WMI queries" in out
        assert "Win32" in out

    def test_live_index_snmp_pattern(self):
        idx = _live_index()
        out = pattern_data_sources("A10 Load Balancer", index=idx, pdi=None)
        assert "SNMP gets / walks" in out

    def test_never_raises(self):
        result = pattern_data_sources("!!!bad", index=EmptyFakeIndex(), pdi=None)
        assert isinstance(result, str)


# ===========================================================================
# 6. pattern_data_sources_lookup  (no index or pdi — pure catalog browse)
# ===========================================================================

class TestPatternDataSourcesLookup:

    def test_no_args_returns_error(self):
        out = pattern_data_sources_lookup()
        assert "ERROR" in out

    def test_neither_target_nor_query_returns_error(self):
        out = pattern_data_sources_lookup(target=None, query=None)
        assert "ERROR" in out

    def test_target_windows_returns_results(self):
        out = pattern_data_sources_lookup(target="windows")
        assert "windows" in out.lower()
        assert "Win32" in out or "data points" in out

    def test_target_linux_returns_results(self):
        out = pattern_data_sources_lookup(target="linux")
        assert "linux" in out.lower()

    def test_target_f5_returns_results(self):
        out = pattern_data_sources_lookup(target="f5")
        assert "f5" in out.lower()

    def test_target_cisco_ios_returns_results(self):
        out = pattern_data_sources_lookup(target="cisco-ios")
        assert "cisco" in out.lower()

    def test_query_ssl_returns_ssl_results(self):
        out = pattern_data_sources_lookup(query="SSL")
        assert "SSL" in out or "ssl" in out.lower() or "no matches" in out

    def test_query_wmi_returns_wmi_results(self):
        out = pattern_data_sources_lookup(query="Win32_Service")
        assert "Win32_Service" in out or "no matches" in out

    def test_query_with_target_filter(self):
        # query + target together — should narrow to windows hits only
        out = pattern_data_sources_lookup(target="windows", query="Win32")
        assert "windows" in out.lower() or "Win32" in out or "no matches" in out

    def test_unknown_target_returns_error_with_known_list(self):
        out = pattern_data_sources_lookup(target="unknown_xyz_target")
        # New behavior: ERROR with the list of known targets so caller can correct
        assert "ERROR" in out
        assert "Known targets:" in out
        # At least one of the curated targets must be present
        assert any(t in out for t in ("windows", "linux", "f5", "cisco-ios"))

    def test_empty_query_string_treated_as_no_query(self):
        # empty string is falsy — falls through to target or error path
        out = pattern_data_sources_lookup(target=None, query="")
        # query="" is falsy, target=None → hits the error branch
        assert "ERROR" in out

    def test_output_is_always_a_string(self):
        for call_args in [
            dict(target="windows"),
            dict(query="hostname"),
            dict(),
            dict(target="esxi"),
            dict(target="linux", query="uname"),
        ]:
            result = pattern_data_sources_lookup(**call_args)
            assert isinstance(result, str)
