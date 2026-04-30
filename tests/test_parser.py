from __future__ import annotations

from pathlib import Path

import pytest

from sn_patterns_mcp.closures import get as get_closure
from sn_patterns_mcp.ndl_parser import NdlParser, NdlSyntaxError, classify_variables
from sn_patterns_mcp.pattern_model import FindProcessStrategy
from sn_patterns_mcp.tools import (
    ndl_explain,
    pattern_analyze,
    pattern_compare,
    pattern_search,
)

FIXTURES = Path(__file__).parent / "fixtures"


def _load(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# Tokenizer / parser
# ---------------------------------------------------------------------------

def test_parse_apache_unix_structure():
    ndl = _load("apache_unix.ndl")
    p = NdlParser().parse(ndl)
    assert p.metadata.id == "apache_on_unix_fixture"
    assert p.metadata.name == "Apache on Unix (fixture)"
    assert p.metadata.ci_type == "cmdb_ci_app_server_apache"
    assert p.metadata.apply_to_os_types == ["linux", "solaris"]
    assert len(p.identifications) == 1
    ident = p.identifications[0]
    assert ident.name == "Apache identification"
    assert ident.entry_point_types == ["TCP"]
    assert ident.find_process_strategy == FindProcessStrategy.LISTENING_PORT
    assert len(ident.steps) == 2
    step1 = ident.steps[0]
    assert step1.operation is not None
    assert step1.operation.keyword == "runcmd_to_var"
    assert step1.operation.operands["command"].keyword == "constant"


def test_library_ref_detected():
    ndl = _load("apache_unix.ndl")
    p = NdlParser().parse(ndl)
    refs = p.library_references()
    assert "get_unix_filesystem_lib_id" in refs


def test_eval_closure_preserved():
    ndl = _load("apache_unix.ndl")
    p = NdlParser().parse(ndl)
    conn = p.connections[0]
    eval_step = conn.steps[1]
    assert eval_step.operation.keyword == "EVAL"


def test_unknown_keyword_still_parses():
    odd = 'pattern { metadata { id="x" name="y" } identification { name="i" step { name="s" some_new_op { a = "b" } } } }'
    p = NdlParser().parse(odd)
    assert p.identifications[0].steps[0].operation.keyword == "some_new_op"


def test_syntax_error_raises():
    with pytest.raises(NdlSyntaxError):
        NdlParser().parse('pattern { metadata { name = "x"')


def test_escape_handling():
    ndl = r'''pattern { metadata { id="x" name="quote \" back\\slash" } }'''
    p = NdlParser().parse(ndl)
    assert p.metadata.name == 'quote " back\\slash'


def test_variables_collected():
    ndl = _load("apache_unix.ndl")
    p = NdlParser().parse(ndl)
    vars_ = classify_variables(p)
    assert "process_list" in vars_ or "$process_list" in vars_ or "conf" in vars_


# ---------------------------------------------------------------------------
# Closure registry
# ---------------------------------------------------------------------------

def test_registry_hits_common_ops():
    for kw in ("runcmd_to_var", "parse_file", "refid", "EVAL", "if", "create_connection"):
        d = get_closure(kw)
        assert d is not None, kw
        # class_name is a bare-class-name hint; non-empty for every catalogued closure.
        assert d.class_name


# ---------------------------------------------------------------------------
# Tool output smoke tests (single pattern — no index/pdi needed)
# ---------------------------------------------------------------------------

class _SingleIndex:
    """Stub index that resolves a single fixture pattern for tool tests."""

    def __init__(self, sys_id: str, ndl: str):
        self._sys_id = sys_id
        self._pattern = NdlParser().parse(ndl)
        self.manifest = {sys_id: {"name": self._pattern.metadata.name, "ci_type": self._pattern.metadata.ci_type}}

    def resolve_sys_id(self, key):
        return self._sys_id if key in (self._sys_id, self._pattern.metadata.name) else None

    def get(self, key):
        return self._pattern if self.resolve_sys_id(key) else None

    def search_text(self, q, limit=10):
        if q.lower() in self._pattern.metadata.name.lower():
            return [{"sys_id": self._sys_id, "name": self._pattern.metadata.name, "ci_type": self._pattern.metadata.ci_type}]
        return []


def test_pattern_analyze_produces_structured_output():
    idx = _SingleIndex("apache_unix_fixture", _load("apache_unix.ndl"))
    out = pattern_analyze("Apache on Unix (fixture)", index=idx, pdi=None)
    assert "Pattern:" in out
    assert "IDENTIFICATIONS:" in out
    assert "runcmd_to_var" in out
    assert "VARIABLES" in out


def test_ndl_explain_parses_fragment():
    frag = 'runcmd_to_var { command = constant { value = "uname -a" } variable_name = "$uname" }'
    out = ndl_explain(frag)
    assert "runcmd_to_var" in out
    assert "Run a shell" in out


def test_pattern_compare_diffs_ops():
    idx_unix = _SingleIndex("a", _load("apache_unix.ndl"))
    idx_win = _SingleIndex("b", _load("apache_windows.ndl"))

    class _CombinedIndex:
        def __init__(self, a, b):
            self.a = a
            self.b = b
            self.manifest = {**a.manifest, **b.manifest}

        def resolve_sys_id(self, key):
            return self.a.resolve_sys_id(key) or self.b.resolve_sys_id(key)

        def get(self, key):
            return self.a.get(key) or self.b.get(key)

        def search_text(self, q, limit=10):
            return self.a.search_text(q, limit) + self.b.search_text(q, limit)

    combined = _CombinedIndex(idx_unix, idx_win)
    out = pattern_compare(
        "Apache on Unix (fixture)", "Apache on Windows (fixture)",
        index=combined, pdi=None,
    )
    assert "OPERATION KEYWORDS" in out
    assert "runcmd_to_var" in out
    assert "run_wmi_query_to_var" in out


def test_pattern_search_substring_fallback():
    idx = _SingleIndex("apache_unix_fixture", _load("apache_unix.ndl"))
    out = pattern_search("Apache", index=idx, chroma=None, limit=5)
    assert "Apache on Unix" in out
