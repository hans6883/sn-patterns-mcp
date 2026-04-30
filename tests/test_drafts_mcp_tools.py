"""Smoke tests for the MCP-facing draft tools."""
import json
from pathlib import Path

import pytest

from sn_patterns_mcp.drafts import mcp_tools
from sn_patterns_mcp.drafts.store import DraftStore

FIXTURES = Path(__file__).parent / "fixtures"


class _StubIndex:
    def __init__(self, ndl: str, sys_id: str) -> None:
        self._ndl = ndl
        self._sys_id = sys_id

    def resolve_sys_id(self, name_or_sys_id: str) -> str | None:
        return self._sys_id

    def get(self, name_or_sys_id: str):
        from types import SimpleNamespace
        return SimpleNamespace(source_ndl=self._ndl)


@pytest.fixture
def store() -> DraftStore:
    return DraftStore()


@pytest.fixture
def caller_ndl() -> str:
    return (FIXTURES / "fixture_caller_pattern.ndl").read_text(encoding="utf-8")


@pytest.fixture
def library_ndl() -> str:
    return (FIXTURES / "fixture_library_with_wmi.ndl").read_text(encoding="utf-8")


def test_pattern_open_draft_returns_draft_id(store, caller_ndl):
    idx = _StubIndex(caller_ndl, "caller")
    out = mcp_tools.pattern_open_draft("caller", store=store, index=idx, pdi=None)
    payload = json.loads(out)
    assert payload["draft_id"].startswith("d_")
    assert payload["step_count"] == 3


def test_pattern_open_draft_unknown_returns_error(store):
    idx = _StubIndex("", None)  # empty
    idx.get = lambda x: None
    idx.resolve_sys_id = lambda x: None
    out = mcp_tools.pattern_open_draft("ghost", store=store, index=idx, pdi=None)
    assert out.startswith("ERROR:")


def test_draft_locate_steps_filters(store, library_ndl):
    idx = _StubIndex(library_ndl, "lib")
    out = mcp_tools.pattern_open_draft("lib", store=store, index=idx, pdi=None)
    draft_id = json.loads(out)["draft_id"]
    locate_out = mcp_tools.draft_locate_steps(
        draft_id, {"closure_keyword": "run_wmi_query_to_var"}, store=store,
    )
    payload = json.loads(locate_out)
    assert payload["draft_id"] == draft_id
    assert len(payload["matches"]) == 2


def test_draft_apply_clone_library_creates_child(store, caller_ndl, library_ndl):
    # Wire index that returns library NDL when CloneLibrary asks for it.
    idx = _StubIndex(caller_ndl, "caller")
    out = mcp_tools.pattern_open_draft("caller", store=store, index=idx, pdi=None)
    parent_id = json.loads(out)["draft_id"]
    # Now wire a different index for the clone lookup. CloneLibrary reads
    # store.index, so swap it.
    store.index = _StubIndex(library_ndl, "lib")
    apply_out = mcp_tools.draft_apply(
        parent_id, "clone_library",
        {"source_library_sys_id": "fixture_lib_gen_vars_0000000000000001",
         "new_name": "Test clone"},
        store=store,
    )
    payload = json.loads(apply_out)
    assert payload["ok"], payload
    assert "child_draft_id" in payload["extra"]


def test_draft_apply_unknown_op(store, caller_ndl):
    idx = _StubIndex(caller_ndl, "caller")
    out = mcp_tools.pattern_open_draft("caller", store=store, index=idx, pdi=None)
    draft_id = json.loads(out)["draft_id"]
    apply_out = mcp_tools.draft_apply(draft_id, "fake_op", {}, store=store)
    assert apply_out.startswith("ERROR:")


def test_draft_diff_renders_unified_diff(store, caller_ndl):
    """After an edit, the diff should be a unified diff with +/- lines."""
    idx = _StubIndex(caller_ndl, "caller")
    out = mcp_tools.pattern_open_draft("caller", store=store, index=idx, pdi=None)
    draft_id = json.loads(out)["draft_id"]
    # Locate the ref step and redirect it
    locate_out = mcp_tools.draft_locate_steps(
        draft_id, {"closure_keyword": "ref"}, store=store,
    )
    locator = json.loads(locate_out)["matches"][0]["locator"]
    apply_out = mcp_tools.draft_apply(
        draft_id, "redirect_ref",
        {"target": locator, "new_refid": "f" * 32},
        store=store,
    )
    assert json.loads(apply_out)["ok"]
    diff_out = mcp_tools.draft_diff(draft_id, store=store)
    # Unified diff produced — contains +/- lines.
    assert "+" in diff_out and "-" in diff_out
    assert "f" * 32 in diff_out


def test_draft_finalize_serialize_only(store, caller_ndl):
    idx = _StubIndex(caller_ndl, "caller")
    out = mcp_tools.pattern_open_draft("caller", store=store, index=idx, pdi=None)
    draft_id = json.loads(out)["draft_id"]
    final = mcp_tools.draft_finalize(draft_id, store=store, mode="serialize_only")
    assert "Fixture - Caller Pattern" in final


def test_draft_abandon_drops_draft(store, caller_ndl):
    idx = _StubIndex(caller_ndl, "caller")
    out = mcp_tools.pattern_open_draft("caller", store=store, index=idx, pdi=None)
    draft_id = json.loads(out)["draft_id"]
    msg = mcp_tools.draft_abandon(draft_id, store=store)
    assert "abandoned" in msg
    assert not store.has(draft_id)


def test_closure_capability_returns_descriptor_and_recipes():
    out = mcp_tools.closure_capability("run_wmi_query_to_var")
    payload = json.loads(out)
    assert payload["closure"] == "run_wmi_query_to_var"
    assert payload["known"] is True
    assert payload["registry"]["class_name"]
    recipe_names = {r["name"] for r in payload["recipes"]}
    assert "namespace_existence_probe" in recipe_names


def test_closure_capability_known_without_recipes_still_returns_descriptor():
    """Most closures (e.g. find_process_to_var) are in the registry but have no
    recipes yet — must still return descriptor info, not ERROR."""
    out = mcp_tools.closure_capability("find_process_to_var")
    payload = json.loads(out)
    assert payload["known"] is True
    assert payload["registry"]
    assert payload["recipes"] == []


def test_closure_capability_unknown_returns_known_false_not_error():
    """Unknown closures (or registry gaps like set_attr) return known=false with
    a hint, NOT an ERROR. Agent can still use the keyword in predicates."""
    out = mcp_tools.closure_capability("totally_made_up_closure")
    assert not out.startswith("ERROR:")
    payload = json.loads(out)
    assert payload["closure"] == "totally_made_up_closure"
    assert payload["known"] is False
    assert payload["registry"] == {}
    assert "hint" in payload


def test_draft_validate_clean_draft(store, caller_ndl):
    idx = _StubIndex(caller_ndl, "caller")
    out = mcp_tools.pattern_open_draft("caller", store=store, index=idx, pdi=None)
    draft_id = json.loads(out)["draft_id"]
    val_out = mcp_tools.draft_validate(draft_id, store=store)
    payload = json.loads(val_out)
    assert payload["ok"] is True
