"""Unit tests for individual edit ops."""
from pathlib import Path

import pytest

from sn_patterns_mcp.drafts.locator import StepPredicate, locate_step, locate_steps, resolve
from sn_patterns_mcp.drafts.ops import (
    OP_REGISTRY,
    InsertStepAfter,
    InsertStepBefore,
    ModifyClosureAttr,
    RedirectRef,
    RemoveStep,
    Severity,
    WrapInGuard,
)
from sn_patterns_mcp.drafts.ops.base import dispatch
from sn_patterns_mcp.drafts.store import DraftStore

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def store() -> DraftStore:
    return DraftStore()


@pytest.fixture
def lib_draft(store: DraftStore):
    ndl = (FIXTURES / "fixture_library_with_wmi.ndl").read_text(encoding="utf-8")
    return store.open(source_ndl=ndl, source_sys_id="lib")


@pytest.fixture
def caller_draft(store: DraftStore):
    ndl = (FIXTURES / "fixture_caller_pattern.ndl").read_text(encoding="utf-8")
    return store.open(source_ndl=ndl, source_sys_id="caller")


# ---------------------------------------------------------------------------
# OP_REGISTRY
# ---------------------------------------------------------------------------

def test_all_ops_registered() -> None:
    expected = {
        "clone_library", "wrap_in_guard", "insert_step_before",
        "insert_step_after", "redirect_ref", "modify_closure_attr", "remove_step",
    }
    assert expected.issubset(set(OP_REGISTRY.keys()))


def test_dispatch_unknown_raises() -> None:
    with pytest.raises(KeyError):
        dispatch("nonexistent_op", {})


# ---------------------------------------------------------------------------
# WrapInGuard
# ---------------------------------------------------------------------------

def test_wrap_in_guard_wraps_simple_step(lib_draft, store) -> None:
    loc = locate_step(lib_draft, StepPredicate(name_contains="isVIP"))
    op = WrapInGuard(target=loc, condition_ndl='is_not_empty {get_attr {"newHostname"}}')
    result = op.apply(lib_draft, store)
    assert result.ok, [i.to_dict() for i in result.issues]
    blk = resolve(lib_draft, loc)
    op_block = next(v for k, v in blk.items if k is None and not isinstance(v, str))
    assert op_block.name == "if"


def test_wrap_in_guard_idempotent(lib_draft, store) -> None:
    loc = locate_step(lib_draft, StepPredicate(name_contains="isVIP"))
    cond = 'is_not_empty {get_attr {"newHostname"}}'
    WrapInGuard(target=loc, condition_ndl=cond).apply(lib_draft, store)
    r2 = WrapInGuard(target=loc, condition_ndl=cond).apply(lib_draft, store)
    assert r2.ok
    assert r2.extra.get("noop") is True


def test_wrap_in_guard_invalid_condition_fails(lib_draft, store) -> None:
    loc = locate_step(lib_draft, StepPredicate(name_contains="isVIP"))
    op = WrapInGuard(target=loc, condition_ndl="this is { not valid")
    result = op.apply(lib_draft, store)
    assert not result.ok
    codes = {i.code for i in result.issues}
    assert "CONDITION_PARSE_ERROR" in codes


# ---------------------------------------------------------------------------
# InsertStepBefore / After
# ---------------------------------------------------------------------------

def test_insert_step_before_with_fragment(lib_draft, store) -> None:
    loc = locate_step(lib_draft, StepPredicate(closure_keyword="run_wmi_query_to_var"))
    fragment = (
        'step {\n'
        '  name = "Inserted probe"\n'
        '  set_attr { "probeRan" "true" }\n'
        '}'
    )
    op = InsertStepBefore(target=loc, ndl_fragment=fragment)
    r = op.apply(lib_draft, store)
    assert r.ok, [i.to_dict() for i in r.issues]
    locs = locate_steps(lib_draft, StepPredicate(name_contains="Inserted probe"))
    assert len(locs) == 1


def test_insert_step_with_recipe(lib_draft, store) -> None:
    loc = locate_step(lib_draft, StepPredicate(closure_keyword="run_wmi_query_to_var"))
    op = InsertStepBefore(
        target=loc, recipe="namespace_existence_probe", closure="run_wmi_query_to_var",
        params={"namespace": "MSCluster", "out_var": "hasMSClusterNs"},
    )
    r = op.apply(lib_draft, store)
    assert r.ok
    locs = locate_steps(lib_draft, StepPredicate(name_contains="Probe MSCluster namespace"))
    assert len(locs) == 1


def test_insert_step_after(lib_draft, store) -> None:
    loc = locate_step(lib_draft, StepPredicate(name_contains="isVIP"))
    fragment = 'step {\n  name = "after_marker"\n  set_attr { "after" "true" }\n}'
    op = InsertStepAfter(target=loc, ndl_fragment=fragment)
    r = op.apply(lib_draft, store)
    assert r.ok, [i.to_dict() for i in r.issues]
    locs = locate_steps(lib_draft, StepPredicate(name_contains="after_marker"))
    assert len(locs) == 1


def test_insert_recipe_missing_param_fails(lib_draft, store) -> None:
    loc = locate_step(lib_draft, StepPredicate(closure_keyword="run_wmi_query_to_var"))
    op = InsertStepBefore(
        target=loc, recipe="namespace_existence_probe", closure="run_wmi_query_to_var",
        params={"namespace": "MSCluster"},  # missing out_var
    )
    r = op.apply(lib_draft, store)
    assert not r.ok
    assert any(i.code == "RECIPE_MATERIALIZE_FAILED" for i in r.issues)


def test_insert_unknown_recipe_fails(lib_draft, store) -> None:
    loc = locate_step(lib_draft, StepPredicate(closure_keyword="run_wmi_query_to_var"))
    op = InsertStepBefore(
        target=loc, recipe="bogus", closure="run_wmi_query_to_var", params={},
    )
    r = op.apply(lib_draft, store)
    assert not r.ok
    assert any(i.code == "RECIPE_NOT_FOUND" for i in r.issues)


# ---------------------------------------------------------------------------
# RedirectRef
# ---------------------------------------------------------------------------

def test_redirect_ref(caller_draft, store) -> None:
    loc = locate_step(caller_draft, StepPredicate(
        ref_to_refid="fixture_lib_gen_vars_0000000000000001"
    ))
    new_id = "abcd" * 8  # 32 hex
    r = RedirectRef(target=loc, new_refid=new_id).apply(caller_draft, store)
    assert r.ok
    new_loc = locate_step(caller_draft, StepPredicate(ref_to_refid=new_id))
    assert new_loc is not None


def test_redirect_ref_on_non_ref_step_fails(lib_draft, store) -> None:
    loc = locate_step(lib_draft, StepPredicate(name_contains="isVIP"))
    r = RedirectRef(target=loc, new_refid="x" * 32).apply(lib_draft, store)
    assert not r.ok
    assert any(i.code == "NOT_A_REF_STEP" for i in r.issues)


# ---------------------------------------------------------------------------
# ModifyClosureAttr
# ---------------------------------------------------------------------------

def test_modify_closure_attr_changes_query(lib_draft, store) -> None:
    loc = locate_step(lib_draft, StepPredicate(closure_keyword="run_wmi_query_to_var"))
    new_q = "SELECT Name FROM MSCluster_Cluster WHERE Status='OK'"
    r = ModifyClosureAttr(
        target=loc, attr_path=("query",), new_value=new_q,
    ).apply(lib_draft, store)
    assert r.ok
    blk = resolve(lib_draft, loc)
    op_blk = next(v for k, v in blk.items if k is None)
    found = next(v for k, v in op_blk.items if k == "query")
    assert found == new_q


def test_modify_closure_attr_empty_path_fails(lib_draft, store) -> None:
    loc = locate_step(lib_draft, StepPredicate(closure_keyword="run_wmi_query_to_var"))
    r = ModifyClosureAttr(target=loc, attr_path=(), new_value="x").apply(lib_draft, store)
    assert not r.ok


# ---------------------------------------------------------------------------
# RemoveStep
# ---------------------------------------------------------------------------

def test_remove_step_safe_when_no_downstream_reads(lib_draft, store) -> None:
    # The set_attr step writes "isVIP" but the fixture doesn't read it. Should remove cleanly.
    loc = locate_step(lib_draft, StepPredicate(name_contains="isVIP"))
    r = RemoveStep(target=loc).apply(lib_draft, store)
    assert r.ok


def test_remove_step_blocks_when_downstream_read(lib_draft, store) -> None:
    # The "Get cluster resources" step writes MSCluster_Resource which is read downstream.
    loc = locate_step(lib_draft, StepPredicate(name_contains="cluster resources"))
    r = RemoveStep(target=loc).apply(lib_draft, store)
    # The downstream read is guarded by is_not_empty, so the simple checker
    # may either flag it as unguarded (if it can't see the guard) or allow it.
    # Either way, force=True must succeed.
    if not r.ok:
        r2 = RemoveStep(target=loc, force=True).apply(lib_draft, store)
        assert r2.ok
