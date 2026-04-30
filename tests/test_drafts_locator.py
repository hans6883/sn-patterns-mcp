"""Unit tests for drafts.locator."""
from pathlib import Path

import pytest

from sn_patterns_mcp.drafts.locator import (
    StepPredicate,
    locate_step,
    locate_steps,
    resolve,
)
from sn_patterns_mcp.drafts.store import DraftStore

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def store() -> DraftStore:
    return DraftStore()


@pytest.fixture
def caller_draft(store: DraftStore):
    ndl = (FIXTURES / "fixture_caller_pattern.ndl").read_text(encoding="utf-8")
    return store.open(source_ndl=ndl, source_sys_id="caller")


@pytest.fixture
def library_draft(store: DraftStore):
    ndl = (FIXTURES / "fixture_library_with_wmi.ndl").read_text(encoding="utf-8")
    return store.open(source_ndl=ndl, source_sys_id="lib")


def test_locate_by_name_contains(library_draft) -> None:
    locs = locate_steps(library_draft, StepPredicate(name_contains="cluster info"))
    assert len(locs) == 1
    blk = resolve(library_draft, locs[0])
    assert "cluster info" in str(blk.items[0]).lower()


def test_locate_by_closure_keyword(library_draft) -> None:
    locs = locate_steps(library_draft, StepPredicate(closure_keyword="run_wmi_query_to_var"))
    assert len(locs) == 2  # two MSCluster steps in the fixture


def test_locate_by_attr_contains_namespace(library_draft) -> None:
    locs = locate_steps(library_draft, StepPredicate(
        closure_keyword="run_wmi_query_to_var",
        attr_contains=("namespace", "MSCluster"),
    ))
    assert len(locs) == 2


def test_locate_no_match_returns_empty(library_draft) -> None:
    locs = locate_steps(library_draft, StepPredicate(closure_keyword="nonexistent_closure"))
    assert locs == []


def test_locate_first(library_draft) -> None:
    loc = locate_step(library_draft, StepPredicate(closure_keyword="run_wmi_query_to_var"))
    assert loc is not None


def test_ref_to_refid(caller_draft) -> None:
    locs = locate_steps(caller_draft, StepPredicate(
        ref_to_refid="fixture_lib_gen_vars_0000000000000001"
    ))
    assert len(locs) == 1


def test_predicate_combines_with_and(library_draft) -> None:
    # Two WMI steps, but only one has "Resource" in the name
    locs = locate_steps(library_draft, StepPredicate(
        closure_keyword="run_wmi_query_to_var",
        name_contains="Resource",
    ))
    assert len(locs) == 1


def test_resolve_returns_block(library_draft) -> None:
    loc = locate_step(library_draft, StepPredicate(name_contains="isVIP"))
    blk = resolve(library_draft, loc)
    assert blk is not None
    assert blk.name == "step"


def test_resolve_unknown_locator_returns_none(library_draft) -> None:
    from sn_patterns_mcp.drafts.locator import StepLocator
    bogus = StepLocator(draft_id=library_draft.id, step_uid="s_does_not_exist")
    assert resolve(library_draft, bogus) is None
