"""Unit tests for drafts.store: Draft, DraftStore, step UID stability."""
from pathlib import Path

import pytest

from sn_patterns_mcp.drafts.store import DraftStore

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def caller_ndl() -> str:
    return (FIXTURES / "fixture_caller_pattern.ndl").read_text(encoding="utf-8")


@pytest.fixture
def library_ndl() -> str:
    return (FIXTURES / "fixture_library_with_wmi.ndl").read_text(encoding="utf-8")


def test_open_pattern(caller_ndl: str) -> None:
    store = DraftStore()
    d = store.open(source_ndl=caller_ndl, source_sys_id="caller")
    assert d.id.startswith("d_")
    assert d.is_library is False
    assert d.name == "Fixture - Caller Pattern"
    assert len(d.step_uids) == 3  # set hostname / ref / guarded use


def test_open_library(library_ndl: str) -> None:
    store = DraftStore()
    d = store.open(source_ndl=library_ndl, source_sys_id="lib")
    assert d.is_library is True
    assert d.name == "Fixture - General Pattern Variables"
    assert len(d.step_uids) == 4


def test_get_unknown_raises() -> None:
    store = DraftStore()
    with pytest.raises(KeyError):
        store.get("d_does_not_exist")


def test_abandon_drops_drafts(caller_ndl: str) -> None:
    store = DraftStore()
    d = store.open(source_ndl=caller_ndl, source_sys_id="caller")
    assert store.has(d.id)
    store.abandon(d.id)
    assert not store.has(d.id)


def test_abandon_cascades_to_children(caller_ndl: str, library_ndl: str) -> None:
    store = DraftStore()
    parent = store.open(source_ndl=caller_ndl, source_sys_id="caller")
    child = store.open(
        source_ndl=library_ndl, source_sys_id="lib", parent_draft_id=parent.id
    )
    parent.child_drafts["lib"] = child.id
    store.abandon(parent.id)
    assert not store.has(parent.id)
    assert not store.has(child.id)


def test_serialize_roundtrip(caller_ndl: str) -> None:
    store = DraftStore()
    d = store.open(source_ndl=caller_ndl, source_sys_id="caller")
    out = store.serialize(d.id)
    # Roundtrip: should re-parse cleanly.
    from sn_patterns_mcp.ndl_parser import NdlParser
    NdlParser().parse_tree(out)


def test_step_uids_are_unique(caller_ndl: str) -> None:
    store = DraftStore()
    d = store.open(source_ndl=caller_ndl, source_sys_id="caller")
    uids = list(d.step_uids.keys())
    assert len(uids) == len(set(uids))


def test_step_uids_stable_across_content_mutation(caller_ndl: str) -> None:
    """UIDs are anchored to step _Block object identity. WrapInGuard mutates
    contents of the step but does NOT replace the step block; UID survives."""
    from sn_patterns_mcp.drafts.locator import StepPredicate, locate_step
    from sn_patterns_mcp.drafts.ops import WrapInGuard
    store = DraftStore()
    d = store.open(source_ndl=caller_ndl, source_sys_id="caller")
    loc_before = locate_step(d, StepPredicate(name_contains="Set hostname"))
    uid_before = loc_before.step_uid
    # Wrap the step's op in a guard.
    r = WrapInGuard(target=loc_before, condition_ndl='is_not_empty {get_attr {"x"}}').apply(d, store)
    assert r.ok
    # The same locator should still resolve (UID stable).
    loc_after = locate_step(d, StepPredicate(name_contains="Set hostname"))
    assert loc_after is not None
    assert loc_after.step_uid == uid_before


def test_step_uids_stable_across_redirect_ref(caller_ndl: str) -> None:
    """RedirectRef changes the inner refid value but does NOT replace the step
    block; UID must survive."""
    from sn_patterns_mcp.drafts.locator import StepPredicate, locate_step
    from sn_patterns_mcp.drafts.ops import RedirectRef
    store = DraftStore()
    d = store.open(source_ndl=caller_ndl, source_sys_id="caller")
    ref_before = locate_step(d, StepPredicate(closure_keyword="ref"))
    uid_before = ref_before.step_uid
    new_id = "f" * 32
    RedirectRef(target=ref_before, new_refid=new_id).apply(d, store)
    # Same UID should still be valid for the same step.
    new_path = d.step_uids.get(uid_before)
    assert new_path is not None


def test_step_uids_stable_after_insert_before(caller_ndl: str) -> None:
    """InsertStepBefore inserts a new step at the target's index; existing
    step UIDs survive (object identity preserved across path shifts)."""
    from sn_patterns_mcp.drafts.locator import StepPredicate, locate_step
    from sn_patterns_mcp.drafts.ops import InsertStepBefore
    store = DraftStore()
    d = store.open(source_ndl=caller_ndl, source_sys_id="caller")
    target = locate_step(d, StepPredicate(closure_keyword="ref"))
    target_uid = target.step_uid
    fragment = 'step {\n  name = "inserted"\n  set_attr { "x" "1" }\n}'
    r = InsertStepBefore(target=target, ndl_fragment=fragment).apply(d, store)
    assert r.ok
    # Original UID still resolves; path moved by +1.
    assert target_uid in d.step_uids
    # New step has a fresh UID.
    new_step = locate_step(d, StepPredicate(name_contains="inserted"))
    assert new_step is not None
    assert new_step.step_uid != target_uid
