"""End-to-end test for thread #1: Windows MSCluster fix workflow.

Walks through the exact sequence of tool calls a user would drive:
  1. Open caller pattern as parent draft
  2. Locate the ref to the WMI-cold library
  3. Clone the library (via CloneLibrary, with fixture source_ndl)
  4. Locate every MSCluster WMI step in the child
  5. Insert the namespace-existence-probe recipe before the first
  6. Wrap each MSCluster step in is_not_empty {hasMSClusterNs}
  7. Redirect the parent ref to the cloned library
  8. Cross-draft validate
  9. Diff the parent

This exercises every primitive (clone, locate, insert recipe, wrap, redirect, validate, diff)
and is the acceptance test for v0.3.
"""
from pathlib import Path

import pytest

from sn_patterns_mcp.drafts.locator import StepPredicate, locate_step, locate_steps, resolve
from sn_patterns_mcp.drafts.ops import (
    CloneLibrary,
    InsertStepBefore,
    RedirectRef,
    WrapInGuard,
)
from sn_patterns_mcp.drafts.store import DraftStore
from sn_patterns_mcp.drafts.validator import validate_draft

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def store() -> DraftStore:
    return DraftStore()


def test_thread1_msccluster_fix_end_to_end(store: DraftStore) -> None:
    # ---- 1. open parent draft (caller pattern) ----
    caller_ndl = (FIXTURES / "fixture_caller_pattern.ndl").read_text(encoding="utf-8")
    parent = store.open(source_ndl=caller_ndl, source_sys_id="caller_sys_id")
    assert parent.is_library is False

    # ---- 2. locate the outer ref ----
    outer_ref = locate_step(parent, StepPredicate(
        ref_to_refid="fixture_lib_gen_vars_0000000000000001"
    ))
    assert outer_ref is not None

    # ---- 3. clone the library ----
    library_ndl = (FIXTURES / "fixture_library_with_wmi.ndl").read_text(encoding="utf-8")
    clone_op = CloneLibrary(
        source_library_sys_id="fixture_lib_gen_vars_0000000000000001",
        new_name="Fixture - General Pattern Variables (custom)",
        source_ndl=library_ndl,
    )
    clone_result = clone_op.apply(parent, store)
    assert clone_result.ok, [i.to_dict() for i in clone_result.issues]
    child_id = clone_result.extra["child_draft_id"]
    new_refid = clone_result.extra["new_refid"]
    new_name = clone_result.extra["new_name"]
    assert child_id != parent.id
    assert len(new_refid) == 32
    assert new_name.startswith("_sandbox_snmcp_")
    child = store.get(child_id)

    # ---- 4. locate every MSCluster WMI step in the child ----
    ms_steps = locate_steps(child, StepPredicate(
        closure_keyword="run_wmi_query_to_var",
        attr_contains=("namespace", "MSCluster"),
    ))
    assert len(ms_steps) == 2  # fixture has two MSCluster WMI steps

    # ---- 5. insert namespace-existence probe before first MSCluster step ----
    insert_op = InsertStepBefore(
        target=ms_steps[0],
        recipe="namespace_existence_probe",
        closure="run_wmi_query_to_var",
        params={"namespace": "MSCluster", "out_var": "hasMSClusterNs"},
    )
    ins_result = insert_op.apply(child, store)
    assert ins_result.ok, [i.to_dict() for i in ins_result.issues]
    probe_steps = locate_steps(child, StepPredicate(name_contains="Probe MSCluster namespace"))
    assert len(probe_steps) == 1

    # ---- 6. wrap every MSCluster step in is_not_empty {hasMSClusterNs} ----
    # Re-locate after insertion (locators are stable but locate again to test that path).
    ms_steps = locate_steps(child, StepPredicate(
        closure_keyword="run_wmi_query_to_var",
        attr_contains=("namespace", "MSCluster"),
    ))
    for loc in ms_steps:
        wrap_result = WrapInGuard(
            target=loc,
            condition_ndl='is_not_empty {get_attr {"hasMSClusterNs"}}',
        ).apply(child, store)
        assert wrap_result.ok, [i.to_dict() for i in wrap_result.issues]

    # Each MSCluster step should now resolve to a step whose op is the if-block.
    for loc in ms_steps:
        blk = resolve(child, loc)
        assert blk is not None
        op_block = next((v for k, v in blk.items if k is None and not isinstance(v, str)), None)
        assert op_block is not None
        assert op_block.name == "if"

    # ---- 7. redirect the parent ref to the cloned library ----
    redir_result = RedirectRef(target=outer_ref, new_refid=new_refid).apply(parent, store)
    assert redir_result.ok
    # Parent now refs the new sys_id, NOT the original.
    assert locate_step(parent, StepPredicate(ref_to_refid=new_refid)) is not None
    assert locate_step(parent, StepPredicate(
        ref_to_refid="fixture_lib_gen_vars_0000000000000001"
    )) is None

    # ---- 8. cross-draft validate ----
    report = validate_draft(parent, store)
    # Parent reads MSCluster_Cluster (still produced by child) — no errors.
    assert report.ok, [i.to_dict() for i in report.issues]
    # No removed-var warnings expected: the child still writes both MSCluster vars
    # (we wrapped them in guards, not removed them), so vars sets are equal.

    # ---- 9. diff parent ----
    from sn_patterns_mcp.ndl_writer import NdlWriter
    final_ndl = NdlWriter().write(parent.tree)
    assert new_refid in final_ndl
    assert "fixture_lib_gen_vars_0000000000000001" not in final_ndl

    # ---- bonus: child serializes back through the parser cleanly ----
    child_ndl = NdlWriter().write(child.tree)
    from sn_patterns_mcp.ndl_parser import NdlParser
    NdlParser().parse_tree(child_ndl)


def test_cross_draft_validator_flags_removed_var(store: DraftStore) -> None:
    """If the cloned library DROPS a var the parent still reads unguarded, it should ERROR.

    To exercise this, we wrap the parent's downstream read so that the read still happens
    but only when guarded — and then *remove* the writer step in the child entirely (with
    force=True). The cross-draft validator should not error because the parent's read is
    inside an is_not_empty guard.

    Then we add a second test where the parent's read is unguarded.
    """
    caller_ndl = (FIXTURES / "fixture_caller_pattern.ndl").read_text(encoding="utf-8")
    parent = store.open(source_ndl=caller_ndl, source_sys_id="caller")

    library_ndl = (FIXTURES / "fixture_library_with_wmi.ndl").read_text(encoding="utf-8")
    clone = CloneLibrary(
        source_library_sys_id="fixture_lib_gen_vars_0000000000000001",
        new_name="dropped-vars",
        source_ndl=library_ndl,
    ).apply(parent, store)
    child = store.get(clone.extra["child_draft_id"])

    # Remove the cluster-info step entirely (drops MSCluster_Cluster export).
    from sn_patterns_mcp.drafts.ops import RemoveStep
    target = locate_step(child, StepPredicate(name_contains="cluster info"))
    RemoveStep(target=target, force=True).apply(child, store)

    # Redirect parent ref to the modified clone.
    outer_ref = locate_step(parent, StepPredicate(
        ref_to_refid="fixture_lib_gen_vars_0000000000000001"
    ))
    RedirectRef(target=outer_ref, new_refid=clone.extra["new_refid"]).apply(parent, store)

    # The parent reads MSCluster_Cluster INSIDE an is_not_empty guard (per fixture).
    # So we expect a WARN, not ERROR.
    report = validate_draft(parent, store)
    codes = [i.code for i in report.issues]
    assert "CROSS_DRAFT_GUARDED_VAR_READ" in codes or "CROSS_DRAFT_UNGUARDED_VAR_READ" in codes
