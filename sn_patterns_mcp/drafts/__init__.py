"""Draft-state harness for surgical pattern editing.

Public surface:
    open_draft(source_ndl, source_sys_id) -> Draft
    apply_op(draft_id, op_name, **params) -> EditResult
    locate_step(s)(draft_id, **predicate) -> StepLocator | list[StepLocator]
    validate(draft_id) -> ValidationReport
    diff(draft_id) -> str
    finalize(draft_id, mode) -> str
    abandon(draft_id) -> None
"""
from sn_patterns_mcp.drafts.locator import StepLocator, StepPredicate, locate_step, locate_steps
from sn_patterns_mcp.drafts.store import DRAFTS, Draft, DraftStore

__all__ = [
    "DRAFTS",
    "Draft",
    "DraftStore",
    "StepLocator",
    "StepPredicate",
    "locate_step",
    "locate_steps",
]
