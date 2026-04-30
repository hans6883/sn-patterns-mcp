"""Cross-draft var-flow validator.

Single-draft validation reuses the existing PatternValidator (Tier-1 syntax,
roundtrip, refids, var ordering). The new piece is the *cross-draft* check:

When a parent draft has a RedirectRef to a child draft (cloned library),
the child's exported var-set may differ from the source library's. Walking
the parent in document order, we check whether downstream reads of vars that
the child no longer produces are guarded with is_not_empty / is_empty.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from sn_patterns_mcp.drafts.locator import StepLocator
from sn_patterns_mcp.drafts.ops.base import Severity, ValidationIssue
from sn_patterns_mcp.drafts.ops.remove_step import _reads_unguarded, _vars_written_by
from sn_patterns_mcp.drafts.store import (
    Draft,
    DraftStore,
    _iter_step_paths,
)
from sn_patterns_mcp.ndl_parser import NdlParser, _Block

log = logging.getLogger(__name__)


@dataclass
class ValidationReport:
    draft_id: str
    issues: list[ValidationIssue] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not any(i.severity == Severity.ERROR for i in self.issues)

    @property
    def errors(self) -> list[ValidationIssue]:
        return [i for i in self.issues if i.severity == Severity.ERROR]

    @property
    def warnings(self) -> list[ValidationIssue]:
        return [i for i in self.issues if i.severity == Severity.WARN]

    def to_dict(self) -> dict[str, Any]:
        return {
            "draft_id": self.draft_id,
            "ok": self.ok,
            "error_count": len(self.errors),
            "warning_count": len(self.warnings),
            "issues": [i.to_dict() for i in self.issues],
        }


def validate_draft(draft: Draft, store: DraftStore) -> ValidationReport:
    """Run all draft-level validators."""
    issues: list[ValidationIssue] = []

    # 1. Tier-1: re-serialize + parse the tree to catch structural drift.
    issues.extend(_tier1_roundtrip(draft))

    # 2. Cross-draft var-flow: every redirect-ref pointing at a child draft
    #    must export at least the var-set the parent reads downstream.
    issues.extend(_cross_draft_var_check(draft, store))

    return ValidationReport(draft_id=draft.id, issues=issues)


def _tier1_roundtrip(draft: Draft) -> list[ValidationIssue]:
    """Serialize → parse roundtrip; failure means the tree is malformed."""
    from sn_patterns_mcp.ndl_writer import NdlWriter
    out: list[ValidationIssue] = []
    try:
        text = NdlWriter().write(draft.tree)
    except Exception as e:
        out.append(ValidationIssue(
            Severity.ERROR, "TIER1_SERIALIZE_FAILED",
            f"current draft tree fails to serialize: {e}",
        ))
        return out
    try:
        NdlParser().parse_tree(text)
    except Exception as e:
        out.append(ValidationIssue(
            Severity.ERROR, "TIER1_PARSE_FAILED",
            f"draft serializes but resulting NDL fails to re-parse: {e}",
        ))
    return out


def _cross_draft_var_check(parent: Draft, store: DraftStore) -> list[ValidationIssue]:
    """For each ref step pointing at a child draft, check parent's downstream
    var-reads against the child's exported var-set.
    """
    out: list[ValidationIssue] = []
    if not parent.child_drafts:
        return out

    # Walk parent in document order, find every ref step.
    for path, blk in _iter_step_paths(parent.tree):
        ref_target = _ref_target_of_step(blk)
        if ref_target is None:
            continue
        # Is this redirect pointing at a child draft? We track child drafts
        # by their *original source* sys_id, so the new (rewritten) refid
        # won't directly match. Walk every child draft and check if its
        # current top-level id matches `ref_target`.
        child_id = _find_child_by_current_refid(parent, store, ref_target)
        if child_id is None:
            continue
        try:
            child = store.get(child_id)
        except KeyError:
            continue
        # Compare original source library's var-exports vs current child exports.
        # Original = child.source_ndl (snapshot at clone time).
        try:
            original_tree = NdlParser().parse_tree(child.source_ndl)
        except Exception as e:
            out.append(ValidationIssue(
                Severity.WARN, "CROSS_DRAFT_ORIGINAL_PARSE_FAILED",
                f"could not parse child {child_id} original source for comparison: {e}",
            ))
            continue
        original_exports = _all_vars_written(original_tree)
        current_exports = _all_vars_written(child.tree)
        removed = original_exports - current_exports
        if not removed:
            continue
        # Walk downstream of `path` in parent — find unguarded reads of any removed var.
        downstream_steps = [(p, b) for (p, b) in _iter_step_paths(parent.tree) if p > path]
        for d_path, d_blk in downstream_steps:
            for var in sorted(removed):
                if _reads_unguarded(d_blk, {var}):
                    # Find a step UID for the locator (best effort).
                    locator = _step_locator_for_path(parent, d_path)
                    out.append(ValidationIssue(
                        Severity.ERROR,
                        "CROSS_DRAFT_UNGUARDED_VAR_READ",
                        f"parent reads {var!r} at step {_step_name(d_blk)!r}, "
                        f"but child draft {child_id} no longer writes it (removed during edit). "
                        "Wrap the read in is_not_empty {} or restore the var write in the child.",
                        locator,
                    ))
                else:
                    locator = _step_locator_for_path(parent, d_path)
                    out.append(ValidationIssue(
                        Severity.WARN,
                        "CROSS_DRAFT_GUARDED_VAR_READ",
                        f"parent reads {var!r} at step {_step_name(d_blk)!r} (guarded); "
                        f"child draft {child_id} no longer writes it — guard will always fall through.",
                        locator,
                    ))
    return out


def _ref_target_of_step(step_blk: _Block) -> str | None:
    """For step{ ref{refid=X} } or step{ refid{id=X} }, return X."""
    for k, v in step_blk.items:
        if k is None and isinstance(v, _Block) and v.name in ("ref", "refid"):
            for k2, v2 in v.items:
                if k2 in ("refid", "id") and isinstance(v2, str):
                    return v2
    for k, v in step_blk.items:
        if k == "refid" and isinstance(v, str):
            return v
    return None


def _find_child_by_current_refid(
    parent: Draft, store: DraftStore, refid: str
) -> str | None:
    """Find a child draft whose CURRENT (post-clone) top-level id matches `refid`."""
    for _src, child_id in parent.child_drafts.items():
        try:
            child = store.get(child_id)
        except KeyError:
            continue
        for k, v in child.tree.items:
            if k == "id" and v == refid:
                return child_id
    return None


def _all_vars_written(tree: _Block) -> set[str]:
    """Set of every var written by any step anywhere in the tree."""
    out: set[str] = set()
    for _path, step_blk in _iter_step_paths(tree):
        out.update(_vars_written_by(step_blk))
    return out


def _step_locator_for_path(draft: Draft, target_path: tuple[int, ...]) -> StepLocator | None:
    for uid, p in draft.step_uids.items():
        if p == target_path:
            return StepLocator(draft_id=draft.id, step_uid=uid)
    return None


def _step_name(blk: _Block) -> str:
    for k, v in blk.items:
        if k == "name" and isinstance(v, str):
            return v
    return ""
