"""RedirectRef — change a step's `ref { refid = X }` to point at Y."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from sn_patterns_mcp.drafts.locator import StepLocator, resolve_path
from sn_patterns_mcp.drafts.ops.base import (
    EditResult,
    Severity,
    ValidationIssue,
    register_op,
    reindex_after_apply,
)
from sn_patterns_mcp.drafts.store import Draft, _resolve_path
from sn_patterns_mcp.ndl_parser import _Block


@register_op
@dataclass(frozen=True)
class RedirectRef:
    name: str = "redirect_ref"
    target: StepLocator = None  # type: ignore[assignment]
    new_refid: str = ""

    @classmethod
    def from_params(cls, p: dict[str, Any]) -> RedirectRef:
        return cls(
            target=StepLocator.from_dict(p["target"]),
            new_refid=p["new_refid"],
        )

    def validate(self, draft: Draft, store: Any) -> list[ValidationIssue]:
        issues: list[ValidationIssue] = []
        path = resolve_path(draft, self.target)
        if path is None:
            return [ValidationIssue(Severity.ERROR, "TARGET_NOT_FOUND",
                                    f"step locator {self.target.step_uid} not found", self.target)]
        step_blk = _resolve_path(draft.tree, path)
        if step_blk is None:
            return [ValidationIssue(Severity.ERROR, "TARGET_NOT_FOUND",
                                    "step block resolution failed", self.target)]
        if not _is_ref_step(step_blk):
            issues.append(ValidationIssue(
                Severity.ERROR, "NOT_A_REF_STEP",
                "step does not contain a `ref { refid = ... }` or `refid { id = ... }` operation",
                self.target,
            ))
        if not self.new_refid or len(self.new_refid) < 8:
            issues.append(ValidationIssue(
                Severity.ERROR, "INVALID_REFID",
                f"new_refid must be a non-empty sys_id (got {self.new_refid!r})",
                self.target,
            ))
        return issues

    @reindex_after_apply
    def apply(self, draft: Draft, store: Any) -> EditResult:
        issues = self.validate(draft, store)
        if any(i.severity == Severity.ERROR for i in issues):
            return EditResult(ok=False, op_name=self.name, issues=issues)
        path = resolve_path(draft, self.target)
        step_blk = _resolve_path(draft.tree, path)  # type: ignore[arg-type]
        # Replace the refid attribute inside the inner ref/refid op.
        for _k_outer, v_outer in step_blk.items:  # type: ignore[union-attr]
            if isinstance(v_outer, _Block) and v_outer.name in ("ref", "refid"):
                _replace_attr(v_outer, ("refid", "id"), self.new_refid)
        draft.edits.append({"op": self.name, "target": self.target.to_dict(),
                            "new_refid": self.new_refid})
        return EditResult(ok=True, op_name=self.name, issues=issues)


def _is_ref_step(step_blk: _Block) -> bool:
    for _k, v in step_blk.items:
        if isinstance(v, _Block) and v.name in ("ref", "refid"):
            return True
    return False


def _replace_attr(blk: _Block, attr_keys: tuple[str, ...], new_value: str) -> None:
    """Replace value of any attribute matching one of attr_keys (first match wins)."""
    for i, (k, v) in enumerate(blk.items):
        if k in attr_keys and not isinstance(v, _Block):
            blk.items[i] = (k, new_value)
            return
