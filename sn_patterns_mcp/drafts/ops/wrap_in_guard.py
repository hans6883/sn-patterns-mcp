"""WrapInGuard — wrap a step's operation in `if { condition = ...; on_true = <op>; on_false = nop {} }`.

If the step is already a refid step, the inner ref/refid sub-block is wrapped.
Idempotent if the existing precondition is structurally equal to the new one.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from sn_patterns_mcp.drafts.locator import StepLocator, resolve, resolve_path
from sn_patterns_mcp.drafts.ops.base import (
    EditResult,
    Severity,
    ValidationIssue,
    parse_ndl_block,
    register_op,
    reindex_after_apply,
)
from sn_patterns_mcp.drafts.store import Draft, _resolve_path
from sn_patterns_mcp.ndl_parser import _Block


@register_op
@dataclass(frozen=True)
class WrapInGuard:
    name: str = "wrap_in_guard"
    target: StepLocator = None  # type: ignore[assignment]
    condition_ndl: str = "is_not_empty {}"
    on_false_ndl: str = "nop {}"

    @classmethod
    def from_params(cls, params: dict[str, Any]) -> WrapInGuard:
        return cls(
            target=StepLocator.from_dict(params["target"]),
            condition_ndl=params["condition_ndl"],
            on_false_ndl=params.get("on_false_ndl", "nop {}"),
        )

    def validate(self, draft: Draft, store: Any) -> list[ValidationIssue]:
        issues: list[ValidationIssue] = []
        step_blk = resolve(draft, self.target)
        if step_blk is None:
            issues.append(ValidationIssue(
                Severity.ERROR, "TARGET_NOT_FOUND",
                f"step locator {self.target.step_uid} not found in draft {draft.id}",
                self.target,
            ))
            return issues
        # Validate the condition NDL parses
        try:
            cond_blk = parse_ndl_block(self.condition_ndl)
        except Exception as e:
            issues.append(ValidationIssue(
                Severity.ERROR, "CONDITION_PARSE_ERROR",
                f"condition_ndl failed to parse: {e}",
                self.target,
            ))
            return issues
        if not isinstance(cond_blk, _Block):
            issues.append(ValidationIssue(
                Severity.ERROR, "CONDITION_NOT_BLOCK",
                "condition_ndl must be a single NDL block",
                self.target,
            ))
        try:
            of_blk = parse_ndl_block(self.on_false_ndl)
            if not isinstance(of_blk, _Block):
                issues.append(ValidationIssue(
                    Severity.ERROR, "ON_FALSE_NOT_BLOCK",
                    "on_false_ndl must be a single NDL block",
                    self.target,
                ))
        except Exception as e:
            issues.append(ValidationIssue(
                Severity.ERROR, "ON_FALSE_PARSE_ERROR",
                f"on_false_ndl failed to parse: {e}",
                self.target,
            ))
        return issues

    @reindex_after_apply
    def apply(self, draft: Draft, store: Any) -> EditResult:
        issues = self.validate(draft, store)
        if any(i.severity == Severity.ERROR for i in issues):
            return EditResult(ok=False, op_name=self.name, issues=issues)
        path = resolve_path(draft, self.target)
        if path is None:
            return EditResult(
                ok=False, op_name=self.name,
                issues=[ValidationIssue(Severity.ERROR, "TARGET_NOT_FOUND",
                                        "step path resolution failed", self.target)],
            )
        step_blk = _resolve_path(draft.tree, path)
        if step_blk is None:
            return EditResult(
                ok=False, op_name=self.name,
                issues=[ValidationIssue(Severity.ERROR, "TARGET_NOT_FOUND",
                                        "step block resolution failed", self.target)],
            )

        # Find the operation sub-block inside the step (the first unkeyed _Block,
        # or the keyed "operation"/"op" entry).
        op_idx = _find_op_index(step_blk)
        if op_idx is None:
            return EditResult(
                ok=False, op_name=self.name,
                issues=[ValidationIssue(Severity.ERROR, "STEP_HAS_NO_OPERATION",
                                        "step has no inner operation block to wrap",
                                        self.target)],
            )

        original_key, original_op = step_blk.items[op_idx]
        if not isinstance(original_op, _Block):
            return EditResult(
                ok=False, op_name=self.name,
                issues=[ValidationIssue(Severity.ERROR, "OP_NOT_BLOCK",
                                        "step operation is not a block", self.target)],
            )
        # Check idempotency: if the inner op is already an `if` block whose
        # condition matches, skip.
        if original_op.name == "if":
            existing_cond = _get_keyed_block(original_op, "condition")
            new_cond = parse_ndl_block(self.condition_ndl)
            if existing_cond is not None and isinstance(new_cond, _Block) and _blocks_equal(existing_cond, new_cond):
                return EditResult(ok=True, op_name=self.name, issues=issues,
                                  extra={"noop": True, "reason": "already wrapped with same condition"})

        # Build new if-block:
        #   if {
        #     condition = <cond>
        #     on_true = <original_op>
        #     on_false = <on_false>
        #   }
        cond_blk = parse_ndl_block(self.condition_ndl)
        of_blk = parse_ndl_block(self.on_false_ndl)
        if_blk = _Block(
            name="if",
            line=step_blk.line,
            col=step_blk.col,
            items=[
                ("condition", cond_blk),
                ("on_true", original_op),
                ("on_false", of_blk),
            ],
        )
        # Replace the original op slot in the step with the new if-block.
        step_blk.items[op_idx] = (original_key, if_blk)

        draft.edits.append({"op": self.name, "target": self.target.to_dict()})
        return EditResult(ok=True, op_name=self.name, issues=issues)


def _find_op_index(step_blk: _Block) -> int | None:
    """Find the position of the step's operation block."""
    for i, (k, v) in enumerate(step_blk.items):
        if isinstance(v, _Block) and (k is None or k in ("operation", "op")):
            return i
    return None


def _get_keyed_block(blk: _Block, key: str) -> _Block | None:
    for k, v in blk.items:
        if k == key and isinstance(v, _Block):
            return v
    return None


def _blocks_equal(a: _Block, b: _Block) -> bool:
    """Structural equality of two _Block trees (ignoring line/col)."""
    if a.name != b.name or len(a.items) != len(b.items):
        return False
    for (ka, va), (kb, vb) in zip(a.items, b.items, strict=False):
        if ka != kb:
            return False
        if isinstance(va, _Block) and isinstance(vb, _Block):
            if not _blocks_equal(va, vb):
                return False
        elif va != vb:
            return False
    return True
