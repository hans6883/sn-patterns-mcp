"""InsertStepBefore / InsertStepAfter — insert a step relative to a target.

Accepts either a recipe reference (preferred — validated NDL with parameter
contract) or a raw NDL fragment.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from sn_patterns_mcp.drafts.locator import StepLocator, resolve_path
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


def _materialize_or_parse(
    *,
    ndl_fragment: str | None,
    recipe: str | None,
    closure: str | None,
    params: dict[str, Any],
) -> tuple[_Block | None, ValidationIssue | None]:
    """Materialize a step _Block from either an inline NDL fragment or a recipe.

    Recipe form requires (closure, recipe). Returns (block, None) on success
    or (None, issue) on failure.
    """
    if recipe is not None:
        # Defer import to avoid circular dependency at module load.
        from sn_patterns_mcp.closures.recipes import get_recipe
        if not closure:
            return None, ValidationIssue(
                Severity.ERROR, "RECIPE_MISSING_CLOSURE",
                "recipe parameter requires `closure` to also be set",
            )
        rec = get_recipe(closure, recipe)
        if rec is None:
            return None, ValidationIssue(
                Severity.ERROR, "RECIPE_NOT_FOUND",
                f"recipe {closure}.{recipe} not registered",
            )
        try:
            ndl = rec.materialize(params)
        except Exception as e:
            return None, ValidationIssue(
                Severity.ERROR, "RECIPE_MATERIALIZE_FAILED",
                f"recipe {closure}.{recipe} failed to materialize: {e}",
            )
    elif ndl_fragment is not None:
        ndl = ndl_fragment
    else:
        return None, ValidationIssue(
            Severity.ERROR, "INSERT_NEEDS_FRAGMENT_OR_RECIPE",
            "must provide either ndl_fragment or recipe",
        )
    try:
        blk = parse_ndl_block(ndl)
    except Exception as e:
        return None, ValidationIssue(
            Severity.ERROR, "FRAGMENT_PARSE_ERROR",
            f"NDL fragment failed to parse: {e}",
        )
    if not isinstance(blk, _Block) or blk.name != "step":
        return None, ValidationIssue(
            Severity.ERROR, "FRAGMENT_NOT_STEP",
            f"fragment must be a step block (got {blk.name if isinstance(blk, _Block) else type(blk).__name__})",
        )
    return blk, None


def _insert_at(draft: Draft, target: StepLocator, *, before: bool, blk: _Block) -> EditResult:
    op_name = "insert_step_before" if before else "insert_step_after"
    path = resolve_path(draft, target)
    if path is None or len(path) == 0:
        return EditResult(
            ok=False, op_name=op_name,
            issues=[ValidationIssue(Severity.ERROR, "TARGET_NOT_FOUND",
                                    "step path resolution failed", target)],
        )
    # Parent block = path[:-1]; insert index in parent items = path[-1] (or +1 for after).
    parent_path = path[:-1]
    parent_blk = _resolve_path(draft.tree, parent_path) if parent_path else draft.tree
    if parent_blk is None:
        return EditResult(
            ok=False, op_name=op_name,
            issues=[ValidationIssue(Severity.ERROR, "PARENT_NOT_FOUND",
                                    "parent block resolution failed", target)],
        )
    insert_idx = path[-1] if before else path[-1] + 1
    parent_blk.items.insert(insert_idx, (None, blk))
    return EditResult(ok=True, op_name=op_name, issues=[])


@register_op
@dataclass(frozen=True)
class InsertStepBefore:
    name: str = "insert_step_before"
    target: StepLocator = None  # type: ignore[assignment]
    ndl_fragment: str | None = None
    recipe: str | None = None
    closure: str | None = None
    params: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_params(cls, p: dict[str, Any]) -> InsertStepBefore:
        return cls(
            target=StepLocator.from_dict(p["target"]),
            ndl_fragment=p.get("ndl_fragment"),
            recipe=p.get("recipe"),
            closure=p.get("closure"),
            params=p.get("params", {}) or {},
        )

    def validate(self, draft: Draft, store: Any) -> list[ValidationIssue]:
        if resolve_path(draft, self.target) is None:
            return [ValidationIssue(Severity.ERROR, "TARGET_NOT_FOUND",
                                    f"step locator {self.target.step_uid} not found", self.target)]
        _, err = _materialize_or_parse(
            ndl_fragment=self.ndl_fragment, recipe=self.recipe,
            closure=self.closure, params=self.params,
        )
        return [err] if err else []

    @reindex_after_apply
    def apply(self, draft: Draft, store: Any) -> EditResult:
        blk, err = _materialize_or_parse(
            ndl_fragment=self.ndl_fragment, recipe=self.recipe,
            closure=self.closure, params=self.params,
        )
        if err is not None:
            return EditResult(ok=False, op_name=self.name, issues=[err])
        result = _insert_at(draft, self.target, before=True, blk=blk)  # type: ignore[arg-type]
        if result.ok:
            draft.edits.append({"op": self.name, "target": self.target.to_dict()})
        return result


@register_op
@dataclass(frozen=True)
class InsertStepAfter:
    name: str = "insert_step_after"
    target: StepLocator = None  # type: ignore[assignment]
    ndl_fragment: str | None = None
    recipe: str | None = None
    closure: str | None = None
    params: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_params(cls, p: dict[str, Any]) -> InsertStepAfter:
        return cls(
            target=StepLocator.from_dict(p["target"]),
            ndl_fragment=p.get("ndl_fragment"),
            recipe=p.get("recipe"),
            closure=p.get("closure"),
            params=p.get("params", {}) or {},
        )

    def validate(self, draft: Draft, store: Any) -> list[ValidationIssue]:
        if resolve_path(draft, self.target) is None:
            return [ValidationIssue(Severity.ERROR, "TARGET_NOT_FOUND",
                                    f"step locator {self.target.step_uid} not found", self.target)]
        _, err = _materialize_or_parse(
            ndl_fragment=self.ndl_fragment, recipe=self.recipe,
            closure=self.closure, params=self.params,
        )
        return [err] if err else []

    @reindex_after_apply
    def apply(self, draft: Draft, store: Any) -> EditResult:
        blk, err = _materialize_or_parse(
            ndl_fragment=self.ndl_fragment, recipe=self.recipe,
            closure=self.closure, params=self.params,
        )
        if err is not None:
            return EditResult(ok=False, op_name=self.name, issues=[err])
        result = _insert_at(draft, self.target, before=False, blk=blk)  # type: ignore[arg-type]
        if result.ok:
            draft.edits.append({"op": self.name, "target": self.target.to_dict()})
        return result
