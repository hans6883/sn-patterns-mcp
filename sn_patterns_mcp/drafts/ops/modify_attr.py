"""ModifyClosureAttr — change one attribute on a step's operation tree."""
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


@register_op
@dataclass(frozen=True)
class ModifyClosureAttr:
    name: str = "modify_closure_attr"
    target: StepLocator = None  # type: ignore[assignment]
    # Path inside the step's op tree, expressed as a tuple of keys.
    # ("query",) targets the top-level operation's `query` attribute.
    # ("on_true", "src_table_name") goes one level deeper.
    attr_path: tuple[str, ...] = field(default_factory=tuple)
    # Either a literal scalar (string/int) — set verbatim — or an NDL fragment
    # (rendered into a _Block first).
    new_value: Any = None
    new_value_is_ndl: bool = False

    @classmethod
    def from_params(cls, p: dict[str, Any]) -> ModifyClosureAttr:
        return cls(
            target=StepLocator.from_dict(p["target"]),
            attr_path=tuple(p["attr_path"]),
            new_value=p["new_value"],
            new_value_is_ndl=bool(p.get("new_value_is_ndl", False)),
        )

    def validate(self, draft: Draft, store: Any) -> list[ValidationIssue]:
        issues: list[ValidationIssue] = []
        if not self.attr_path:
            issues.append(ValidationIssue(
                Severity.ERROR, "EMPTY_ATTR_PATH",
                "attr_path must be a non-empty tuple of keys",
                self.target,
            ))
        if resolve_path(draft, self.target) is None:
            issues.append(ValidationIssue(
                Severity.ERROR, "TARGET_NOT_FOUND",
                f"step locator {self.target.step_uid} not found",
                self.target,
            ))
        if self.new_value_is_ndl and isinstance(self.new_value, str):
            try:
                parse_ndl_block(self.new_value)
            except Exception as e:
                issues.append(ValidationIssue(
                    Severity.ERROR, "NEW_VALUE_PARSE_ERROR",
                    f"new_value (NDL) failed to parse: {e}",
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
        op_blk = _step_op_block(step_blk)  # type: ignore[arg-type]
        if op_blk is None:
            return EditResult(
                ok=False, op_name=self.name,
                issues=[ValidationIssue(Severity.ERROR, "STEP_HAS_NO_OPERATION",
                                        "step has no inner operation", self.target)],
            )
        # Walk attr_path, last key is the attribute to set.
        cur = op_blk
        for key in self.attr_path[:-1]:
            sub = _find_keyed(cur, key)
            if sub is None or not isinstance(sub, _Block):
                return EditResult(
                    ok=False, op_name=self.name,
                    issues=[ValidationIssue(Severity.ERROR, "ATTR_PATH_NOT_FOUND",
                                            f"attr_path key {key!r} not found in op tree",
                                            self.target)],
                )
            cur = sub
        last_key = self.attr_path[-1]
        new_val: Any
        if self.new_value_is_ndl and isinstance(self.new_value, str):
            new_val = parse_ndl_block(self.new_value)
        else:
            new_val = self.new_value
        # Find existing attribute by key and replace; or append.
        for i, (k, _v) in enumerate(cur.items):
            if k == last_key:
                cur.items[i] = (k, new_val)
                draft.edits.append({"op": self.name, "target": self.target.to_dict(),
                                    "attr_path": list(self.attr_path)})
                return EditResult(ok=True, op_name=self.name, issues=issues)
        # Not found — append.
        cur.items.append((last_key, new_val))
        draft.edits.append({"op": self.name, "target": self.target.to_dict(),
                            "attr_path": list(self.attr_path), "added": True})
        return EditResult(ok=True, op_name=self.name, issues=issues)


def _step_op_block(step_blk: _Block) -> _Block | None:
    for k, v in step_blk.items:
        if isinstance(v, _Block) and (k is None or k in ("operation", "op")):
            return v
    return None


def _find_keyed(blk: _Block, key: str) -> Any:
    for k, v in blk.items:
        if k == key:
            return v
    return None
