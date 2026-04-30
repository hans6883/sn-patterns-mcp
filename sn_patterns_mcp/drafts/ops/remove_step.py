"""RemoveStep — delete a step from a section.

Validates that the step doesn't write any vars consumed by *unguarded* downstream
reads (best-effort static analysis on the current draft tree).
"""
from __future__ import annotations

import re
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
class RemoveStep:
    name: str = "remove_step"
    target: StepLocator = None  # type: ignore[assignment]
    force: bool = False  # bypass downstream-read safety check

    @classmethod
    def from_params(cls, p: dict[str, Any]) -> RemoveStep:
        return cls(
            target=StepLocator.from_dict(p["target"]),
            force=bool(p.get("force", False)),
        )

    def validate(self, draft: Draft, store: Any) -> list[ValidationIssue]:
        path = resolve_path(draft, self.target)
        if path is None or len(path) == 0:
            return [ValidationIssue(Severity.ERROR, "TARGET_NOT_FOUND",
                                    "step path resolution failed", self.target)]
        if self.force:
            return []
        # Best-effort safety: collect the vars this step writes; check whether
        # any later step reads them without is_not_empty / is_empty / contains
        # guards. If yes, ERROR (caller can use force=True).
        step_blk = _resolve_path(draft.tree, path)
        written = _vars_written_by(step_blk) if step_blk else set()
        if not written:
            return []
        unguarded_consumers = _find_unguarded_reads_after(draft.tree, path, written)
        if unguarded_consumers:
            return [ValidationIssue(
                Severity.ERROR, "REMOVE_BREAKS_DOWNSTREAM",
                f"step writes vars {sorted(written)} consumed unguarded by "
                f"{len(unguarded_consumers)} downstream step(s); use force=True to override",
                self.target,
            )]
        return []

    @reindex_after_apply
    def apply(self, draft: Draft, store: Any) -> EditResult:
        issues = self.validate(draft, store)
        if any(i.severity == Severity.ERROR for i in issues):
            return EditResult(ok=False, op_name=self.name, issues=issues)
        path = resolve_path(draft, self.target)
        if path is None or len(path) == 0:
            return EditResult(ok=False, op_name=self.name, issues=[
                ValidationIssue(Severity.ERROR, "TARGET_NOT_FOUND", "step path lost", self.target)
            ])
        parent = _resolve_path(draft.tree, path[:-1]) if len(path) > 1 else draft.tree
        if parent is None:
            return EditResult(ok=False, op_name=self.name, issues=[
                ValidationIssue(Severity.ERROR, "PARENT_NOT_FOUND", "parent block missing", self.target)
            ])
        del parent.items[path[-1]]
        draft.edits.append({"op": self.name, "target": self.target.to_dict()})
        return EditResult(ok=True, op_name=self.name, issues=issues)


# ---------------------------------------------------------------------------
# Var-flow helpers (lightweight; the full validator does deeper analysis)
# ---------------------------------------------------------------------------

def _vars_written_by(step_blk: _Block | None) -> set[str]:
    """Vars this step writes — set_attr {"x" ...}, var_names = scalar/table {name="x"}, table_name."""
    if step_blk is None:
        return set()
    out: set[str] = set()
    _collect_writes(step_blk, out)
    return out


def _collect_writes(blk: _Block, out: set[str]) -> None:
    # set_attr { "name" value }  → first positional string is the var
    if blk.name == "set_attr":
        for k, v in blk.items:
            if k is None and isinstance(v, str):
                out.add(v)
                break
    # run_*_to_var / runcmd_to_var: var_names = scalar/table { name = "x" }
    if blk.name.endswith("_to_var") or blk.name == "parse_var_to_var":
        for k, v in blk.items:
            if k == "var_names" and isinstance(v, _Block):
                for k2, v2 in v.items:
                    if k2 == "name" and isinstance(v2, str):
                        out.add(v2)
                    if isinstance(v2, _Block):
                        for k3, v3 in v2.items:
                            if k3 == "name" and isinstance(v3, str):
                                out.add(v3)
            elif k == "to_var_names" and isinstance(v, _Block):
                for k2, v2 in v.items:
                    if k2 == "name" and isinstance(v2, str):
                        out.add(v2)
    # transform / merge / union / filter target_table_name and result_table_name
    for k, v in blk.items:
        if k in ("target_table_name", "result_table_name") and isinstance(v, str):
            out.add(v)
    # Recurse
    for _k, v in blk.items:
        if isinstance(v, _Block):
            _collect_writes(v, out)


_GUARD_KEYWORDS = {"is_empty", "is_not_empty", "contains", "not_contains"}


def _find_unguarded_reads_after(
    root: _Block, deleted_path: tuple[int, ...], vars_set: set[str]
) -> list[_Block]:
    """Return downstream step blocks that read any var in vars_set without a guard.

    Best-effort — walks all steps in document order after deleted_path.
    """
    out: list[_Block] = []
    later = _steps_after(root, deleted_path)
    for blk in later:
        if _reads_unguarded(blk, vars_set):
            out.append(blk)
    return out


def _steps_after(root: _Block, deleted_path: tuple[int, ...]) -> list[_Block]:
    """All step blocks whose path sorts strictly after deleted_path."""
    from sn_patterns_mcp.drafts.store import _iter_step_paths
    out = []
    for path, blk in _iter_step_paths(root):
        if path > deleted_path:
            out.append(blk)
    return out


def _reads_unguarded(step_blk: _Block, vars_set: set[str]) -> bool:
    """True if this step reads any var in vars_set outside a guard expression."""
    return _reads_any(step_blk, vars_set, in_guard=False)


# Matches $name, ${name}, ${name[..].field} — exact word boundary on the bare $ form.
_INTERP_RE = re.compile(r"\$\{?([A-Za-z_][A-Za-z0-9_]*)")


def _reads_any(blk: _Block, vars_set: set[str], *, in_guard: bool) -> bool:
    is_guard = blk.name in _GUARD_KEYWORDS
    next_in_guard = in_guard or is_guard
    # Inspect attribute values for var refs.
    for _k, v in blk.items:
        if isinstance(v, _Block):
            if v.name == "get_attr":
                # get_attr { "varname" } or get_attr { "varname[].field" }
                for _k2, v2 in v.items:
                    if isinstance(v2, str):
                        # Match "varname" or "varname[*].x" or "varname[].x"
                        head = v2.split("[")[0].split(".")[0]
                        if head in vars_set and not next_in_guard:
                            return True
            elif _reads_any(v, vars_set, in_guard=next_in_guard):
                return True
        elif isinstance(v, str):
            # $name or ${name[...]field} interpolation. Word boundary by regex.
            for m in _INTERP_RE.finditer(v):
                if m.group(1) in vars_set and not next_in_guard:
                    return True
    return False
