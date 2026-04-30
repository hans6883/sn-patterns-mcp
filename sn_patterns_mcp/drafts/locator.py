"""StepLocator + StepPredicate + locate_step(s).

A StepLocator is opaque (a draft_id + step_uid). It survives structural
mutations because the draft remaps uid → path on every edit. Predicates are
runtime-composed; locate_step(s) returns matches.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

from sn_patterns_mcp.drafts.store import Draft, _resolve_path
from sn_patterns_mcp.ndl_parser import _Block


@dataclass(frozen=True)
class StepLocator:
    draft_id: str
    step_uid: str

    def to_dict(self) -> dict[str, str]:
        return {"draft_id": self.draft_id, "step_uid": self.step_uid}

    @classmethod
    def from_dict(cls, d: dict[str, str]) -> StepLocator:
        return cls(draft_id=d["draft_id"], step_uid=d["step_uid"])


@dataclass(frozen=True)
class StepPredicate:
    """Runtime-composed step matcher. Only specified fields constrain.

    Every field is optional. When multiple fields are set, semantics are AND.
    """
    name_contains: str | None = None
    name_equals: str | None = None
    closure_keyword: str | None = None       # e.g. "run_wmi_query_to_var" or "ref"
    ref_to_refid: str | None = None          # match ref/refid steps targeting this sys_id
    attr_eq: tuple[str, str] | None = None   # (attr_name, exact_value)
    attr_contains: tuple[str, str] | None = None  # (attr_name, substring)
    section: Literal["identification", "connection", "extension", "library"] | None = None


def locate_steps(draft: Draft, pred: StepPredicate) -> list[StepLocator]:
    """Return all locators matching the predicate, in document order."""
    out: list[StepLocator] = []
    # Iterate in path order so callers get document-order results.
    sorted_uids = sorted(draft.step_uids.items(), key=lambda kv: kv[1])
    for uid, path in sorted_uids:
        blk = _resolve_path(draft.tree, path)
        if blk is None:
            continue
        if not _matches(blk, path, pred, draft):
            continue
        out.append(StepLocator(draft_id=draft.id, step_uid=uid))
    return out


def locate_step(draft: Draft, pred: StepPredicate) -> StepLocator | None:
    """Return the first locator matching the predicate, or None."""
    found = locate_steps(draft, pred)
    return found[0] if found else None


def resolve(draft: Draft, locator: StepLocator) -> _Block | None:
    """Resolve a locator to the current step _Block (None if invalidated)."""
    if locator.draft_id != draft.id:
        return None
    path = draft.step_uids.get(locator.step_uid)
    if path is None:
        return None
    return _resolve_path(draft.tree, path)


def resolve_path(draft: Draft, locator: StepLocator) -> tuple[int, ...] | None:
    """Resolve a locator to its current AST path (or None if invalidated)."""
    if locator.draft_id != draft.id:
        return None
    return draft.step_uids.get(locator.step_uid)


# ---------------------------------------------------------------------------
# Predicate matching
# ---------------------------------------------------------------------------

def _matches(blk: _Block, path: tuple[int, ...], pred: StepPredicate, draft: Draft) -> bool:
    name = _step_name(blk)
    op = _step_op(blk)

    if pred.name_equals is not None and name != pred.name_equals:
        return False
    if pred.name_contains is not None and pred.name_contains.lower() not in name.lower():
        return False

    if pred.section is not None:
        sect = _section_of(draft.tree, path)
        if sect != pred.section:
            return False

    if pred.closure_keyword is not None:
        if op is None or op.name != pred.closure_keyword:
            return False

    if pred.ref_to_refid is not None:
        rid = _ref_target(blk)
        if rid != pred.ref_to_refid:
            return False

    if pred.attr_eq is not None:
        k, v = pred.attr_eq
        actual = _op_attr_recursive(op, k) if op is not None else None
        if str(actual) != v:
            return False

    if pred.attr_contains is not None:
        k, sub = pred.attr_contains
        actual = _op_attr_recursive(op, k) if op is not None else None
        if actual is None or sub not in str(actual):
            return False

    return True


def _step_name(blk: _Block) -> str:
    for k, v in blk.items:
        if k == "name" and isinstance(v, str):
            return v
    return ""


def _step_op(blk: _Block) -> _Block | None:
    """Return the operation sub-block of a step (the first unkeyed _Block)."""
    for k, v in blk.items:
        if k is None and isinstance(v, _Block):
            return v
        if k in ("operation", "op") and isinstance(v, _Block):
            return v
    return None


def _ref_target(blk: _Block) -> str | None:
    """For a step like step{ ref { refid = X } } or step{ refid = X }, return X."""
    op = _step_op(blk)
    if op is not None:
        if op.name in ("ref", "refid"):
            for k, v in op.items:
                if k in ("refid", "id") and isinstance(v, str):
                    return v
    # Some steps put refid as a top-level key (rare).
    for k, v in blk.items:
        if k == "refid" and isinstance(v, str):
            return v
    return None


def _op_attr_recursive(op: _Block | None, key: str) -> Any:
    """Find an attribute by key anywhere in the op subtree (depth-first)."""
    if op is None:
        return None
    for k, v in op.items:
        if k == key and not isinstance(v, _Block):
            return v
    for _k, v in op.items:
        if isinstance(v, _Block):
            sub = _op_attr_recursive(v, key)
            if sub is not None:
                return sub
    return None


_SECTION_BLOCK_NAMES = {"identification", "connection", "extension"}


def _section_of(root: _Block, path: tuple[int, ...]) -> str | None:
    """Walk down `path` from root; return the section block name above the step."""
    cur: Any = root
    section: str | None = None
    if root.name == "library":
        section = "library"
    for idx in path:
        if not isinstance(cur, _Block):
            return None
        if idx >= len(cur.items):
            return None
        _k, v = cur.items[idx]
        if isinstance(v, _Block):
            if v.name in _SECTION_BLOCK_NAMES:
                section = v.name
        cur = v
    return section
