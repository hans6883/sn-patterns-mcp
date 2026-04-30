"""MCP tool implementations for the surgical-edit harness.

All tools accept primitives + a draft store; never raise; format ERROR: lines on failure.
The MCP server passes a singleton DraftStore (with .index / .pdi attached for
CloneLibrary lookups).
"""
from __future__ import annotations

import difflib
import json
import logging
from typing import Any

from sn_patterns_mcp.closures.recipes import list_recipes
from sn_patterns_mcp.drafts.locator import (
    StepPredicate,
    locate_steps,
    resolve,
)
from sn_patterns_mcp.drafts.ops.base import OP_REGISTRY, dispatch
from sn_patterns_mcp.drafts.store import DraftStore
from sn_patterns_mcp.drafts.validator import validate_draft
from sn_patterns_mcp.ndl_writer import NdlWriter

log = logging.getLogger(__name__)

MAX_CHARS = 8000


def _clip(s: str) -> str:
    if len(s) <= MAX_CHARS:
        return s
    return s[: MAX_CHARS - 60] + "\n\n... [truncated to 8000 chars]"


def _err(msg: str) -> str:
    return f"ERROR: {msg}"


# ---------------------------------------------------------------------------
# Lookup helpers
# ---------------------------------------------------------------------------

def _load_pattern_ndl(name_or_sys_id: str, *, index, pdi) -> tuple[str | None, str | None]:
    """Returns (ndl, sys_id) — index first, PDI fallback. None,None if not found."""
    if index is not None:
        sys_id = index.resolve_sys_id(name_or_sys_id)
        if sys_id is not None:
            pattern = index.get(sys_id)
            if pattern is not None and pattern.source_ndl:
                return pattern.source_ndl, sys_id
    if pdi is not None:
        try:
            row = pdi.get_pattern(name_or_sys_id)
            if row and row.get("pattern_text"):
                return row["pattern_text"], row.get("sys_id")
        except Exception as e:
            log.warning("PDI fetch failed for %r: %s", name_or_sys_id, e)
    return None, None


# ---------------------------------------------------------------------------
# pattern_open_draft
# ---------------------------------------------------------------------------

def pattern_open_draft(name_or_sys_id: str, *, store: DraftStore, index, pdi) -> str:
    ndl, sys_id = _load_pattern_ndl(name_or_sys_id, index=index, pdi=pdi)
    if ndl is None:
        return _err(f"pattern not found: {name_or_sys_id!r}")
    try:
        d = store.open(source_ndl=ndl, source_sys_id=sys_id)
    except Exception as e:
        return _err(f"failed to open draft: {e}")
    return _clip(json.dumps({
        "draft_id": d.id,
        "source_sys_id": d.source_sys_id,
        "name": d.name,
        "is_library": d.is_library,
        "step_count": len(d.step_uids),
    }, indent=2))


# ---------------------------------------------------------------------------
# draft_locate_steps
# ---------------------------------------------------------------------------

def draft_locate_steps(
    draft_id: str,
    predicate: dict[str, Any],
    *,
    store: DraftStore,
    limit: int = 50,
) -> str:
    if not store.has(draft_id):
        return _err(f"draft not found: {draft_id}")
    draft = store.get(draft_id)
    try:
        pred = _predicate_from_dict(predicate or {})
    except Exception as e:
        return _err(f"invalid predicate: {e}")
    locs = locate_steps(draft, pred)[:limit]
    out: list[dict[str, Any]] = []
    for loc in locs:
        blk = resolve(draft, loc)
        if blk is None:
            continue
        name = ""
        op_kw = ""
        for k, v in blk.items:
            if k == "name" and isinstance(v, str):
                name = v
            elif k is None:
                from sn_patterns_mcp.ndl_parser import _Block
                if isinstance(v, _Block):
                    op_kw = v.name
                    break
        out.append({"locator": loc.to_dict(), "name": name, "operation": op_kw})
    return _clip(json.dumps({"draft_id": draft_id, "matches": out}, indent=2))


def _predicate_from_dict(d: dict[str, Any]) -> StepPredicate:
    attr_eq = d.get("attr_eq")
    attr_contains = d.get("attr_contains")
    return StepPredicate(
        name_contains=d.get("name_contains"),
        name_equals=d.get("name_equals"),
        closure_keyword=d.get("closure_keyword"),
        ref_to_refid=d.get("ref_to_refid"),
        attr_eq=tuple(attr_eq) if attr_eq else None,
        attr_contains=tuple(attr_contains) if attr_contains else None,
        section=d.get("section"),
    )


# ---------------------------------------------------------------------------
# draft_apply
# ---------------------------------------------------------------------------

def draft_apply(
    draft_id: str,
    op_name: str,
    params: dict[str, Any],
    *,
    store: DraftStore,
) -> str:
    if not store.has(draft_id):
        return _err(f"draft not found: {draft_id}")
    if op_name not in OP_REGISTRY:
        return _err(f"unknown op: {op_name!r} (known: {sorted(OP_REGISTRY)})")
    draft = store.get(draft_id)
    p = dict(params or {})
    try:
        op = dispatch(op_name, p)
    except Exception as e:
        return _err(f"failed to dispatch op {op_name!r}: {e}")
    try:
        result = op.apply(draft, store)
    except Exception as e:
        log.exception("apply %s failed", op_name)
        return _err(f"op {op_name!r} apply raised: {e}")
    return _clip(json.dumps(result.to_dict(), indent=2))


# ---------------------------------------------------------------------------
# draft_validate
# ---------------------------------------------------------------------------

def draft_validate(draft_id: str, *, store: DraftStore) -> str:
    if not store.has(draft_id):
        return _err(f"draft not found: {draft_id}")
    draft = store.get(draft_id)
    try:
        report = validate_draft(draft, store)
    except Exception as e:
        log.exception("validate failed")
        return _err(f"validation raised: {e}")
    return _clip(json.dumps(report.to_dict(), indent=2))


# ---------------------------------------------------------------------------
# draft_diff
# ---------------------------------------------------------------------------

def draft_diff(draft_id: str, *, store: DraftStore) -> str:
    if not store.has(draft_id):
        return _err(f"draft not found: {draft_id}")
    draft = store.get(draft_id)
    try:
        current = NdlWriter().write(draft.tree)
    except Exception as e:
        return _err(f"failed to serialize draft: {e}")
    diff = "\n".join(difflib.unified_diff(
        draft.source_ndl.splitlines(),
        current.splitlines(),
        fromfile=f"{draft.name} (original)",
        tofile=f"{draft.name} (draft {draft.id})",
        n=3,
        lineterm="",
    ))
    if not diff:
        return f"(no changes in draft {draft.id})"
    return _clip(diff)


# ---------------------------------------------------------------------------
# draft_finalize
# ---------------------------------------------------------------------------

def draft_finalize(
    draft_id: str,
    *,
    store: DraftStore,
    pdi: Any = None,
    mode: str = "sandbox",
) -> str:
    """Modes:
        'serialize_only' — return current NDL, do nothing else
        'sandbox'        — push to PDI as sandbox row (sa_pattern with prefix)
        'push_live'      — overwrite the actual sa_pattern row [DANGEROUS, requires confirm]
    """
    if not store.has(draft_id):
        return _err(f"draft not found: {draft_id}")
    draft = store.get(draft_id)
    try:
        ndl = NdlWriter().write(draft.tree)
    except Exception as e:
        return _err(f"serialize failed: {e}")
    if mode == "serialize_only":
        return _clip(ndl)
    if mode in ("sandbox", "push_live") and pdi is None:
        return _err(f"finalize mode={mode!r} requires a configured PDI client")
    if mode == "sandbox":
        try:
            sandbox_name = draft.name if draft.name.startswith("_sandbox_snmcp_") else f"_sandbox_snmcp_{draft.name}"
            row = pdi.create_pattern(name=sandbox_name, ndl=ndl)
            return _clip(json.dumps({"mode": "sandbox", "sys_id": row.get("sys_id"),
                                     "name": sandbox_name}, indent=2))
        except Exception as e:
            log.exception("sandbox finalize failed")
            return _err(f"sandbox push failed: {e}")
    if mode == "push_live":
        return _err("push_live not implemented (intentional safety guard); use sandbox + manual review")
    return _err(f"unknown mode: {mode!r}")


# ---------------------------------------------------------------------------
# draft_abandon
# ---------------------------------------------------------------------------

def draft_abandon(draft_id: str, *, store: DraftStore) -> str:
    if not store.has(draft_id):
        return _err(f"draft not found: {draft_id}")
    store.abandon(draft_id)
    return f"draft {draft_id} abandoned"


# ---------------------------------------------------------------------------
# closure_capability
# ---------------------------------------------------------------------------

def closure_capability(closure_keyword: str) -> str:
    """Describe a closure: signature + recipes addressing its limitations.

    Always returns a JSON object with:
      - closure: the keyword
      - known: true if it's in the descriptor registry (90 cataloged closures)
      - registry: descriptor fields (class_name, inputs, outputs, summary,
        category, failure_modes) if known; empty otherwise
      - recipes: list of recipes attached to this closure (may be empty)
      - hint: only present when known=false; suggests what the agent can do
    """
    from sn_patterns_mcp.closures import registry as closure_registry
    desc = closure_registry.get(closure_keyword)
    recipes = list_recipes(closure_keyword)
    out: dict[str, Any] = {"closure": closure_keyword, "known": desc is not None}
    if desc is not None:
        out["registry"] = {
            "class_name": getattr(desc, "class_name", None),
            "category": getattr(getattr(desc, "category", None), "value", None),
            "summary": getattr(desc, "summary", "") or "",
            "inputs": list(getattr(desc, "inputs", []) or []),
            "outputs": list(getattr(desc, "outputs", []) or []),
            "failure_modes": list(getattr(desc, "failure_modes", []) or []),
        }
    else:
        out["registry"] = {}
        out["hint"] = (
            "Closure keyword is not in the registered catalog. The harness can "
            "still locate, wrap, or modify steps using this keyword via predicates "
            "(closure_keyword=...). Validation will skip required-input checks for it."
        )
    out["recipes"] = [
        {
            "name": r.name,
            "purpose": r.purpose,
            "addresses_limitation": r.addresses_limitation,
            "parameters": r.parameters,
            "requires_vars": r.requires_vars,
            "declares_vars": r.declares_vars,
        }
        for r in recipes
    ]
    return _clip(json.dumps(out, indent=2))


__all__ = [
    "pattern_open_draft",
    "draft_locate_steps",
    "draft_apply",
    "draft_validate",
    "draft_diff",
    "draft_finalize",
    "draft_abandon",
    "closure_capability",
]
