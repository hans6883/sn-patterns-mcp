"""CloneLibrary — fork a library by sys_id, open as child draft.

The cloned library:
  - has a freshly minted 32-char hex sys_id
  - has its `id` field rewritten to that new sys_id
  - has its `name` rewritten with the SANDBOX_PREFIX
  - is opened as a child draft of the requester's parent draft

Source NDL is loaded from the PatternIndex if available, or directly via PDI
client if a live client is provided. Falls back to provided source_ndl param.
"""
from __future__ import annotations

import secrets
from dataclasses import dataclass
from typing import Any

from sn_patterns_mcp.drafts.ops.base import (
    EditResult,
    Severity,
    ValidationIssue,
    register_op,
)
from sn_patterns_mcp.drafts.store import Draft
from sn_patterns_mcp.ndl_parser import _Block

# Mandatory prefix for cloned library names — same convention pattern_test_compile uses.
SANDBOX_PREFIX = "_sandbox_snmcp_"


@register_op
@dataclass(frozen=True)
class CloneLibrary:
    name: str = "clone_library"
    source_library_sys_id: str = ""         # what to clone
    new_name: str = ""                      # (will be sandbox-prefixed if not already)
    source_ndl: str | None = None           # optional override — if provided, skip lookup

    @classmethod
    def from_params(cls, p: dict[str, Any]) -> CloneLibrary:
        # parent_draft_id is intentionally NOT a parameter — apply() uses the
        # `draft` argument as the parent. Older callers may still pass it; ignore.
        return cls(
            source_library_sys_id=p["source_library_sys_id"],
            new_name=p["new_name"],
            source_ndl=p.get("source_ndl"),
        )

    def validate(self, draft: Draft, store: Any) -> list[ValidationIssue]:
        issues: list[ValidationIssue] = []
        if not self.source_library_sys_id:
            issues.append(ValidationIssue(Severity.ERROR, "MISSING_SOURCE",
                                          "source_library_sys_id is required"))
        if not self.new_name:
            issues.append(ValidationIssue(Severity.ERROR, "MISSING_NAME",
                                          "new_name is required"))
        return issues

    def apply(self, draft: Draft, store: Any) -> EditResult:
        # Note: This op operates on the *parent* draft (`draft` here) but creates a NEW
        # child draft. The `draft` arg is the parent, not the clone target.
        issues = self.validate(draft, store)
        if any(i.severity == Severity.ERROR for i in issues):
            return EditResult(ok=False, op_name=self.name, issues=issues)

        ndl = self.source_ndl
        if ndl is None:
            ndl = _load_library_ndl(self.source_library_sys_id, store)
        if ndl is None:
            return EditResult(
                ok=False, op_name=self.name,
                issues=[ValidationIssue(Severity.ERROR, "SOURCE_NOT_LOADABLE",
                                        f"library {self.source_library_sys_id} not found in pattern_index "
                                        "and no source_ndl override given")],
            )

        # Open child draft.
        child = store.open(
            source_ndl=ndl,
            source_sys_id=self.source_library_sys_id,
            parent_draft_id=draft.id,
        )
        # Mutate id + name in-place on the child's tree. _set_top_attr may insert
        # at position 0 if the key is missing, which shifts step paths. Reindex
        # the child after any mutation that could shift its step indices.
        new_sys_id = secrets.token_hex(16)
        prefixed_name = self.new_name
        if not prefixed_name.startswith(SANDBOX_PREFIX):
            prefixed_name = SANDBOX_PREFIX + prefixed_name
        _set_top_attr(child.tree, "id", new_sys_id)
        _set_top_attr(child.tree, "name", prefixed_name)
        child.reindex_steps()
        child.name = prefixed_name
        child.source_sys_id = None  # cloned, not from PDI

        # Register the child on the parent.
        draft.child_drafts[self.source_library_sys_id] = child.id
        draft.edits.append({
            "op": self.name,
            "source_library_sys_id": self.source_library_sys_id,
            "child_draft_id": child.id,
            "new_refid": new_sys_id,
            "new_name": prefixed_name,
        })
        return EditResult(
            ok=True, op_name=self.name, issues=issues,
            extra={
                "child_draft_id": child.id,
                "new_refid": new_sys_id,
                "new_name": prefixed_name,
            },
        )


def _set_top_attr(tree: _Block, key: str, value: str) -> None:
    for i, (k, _v) in enumerate(tree.items):
        if k == key:
            tree.items[i] = (k, value)
            return
    # Not found — prepend so id/name appears near the top.
    tree.items.insert(0, (key, value))


def _load_library_ndl(sys_id: str, store: Any) -> str | None:
    """Try to load library NDL from the pattern index, then PDI.

    `store` is the DraftStore — used to access optional helpers attached
    via .index / .pdi attributes (set by the MCP server on startup).
    """
    # Index-first
    index = getattr(store, "index", None)
    if index is not None:
        try:
            pattern = index.get(sys_id)
            if pattern is not None and pattern.source_ndl:
                return pattern.source_ndl
        except Exception:
            pass
    # PDI fallback
    pdi = getattr(store, "pdi", None)
    if pdi is not None:
        try:
            return pdi.get_pattern_text(sys_id)
        except Exception:
            return None
    return None
