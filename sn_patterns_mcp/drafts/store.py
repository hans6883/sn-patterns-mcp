"""Draft + DraftStore.

A Draft holds a mutable parse tree (_Block) for one pattern under edit, plus a
stable UID per step that survives structural mutations (insert/remove). Edit
ops mutate the tree in place; validation re-derives the typed Pattern view
from the current tree.

Drafts can have child drafts (via CloneLibrary). The cross-draft validator
walks parent → child redirect chains.
"""
from __future__ import annotations

import logging
import secrets
from dataclasses import dataclass, field
from typing import Any

from sn_patterns_mcp.ndl_parser import NdlParser, _Block
from sn_patterns_mcp.ndl_writer import NdlWriter

log = logging.getLogger(__name__)


# A path through the _Block tree: tuple of (item-index | (name, key-index))
# We use plain integer indices for items within a block. This is computed
# fresh each time it's needed; the only stable identifier is StepLocator.step_uid.
AstPath = tuple[int, ...]


@dataclass
class Draft:
    """One pattern (or library) under edit."""
    id: str
    source_sys_id: str | None        # None for synthesized clones
    source_ndl: str
    name: str                         # current name (may change via edits)
    is_library: bool                  # True if root block is "library"
    tree: _Block                      # mutable AST
    edits: list[dict[str, Any]] = field(default_factory=list)  # audit log
    step_uids: dict[str, AstPath] = field(default_factory=dict)  # uid -> current path
    child_drafts: dict[str, str] = field(default_factory=dict)  # source_refid -> child draft id
    parent_draft_id: str | None = None
    validation_state: Any = None      # last ValidationReport (lazy)
    compile_state: Any = None         # last CompileReport

    # uid -> id(_Block) of the step's _Block object. Stable across content
    # mutations of the step's children (WrapInGuard, RedirectRef, ModifyClosureAttr).
    step_block_ids: dict[str, int] = field(default_factory=dict)

    def reindex_steps(self) -> None:
        """Rebuild step_uids -> path map from the current tree.

        UIDs are anchored to step _Block object identity (id(blk)). Steps whose
        block object survives the edit keep their UID — guaranteeing locator
        stability across content-only mutations. Newly inserted step blocks
        get fresh UIDs; removed step blocks have their UIDs (and id-mapping)
        retired.
        """
        live_steps = _iter_step_paths(self.tree)
        new_uids: dict[str, AstPath] = {}
        new_block_ids: dict[str, int] = {}
        # Reverse map: object-id -> existing UID (for survivors)
        existing_id_to_uid = {bid: uid for uid, bid in self.step_block_ids.items()}
        for path, blk in live_steps:
            blk_id = id(blk)
            uid = existing_id_to_uid.get(blk_id)
            if uid is None:
                uid = _new_uid()
            new_uids[uid] = path
            new_block_ids[uid] = blk_id
        self.step_uids = new_uids
        self.step_block_ids = new_block_ids


@dataclass
class DraftStore:
    """In-memory dict of drafts. Lives for the life of the MCP server process."""
    _drafts: dict[str, Draft] = field(default_factory=dict)

    def open(
        self,
        *,
        source_ndl: str,
        source_sys_id: str | None,
        parent_draft_id: str | None = None,
    ) -> Draft:
        parser = NdlParser()
        tree = parser.parse_tree(source_ndl)
        # Determine name + library-ness from the tree.
        name = ""
        is_library = (tree.name == "library")
        for k, v in tree.items:
            if k == "name" and isinstance(v, str):
                name = v
            elif k is None and isinstance(v, _Block) and v.name == "metadata":
                for k2, v2 in v.items:
                    if k2 == "name" and isinstance(v2, str):
                        name = v2
        draft = Draft(
            id=_new_uid(prefix="d"),
            source_sys_id=source_sys_id,
            source_ndl=source_ndl,
            name=name,
            is_library=is_library,
            tree=tree,
            parent_draft_id=parent_draft_id,
        )
        draft.reindex_steps()
        self._drafts[draft.id] = draft
        return draft

    def get(self, draft_id: str) -> Draft:
        d = self._drafts.get(draft_id)
        if d is None:
            raise KeyError(f"draft not found: {draft_id}")
        return d

    def has(self, draft_id: str) -> bool:
        return draft_id in self._drafts

    def abandon(self, draft_id: str) -> None:
        d = self._drafts.pop(draft_id, None)
        if d is None:
            return
        # Recursively drop child drafts.
        for cid in list(d.child_drafts.values()):
            self.abandon(cid)

    def serialize(self, draft_id: str) -> str:
        d = self.get(draft_id)
        return NdlWriter().write(d.tree)


# Module-level singleton store. The MCP server uses this; tests can either
# share or instantiate their own DraftStore directly.
DRAFTS = DraftStore()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _new_uid(prefix: str = "s") -> str:
    return f"{prefix}_{secrets.token_hex(4)}"


def _iter_step_paths(blk: _Block, prefix: AstPath = ()) -> list[tuple[AstPath, _Block]]:
    """Walk the block tree and yield every step block with its path.

    Path is the index sequence into items[] (positional or keyed) needed to
    reach the block from the tree root.
    """
    out: list[tuple[AstPath, _Block]] = []
    for i, (_k, v) in enumerate(blk.items):
        if isinstance(v, _Block):
            sub_path: AstPath = prefix + (i,)
            if v.name == "step":
                out.append((sub_path, v))
            # Recurse — patterns nest steps inside identification/connection/extension.
            out.extend(_iter_step_paths(v, sub_path))
    return out


def _resolve_path(blk: _Block, path: AstPath) -> _Block | None:
    """Walk a path; return the _Block at that path, or None if invalid."""
    cur: Any = blk
    for idx in path:
        if not isinstance(cur, _Block):
            return None
        if idx >= len(cur.items):
            return None
        _k, v = cur.items[idx]
        cur = v
    return cur if isinstance(cur, _Block) else None


