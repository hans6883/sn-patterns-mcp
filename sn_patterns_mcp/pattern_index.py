"""On-disk JSON cache of parsed patterns + manifest with semantic facets.

Layout:
    pattern_index/
        manifest.json          {sys_id: {name, ci_type, path, operation_kws, library_refs}}
        patterns/<sys_id>.json {metadata, parsed, source_ndl}
        parse_failures.json    {sys_id, name, reason} for any row that failed to parse
        unknown_keywords.log   NDL keywords missing from closure registry (for registry feedback)
        # offline auxiliary data (from scripts/ingest_local.py):
        prepost.json, classifiers.json, extensions.json

Build via scripts/export_patterns.py (live PDI) or scripts/ingest_local.py (offline).
Load at MCP startup with PatternIndex.load(root).
"""
from __future__ import annotations

import dataclasses
import json
import logging
import re
from collections.abc import Iterator
from dataclasses import asdict, is_dataclass
from enum import Enum
from pathlib import Path
from typing import Any

from sn_patterns_mcp.ndl_parser import NdlParser
from sn_patterns_mcp.pattern_model import Pattern

log = logging.getLogger(__name__)

# Path-safety: sys_ids from PDI rows are interpolated into filenames.
# Reject anything that isn't a 32-char hex string before constructing a path.
_SYS_ID_RE = re.compile(r"^[0-9a-fA-F]{32}$")


def _default_encode(obj: Any) -> Any:
    if is_dataclass(obj):
        return asdict(obj)
    if isinstance(obj, Enum):
        return obj.value
    if isinstance(obj, (set, frozenset)):
        return list(obj)
    raise TypeError(f"Cannot JSON-encode {type(obj).__name__}")


class PatternIndex:
    """Loads + queries the local parsed-pattern cache."""

    def __init__(self, root: Path, manifest: dict[str, Any]) -> None:
        self.root = Path(root)
        self.manifest: dict[str, dict[str, Any]] = manifest
        self._patterns_dir = self.root / "patterns"
        self._cache: dict[str, Pattern] = {}
        self._by_name: dict[str, str] = {
            (entry.get("name") or "").lower(): sys_id
            for sys_id, entry in manifest.items()
        }
        # Lazy-loaded offline auxiliary data (classifiers, prepost, extensions)
        from sn_patterns_mcp.local_data import LocalData
        self.local = LocalData(self.root)

    def metadata_for(self, name_or_sys_id: str) -> dict[str, Any] | None:
        sys_id = self.resolve_sys_id(name_or_sys_id)
        return self.manifest.get(sys_id) if sys_id else None

    def has_ndl_cache(self, sys_id: str) -> bool:
        return (self._patterns_dir / f"{sys_id}.json").exists()

    # ------------------------------------------------------------------
    # Loading
    # ------------------------------------------------------------------

    @classmethod
    def load(cls, root: str | Path) -> PatternIndex:
        root_path = Path(root)
        manifest_path = root_path / "manifest.json"
        if not manifest_path.exists():
            return cls(root=root_path, manifest={})
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        return cls(root=root_path, manifest=manifest)

    def is_empty(self) -> bool:
        return not self.manifest

    def size(self) -> int:
        return len(self.manifest)

    # ------------------------------------------------------------------
    # Lookup
    # ------------------------------------------------------------------

    def resolve_sys_id(self, name_or_sys_id: str) -> str | None:
        if not name_or_sys_id:
            return None
        if name_or_sys_id in self.manifest:
            return name_or_sys_id
        return self._by_name.get(name_or_sys_id.lower())

    def get(self, name_or_sys_id: str) -> Pattern | None:
        sys_id = self.resolve_sys_id(name_or_sys_id)
        if sys_id is None or not _SYS_ID_RE.match(sys_id):
            return None
        if sys_id in self._cache:
            return self._cache[sys_id]
        path = self._patterns_dir / f"{sys_id}.json"
        if not path.exists():
            return None
        try:
            ndl_text = json.loads(path.read_text(encoding="utf-8")).get("source_ndl")
        except (json.JSONDecodeError, OSError) as e:
            log.warning("failed to read cached pattern %s: %s", sys_id, e)
            return None
        if not ndl_text:
            return None
        try:
            pattern = NdlParser().parse(ndl_text)
        except Exception as e:
            log.warning("cached pattern %s failed to re-parse (rebuild index?): %s", sys_id, e)
            return None
        self._cache[sys_id] = pattern
        return pattern

    def search_text(self, query: str, limit: int = 20) -> list[dict[str, Any]]:
        """Simple substring search over manifest (name, ci_type, ops)."""
        q = query.lower()
        hits: list[dict[str, Any]] = []
        for sys_id, entry in self.manifest.items():
            hay = " ".join(
                str(entry.get(k, "")) for k in ("name", "ci_type", "description")
            ).lower()
            if q in hay or any(q in op for op in entry.get("operation_kws", [])):
                hits.append({"sys_id": sys_id, **entry})
                if len(hits) >= limit:
                    break
        return hits

    def iter_all(self) -> Iterator[tuple[str, Pattern]]:
        for sys_id in self.manifest:
            pattern = self.get(sys_id)
            if pattern is not None:
                yield sys_id, pattern

    def add_in_memory(
        self,
        *,
        sys_id: str,
        name: str,
        pattern: Pattern,
        ci_type: str = "",
        description: str = "",
        source: str = "ingested",
    ) -> dict[str, Any]:
        """Add a session-scoped pattern to the index without writing to disk.

        The entry is flagged not_authoritative=true so downstream tools can
        distinguish ingested patterns from PDI-fetched ones. The Pattern is
        precached so PatternIndex.get() returns it without disk lookup.

        Returns the manifest entry (for confirmation in the MCP response).
        """
        op_kws: list[str] = []
        try:
            op_kws = sorted(set(pattern.operation_keywords()))
        except Exception:  # pragma: no cover - defensive
            pass
        entry = {
            "name": name,
            "description": description,
            "ci_type": ci_type,
            "cpattern_type": "0",
            "operation_kws": op_kws,
            "not_authoritative": True,
            "source": source,
        }
        self.manifest[sys_id] = entry
        self._cache[sys_id] = pattern
        if name:
            self._by_name[name.lower()] = sys_id
        return entry


# ---------------------------------------------------------------------------
# Builder — consumes raw sa_pattern rows, parses NDL, writes JSON cache
# ---------------------------------------------------------------------------

def build_index(
    root: str | Path,
    rows: list[dict[str, Any]],
    parser: NdlParser | None = None,
) -> dict[str, Any]:
    """Build the on-disk index from a list of sa_pattern rows.

    Each row must have at least: sys_id, name, pattern_text.
    Optional: description, ci_type, cpattern_type, active, version.

    Returns a summary dict — counts, parse failures, unknown keyword tally.
    """
    root_path = Path(root)
    patterns_dir = root_path / "patterns"
    patterns_dir.mkdir(parents=True, exist_ok=True)
    parser = parser or NdlParser()
    manifest: dict[str, dict[str, Any]] = {}
    parse_failures: list[dict[str, Any]] = []
    unknown_keywords: dict[str, int] = {}

    for row in rows:
        sys_id = row.get("sys_id")
        ndl_text = row.get("ndl") or row.get("pattern_text")
        if not sys_id or not isinstance(sys_id, str) or not _SYS_ID_RE.match(sys_id):
            log.warning("skipping row with invalid sys_id: %r", sys_id)
            parse_failures.append({"sys_id": sys_id, "reason": "invalid sys_id (must be 32 hex chars)"})
            continue
        if not ndl_text:
            parse_failures.append({"sys_id": sys_id, "name": row.get("name"), "reason": "missing ndl text"})
            continue
        try:
            pattern = parser.parse(ndl_text)
        except Exception as e:
            log.warning("parse failed for %s (%s): %s: %s", sys_id, row.get("name"), type(e).__name__, e)
            parse_failures.append({
                "sys_id": sys_id,
                "name": row.get("name"),
                "reason": type(e).__name__ + ": " + str(e)[:500],
            })
            continue

        # Serialize parsed tree + keep source NDL for roundtrip tests
        payload = {
            "sys_id": sys_id,
            "name": row.get("name"),
            "description": row.get("description", ""),
            "ci_type": row.get("ci_type") or pattern.metadata.ci_type,
            "cpattern_type": row.get("cpattern_type"),
            "version": row.get("version"),
            "active": row.get("active"),
            "source_ndl": ndl_text,
            "parsed": _pattern_to_dict(pattern),
        }
        (patterns_dir / f"{sys_id}.json").write_text(
            json.dumps(payload, ensure_ascii=False, default=_default_encode), encoding="utf-8",
        )
        manifest[sys_id] = {
            "name": row.get("name"),
            "description": row.get("description", ""),
            "ci_type": row.get("ci_type") or pattern.metadata.ci_type,
            "operation_kws": sorted(set(pattern.operation_keywords())),
            "library_refs": pattern.library_references(),
            "path": f"patterns/{sys_id}.json",
        }
        # Collect unknown keywords for registry feedback
        from sn_patterns_mcp.closures.registry import CLOSURE_REGISTRY
        for kw in pattern.operation_keywords():
            if kw not in CLOSURE_REGISTRY and kw.lower() not in CLOSURE_REGISTRY:
                unknown_keywords[kw] = unknown_keywords.get(kw, 0) + 1

    (root_path / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2, default=_default_encode),
        encoding="utf-8",
    )
    if parse_failures:
        (root_path / "parse_failures.json").write_text(
            json.dumps(parse_failures, ensure_ascii=False, indent=2), encoding="utf-8",
        )
    if unknown_keywords:
        lines = [f"{kw}\t{count}" for kw, count in sorted(unknown_keywords.items(), key=lambda kv: -kv[1])]
        (root_path / "unknown_keywords.log").write_text("\n".join(lines), encoding="utf-8")

    return {
        "total_rows": len(rows),
        "indexed": len(manifest),
        "parse_failures": len(parse_failures),
        "unknown_keyword_count": len(unknown_keywords),
    }


def _pattern_to_dict(p: Pattern) -> dict[str, Any]:
    return {
        "metadata": dataclasses.asdict(p.metadata),
        "identifications": [
            {
                "name": i.name,
                "entry_point_types": i.entry_point_types,
                "find_process_strategy": i.find_process_strategy.value if i.find_process_strategy else None,
                "steps": [_step_to_dict(s) for s in i.steps],
            }
            for i in p.identifications
        ],
        "connections": [
            {
                "name": c.name,
                "steps": [_step_to_dict(s) for s in c.steps],
            }
            for c in p.connections
        ],
        "extensions": [
            {
                "name": e.name,
                "order": e.order,
                "steps": [_step_to_dict(s) for s in e.steps],
            }
            for e in p.extensions
        ],
        "pattern_type": p.pattern_type.value,
    }


def _step_to_dict(s) -> dict[str, Any]:
    return {
        "name": s.name,
        "comment": s.comment,
        "disabled": s.disabled,
        "library_ref": s.library_ref,
        "operation": _op_to_dict(s.operation) if s.operation else None,
        "precondition": _op_to_dict(s.precondition) if s.precondition else None,
    }


def _op_to_dict(op) -> dict[str, Any]:
    return {
        "keyword": op.keyword,
        "class_name": op.class_name,
        "attributes": op.attributes,
        "operands": {k: _op_to_dict(v) for k, v in op.operands.items()},
        "list_operands": [_op_to_dict(v) for v in op.list_operands],
        "positional_args": list(op.positional_args),
    }


__all__ = ["PatternIndex", "build_index"]
