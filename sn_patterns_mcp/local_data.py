"""Offline data loader — reads pre-exported metadata dumps alongside the index.

Data files (optional; all produced by scripts/ingest_local.py):
    manifest.json        { sys_id: {name, ci_type, description, scope, active, ...} }
    prepost.json         { pattern_sys_id: [{sys_id,name,active,scope,script_preview}, ...] }
    classifiers.json     { pattern_sys_id: [...] }   or a global list if linkage unknown
    extensions.json      [{sys_id, pattern, ...}, ...]

Any file missing is tolerated (empty dict/list). Consumers must be robust.
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)


class LocalData:
    def __init__(self, root: Path) -> None:
        self.root = Path(root)

    def _read(self, name: str, default):
        p = self.root / name
        if not p.exists():
            return default
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except json.JSONDecodeError as e:
            log.warning("local-data %s is corrupt JSON: %s — treating as empty", p, e)
            return default
        except OSError as e:
            log.warning("local-data %s could not be read: %s — treating as empty", p, e)
            return default

    def prepost_for(self, pattern_sys_id: str) -> list[dict[str, Any]]:
        data = self._read("prepost.json", {})
        return data.get(pattern_sys_id, []) if isinstance(data, dict) else []

    def classifiers_for(self, pattern_sys_id: str) -> list[dict[str, Any]]:
        data = self._read("classifiers.json", {})
        if isinstance(data, dict):
            return data.get(pattern_sys_id, [])
        return []

    def all_classifiers(self) -> list[dict[str, Any]]:
        data = self._read("classifiers.json", {})
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            out: list[dict[str, Any]] = []
            for v in data.values():
                if isinstance(v, list):
                    out.extend(v)
            return out
        return []

    def extensions_for(self, pattern_sys_id: str) -> list[dict[str, Any]]:
        rows = self._read("extensions.json", [])
        if not isinstance(rows, list):
            return []
        out: list[dict[str, Any]] = []
        for row in rows:
            ref = str(row.get("pattern", ""))
            if pattern_sys_id in ref:
                out.append(row)
        return out


__all__ = ["LocalData"]
