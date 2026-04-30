"""ChromaDB wrapper for sn_patterns_structured collection."""
from __future__ import annotations

from pathlib import Path
from typing import Any

COLLECTION = "sn_patterns_structured"


class ChromaPatternIndex:
    def __init__(self, persist_dir: str | Path) -> None:
        self.persist_dir = Path(persist_dir)
        self._client = None
        self._collection = None

    def _ensure(self):
        if self._collection is not None:
            return self._collection
        import chromadb
        self._client = chromadb.PersistentClient(path=str(self.persist_dir))
        self._collection = self._client.get_or_create_collection(
            name=COLLECTION,
            metadata={"description": "Structured sa_pattern index — operation-type + CI-target aware"},
        )
        return self._collection

    def upsert_pattern(
        self,
        sys_id: str,
        name: str,
        ci_type: str,
        operation_kws: list[str],
        description: str,
        os_types: list[str] | None = None,
    ) -> None:
        col = self._ensure()
        text = self._summary_text(name, ci_type, description, operation_kws, os_types or [])
        col.upsert(
            ids=[sys_id],
            documents=[text],
            metadatas=[{
                "name": name,
                "ci_type": ci_type or "",
                "description": description or "",
                "operation_kws": ",".join(sorted(set(operation_kws))),
                "os_types": ",".join(sorted(set(os_types or []))),
            }],
        )

    def search(self, query: str, n: int = 10, where: dict[str, Any] | None = None) -> list[dict[str, Any]]:
        col = self._ensure()
        res = col.query(query_texts=[query], n_results=n, where=where)
        out: list[dict[str, Any]] = []
        ids = (res.get("ids") or [[]])[0]
        metas = (res.get("metadatas") or [[]])[0]
        docs = (res.get("documents") or [[]])[0]
        dists = (res.get("distances") or [[]])[0]
        for sys_id, meta, doc, dist in zip(ids, metas, docs, dists, strict=False):
            out.append({"sys_id": sys_id, "metadata": meta, "document": doc, "distance": dist})
        return out

    def _summary_text(
        self,
        name: str,
        ci_type: str,
        description: str,
        operation_kws: list[str],
        os_types: list[str],
    ) -> str:
        parts = [f"Pattern: {name}"]
        if ci_type:
            parts.append(f"CI type: {ci_type}")
        if description:
            parts.append(f"Description: {description}")
        if os_types:
            parts.append(f"OS: {', '.join(os_types)}")
        if operation_kws:
            parts.append(f"Operations: {', '.join(sorted(set(operation_kws)))}")
        return "\n".join(parts)


__all__ = ["ChromaPatternIndex", "COLLECTION"]
