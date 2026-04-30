"""ChromaDB collection wrapper for semantic OID search.

Collection: `sn_oids` — embeds (name + description + MIB) per OID. Use for
natural-language queries that keyword-match (FTS5) can't handle, e.g.:
    "interface error counters"
    "BGP session state"
    "memory utilization for line cards"

Build the collection from a populated SQLite OID DB via `populate_from_db()`.
At runtime, the OidChromaIndex.search() method returns the top N matches.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

COLLECTION = "sn_oids"


class OidChromaIndex:
    """Thin wrapper around a Chroma collection of OID embeddings."""

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
            metadata={"description": "Semantic index over (name + description + MIB) per OID"},
        )
        return self._collection

    def upsert(self, oid: str, name: str, mib: str, syntax: str, description: str,
               is_table: bool = False, is_columnar: bool = False) -> None:
        col = self._ensure()
        text = self._embed_text(name, mib, syntax, description)
        col.upsert(
            ids=[oid],
            documents=[text],
            metadatas=[{
                "name": name,
                "mib": mib,
                "syntax": syntax,
                "is_table": is_table,
                "is_columnar": is_columnar,
            }],
        )

    def upsert_batch(self, batch: list[dict[str, Any]]) -> None:
        """Batch insert. Each dict needs keys: oid, name, mib, syntax, description,
        is_table, is_columnar."""
        if not batch:
            return
        col = self._ensure()
        col.upsert(
            ids=[b["oid"] for b in batch],
            documents=[self._embed_text(b["name"], b["mib"], b.get("syntax", ""), b.get("description", "")) for b in batch],
            metadatas=[{
                "name": b["name"],
                "mib": b["mib"],
                "syntax": b.get("syntax", ""),
                "is_table": bool(b.get("is_table", False)),
                "is_columnar": bool(b.get("is_columnar", False)),
            } for b in batch],
        )

    def search(self, query: str, n: int = 10) -> list[dict[str, Any]]:
        col = self._ensure()
        res = col.query(query_texts=[query], n_results=n)
        ids = (res.get("ids") or [[]])[0]
        metas = (res.get("metadatas") or [[]])[0]
        docs = (res.get("documents") or [[]])[0]
        dists = (res.get("distances") or [[]])[0]
        return [
            {"oid": oid, "metadata": meta, "document": doc, "distance": dist}
            for oid, meta, doc, dist in zip(ids, metas, docs, dists, strict=False)
        ]

    def count(self) -> int:
        col = self._ensure()
        return col.count()

    @staticmethod
    def _embed_text(name: str, mib: str, syntax: str, description: str) -> str:
        """Compose the text fed to the embedder. Order matters slightly: name + MIB
        is the most identifying signal, then description provides the long-form match."""
        parts = [f"{name}", f"MIB: {mib}"]
        if syntax:
            parts.append(f"Syntax: {syntax}")
        if description:
            parts.append(description)
        return "\n".join(parts)


def populate_from_db(db_path: str | Path, chroma_dir: str | Path,
                     batch_size: int = 500, limit: int | None = None) -> int:
    """Walk every row in oids.db and upsert into the Chroma collection.

    Returns count of OIDs embedded. Filters out columnar entries (they're
    repetitive and not useful as standalone search results) and entries with
    no description (no semantic signal).
    """
    from sn_patterns_mcp.oids.db import OidStore

    store = OidStore(db_path)
    if not store.exists():
        raise FileNotFoundError(f"OID database not found: {db_path}")
    chroma = OidChromaIndex(chroma_dir)

    total = 0
    batch: list[dict[str, Any]] = []
    for row in store.iter_all(batch_size=2000):
        # Skip pure-columnar rows: a query like "interface description" should
        # match ifDescr (the column definition), not the 10K instance rows.
        # Keep table headers + scalars + group nodes.
        if row.is_columnar and not row.description:
            continue
        # Keep rows with descriptions OR table/group structure
        if not row.description and not row.is_table:
            continue
        batch.append({
            "oid": row.oid,
            "name": row.name,
            "mib": row.mib,
            "syntax": row.syntax,
            "description": row.description,
            "is_table": row.is_table,
            "is_columnar": row.is_columnar,
        })
        if len(batch) >= batch_size:
            chroma.upsert_batch(batch)
            total += len(batch)
            batch.clear()
            if limit and total >= limit:
                break
    if batch:
        chroma.upsert_batch(batch)
        total += len(batch)
    log.info("Populated Chroma %s: %d OIDs embedded", COLLECTION, total)
    return total


__all__ = ["OidChromaIndex", "COLLECTION", "populate_from_db"]
