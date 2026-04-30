"""SQLite-backed OID/MIB store.

Schema lives in a single file (~50-200MB depending on corpus size):
    sn_patterns_mcp/oids/oids.db

Why SQLite:
  - Cold start <50ms (vs 3s loading 2,361 JSON files)
  - RAM <20MB resident (vs ~150MB for in-memory dicts)
  - Indexed B-tree lookups on oid, name, parent_oid (sub-millisecond)
  - FTS5 virtual table for keyword search across descriptions
  - Single file artifact — easy to ship, easy to swap

The writer (build_oid_db) is invoked from scripts/build_oid_index.py and
populates the DB from the parsed MIB corpus. The reader (OidStore) is the
runtime — it's used by the OidRegistry facade in __init__.py.
"""
from __future__ import annotations

import logging
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)

DEFAULT_DB_PATH = Path(__file__).parent / "oids.db"


SCHEMA = """
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS mibs (
    id            INTEGER PRIMARY KEY,
    name          TEXT UNIQUE NOT NULL,
    is_standard   INTEGER NOT NULL DEFAULT 0,
    source_url    TEXT,
    fetched_at    INTEGER,           -- unix timestamp
    parser        TEXT NOT NULL DEFAULT 'regex',
    entry_count   INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS oid_entries (
    oid          TEXT PRIMARY KEY,
    name         TEXT NOT NULL,
    mib_id       INTEGER NOT NULL REFERENCES mibs(id),
    syntax       TEXT NOT NULL DEFAULT '',
    access       TEXT NOT NULL DEFAULT '',
    description  TEXT NOT NULL DEFAULT '',
    is_table     INTEGER NOT NULL DEFAULT 0,
    is_columnar  INTEGER NOT NULL DEFAULT 0,
    parent_oid   TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_oid_name        ON oid_entries(name);
CREATE INDEX IF NOT EXISTS idx_oid_parent      ON oid_entries(parent_oid);
CREATE INDEX IF NOT EXISTS idx_oid_mib         ON oid_entries(mib_id);

CREATE TABLE IF NOT EXISTS vendor_prefixes (
    prefix       TEXT PRIMARY KEY,
    vendor       TEXT NOT NULL,
    description  TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS mib_imports (
    mib_id       INTEGER NOT NULL REFERENCES mibs(id),
    imports_mib  TEXT NOT NULL,
    PRIMARY KEY (mib_id, imports_mib)
);

CREATE TABLE IF NOT EXISTS build_metadata (
    key          TEXT PRIMARY KEY,
    value        TEXT NOT NULL
);

-- Full-text search across (name, description, mib). Maintained by triggers
-- below so it stays in sync with oid_entries.
CREATE VIRTUAL TABLE IF NOT EXISTS oid_fts USING fts5(
    oid UNINDEXED, name, description, mib_name UNINDEXED,
    tokenize='porter ascii'
);
"""


@dataclass(frozen=True)
class OidRow:
    """One row from oid_entries — same shape as the legacy OidEntry dataclass."""
    oid: str
    name: str
    mib: str
    syntax: str
    access: str
    description: str
    is_table: bool = False
    is_columnar: bool = False

    @property
    def full_name(self) -> str:
        return f"{self.mib}::{self.name}"

    @property
    def parent_oid(self) -> str:
        return self.oid.rsplit(".", 1)[0] if "." in self.oid else ""


@contextmanager
def connect(path: str | Path = DEFAULT_DB_PATH, read_only: bool = False) -> Iterator[sqlite3.Connection]:
    """Open the DB. Read-only connections are cheaper to set up and let multiple
    readers run concurrently without WAL contention."""
    p = Path(path)
    if read_only:
        if not p.exists():
            raise FileNotFoundError(f"OID database not found: {p}")
        uri = f"file:{p.as_posix()}?mode=ro"
        conn = sqlite3.connect(uri, uri=True, check_same_thread=False)
    else:
        p.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(p), check_same_thread=False)
        conn.executescript(SCHEMA)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Writer — populates the DB from parsed MIB entries
# ---------------------------------------------------------------------------

def build_db(
    db_path: str | Path,
    entries_by_mib: dict[str, list[dict]],
    vendor_prefixes: list[tuple[str, str, str]],
    standard_mibs: set[str],
    mib_imports: dict[str, list[str]] | None = None,
    parser_name: str = "regex",
    build_metadata: dict[str, str] | None = None,
) -> dict[str, int]:
    """Build the SQLite database from the parsed corpus.

    entries_by_mib: {mib_name: [{oid, name, syntax, access, description, ...}, ...]}
    vendor_prefixes: [(prefix_oid, vendor_name, description), ...]
    standard_mibs: set of MIB names considered authoritative (IETF set)
    mib_imports: {mib_name: [imports_mib_name, ...]}
    Returns a stats dict with row counts.
    """
    p = Path(db_path)
    if p.exists():
        p.unlink()  # rebuild from scratch — simpler than incremental sync
    counts = {"mibs": 0, "entries": 0, "vendors": 0, "imports": 0}

    with connect(p) as conn:
        cur = conn.cursor()
        # Vendors
        for prefix, vendor, desc in vendor_prefixes:
            cur.execute(
                "INSERT OR REPLACE INTO vendor_prefixes(prefix, vendor, description) VALUES (?,?,?)",
                (prefix, vendor, desc),
            )
            counts["vendors"] += 1
        # MIBs — need to insert rows first to get IDs, then fill entries
        mib_id_by_name: dict[str, int] = {}
        for mib_name, mib_entries in entries_by_mib.items():
            is_std = 1 if mib_name in standard_mibs else 0
            cur.execute(
                "INSERT INTO mibs(name, is_standard, parser, entry_count) VALUES (?,?,?,?)",
                (mib_name, is_std, parser_name, len(mib_entries)),
            )
            mib_id_by_name[mib_name] = cur.lastrowid
            counts["mibs"] += 1

        # IMPORTS edges
        if mib_imports:
            for mib_name, imports in mib_imports.items():
                mib_id = mib_id_by_name.get(mib_name)
                if mib_id is None:
                    continue
                for imp in imports:
                    cur.execute(
                        "INSERT OR IGNORE INTO mib_imports(mib_id, imports_mib) VALUES (?,?)",
                        (mib_id, imp),
                    )
                    counts["imports"] += 1

        # OID entries — first-write-wins to handle conflicts. Standard MIBs
        # are inserted first so their entries claim ambiguous OIDs.
        # We insert standard MIBs first, then non-standard.
        ordered_mibs = sorted(
            entries_by_mib.keys(),
            key=lambda m: (0 if m in standard_mibs else 1, m),
        )
        seen_oids: set[str] = set()
        for mib_name in ordered_mibs:
            mib_id = mib_id_by_name[mib_name]
            for raw in entries_by_mib[mib_name]:
                oid = raw["oid"]
                if oid in seen_oids:
                    continue
                seen_oids.add(oid)
                parent = oid.rsplit(".", 1)[0] if "." in oid else ""
                cur.execute(
                    """INSERT INTO oid_entries
                       (oid, name, mib_id, syntax, access, description, is_table, is_columnar, parent_oid)
                       VALUES (?,?,?,?,?,?,?,?,?)""",
                    (
                        oid,
                        raw["name"],
                        mib_id,
                        raw.get("syntax", "") or "",
                        raw.get("access", "") or "",
                        raw.get("description", "") or "",
                        1 if raw.get("is_table") else 0,
                        1 if raw.get("is_columnar") else 0,
                        parent,
                    ),
                )
                counts["entries"] += 1

        # Populate FTS5 — single bulk INSERT is much faster than per-row triggers
        cur.execute(
            """INSERT INTO oid_fts(oid, name, description, mib_name)
               SELECT e.oid, e.name, e.description, m.name
                 FROM oid_entries e JOIN mibs m ON m.id = e.mib_id"""
        )

        # Build metadata
        if build_metadata:
            for k, v in build_metadata.items():
                cur.execute(
                    "INSERT OR REPLACE INTO build_metadata(key, value) VALUES (?,?)",
                    (k, str(v)),
                )

        conn.commit()
        cur.execute("ANALYZE")
        conn.commit()

    return counts


# ---------------------------------------------------------------------------
# Reader — used at runtime by OidRegistry
# ---------------------------------------------------------------------------

class OidStore:
    """Read-only SQLite store. Thread-safe (sqlite3 with check_same_thread=False
    + read-only URI). Connection is cached per-instance.
    """

    def __init__(self, db_path: str | Path = DEFAULT_DB_PATH) -> None:
        self.db_path = Path(db_path)
        self._conn: sqlite3.Connection | None = None

    def _conn_or_open(self) -> sqlite3.Connection:
        if self._conn is None:
            uri = f"file:{self.db_path.as_posix()}?mode=ro"
            self._conn = sqlite3.connect(uri, uri=True, check_same_thread=False)
            self._conn.row_factory = sqlite3.Row
        return self._conn

    # --------------- introspection ---------------

    def exists(self) -> bool:
        return self.db_path.exists()

    def stats(self) -> dict[str, int]:
        if not self.exists():
            return {"mibs": 0, "entries": 0}
        c = self._conn_or_open().cursor()
        return {
            "mibs": c.execute("SELECT COUNT(*) FROM mibs").fetchone()[0],
            "entries": c.execute("SELECT COUNT(*) FROM oid_entries").fetchone()[0],
            "standard_mibs": c.execute("SELECT COUNT(*) FROM mibs WHERE is_standard=1").fetchone()[0],
            "vendors": c.execute("SELECT COUNT(*) FROM vendor_prefixes").fetchone()[0],
        }

    def size(self) -> int:
        return self.stats()["entries"]

    # --------------- lookups ---------------

    def get_by_oid(self, oid: str) -> OidRow | None:
        c = self._conn_or_open().cursor()
        row = c.execute(
            """SELECT e.oid, e.name, m.name AS mib, e.syntax, e.access, e.description,
                      e.is_table, e.is_columnar
                 FROM oid_entries e JOIN mibs m ON m.id = e.mib_id
                WHERE e.oid = ?""",
            (oid,),
        ).fetchone()
        return _row_to_oid(row) if row else None

    def get_by_name(self, name: str) -> OidRow | None:
        """Look up by short name. If multiple MIBs define the same name, prefer
        the entry whose MIB is marked standard."""
        c = self._conn_or_open().cursor()
        row = c.execute(
            """SELECT e.oid, e.name, m.name AS mib, e.syntax, e.access, e.description,
                      e.is_table, e.is_columnar
                 FROM oid_entries e JOIN mibs m ON m.id = e.mib_id
                WHERE e.name = ?
                ORDER BY m.is_standard DESC, m.name ASC
                LIMIT 1""",
            (name,),
        ).fetchone()
        return _row_to_oid(row) if row else None

    def get_by_full_name(self, mib: str, name: str) -> OidRow | None:
        c = self._conn_or_open().cursor()
        row = c.execute(
            """SELECT e.oid, e.name, m.name AS mib, e.syntax, e.access, e.description,
                      e.is_table, e.is_columnar
                 FROM oid_entries e JOIN mibs m ON m.id = e.mib_id
                WHERE m.name = ? AND e.name = ?
                LIMIT 1""",
            (mib, name),
        ).fetchone()
        return _row_to_oid(row) if row else None

    def children(self, parent_oid: str) -> list[OidRow]:
        c = self._conn_or_open().cursor()
        rows = c.execute(
            """SELECT e.oid, e.name, m.name AS mib, e.syntax, e.access, e.description,
                      e.is_table, e.is_columnar
                 FROM oid_entries e JOIN mibs m ON m.id = e.mib_id
                WHERE e.parent_oid = ?
                ORDER BY e.oid""",
            (parent_oid,),
        ).fetchall()
        return [_row_to_oid(r) for r in rows]

    def vendor_prefixes(self) -> list[tuple[str, str, str]]:
        c = self._conn_or_open().cursor()
        rows = c.execute("SELECT prefix, vendor, description FROM vendor_prefixes").fetchall()
        return [(r["prefix"], r["vendor"], r["description"]) for r in rows]

    def standard_mibs(self) -> set[str]:
        c = self._conn_or_open().cursor()
        rows = c.execute("SELECT name FROM mibs WHERE is_standard=1").fetchall()
        return {r["name"] for r in rows}

    def fts_search(self, query: str, limit: int = 25) -> list[OidRow]:
        """FTS5 full-text search over name + description. Returns best matches."""
        if not query.strip():
            return []
        c = self._conn_or_open().cursor()
        rows = c.execute(
            """SELECT e.oid, e.name, m.name AS mib, e.syntax, e.access, e.description,
                      e.is_table, e.is_columnar
                 FROM oid_fts f
                 JOIN oid_entries e ON e.oid = f.oid
                 JOIN mibs m ON m.id = e.mib_id
                WHERE oid_fts MATCH ?
                ORDER BY rank
                LIMIT ?""",
            (_sanitize_fts_query(query), limit),
        ).fetchall()
        return [_row_to_oid(r) for r in rows]

    def iter_all(self, batch_size: int = 1000) -> Iterator[OidRow]:
        c = self._conn_or_open().cursor()
        offset = 0
        while True:
            rows = c.execute(
                """SELECT e.oid, e.name, m.name AS mib, e.syntax, e.access, e.description,
                          e.is_table, e.is_columnar
                     FROM oid_entries e JOIN mibs m ON m.id = e.mib_id
                    ORDER BY e.oid
                    LIMIT ? OFFSET ?""",
                (batch_size, offset),
            ).fetchall()
            if not rows:
                return
            for r in rows:
                yield _row_to_oid(r)
            offset += len(rows)


def _row_to_oid(row: sqlite3.Row | dict[str, Any]) -> OidRow:
    return OidRow(
        oid=row["oid"],
        name=row["name"],
        mib=row["mib"],
        syntax=row["syntax"] or "",
        access=row["access"] or "",
        description=row["description"] or "",
        is_table=bool(row["is_table"]),
        is_columnar=bool(row["is_columnar"]),
    )


def _sanitize_fts_query(q: str) -> str:
    """FTS5 has its own query syntax. We treat the input as a phrase by default;
    individual words are AND'd. Strip characters that would break the parser."""
    cleaned = "".join(c if c.isalnum() or c in " -_." else " " for c in q.strip())
    words = [w for w in cleaned.split() if len(w) > 1]
    if not words:
        return cleaned or '""'
    return " ".join(words)


__all__ = ["OidStore", "OidRow", "build_db", "connect", "DEFAULT_DB_PATH", "SCHEMA"]
