"""Bulk export sa_pattern rows from PDI into the local pattern index.

Usage:
    python scripts/export_patterns.py [--limit 1000] [--populate-chroma]
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from sn_patterns_mcp.chroma_index import ChromaPatternIndex
from sn_patterns_mcp.pattern_index import build_index
from sn_patterns_mcp.pdi_client import try_create_client


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--index-root", default=str(REPO_ROOT / "sn_patterns_mcp" / "pattern_index"))
    ap.add_argument("--limit", type=int, default=1000)
    ap.add_argument("--populate-chroma", action="store_true")
    ap.add_argument("--chroma-dir", default=None)
    args = ap.parse_args()

    pdi = try_create_client()
    if pdi is None:
        raise SystemExit(
            "PDI credentials not found. Set SN_INSTANCE, SN_USERNAME, SN_PASSWORD."
        )

    # Page through sa_pattern in batches — try both field names for the NDL text.
    fields = ["sys_id", "name", "description", "ci_type", "cpattern_type",
              "active", "version", "ndl", "pattern_text"]
    page_size = 100
    rows: list[dict] = []
    offset = 0
    while len(rows) < args.limit:
        batch = pdi.query(
            "sa_pattern",
            sysparm_query="ORDERBYname",
            fields=fields,
            limit=min(page_size, args.limit - len(rows)),
            offset=offset,
        )
        if not batch:
            break
        rows.extend(batch)
        offset += len(batch)
        print(f"  fetched {len(rows)} rows (offset={offset})")
        if len(batch) < page_size:
            break

    # Per-row fallback for any row without NDL text
    missing = [r for r in rows if not (r.get("ndl") or r.get("pattern_text"))]
    if missing:
        print(f"  hydrating {len(missing)} rows missing NDL ...")
        for i, row in enumerate(missing):
            txt = pdi.get_pattern_text(row["sys_id"])
            if txt:
                row["ndl"] = txt
            if (i + 1) % 25 == 0:
                print(f"    {i + 1}/{len(missing)}")

    summary = build_index(args.index_root, rows)
    print(json.dumps(summary, indent=2))

    if args.populate_chroma:
        chroma_dir = args.chroma_dir or str(Path.home() / ".sn_patterns_mcp" / "chroma")
        cidx = ChromaPatternIndex(chroma_dir)
        manifest_path = Path(args.index_root) / "manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        print(f"Populating ChromaDB at {chroma_dir} ...")
        for sys_id, entry in manifest.items():
            cidx.upsert_pattern(
                sys_id=sys_id,
                name=entry.get("name", ""),
                ci_type=entry.get("ci_type", ""),
                operation_kws=list(entry.get("operation_kws", [])),
                description=entry.get("description", ""),
            )
        print(f"  upserted {len(manifest)} patterns")


if __name__ == "__main__":
    main()
