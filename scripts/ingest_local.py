"""Offline ingest — builds the pattern index + auxiliary data from JSON exports
of `sa_pattern`, `sa_pattern_prepost_script`, `sa_pattern_extensions`, and
`discovery_classy_*` tables that the user has produced themselves (e.g. via
the ServiceNow Table API or the platform's "Export to JSON" UI option).

Use this when you have JSON exports on disk and prefer not to run live PDI
fetches via scripts/export_patterns.py.

Expected layout (configurable via --workspace and --raw-subdir):
    <workspace>/patterns/                  per-pattern metadata JSONs
    <workspace>/<raw-subdir>/sa_patterns_full.json
    <workspace>/<raw-subdir>/sa_prepost_scripts_full.json
    <workspace>/<raw-subdir>/sa_pattern_extensions.json
    <workspace>/<raw-subdir>/discovery_classy_*.json

Writes to sn_patterns_mcp/pattern_index/:
    manifest.json        union of patterns/*.json and sa_patterns_full.json
    prepost.json         pattern_sys_id -> pre/post scripts
    classifiers.json     all discovery_classy_* rows (linkage by name heuristic)
    extensions.json      sa_pattern_extensions rows (raw)
    ingest_summary.json  counts

Optional: --populate-chroma upserts everything into sn_patterns_structured.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from collections import defaultdict
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

# Workspace path must be supplied via --workspace, $SN_WORKSPACE, or implied
# from CWD if it contains a `patterns/` subdirectory.
DEFAULT_WORKSPACE = Path(os.environ.get("SN_WORKSPACE", "")) if os.environ.get("SN_WORKSPACE") else None
DEFAULT_RAW_SUBDIR = os.environ.get("SN_RAW_SUBDIR", "raw")

WORKSPACE: Path | None = DEFAULT_WORKSPACE
PATTERNS_DIR: Path | None = (WORKSPACE / "patterns") if WORKSPACE else None
RAW_DIR: Path | None = (WORKSPACE / DEFAULT_RAW_SUBDIR) if WORKSPACE else None


def _load_json_strip_bom(path: Path):
    raw = path.read_bytes().lstrip(b"\xef\xbb\xbf").decode("utf-8", errors="replace")
    return json.loads(raw)


def _iter_rows(doc):
    if isinstance(doc, list):
        return doc
    if isinstance(doc, dict):
        if isinstance(doc.get("result"), list):
            return doc["result"]
        for v in doc.values():
            if isinstance(v, list):
                return v
    return []


def load_pattern_metadata() -> dict[str, dict]:
    manifest: dict[str, dict] = {}

    # 1. Individual per-pattern metadata files (rich description fields, but content=null)
    if PATTERNS_DIR.exists():
        for p in PATTERNS_DIR.glob("*.json"):
            try:
                d = _load_json_strip_bom(p)
            except Exception:
                continue
            sys_id = d.get("sys_id")
            if not sys_id:
                continue
            manifest[sys_id] = {
                "sys_id": sys_id,
                "name": d.get("name", p.stem),
                "description": d.get("description", "") or "",
                "ci_type": d.get("type") or "",
                "applies_to": d.get("applies_to") or "",
                "scope": d.get("scope") or "",
                "active": d.get("active") or "",
                "version": d.get("version") or "",
                "file": str(p.relative_to(WORKSPACE)),
                "has_ndl": False,
            }

    # 2. Union with sa_patterns_full.json (the full table export incl. scoped-app patterns)
    full_path = RAW_DIR / "sa_patterns_full.json"
    if full_path.exists():
        rows = _iter_rows(_load_json_strip_bom(full_path))
        for r in rows:
            sid = r.get("sys_id")
            if not sid:
                continue
            entry = manifest.setdefault(sid, {"sys_id": sid, "has_ndl": False})
            entry.setdefault("name", r.get("name") or "")
            entry.setdefault("description", "")
            entry.setdefault("ci_type", "")
            entry["scope"] = entry.get("scope") or r.get("sys_scope.scope") or ""
            entry["active"] = entry.get("active") or r.get("active") or ""
            entry["version"] = entry.get("version") or r.get("version") or ""
            entry["sys_package"] = r.get("sys_package") or entry.get("sys_package", "")

    return manifest


def load_prepost_scripts() -> dict[str, list[dict]]:
    path = RAW_DIR / "sa_prepost_scripts_full.json"
    if not path.exists():
        return {}
    rows = _iter_rows(_load_json_strip_bom(path))
    out: dict[str, list[dict]] = defaultdict(list)
    for r in rows:
        pattern_field = r.get("pattern") or ""
        # Field is a CSV of sys_ids (sometimes a single id) or a structured object
        ids: list[str] = []
        if isinstance(pattern_field, str):
            ids = [x.strip() for x in pattern_field.split(",") if len(x.strip()) == 32]
        elif isinstance(pattern_field, dict):
            v = pattern_field.get("value")
            if isinstance(v, str):
                ids = [v]
        entry = {
            "sys_id": r.get("sys_id"),
            "name": r.get("name"),
            "active": r.get("active"),
            "scope": r.get("sys_scope.scope"),
            "script_preview": (r.get("script") or "")[:280],
        }
        for pid in ids:
            out[pid].append(entry)
    return dict(out)


_CLASSIFIER_FILES = [
    "discovery_classy_cim.json",
    "discovery_classy_http_full.json",
    "discovery_classy_http_match.json",
    "discovery_classy_param.json",
    "discovery_classy_proc.json",
    "discovery_classy_proc_to_param.json",
    "discovery_classy_scan.json",
    "discovery_classy_scan_apps.json",
    "discovery_classy_snmp.json",
    "discovery_classy_unix.json",
    "discovery_classy_windows.json",
]


def load_classifiers() -> dict[str, list[dict]]:
    """Load every classifier file; bucket them by name-inferred pattern match when possible.

    The raw dumps don't carry the pattern sys_id linkage, so classifiers are
    stored under a special "__all__" key by source file, and the resolver will
    do name-based matching at query time.
    """
    buckets: dict[str, list[dict]] = defaultdict(list)
    for fname in _CLASSIFIER_FILES:
        p = RAW_DIR / fname
        if not p.exists():
            continue
        rows = _iter_rows(_load_json_strip_bom(p))
        for r in rows:
            r.setdefault("_source_table", fname.replace(".json", ""))
            buckets["__all__"].append(r)
    return dict(buckets)


def load_extensions() -> list[dict]:
    p = RAW_DIR / "sa_pattern_extensions.json"
    if not p.exists():
        return []
    return _iter_rows(_load_json_strip_bom(p))


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--workspace",
                    default=str(DEFAULT_WORKSPACE) if DEFAULT_WORKSPACE else None,
                    help="Root directory containing your JSON exports. "
                         "Falls back to $SN_WORKSPACE if not given.")
    ap.add_argument("--raw-subdir", default=DEFAULT_RAW_SUBDIR,
                    help="Subdir of <workspace> containing sa_patterns_full.json etc.")
    ap.add_argument("--index-root", default=str(REPO_ROOT / "sn_patterns_mcp" / "pattern_index"))
    ap.add_argument("--populate-chroma", action="store_true")
    ap.add_argument("--chroma-dir", default=None)
    args = ap.parse_args()

    # Resolve the workspace + raw paths from args (override module-level defaults)
    if not args.workspace:
        sys.stderr.write(
            "ERROR: no workspace given.\n"
            "Pass --workspace <path-to-json-exports> or set $SN_WORKSPACE.\n"
        )
        sys.exit(2)
    global WORKSPACE, PATTERNS_DIR, RAW_DIR
    WORKSPACE = Path(args.workspace)
    PATTERNS_DIR = WORKSPACE / "patterns"
    RAW_DIR = WORKSPACE / args.raw_subdir
    if not WORKSPACE.exists():
        sys.stderr.write(
            f"ERROR: workspace path not found: {WORKSPACE}\n"
            f"Pass --workspace <path> or set $SN_WORKSPACE.\n"
        )
        sys.exit(2)

    root = Path(args.index_root)
    root.mkdir(parents=True, exist_ok=True)

    print("Loading per-pattern metadata files + sa_patterns_full.json ...")
    manifest = load_pattern_metadata()
    print(f"  {len(manifest)} unique patterns")

    print("Loading sa_prepost_scripts_full.json ...")
    prepost = load_prepost_scripts()
    print(f"  {sum(len(v) for v in prepost.values())} scripts across {len(prepost)} patterns")

    print("Loading 11 discovery_classy_*.json files ...")
    classifiers = load_classifiers()
    print(f"  {sum(len(v) for v in classifiers.values())} classifier rows")

    print("Loading sa_pattern_extensions.json ...")
    extensions = load_extensions()
    print(f"  {len(extensions)} extension rows")

    (root / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    (root / "prepost.json").write_text(json.dumps(prepost, indent=2), encoding="utf-8")
    (root / "classifiers.json").write_text(json.dumps(classifiers, indent=2), encoding="utf-8")
    (root / "extensions.json").write_text(json.dumps(extensions, indent=2), encoding="utf-8")

    summary = {
        "patterns": len(manifest),
        "prepost_scripts": sum(len(v) for v in prepost.values()),
        "patterns_with_prepost": len(prepost),
        "classifier_rows": sum(len(v) for v in classifiers.values()),
        "extension_rows": len(extensions),
        "has_ndl_cached": 0,
        "source": str(WORKSPACE),
    }
    (root / "ingest_summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2))

    if args.populate_chroma:
        try:
            from sn_patterns_mcp.chroma_index import ChromaPatternIndex
        except Exception as e:
            print(f"Chroma import failed ({e}); skipping.")
            return
        chroma_dir = args.chroma_dir or str(Path.home() / ".sn_patterns_mcp" / "chroma")
        print(f"Populating ChromaDB at {chroma_dir} ...")
        cidx = ChromaPatternIndex(chroma_dir)
        for sid, entry in manifest.items():
            try:
                cidx.upsert_pattern(
                    sys_id=sid,
                    name=entry.get("name", ""),
                    ci_type=entry.get("ci_type", ""),
                    operation_kws=[],
                    description=entry.get("description", ""),
                    os_types=[entry["applies_to"]] if entry.get("applies_to") else [],
                )
            except Exception as e:
                print(f"  chroma upsert failed for {sid}: {e}")
        print(f"  upserted {len(manifest)} patterns")


if __name__ == "__main__":
    main()
