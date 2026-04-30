"""Build the OID/MIB knowledge base from public MIB collections.

Sources (all GitHub, all Apache 2.0 / public):
    librenms/librenms              ~4,700  curated, well-organized by vendor
    librenms/librenms-mibs         ~1,900  community supplement
    trevoro/snmp-mibs              ~10,900 largest single archive
    hsnodgrass/snmp_mib_archive    ~3,100  vendor-organized
    kcsinclair/mibs                ~2,800  long-running personal archive
    kmalinich/snmp-mibs              ~620  small but high-quality
    net-snmp/net-snmp                  94  canonical IETF set (RFC text)

Pipeline:
    1. List MIB blobs via GitHub tree API (one call per source).
    2. Download each blob concurrently (cached at ~/.sn_patterns_mcp/mib_cache/<repo>/).
    3. Deduplicate by MIB module name (defined inside the file as `<NAME> DEFINITIONS ::= BEGIN`).
       Standard / canonical MIBs win on conflict.
    4. Parse all unique MIBs with the regex parser (pysmi optional via --pysmi).
    5. BFS-resolve symbol names to dotted OIDs.
    6. Write a single SQLite database: sn_patterns_mcp/oids/oids.db

Re-runs reuse cached files. Pass --refresh to force re-download.

Usage:
    python scripts/build_oid_index.py                       # full multi-source build
    python scripts/build_oid_index.py --sources librenms    # one source only
    python scripts/build_oid_index.py --max-files 200       # smoke test
    python scripts/build_oid_index.py --refresh             # ignore cache
"""
from __future__ import annotations

import argparse
import collections
import concurrent.futures as cf
import logging
import re
import sys
import time
from dataclasses import dataclass
from pathlib import Path

import requests

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from scripts.mib_parser import MibParser  # noqa: E402
from sn_patterns_mcp.oids import VENDOR_PREFIXES  # noqa: E402
from sn_patterns_mcp.oids.db import build_db  # noqa: E402

CACHE_DIR = Path.home() / ".sn_patterns_mcp" / "mib_cache"
DEFAULT_DB_PATH = REPO_ROOT / "sn_patterns_mcp" / "oids" / "oids.db"
DEFAULT_WORKERS = 16

log = logging.getLogger("build_oid_index")

# Standard IETF / IRTF MIBs — when these are seen, they take priority on OID conflicts.
# Mirrors the set in sn_patterns_mcp/oids/__init__.py
STANDARD_MIBS: frozenset[str] = frozenset({
    "SNMPv2-MIB", "SNMPv2-SMI", "SNMPv2-TC", "SNMPv2-CONF", "RFC1213-MIB",
    "IF-MIB", "IF-INVERTED-STACK-MIB", "EtherLike-MIB", "MAU-MIB",
    "HOST-RESOURCES-MIB", "HOST-RESOURCES-TYPES",
    "ENTITY-MIB", "ENTITY-SENSOR-MIB", "ENTITY-STATE-MIB", "ENTITY-STATE-TC-MIB",
    "IP-MIB", "IP-FORWARD-MIB", "IPV6-MIB", "IPV6-TC", "IPV6-ICMP-MIB", "IPV6-FLOW-LABEL-MIB",
    "TCP-MIB", "UDP-MIB", "ICMP-MIB",
    "BRIDGE-MIB", "Q-BRIDGE-MIB", "P-BRIDGE-MIB", "RSTP-MIB", "MSTP-MIB",
    "RMON-MIB", "RMON2-MIB", "DSMON-MIB", "TOKEN-RING-RMON-MIB", "HCNUM-TC",
    "DISMAN-EVENT-MIB", "DISMAN-SCHEDULE-MIB",
    "SNMP-FRAMEWORK-MIB", "SNMP-MPD-MIB", "SNMP-TARGET-MIB", "SNMP-NOTIFICATION-MIB",
    "SNMP-USER-BASED-SM-MIB", "SNMP-VIEW-BASED-ACM-MIB", "SNMP-COMMUNITY-MIB",
    "INET-ADDRESS-MIB", "IANA-ADDRESS-FAMILY-NUMBERS-MIB", "IANAifType-MIB",
    "IANA-LANGUAGE-MIB", "IANA-RTPROTO-MIB", "IANA-MAU-MIB", "IANA-CHARSET-MIB",
    "DIFFSERV-MIB", "DIFFSERV-CONFIG-MIB",
    "POWER-ETHERNET-MIB", "TUNNEL-MIB", "DOT3-EPON-MIB", "DOT3-OAM-MIB",
    "LLDP-MIB", "LLDP-EXT-DOT1-MIB", "LLDP-EXT-DOT3-MIB",
    "TRANSPORT-ADDRESS-MIB", "DIRECTORY-SERVER-MIB",
    "AGENTX-MIB", "FRAME-RELAY-DTE-MIB", "OSPF-MIB", "OSPFV3-MIB", "BGP4-MIB",
    "ATM-MIB", "FDDI-SMT73-MIB", "DOCS-CABLE-DEVICE-MIB",
})


@dataclass(frozen=True)
class Source:
    """A GitHub repo containing MIB files."""
    repo: str           # owner/name
    branch: str         # branch / ref
    prefix: str         # path prefix in the repo
    priority: int       # lower = preferred when MIB module name conflicts (0 = highest)

    @property
    def key(self) -> str:
        return self.repo.split("/", 1)[1]


# Sources in priority order (most authoritative first). Conflict resolution
# below picks the source with the lowest priority number for each MIB module.
SOURCES: tuple[Source, ...] = (
    Source("net-snmp/net-snmp",          "master", "mibs/",                    priority=0),
    Source("librenms/librenms",          "master", "mibs/",                    priority=1),
    Source("librenms/librenms-mibs",     "master", "",                          priority=2),
    Source("trevoro/snmp-mibs",          "master", "mibs/",                    priority=3),
    Source("hsnodgrass/snmp_mib_archive","master", "snmp_mib_archive/",        priority=4),
    Source("kcsinclair/mibs",            "master", "",                          priority=5),
    Source("kmalinich/snmp-mibs",        "master", "",                          priority=6),
)


# Filename heuristics — accept .mib, .my, .txt, or no extension if path looks MIB-like.
_MIB_EXT_RE = re.compile(r"\.(mib|my|smi|txt)$", re.IGNORECASE)
_NON_MIB_FILES = re.compile(r"\.(md|json|yml|yaml|sh|py|gitignore|license|gitkeep)$|^LICENSE|^README", re.IGNORECASE)


def is_mib_path(path: str) -> bool:
    name = Path(path).name
    if _NON_MIB_FILES.search(name):
        return False
    # Accept anything with .mib/.my/.smi/.txt OR all-uppercase file with no ext (typical MIB convention)
    if _MIB_EXT_RE.search(name):
        return True
    if "." not in name and name.replace("-", "").replace("_", "").isupper():
        return True
    if "." not in name and len(name) > 3:
        # heuristic: librenms convention is bare names like "CISCO-PRODUCTS-MIB"
        return True
    return False


# ---------------------------------------------------------------------------
# Fetching
# ---------------------------------------------------------------------------

def fetch_tree(source: Source) -> list[dict]:
    """List all MIB blobs in one source via the GitHub tree API."""
    url = f"https://api.github.com/repos/{source.repo}/git/trees/{source.branch}?recursive=1"
    log.info("Listing %s ...", source.repo)
    r = requests.get(url, timeout=60, headers={"Accept": "application/vnd.github.v3+json"})
    if r.status_code == 404:
        log.warning("repo %s @ %s not found (404)", source.repo, source.branch)
        return []
    r.raise_for_status()
    body = r.json()
    if body.get("truncated"):
        log.warning("tree truncated for %s — some files may be missing", source.repo)
    matches: list[dict] = []
    for t in body["tree"]:
        if t["type"] != "blob":
            continue
        path = t["path"]
        if not path.startswith(source.prefix):
            continue
        if not is_mib_path(path):
            continue
        matches.append({"source": source, "path": path, "sha": t.get("sha")})
    log.info("  %s: %d MIB-shaped blobs", source.repo, len(matches))
    return matches


def fetch_one(item: dict, refresh: bool = False) -> tuple[dict, str]:
    """Download one MIB. Returns (item, text)."""
    src: Source = item["source"]
    path = item["path"]
    cache = CACHE_DIR / src.repo / path
    if cache.exists() and not refresh:
        return item, cache.read_text(encoding="utf-8", errors="replace")
    raw_url = f"https://raw.githubusercontent.com/{src.repo}/{src.branch}/{path}"
    r = requests.get(raw_url, timeout=30)
    r.raise_for_status()
    text = r.text
    cache.parent.mkdir(parents=True, exist_ok=True)
    cache.write_text(text, encoding="utf-8")
    return item, text


def fetch_all(items: list[dict], refresh: bool, workers: int) -> dict[tuple[str, str], tuple[dict, str]]:
    """Concurrent fetch. Returns {(source.repo, path): (item, text)}."""
    out: dict[tuple[str, str], tuple[dict, str]] = {}
    errors = 0
    t0 = time.time()
    with cf.ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(fetch_one, i, refresh): i for i in items}
        for n, fut in enumerate(cf.as_completed(futures), 1):
            i = futures[fut]
            try:
                item, text = fut.result()
                out[(item["source"].repo, item["path"])] = (item, text)
            except Exception as e:
                errors += 1
                log.debug("fetch failed %s/%s: %s", i["source"].repo, i["path"], e)
            if n % 500 == 0:
                log.info("  fetched %d/%d (%.1fs, %d errors)", n, len(items), time.time() - t0, errors)
    log.info("Fetched %d/%d in %.1fs (%d errors)", len(out), len(items), time.time() - t0, errors)
    return out


# ---------------------------------------------------------------------------
# MIB-name extraction + dedup
# ---------------------------------------------------------------------------

_MODULE_HEADER_RE = re.compile(r"^\s*([A-Z][\w-]+)\s+DEFINITIONS\b", re.MULTILINE)
_IMPORTS_RE = re.compile(r"\bIMPORTS\b(.+?);", re.DOTALL)
_FROM_RE = re.compile(r"\bFROM\s+([A-Z][\w-]+)")


def mib_module_name(text: str, fallback: str) -> str:
    m = _MODULE_HEADER_RE.search(text)
    return m.group(1) if m else fallback


def mib_imports(text: str) -> list[str]:
    """Return the list of MIB module names this MIB imports from."""
    seen: set[str] = set()
    for imp_block in _IMPORTS_RE.findall(text):
        for m in _FROM_RE.findall(imp_block):
            seen.add(m)
    return sorted(seen)


def dedupe_by_module(items: dict[tuple[str, str], tuple[dict, str]]) -> dict[str, tuple[dict, str]]:
    """Group fetched files by MIB module name. Source priority breaks ties.

    Same MIB module may exist in 3+ source repos; keep the highest-priority copy.
    Within the same source, keep the first occurrence.
    """
    by_module: dict[str, tuple[int, dict, str]] = {}
    skipped_no_module = 0
    for (_, path), (item, text) in items.items():
        fallback = Path(path).stem
        name = mib_module_name(text, fallback)
        if not name or len(name) < 2:
            skipped_no_module += 1
            continue
        priority = item["source"].priority
        existing = by_module.get(name)
        if existing is None or priority < existing[0]:
            by_module[name] = (priority, item, text)
    if skipped_no_module:
        log.info("skipped %d files with no detectable MIB module name", skipped_no_module)
    return {name: (item, text) for name, (_, item, text) in by_module.items()}


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--sources", default="all",
                    help="Comma-separated source keys (e.g. 'librenms,trevoro'). Default: all configured.")
    ap.add_argument("--workers", type=int, default=DEFAULT_WORKERS)
    ap.add_argument("--max-files", type=int, default=0, help="Cap (0 = unlimited)")
    ap.add_argument("--refresh", action="store_true", help="Re-download even if cached")
    ap.add_argument("--db-path", default=str(DEFAULT_DB_PATH), help="Output SQLite path")
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
    )

    # Source selection
    if args.sources == "all":
        sources = SOURCES
    else:
        keys = {s.strip() for s in args.sources.split(",")}
        sources = tuple(s for s in SOURCES if s.key in keys or s.repo.split("/")[1] in keys)
        if not sources:
            log.error("No sources matched %r. Available: %s", args.sources, [s.key for s in SOURCES])
            return 1

    log.info("=== HARVEST: %d source repos ===", len(sources))
    all_items: list[dict] = []
    for s in sources:
        all_items.extend(fetch_tree(s))
    log.info("Total candidate files across sources: %d", len(all_items))

    if args.max_files > 0:
        all_items = all_items[: args.max_files]
        log.info("Capped to first %d", len(all_items))

    # Phase 1: fetch
    fetched = fetch_all(all_items, args.refresh, args.workers)

    # Phase 2: dedupe by module name
    log.info("Deduplicating by MIB module name ...")
    unique = dedupe_by_module(fetched)
    log.info("Unique MIB modules: %d (from %d files)", len(unique), len(fetched))

    # Phase 3: parse all into a global symbol table
    log.info("Parsing %d unique MIBs ...", len(unique))
    parser = MibParser()
    imports_by_mib: dict[str, list[str]] = {}
    parse_errors = 0
    for name, (_item, text) in unique.items():
        try:
            parser.parse(text, source_mib=name)
        except Exception as e:
            parse_errors += 1
            log.debug("parse error %s: %s", name, e)
            continue
        try:
            imps = mib_imports(text)
            if imps:
                imports_by_mib[name] = imps
        except Exception:
            pass
    log.info("Symbol table: %d definitions (%d parse errors)", len(parser.defs), parse_errors)

    # Phase 4: resolve
    log.info("Resolving OIDs ...")
    entries = parser.resolve()
    log.info("Resolved: %d entries  (unresolved: %d)", len(entries), len(parser.parse_warnings))

    # Group entries by source MIB
    by_mib: dict[str, list[dict]] = collections.defaultdict(list)
    for e in entries:
        by_mib[e["mib"]].append(e)

    # Phase 5: write SQLite DB
    log.info("Writing SQLite DB at %s ...", args.db_path)
    counts = build_db(
        db_path=args.db_path,
        entries_by_mib=dict(by_mib),
        vendor_prefixes=[(vp.prefix, vp.vendor, vp.description) for vp in VENDOR_PREFIXES],
        standard_mibs=set(STANDARD_MIBS),
        mib_imports=imports_by_mib,
        parser_name="regex",
        build_metadata={
            "built_at": str(int(time.time())),
            "sources": ",".join(s.repo for s in sources),
            "total_files_fetched": str(len(fetched)),
            "unique_mibs": str(len(unique)),
            "parse_errors": str(parse_errors),
            "unresolved_symbols": str(len(parser.parse_warnings)),
        },
    )

    log.info("=== BUILD COMPLETE ===")
    print(f"\n{'=' * 60}")
    print("OID DATABASE BUILD SUMMARY")
    print(f"{'=' * 60}")
    print(f"Sources:           {len(sources)} repos")
    print(f"Files fetched:     {len(fetched)}")
    print(f"Unique MIBs:       {len(unique)}")
    print(f"Symbols parsed:    {len(parser.defs)}")
    print(f"OIDs resolved:     {len(entries)}")
    print(f"Unresolved:        {len(parser.parse_warnings)}")
    print(f"DB rows written:   {counts}")
    print(f"DB path:           {args.db_path}")
    print(f"DB size:           {Path(args.db_path).stat().st_size / 1024 / 1024:.1f} MB")
    print(f"Cache:             {CACHE_DIR}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
