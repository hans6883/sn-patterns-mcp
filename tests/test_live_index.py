"""Integration tests against a hydrated local pattern index.

Skipped if the index hasn't been built yet (scripts/ingest_local.py or
scripts/export_patterns.py).
"""
from __future__ import annotations

from pathlib import Path

import pytest

from sn_patterns_mcp.pattern_index import PatternIndex
from sn_patterns_mcp.tools import (
    pattern_analyze,
    pattern_compare,
    pattern_debug,
    pattern_resolve,
    pattern_search,
)

INDEX_ROOT = Path(__file__).resolve().parents[1] / "sn_patterns_mcp" / "pattern_index"


def _index_or_skip() -> PatternIndex:
    if not (INDEX_ROOT / "manifest.json").exists():
        pytest.skip("run scripts/ingest_local.py to build the local index first")
    idx = PatternIndex.load(INDEX_ROOT)
    if idx.is_empty():
        pytest.skip("index is empty")
    return idx


def test_index_loaded_with_expected_coverage():
    idx = _index_or_skip()
    assert idx.size() > 1000, f"expected >1000 patterns, got {idx.size()}"


def test_pattern_search_apache_returns_results():
    idx = _index_or_skip()
    out = pattern_search("Apache", index=idx, chroma=None, limit=5)
    assert "Apache" in out
    assert "sys_id=" in out


def test_pattern_search_aws():
    idx = _index_or_skip()
    out = pattern_search("Amazon AWS", index=idx, chroma=None, limit=10)
    assert "Amazon" in out or "AWS" in out


def test_pattern_analyze_metadata_only_for_known_pattern():
    idx = _index_or_skip()
    # Pick a pattern likely to be present in any reasonably hydrated corpus
    out = pattern_analyze("A10", index=idx, pdi=None)
    assert "A10" in out
    # Since NDL isn't cached, we expect the metadata-only fallback
    assert "NDL text not in local index" in out or "IDENTIFICATIONS" in out


def test_pattern_resolve_uses_local_prepost_or_classifiers():
    idx = _index_or_skip()
    # Find a pattern with known prepost scripts via the manifest
    import json
    prepost = json.loads((INDEX_ROOT / "prepost.json").read_text(encoding="utf-8"))
    if not prepost:
        pytest.skip("no prepost data loaded")
    # Pick first pattern_sys_id that exists in manifest
    target = None
    for sid in prepost:
        if sid in idx.manifest:
            target = sid
            break
    assert target, "expected overlap between prepost and manifest"
    out = pattern_resolve(target, index=idx, pdi=None)
    assert "PRE/POST SCRIPTS" in out


def test_pattern_debug_metadata_mode():
    idx = _index_or_skip()
    out = pattern_debug("A10", "wmi timeout", index=idx, pdi=None)
    assert "Debug plan" in out
    assert "sa_discovery_log" in out


def test_pattern_compare_metadata_mode():
    idx = _index_or_skip()
    # Pick two patterns both known by name
    names = [e.get("name") for e in idx.manifest.values() if e.get("name")]
    if len(names) < 2:
        pytest.skip("need at least 2 named patterns")
    a = next((n for n in names if "Apache" in n), names[0])
    b = next((n for n in names if "AWS" in n or "Amazon" in n), names[1])
    if a == b:
        b = names[1] if names[0] == a else names[0]
    out = pattern_compare(a, b, index=idx, pdi=None)
    assert "Compare" in out
    assert a.split()[0] in out or "metadata" in out.lower()
