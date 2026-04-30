"""Tests for pattern_ingest_ndl: session-scoped pattern ingestion."""
import json
import tempfile
from pathlib import Path

import pytest

from sn_patterns_mcp.pattern_index import PatternIndex
from sn_patterns_mcp.tools import pattern_ingest_ndl


@pytest.fixture
def empty_index() -> PatternIndex:
    with tempfile.TemporaryDirectory() as td:
        yield PatternIndex(root=Path(td), manifest={})


@pytest.fixture
def caller_ndl() -> str:
    return (Path(__file__).parent / "fixtures" / "fixture_caller_pattern.ndl").read_text(encoding="utf-8")


def test_ingest_adds_pattern_to_in_memory_index(empty_index, caller_ndl):
    out = pattern_ingest_ndl("Forum thread #1234", caller_ndl, index=empty_index)
    payload = json.loads(out)
    assert payload["ok"] is True
    assert payload["not_authoritative"] is True
    sys_id = payload["sys_id"]
    assert empty_index.size() == 1
    pat = empty_index.get(sys_id)
    assert pat is not None
    assert empty_index.manifest[sys_id]["not_authoritative"] is True


def test_ingest_uses_metadata_id_when_real_sys_id(empty_index):
    """If the NDL has metadata.id that's a real 32-hex sys_id, reuse it."""
    real_id = "a" * 32
    ndl = (
        'pattern { metadata { id = "' + real_id + '" name = "T" '
        'citype = "cmdb_ci_x" } identification { name = "x" '
        'step { name = "s" set_attr { "x" "y" } } } }'
    )
    out = pattern_ingest_ndl("T", ndl, index=empty_index)
    payload = json.loads(out)
    assert payload["sys_id"] == real_id


def test_ingest_mints_hex_when_metadata_id_not_sysid_shape(empty_index, caller_ndl):
    """The fixture has metadata.id with underscores — gets a fresh 32-hex sys_id minted."""
    out = pattern_ingest_ndl("X", caller_ndl, index=empty_index)
    payload = json.loads(out)
    sys_id = payload["sys_id"]
    assert len(sys_id) == 32
    assert all(c in "0123456789abcdef" for c in sys_id)


def test_ingest_renames_when_name_conflicts_with_authoritative(empty_index, caller_ndl):
    """If the name already exists in the index from PDI, ingest gets '(ingested)' suffix."""
    # Pre-populate with an authoritative entry (not_authoritative=False / missing).
    empty_index.manifest["a" * 32] = {
        "name": "Existing PDI pattern", "ci_type": "cmdb_ci_x", "operation_kws": [],
    }
    empty_index._by_name["existing pdi pattern"] = "a" * 32
    out = pattern_ingest_ndl("Existing PDI pattern", caller_ndl, index=empty_index)
    payload = json.loads(out)
    assert payload["name"] == "Existing PDI pattern (ingested)"
    # Both entries exist
    assert "a" * 32 in empty_index.manifest
    assert payload["sys_id"] in empty_index.manifest


def test_ingest_mints_fresh_sys_id_on_collision_with_authoritative(empty_index):
    """If NDL metadata.id is a real sys_id that collides with an authoritative entry, mint a fresh one."""
    colliding_sys_id = "b" * 32
    empty_index.manifest[colliding_sys_id] = {
        "name": "Some real pattern", "ci_type": "cmdb_ci_x", "operation_kws": [],
    }
    ndl = (
        'pattern { metadata { id = "' + colliding_sys_id + '" name = "Mine" '
        'citype = "cmdb_ci_x" } identification { name = "x" '
        'step { name = "s" set_attr { "x" "y" } } } }'
    )
    out = pattern_ingest_ndl("My ingest", ndl, index=empty_index)
    payload = json.loads(out)
    assert payload["sys_id"] != colliding_sys_id
    assert len(payload["sys_id"]) == 32
    # Authoritative entry preserved
    assert empty_index.manifest[colliding_sys_id]["name"] == "Some real pattern"


def test_ingest_rejects_empty_inputs(empty_index, caller_ndl):
    assert "name is required" in pattern_ingest_ndl("", caller_ndl, index=empty_index)
    assert "ndl text is required" in pattern_ingest_ndl("X", "", index=empty_index)


def test_ingest_rejects_invalid_ndl(empty_index):
    out = pattern_ingest_ndl("bad", "this is { not valid", index=empty_index)
    assert out.startswith("ERROR:")
    assert "failed to parse" in out


def test_ingest_rejects_oversize(empty_index):
    huge = "pattern { metadata { } " + "//" + "x" * 1_100_000 + "\n }"
    out = pattern_ingest_ndl("huge", huge, index=empty_index)
    assert out.startswith("ERROR:")
    assert "exceeds" in out


def test_ingested_pattern_works_with_open_draft(empty_index, caller_ndl):
    """An ingested pattern should be openable as a draft via pattern_open_draft."""
    out = pattern_ingest_ndl("forum #1", caller_ndl, index=empty_index)
    sys_id = json.loads(out)["sys_id"]
    # Now open as a draft via the MCP tool
    from sn_patterns_mcp.drafts.mcp_tools import pattern_open_draft
    from sn_patterns_mcp.drafts.store import DraftStore
    store = DraftStore()
    draft_out = pattern_open_draft(sys_id, store=store, index=empty_index, pdi=None)
    payload = json.loads(draft_out)
    assert payload["draft_id"].startswith("d_")
    assert payload["step_count"] > 0
