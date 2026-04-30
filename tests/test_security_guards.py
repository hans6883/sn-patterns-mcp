"""Security regression tests — sysparm_query injection and path-traversal guards."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from sn_patterns_mcp.pattern_index import PatternIndex, build_index
from sn_patterns_mcp.pdi_client import _looks_like_sysid, _safe_name


class TestPdiInputValidation:
    def test_sys_id_must_be_32_hex(self) -> None:
        assert _looks_like_sysid("00112233445566778899aabbccddeeff")
        assert _looks_like_sysid("DEADBEEFDEADBEEFDEADBEEFDEADBEEF")
        # Wrong length
        assert not _looks_like_sysid("0011")
        assert not _looks_like_sysid("0" * 33)
        # Non-hex characters
        assert not _looks_like_sysid("z" * 32)
        assert not _looks_like_sysid("../etc/passwd" + "0" * 19)
        # Empty / None-like
        assert not _looks_like_sysid("")

    def test_safe_name_accepts_normal_pattern_names(self) -> None:
        assert _safe_name("Apache HTTP Server On Unix") == "Apache HTTP Server On Unix"
        assert _safe_name("Linux Server (LP)") == "Linux Server (LP)"
        assert _safe_name("AWS - EC2 - Instance") == "AWS - EC2 - Instance"
        assert _safe_name("net.io_module.v2") == "net.io_module.v2"

    def test_safe_name_rejects_sysparm_query_injection(self) -> None:
        # The ServiceNow sysparm_query operator is ^ (AND). Injecting it could
        # let a caller pivot the query.
        with pytest.raises(ValueError):
            _safe_name("foo^sys_id=000^ORname=bar")
        with pytest.raises(ValueError):
            _safe_name("foo=bar")
        with pytest.raises(ValueError):
            _safe_name("name|x")
        with pytest.raises(ValueError):
            _safe_name("name\nname2")


class TestPatternIndexPathSafety:
    def test_build_index_rejects_traversal_in_sys_id(self, tmp_path: Path) -> None:
        # A malicious row attempting to write outside patterns_dir
        rows = [
            {"sys_id": "../etc/passwd", "name": "evil", "ndl": "library {name = \"x\"}"},
            {"sys_id": "..\\windows\\system32", "name": "evil2", "ndl": "library {name = \"x\"}"},
            {"sys_id": "path/with/slash", "name": "evil3", "ndl": "library {name = \"x\"}"},
            {"sys_id": "/absolute/path", "name": "evil4", "ndl": "library {name = \"x\"}"},
            {"sys_id": "not_hex_at_all_just_31_chars_X", "name": "evil5", "ndl": "library {name = \"x\"}"},
            # One legitimate row
            {"sys_id": "00112233445566778899aabbccddeeff", "name": "good",
             "ndl": 'library {name = "ok" id = "x" description = "" step {name = "s" set_attr {"v" "1"}}}'},
        ]
        summary = build_index(tmp_path, rows)
        # Only the legitimate row should be indexed
        assert summary["indexed"] == 1
        assert summary["parse_failures"] >= 5
        # No file should exist outside patterns_dir
        patterns_dir = tmp_path / "patterns"
        files = list(patterns_dir.glob("*.json"))
        assert len(files) == 1
        assert files[0].name == "00112233445566778899aabbccddeeff.json"

    def test_pattern_index_get_rejects_invalid_sys_id_format(self, tmp_path: Path) -> None:
        # Build a tiny index then attempt to load a pattern with a malformed sys_id
        rows = [{
            "sys_id": "00112233445566778899aabbccddeeff",
            "name": "good",
            "ndl": 'library {name = "ok" id = "x" description = "" step {name = "s" set_attr {"v" "1"}}}',
        }]
        build_index(tmp_path, rows)
        # Hand-craft a manifest entry pointing to a traversal path
        manifest = json.loads((tmp_path / "manifest.json").read_text(encoding="utf-8"))
        manifest["../traversal"] = {
            "name": "evil",
            "ci_type": "x",
            "operation_kws": [],
            "library_refs": [],
            "path": "patterns/../traversal.json",
        }
        (tmp_path / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")

        idx = PatternIndex.load(tmp_path)
        # get() must reject this even though it's in the manifest
        assert idx.get("../traversal") is None
