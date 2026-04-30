"""Track 2: PDI compile harness — pattern_test_compile + pattern_diff_against_live + sandbox guards.

PDI is mocked; no network calls.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from sn_patterns_mcp.pdi_client import (
    SANDBOX_PREFIX,
    PdiClient,
    PdiConfig,
    PdiRejected,
    SandboxViolation,
    _ensure_sandbox,
)
from sn_patterns_mcp.tools import pattern_diff_against_live, pattern_test_compile

VALID_PATTERN = '''pattern {
    metadata {
        id = "00000000000000000000000000000001"
        name = "TestPattern"
        citype = "cmdb_ci_appl"
    }
    identification {
        name = "i"
        find_process_strategy {strategy = LISTENING_PORT}
        step {
            name = "set name"
            set_attr {
                "name"
                "literal"
            }
        }
    }
}'''


# ---------------------------------------------------------------------------
# Mock PdiClient — captures calls, configurable responses
# ---------------------------------------------------------------------------

class FakePdi:
    """Stand-in for PdiClient that records all write/read operations."""

    def __init__(self, *, accept_create: bool = True, reject_body: dict | None = None) -> None:
        self.accept_create = accept_create
        self.reject_body = reject_body or {"error": {"message": "Invalid NDL", "detail": "field 'ndl' is malformed"}}
        self.rows: dict[str, dict] = {}
        self.calls: list[tuple[str, dict]] = []
        self._next_sys_id = 0

    def _new_sys_id(self) -> str:
        self._next_sys_id += 1
        return f"{self._next_sys_id:032x}"

    def create_pattern(self, *, name: str, ndl: str, ci_type: str = "", description: str = ""):
        self.calls.append(("create_pattern", {"name": name, "ci_type": ci_type}))
        # Enforce the same sandbox guard the real client does — name must start with SANDBOX_PREFIX.
        _ensure_sandbox(name)
        if not self.accept_create:
            raise PdiRejected(status=400, body=self.reject_body)
        sys_id = self._new_sys_id()
        row = {"sys_id": sys_id, "name": name, "ndl": ndl, "ci_type": ci_type, "description": description}
        self.rows[sys_id] = row
        return row

    def update_pattern(self, sys_id: str, ndl: str, expected_name: str | None = None):
        self.calls.append(("update_pattern", {"sys_id": sys_id, "expected_name": expected_name}))
        existing = self.rows.get(sys_id)
        if existing is None:
            raise ValueError(f"sys_id {sys_id} not found")
        if expected_name and existing["name"] != expected_name:
            raise SandboxViolation("name mismatch")
        _ensure_sandbox(existing["name"])
        existing["ndl"] = ndl
        return existing

    def delete_pattern(self, sys_id: str, expected_name: str | None = None):
        self.calls.append(("delete_pattern", {"sys_id": sys_id, "expected_name": expected_name}))
        existing = self.rows.get(sys_id)
        if existing is None:
            return
        if expected_name and existing["name"] != expected_name:
            raise SandboxViolation("name mismatch")
        _ensure_sandbox(existing["name"])
        del self.rows[sys_id]

    def get_pattern(self, name_or_sys_id: str):
        self.calls.append(("get_pattern", {"key": name_or_sys_id}))
        for row in self.rows.values():
            if row.get("sys_id") == name_or_sys_id or row.get("name") == name_or_sys_id:
                return row
        return None

    def get_pattern_text(self, sys_id: str):
        row = self.rows.get(sys_id)
        return row.get("ndl") if row else None


# ---------------------------------------------------------------------------
# Sandbox enforcement (PdiClient direct)
# ---------------------------------------------------------------------------

class TestPdiResponseRouting:
    """Auth-403 vs structured-error-403 routing in PdiClient._write."""

    def _make_client_with_response(self, status_code: int, json_body=None, text_body: str = ""):
        """Build a PdiClient whose session returns the given response."""
        from unittest.mock import MagicMock
        client = PdiClient(PdiConfig(instance="https://x.example.com", username="u", password="p"))
        resp = MagicMock()
        resp.status_code = status_code
        if json_body is not None:
            resp.json = MagicMock(return_value=json_body)
        else:
            resp.json = MagicMock(side_effect=ValueError("no json"))
        resp.text = text_body
        session = MagicMock()
        session.request = MagicMock(return_value=resp)
        session.get = MagicMock(return_value=resp)
        client._session = session
        return client

    def test_403_with_no_body_is_auth_error(self) -> None:
        from sn_patterns_mcp.pdi_client import PdiUnavailable
        client = self._make_client_with_response(403, json_body=None, text_body="")
        with pytest.raises(PdiUnavailable) as exc:
            client._write("POST", "sa_pattern", sys_id=None, body={"name": f"{SANDBOX_PREFIX}x", "ndl": "x"})
        assert exc.value.status == 403
        assert "auth" in str(exc.value).lower()

    def test_403_with_business_rule_error_is_rejection(self) -> None:
        """A BR-aborted write returns 403 with a structured error body —
        must route as PdiRejected so callers can show the BR message, not 'auth failed'."""
        from sn_patterns_mcp.pdi_client import PdiRejected
        br_body = {
            "error": {
                "message": "Operation Failed",
                "detail": "Operation against file 'sa_pattern' was aborted by Business Rule 'Validate NDL'.",
            },
            "status": "failure",
        }
        client = self._make_client_with_response(403, json_body=br_body)
        with pytest.raises(PdiRejected) as exc:
            client._write("POST", "sa_pattern", sys_id=None, body={"name": f"{SANDBOX_PREFIX}x", "ndl": "x"})
        assert exc.value.status == 403
        assert "Validate NDL" in str(exc.value)

    def test_400_with_structured_error_is_rejection(self) -> None:
        from sn_patterns_mcp.pdi_client import PdiRejected
        body = {"error": {"message": "Invalid table", "detail": ""}, "status": "failure"}
        client = self._make_client_with_response(400, json_body=body)
        with pytest.raises(PdiRejected):
            client._write("POST", "sa_pattern", sys_id=None, body={"name": f"{SANDBOX_PREFIX}x", "ndl": "x"})

    def test_401_no_body_is_auth_error(self) -> None:
        from sn_patterns_mcp.pdi_client import PdiUnavailable
        client = self._make_client_with_response(401, json_body=None)
        with pytest.raises(PdiUnavailable) as exc:
            client._write("POST", "sa_pattern", sys_id=None, body={"name": f"{SANDBOX_PREFIX}x", "ndl": "x"})
        assert exc.value.status == 401


class TestSandboxEnforcement:
    def test_ensure_sandbox_accepts_prefixed_name(self) -> None:
        assert _ensure_sandbox(f"{SANDBOX_PREFIX}123_abc").startswith(SANDBOX_PREFIX)

    def test_ensure_sandbox_rejects_real_name(self) -> None:
        with pytest.raises(SandboxViolation):
            _ensure_sandbox("Apache HTTP Server On Unix")

    def test_ensure_sandbox_rejects_lookalike(self) -> None:
        with pytest.raises(SandboxViolation):
            _ensure_sandbox("sandbox_test")  # missing leading underscore + snmcp

    def test_create_pattern_refuses_real_name(self) -> None:
        # Use the real PdiClient with a stub session — the guard is in pure code.
        client = PdiClient(PdiConfig(instance="https://x", username="u", password="p"))
        with pytest.raises(SandboxViolation):
            client.create_pattern(name="Apache HTTP Server On Unix", ndl="x", ci_type="x")


# ---------------------------------------------------------------------------
# pattern_test_compile
# ---------------------------------------------------------------------------

class TestPatternTestCompile:
    def test_local_validation_gate(self, tmp_path: Path, monkeypatch) -> None:
        # Bad NDL — local validator rejects, PDI never contacted.
        monkeypatch.setattr("sn_patterns_mcp.tools._sandbox_log_path", lambda: tmp_path / "sandbox.json")
        pdi = FakePdi()
        out = pattern_test_compile("not valid ndl at all", pdi=pdi)
        assert "LOCAL_VALIDATION_FAILED" in out
        assert pdi.calls == []  # PDI not contacted

    def test_no_pdi_returns_error(self) -> None:
        out = pattern_test_compile(VALID_PATTERN, pdi=None)
        assert "ERROR:" in out
        assert "credentials" in out.lower()

    def test_input_size_cap(self) -> None:
        big = "pattern { metadata { id = \"x\" } " + ("x" * (1_048_577))
        out = pattern_test_compile(big, pdi=FakePdi())
        assert "ERROR:" in out and "cap" in out.lower()

    def test_accept_path_creates_then_deletes(self, tmp_path: Path, monkeypatch) -> None:
        monkeypatch.setattr("sn_patterns_mcp.tools._sandbox_log_path", lambda: tmp_path / "sandbox.json")
        pdi = FakePdi(accept_create=True)
        out = pattern_test_compile(VALID_PATTERN, pdi=pdi, cleanup=True)
        assert "Local validation: PASSED" in out
        assert "PDI compile: ACCEPTED" in out
        assert "Cleanup: DELETED" in out
        # Mock should have seen create + delete
        actions = [c[0] for c in pdi.calls]
        assert "create_pattern" in actions
        assert "delete_pattern" in actions
        # Sandbox row should be gone after cleanup
        assert pdi.rows == {}

    def test_accept_path_skips_cleanup_when_disabled(self, tmp_path: Path, monkeypatch) -> None:
        monkeypatch.setattr("sn_patterns_mcp.tools._sandbox_log_path", lambda: tmp_path / "sandbox.json")
        pdi = FakePdi(accept_create=True)
        out = pattern_test_compile(VALID_PATTERN, pdi=pdi, cleanup=False)
        assert "PDI compile: ACCEPTED" in out
        assert "Cleanup: SKIPPED" in out
        assert "delete_pattern" not in [c[0] for c in pdi.calls]
        # Row retained
        assert len(pdi.rows) == 1

    def test_reject_path_surfaces_pdi_error(self, tmp_path: Path, monkeypatch) -> None:
        monkeypatch.setattr("sn_patterns_mcp.tools._sandbox_log_path", lambda: tmp_path / "sandbox.json")
        pdi = FakePdi(accept_create=False)
        out = pattern_test_compile(VALID_PATTERN, pdi=pdi)
        assert "PDI compile: REJECTED" in out
        assert "Invalid NDL" in out  # error.message bubbled up
        # No delete attempted — row was never created
        assert "delete_pattern" not in [c[0] for c in pdi.calls]

    def test_sandbox_name_is_used_not_original(self, tmp_path: Path, monkeypatch) -> None:
        monkeypatch.setattr("sn_patterns_mcp.tools._sandbox_log_path", lambda: tmp_path / "sandbox.json")
        pdi = FakePdi(accept_create=True)
        pattern_test_compile(VALID_PATTERN, pdi=pdi, cleanup=False)
        # The name passed to create_pattern must be the sandbox name, NOT "TestPattern"
        create_call = next(c for c in pdi.calls if c[0] == "create_pattern")
        assert create_call[1]["name"].startswith(SANDBOX_PREFIX)
        assert create_call[1]["name"] != "TestPattern"

    def test_sandbox_log_records_runs(self, tmp_path: Path, monkeypatch) -> None:
        log_path = tmp_path / "sandbox.json"
        monkeypatch.setattr("sn_patterns_mcp.tools._sandbox_log_path", lambda: log_path)
        pdi = FakePdi(accept_create=True)
        pattern_test_compile(VALID_PATTERN, pdi=pdi, cleanup=True)
        assert log_path.exists()
        runs = json.loads(log_path.read_text(encoding="utf-8"))
        actions = [r["action"] for r in runs]
        statuses = [r["status"] for r in runs]
        assert "create" in actions
        assert "delete" in actions
        assert "accepted" in statuses
        assert "cleaned" in statuses


# ---------------------------------------------------------------------------
# pattern_diff_against_live
# ---------------------------------------------------------------------------

class TestPatternDiffAgainstLive:
    def test_no_pdi_returns_error(self) -> None:
        out = pattern_diff_against_live("X", VALID_PATTERN, pdi=None)
        assert "ERROR:" in out

    def test_pattern_not_found(self) -> None:
        pdi = FakePdi()
        out = pattern_diff_against_live("Nonexistent", VALID_PATTERN, pdi=pdi)
        assert "ERROR: pattern not found in PDI" in out

    def test_identical_ndl_shows_no_textual_diff(self, tmp_path: Path, monkeypatch) -> None:
        # Pre-load the FakePdi with an identical NDL
        pdi = FakePdi()
        sys_id = "0" * 31 + "a"
        pdi.rows[sys_id] = {"sys_id": sys_id, "name": "TestPattern", "ndl": VALID_PATTERN, "ci_type": "cmdb_ci_appl"}
        out = pattern_diff_against_live("TestPattern", VALID_PATTERN, pdi=pdi)
        assert "byte-identical" in out

    def test_diff_shows_added_operations(self) -> None:
        # Live pattern has no runcmd_to_var; local adds one
        live_ndl = VALID_PATTERN
        local_ndl = VALID_PATTERN.replace(
            'set_attr {\n                "name"\n                "literal"\n            }',
            'runcmd_to_var {\n                cmd = "uname -a"\n                var_names = "kernel"\n            }'
        )
        pdi = FakePdi()
        sys_id = "0" * 31 + "b"
        pdi.rows[sys_id] = {"sys_id": sys_id, "name": "TestPattern", "ndl": live_ndl, "ci_type": "cmdb_ci_appl"}
        out = pattern_diff_against_live("TestPattern", local_ndl, pdi=pdi)
        # Structural diff should call out runcmd_to_var as added
        assert "added in local:" in out
        assert "runcmd_to_var" in out
        # And textual diff should show the change
        assert "TEXTUAL DIFF" in out
