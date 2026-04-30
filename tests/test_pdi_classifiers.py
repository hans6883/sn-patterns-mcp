"""Test get_classifiers_for_pattern: routes through pattern.ci_type → discovery_classifier.table."""
from unittest.mock import MagicMock

from sn_patterns_mcp.pdi_client import PdiClient, PdiConfig


def _make_client(query_responses: list) -> PdiClient:
    """Make a PdiClient whose .query() returns successive responses from the list."""
    client = PdiClient(PdiConfig(instance="https://x.example.com", username="u", password="p"))
    client.query = MagicMock(side_effect=query_responses)
    return client


def test_classifier_query_routes_via_ci_type() -> None:
    """The fix: look up pattern.ci_type, then query discovery_classifier where table=ci_type."""
    pattern_sys_id = "a" * 32
    pattern_row = {"sys_id": pattern_sys_id, "name": "DB2 instance", "ci_type": "cmdb_ci_db_db2_instance"}
    classifier_row = {
        "sys_id": "c" * 32, "name": "DB2 Server",
        "sys_class_name": "discovery_classy_proc",
        "active": "true", "table": "cmdb_ci_db_db2_instance",
        "process_search": "db2sysc",
    }
    client = _make_client([
        [pattern_row],         # 1st query: sa_pattern lookup
        [classifier_row],      # 2nd query: discovery_classifier with table=...
    ])
    rows = client.get_classifiers_for_pattern(pattern_sys_id)
    assert len(rows) == 1
    assert rows[0]["sys_class_name"] == "discovery_classy_proc"
    # Verify the query path: 1st on sa_pattern, 2nd on discovery_classifier with table=
    calls = client.query.call_args_list
    assert calls[0].args[0] == "sa_pattern"
    assert calls[1].args[0] == "discovery_classifier"
    assert "table=cmdb_ci_db_db2_instance" in calls[1].args[1]
    assert "active=true" in calls[1].args[1]


def test_classifier_query_falls_back_to_cmdb_ci_class() -> None:
    """Older releases use cmdb_ci_class instead of table. Falls back when table=... returns 0."""
    pattern_sys_id = "a" * 32
    client = _make_client([
        [{"sys_id": pattern_sys_id, "ci_type": "cmdb_ci_some_app"}],
        [],   # table=... returns empty
        [{"sys_id": "c" * 32, "name": "Old classifier", "sys_class_name": "discovery_classy_proc"}],
    ])
    rows = client.get_classifiers_for_pattern(pattern_sys_id)
    assert len(rows) == 1
    # 3 queries: pattern lookup, table=... empty, cmdb_ci_class=... hit
    calls = client.query.call_args_list
    assert "table=cmdb_ci_some_app" in calls[1].args[1]
    assert "cmdb_ci_class=cmdb_ci_some_app" in calls[2].args[1]


def test_classifier_query_returns_empty_for_unknown_pattern() -> None:
    """If the pattern doesn't exist, we get empty back without touching discovery_classifier."""
    client = _make_client([[]])  # sa_pattern lookup returns nothing
    rows = client.get_classifiers_for_pattern("a" * 32)
    assert rows == []
    # Should not have queried discovery_classifier
    assert client.query.call_count == 1


def test_classifier_query_returns_empty_for_pattern_without_ci_type() -> None:
    """A pattern with no ci_type can't be linked to classifiers — return empty."""
    client = _make_client([[{"sys_id": "a" * 32, "name": "X", "ci_type": ""}]])
    rows = client.get_classifiers_for_pattern("a" * 32)
    assert rows == []
    assert client.query.call_count == 1


def test_classifier_query_rejects_invalid_sys_id() -> None:
    import pytest
    client = _make_client([])
    with pytest.raises(ValueError):
        client.get_classifiers_for_pattern("not-a-real-sys-id")


def test_classifier_query_propagates_auth_errors() -> None:
    """Auth/network failures must NOT be silently swallowed."""
    import pytest

    from sn_patterns_mcp.pdi_client import PdiUnavailable
    pattern_sys_id = "a" * 32
    client = PdiClient(PdiConfig(instance="https://x.example.com", username="u", password="p"))

    def fake_query(*args, **kwargs):
        if args[0] == "sa_pattern":
            return [{"sys_id": pattern_sys_id, "ci_type": "cmdb_ci_x"}]
        raise PdiUnavailable("PDI auth failed (401)")

    client.query = fake_query
    with pytest.raises(PdiUnavailable):
        client.get_classifiers_for_pattern(pattern_sys_id)
