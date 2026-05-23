"""CLI argument-parsing regression tests.

The previous bug: `--verbose` was declared on the root parser but the
documented usage placed it AFTER the subcommand, where argparse couldn't
see it and the invocation died with `unrecognized arguments: --verbose`.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from sn_patterns_mcp.target_emulator import cli


def test_verbose_after_subcommand_is_accepted():
    parser = cli._build_parser()
    args = parser.parse_args(["serve", "--blueprint", "bp.json", "--verbose"])
    assert args.cmd == "serve"
    assert args.blueprint == "bp.json"
    assert args.verbose is True


def test_serve_requires_blueprint():
    parser = cli._build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["serve"])


def test_inspect_requires_recording():
    parser = cli._build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["inspect"])


def test_inspect_subcommand_runs_end_to_end(tmp_path, capsys):
    rec = tmp_path / "session.jsonl"
    rec.write_text(
        json.dumps({
            "ts": "2026-05-23T00:00:00+00:00",
            "proto": "snmp",
            "client": "127.0.0.1:1234",
            "request": {"type": "GetRequest", "oids": ["1.3.6.1.2.1.1.5.0"]},
            "response": {"type": "Response"},
            "error": None,
        }) + "\n",
        encoding="utf-8",
    )
    rc = cli.main(["inspect", "--recording", str(rec)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "loaded 1 interaction" in out
    assert "1.3.6.1.2.1.1.5.0" in out


def test_inspect_missing_file_exits_2(tmp_path, capsys):
    missing = tmp_path / "does_not_exist.jsonl"
    rc = cli.main(["inspect", "--recording", str(missing)])
    assert rc == 2


def test_serve_rejects_missing_blueprint_file(tmp_path, monkeypatch):
    # Don't actually start a server — test the early-exit path
    import asyncio

    missing = tmp_path / "missing.json"
    # _serve is async; run it directly to assert the early return code
    args = cli._build_parser().parse_args([
        "serve", "--blueprint", str(missing),
    ])
    rc = asyncio.run(cli._serve(args))
    assert rc == 2


def test_serve_rejects_malformed_blueprint(tmp_path):
    import asyncio
    bp = tmp_path / "bad.json"
    bp.write_text("{ not valid json", encoding="utf-8")
    args = cli._build_parser().parse_args(["serve", "--blueprint", str(bp)])
    rc = asyncio.run(cli._serve(args))
    assert rc == 2
