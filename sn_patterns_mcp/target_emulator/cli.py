"""Standalone CLI for the Tier-3 emulator — useful without an MCP client.

Usage:
    sn-target-emulator serve --blueprint blueprint.json \
        [--bind-host 127.0.0.1] [--bind-port 16100] \
        [--community public] [--recording path/to/session.jsonl]

    sn-target-emulator inspect --recording path/to/session.jsonl

`serve` blocks until SIGINT (Ctrl-C). `inspect` prints a per-interaction
summary of an existing recording file.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys
from pathlib import Path

from sn_patterns_mcp.target_emulator.recording import Recorder
from sn_patterns_mcp.target_emulator.runtime import (
    DEFAULT_BIND_HOST,
    EmulatorRuntime,
)

log = logging.getLogger(__name__)


def _configure_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
        stream=sys.stderr,
    )


async def _serve(args: argparse.Namespace) -> int:
    blueprint_path = Path(args.blueprint)
    if not blueprint_path.is_file():
        print(f"ERROR: blueprint file not found: {blueprint_path}", file=sys.stderr)
        return 2
    try:
        blueprint = json.loads(blueprint_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        print(f"ERROR: blueprint is not valid JSON: {e}", file=sys.stderr)
        return 2

    recording_path = Path(args.recording) if args.recording else None
    rt = EmulatorRuntime.from_blueprint(
        blueprint,
        community=args.community,
        bind_host=args.bind_host,
        bind_port=args.bind_port,
        recording_path=recording_path,
    )
    await rt.start()
    host, port = rt.snmp_address()
    log.info(
        "serving SNMPv2c on %s:%d (community=%r, fixtures=%d, recording=%s)",
        host, port, args.community, len(rt.entries),
        str(recording_path) if recording_path else "memory-only",
    )

    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    try:
        # SIGINT handler — Windows lacks add_signal_handler so we fall back to
        # waiting on KeyboardInterrupt.
        loop.add_signal_handler(2, stop.set)  # SIGINT
    except (NotImplementedError, OSError):
        pass

    try:
        await stop.wait()
    except KeyboardInterrupt:
        pass
    finally:
        await rt.stop()
        log.info("emulator stopped. recorded interactions: %d", rt.recording.count())
    return 0


def _inspect(args: argparse.Namespace) -> int:
    p = Path(args.recording)
    if not p.is_file():
        print(f"ERROR: recording file not found: {p}", file=sys.stderr)
        return 2
    interactions = Recorder.load(p)
    print(f"loaded {len(interactions)} interaction(s) from {p}")
    for i, x in enumerate(interactions):
        err = f" ERROR={x.error}" if x.error else ""
        oids = ",".join(x.request.get("oids", [])) if isinstance(x.request, dict) else ""
        rtype = x.request.get("type", "?") if isinstance(x.request, dict) else "?"
        print(f"  [{i:>3}] {x.ts} {x.proto:>5} {rtype:>14} {oids}{err}")
    return 0


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="sn-target-emulator", description=__doc__)
    # --verbose is a per-subcommand flag (placed AFTER the subcommand).
    # argparse can't reliably merge a flag declared on both the root parser
    # and a subparser, so we declare it once via a parent parser.
    verbose_parent = argparse.ArgumentParser(add_help=False)
    verbose_parent.add_argument("--verbose", "-v", action="store_true",
                                help="DEBUG logging")

    sub = p.add_subparsers(dest="cmd", required=True)

    serve = sub.add_parser("serve", parents=[verbose_parent],
                           help="Start an SNMPv2c sandbox responder")
    serve.add_argument("--blueprint", required=True, help="Path to blueprint JSON")
    serve.add_argument("--bind-host", default=DEFAULT_BIND_HOST)
    serve.add_argument("--bind-port", type=int, default=0,
                       help="UDP port (0 = OS-assigned)")
    serve.add_argument("--community", default="public")
    serve.add_argument("--recording", default=None,
                       help="JSONL file path for interaction persistence")

    inspect = sub.add_parser("inspect", parents=[verbose_parent],
                             help="Print a JSONL recording's contents")
    inspect.add_argument("--recording", required=True, help="Path to JSONL recording")
    return p


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    _configure_logging(args.verbose)
    if args.cmd == "serve":
        try:
            return asyncio.run(_serve(args))
        except KeyboardInterrupt:
            return 0
    if args.cmd == "inspect":
        return _inspect(args)
    parser.error(f"unknown subcommand: {args.cmd!r}")
    return 2  # argparse.error() exits, but mypy/ruff need an explicit return


if __name__ == "__main__":
    sys.exit(main())
