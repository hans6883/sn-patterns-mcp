# Contributing

Thanks for considering a contribution. This project is a pattern-intelligence MCP server for ServiceNow Discovery — read [README.md](README.md) and [docs/AGENTS.md](docs/AGENTS.md) first to understand the architecture and the agent-facing tool contract.

## Getting started

```bash
git clone https://github.com/<your-fork>/sn-patterns-mcp
cd sn-patterns-mcp
python -m venv .venv
.venv/Scripts/activate     # Windows
# source .venv/bin/activate # macOS/Linux
pip install -e .[dev]
pytest -q                   # 181 / 181 should pass
```

Test suite runs against the bundled fixtures by default. Some integration tests skip cleanly when `oids.db` or the live pattern index aren't present — that's expected on a fresh clone. To exercise everything end-to-end, see "Build the index" in the README.

## Code style

- **Format**: ruff handles formatting + import ordering. `python -m ruff check sn_patterns_mcp/ scripts/ tests/ --fix` before pushing.
- **Type annotations**: required on public functions, dataclasses, and any function over 10 lines.
- **Tests**: every new MCP tool needs happy-path + error-path + edge-case + never-raises coverage. See `tests/test_harness_completeness.py` for the established pattern.
- **Logging**: `log = logging.getLogger(__name__)` at module top. Stderr only — stdout belongs to MCP JSON-RPC.

## Three things to know

1. **The OID corpus is not committed.** It's a 529 MB SQLite + ~50 MB of per-MIB JSONs, all gitignored. Run `python scripts/build_oid_index.py` to harvest from the public sources listed in that script.

2. **The pattern_index is not committed.** Real ServiceNow Discovery patterns are vendor IP. The repo ships with synthetic fixtures only; real-pattern parity is exercised via your own PDI hydration.

3. **Pre-commit hooks aren't enforced** but the CI (when added) will run `pytest` and `ruff check`. Don't push code that doesn't pass both locally.

## Pull requests

- Branch from `main`. Keep PRs scoped — one logical change per PR.
- Update `docs/AGENTS.md` if you add a tool, change a tool's signature, or change output format. AI agents read that file at runtime; stale docs are worse than no docs.
- Update `README.md` only for top-level architecture changes. Keep it terse.
- Run `pytest` and `ruff check` before opening the PR. The PR template will ask for the test count.

## Reporting issues

When reporting a bug, include:
1. The minimal NDL or tool invocation that reproduces it
2. The full output (anything after the `ERROR:` prefix tells you the routed exception class — share that)
3. Whether `oids.db` is built and whether `SN_INSTANCE` env vars are set
4. The output of `pytest -q` from your clone

For SNMP / OID issues, please also include the source MIB if you have it — many vendor MIBs aren't in our default seven-source harvest.

## Security

Don't open a public issue for security concerns. See [SECURITY.md](SECURITY.md) (if present) or email the maintainers directly.
