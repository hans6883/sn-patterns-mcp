# Changelog

All notable changes to this project are documented here. Format loosely follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] — 2026-05-23

First PyPI release. Captures everything in the public repo as of the `go-public` milestone, plus the surgical-edit harness and Tier-3 emulator blueprint surface introduced after v0.2.0.

### Added
- **PyPI distribution.** `pip install sn-patterns-mcp` works against a clean venv. `sn-patterns-mcp` console entry point boots the stdio server with sensible defaults — bundled pattern index, no PDI required, fully offline.
- **`claude mcp add sn-patterns sn-patterns-mcp`** one-line registration recipe in the README.
- **Surgical-edit harness** (v0.3 flagship): 8 `draft_*` tools, 6 AST edit ops (`clone_library`, `wrap_in_guard`, `insert_step_before`/`_after`, `redirect_ref`, `modify_closure_attr`, `remove_step`), object-identity-anchored locators, cross-draft variable-flow validator. See `docs/AGENTS.md` "Surgical-edit workflow" and `docs/DEMO.md`.
- **Closure capability matrix + recipe library.** `closure_capability` returns per-closure recipes (e.g. `namespace_existence_probe` for `run_wmi_query_to_var`) addressing known limitations as tested, parameterized NDL fragments.
- **Target emulator catalog + blueprint.** `emulator_catalog` lists supported sidecar targets (Windows, Linux, F5, NetScaler, Cisco, ESXi, generic SNMP). `emulator_blueprint` emits a deterministic Tier-3 contract (listeners, fixtures, OID/MIB-backed responses) for a pattern, raw NDL, target, or OID list.
- **`pattern_ingest_ndl`** for session-scoped pattern injection — paste a forum / community / decommissioned-pattern NDL and the rest of the toolchain works on it (flagged `not_authoritative=true`).
- **27 missing common closures** added to the registry; `closure_capability` returns useful JSON for any keyword.
- **`docs/DEMO.md`** — copy-pasteable MSCluster surgical-edit walk-through with a headless smoke test that works against bundled fixtures.
- **CI workflow** (`.github/workflows/ci.yml`) running ruff + pytest on Python 3.10/3.11/3.12.
- **`SECURITY.md`** — coordinated vulnerability disclosure path.
- **CHANGELOG.md** (this file).
- PyPI classifiers, authors, README rendering, Changelog + Documentation URLs in `pyproject.toml`.

### Changed
- README quickstart leads with `pip install sn-patterns-mcp` instead of `git clone`.
- README MCP registration section shows the minimal zero-env-var config first; the env-overridden form is shown as a "with your own corpus" alternative.
- Fixed: `pattern_resolve` PDI classifier query routing.
- Documentation references corrected for the public corpus (no more stale "17 tools" / "90 closures" mentions).

### Removed
- Personal-corpus references and origin-hint phrasing scrubbed for the public repository.

### Known limitations
- Tier-3 emulator contract is defined and emitted, but a companion that actually binds listeners and serves fixtures is not yet published. The SNMP emulator companion lands in 0.4.0 (Phase 2 of the roadmap).
- `draft_finalize` does not implement `push_live` mode. This is intentional: live pushes stay human-in-the-loop until the regression harness ships. Use `serialize_only` and upload via the ServiceNow UI or REST.

## [0.2.0] — Previous

Initial public surface — pattern read/search/analyze/validate/author tools, NDL parser/writer, PatternIndex, OID/MIB SQLite knowledge base, PDI sandbox compile-test harness.

[0.3.0]: https://github.com/hans6883/sn-patterns-mcp/releases/tag/v0.3.0
