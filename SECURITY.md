# Security policy

## Reporting a vulnerability

**Do not open a public issue for security concerns.** Email the maintainer directly with the subject line `[security] sn-patterns-mcp` and we'll respond within 5 business days.

For non-security bugs (parser crashes, validator false positives, MCP protocol issues, etc.), use the regular GitHub issue tracker — those are not sensitive.

## Supported versions

Only the `master` branch is supported. There are no LTS releases — fixes land on `master` and are picked up by anyone tracking it.

## What we treat as a vulnerability

The realistic threat surface for an MCP server like this:

- **PDI client misuse.** The PDI client interpolates pattern names into `sysparm_query` for ServiceNow REST calls. Sanitization lives in `pdi_client._safe_name`. If you find a way around it that lets an attacker influence a query against an arbitrary table, that is a real vulnerability.
- **Sandbox escape on `pattern_test_compile` / `draft_finalize`.** Both write to `sa_pattern` rows whose names start with `_sandbox_snmcp_`. The prefix enforcement (`pdi_client._ensure_sandbox`) is the only thing preventing these tools from editing real patterns. A bypass — anything that lets a tool call land outside the sandbox prefix — is a real vulnerability.
- **Parser crashes / DoS.** The NDL parser caps input at 1 MiB and is recursive-descent. A crafted NDL that crashes the server (rather than producing a parse error) or causes unbounded memory growth is a vulnerability.
- **Recipe template traversal.** `Recipe.materialize` uses a restricted `{name}`-only substituter that rejects format-spec / attribute traversal. Any input that bypasses those guards and lets a user influence Python attribute access is a vulnerability.
- **Secrets in tool output.** Tool responses are capped at 8000 chars and never raise; failures arrive as `ERROR:` strings. If any tool ever leaks credentials, request bodies, or full PDI auth headers into its response, that is a vulnerability.

## What we do NOT treat as a vulnerability

- Local file reads / writes by the MCP server inside its own working directory (the OID build cache, pattern index, draft store) — the server runs as the user, with the user's permissions, by design.
- Anything that requires the attacker to already control the machine running the MCP server.
- Bugs in optional integrations (ChromaDB, ServiceNow PDI itself) that this project consumes but does not own.

## Disclosure

Once a fix lands on `master`, we'll add a brief note to the relevant commit message and (if the impact is meaningful) a line in CHANGELOG-style notes inside the next release. We do not maintain a separate CVE registry.
