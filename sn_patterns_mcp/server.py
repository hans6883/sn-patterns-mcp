"""MCP stdio server exposing the 28 ServiceNow Discovery pattern tools.

CRITICAL: stdout is reserved for MCP JSON-RPC. All logging must go to stderr.

Environment variables:
    SN_PATTERNS_INDEX_ROOT  Override pattern index location (default: ./pattern_index)
    SN_PATTERNS_CHROMA_DIR  Override Chroma DB location (default: ~/.sn_patterns_mcp/chroma)
    SN_PATTERNS_DEBUG       Set to 1 to include full tracebacks in tool output
    SN_PATTERNS_LOG_LEVEL   Override stderr log level (DEBUG/INFO/WARNING/ERROR; default INFO)
    SN_INSTANCE / SN_USERNAME / SN_PASSWORD   Optional PDI live-fallback credentials
"""
from __future__ import annotations

import asyncio
import logging
import os
import sys
import traceback
from pathlib import Path

from sn_patterns_mcp import tools as ptools
from sn_patterns_mcp.chroma_index import ChromaPatternIndex
from sn_patterns_mcp.drafts import DRAFTS
from sn_patterns_mcp.drafts import mcp_tools as dtools
from sn_patterns_mcp.pattern_index import PatternIndex
from sn_patterns_mcp.pdi_client import PdiUnavailable, try_create_client

log = logging.getLogger(__name__)

DEFAULT_INDEX_ROOT = Path(__file__).parent / "pattern_index"
DEFAULT_CHROMA_DIR = os.environ.get("SN_PATTERNS_CHROMA_DIR") or str(
    Path.home() / ".sn_patterns_mcp" / "chroma"
)


def configure_logging() -> None:
    """Configure stderr logging. STDOUT MUST stay clean for MCP JSON-RPC."""
    level_name = os.environ.get("SN_PATTERNS_LOG_LEVEL", "INFO").upper()
    level = getattr(logging, level_name, logging.INFO)
    handler = logging.StreamHandler(stream=sys.stderr)
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)-7s %(name)s: %(message)s"))
    root = logging.getLogger()
    root.setLevel(level)
    # Remove any handler that might write to stdout
    root.handlers = [handler]


# ---------------------------------------------------------------------------
# Tool descriptions — written for AI agent consumption (Claude / Codex).
# Each description includes: what it does, when to use, what it returns,
# and (where applicable) the relationship to other tools.
# ---------------------------------------------------------------------------

TOOL_DESCRIPTIONS: dict[str, str] = {
    "pattern_analyze": (
        "Get a structured step-by-step breakdown of an existing ServiceNow Discovery pattern. "
        "Use this when the user names a known pattern (e.g. 'Apache HTTP Server On Unix' or a 32-char sys_id) "
        "and wants to understand what it does. Returns: metadata (CI type, OS), every step's operation keyword "
        "+ description, command/parse strategy details, variables read/written. "
        "Falls back to metadata-only output if NDL is not cached locally."
    ),
    "pattern_resolve": (
        "Resolve a pattern's full ecosystem: shared libraries it references, classifiers that route to it, "
        "pre/post scripts attached to it, and a command inventory parsed from its NDL. "
        "Use this when answering 'what runs alongside pattern X?' or 'what triggers pattern X?'. "
        "Returns each section with a source tag (pdi, local, local-heuristic) so you can tell whether "
        "a result is authoritative or a best-effort fallback. PDI failures are surfaced inline, not silenced."
    ),
    "pattern_debug": (
        "Generate an operation-aware debug plan for a specific issue on a pattern (e.g. 'returns no CIs', "
        "'authentication failing', 'WMI timeout'). Returns: sa_discovery_log query template, ecc_queue lookup "
        "hints, per-operation failure modes from the closure registry, and pre/post script previews that may "
        "explain the issue. Use this BEFORE asking the user to share logs — the output tells them what to fetch."
    ),
    "pattern_search": (
        "Find ServiceNow Discovery patterns by intent. Uses semantic embeddings via ChromaDB when available, "
        "falling back to substring search across the pattern manifest. "
        "Use natural language: 'Tomcat on Linux', 'AWS S3 inventory', 'how does discovery find IIS'. "
        "Returns top N matches with sys_id + CI type + operation fingerprint. The response header tells you which "
        "backend was used so you know the result quality. Prefer this over asking the user to remember exact names."
    ),
    "ndl_explain": (
        "Parse an arbitrary NDL text snippet (pattern, library, or single operation) and explain it in plain English. "
        "Use when the user pastes NDL inline rather than referencing a known pattern. "
        "Tries pattern → library → fragment in that order; surfaces the most informative parse error. "
        "Hard cap: 1 MiB input. Does NOT require the input to be in the index."
    ),
    "pattern_compare": (
        "Structural diff between two patterns by name or sys_id. Returns: differing CI types, OS family, "
        "operation keywords (only-in-A, only-in-B, shared), variables, and shared library references. "
        "Use this for 'how does Apache on Unix differ from Apache on Windows' or 'what's new in pattern v2 vs v1'."
    ),
    "pattern_validate": (
        "Tier-1 local validation of raw NDL text. Checks syntax, parser/writer roundtrip agreement, metadata "
        "completeness, refid library resolution, and variable read-before-write ordering. Returns severity-ranked "
        "findings (ERROR/WARN/INFO; INFO suppressed unless verbose=true). Use this AFTER drafting NDL via "
        "pattern_create or by hand, BEFORE attempting to upload to ServiceNow. Hard cap: 1 MiB input."
    ),
    "pattern_create": (
        "Generate synthesis context for authoring a NEW ServiceNow Discovery pattern. Returns: 3 nearest-neighbor "
        "existing patterns from the corpus (with full NDL snippets you can crib from), keyword-scored relevant "
        "closure descriptors from the registry, and a skeleton pattern shape. "
        "This tool does NOT generate NDL itself — it gives YOU (the AI agent) the structured context needed to "
        "synthesize NDL. After drafting, call pattern_validate to check your work. "
        "Inputs: intent (required, natural language), ci_type (optional cmdb_ci_*), os_family (optional cmdb_ci_*_server)."
    ),
    "pattern_test_compile": (
        "Tier-2 PDI compile test. Uploads NDL to a sandbox sa_pattern row in ServiceNow, observes whether the "
        "instance accepts or rejects it, then deletes the sandbox row. The pattern's name is rewritten to a "
        "_sandbox_snmcp_ prefix so this NEVER touches real patterns. "
        "Local Tier-1 validation runs first; if it fails, PDI is not contacted. "
        "Use this AFTER pattern_validate passes, to catch server-side issues (CI type unknown, dictionary "
        "violations, library refs that don't resolve in PDI). Requires PDI credentials. "
        "Inputs: ndl (required), cleanup (default true; set false to retain sandbox row for inspection)."
    ),
    "pattern_diff_against_live": (
        "Fetch the current PDI version of a pattern and diff it against your local NDL draft. Returns: "
        "structural diff (operation keywords, variables, library refs added/removed) PLUS a textual unified "
        "diff. Use BEFORE pushing edits to PDI to confirm exactly what changes. Does not modify anything. "
        "Inputs: name_or_sys_id (required — pattern to fetch from PDI), local_ndl (required — your draft)."
    ),
    "oid_lookup": (
        "Resolve an SNMP OID by dotted-decimal (e.g. 1.3.6.1.2.1.1.5.0) or by name (e.g. sysName) "
        "into name/MIB/syntax/access/description. Walks up the OID tree to identify columnar instances "
        "(e.g. 1.3.6.1.2.1.2.2.1.5.3 → ifSpeed for instance 3). For unknown OIDs in 1.3.6.1.4.1.*, "
        "identifies the enterprise vendor. Use this to make SNMP-using patterns legible."
    ),
    "oid_walk_explain": (
        "Show the structure under an OID prefix — what an SNMP walk would return. Lists every "
        "child OID (recursive) with name, syntax, and table/columnar tags. Use this to understand "
        "what data is in a table like ifTable or hrStorageTable before you query it."
    ),
    "oid_search": (
        "Natural-language semantic search across the OID corpus (~hundreds of thousands of OIDs). "
        "Use this when the user describes what they want rather than naming an OID — e.g. "
        "'interface error counters', 'BGP session state', 'CPU temperature sensor'. "
        "Tries ChromaDB semantic embeddings first; falls back to SQLite FTS5 keyword search."
    ),
    "pattern_snmp_audit": (
        "For every run_snmp_* operation in a pattern, resolve the OID and report what it queries, "
        "which MIB it's from, and which vendor (if enterprise-private). Surfaces vendor lock-in "
        "and OID typos. Use this when reviewing or porting an SNMP discovery pattern. "
        "Inputs: name_or_sys_id (required)."
    ),
    "pattern_lineage": (
        "Trace the full dependency graph around a pattern: shared libraries it references "
        "(recursive), extensions that graft into it, classifiers that route discovery to it, "
        "pre/post scripts and the variables they inject via CTX.setAttribute, and provenance "
        "of every variable the pattern reads (discovery context / process scope / pre-script / "
        "set_attr / unknown). Use this when a user asks 'where does this pattern fit?' or "
        "'what runs around it?' — gives the complete picture in one call."
    ),
    "pattern_data_sources": (
        "For an existing pattern, list every external data point it touches: WMI classes "
        "(with namespace + WQL), shell commands (Windows / Linux / F5 tmsh / Cisco CLI), "
        "registry reads, SNMP OIDs (auto-resolved to MIB::name), file parses, HTTP/REST "
        "endpoints, LDAP queries. Cross-references the bundled data-source catalog to show "
        "what each data point typically populates in the CMDB. Use this to understand 'what "
        "is this pattern actually collecting?' before modifying or troubleshooting."
    ),
    "pattern_data_sources_lookup": (
        "Browse the data-source knowledge base — what data is available on a given target type "
        "and how ServiceNow Discovery patterns typically ingest it. Use target='windows' / 'linux' "
        "/ 'f5' / 'cisco-ios' to enumerate, or pass query=<keyword> to search across all. "
        "Each entry shows the data point, access method (wmi/registry/command/snmp/rest), "
        "the closure that ingests it, and the typical CI attribute it lands in."
    ),
    "emulator_catalog": (
        "Browse the Tier-3 target-emulator catalog for a sidecar/helper MCP. Returns structured JSON "
        "profiles for Windows, Linux/Unix, F5 BIG-IP, Citrix ADC/NetScaler, Cisco IOS/NX-OS, ESXi, "
        "and generic SNMP targets, including exact listener ports/protocols and fidelity notes. "
        "Use this when an agent needs to choose what kind of synthetic target to run a pattern against."
    ),
    "emulator_blueprint": (
        "Generate a deterministic sidecar emulator blueprint for a pattern, raw NDL, explicit target, "
        "or list of SNMP OIDs. Returns JSON with required TCP/UDP listeners, WMI/command/registry/SNMP/"
        "file/HTTP/LDAP fixture obligations, OID/MIB resolution, and the strict execution contract. "
        "Use this after pattern_validate or pattern_test_compile when you need Tier-3 behavioral testing "
        "against an emulated real target."
    ),
    "pattern_open_draft": (
        "Open an existing pattern (or library) as a mutable Draft for surgical editing. "
        "Returns a draft_id you pass to all subsequent draft_* calls in this session. "
        "Use this as the FIRST step when the user wants to clone-and-customize a pattern, "
        "wrap a step in a guard, fix a hardcoded path, or otherwise mutate a shipping pattern. "
        "The draft holds a mutable AST; edits do not affect the source until draft_finalize."
    ),
    "draft_locate_steps": (
        "Find steps in a draft matching a predicate. Returns opaque locators (draft_id + step_uid) "
        "stable across structural mutations. Predicate fields: name_contains, name_equals, "
        "closure_keyword (e.g. 'run_wmi_query_to_var', 'ref'), ref_to_refid (sys_id of target library), "
        "attr_eq=[name,value], attr_contains=[name,substr], section ('identification' | 'connection' | "
        "'extension' | 'library'). Multiple fields combine with AND. Use this BEFORE every edit op "
        "to obtain target locators."
    ),
    "draft_apply": (
        "Apply an edit op to a draft. Op names: clone_library, wrap_in_guard, insert_step_before, "
        "insert_step_after, redirect_ref, modify_closure_attr, remove_step. Each op validates before "
        "mutating; failures return ok=false with a list of issues (each with a code, message, and "
        "sometimes a suggested_fix the agent can apply). Recipe-based inserts: pass {recipe: <name>, "
        "closure: <keyword>, params: {...}} instead of ndl_fragment to use a curated, tested NDL "
        "template attached to the closure (call closure_capability to discover available recipes)."
    ),
    "draft_validate": (
        "Run all validators on a draft: Tier-1 syntax + roundtrip; cross-draft var-flow (parent reads "
        "vs child exports for clone-then-redirect workflows). Returns severity-ranked issues. Run this "
        "AFTER each significant edit and BEFORE finalize. Cross-draft check is the safety net for the "
        "clone-and-edit workflow: if the cloned library no longer writes a var the parent still reads, "
        "this is where it surfaces."
    ),
    "draft_diff": (
        "Unified textual diff: original source NDL vs current draft tree. Use to review your changes "
        "before finalizing. Returns the diff verbatim (capped at 8000 chars)."
    ),
    "draft_finalize": (
        "Materialize the draft. Modes: 'serialize_only' (return current NDL as text), 'sandbox' "
        "(create new sa_pattern row in PDI with _sandbox_snmcp_ prefix — same safety as "
        "pattern_test_compile), 'push_live' (NOT IMPLEMENTED — intentional safety guard). For "
        "production deploys: serialize_only + manual review + manual upload."
    ),
    "draft_abandon": (
        "Drop a draft and all its child drafts from the in-memory store. Use when the user gives up "
        "on the workflow or starts over. Drafts are also dropped on server restart."
    ),
    "closure_capability": (
        "Describe a closure: required inputs, outputs, semantics, and the list of recipes addressing "
        "its known limitations. Recipes are tested NDL fragments parameterized for re-use. Use this "
        "WHEN you need to know how to work around a closure-level gap (e.g. run_wmi_query_to_var "
        "doesn't validate namespace existence — there's a recipe for that). Always returns a JSON "
        "object with `known: bool` — unknown closure keywords are NOT errors."
    ),
    "pattern_ingest_ndl": (
        "Add a pattern (or library) to the in-memory index for THIS SESSION ONLY from raw NDL text. "
        "Use this when the user pastes a community pattern, a forum-thread NDL fragment, or a "
        "decommissioned pattern not in the indexed corpus — and wants to analyze it with the regular "
        "tools (pattern_analyze, pattern_lineage, pattern_open_draft, etc.). The new entry is flagged "
        "not_authoritative=true so it can be distinguished from PDI-fetched patterns. Survives only "
        "until server restart. Returns the sys_id you can pass to all other tools."
    ),
}


def _make_tool_list():
    """Build MCP Tool definitions. Imported lazily inside run() because mcp.types
    requires the mcp dependency which is not always installed in test environments."""
    from mcp.types import Tool

    def _input(properties: dict, required: list[str]) -> dict:
        return {"type": "object", "properties": properties, "required": required, "additionalProperties": False}

    return [
        Tool(name="pattern_analyze", description=TOOL_DESCRIPTIONS["pattern_analyze"],
             inputSchema=_input({"name": {"type": "string", "description": "Pattern name or 32-char sys_id"}}, ["name"])),
        Tool(name="pattern_resolve", description=TOOL_DESCRIPTIONS["pattern_resolve"],
             inputSchema=_input({
                 "name": {"type": "string", "description": "Pattern name or 32-char sys_id"},
                 "depth": {"type": "string", "enum": ["shallow", "deep"], "default": "deep"},
             }, ["name"])),
        Tool(name="pattern_debug", description=TOOL_DESCRIPTIONS["pattern_debug"],
             inputSchema=_input({
                 "name": {"type": "string", "description": "Pattern name or 32-char sys_id"},
                 "issue": {"type": "string", "description": "Free-form issue description, e.g. 'returns no CIs', 'auth failing'"},
             }, ["name", "issue"])),
        Tool(name="pattern_search", description=TOOL_DESCRIPTIONS["pattern_search"],
             inputSchema=_input({
                 "query": {"type": "string", "description": "Natural-language search query"},
                 "limit": {"type": "integer", "default": 10, "minimum": 1, "maximum": 50},
             }, ["query"])),
        Tool(name="ndl_explain", description=TOOL_DESCRIPTIONS["ndl_explain"],
             inputSchema=_input({"ndl": {"type": "string", "description": "Raw NDL text (max 1 MiB)"}}, ["ndl"])),
        Tool(name="pattern_compare", description=TOOL_DESCRIPTIONS["pattern_compare"],
             inputSchema=_input({
                 "a": {"type": "string", "description": "First pattern name or sys_id"},
                 "b": {"type": "string", "description": "Second pattern name or sys_id"},
             }, ["a", "b"])),
        Tool(name="pattern_validate", description=TOOL_DESCRIPTIONS["pattern_validate"],
             inputSchema=_input({
                 "ndl": {"type": "string", "description": "Raw NDL text to validate (max 1 MiB)"},
                 "verbose": {"type": "boolean", "default": False, "description": "Include INFO findings (mostly unregistered closure names)"},
             }, ["ndl"])),
        Tool(name="pattern_create", description=TOOL_DESCRIPTIONS["pattern_create"],
             inputSchema=_input({
                 "intent": {"type": "string", "description": "Natural-language description of what the pattern should do"},
                 "ci_type": {"type": "string", "description": "Target CI table (e.g. cmdb_ci_app_server_tomcat)"},
                 "os_family": {"type": "string", "description": "OS family table (e.g. cmdb_ci_linux_server)"},
             }, ["intent"])),
        Tool(name="pattern_test_compile", description=TOOL_DESCRIPTIONS["pattern_test_compile"],
             inputSchema=_input({
                 "ndl": {"type": "string", "description": "Raw NDL text to compile-test (max 1 MiB)"},
                 "cleanup": {"type": "boolean", "default": True, "description": "Delete the sandbox row after test (set false to retain for inspection)"},
             }, ["ndl"])),
        Tool(name="pattern_diff_against_live", description=TOOL_DESCRIPTIONS["pattern_diff_against_live"],
             inputSchema=_input({
                 "name_or_sys_id": {"type": "string", "description": "Pattern name or sys_id to fetch from PDI"},
                 "local_ndl": {"type": "string", "description": "Your local NDL draft to compare against the PDI version"},
             }, ["name_or_sys_id", "local_ndl"])),
        Tool(name="oid_lookup", description=TOOL_DESCRIPTIONS["oid_lookup"],
             inputSchema=_input({
                 "oid_or_name": {"type": "string", "description": "Dotted-decimal OID, short name, or MIB::Name"},
             }, ["oid_or_name"])),
        Tool(name="oid_walk_explain", description=TOOL_DESCRIPTIONS["oid_walk_explain"],
             inputSchema=_input({
                 "prefix_oid": {"type": "string", "description": "OID prefix (a table OID, group OID, or any node)"},
             }, ["prefix_oid"])),
        Tool(name="oid_search", description=TOOL_DESCRIPTIONS["oid_search"],
             inputSchema=_input({
                 "query": {"type": "string", "description": "Natural-language description of what OID(s) you want"},
                 "limit": {"type": "integer", "default": 10, "minimum": 1, "maximum": 50},
             }, ["query"])),
        Tool(name="pattern_snmp_audit", description=TOOL_DESCRIPTIONS["pattern_snmp_audit"],
             inputSchema=_input({
                 "name_or_sys_id": {"type": "string", "description": "Pattern name or 32-char sys_id"},
             }, ["name_or_sys_id"])),
        Tool(name="pattern_lineage", description=TOOL_DESCRIPTIONS["pattern_lineage"],
             inputSchema=_input({
                 "name_or_sys_id": {"type": "string", "description": "Pattern name or 32-char sys_id"},
             }, ["name_or_sys_id"])),
        Tool(name="pattern_data_sources", description=TOOL_DESCRIPTIONS["pattern_data_sources"],
             inputSchema=_input({
                 "name_or_sys_id": {"type": "string", "description": "Pattern name or 32-char sys_id"},
             }, ["name_or_sys_id"])),
        Tool(name="pattern_data_sources_lookup", description=TOOL_DESCRIPTIONS["pattern_data_sources_lookup"],
             inputSchema=_input({
                 "target": {"type": "string", "description": "Target family: windows, linux, f5, cisco-ios, esxi"},
                 "query": {"type": "string", "description": "Keyword to search across all targets (use instead of or with target)"},
             }, [])),
        Tool(name="emulator_catalog", description=TOOL_DESCRIPTIONS["emulator_catalog"],
             inputSchema=_input({
                 "target": {"type": "string", "description": "Optional target alias: windows, linux, f5, netscaler, cisco-ios, esxi, generic-snmp"},
                 "query": {"type": "string", "description": "Optional text filter across profile names, aliases, ports, and services"},
             }, [])),
        Tool(name="emulator_blueprint", description=TOOL_DESCRIPTIONS["emulator_blueprint"],
             inputSchema=_input({
                 "target": {"type": "string", "description": "Optional explicit target alias; overrides pattern inference"},
                 "name_or_sys_id": {"type": "string", "description": "Optional indexed pattern name or 32-char sys_id"},
                 "ndl": {"type": "string", "description": "Optional raw NDL text (max 1 MiB)"},
                 "oids": {
                     "type": "array",
                     "items": {"type": "string"},
                     "description": "Optional SNMP OIDs the emulator must serve, useful for generic MIB-driven targets",
                 },
             }, [])),
        # ----- Draft / surgical-edit harness tools -----
        Tool(name="pattern_open_draft", description=TOOL_DESCRIPTIONS["pattern_open_draft"],
             inputSchema=_input({
                 "name_or_sys_id": {"type": "string", "description": "Pattern or library name / 32-char sys_id"},
             }, ["name_or_sys_id"])),
        Tool(name="draft_locate_steps", description=TOOL_DESCRIPTIONS["draft_locate_steps"],
             inputSchema=_input({
                 "draft_id": {"type": "string", "description": "Draft id from pattern_open_draft"},
                 "predicate": {
                     "type": "object",
                     "description": "Predicate fields (all optional, ANDed). See tool description for fields.",
                     "additionalProperties": True,
                 },
                 "limit": {"type": "integer", "default": 50, "minimum": 1, "maximum": 500},
             }, ["draft_id", "predicate"])),
        Tool(name="draft_apply", description=TOOL_DESCRIPTIONS["draft_apply"],
             inputSchema=_input({
                 "draft_id": {"type": "string"},
                 "op_name": {"type": "string", "description": "One of: clone_library, wrap_in_guard, insert_step_before, insert_step_after, redirect_ref, modify_closure_attr, remove_step"},
                 "params": {"type": "object", "description": "Op-specific parameters", "additionalProperties": True},
             }, ["draft_id", "op_name", "params"])),
        Tool(name="draft_validate", description=TOOL_DESCRIPTIONS["draft_validate"],
             inputSchema=_input({"draft_id": {"type": "string"}}, ["draft_id"])),
        Tool(name="draft_diff", description=TOOL_DESCRIPTIONS["draft_diff"],
             inputSchema=_input({"draft_id": {"type": "string"}}, ["draft_id"])),
        Tool(name="draft_finalize", description=TOOL_DESCRIPTIONS["draft_finalize"],
             inputSchema=_input({
                 "draft_id": {"type": "string"},
                 "mode": {"type": "string", "enum": ["serialize_only", "sandbox", "push_live"], "default": "serialize_only"},
             }, ["draft_id"])),
        Tool(name="draft_abandon", description=TOOL_DESCRIPTIONS["draft_abandon"],
             inputSchema=_input({"draft_id": {"type": "string"}}, ["draft_id"])),
        Tool(name="closure_capability", description=TOOL_DESCRIPTIONS["closure_capability"],
             inputSchema=_input({"closure_keyword": {"type": "string"}}, ["closure_keyword"])),
        Tool(name="pattern_ingest_ndl", description=TOOL_DESCRIPTIONS["pattern_ingest_ndl"],
             inputSchema=_input({
                 "name": {"type": "string", "description": "Display name for the ingested pattern"},
                 "ndl": {"type": "string", "description": "Raw NDL text (max 1 MiB)"},
                 "ci_type": {"type": "string", "description": "Optional cmdb_ci_* CI type (defaults to NDL metadata.citype)"},
                 "description": {"type": "string", "description": "Optional human description"},
             }, ["name", "ndl"])),
    ]


class SnPatternsServer:
    def __init__(self) -> None:
        index_root = os.environ.get("SN_PATTERNS_INDEX_ROOT") or str(DEFAULT_INDEX_ROOT)
        self.index = PatternIndex.load(index_root)
        self.chroma = ChromaPatternIndex(DEFAULT_CHROMA_DIR)
        try:
            self.pdi = try_create_client()
        except PdiUnavailable as e:
            log.info("PDI unavailable: %s", e)
            self.pdi = None

        # Wire the global draft store with index/pdi so CloneLibrary can resolve sys_ids.
        self.drafts = DRAFTS
        self.drafts.index = self.index  # type: ignore[attr-defined]
        self.drafts.pdi = self.pdi      # type: ignore[attr-defined]

        # Debug mode: include full tracebacks in tool error responses
        self._debug = os.environ.get("SN_PATTERNS_DEBUG", "").lower() in ("1", "true", "yes")

        log.info(
            "sn-patterns server initialized — index=%s patterns, chroma_dir=%s, pdi=%s, debug=%s",
            self.index.size(), DEFAULT_CHROMA_DIR,
            "active" if self.pdi else "offline (no creds in env)",
            self._debug,
        )

    def _ctx(self) -> dict:
        return {"index": self.index, "pdi": self.pdi, "chroma": self.chroma}

    def _dispatch(self, name: str, arguments: dict) -> str:
        """Route an MCP call to the right tool. Returns plain text on success or ERROR on failure."""
        ctx = self._ctx()
        if name == "pattern_analyze":
            return ptools.pattern_analyze(arguments["name"], index=ctx["index"], pdi=ctx["pdi"])
        if name == "pattern_resolve":
            return ptools.pattern_resolve(
                arguments["name"],
                index=ctx["index"], pdi=ctx["pdi"],
                depth=arguments.get("depth", "deep"),
            )
        if name == "pattern_debug":
            return ptools.pattern_debug(
                arguments["name"], arguments["issue"],
                index=ctx["index"], pdi=ctx["pdi"],
            )
        if name == "pattern_search":
            return ptools.pattern_search(
                arguments["query"],
                index=ctx["index"], chroma=ctx["chroma"],
                limit=int(arguments.get("limit", 10)),
            )
        if name == "ndl_explain":
            return ptools.ndl_explain(arguments["ndl"])
        if name == "pattern_compare":
            return ptools.pattern_compare(
                arguments["a"], arguments["b"],
                index=ctx["index"], pdi=ctx["pdi"],
            )
        if name == "pattern_validate":
            return ptools.pattern_validate(
                arguments["ndl"],
                verbose=bool(arguments.get("verbose", False)),
                index=ctx["index"],
            )
        if name == "pattern_create":
            return ptools.pattern_create(
                arguments["intent"],
                ci_type=arguments.get("ci_type"),
                os_family=arguments.get("os_family"),
                index=ctx["index"], chroma=ctx["chroma"],
            )
        if name == "pattern_test_compile":
            return ptools.pattern_test_compile(
                arguments["ndl"],
                pdi=ctx["pdi"],
                cleanup=bool(arguments.get("cleanup", True)),
            )
        if name == "pattern_diff_against_live":
            return ptools.pattern_diff_against_live(
                arguments["name_or_sys_id"],
                arguments["local_ndl"],
                pdi=ctx["pdi"],
            )
        if name == "oid_lookup":
            return ptools.oid_lookup(arguments["oid_or_name"])
        if name == "oid_walk_explain":
            return ptools.oid_walk_explain(arguments["prefix_oid"])
        if name == "oid_search":
            return ptools.oid_search(arguments["query"], limit=int(arguments.get("limit", 10)))
        if name == "pattern_snmp_audit":
            return ptools.pattern_snmp_audit(
                arguments["name_or_sys_id"],
                index=ctx["index"], pdi=ctx["pdi"],
            )
        if name == "pattern_lineage":
            return ptools.pattern_lineage(
                arguments["name_or_sys_id"],
                index=ctx["index"], pdi=ctx["pdi"],
            )
        if name == "pattern_data_sources":
            return ptools.pattern_data_sources(
                arguments["name_or_sys_id"],
                index=ctx["index"], pdi=ctx["pdi"],
            )
        if name == "pattern_data_sources_lookup":
            return ptools.pattern_data_sources_lookup(
                target=arguments.get("target"),
                query=arguments.get("query"),
            )
        if name == "emulator_catalog":
            return ptools.emulator_catalog(
                target=arguments.get("target"),
                query=arguments.get("query"),
            )
        if name == "emulator_blueprint":
            return ptools.emulator_blueprint(
                target=arguments.get("target"),
                name_or_sys_id=arguments.get("name_or_sys_id"),
                ndl=arguments.get("ndl"),
                oids=arguments.get("oids") or [],
                index=ctx["index"],
                pdi=ctx["pdi"],
            )
        # ----- Draft / surgical-edit harness -----
        if name == "pattern_open_draft":
            return dtools.pattern_open_draft(
                arguments["name_or_sys_id"],
                store=self.drafts, index=ctx["index"], pdi=ctx["pdi"],
            )
        if name == "draft_locate_steps":
            return dtools.draft_locate_steps(
                arguments["draft_id"],
                arguments["predicate"],
                store=self.drafts,
                limit=int(arguments.get("limit", 50)),
            )
        if name == "draft_apply":
            return dtools.draft_apply(
                arguments["draft_id"],
                arguments["op_name"],
                arguments["params"],
                store=self.drafts,
            )
        if name == "draft_validate":
            return dtools.draft_validate(arguments["draft_id"], store=self.drafts)
        if name == "draft_diff":
            return dtools.draft_diff(arguments["draft_id"], store=self.drafts)
        if name == "draft_finalize":
            return dtools.draft_finalize(
                arguments["draft_id"],
                store=self.drafts, pdi=ctx["pdi"],
                mode=arguments.get("mode", "serialize_only"),
            )
        if name == "draft_abandon":
            return dtools.draft_abandon(arguments["draft_id"], store=self.drafts)
        if name == "closure_capability":
            return dtools.closure_capability(arguments["closure_keyword"])
        if name == "pattern_ingest_ndl":
            return ptools.pattern_ingest_ndl(
                arguments["name"], arguments["ndl"],
                index=ctx["index"],
                ci_type=arguments.get("ci_type", ""),
                description=arguments.get("description", ""),
            )
        return f"ERROR: unknown tool: {name}"

    async def run(self) -> None:
        from mcp.server import Server
        from mcp.server.stdio import stdio_server
        from mcp.types import TextContent

        server = Server("sn-patterns")
        tool_list = _make_tool_list()

        @server.list_tools()
        async def list_tools():
            return tool_list

        @server.call_tool()
        async def call_tool(name: str, arguments: dict) -> list[TextContent]:
            try:
                out = self._dispatch(name, arguments)
            except KeyError as e:
                out = f"ERROR: missing required argument {e} for tool {name!r}"
                log.warning("call_tool %s missing argument: %s", name, e)
            except Exception as e:
                log.exception("call_tool %s crashed", name)
                out = f"ERROR: {name} raised {type(e).__name__}: {e}"
                if self._debug:
                    out += "\n\nTRACEBACK:\n" + traceback.format_exc()
            return [TextContent(type="text", text=out)]

        async with stdio_server() as (reader, writer):
            await server.run(reader, writer, server.create_initialization_options())


def main() -> None:
    configure_logging()
    asyncio.run(SnPatternsServer().run())


if __name__ == "__main__":
    main()
