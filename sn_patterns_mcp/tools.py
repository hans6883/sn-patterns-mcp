"""MCP tool implementations. Pure functions on (index, pdi, chroma) + args.

Each returns plain text capped at MAX_CHARS. Tools never raise — failures become
a one-line ERROR: prefix in the response so the calling AI can read and act on them.
"""
from __future__ import annotations

import difflib
import json
import logging
import secrets
import time
from pathlib import Path
from typing import Any

from sn_patterns_mcp.closures import registry as closures
from sn_patterns_mcp.ndl_parser import NdlParser, NdlSyntaxError, classify_variables
from sn_patterns_mcp.pattern_model import Pattern, Step

log = logging.getLogger(__name__)

MAX_CHARS = 8000
# Cap raw NDL inputs to ndl_explain / pattern_validate to prevent DoS via
# deeply nested / huge text from a misbehaving caller.
MAX_NDL_INPUT_BYTES = 1_048_576  # 1 MiB


# ---------------------------------------------------------------------------
# Fetch helper — index first, PDI fallback
# ---------------------------------------------------------------------------

def _fetch_pattern(name_or_sys_id: str, index, pdi) -> tuple[Pattern | None, dict[str, Any] | None]:
    pattern = index.get(name_or_sys_id) if index is not None else None
    meta: dict[str, Any] | None = None
    if index is not None:
        getter = getattr(index, "metadata_for", None)
        if getter is not None:
            meta = getter(name_or_sys_id)
        else:
            sys_id = index.resolve_sys_id(name_or_sys_id)
            meta = index.manifest.get(sys_id) if sys_id else None
    if pattern is not None:
        return pattern, meta
    if pdi is not None:
        row = pdi.get_pattern(name_or_sys_id)
        if row and row.get("pattern_text"):
            pattern = NdlParser().parse(row["pattern_text"])
            if meta is None:
                meta = {
                    "name": row.get("name"),
                    "description": row.get("description"),
                    "ci_type": row.get("ci_type"),
                    "sys_id": row.get("sys_id"),
                }
            return pattern, meta
    return None, meta


def _clip(s: str) -> str:
    if len(s) <= MAX_CHARS:
        return s
    return s[: MAX_CHARS - 60] + "\n\n... [truncated to 8000 chars]"


# ---------------------------------------------------------------------------
# pattern_analyze
# ---------------------------------------------------------------------------

def pattern_analyze(name_or_sys_id: str, *, index, pdi) -> str:
    pattern, meta = _fetch_pattern(name_or_sys_id, index, pdi)
    if pattern is None:
        if meta:
            return _format_metadata_only(meta)
        return f"Pattern not found: {name_or_sys_id!r}"

    md = pattern.metadata
    lines: list[str] = []
    lines.append(f"Pattern: {md.name or meta.get('name') if meta else '(unknown)'}")
    lines.append(f"  sys_id: {md.id or (meta.get('sys_id') if meta else '')}")
    lines.append(f"  CI type: {md.ci_type}")
    if md.description:
        lines.append(f"  Description: {md.description}")
    if md.apply_to_os_types:
        lines.append(f"  OS types: {', '.join(md.apply_to_os_types)}")
    lines.append(f"  Type: {pattern.pattern_type.value}")
    lines.append("")

    variables = classify_variables(pattern)
    lines.append(f"IDENTIFICATIONS: {len(pattern.identifications)}")
    for idx, ident in enumerate(pattern.identifications, 1):
        lines.append(f"  [{idx}] {ident.name or '(unnamed)'}"
                     f"   strategy={ident.find_process_strategy.value if ident.find_process_strategy else 'NONE'}"
                     f"   entry_points={','.join(ident.entry_point_types) or '-'}")
        for s_i, step in enumerate(ident.steps, 1):
            lines.append(_format_step(s_i, step))

    if pattern.connections:
        lines.append("")
        lines.append(f"CONNECTIONS: {len(pattern.connections)}")
        for idx, conn in enumerate(pattern.connections, 1):
            lines.append(f"  [{idx}] {conn.name or '(unnamed)'}")
            for s_i, step in enumerate(conn.steps, 1):
                lines.append(_format_step(s_i, step))

    if pattern.extensions:
        lines.append("")
        lines.append(f"EXTENSIONS: {len(pattern.extensions)}")
        for idx, ext in enumerate(pattern.extensions, 1):
            lines.append(f"  [{idx}] {ext.name or '(unnamed)'}   order={ext.order}")
            for s_i, step in enumerate(ext.steps, 1):
                lines.append(_format_step(s_i, step))

    lines.append("")
    lines.append(f"VARIABLES ({len(variables)}):")
    for name in sorted(variables.keys()):
        v = variables[name]
        lines.append(f"  ${name}  [{v.scope.value}]")

    return _clip("\n".join(lines))


def _format_step(idx: int, step: Step) -> str:
    if step.is_library_ref:
        rid = step.referenced_library_id() or "(unknown)"
        flag = " [CONDITIONAL]" if step.is_conditional_library_ref else ""
        disabled = " [DISABLED]" if step.is_disabled else ""
        return f"    Step {idx}: refid -> {rid}{flag}{disabled}"
    op = step.operation
    if op is None:
        return f"    Step {idx}: {step.name or '(unnamed)'} [NO OPERATION]"
    descriptor = closures.get(op.keyword)
    disabled = " [DISABLED]" if step.is_disabled else ""
    head = f"    Step {idx}: {step.name or '(unnamed)'} — {op.keyword}{disabled}"
    detail_lines = [head]
    if descriptor:
        detail_lines.append(f"        > {descriptor.summary}")
    for key, val in list(op.attributes.items())[:6]:
        detail_lines.append(f"        {key} = {_short(val)}")
    for oper_key, sub_op in list(op.operands.items())[:4]:
        detail_lines.append(f"        {oper_key} -> {sub_op.keyword}")
    # Track 3 inline OID resolution: when the op is run_snmp_*, look up its OID
    # and append a one-line semantic gloss.
    snmp_gloss = _resolve_snmp_oid_inline(op)
    if snmp_gloss:
        detail_lines.append(f"        SNMP: {snmp_gloss}")
    return "\n".join(detail_lines)


def _resolve_snmp_oid_inline(op) -> str:
    """If op is an SNMP operation, return a one-line description of the OID it queries."""
    if not op.keyword.startswith("run_snmp"):
        return ""
    oid = op.attributes.get("oid") or ""
    if not oid:
        oid_op = op.operands.get("oid")
        if oid_op is not None:
            oid = oid_op.attributes.get("value", "") or (str(oid_op.positional_args[0]) if oid_op.positional_args else "")
    if not oid and op.positional_args:
        oid = str(op.positional_args[0])
    if not oid or "$" in oid:
        return ""
    from sn_patterns_mcp import oids
    entry = oids.lookup(oid)
    if entry is not None:
        tag = " [TABLE]" if entry.is_table else (" [COLUMNAR]" if entry.is_columnar else "")
        return f"{oid} → {entry.full_name}{tag}"
    vendor = oids.identify_vendor(oid)
    if vendor is not None:
        return f"{oid} → {vendor.vendor}-private (MIB not in registry)"
    return f"{oid} → unresolved"


def _format_metadata_only(meta: dict[str, Any]) -> str:
    lines = [
        f"Pattern: {meta.get('name', '?')}",
        f"  sys_id: {meta.get('sys_id', '')}",
        f"  ci_type: {meta.get('ci_type') or '(unknown)'}",
        f"  scope: {meta.get('scope') or 'global'}",
        f"  active: {meta.get('active', '?')}   version: {meta.get('version', '')}",
    ]
    if meta.get("description"):
        lines.append(f"  description: {meta['description']}")
    if meta.get("applies_to"):
        lines.append(f"  applies_to: {meta['applies_to']}")
    lines.append("")
    lines.append("NDL text not in local index. To see step-by-step breakdown:")
    lines.append("  - set SN_INSTANCE / SN_USERNAME / SN_PASSWORD env vars, OR")
    lines.append("  - run scripts/export_patterns.py to hydrate the index from PDI.")
    return _clip("\n".join(lines))


def _short(val: Any) -> str:
    if isinstance(val, str):
        return (val[:120] + "...") if len(val) > 120 else val
    if isinstance(val, list):
        parts = [_short(x) for x in val[:4]]
        return "[" + ", ".join(parts) + (", ..." if len(val) > 4 else "") + "]"
    return str(val)[:120]


# ---------------------------------------------------------------------------
# pattern_resolve — full ecosystem
# ---------------------------------------------------------------------------

def pattern_resolve(name_or_sys_id: str, *, index, pdi, depth: str = "deep") -> str:
    pattern, meta = _fetch_pattern(name_or_sys_id, index, pdi)
    if pattern is None and meta is None:
        return f"Pattern not found: {name_or_sys_id!r}"

    sys_id = (pattern.metadata.id if pattern else "") or (meta or {}).get("sys_id", "")
    name = (pattern.metadata.name if pattern else "") or (meta or {}).get("name", "?")
    lines: list[str] = [f"Resolve: {name}  (sys_id={sys_id})", ""]

    # Shared library refs (only when we have parsed NDL)
    if pattern:
        refs = pattern.library_references()
        lines.append(f"SHARED LIBRARIES REFERENCED ({len(refs)}):")
        for ref in refs:
            lib_name = _resolve_library_name(ref, index, pdi)
            lines.append(f"  - {ref}  ({lib_name or '?'})")
    else:
        lines.append("SHARED LIBRARIES: NDL not cached locally — run scripts/export_patterns.py with PDI creds.")

    # Classifiers — PDI first, local fallback. Tag the source so callers know.
    classifiers: list[dict[str, Any]] = []
    classifier_source = "none"
    pdi_error: str | None = None
    if pdi is not None and sys_id:
        try:
            classifiers = pdi.get_classifiers_for_pattern(sys_id)
            classifier_source = "pdi"
        except Exception as e:
            pdi_error = f"{type(e).__name__}: {e}"
            log.warning("PDI classifier lookup failed for %s: %s", sys_id, pdi_error)
    if not classifiers and index is not None:
        classifiers = _local_classifiers_for(index, sys_id, name)
        if classifiers:
            classifier_source = "local-heuristic"
    lines.append("")
    note = f"  (source: {classifier_source}"
    if pdi_error:
        note += f"; PDI failed: {pdi_error}"
    note += ")"
    lines.append(f"CLASSIFIERS ({len(classifiers)}){note}:")
    for c in classifiers[:20]:
        src = c.get("_source_table") or c.get("table", "?")
        lines.append(f"  - {c.get('name') or c.get('sys_id')}  [{src}]")

    # Pre/post scripts — PDI first, local fallback. Same source-tagging.
    scripts: list[dict[str, Any]] = []
    script_source = "none"
    script_pdi_error: str | None = None
    if pdi is not None and sys_id:
        try:
            scripts = pdi.get_prepost_scripts(sys_id)
            script_source = "pdi"
        except Exception as e:
            script_pdi_error = f"{type(e).__name__}: {e}"
            log.warning("PDI prepost lookup failed for %s: %s", sys_id, script_pdi_error)
    if not scripts and index is not None and sys_id:
        scripts = index.local.prepost_for(sys_id)
        if scripts:
            script_source = "local"
    lines.append("")
    s_note = f"  (source: {script_source}"
    if script_pdi_error:
        s_note += f"; PDI failed: {script_pdi_error}"
    s_note += ")"
    lines.append(f"PRE/POST SCRIPTS ({len(scripts)}){s_note}:")
    for s in scripts[:20]:
        stage = s.get("phase") or s.get("stage") or s.get("type") or s.get("scope") or "?"
        lines.append(f"  - [{stage}] {s.get('name') or s.get('sys_id')}")
        if s.get("script_preview"):
            preview = s["script_preview"].replace("\n", " ").strip()
            lines.append(f"      {preview[:180]}")

    # Extensions (local only)
    if index is not None and sys_id:
        extensions = index.local.extensions_for(sys_id)
        if extensions:
            lines.append("")
            lines.append(f"EXTENSIONS ({len(extensions)}):")
            for e in extensions[:10]:
                lines.append(f"  - {e.get('sys_id', '?')}")

    # Command inventory (from parsed NDL) — only when NDL available.
    # Source of truth: registry's COMMAND category (run*, http_invoke, ldap_query, etc.)
    if pattern is None:
        return _clip("\n".join(lines))
    lines.append("")
    lines.append("COMMANDS (parsed from NDL):")
    cmd_count = 0
    for step in pattern.all_steps():
        if step.operation is None:
            continue
        for op in _iter_ops(step.operation):
            if op.keyword in _COMMAND_KEYWORDS:
                cmd = op.operands.get("command") or op.operands.get("cmd")
                cmd_text = (
                    cmd.attributes.get("value") if cmd and "value" in cmd.attributes
                    else op.attributes.get("command") or op.attributes.get("cmd") or ""
                )
                lines.append(f"  - {op.keyword}: {_short(cmd_text)}")
                cmd_count += 1
                if cmd_count >= 20:
                    break
        if cmd_count >= 20:
            break

    return _clip("\n".join(lines))


_COMMAND_KEYWORDS: frozenset[str] = frozenset(
    kw for kw, d in closures.CLOSURE_REGISTRY.items()
    if d.category == closures.OperationCategory.COMMAND
)


def _local_classifiers_for(index, sys_id: str, name: str) -> list[dict[str, Any]]:
    """Heuristic match: pattern name appears in classifier name (case-insensitive)."""
    if index is None or index.local is None:
        return []
    all_cls = index.local.all_classifiers()
    if not all_cls:
        return []
    name_l = (name or "").lower()
    # Strip common suffixes to improve match rate
    for suffix in (" on unix", " on windows", " on linux", " - identity"):
        if name_l.endswith(suffix):
            name_l = name_l[: -len(suffix)]
    hits: list[dict[str, Any]] = []
    for c in all_cls:
        cn = (c.get("name") or "").lower()
        if not cn:
            continue
        if name_l and (name_l in cn or cn in name_l):
            hits.append(c)
    return hits[:50]


def _resolve_library_name(sys_id: str, index, pdi) -> str | None:
    if index is not None:
        entry = index.manifest.get(sys_id)
        if entry:
            return entry.get("name")
    if pdi is not None:
        try:
            row = pdi.get_library(sys_id)
            if row:
                return row.get("name")
        except Exception as e:
            log.warning("library name lookup failed for %s: %s", sys_id, e)
    return None


def _iter_ops(op):
    yield op
    for sub in op.operands.values():
        yield from _iter_ops(sub)
    for sub in op.list_operands:
        yield from _iter_ops(sub)


# ---------------------------------------------------------------------------
# pattern_debug
# ---------------------------------------------------------------------------

def pattern_debug(name_or_sys_id: str, issue: str, *, index, pdi) -> str:
    pattern, meta = _fetch_pattern(name_or_sys_id, index, pdi)
    if pattern is None and meta is None:
        return f"Pattern not found: {name_or_sys_id!r}"

    lines: list[str] = []
    name = (pattern.metadata.name if pattern else "") or (meta or {}).get("name", "?")
    lines.append(f"Debug plan — {name}")
    lines.append(f"  issue: {issue}")
    lines.append("")
    lines.append("1. sa_discovery_log lookup:")
    sys_id = (pattern.metadata.id if pattern else "") or (meta or {}).get("sys_id", "")
    lines.append(f"   sysparm_query=pattern={sys_id}^statusIN3,4^ORDERBYDESCsys_created_on")
    lines.append("")
    lines.append("2. ecc_queue MID payload check:")
    ci_type = (pattern.metadata.ci_type if pattern else "") or (meta or {}).get("ci_type", "?")
    lines.append("   table=ecc_queue agent=mid.server.*  topic=SystemCommand/WMIQuery/SNMPQuery")
    lines.append(f"   look for source={ci_type} or referencing this pattern sys_id")
    lines.append("")

    # Prepost scripts that may explain the failure (offline data)
    if index is not None and sys_id:
        scripts = index.local.prepost_for(sys_id)
        if scripts:
            lines.append(f"2b. Pre/post scripts attached to this pattern ({len(scripts)}):")
            for s in scripts[:10]:
                lines.append(f"    - {s.get('name', '?')}  (scope={s.get('scope', '-')}, active={s.get('active', '?')})")
            lines.append("")

    # Per-operation debug hints (NDL-dependent)
    if pattern is None:
        lines.append("3. Operation-specific failure modes:")
        lines.append("    NDL not cached; run scripts/export_patterns.py to enable op-aware debug.")
        return _clip("\n".join(lines))

    kws = sorted(set(pattern.operation_keywords()))
    lines.append(f"3. Operation-specific failure modes ({len(kws)} op types):")
    for kw in kws[:30]:
        d = closures.get(kw)
        if not d or not d.failure_modes:
            continue
        lines.append(f"   {kw}:")
        for fm in d.failure_modes:
            lines.append(f"     - {fm}")

    # Issue-specific routing
    lines.append("")
    lines.append("4. Issue-specific guidance:")
    lowered = issue.lower()
    if "credential" in lowered or "auth" in lowered:
        lines.append("   - Check discovery_credentials table for matching credential_type.")
        lines.append("   - If runcmd_to_var uses applicative credentials, verify ci_type_id links.")
    if "timeout" in lowered or "slow" in lowered:
        lines.append("   - WMI default timeout is 60s; tune via mid.sm.wmi_query_timeout property.")
        lines.append("   - SNMP retries: mid.sm.snmp.retries, mid.sm.snmp.timeout.")
    if "no ci" in lowered or "empty" in lowered or "not found" in lowered:
        lines.append("   - Identification step likely produced no rows — check parse strategy regex/xpath.")
        lines.append("   - Verify find_process_strategy matches what listens on target.")
    if "ecc" in lowered or "midserver" in lowered or "mid server" in lowered:
        lines.append("   - MID log: /opt/mid/agent/logs/agent0.log.0  (or <mid_home>/agent/logs on Windows)")

    return _clip("\n".join(lines))


# ---------------------------------------------------------------------------
# pattern_search
# ---------------------------------------------------------------------------

def pattern_search(query: str, *, index, chroma, limit: int = 10) -> str:
    if not query or not query.strip():
        return "Empty query"

    results: list[dict[str, Any]] = []
    backend = "none"
    chroma_error: str | None = None
    if chroma is not None:
        try:
            results = chroma.search(query, n=limit)
            backend = "chroma-semantic"
        except Exception as e:
            chroma_error = f"{type(e).__name__}: {e}"
            log.warning("Chroma search failed for %r: %s", query, chroma_error)
    if not results and index is not None:
        hits = index.search_text(query, limit=limit)
        results = [{"sys_id": h["sys_id"], "metadata": h, "distance": None} for h in hits]
        if results:
            backend = "manifest-substring"

    if not results:
        msg = f"No patterns match {query!r}"
        if chroma_error:
            msg += f"  (semantic search failed: {chroma_error}; substring fallback also empty)"
        return msg

    header = f"Search: {query}  [backend: {backend}]"
    if chroma_error:
        header += f"  (Chroma error: {chroma_error} — using substring fallback)"
    lines = [header, f"Top {len(results)} result(s):", ""]
    for r in results:
        meta = r.get("metadata") or {}
        name = meta.get("name", "?")
        ci = meta.get("ci_type", "")
        ops = meta.get("operation_kws", "")
        if isinstance(ops, list):
            ops = ", ".join(sorted(set(ops)))
        dist = r.get("distance")
        score = f"  (distance={dist:.3f})" if isinstance(dist, (int, float)) else ""
        lines.append(f"- {name}  [{ci}]  sys_id={r['sys_id']}{score}")
        if ops:
            lines.append(f"    ops: {ops[:300]}")

    return _clip("\n".join(lines))


# ---------------------------------------------------------------------------
# ndl_explain
# ---------------------------------------------------------------------------

def ndl_explain(ndl_text: str) -> str:
    if not ndl_text:
        return "Empty NDL"
    if len(ndl_text.encode("utf-8")) > MAX_NDL_INPUT_BYTES:
        return f"ERROR: NDL input exceeds {MAX_NDL_INPUT_BYTES // 1024} KiB cap; refusing to parse."
    parser = NdlParser()
    text = ndl_text.strip()
    if not text:
        return "Empty NDL"

    # Try pattern → library → fragment, in order of how a user would most likely
    # paste NDL. Preserve the FIRST error (the one matching the user's likely intent)
    # rather than the last, which is what matters for diagnostics.
    first_error: Exception | None = None
    try:
        return _explain_pattern(parser.parse(text))
    except NdlSyntaxError as e:
        first_error = e
    except Exception as e:
        log.warning("ndl_explain pattern parse raised non-syntax error: %s", e)
        first_error = e
    try:
        return _explain_library(parser.parse_library(text))
    except NdlSyntaxError:
        pass
    try:
        return _explain_operation(parser.parse_fragment(text))
    except NdlSyntaxError:
        pass
    return f"Unable to parse NDL as pattern, library, or fragment.\nFirst error (pattern parse): {first_error}"


def _explain_pattern(pattern: Pattern) -> str:
    lines = [
        f"This is a pattern: {pattern.metadata.name!r} producing {pattern.metadata.ci_type!r}.",
    ]
    if pattern.identifications:
        lines.append(f"It has {len(pattern.identifications)} identification section(s).")
    if pattern.connections:
        lines.append(f"It has {len(pattern.connections)} connection section(s).")
    lines.append("")
    for idx, ident in enumerate(pattern.identifications, 1):
        lines.append(
            f"Identification {idx} ('{ident.name}') — strategy "
            f"{ident.find_process_strategy.value if ident.find_process_strategy else 'NONE'}"
        )
        for s_i, step in enumerate(ident.steps, 1):
            lines.append(f"  Step {s_i}: {_explain_step(step)}")
    return _clip("\n".join(lines))


def _explain_library(lib) -> str:
    lines = [f"Shared library '{lib.name}' (id={lib.id}). {lib.description}"]
    for s_i, step in enumerate(lib.steps, 1):
        lines.append(f"  Step {s_i}: {_explain_step(step)}")
    return _clip("\n".join(lines))


def _explain_step(step) -> str:
    if step.is_library_ref:
        return f"Expand shared library {step.referenced_library_id()}"
    if step.operation is None:
        return f"{step.name} — empty step"
    op = step.operation
    d = closures.get(op.keyword)
    if d:
        return f"{step.name}: [{op.keyword}] {d.summary}"
    return f"{step.name}: [{op.keyword}] (no registered descriptor)"


def _explain_operation(op) -> str:
    d = closures.get(op.keyword)
    if d:
        lines = [
            f"Operation: {op.keyword}  ({d.class_name})",
            f"  category: {d.category.value}",
            f"  purpose: {d.summary}",
        ]
        if d.inputs:
            lines.append(f"  inputs: {', '.join(d.inputs)}")
        if d.outputs:
            lines.append(f"  outputs: {', '.join(d.outputs)}")
        if d.failure_modes:
            lines.append("  failure modes:")
            for fm in d.failure_modes:
                lines.append(f"    - {fm}")
    else:
        lines = [f"Operation: {op.keyword}  (no registered descriptor)"]
    if op.attributes:
        lines.append("  attributes:")
        for k, v in op.attributes.items():
            lines.append(f"    {k} = {_short(v)}")
    if op.operands:
        lines.append("  operands:")
        for k, v in op.operands.items():
            lines.append(f"    {k} -> {v.keyword}")
    return _clip("\n".join(lines))


# ---------------------------------------------------------------------------
# pattern_compare
# ---------------------------------------------------------------------------

def pattern_compare(name_a: str, name_b: str, *, index, pdi) -> str:
    pa, ma = _fetch_pattern(name_a, index, pdi)
    pb, mb = _fetch_pattern(name_b, index, pdi)
    if pa is None and ma is None:
        return f"Pattern not found: {name_a!r}"
    if pb is None and mb is None:
        return f"Pattern not found: {name_b!r}"
    if pa is None or pb is None:
        na = (pa.metadata.name if pa else "") or (ma or {}).get("name", "?")
        nb = (pb.metadata.name if pb else "") or (mb or {}).get("name", "?")
        lines = [
            f"Compare (metadata-only): A='{na}'   B='{nb}'",
            "",
            f"ci_type:  A={(pa.metadata.ci_type if pa else (ma or {}).get('ci_type', ''))}"
            f"   B={(pb.metadata.ci_type if pb else (mb or {}).get('ci_type', ''))}",
            f"scope:    A={(ma or {}).get('scope', '?')}   B={(mb or {}).get('scope', '?')}",
            f"active:   A={(ma or {}).get('active', '?')}   B={(mb or {}).get('active', '?')}",
            "",
            "NDL not cached for one or both patterns — structural diff unavailable.",
            "Run scripts/export_patterns.py with PDI creds to enable full compare.",
        ]
        return _clip("\n".join(lines))

    ops_a = set(pa.operation_keywords())
    ops_b = set(pb.operation_keywords())
    vars_a = set(classify_variables(pa).keys())
    vars_b = set(classify_variables(pb).keys())

    lines = [
        f"Compare: A='{pa.metadata.name}'   B='{pb.metadata.name}'",
        "",
        f"CI types: A={pa.metadata.ci_type}   B={pb.metadata.ci_type}",
        f"OS types: A={','.join(pa.metadata.apply_to_os_types) or '-'}"
        f"   B={','.join(pb.metadata.apply_to_os_types) or '-'}",
        f"Identifications: A={len(pa.identifications)} B={len(pb.identifications)}",
        f"Connections:     A={len(pa.connections)} B={len(pb.connections)}",
        "",
        "OPERATION KEYWORDS:",
        f"  only in A: {sorted(ops_a - ops_b)}",
        f"  only in B: {sorted(ops_b - ops_a)}",
        f"  shared:    {sorted(ops_a & ops_b)}",
        "",
        "VARIABLES:",
        f"  only in A: {sorted(vars_a - vars_b)}",
        f"  only in B: {sorted(vars_b - vars_a)}",
        f"  shared:    {sorted(vars_a & vars_b)}",
    ]

    refs_a = set(pa.library_references())
    refs_b = set(pb.library_references())
    lines.append("")
    lines.append("SHARED LIBRARIES:")
    lines.append(f"  only in A: {sorted(refs_a - refs_b)}")
    lines.append(f"  only in B: {sorted(refs_b - refs_a)}")
    lines.append(f"  shared:    {sorted(refs_a & refs_b)}")

    return _clip("\n".join(lines))


# ---------------------------------------------------------------------------
# pattern_validate — Tier-1 local validation
# ---------------------------------------------------------------------------

def pattern_validate(ndl_text: str, *, verbose: bool = False, index=None) -> str:
    """Validate raw NDL text. Returns severity-ranked findings.

    `verbose=False` suppresses INFO findings (mostly unregistered closure names).
    Hard cap on input size to prevent DoS via deeply nested or huge NDL.

    When `index` is supplied AND the NDL's metadata.id matches an indexed pattern,
    the validator also loads pre-script context vars (CTX.setAttribute) and known
    library sys_ids — eliminating false read-before-write warnings on context vars.
    """
    if not ndl_text:
        return "ERROR: empty NDL"
    if len(ndl_text.encode("utf-8")) > MAX_NDL_INPUT_BYTES:
        return f"ERROR: NDL input exceeds {MAX_NDL_INPUT_BYTES // 1024} KiB cap; refusing to validate."

    from sn_patterns_mcp.validator import PatternValidator

    # Auto-detect predefined vars + known libraries from the index when provided.
    predefined_vars: set[str] = set()
    library_ids: set[str] = set()
    context_load_error: str | None = None
    if index is not None:
        try:
            from sn_patterns_mcp.ndl_parser import NdlParser, NdlSyntaxError
            from sn_patterns_mcp.prepost import analyze_prepost_bundle
            sys_id_match = None
            try:
                meta = NdlParser().parse(ndl_text).metadata
                sys_id_match = meta.id or None
            except NdlSyntaxError:
                # Pattern is unparseable — validator will emit ERROR for that anyway,
                # so we skip context lookup but don't suppress the syntax issue.
                pass
            if sys_id_match and hasattr(index, "local") and index.local is not None:
                scripts = index.local.prepost_for(sys_id_match)
                ctx = analyze_prepost_bundle(scripts)
                predefined_vars = ctx.all_predefined_vars
            if hasattr(index, "manifest"):
                library_ids = set(index.manifest.keys())
        except Exception as e:
            log.warning("pattern_validate: index context load failed: %s", e)
            context_load_error = f"{type(e).__name__}: {e}"

    result = PatternValidator(
        library_ids=library_ids or None,
        predefined_vars=predefined_vars or None,
    ).validate(ndl_text)
    findings = result.findings if verbose else [f for f in result.findings if f.severity != "INFO"]
    errors = [f for f in findings if f.severity == "ERROR"]
    warnings = [f for f in findings if f.severity == "WARN"]

    header = "VALID" if not errors else "INVALID"
    out = [f"Status: {header}", f"Errors: {len(errors)} / Warnings: {len(warnings)}"]
    if result.pattern is not None:
        out.append(f"Pattern: {result.pattern.metadata.name or '?'} (citype={result.pattern.metadata.ci_type or '-'})")
    if context_load_error:
        out.append(f"Note: index context unavailable ({context_load_error}) — refid + pre-script checks ran shallow.")
    out.append("")
    if findings:
        from sn_patterns_mcp.validator import SEVERITY_ORDER
        sorted_findings = sorted(findings, key=lambda f: (SEVERITY_ORDER[f.severity], f.code, f.location))
        counts = {sev: sum(1 for f in findings if f.severity == sev) for sev in ("ERROR", "WARN", "INFO")}
        out.append(f"Findings: {counts['ERROR']} ERROR, {counts['WARN']} WARN, {counts['INFO']} INFO")
        out.append("")
        out.extend(f.format() for f in sorted_findings)
    else:
        out.append("No findings.")
    return _clip("\n".join(out))


# ---------------------------------------------------------------------------
# pattern_create — synthesis context for new pattern authoring
# ---------------------------------------------------------------------------

def pattern_create(intent: str, *, ci_type: str | None = None, os_family: str | None = None,
                   index, chroma) -> str:
    """Return structured context for drafting a new pattern.

    The MCP client (Claude) uses the returned context to synthesize NDL.
    Output: 3 nearest-neighbor patterns by semantic search + relevant closure
    descriptors + a skeleton pattern shape. Does NOT generate NDL itself.
    """
    parts: list[str] = [
        f"Intent: {intent}",
    ]
    if ci_type:
        parts.append(f"Target CI type: {ci_type}")
    if os_family:
        parts.append(f"OS family: {os_family}")
    parts.append("")

    # 1. Nearest-neighbor patterns from Chroma
    parts.append("=== NEAREST EXISTING PATTERNS (use as templates) ===")
    hits: list[dict[str, Any]] = []
    if chroma is None:
        parts.append("(Chroma not configured — semantic search unavailable.)")
    else:
        try:
            hits = chroma.search(intent, n=3)
        except Exception as e:
            log.warning("pattern_create chroma search failed: %s", e)
            parts.append(f"(Chroma error: {type(e).__name__}: {e})")
    if not hits and chroma is not None:
        parts.append("(no neighbors found)")
    for hit in hits[:3]:
        md = hit.get("metadata") or {}
        parts.append(f"- {md.get('name','?')} [{md.get('ci_type','-')}] sys_id={hit.get('sys_id')}")
        dist = hit.get("distance")
        if isinstance(dist, (int, float)):
            parts.append(f"    distance: {dist:.3f}")
        kws = md.get("operation_kws", "")
        if kws:
            parts.append(f"    ops: {kws[:300]}")
        # Include source NDL snippet (first 1500 chars) so Claude can crib structure
        sys_id = hit.get("sys_id") or ""
        if (
            index is not None
            and sys_id
            and hasattr(index, "metadata_for")
            and hasattr(index, "has_ndl_cache")
        ):
            pat_meta = index.metadata_for(sys_id)
            if pat_meta and index.has_ndl_cache(sys_id):
                ndl_path = Path(index.root) / pat_meta.get("path", "")
                if ndl_path.exists():
                    try:
                        data = json.loads(ndl_path.read_text(encoding="utf-8"))
                        snippet = (data.get("source_ndl") or "")[:1500]
                        parts.append("    --- NDL snippet ---")
                        parts.append(snippet)
                        parts.append("    ---")
                    except (json.JSONDecodeError, OSError) as e:
                        log.warning("could not read NDL cache for %s: %s", sys_id, e)
        parts.append("")

    # 2. Relevant closure descriptors — keyword search across registry
    parts.append("=== RELEVANT CLOSURES ===")
    intent_lower = intent.lower()
    matched = []
    for kw, desc in closures.iter_descriptors():
        haystack = " ".join([kw, desc.summary, desc.category.value, " ".join(desc.inputs), " ".join(desc.outputs)]).lower()
        score = sum(1 for w in intent_lower.split() if len(w) > 3 and w in haystack)
        if score:
            matched.append((score, kw, desc))
    matched.sort(reverse=True)
    for _score, kw, desc in matched[:8]:
        parts.append(f"- {kw} ({desc.category.value}): {desc.summary}")
        if desc.inputs:
            parts.append(f"    inputs: {', '.join(desc.inputs)}")
        if desc.outputs:
            parts.append(f"    outputs: {', '.join(desc.outputs)}")

    # 3. Skeleton
    parts.append("")
    parts.append("=== SKELETON ===")
    parts.append("pattern {")
    parts.append("    metadata {")
    parts.append('        id = "<32-char hex sys_id>"')
    parts.append('        name = "<pattern name>"')
    parts.append(f'        citype = "{ci_type or "<cmdb_ci_*>"}"')
    if os_family:
        parts.append(f'        apply_to_os_families = "{os_family}"')
    parts.append("    }")
    parts.append("    identification {")
    parts.append('        name = "<identification name>"')
    parts.append("        find_process_strategy {strategy = LISTENING_PORT}")
    parts.append("        step {")
    parts.append('            name = "<what this step does>"')
    parts.append("            <closure> { ... }")
    parts.append("        }")
    parts.append("    }")
    parts.append("}")
    parts.append("")
    parts.append("After drafting, call pattern_validate(ndl_text=...) to check.")

    return _clip("\n".join(parts))


# ---------------------------------------------------------------------------
# pattern_test_compile — Tier-2 PDI compile harness
# ---------------------------------------------------------------------------

def _sandbox_name() -> str:
    """Generate a unique sandbox pattern name. Sortable + collision-resistant."""
    from sn_patterns_mcp.pdi_client import SANDBOX_PREFIX
    return f"{SANDBOX_PREFIX}{int(time.time())}_{secrets.token_hex(3)}"


def _sandbox_log_path() -> Path:
    """Where to record sandbox runs in case cleanup fails. Lives next to Chroma DB."""
    return Path.home() / ".sn_patterns_mcp" / "sandbox_runs.json"


def _record_sandbox(sys_id: str, name: str, action: str, status: str, detail: str = "") -> None:
    """Append a sandbox run to the local log so abandoned rows can be reaped later."""
    p = _sandbox_log_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    try:
        runs = json.loads(p.read_text(encoding="utf-8")) if p.exists() else []
    except (json.JSONDecodeError, OSError):
        runs = []
    runs.append({
        "ts": int(time.time()),
        "sys_id": sys_id,
        "name": name,
        "action": action,
        "status": status,
        "detail": detail[:500],
    })
    # Keep only last 200 entries
    p.write_text(json.dumps(runs[-200:], indent=2), encoding="utf-8")


def pattern_test_compile(ndl_text: str, *, pdi, cleanup: bool = True) -> str:
    """Tier-2 compile test: upload NDL to a sandbox sa_pattern row and observe accept/reject.

    Local Tier-1 validation runs first; if that fails, PDI is never contacted.
    Sandbox naming + cleanup tracking ensures we never touch real patterns.

    Returns plain text describing: local validation result, PDI outcome (accepted/rejected),
    error detail if rejected, cleanup result.
    """
    if not ndl_text:
        return "ERROR: empty NDL"
    if len(ndl_text.encode("utf-8")) > MAX_NDL_INPUT_BYTES:
        return f"ERROR: NDL input exceeds {MAX_NDL_INPUT_BYTES // 1024} KiB cap"
    if pdi is None:
        return (
            "ERROR: pattern_test_compile requires PDI credentials.\n"
            "Set SN_INSTANCE / SN_USERNAME / SN_PASSWORD in env, then re-invoke the MCP server."
        )

    # Step 1 — local validation gate. Don't bother PDI with broken NDL.
    from sn_patterns_mcp.validator import PatternValidator
    local_result = PatternValidator().validate(ndl_text)
    if local_result.errors:
        out = ["Status: LOCAL_VALIDATION_FAILED",
               f"Local validator returned {len(local_result.errors)} errors. PDI not contacted.",
               ""]
        out.extend(f.format() for f in local_result.errors)
        return _clip("\n".join(out))

    # Step 2 — synthesize a sandbox name, override the metadata.name so we don't clash.
    # We re-write the NDL with the sandbox name (preserves the original metadata.id).
    sandbox = _sandbox_name()
    parser = NdlParser()
    pattern = parser.parse(ndl_text)
    original_name = pattern.metadata.name or "(unnamed)"
    original_ci = pattern.metadata.ci_type or ""
    # Substitute the name in the NDL text. Do it via the parser's tree to be safe.
    # Simplest reliable approach: re-emit with the sandbox name via the writer.
    from sn_patterns_mcp.ndl_writer import NdlWriter
    tree = parser.parse_tree(ndl_text)
    # Mutate the metadata.name in the tree directly (positional or keyed).
    _override_metadata_name(tree, sandbox)
    sandbox_ndl = NdlWriter().write(tree)

    # Step 3 — POST to sa_pattern. On 403 (missing role), self-heal by granting
    # pattern_designer to the configured user and retry once. On 401, the password
    # is genuinely wrong — surface immediately.
    out: list[str] = [
        f"Pattern: {original_name}  (ci_type: {original_ci or '-'})",
        f"Sandbox name: {sandbox}",
        "",
        "Local validation: PASSED",
    ]
    from sn_patterns_mcp.pdi_client import PdiRejected, PdiUnavailable, SandboxViolation
    created_sys_id: str | None = None

    def _create() -> dict:
        return pdi.create_pattern(name=sandbox, ndl=sandbox_ndl, ci_type=original_ci)

    try:
        try:
            created = _create()
        except PdiUnavailable as e:
            if e.status == 403:
                # Try to self-heal: grant pattern_designer and retry once.
                log.info("pattern_test_compile: 403 on first POST — attempting role grant self-heal")
                try:
                    granted = pdi.ensure_write_permission()
                except Exception as grant_err:
                    log.warning("self-heal role grant failed: %s", grant_err)
                    raise PdiUnavailable(
                        f"PDI returned 403 and role grant also failed: {grant_err}",
                        status=403,
                    ) from grant_err
                if granted:
                    out.append(f"Self-heal: granted role(s) {granted} to PDI user, retrying compile...")
                    log.info("pattern_test_compile: granted %s, retrying", granted)
                else:
                    out.append("Self-heal: user already has required roles; 403 is genuine.")
                    raise
                created = _create()
            else:
                raise
        created_sys_id = created.get("sys_id")
        log.info("pattern_test_compile: PDI accepted sandbox=%s sys_id=%s", sandbox, created_sys_id)
        _record_sandbox(created_sys_id or "?", sandbox, "create", "accepted")
        out.append(f"PDI compile: ACCEPTED  (sys_id={created_sys_id})")
    except PdiRejected as e:
        log.info("pattern_test_compile: PDI rejected sandbox=%s status=%s", sandbox, e.status)
        out.append(f"PDI compile: REJECTED  (HTTP {e.status})")
        out.append(f"  reason: {e}")
        out.append("")
        out.append("Action: fix the NDL and re-run pattern_validate then pattern_test_compile.")
        return _clip("\n".join(out))
    except (PdiUnavailable, SandboxViolation) as e:
        out.append(f"PDI compile: ERROR  ({type(e).__name__}: {e})")
        return _clip("\n".join(out))

    # Step 4 — cleanup.
    if cleanup and created_sys_id:
        try:
            pdi.delete_pattern(created_sys_id, expected_name=sandbox)
            _record_sandbox(created_sys_id, sandbox, "delete", "cleaned")
            out.append(f"Cleanup: DELETED  (sandbox sys_id={created_sys_id} removed)")
        except Exception as e:
            log.warning("cleanup failed for sandbox=%s sys_id=%s: %s", sandbox, created_sys_id, e)
            _record_sandbox(created_sys_id, sandbox, "delete", "FAILED", str(e))
            out.append(f"Cleanup: FAILED  ({type(e).__name__}: {e})")
            out.append(f"  Sandbox row {sandbox} (sys_id={created_sys_id}) is still in PDI; manual cleanup needed.")
    elif created_sys_id:
        out.append(f"Cleanup: SKIPPED  (cleanup=False; sandbox sys_id={created_sys_id} retained for inspection)")

    return _clip("\n".join(out))


def _override_metadata_name(tree: Any, new_name: str) -> None:
    """Find pattern.metadata.name in a parsed _Block tree and replace its value with new_name."""
    from sn_patterns_mcp.ndl_parser import _Block
    if not isinstance(tree, _Block):
        return
    for key, value in tree.items:
        if key is None and isinstance(value, _Block) and value.name == "metadata":
            new_items = []
            for k, v in value.items:
                if k == "name":
                    new_items.append(("name", new_name))
                else:
                    new_items.append((k, v))
            value.items = new_items
            return


# ---------------------------------------------------------------------------
# pattern_diff_against_live — fetch PDI version, diff against local draft
# ---------------------------------------------------------------------------

def pattern_diff_against_live(name_or_sys_id: str, local_ndl: str, *, pdi) -> str:
    """Fetch the live PDI version of a pattern and diff it against the local NDL draft.

    Returns: structural diff (operation keywords, variables, refids — same shape as
    pattern_compare) PLUS a textual unified diff of the NDL source.
    Use BEFORE pushing edits to PDI to see exactly what will change.
    """
    if pdi is None:
        return (
            "ERROR: pattern_diff_against_live requires PDI credentials.\n"
            "Set SN_INSTANCE / SN_USERNAME / SN_PASSWORD in env, then re-invoke the MCP server."
        )
    if not local_ndl:
        return "ERROR: empty local_ndl"
    if len(local_ndl.encode("utf-8")) > MAX_NDL_INPUT_BYTES:
        return f"ERROR: local_ndl exceeds {MAX_NDL_INPUT_BYTES // 1024} KiB cap"

    from sn_patterns_mcp.pdi_client import PdiUnavailable
    try:
        row = pdi.get_pattern(name_or_sys_id)
    except (PdiUnavailable, ValueError) as e:
        return f"ERROR: PDI lookup failed: {type(e).__name__}: {e}"
    if row is None:
        return f"ERROR: pattern not found in PDI: {name_or_sys_id!r}"
    live_ndl = row.get("ndl") or row.get("pattern_text") or ""
    if not live_ndl:
        # Try a per-row hydration
        sys_id = row.get("sys_id")
        if sys_id:
            try:
                live_ndl = pdi.get_pattern_text(sys_id) or ""
            except (PdiUnavailable, ValueError) as e:
                return f"ERROR: PDI text fetch failed for sys_id={sys_id}: {type(e).__name__}: {e}"
    if not live_ndl:
        return f"ERROR: PDI returned a row but no NDL text for {name_or_sys_id!r}"

    parser = NdlParser()
    try:
        live_pat = parser.parse(live_ndl)
    except NdlSyntaxError as e:
        return f"ERROR: live PDI NDL is unparseable: {e}"
    try:
        local_pat = parser.parse(local_ndl)
    except NdlSyntaxError as e:
        return f"ERROR: local NDL is unparseable: {e}"

    # Structural diff (same shape as pattern_compare)
    out: list[str] = [
        f"Diff: live PDI version vs local draft of {row.get('name') or '?'!r}",
        f"  live  sys_id: {row.get('sys_id') or '-'}",
        f"  live  name:   {live_pat.metadata.name}  (citype: {live_pat.metadata.ci_type or '-'})",
        f"  local name:   {local_pat.metadata.name}  (citype: {local_pat.metadata.ci_type or '-'})",
        "",
    ]

    live_ops = set(live_pat.operation_keywords())
    local_ops = set(local_pat.operation_keywords())
    out.append("OPERATION KEYWORDS:")
    out.append(f"  added in local:   {sorted(local_ops - live_ops) or '-'}")
    out.append(f"  removed in local: {sorted(live_ops - local_ops) or '-'}")

    live_vars = set(classify_variables(live_pat).keys())
    local_vars = set(classify_variables(local_pat).keys())
    out.append("")
    out.append("VARIABLES:")
    out.append(f"  added in local:   {sorted(local_vars - live_vars) or '-'}")
    out.append(f"  removed in local: {sorted(live_vars - local_vars) or '-'}")

    live_refs = set(live_pat.library_references())
    local_refs = set(local_pat.library_references())
    out.append("")
    out.append("LIBRARY REFS:")
    out.append(f"  added in local:   {sorted(local_refs - live_refs) or '-'}")
    out.append(f"  removed in local: {sorted(live_refs - local_refs) or '-'}")

    # Step counts
    out.append("")
    out.append("STEP COUNTS:")
    out.append(f"  identifications: live={len(live_pat.identifications)}  local={len(local_pat.identifications)}")
    out.append(f"  connections:     live={len(live_pat.connections)}      local={len(local_pat.connections)}")

    # Textual diff (truncated)
    out.append("")
    out.append("TEXTUAL DIFF (live → local, first 80 lines of changes):")
    diff_iter = difflib.unified_diff(
        live_ndl.splitlines(keepends=False),
        local_ndl.splitlines(keepends=False),
        fromfile="live",
        tofile="local",
        n=2,
        lineterm="",
    )
    diff_lines = list(diff_iter)
    if not diff_lines:
        out.append("  (live and local NDL are byte-identical)")
    else:
        out.extend(diff_lines[:80])
        if len(diff_lines) > 80:
            out.append(f"... ({len(diff_lines) - 80} more diff lines truncated)")

    return _clip("\n".join(out))


# ---------------------------------------------------------------------------
# Track 3: OID / MIB intelligence
# ---------------------------------------------------------------------------

def oid_lookup(oid_or_name: str) -> str:
    """Resolve an OID by dotted-decimal or by name. Returns full descriptor +
    parent context + immediate children. Walks up the OID hierarchy to identify
    columnar instances (e.g. 1.3.6.1.2.1.2.2.1.5.3 → ifSpeed for instance 3).
    Also reports the enterprise vendor for any 1.3.6.1.4.1.* OID.
    """
    from sn_patterns_mcp import oids
    from sn_patterns_mcp.oids import _DB_PATH
    if not oid_or_name or not oid_or_name.strip():
        return "ERROR: empty input"
    db_warning = ""
    if not _DB_PATH.exists():
        db_warning = (
            f"\nWARN: OID database not found at {_DB_PATH}. "
            "Lookup will use the in-memory dict fallback (only ~1K seed entries). "
            "Run `python scripts/build_oid_index.py` to build the full 847K-entry corpus."
        )
    query = oid_or_name.strip()
    entry = oids.lookup(query)
    if entry is None:
        # Try vendor identification — even unknown OIDs in 1.3.6.1.4.1 yield a vendor
        vendor = oids.identify_vendor(query)
        if vendor is not None:
            return _clip(
                f"OID: {query}  (no exact match in registry)\n"
                f"Vendor (by enterprise prefix): {vendor.vendor}\n"
                f"  prefix: {vendor.prefix}\n"
                f"  description: {vendor.description}\n"
                f"\nThis is a vendor-private OID. The MIB defining it is not in the bundled corpus."
                + db_warning
            )
        return f"OID/name not found: {oid_or_name!r}{db_warning}"

    out: list[str] = [
        f"OID: {entry.oid}",
        f"Name: {entry.full_name}",
        f"  Syntax: {entry.syntax or '(unspecified)'}",
        f"  Access: {entry.access or '(unspecified)'}",
    ]
    if entry.is_table:
        out.append("  [TABLE — use SNMP walk, not get]")
    if entry.is_columnar:
        out.append("  [COLUMNAR — instance is appended after this OID]")
    if entry.description:
        out.append("")
        out.append(f"Description: {entry.description}")

    # Vendor (helps callers know what device class this is for)
    vendor = oids.identify_vendor(entry.oid)
    if vendor is not None:
        out.append("")
        out.append(f"Enterprise vendor: {vendor.vendor}  ({vendor.description})")

    # Parent context
    if entry.parent_oid:
        parent = oids.lookup(entry.parent_oid)
        if parent is not None:
            out.append("")
            out.append(f"Parent: {parent.full_name}  ({parent.oid})")

    # Immediate children
    children = oids.walk(entry.oid)
    if children:
        out.append("")
        out.append(f"Children ({len(children)}):")
        for c in children[:20]:
            label = "[T]" if c.is_table else ("[C]" if c.is_columnar else "   ")
            out.append(f"  {label} {c.oid}  {c.name}  ({c.syntax or '-'})")
        if len(children) > 20:
            out.append(f"  ... ({len(children) - 20} more)")

    return _clip("\n".join(out))


def oid_walk_explain(prefix_oid: str) -> str:
    """Show the structure under an OID prefix — useful for understanding what
    an SNMP walk would return.

    For a table OID (e.g. ifTable = 1.3.6.1.2.1.2.2), shows the columns. For
    a group OID (e.g. system = 1.3.6.1.2.1.1), shows the leaf objects.
    """
    from sn_patterns_mcp import oids
    if not prefix_oid or not prefix_oid.strip():
        return "ERROR: empty prefix"
    prefix = prefix_oid.strip().lstrip(".")

    root = oids.lookup(prefix)
    out: list[str] = []
    if root is not None:
        out.append(f"Prefix: {root.full_name}  ({root.oid})")
        if root.description:
            out.append(f"  {root.description[:300]}")
    else:
        out.append(f"Prefix: {prefix}  (not in registry — showing whatever children exist)")

    # All descendants, recursive
    descendants = oids.walk(prefix, recursive=True)
    if not descendants:
        out.append("\nNo children found in registry.")
        return _clip("\n".join(out))

    out.append("")
    out.append(f"Tree underneath ({len(descendants)} entries):")
    # Display compactly — show OID suffix relative to prefix
    prefix_len = len(prefix.split("."))
    for e in descendants[:60]:
        suffix_parts = e.oid.split(".")[prefix_len:]
        suffix = ".".join(suffix_parts) if suffix_parts else "(self)"
        marker = "[T]" if e.is_table else ("[C]" if e.is_columnar else "   ")
        out.append(f"  {marker} +{suffix}  {e.name}  -- {e.syntax or '-'}")
    if len(descendants) > 60:
        out.append(f"  ... ({len(descendants) - 60} more)")

    # If the prefix is a table, give the user a head start on iterating
    if root and root.is_table:
        out.append("")
        out.append(f"Iteration hint: SNMP-walk this table by GET-NEXT on {root.oid}.")
        out.append("Each row appends the index value to the column OID.")

    return _clip("\n".join(out))


def oid_search(query: str, *, limit: int = 10) -> str:
    """Natural-language search across all known OIDs.

    Two backends, tried FTS5 first then Chroma:
      1. SQLite FTS5 keyword index — empirically outperforms generic embeddings
         on technical SNMP terminology (BGP, ifSpeed, temperature sensors etc.).
         Sub-10ms across hundreds of thousands of rows.
      2. ChromaDB semantic embeddings — fallback for queries that need meaning-
         level matching FTS5 can't do.

    Use when the user's query is a description, not an OID/name. Examples:
        "interface error counters"
        "BGP peer session state"
        "CPU temperature sensor"
        "SSL certificate expiry"
    """
    if not query or not query.strip():
        return "ERROR: empty query"
    from sn_patterns_mcp import oids

    out: list[str] = [f"OID search: {query!r}"]

    # 1) FTS5 — fast + accurate on technical terms
    fts_hits = oids.fts_search(query, limit=limit)
    if fts_hits:
        out.append(f"  [backend: sqlite-fts5, {len(fts_hits)} hits]")
        out.append("")
        for e in fts_hits:
            tag = " [TABLE]" if e.is_table else (" [COLUMNAR]" if e.is_columnar else "")
            out.append(f"- {e.oid}  {e.full_name}{tag}")
            if e.description:
                out.append(f"    {e.description[:200]}")
        return _clip("\n".join(out))

    # 2) Chroma fallback — for queries with no keyword overlap
    try:
        from sn_patterns_mcp.oids.chroma import OidChromaIndex
        chroma_dir = Path.home() / ".sn_patterns_mcp" / "oids_chroma"
        if chroma_dir.exists():
            hits = OidChromaIndex(chroma_dir).search(query, n=limit)
            if hits:
                out.append(f"  [backend: chroma-semantic, {len(hits)} hits  (FTS5 returned 0)]")
                out.append("")
                for h in hits:
                    md = h.get("metadata") or {}
                    dist = h.get("distance")
                    score = f"  (distance={dist:.3f})" if isinstance(dist, (int, float)) else ""
                    tag = " [TABLE]" if md.get("is_table") else (" [COLUMNAR]" if md.get("is_columnar") else "")
                    out.append(f"- {h['oid']}  {md.get('mib','?')}::{md.get('name','?')}{tag}{score}")
                    doc = (h.get("document") or "").replace("\n", " ")[:200]
                    if doc:
                        out.append(f"    {doc}")
                return _clip("\n".join(out))
    except Exception as e:
        log.warning("oid_search chroma fallback failed: %s", e)

    return f"No OID matches for {query!r}"


def pattern_snmp_audit(name_or_sys_id: str, *, index, pdi) -> str:
    """For every run_snmp_* operation in a pattern, resolve the OID and report
    what it queries. Surfaces vendor lock-in (vendor-private OIDs) and OID
    typos (unresolved OIDs not in any known MIB).
    """
    from sn_patterns_mcp import oids
    pattern, meta = _fetch_pattern(name_or_sys_id, index, pdi)
    if pattern is None:
        return f"Pattern not found: {name_or_sys_id!r}"

    name = pattern.metadata.name or "(unnamed)"
    sys_id = pattern.metadata.id or (meta or {}).get("sys_id", "")
    out: list[str] = [f"SNMP audit: {name}  (sys_id={sys_id})", ""]

    snmp_ops: list[tuple[str, str, str, str]] = []  # (step_name, op_keyword, oid, src)
    for step in pattern.all_steps():
        if step.operation is None:
            continue
        for op in _iter_ops(step.operation):
            if not op.keyword.startswith("run_snmp"):
                continue
            # OID is typically in attributes['oid'] or operands['oid'].attributes['value']
            oid = op.attributes.get("oid") or ""
            if not oid:
                oid_op = op.operands.get("oid")
                if oid_op is not None:
                    oid = oid_op.attributes.get("value", "") or ""
                    if not oid and oid_op.positional_args:
                        oid = str(oid_op.positional_args[0])
            if not oid and op.positional_args:
                oid = str(op.positional_args[0])
            snmp_ops.append((step.name or "(unnamed step)", op.keyword, str(oid), step.name or ""))

    if not snmp_ops:
        out.append("No SNMP operations in this pattern.")
        return _clip("\n".join(out))

    out.append(f"SNMP operations: {len(snmp_ops)}")
    out.append("")
    unresolved: list[tuple[str, str]] = []
    vendor_locked: dict[str, list[str]] = {}
    for step_name, op_kw, oid, _src in snmp_ops:
        if not oid or "$" in oid:
            out.append(f"- step '{step_name}': {op_kw}  oid={oid or '(empty)'}  [DYNAMIC — variable substitution at runtime]")
            continue
        entry = oids.lookup(oid)
        vendor = oids.identify_vendor(oid)
        if entry is not None:
            tag = " [TABLE]" if entry.is_table else (" [COLUMNAR]" if entry.is_columnar else "")
            out.append(f"- step '{step_name}': {op_kw}  oid={oid}{tag}")
            out.append(f"    → {entry.full_name}  ({entry.syntax or '-'})")
            if entry.description:
                out.append(f"      {entry.description[:200]}")
            if vendor is not None:
                vendor_locked.setdefault(vendor.vendor, []).append(step_name)
        elif vendor is not None:
            out.append(f"- step '{step_name}': {op_kw}  oid={oid}  [{vendor.vendor}-private, MIB not in registry]")
            vendor_locked.setdefault(vendor.vendor, []).append(step_name)
        else:
            out.append(f"- step '{step_name}': {op_kw}  oid={oid}  [UNRESOLVED — not in any known MIB]")
            unresolved.append((step_name, oid))

    out.append("")
    if vendor_locked:
        out.append("VENDOR DEPENDENCIES:")
        for v, steps in vendor_locked.items():
            out.append(f"  - {v}: {len(steps)} step(s)")
        out.append("  → This pattern is vendor-locked. It will only work against these device families.")
    if unresolved:
        out.append("")
        out.append("UNRESOLVED OIDs:")
        for step_name, oid in unresolved:
            out.append(f"  - {oid}  (in step '{step_name}') — typo, custom MIB, or missing from corpus")
    if not vendor_locked and not unresolved:
        out.append("All OIDs resolve to standard IETF MIBs — pattern is portable across vendors.")

    return _clip("\n".join(out))


# ---------------------------------------------------------------------------
# pattern_lineage — full graph: libraries, extensions, classifiers, prepost
# ---------------------------------------------------------------------------

def pattern_lineage(name_or_sys_id: str, *, index, pdi) -> str:
    """Trace the complete dependency graph around a pattern.

    Shows:
      - Identification + connection sections (steps + targets)
      - Shared libraries this pattern references via `refid` (recursive — also
        shows libraries-of-libraries up to depth 3)
      - Extensions that graft onto this pattern
      - Classifiers that route discovery to this pattern
      - Pre-scripts that inject context variables (with names of vars defined)
      - Post-scripts that run after
      - Variable provenance: where every variable the pattern reads comes from
        (find_process_strategy, pre-script, set_attr in earlier step, etc.)

    This is the "connect the dots" view for understanding a pattern in full.
    """
    pattern, meta = _fetch_pattern(name_or_sys_id, index, pdi)
    if pattern is None and meta is None:
        return f"Pattern not found: {name_or_sys_id!r}"
    sys_id = (pattern.metadata.id if pattern else "") or (meta or {}).get("sys_id", "")
    name = (pattern.metadata.name if pattern else "") or (meta or {}).get("name", "?")

    out: list[str] = [f"Lineage: {name}  (sys_id={sys_id})", ""]

    # 1. Sections summary
    if pattern is not None:
        out.append("SECTIONS:")
        out.append(f"  {len(pattern.identifications)} identification section(s)")
        out.append(f"  {len(pattern.connections)} connection section(s)")
        out.append(f"  {len(pattern.extensions)} extension section(s) (built-in)")
    else:
        out.append("SECTIONS: NDL not cached; rebuild index for full breakdown.")
    out.append("")

    # 2. Library references (recursive)
    if pattern is not None:
        refs = pattern.library_references()
        out.append(f"SHARED LIBRARIES REFERENCED ({len(refs)}):")
        if not refs:
            out.append("  (none — this pattern is self-contained)")
        else:
            seen: set[str] = set()
            _walk_lib_refs(refs, index, pdi, seen, out, depth=0, max_depth=3)
    out.append("")

    # 3. Extensions targeting this pattern (sa_pattern_extension rows)
    extensions: list[dict[str, Any]] = []
    if index is not None and index.local is not None and sys_id:
        extensions = index.local.extensions_for(sys_id)
    out.append(f"EXTENSIONS TARGETING THIS PATTERN ({len(extensions)}):")
    for ext in extensions[:15]:
        ext_name = ext.get("name") or ext.get("sys_id") or "?"
        out.append(f"  - {ext_name}  sys_id={ext.get('sys_id', '')}")
    if len(extensions) > 15:
        out.append(f"  ... ({len(extensions) - 15} more)")
    out.append("")

    # 4. Classifiers routing to this pattern
    classifiers: list[dict[str, Any]] = []
    classifier_source = "none"
    if pdi is not None and sys_id:
        try:
            classifiers = pdi.get_classifiers_for_pattern(sys_id)
            classifier_source = "pdi"
        except Exception:
            pass
    if not classifiers and index is not None and sys_id:
        classifiers = _local_classifiers_for(index, sys_id, name)
        if classifiers:
            classifier_source = "local-heuristic"
    out.append(f"CLASSIFIERS ROUTING TO THIS PATTERN ({len(classifiers)}, source: {classifier_source}):")
    for c in classifiers[:10]:
        out.append(f"  - {c.get('name') or c.get('sys_id')}  table={c.get('table', c.get('_source_table', '?'))}")
    out.append("")

    # 5. Pre/post scripts + variable provenance
    scripts: list[dict[str, Any]] = []
    if pdi is not None and sys_id:
        try:
            scripts = pdi.get_prepost_scripts(sys_id)
        except Exception:
            pass
    if not scripts and index is not None and index.local is not None and sys_id:
        scripts = index.local.prepost_for(sys_id)
    from sn_patterns_mcp.prepost import analyze_prepost_bundle
    ctx = analyze_prepost_bundle(scripts)

    pre_count = len(ctx.pre_scripts)
    post_count = len(ctx.post_scripts)
    out.append(f"PRE/POST SCRIPTS: {pre_count} pre, {post_count} post")
    if ctx.all_predefined_vars:
        out.append(f"  Variables injected by pre-scripts: {sorted(ctx.all_predefined_vars)}")
    if ctx.all_read_vars:
        out.append(f"  Variables read by scripts:          {sorted(ctx.all_read_vars)}")
    # Report scripts with content
    for i, s in enumerate(ctx.pre_scripts[:5], 1):
        if s.has_javascript:
            out.append(f"  pre[{i}]: {s.line_count} lines; sets={list(s.sets)} reads={list(s.reads)}")
    for i, s in enumerate(ctx.post_scripts[:5], 1):
        if s.has_javascript:
            out.append(f"  post[{i}]: {s.line_count} lines; sets={list(s.sets)} reads={list(s.reads)}")
    out.append("")

    # 6. Variable provenance summary (only when NDL is parsed)
    if pattern is not None:
        from sn_patterns_mcp.validator import (
            _DISCOVERY_CONTEXT_VARS,
            _PROCESS_VARS,
            _vars_read,
            _vars_written,
        )
        all_reads: set[str] = set()
        all_writes: set[str] = set()
        for step in pattern.all_steps():
            if step.operation is None:
                continue
            all_reads |= _vars_read(step.operation)
            all_writes |= _vars_written(step.operation)
        out.append("VARIABLE PROVENANCE:")
        provenance: dict[str, str] = {}
        for v in sorted(all_reads):
            base = v.split(".")[0].split("[")[0]
            if v in _DISCOVERY_CONTEXT_VARS or base == "computer_system" or base == "entry_point":
                provenance[v] = "discovery context (always available)"
            elif v in _PROCESS_VARS or base == "process":
                provenance[v] = "process scope (find_process_strategy)"
            elif v in ctx.all_predefined_vars:
                provenance[v] = "pre-script CTX.setAttribute"
            elif v in all_writes or base in {w.split(".")[0] for w in all_writes}:
                provenance[v] = "in-pattern (set_attr / runcmd_to_var / etc.)"
            else:
                provenance[v] = "UNKNOWN — possible read-before-write"
        for v, src in list(provenance.items())[:30]:
            tag = " [WARN]" if "UNKNOWN" in src else ""
            out.append(f"  ${v:30s} <- {src}{tag}")
        if len(provenance) > 30:
            out.append(f"  ... ({len(provenance) - 30} more variables)")

    return _clip("\n".join(out))


def pattern_data_sources(name_or_sys_id: str, *, index, pdi) -> str:  # noqa: PLR0912 — bucket dispatch
    """For a pattern, list every external data point it touches and what it ingests from each.

    Walks every operation in the pattern and:
      - For run_wmi_query_to_var: extracts the WMI class + namespace + selected fields,
        cross-references with sn_patterns_mcp.data_sources Windows catalog.
      - For runcmd_to_var: extracts the command, classifies it (Linux shell, F5 tmsh, Cisco CLI,
        Windows powershell/cmd) and matches against the data-source catalog.
      - For find_registry_val_to_var: shows the registry hive + key path.
      - For run_snmp_to_var: resolves the OID to MIB::name + vendor (via OID registry).
      - For parse_*_file_to_var: shows the file path being read.
      - For http_invoke: shows the URL/endpoint path.

    Output is grouped by access method so an agent can see at a glance: "this pattern
    runs 4 WMI queries, 2 PowerShell cmdlets, 6 SNMP gets, parses 3 files."
    """
    pattern, meta = _fetch_pattern(name_or_sys_id, index, pdi)
    if pattern is None:
        if meta:
            return (
                f"Pattern not found: {name_or_sys_id!r} (metadata cached but NDL not — "
                f"run scripts/export_patterns.py with PDI creds to hydrate)"
            )
        return f"Pattern not found: {name_or_sys_id!r}"

    name = pattern.metadata.name or "(unnamed)"
    ci_type = pattern.metadata.ci_type or "(unknown)"
    out: list[str] = [f"Pattern: {name}", f"  ci_type: {ci_type}", ""]

    # Group by access method
    buckets: dict[str, list[str]] = {
        "WMI queries": [],
        "PowerShell / shell commands": [],
        "Registry reads": [],
        "SNMP gets / walks": [],
        "File parses": [],
        "HTTP / REST calls": [],
        "LDAP queries": [],
        "Other": [],
    }

    from sn_patterns_mcp import oids as _oid_pkg

    for step in pattern.all_steps():
        if step.operation is None:
            continue
        for op in _iter_ops(step.operation):
            kw = op.keyword
            step_name = step.name or "(unnamed)"

            if kw == "run_wmi_query_to_var":
                wql = (
                    op.attributes.get("query")
                    or _operand_value(op, "query")
                    or "(query not literal)"
                )
                ns = op.attributes.get("namespace") or "root\\cimv2"
                buckets["WMI queries"].append(
                    f"  - step '{step_name}': namespace={ns}\n      WQL: {_short(wql)}"
                )

            elif kw == "runcmd_to_var":
                cmd = (
                    op.attributes.get("cmd")
                    or op.attributes.get("command")
                    or _operand_value(op, "cmd")
                    or _operand_value(op, "command")
                    or "(command not literal)"
                )
                family = _classify_command(str(cmd))
                buckets["PowerShell / shell commands"].append(
                    f"  - step '{step_name}'  [{family}]\n      cmd: {_short(cmd)}"
                )

            elif kw == "find_registry_val_to_var":
                hive = op.attributes.get("hive", "")
                key = op.attributes.get("keyPath") or op.attributes.get("key", "")
                val = op.attributes.get("valueName", "")
                buckets["Registry reads"].append(
                    f"  - step '{step_name}': {hive}\\{key}  ({val})"
                )

            elif kw.startswith("run_snmp"):
                oid = (
                    op.attributes.get("oid")
                    or _operand_value(op, "oid")
                    or "(oid not literal)"
                )
                resolved = ""
                if isinstance(oid, str) and "$" not in oid:
                    e = _oid_pkg.lookup(oid)
                    if e:
                        resolved = f"  → {e.full_name}"
                    else:
                        v = _oid_pkg.identify_vendor(oid)
                        if v:
                            resolved = f"  → ({v.vendor}-private)"
                buckets["SNMP gets / walks"].append(f"  - step '{step_name}': {oid}{resolved}")

            elif kw in ("parse_file", "parse_text_file_to_var", "parse_xml_file_to_var",
                        "parse_property_file_to_var", "parse_ini_file_to_var"):
                path = op.attributes.get("filePath") or op.attributes.get("file") or "(path not literal)"
                buckets["File parses"].append(f"  - step '{step_name}'  [{kw}]\n      path: {_short(path)}")

            elif kw == "http_invoke":
                url = op.attributes.get("url") or _operand_value(op, "url") or "(url not literal)"
                method = op.attributes.get("method", "GET")
                buckets["HTTP / REST calls"].append(f"  - step '{step_name}': {method} {_short(url)}")

            elif kw == "ldap_query":
                dn = op.attributes.get("baseDN") or op.attributes.get("base", "(dn not literal)")
                filt = op.attributes.get("filter", "")
                buckets["LDAP queries"].append(f"  - step '{step_name}': base={dn} filter={_short(filt)}")

            elif kw == "put_file":
                fname = op.attributes.get("file", "?")
                buckets["Other"].append(f"  - step '{step_name}': put_file {fname} (uploads MID-side file to target)")

    # Render buckets that have content
    any_content = False
    for bucket, items in buckets.items():
        if not items:
            continue
        any_content = True
        out.append(f"{bucket} ({len(items)}):")
        for line in items[:15]:
            out.append(line)
        if len(items) > 15:
            out.append(f"  ... ({len(items) - 15} more)")
        out.append("")

    if not any_content:
        out.append("(No external data sources detected — pattern is purely transformational.)")

    # Cross-reference to the data-source catalog when CI type implies a target
    target_hint = _target_hint_for_ci(ci_type)
    if target_hint:
        from sn_patterns_mcp import data_sources as _ds
        catalog = _ds.for_target(target_hint)
        if catalog:
            out.append(f"Reference data-source catalog for '{target_hint}': {len(catalog)} known data points")
            out.append(f"  (call pattern_data_sources_lookup with target='{target_hint}' to enumerate all)")

    return _clip("\n".join(out))


def pattern_data_sources_lookup(target: str | None = None, query: str | None = None) -> str:
    """Browse the data-source knowledge base.

    `target` filters by family: 'windows', 'linux', 'f5', 'cisco-ios'.
    `query` searches the catalog by name / description / example.
    Pass both to scope a search to one target. Pass neither and you get an error.
    """
    from sn_patterns_mcp import data_sources as _ds
    target_norm = (target or "").strip().lower() or None
    query_norm = (query or "").strip() or None
    if not target_norm and not query_norm:
        return ("ERROR: provide either target=<windows|linux|f5|cisco-ios|esxi> "
                "or query=<keyword> (or both). Example: target='windows' or query='SSL certificate'.")

    # Search path — query is provided (with or without target)
    if query_norm:
        hits = _ds.lookup(query_norm, target=target_norm)
        scope = f"target={target_norm}" if target_norm else "target=any"
        out = [f"Data-source search: query={query_norm!r}, {scope}"]
        if not hits:
            out.append(f"  (no matches in {len(list(_ds.REGISTRY.iter_all()))}-entry catalog)")
            if target_norm and not _ds.for_target(target_norm):
                out.append(f"  Note: target {target_norm!r} has no entries — known: windows, linux, f5, cisco-ios")
        for dp in hits[:20]:
            out.append("")
            out.append(f"- [{dp.target}] {dp.name}  via {dp.access_method} -> {dp.closure}")
            out.append(f"    {dp.description}")
            if dp.typical_ci:
                out.append(f"    typical CI: {dp.typical_ci}")
            if dp.example_query:
                out.append(f"    example: {dp.example_query[:160]}")
        return _clip("\n".join(out))

    # Browse path — target only
    hits = _ds.for_target(target_norm)
    if not hits:
        known = sorted({dp.target for dp in _ds.REGISTRY.iter_all()})
        return (f"ERROR: target {target_norm!r} has no entries in the catalog. "
                f"Known targets: {', '.join(known) or '(none)'}.")
    out = [f"Data sources for target={target_norm}:  {len(hits)} known data points"]
    for dp in hits:
        out.append(f"  - {dp.name}  ({dp.access_method})  -> {dp.closure}")
    return _clip("\n".join(out))


# ---------------------------------------------------------------------------
# emulator_* — Tier-3 target-emulator sidecar contract
# ---------------------------------------------------------------------------

def emulator_catalog(target: str | None = None, query: str | None = None) -> str:
    """Browse the target-emulator catalog.

    This is the discovery surface for a future sidecar/helper MCP whose only job
    is target emulation. The output is structured JSON so an agent can pick an
    exact target profile and hand it to an emulator runner.
    """
    from sn_patterns_mcp import emulator

    payload = emulator.catalog(target=target, query=query)
    if target and not payload["matches"]:
        known = ", ".join(payload["known_targets"])
        return f"ERROR: target {target!r} is not in the emulator catalog. Known targets: {known}."
    return _clip(emulator.dumps(payload))


def emulator_blueprint(
    *,
    target: str | None = None,
    name_or_sys_id: str | None = None,
    ndl: str | None = None,
    oids: list[str] | None = None,
    index=None,
    pdi=None,
) -> str:
    """Generate a deterministic sidecar emulator blueprint.

    Provide either a known pattern (`name_or_sys_id`), raw `ndl`, an explicit
    `target`, or one or more SNMP `oids`. Pattern inputs produce the highest
    fidelity output because the blueprint lists the exact WMI, command, registry,
    SNMP, file, HTTP, and LDAP fixtures the emulator must serve.
    """
    from sn_patterns_mcp import emulator

    profile = emulator.resolve_profile(target) if target else None
    if target and profile is None:
        known = ", ".join(emulator.known_targets())
        return f"ERROR: target {target!r} is not in the emulator catalog. Known targets: {known}."

    pattern = None
    pattern_name = ""
    if ndl and ndl.strip():
        if len(ndl.encode("utf-8")) > MAX_NDL_INPUT_BYTES:
            return f"ERROR: ndl exceeds {MAX_NDL_INPUT_BYTES} bytes"
        try:
            pattern = NdlParser().parse(ndl)
        except NdlSyntaxError as e:
            return f"ERROR: NDL failed to parse: {e}"
        pattern_name = pattern.metadata.name or "(inline NDL)"
    elif name_or_sys_id and name_or_sys_id.strip():
        pattern, meta = _fetch_pattern(name_or_sys_id, index, pdi)
        if pattern is None:
            if meta:
                return (
                    f"ERROR: pattern {name_or_sys_id!r} has metadata but no cached NDL; "
                    "hydrate the index or pass ndl=<raw pattern text>."
                )
            return f"ERROR: pattern not found: {name_or_sys_id!r}"
        pattern_name = pattern.metadata.name or (meta or {}).get("name", "") or name_or_sys_id

    if pattern is None and profile is None and not oids:
        return "ERROR: provide target=<known target>, name_or_sys_id=<pattern>, ndl=<raw NDL>, or oids=[...]."

    payload = emulator.blueprint(
        target=target,
        pattern=pattern,
        pattern_name=pattern_name,
        requested_oids=oids or [],
    )
    return _clip(emulator.dumps(payload))


def _operand_value(op, key: str) -> str:
    """Pull a literal string out of an operand (e.g. cmd -> concat { 'literal' }).

    Returns '' if the value isn't a simple literal.
    """
    sub = op.operands.get(key)
    if sub is None:
        return ""
    # Direct literal value attribute
    v = sub.attributes.get("value")
    if isinstance(v, str):
        return v
    # Single positional literal
    if sub.positional_args and isinstance(sub.positional_args[0], str):
        return sub.positional_args[0]
    return ""


def _classify_command(cmd: str) -> str:
    """Heuristic: classify a runcmd_to_var command string into its target family."""
    c = cmd.lower()
    if c.startswith("powershell") or "get-" in c or "select-object" in c:
        return "Windows PowerShell"
    if c.startswith("tmsh ") or " tmsh " in c:
        return "F5 tmsh"
    if c.startswith("show ") or c.startswith("show\t"):
        return "Cisco CLI"
    if c.startswith(("cat ", "ls ", "ps ", "df ", "ip ", "ss ", "uname", "rpm ", "dpkg", "lsblk", "dmidecode", "systemctl", "/proc")):
        return "Linux shell"
    if c.startswith(("ipconfig", "tasklist", "netstat", "systeminfo", "wmic", "reg ")):
        return "Windows cmd"
    if "esxcli" in c or "vim-cmd" in c:
        return "VMware ESXi"
    return "shell (unclassified)"


def _target_hint_for_ci(ci_type: str) -> str | None:
    """Best-effort: map CI type → data-source target family."""
    c = ci_type.lower()
    if "win" in c:
        return "windows"
    if "linux" in c or "unix" in c or "redhat" in c or "ubuntu" in c:
        return "linux"
    if "lb_" in c or "f5" in c or "bigip" in c:
        return "f5"
    if "cisco" in c or "ios_router" in c or "ios_switch" in c:
        return "cisco-ios"
    if "esxi" in c or "vmware" in c:
        return "esxi"
    return None


def _walk_lib_refs(refs: list[str], index, pdi, seen: set[str], out: list[str],
                   depth: int, max_depth: int) -> None:
    """Recursively expand library references up to max_depth."""
    indent = "  " * (depth + 1)
    for ref in refs:
        if ref in seen:
            out.append(f"{indent}- {ref}  (already shown)")
            continue
        seen.add(ref)
        # Resolve library name + recurse
        lib_name = _resolve_library_name(ref, index, pdi)
        out.append(f"{indent}- {ref}  ({lib_name or '?'})")
        if depth >= max_depth:
            continue
        # Get the library's own NDL to recurse
        try:
            lib_pattern = index.get(ref) if index is not None else None
        except Exception:
            lib_pattern = None
        if lib_pattern is not None:
            sub_refs = lib_pattern.library_references()
            if sub_refs:
                _walk_lib_refs(sub_refs, index, pdi, seen, out, depth + 1, max_depth)


def _looks_like_sys_id(s: str) -> bool:
    """True if `s` is exactly 32 hex characters — the ServiceNow sys_id shape."""
    if not s or len(s) != 32:
        return False
    return all(c in "0123456789abcdefABCDEF" for c in s)


# ---------------------------------------------------------------------------
# pattern_ingest_ndl — paste a community / forum pattern for this session
# ---------------------------------------------------------------------------

def pattern_ingest_ndl(
    name: str,
    ndl: str,
    *,
    index,
    ci_type: str = "",
    description: str = "",
) -> str:
    """Add a pattern to the in-memory index for this session.

    The new entry is flagged not_authoritative=true so downstream tools and the
    agent can distinguish it from PDI-fetched patterns. Enables the draft
    harness (pattern_open_draft + draft_*) against arbitrary NDL the user pastes.

    The session-scoped entry survives only until server restart; nothing is
    written to disk.
    """
    if index is None:
        return "ERROR: pattern_ingest_ndl requires a PatternIndex (server not initialized)"
    if not name or not name.strip():
        return "ERROR: name is required"
    if not ndl or not ndl.strip():
        return "ERROR: ndl text is required"
    if len(ndl.encode("utf-8")) > MAX_NDL_INPUT_BYTES:
        return f"ERROR: ndl exceeds {MAX_NDL_INPUT_BYTES} bytes"

    # Parse — pattern OR library; either is valid.
    parser = NdlParser()
    try:
        pattern = parser.parse(ndl)
    except NdlSyntaxError as e:
        return f"ERROR: NDL failed to parse: {e}"
    except Exception as e:
        return f"ERROR: ingest crashed parsing NDL: {e}"

    # Resolve sys_id. Prefer the NDL metadata.id when it's a real 32-char hex
    # (so callers using the original sys_id can find the entry). Otherwise mint
    # one — the original metadata.id is preserved on the Pattern object itself.
    metadata_id = (pattern.metadata.id or "").strip()
    sys_id = ""
    if _looks_like_sys_id(metadata_id):
        existing = index.manifest.get(metadata_id)
        if existing and not existing.get("not_authoritative", False):
            sys_id = secrets.token_hex(16)
            log.info(
                "ingest: NDL metadata.id %s collides with authoritative entry; minting %s instead",
                metadata_id, sys_id,
            )
        else:
            sys_id = metadata_id
    else:
        sys_id = secrets.token_hex(16)

    final_name = name.strip()
    # If the manifest already has a different entry with this name (from PDI),
    # rename the ingest with a "(ingested)" suffix to keep both reachable.
    other_sys_id = index._by_name.get(final_name.lower())  # type: ignore[attr-defined]
    if other_sys_id and other_sys_id != sys_id:
        other_entry = index.manifest.get(other_sys_id, {})
        if not other_entry.get("not_authoritative", False):
            final_name = f"{final_name} (ingested)"

    entry = index.add_in_memory(
        sys_id=sys_id, name=final_name, pattern=pattern,
        ci_type=ci_type or pattern.metadata.ci_type or "",
        description=description or pattern.metadata.description or "",
    )
    payload = {
        "ok": True,
        "sys_id": sys_id,
        "name": final_name,
        "ci_type": entry.get("ci_type", ""),
        "operation_count": len(entry.get("operation_kws", [])),
        "not_authoritative": True,
        "note": (
            "Session-scoped; survives until server restart. Use the returned sys_id "
            "with pattern_open_draft, pattern_analyze, etc. The 'not_authoritative' "
            "flag distinguishes it from PDI-fetched patterns."
        ),
    }
    return _clip(json.dumps(payload, indent=2))


__all__ = [
    "pattern_analyze",
    "pattern_resolve",
    "pattern_debug",
    "pattern_search",
    "ndl_explain",
    "pattern_compare",
    "pattern_validate",
    "pattern_create",
    "pattern_test_compile",
    "pattern_diff_against_live",
    "oid_lookup",
    "oid_walk_explain",
    "oid_search",
    "pattern_snmp_audit",
    "pattern_lineage",
    "pattern_data_sources",
    "pattern_data_sources_lookup",
    "emulator_catalog",
    "emulator_blueprint",
    "pattern_ingest_ndl",
    "MAX_CHARS",
]
