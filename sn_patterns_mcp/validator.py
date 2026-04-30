"""Tier-1 pattern validation — local checks that don't need PDI.

Severity levels:
    ERROR   — pattern won't parse / will be rejected by ServiceNow
    WARN    — likely bug at runtime (undefined var, unknown closure, missing refid)
    INFO    — style / portability hint
"""
from __future__ import annotations

import logging
import re
from collections.abc import Iterator
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from sn_patterns_mcp.closures import registry as closure_registry
from sn_patterns_mcp.ndl_parser import NdlParser, NdlSyntaxError, blocks_equivalent
from sn_patterns_mcp.ndl_writer import NdlWriter
from sn_patterns_mcp.pattern_model import Operation, Pattern, Step

log = logging.getLogger(__name__)


class Severity(str, Enum):
    """Finding severity. Inherits from str so existing str comparisons keep working."""
    ERROR = "ERROR"
    WARN = "WARN"
    INFO = "INFO"


SEVERITY_ORDER: dict[str, int] = {Severity.ERROR: 0, Severity.WARN: 1, Severity.INFO: 2}
_VALID_SEVERITIES: frozenset[str] = frozenset(s.value for s in Severity)


@dataclass(frozen=True)
class Finding:
    severity: str
    code: str
    message: str
    location: str = ""

    def __post_init__(self) -> None:
        if self.severity not in _VALID_SEVERITIES:
            raise ValueError(f"severity must be one of {sorted(_VALID_SEVERITIES)}, got {self.severity!r}")

    def format(self) -> str:
        loc = f" [{self.location}]" if self.location else ""
        return f"{self.severity:5s}  {self.code:24s}  {self.message}{loc}"


@dataclass
class ValidationResult:
    pattern: Pattern | None
    findings: list[Finding] = field(default_factory=list)

    @property
    def errors(self) -> list[Finding]:
        return [f for f in self.findings if f.severity == "ERROR"]

    @property
    def warnings(self) -> list[Finding]:
        return [f for f in self.findings if f.severity == "WARN"]

    @property
    def is_valid(self) -> bool:
        return not self.errors

    def format(self) -> str:
        if not self.findings:
            return "VALID — no findings."
        sorted_findings = sorted(self.findings, key=lambda f: (SEVERITY_ORDER[f.severity], f.code, f.location))
        out = [f.format() for f in sorted_findings]
        counts = {sev: sum(1 for f in self.findings if f.severity == sev) for sev in ("ERROR", "WARN", "INFO")}
        summary = f"Findings: {counts['ERROR']} ERROR, {counts['WARN']} WARN, {counts['INFO']} INFO"
        return summary + "\n\n" + "\n".join(out)


class PatternValidator:
    """Tier-1 validator. Does not call PDI."""

    def __init__(
        self,
        library_ids: set[str] | None = None,
        predefined_vars: set[str] | None = None,
    ) -> None:
        # If provided, refid checks resolve against this set (lowercased sys_ids).
        self._library_ids = {x.lower() for x in (library_ids or set())}
        # Variables defined by pre-scripts (CTX.setAttribute) — suppress
        # read-before-write warnings on these. Pass via index.local.prepost_for(sys_id).
        self._predefined_vars = set(predefined_vars or set())

    def validate(self, ndl_text: str) -> ValidationResult:
        result = ValidationResult(pattern=None)

        # 1. Syntax
        try:
            parser = NdlParser()
            tree = parser.parse_tree(ndl_text)
        except NdlSyntaxError as e:
            result.findings.append(Finding("ERROR", "syntax", str(e)))
            return result

        # 2. Roundtrip (parser/writer agreement — catches dialect drift)
        try:
            out = NdlWriter().write(tree)
            tree2 = parser.parse_tree(out)
            if not blocks_equivalent(tree, tree2):
                result.findings.append(Finding(
                    "ERROR", "roundtrip",
                    "Parser/writer disagree on this NDL — likely a parser or writer bug.",
                ))
        except NdlSyntaxError as e:
            result.findings.append(Finding("ERROR", "roundtrip", f"{type(e).__name__}: {e}"))
        except Exception as e:
            log.exception("validator roundtrip crashed (validator bug, not user NDL)")
            result.findings.append(Finding(
                "ERROR", "validator-bug",
                f"roundtrip check raised {type(e).__name__}: {e} — please report.",
            ))

        # 3. Build typed Pattern (re-parse — gives us steps/ops to walk)
        try:
            pattern = parser.parse(ndl_text)
        except NdlSyntaxError as e:
            result.findings.append(Finding("ERROR", "build", f"{type(e).__name__}: {e}"))
            return result
        except Exception as e:
            log.exception("validator build crashed (validator bug, not user NDL)")
            result.findings.append(Finding(
                "ERROR", "validator-bug",
                f"typed-model build raised {type(e).__name__}: {e} — please report.",
            ))
            return result
        result.pattern = pattern

        # 4. Metadata sanity
        if not pattern.metadata.id:
            result.findings.append(Finding("ERROR", "metadata.id", "metadata.id is required."))
        if not pattern.metadata.name:
            result.findings.append(Finding("WARN", "metadata.name", "metadata.name is empty."))
        if not pattern.metadata.ci_type and not pattern.metadata.extra.get("_is_library"):
            result.findings.append(Finding("WARN", "metadata.citype", "metadata.citype is empty (non-library pattern)."))

        # 5. Per-step checks
        for section_kind, section_idx, step_idx, step in self._iter_steps(pattern):
            self._check_step(result, section_kind, section_idx, step_idx, step)

        # 6. Variable ordering (read before write)
        self._check_variable_ordering(result, pattern)

        return result

    # ------------------------------------------------------------------

    def _iter_steps(self, pattern: Pattern) -> Iterator[tuple[str, int, int, Step]]:
        for i, sec in enumerate(pattern.identifications):
            for j, step in enumerate(sec.steps):
                yield "identification", i, j, step
        for i, sec in enumerate(pattern.connections):
            for j, step in enumerate(sec.steps):
                yield "connection", i, j, step
        for i, sec in enumerate(pattern.extensions):
            for j, step in enumerate(sec.steps):
                yield "extension", i, j, step

    def _check_step(self, result: ValidationResult, kind: str, sec_idx: int, step_idx: int, step: Step) -> None:
        loc = f"{kind}[{sec_idx}].step[{step_idx}] '{step.name or ''}'"
        if not step.name:
            result.findings.append(Finding("INFO", "step.name", "Step has no name (hurts log readability).", loc))

        # refid must resolve when we have a library set
        if step.library_ref and self._library_ids:
            if step.library_ref.lower() not in self._library_ids:
                result.findings.append(Finding(
                    "WARN", "refid.unresolved",
                    f"refid '{step.library_ref}' does not match any known library sys_id.", loc,
                ))

        # walk operation tree
        if step.operation is not None:
            self._walk_op(result, step.operation, loc)
        if step.precondition is not None:
            self._walk_op(result, step.precondition, loc + " (precondition)")

    def _walk_op(self, result: ValidationResult, op: Operation, loc: str) -> None:
        descriptor = closure_registry.get(op.keyword)
        if descriptor is None:
            result.findings.append(Finding(
                "INFO", "closure.unknown",
                f"Operation '{op.keyword}' is not in the closure registry — analysis will be shallow.",
                loc,
            ))
        else:
            self._check_required_inputs(result, op, loc)

        # SNMP OID validation
        if op.keyword.startswith("run_snmp"):
            self._check_snmp_oid(result, op, loc)

        for sub in op.operands.values():
            self._walk_op(result, sub, loc)
        for sub in op.list_operands:
            self._walk_op(result, sub, loc)

    def _check_required_inputs(self, result: ValidationResult, op: Operation, loc: str) -> None:
        """For closures with declared required inputs, ERROR if missing.

        Each entry in _REQUIRED_INPUTS is a "|"-separated alias group. The
        requirement is satisfied if ANY alias in the group is present (handles
        legacy field names like `command` vs `cmd`).
        """
        required = _REQUIRED_INPUTS.get(op.keyword)
        if not required:
            return
        provided_keys = set(op.attributes.keys()) | set(op.operands.keys())
        for req_group in required:
            if req_group == "__positional__":
                if op.positional_args:
                    continue
                result.findings.append(Finding(
                    "ERROR", "closure.missing_input",
                    f"'{op.keyword}' missing required positional argument.", loc,
                ))
                continue
            aliases = req_group.split("|")
            if any(a in provided_keys for a in aliases):
                continue
            display = aliases[0]
            result.findings.append(Finding(
                "ERROR", "closure.missing_input",
                f"'{op.keyword}' missing required input '{display}'.", loc,
            ))

    def _check_snmp_oid(self, result: ValidationResult, op: Operation, loc: str) -> None:
        """For run_snmp_* operations, sanity-check the OID format and resolution."""
        oid = op.attributes.get("oid")
        if oid is None:
            sub = op.operands.get("oid")
            if sub is not None:
                oid = sub.attributes.get("value")
                if oid is None and sub.positional_args:
                    oid = sub.positional_args[0] if isinstance(sub.positional_args[0], str) else None
        if not oid or not isinstance(oid, str):
            return
        if "$" in oid:
            return  # dynamic — variable substituted at runtime
        # Format check: dotted decimal
        bare = oid.lstrip(".")
        if not bare or not all(p.isdigit() for p in bare.split(".")):
            result.findings.append(Finding(
                "WARN", "snmp.oid_format",
                f"OID {oid!r} is not dotted decimal — runtime parse failure likely.", loc,
            ))
            return
        # Resolution check (lazy import — keeps validator usable without OID DB)
        try:
            from sn_patterns_mcp import oids as _oid_pkg
            entry = _oid_pkg.lookup(oid)
            if entry is None:
                vendor = _oid_pkg.identify_vendor(oid)
                if vendor is None:
                    result.findings.append(Finding(
                        "INFO", "snmp.oid_unresolved",
                        f"OID {oid} is not in any known MIB. Verify the OID is correct.", loc,
                    ))
        except Exception as e:
            log.debug("OID resolution skipped: %s", e)

    def _check_variable_ordering(self, result: ValidationResult, pattern: Pattern) -> None:
        # Start with the union of: process-scope vars (find_process_strategy provides these),
        # pre-script CTX.setAttribute() defined vars, and standard discovery context vars.
        defined: set[str] = set(self._predefined_vars) | set(_PROCESS_VARS) | set(_DISCOVERY_CONTEXT_VARS)
        for kind, sec_idx, step_idx, step in self._iter_steps(pattern):
            loc = f"{kind}[{sec_idx}].step[{step_idx}] '{step.name or ''}'"
            if step.operation is None:
                continue
            reads = _vars_read(step.operation)
            writes = _vars_written(step.operation)
            for var in sorted(reads - defined):
                if "." in var or "[" in var:
                    continue  # field/index access — defer (can't tell from syntax alone)
                result.findings.append(Finding(
                    "WARN", "var.read_before_write",
                    f"Variable '{var}' is read before being written.",
                    loc,
                ))
            defined |= writes


# Process scope variables provided implicitly by find_process_strategy
_PROCESS_VARS = {
    "process.pid", "process.executable", "process.executablePath",
    "process.executableDir", "process.workingDir", "process.commandLine",
    "process.parameters", "process.user", "process.parent.pid",
    "process.parent.executable", "process.cmdline",
}

# Discovery-runtime variables ServiceNow always provides to a pattern's context,
# regardless of pre-scripts. Reading these never warrants a "read before write"
# warning.
_DISCOVERY_CONTEXT_VARS = {
    # Target identification
    "computer_system",                  # the CI being discovered
    "computer_system.primaryHostname",
    "computer_system.serial_number",
    "computer_system.os",
    "computer_system.os_version",
    "computer_system.fqdn",
    "computer_system.dns",
    "computer_system.ip_address",
    "host",                             # legacy alias
    "ip_address", "ipAddress",
    "fqdn",
    # Discovery flow control
    "discovery_type",                   # 'horizontal' | 'top-down' | 'vertical'
    "g_signal_state",
    "g_pattern_loop",
    "ci_type",
    "current_pattern_id",
    "current_step_name",
    "schedule_id",                      # discovery_schedule sys_id
    "device_credentials",
    "ssh_credentials", "snmp_credentials", "wmi_credentials",
    # MID server context
    "mid_server", "mid_server_name",
    # Misc commonly-injected
    "entry_point.url", "entry_point.host", "entry_point.port",
    "entry_point.protocol",
}


def _vars_read(op: Operation) -> set[str]:
    """Variables this op reads — union of get_attr targets + $vars in attribute strings."""
    out: set[str] = set()
    _walk_reads(op, out)
    return out


def _walk_reads(op: Operation, out: set[str]) -> None:
    if op.keyword == "get_attr":
        for v in op.positional_args:
            if isinstance(v, str):
                out.add(v)
    elif op.keyword in ("parse_var_to_var", "parse_url_to_var"):
        # from_var_name = "X" → reads X
        v = op.attributes.get("from_var_name")
        if isinstance(v, str) and v:
            out.add(v)
    # $var references in any string attribute
    for v in op.attributes.values():
        _scan_value(v, out)
    for v in op.positional_args:
        if isinstance(v, str) and op.keyword != "get_attr":
            _scan_value(v, out)
    for sub in op.operands.values():
        _walk_reads(sub, out)
    for sub in op.list_operands:
        _walk_reads(sub, out)


_VAR_REF_RE = re.compile(r"\$\{?([A-Za-z_][A-Za-z0-9_.\[\]]*)\}?")


def _scan_value(v: Any, out: set[str]) -> None:
    if isinstance(v, str):
        for m in _VAR_REF_RE.finditer(v):
            out.add(m.group(1))
    elif isinstance(v, list):
        for x in v:
            _scan_value(x, out)


def _vars_written(op: Operation) -> set[str]:
    out: set[str] = set()
    _walk_writes(op, out)
    return out


# Closures that write a variable — derived from the registry's outputs marker.
# Single source of truth: ClosureDescriptor.outputs contains "variable_name".
_TO_VAR_CLOSURES: frozenset[str] = frozenset(
    kw for kw, desc in closure_registry.CLOSURE_REGISTRY.items()
    if "variable_name" in desc.outputs
)


# Required arguments per closure. Each entry is a tuple of "alias-groups";
# a group is a "|"-separated list of acceptable attribute or operand names — the
# requirement is satisfied if ANY alias appears as either an attribute or an
# operand on the operation.
#
# Conservative whitelist: only closures where every real PDI pattern includes
# the field, AND a missing field is provably a fatal runtime error. We don't
# flag closures with optional/positional/nested-op-style required-arg patterns
# because the corpus has too many legitimate variations.
_REQUIRED_INPUTS: dict[str, tuple[str, ...]] = {
    "runcmd_to_var": ("cmd|command", "var_names|variable_name|var_name"),
    "run_wmi_query_to_var": ("query", "var_names|variable_name|var_name"),
    "parse_text_file_to_var": ("filePath|file_path|file", "var_names|variable_name"),
    "parse_xml_file_to_var": ("filePath|file_path|file", "var_names|variable_name"),
    "set_attr": ("__positional__",),  # name + value as positional args
    "transform_table": ("src_table_name|srcTableName",),
    "filter_table": ("src_table_name|srcTableName",),
    "merge_table": ("src_table_name|srcTableName",),
}


def _walk_writes(op: Operation, out: set[str]) -> None:
    kw = op.keyword
    if kw == "set_attr":
        if op.positional_args and isinstance(op.positional_args[0], str):
            out.add(op.positional_args[0])
    elif kw == "put_file":
        # full_path_var = "name" → writes that var
        v = op.attributes.get("full_path_var")
        if isinstance(v, str) and v:
            out.add(v)
    elif kw in {"transform_table", "filter_table", "merge_table"}:
        # These produce a variable named by target_table_name (modern releases),
        # table_name (Geneva era), or var_names (rare/test fixtures).
        v = (
            op.attributes.get("target_table_name")
            or op.attributes.get("table_name")
            or op.attributes.get("var_names")
        )
        if isinstance(v, str) and v:
            out.add(v)
    elif kw in _TO_VAR_CLOSURES:
        names = (
            op.attributes.get("var_names")
            or op.attributes.get("var_name")
            or op.attributes.get("to_var_names")
            or op.attributes.get("output_var")  # http_invoke variant
        )
        if isinstance(names, str):
            for n in names.split(","):
                n = n.strip()
                if n:
                    out.add(n)
        elif isinstance(names, list):
            for x in names:
                if isinstance(x, str):
                    out.add(x.strip())
        # parse_var_to_var has nested table writes too
        if kw == "parse_var_to_var":
            tbl = op.operands.get("to_var_names")
            if tbl is not None:
                # to_var_names = table { name = "X" col_names = ... }
                t_name = tbl.attributes.get("name")
                if isinstance(t_name, str) and t_name:
                    out.add(t_name)
    for sub in op.operands.values():
        _walk_writes(sub, out)
    for sub in op.list_operands:
        _walk_writes(sub, out)


__all__ = ["PatternValidator", "ValidationResult", "Finding"]
