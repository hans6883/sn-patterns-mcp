"""
Pattern data model — typed dataclasses representing the structural shape of
ServiceNow Discovery patterns (Pattern, Step, Identification, ConnectionSection,
Extension, Operation, Variable, ReferenceLibrary).

Field names mirror the property names used in NDL itself, so roundtripping
parse -> serialize -> parse preserves equality at the AST level.

Mutation policy: instances are produced once by the parser and treated as
immutable downstream. Use dataclasses.replace() to derive variants.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

# Matches $name, ${name}, and ${name.subfield} — the three forms NDL uses for variable references.
_VAR_RE = re.compile(r"\$\{?([A-Za-z_][A-Za-z0-9_.\[\]]*)\}?")


# ---------------------------------------------------------------------------
# Enums — pattern flow control / process-finding strategies
# ---------------------------------------------------------------------------

class FindProcessStrategy(str, Enum):
    """Identification find strategy."""
    LISTENING_PORT = "LISTENING_PORT"
    TARGET_PORT_AND_IP = "TARGET_PORT_AND_IP"
    NONE = "NONE"


class VariableScope(str, Enum):
    """CI attribute (table column on target CI) vs pattern-local temporary."""
    CI_ATTRIBUTE = "ci_attribute"
    TEMPORARY = "temporary"
    UNKNOWN = "unknown"


class PatternType(str, Enum):
    """sa_pattern.cpattern_type values.

    0 = horizontal discovery pattern
    2 = identification section only (ID pattern)
    3 = shared library (ReferenceElement, not a top-level pattern)
    """
    HORIZONTAL = "0"
    IDENTIFICATION = "2"
    LIBRARY = "3"


# ---------------------------------------------------------------------------
# Variables
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Variable:
    """A $-prefixed variable reference appearing in NDL.

    table=True means the value is a list-of-rows (multi-row result from
    parse/WMI/SNMP); False means a scalar. Unknown until classifier runs.
    """
    name: str
    scope: VariableScope = VariableScope.UNKNOWN
    ci_attribute: str | None = None  # e.g. "install_directory" if scope == CI_ATTRIBUTE
    table: bool | None = None

    def is_ci(self) -> bool:
        return self.scope == VariableScope.CI_ATTRIBUTE


# ---------------------------------------------------------------------------
# Operations
# ---------------------------------------------------------------------------

@dataclass
class Operation:
    """One NDL operation block — e.g. runcmd_to_var { ... }.

    Fields mirror the four shapes NDL allows inside a functor block:
        keyword=value                   → attributes[key] = value
        keyword = nested_block { ... }  → operands[key] = Operation(...)
        bare_block { ... }              → list_operands.append(Operation(...))
        "literal" / 42 / IDENT          → positional_args.append(value)

    `class_name` is the fully-qualified class name from the closure registry (None for unknown keywords).
    Lossless serialization is performed by NdlWriter operating on the raw _Block
    tree — Operation does NOT preserve a parallel raw representation.
    """
    keyword: str
    class_name: str | None = None
    attributes: dict[str, Any] = field(default_factory=dict)
    operands: dict[str, Operation] = field(default_factory=dict)
    list_operands: list[Operation] = field(default_factory=list)
    positional_args: list[Any] = field(default_factory=list)

    def get_variables(self) -> list[Variable]:
        """Walk the op tree, collect every $var referenced or written."""
        found: dict[str, Variable] = {}
        _collect_vars(self, found)
        return list(found.values())

    def find(self, keyword: str) -> list[Operation]:
        """Find all nested operations by NDL keyword (depth-first)."""
        hits: list[Operation] = []
        _walk_ops(self, lambda op: hits.append(op) if op.keyword == keyword else None)
        return hits


def _collect_vars(op: Operation, out: dict[str, Variable]) -> None:
    for v in op.attributes.values():
        _scan_value_for_vars(v, out)
    for sub in op.operands.values():
        _collect_vars(sub, out)
    for sub in op.list_operands:
        _collect_vars(sub, out)
    for v in op.positional_args:
        _scan_value_for_vars(v, out)


def _scan_value_for_vars(v: Any, out: dict[str, Variable]) -> None:
    if isinstance(v, str):
        _scan_string_for_vars(v, out)
    elif isinstance(v, (list, tuple)):
        for x in v:
            _scan_value_for_vars(x, out)


def _scan_string_for_vars(s: str, out: dict[str, Variable]) -> None:
    for m in _VAR_RE.finditer(s):
        name = m.group(1)
        out.setdefault(name, Variable(name=name))


def _walk_ops(op: Operation, fn) -> None:
    fn(op)
    for sub in op.operands.values():
        _walk_ops(sub, fn)
    for sub in op.list_operands:
        _walk_ops(sub, fn)


# ---------------------------------------------------------------------------
# Steps
# ---------------------------------------------------------------------------

@dataclass
class Step:
    """A single executable step inside an identification/connection/extension.

    A step is EITHER:
      - operation: a regular functor step (step { name="..."; op { ... } })
      - library_ref: a refid step that expands a shared library at runtime
    """
    name: str = ""
    comment: str | None = None
    disabled: str | None = None  # "true"/"false" string literals in the NDL
    operation: Operation | None = None
    library_ref: str | None = None
    # If wrapped in an IfClosure, the guard operation lives here and `operation`
    # holds the inner body (LibraryReference or a normal Operation).
    precondition: Operation | None = None

    @property
    def is_library_ref(self) -> bool:
        return self.library_ref is not None or (
            self.operation is not None and self.operation.keyword == "refid"
        )

    @property
    def is_conditional_library_ref(self) -> bool:
        return self.precondition is not None and self.is_library_ref

    @property
    def is_disabled(self) -> bool:
        return str(self.disabled).lower() == "true"

    def referenced_library_id(self) -> str | None:
        if self.library_ref:
            return self.library_ref
        if self.operation and self.operation.keyword == "refid":
            return self.operation.attributes.get("id") or self.operation.attributes.get("refid")
        return None


# ---------------------------------------------------------------------------
# Sections
# ---------------------------------------------------------------------------

@dataclass
class Identification:
    """One identification section of a pattern."""
    name: str = ""
    entry_point_types: list[str] = field(default_factory=list)
    find_process_strategy: FindProcessStrategy | None = None
    steps: list[Step] = field(default_factory=list)


@dataclass
class ConnectionSection:
    """One connection section of a pattern."""
    name: str = ""
    steps: list[Step] = field(default_factory=list)


@dataclass
class Extension:
    """Extension block — groups steps that run after the main identification.

    Recent SN releases fold these into the connections-list semantically, but they're
    worth modeling separately for display and debug tooling.
    """
    name: str = ""
    order: int | None = None
    steps: list[Step] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Metadata + top-level Pattern
# ---------------------------------------------------------------------------

@dataclass
class PatternMetadata:
    """pattern.metadata { ... } block — fields from LanguagePattern.toNdl."""
    id: str = ""
    name: str = ""
    description: str = ""
    ci_type: str = ""                    # "citype" in NDL; produced CI type ID
    apply_to_os_types: list[str] = field(default_factory=list)
    apply_to_os_families: list[str] = field(default_factory=list)
    runs_before: str | None = None
    runs_after: str | None = None
    # Extra fields seen in the wild (not emitted by NdlWriter but present in
    # extensions encountered in real patterns): preserved raw.
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass
class Pattern:
    """Top-level pattern — mirrors LanguagePattern fields."""
    metadata: PatternMetadata = field(default_factory=PatternMetadata)
    identifications: list[Identification] = field(default_factory=list)
    connections: list[ConnectionSection] = field(default_factory=list)
    extensions: list[Extension] = field(default_factory=list)
    pattern_type: PatternType = PatternType.HORIZONTAL
    # Preserve the original NDL text so pattern_compare can fall back to a
    # textual diff when structural diff is unhelpful.
    source_ndl: str | None = None

    # Convenience helpers used by the MCP tools -------------------------------

    def all_steps(self) -> list[Step]:
        out: list[Step] = []
        for ident in self.identifications:
            out.extend(ident.steps)
        for conn in self.connections:
            out.extend(conn.steps)
        for ext in self.extensions:
            out.extend(ext.steps)
        return out

    def library_references(self) -> list[str]:
        refs: list[str] = []
        for step in self.all_steps():
            rid = step.referenced_library_id()
            if rid:
                refs.append(rid)
        return refs

    def operation_keywords(self) -> list[str]:
        """All operation NDL keywords used anywhere in the pattern (with duplicates)."""
        kws: list[str] = []
        for step in self.all_steps():
            if step.operation is not None:
                _walk_ops(step.operation, lambda op: kws.append(op.keyword))
        return kws


# ---------------------------------------------------------------------------
# Shared library (ReferenceElement)
# ---------------------------------------------------------------------------

@dataclass
class ReferenceLibrary:
    """A shared library expanded into a pattern via `refid`."""
    id: str = ""
    name: str = ""
    description: str = ""
    steps: list[Step] = field(default_factory=list)
    source_ndl: str | None = None
