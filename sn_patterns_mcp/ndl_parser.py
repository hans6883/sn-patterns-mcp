r"""
NDL (Network Discovery Language) parser.

Parses NDL text (the contents of the `ndl` field on `sa_pattern` rows) into
typed `Pattern` / `ReferenceLibrary` models for analysis and validation.

Grammar (informally):

    ndl         := block
    block       := IDENT "{" content* "}"
    content     := assignment | block | positional | comment
    assignment  := IDENT "=" value
    positional  := STRING | INT | IDENT | block
    value       := STRING | INT | IDENT | block_rhs | csv
    block_rhs   := IDENT "{" content* "}"
    csv         := value ("," value)+

Lexical rules:
  - STRING: double-quoted, escapes \" \\ \b \f \n \t \r \uXXXX (others literal)
  - INT:    optional minus, [0-9]+
  - IDENT:  [A-Za-z_][A-Za-z0-9_.]*        (dots allowed: cmdb_ci_app_server.apache)
  - COMMENT: // to EOL   or   /* ... */
  - whitespace / \r\n separated
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Any

from sn_patterns_mcp.closures import registry as closure_registry
from sn_patterns_mcp.pattern_model import (
    ConnectionSection,
    Extension,
    FindProcessStrategy,
    Identification,
    Operation,
    Pattern,
    PatternMetadata,
    PatternType,
    ReferenceLibrary,
    Step,
    Variable,
    VariableScope,
)

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class NdlSyntaxError(ValueError):
    """Raised when the tokenizer/parser encounters malformed NDL."""

    def __init__(self, message: str, line: int = 0, col: int = 0, excerpt: str = ""):
        self.line = line
        self.col = col
        self.excerpt = excerpt
        super().__init__(f"{message} at line {line}, col {col}: {excerpt!r}")


# ---------------------------------------------------------------------------
# Tokens
# ---------------------------------------------------------------------------

_TOK_IDENT = "IDENT"
_TOK_STRING = "STRING"
_TOK_INT = "INT"
_TOK_LBRACE = "LBRACE"
_TOK_RBRACE = "RBRACE"
_TOK_EQ = "EQ"
_TOK_COMMA = "COMMA"
_TOK_EOF = "EOF"


@dataclass(frozen=True)
class _Token:
    kind: str
    value: Any
    line: int
    col: int


# ---------------------------------------------------------------------------
# Tokenizer
# ---------------------------------------------------------------------------

_IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_.]*")
_INT_RE = re.compile(r"-?[0-9]+(?![.A-Za-z_])")


class _Tokenizer:
    __slots__ = ("src", "pos", "line", "col")

    def __init__(self, src: str) -> None:
        self.src = src
        self.pos = 0
        self.line = 1
        self.col = 1

    def _advance(self, n: int) -> None:
        for _ in range(n):
            ch = self.src[self.pos]
            self.pos += 1
            if ch == "\n":
                self.line += 1
                self.col = 1
            else:
                self.col += 1

    def _skip_ws_comments(self) -> None:
        src = self.src
        while self.pos < len(src):
            ch = src[self.pos]
            if ch in " \t\r\n":
                self._advance(1)
                continue
            if ch == "/" and self.pos + 1 < len(src):
                nxt = src[self.pos + 1]
                if nxt == "/":
                    # Line comment
                    while self.pos < len(src) and src[self.pos] != "\n":
                        self._advance(1)
                    continue
                if nxt == "*":
                    self._advance(2)
                    while self.pos + 1 < len(src) and not (
                        src[self.pos] == "*" and src[self.pos + 1] == "/"
                    ):
                        self._advance(1)
                    if self.pos + 1 < len(src):
                        self._advance(2)
                    continue
            break

    def _read_string(self) -> _Token:
        # Caller positioned on opening "
        start_line, start_col = self.line, self.col
        self._advance(1)  # consume opening "
        out: list[str] = []
        src = self.src
        while self.pos < len(src):
            ch = src[self.pos]
            if ch == '"':
                self._advance(1)
                return _Token(_TOK_STRING, "".join(out), start_line, start_col)
            if ch == "\\" and self.pos + 1 < len(src):
                esc = src[self.pos + 1]
                self._advance(2)
                if esc == '"':
                    out.append('"')
                elif esc == "\\":
                    out.append("\\")
                elif esc == "b":
                    out.append("\b")
                elif esc == "f":
                    out.append("\f")
                elif esc == "n":
                    out.append("\n")
                elif esc == "r":
                    out.append("\r")
                elif esc == "t":
                    out.append("\t")
                elif esc == "/":
                    out.append("/")
                elif esc == "u" and self.pos + 3 < len(src):
                    hex4 = src[self.pos : self.pos + 4]
                    self._advance(4)
                    try:
                        out.append(chr(int(hex4, 16)))
                    except ValueError:
                        out.append("\\u" + hex4)
                else:
                    # Unknown escape: keep backslash + char literally, as Java
                    # StringUtilities does for non-recognized escapes.
                    out.append("\\" + esc)
                continue
            self._advance(1)
            out.append(ch)
        raise NdlSyntaxError("Unterminated string literal", start_line, start_col, "")

    def next(self) -> _Token:
        self._skip_ws_comments()
        if self.pos >= len(self.src):
            return _Token(_TOK_EOF, None, self.line, self.col)
        ch = self.src[self.pos]
        line, col = self.line, self.col

        if ch == "{":
            self._advance(1)
            return _Token(_TOK_LBRACE, "{", line, col)
        if ch == "}":
            self._advance(1)
            return _Token(_TOK_RBRACE, "}", line, col)
        if ch == "=":
            self._advance(1)
            return _Token(_TOK_EQ, "=", line, col)
        if ch == ",":
            self._advance(1)
            return _Token(_TOK_COMMA, ",", line, col)
        if ch == '"':
            return self._read_string()

        m = _INT_RE.match(self.src, self.pos)
        if m:
            text = m.group(0)
            self._advance(len(text))
            return _Token(_TOK_INT, int(text), line, col)

        m = _IDENT_RE.match(self.src, self.pos)
        if m:
            text = m.group(0)
            self._advance(len(text))
            return _Token(_TOK_IDENT, text, line, col)

        raise NdlSyntaxError(f"Unexpected character {ch!r}", line, col, self.src[self.pos : self.pos + 40])

    def tokens(self) -> list[_Token]:
        out: list[_Token] = []
        while True:
            tok = self.next()
            out.append(tok)
            if tok.kind == _TOK_EOF:
                return out


# ---------------------------------------------------------------------------
# Parse tree — untyped intermediate the NdlParser builds first, before it
# turns the tree into Pattern/Identification/Step/Operation objects.
# ---------------------------------------------------------------------------

@dataclass
class _Block:
    name: str
    line: int
    col: int
    # Ordered list of (key|None, value). key=None means unassigned sub-block.
    items: list[tuple[str | None, Any]]


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

class _Parser:
    def __init__(self, tokens: list[_Token]) -> None:
        self.tokens = tokens
        self.i = 0

    def _peek(self, off: int = 0) -> _Token:
        idx = self.i + off
        if idx >= len(self.tokens):
            return self.tokens[-1]
        return self.tokens[idx]

    def _eat(self, kind: str) -> _Token:
        tok = self.tokens[self.i]
        if tok.kind != kind:
            raise NdlSyntaxError(f"Expected {kind}, got {tok.kind}({tok.value!r})", tok.line, tok.col)
        self.i += 1
        return tok

    def parse_top(self) -> _Block:
        blk = self._parse_block()
        eof = self._peek()
        if eof.kind != _TOK_EOF:
            raise NdlSyntaxError(f"Trailing tokens after root block: {eof.value!r}", eof.line, eof.col)
        return blk

    def _parse_block(self) -> _Block:
        ident = self._eat(_TOK_IDENT)
        self._eat(_TOK_LBRACE)
        items: list[tuple[str | None, Any]] = []
        while True:
            tok = self._peek()
            if tok.kind == _TOK_RBRACE:
                self.i += 1
                return _Block(name=ident.value, line=ident.line, col=ident.col, items=items)
            if tok.kind == _TOK_EOF:
                raise NdlSyntaxError("Unterminated block", ident.line, ident.col, ident.value)
            items.append(self._parse_content())

    def _parse_content(self) -> tuple[str | None, Any]:
        tok = self._peek()
        # Positional bare-string / bare-int (e.g. set_attr { "pid" get_attr{...} })
        if tok.kind == _TOK_STRING:
            self.i += 1
            return (None, tok.value)
        if tok.kind == _TOK_INT:
            self.i += 1
            return (None, tok.value)
        if tok.kind != _TOK_IDENT:
            raise NdlSyntaxError(
                f"Expected identifier, string, or integer, got {tok.kind}",
                tok.line, tok.col, str(tok.value),
            )
        nxt = self._peek(1)
        if nxt.kind == _TOK_LBRACE:
            # Sub-block (positional, key=None):  foo { ... }
            blk = self._parse_block()
            return (None, blk)
        if nxt.kind == _TOK_EQ:
            ident = self._eat(_TOK_IDENT)
            self._eat(_TOK_EQ)
            value = self._parse_value_maybe_csv()
            return (ident.value, value)
        # Bare identifier as positional value
        ident = self._eat(_TOK_IDENT)
        return (None, _UnQuoted(ident.value))

    def _parse_value_maybe_csv(self) -> Any:
        first = self._parse_single_value()
        if self._peek().kind != _TOK_COMMA:
            return first
        items: list[Any] = [first]
        while self._peek().kind == _TOK_COMMA:
            self.i += 1
            items.append(self._parse_single_value())
        return items

    def _parse_single_value(self) -> Any:
        tok = self._peek()
        if tok.kind == _TOK_STRING:
            self.i += 1
            return tok.value
        if tok.kind == _TOK_INT:
            self.i += 1
            return tok.value
        if tok.kind == _TOK_IDENT:
            # Either a bare identifier or an assigned block
            if self._peek(1).kind == _TOK_LBRACE:
                return self._parse_block()
            self.i += 1
            return _UnQuoted(tok.value)
        raise NdlSyntaxError(f"Unexpected token {tok.kind}({tok.value!r})", tok.line, tok.col)


@dataclass(frozen=True)
class _UnQuoted:
    """Sentinel for bare-identifier values."""
    value: str


# ---------------------------------------------------------------------------
# Tree -> typed model
# ---------------------------------------------------------------------------

class NdlParser:
    """Parses NDL text into a typed Pattern / ReferenceLibrary model.

    Usage:
        parser = NdlParser()
        pattern = parser.parse(ndl_text)
        library = parser.parse_library(ndl_text)   # for shared-library NDL
    """

    def parse(self, ndl_text: str) -> Pattern:
        """Parse pattern NDL. If root is 'library', wrap it as a single-identification pattern."""
        root = self._tree(ndl_text)
        if root.name == "library":
            lib = self._build_library(root, source=ndl_text)
            pat = Pattern(source_ndl=ndl_text)
            pat.metadata.id = lib.id
            pat.metadata.name = lib.name
            pat.metadata.description = lib.description
            ident = Identification(name=lib.name or "library")
            ident.steps = lib.steps
            pat.identifications.append(ident)
            pat.pattern_type = PatternType.IDENTIFICATION
            pat.metadata.extra["_is_library"] = True
            return pat
        return self._build_pattern(root, source=ndl_text)

    def parse_library(self, ndl_text: str) -> ReferenceLibrary:
        """Parse a library / shared-reference NDL string."""
        root = self._tree(ndl_text)
        return self._build_library(root, source=ndl_text)

    def parse_fragment(self, ndl_text: str) -> Operation:
        """Parse a bare operation block — used by ndl_explain."""
        root = self._tree(ndl_text)
        return self._build_operation(root)

    def parse_tree(self, ndl_text: str) -> _Block:
        """Return the raw untyped block tree — used by NdlWriter for roundtrip."""
        return self._tree(ndl_text)

    # ------------------------------------------------------------------ tree

    def _tree(self, ndl_text: str) -> _Block:
        if ndl_text is None:
            raise NdlSyntaxError("NDL text is None")
        stripped = ndl_text.lstrip("\ufeff").strip()
        if not stripped:
            raise NdlSyntaxError("NDL text is empty")
        toks = _Tokenizer(stripped).tokens()
        return _Parser(toks).parse_top()

    # ------------------------------------------------------------------ root builders

    def _build_pattern(self, root: _Block, *, source: str | None) -> Pattern:
        if root.name != "pattern":
            # Some identification-only patterns emit root "pattern" too; some
            # library NDL emits "library". Anything else is unexpected.
            raise NdlSyntaxError(f"Expected root block 'pattern', got {root.name!r}", root.line, root.col)
        pat = Pattern(source_ndl=source)
        for key, value in root.items:
            if key is not None:
                # Top-level key=value is rare but seen for some metadata shortcuts.
                pat.metadata.extra[key] = _to_python(value)
                continue
            blk: _Block = value  # unassigned sub-block
            nm = blk.name
            if nm == "metadata":
                pat.metadata = self._build_metadata(blk)
            elif nm == "identification":
                pat.identifications.append(self._build_identification(blk))
            elif nm == "connection":
                pat.connections.append(self._build_connection(blk))
            elif nm == "extension":
                pat.extensions.append(self._build_extension(blk))
            else:
                # Forward-compatibility: preserve unknown blocks as metadata.extra
                pat.metadata.extra.setdefault("_unknown_blocks", []).append(nm)
        # Infer pattern_type from shape
        if not pat.connections and pat.identifications:
            pat.pattern_type = PatternType.IDENTIFICATION
        else:
            pat.pattern_type = PatternType.HORIZONTAL
        return pat

    def _build_library(self, root: _Block, *, source: str | None) -> ReferenceLibrary:
        if root.name != "library":
            raise NdlSyntaxError(f"Expected root block 'library', got {root.name!r}", root.line, root.col)
        lib = ReferenceLibrary(source_ndl=source)
        for key, value in root.items:
            if key == "id":
                lib.id = _as_str(value)
            elif key == "name":
                lib.name = _as_str(value)
            elif key == "description":
                lib.description = _as_str(value)
            elif key is None and isinstance(value, _Block) and value.name == "step":
                lib.steps.append(self._build_step(value))
        return lib

    # ------------------------------------------------------------------ blocks

    def _build_metadata(self, blk: _Block) -> PatternMetadata:
        md = PatternMetadata()
        for key, value in blk.items:
            if key == "id":
                md.id = _as_str(value)
            elif key == "name":
                md.name = _as_str(value)
            elif key in ("description", "desc"):
                md.description = _as_str(value)
            elif key in ("citype", "ci_type"):
                md.ci_type = _as_str(value)
            elif key == "apply_to_os_types":
                md.apply_to_os_types = _as_str_list(value)
            elif key == "apply_to_os_families":
                md.apply_to_os_families = _as_str_list(value)
            elif key == "runs_before":
                md.runs_before = _as_str(value)
            elif key == "runs_after":
                md.runs_after = _as_str(value)
            elif key is not None:
                md.extra[key] = _to_python(value)
        return md

    def _build_identification(self, blk: _Block) -> Identification:
        ident = Identification()
        for key, value in blk.items:
            if key == "name":
                ident.name = _as_str(value)
            elif key == "entry_point_types":
                ident.entry_point_types = _as_str_list(value)
            elif key is None and isinstance(value, _Block):
                if value.name == "entrypoint":
                    # entrypoint { type = "TCP,UDP" }  -> split on comma
                    t = _get_value(value, "type")
                    if isinstance(t, str):
                        ident.entry_point_types.extend([s.strip() for s in t.split(",") if s.strip()])
                    elif isinstance(t, list):
                        ident.entry_point_types.extend(_as_str_list(t))
                elif value.name == "find_process_strategy":
                    strat = _get_value(value, "strategy")
                    name = strat.value if isinstance(strat, _UnQuoted) else _as_str(strat)
                    try:
                        ident.find_process_strategy = FindProcessStrategy(name)
                    except ValueError:
                        # Unknown strategy — record under metadata.extra so
                        # validators / pattern_analyze can surface it instead of
                        # silently dropping. Common cause: typo or new-release
                        # strategy name not in our enum.
                        log.warning("unknown find_process_strategy: %r (pattern will lose this directive)", name)
                        ident.entry_point_types.append(f"<unknown find_process_strategy: {name!r}>")
                elif value.name == "step":
                    ident.steps.append(self._build_step(value))
            elif key == "find_process_strategy":
                name = value.value if isinstance(value, _UnQuoted) else _as_str(value)
                try:
                    ident.find_process_strategy = FindProcessStrategy(name)
                except ValueError:
                    log.warning("unknown find_process_strategy: %r", name)
                    ident.entry_point_types.append(f"<unknown find_process_strategy: {name!r}>")
        return ident

    def _build_connection(self, blk: _Block) -> ConnectionSection:
        conn = ConnectionSection()
        for key, value in blk.items:
            if key == "name":
                conn.name = _as_str(value)
            elif key is None and isinstance(value, _Block) and value.name == "step":
                conn.steps.append(self._build_step(value))
        return conn

    def _build_extension(self, blk: _Block) -> Extension:
        ext = Extension()
        for key, value in blk.items:
            if key == "name":
                ext.name = _as_str(value)
            elif key == "order":
                ext.order = int(value) if isinstance(value, (int, str)) and str(value).lstrip("-").isdigit() else None
            elif key is None and isinstance(value, _Block) and value.name == "step":
                ext.steps.append(self._build_step(value))
        return ext

    # ------------------------------------------------------------------ steps

    def _build_step(self, blk: _Block) -> Step:
        step = Step()
        for key, value in blk.items:
            if key == "name":
                step.name = _as_str(value)
            elif key == "comment":
                step.comment = _as_str(value)
            elif key == "disabled":
                step.disabled = _as_str(value) if not isinstance(value, _UnQuoted) else value.value
            elif key == "refid":
                step.library_ref = _as_str(value)
                step.operation = Operation(keyword="refid", attributes={"id": step.library_ref})
            elif key is None and isinstance(value, _Block):
                # Either the operation block or a wrapping IfClosure (conditional lib).
                op = self._build_operation(value)
                if op.keyword == "if" and "then" in op.operands:
                    inner = op.operands["then"]
                    # Conditional library reference
                    if inner.keyword == "refid":
                        step.library_ref = _as_str(inner.attributes.get("id"))
                    step.precondition = op.operands.get("condition")
                    step.operation = inner
                else:
                    if op.keyword == "refid":
                        step.library_ref = _as_str(op.attributes.get("id"))
                    step.operation = op
            elif key is not None and isinstance(value, _Block):
                # Some NDL uses:  operation = runcmd_to_var { ... }
                if key in ("operation", "op"):
                    op = self._build_operation(value)
                    step.operation = op
                    if op.keyword == "refid":
                        step.library_ref = _as_str(op.attributes.get("id"))
        if step.operation is None and step.library_ref is None:
            # Fallback: step with only a scalar refid=… attribute
            pass
        return step

    # ------------------------------------------------------------------ operations

    def _build_operation(self, blk: _Block) -> Operation:
        descriptor = closure_registry.get(blk.name)
        op = Operation(keyword=blk.name, class_name=(descriptor.class_name if descriptor else None))
        for key, value in blk.items:
            if key is None:
                # Positional argument
                if isinstance(value, _Block):
                    op.list_operands.append(self._build_operation(value))
                else:
                    op.positional_args.append(_to_python(value))
                continue
            if isinstance(value, _Block):
                op.operands[key] = self._build_operation(value)
            elif isinstance(value, list) and value and isinstance(value[0], _Block):
                op.list_operands.extend(self._build_operation(v) for v in value if isinstance(v, _Block))
            else:
                op.attributes[key] = _to_python(value)
        return op


# ---------------------------------------------------------------------------
# Helpers: value coercion
# ---------------------------------------------------------------------------

def _to_python(v: Any) -> Any:
    if isinstance(v, _UnQuoted):
        return v.value
    if isinstance(v, list):
        return [_to_python(x) for x in v]
    if isinstance(v, _Block):
        return _raw(v)  # preserve block raw form in attributes dict
    return v


def _raw(v: Any) -> Any:
    if isinstance(v, _Block):
        return {"__block__": v.name, "items": [(k, _raw(val)) for k, val in v.items]}
    if isinstance(v, _UnQuoted):
        return {"__unquoted__": v.value}
    if isinstance(v, list):
        return [_raw(x) for x in v]
    return v


def _as_str(v: Any) -> str:
    if v is None:
        return ""
    if isinstance(v, _UnQuoted):
        return v.value
    if isinstance(v, str):
        return v
    if isinstance(v, (int, float)):
        return str(v)
    if isinstance(v, list):
        return ",".join(_as_str(x) for x in v)
    return str(v)


def _as_str_list(v: Any) -> list[str]:
    if v is None:
        return []
    if isinstance(v, list):
        return [_as_str(x) for x in v]
    return [_as_str(v)]


def _get_value(blk: _Block, key: str) -> Any:
    for k, v in blk.items:
        if k == key:
            return v
    return None


# ---------------------------------------------------------------------------
# Variable classifier — annotates each Variable with scope/ci_attribute.
# ---------------------------------------------------------------------------

def classify_variables(pattern: Pattern, ci_attribute_columns: set[str] | None = None) -> dict[str, Variable]:
    """Walk pattern, build a variable directory with scope classification.

    ci_attribute_columns: set of column names on the target CI table. If a
    variable's name matches one of these, it's marked CI_ATTRIBUTE. Otherwise
    it's TEMPORARY. If None is passed, everything is marked UNKNOWN (caller
    can fetch the column list from the PDI dictionary when needed).
    """
    found: dict[str, Variable] = {}
    for step in pattern.all_steps():
        if step.operation is not None:
            for var in step.operation.get_variables():
                found.setdefault(var.name, var)
    if ci_attribute_columns is None:
        return found

    out: dict[str, Variable] = {}
    for name in found:
        key = name.split(".")[0].split("[")[0]
        if key in ci_attribute_columns:
            out[name] = Variable(name=name, scope=VariableScope.CI_ATTRIBUTE, ci_attribute=key)
        else:
            out[name] = Variable(name=name, scope=VariableScope.TEMPORARY)
    return out


def blocks_equivalent(a: _Block, b: _Block) -> bool:
    """Structural equality of two parser block trees, ignoring source positions."""
    if not isinstance(a, _Block) or not isinstance(b, _Block):
        return False
    if a.name != b.name or len(a.items) != len(b.items):
        return False
    for (ka, va), (kb, vb) in zip(a.items, b.items, strict=True):
        if ka != kb:
            return False
        if not _values_equivalent(va, vb):
            return False
    return True


def _values_equivalent(a: Any, b: Any) -> bool:
    if isinstance(a, _Block) and isinstance(b, _Block):
        return blocks_equivalent(a, b)
    if isinstance(a, _UnQuoted) and isinstance(b, _UnQuoted):
        return a.value == b.value
    if isinstance(a, list) and isinstance(b, list):
        return len(a) == len(b) and all(_values_equivalent(x, y) for x, y in zip(a, b, strict=True))
    return a == b


__all__ = ["NdlParser", "NdlSyntaxError", "classify_variables", "blocks_equivalent"]
