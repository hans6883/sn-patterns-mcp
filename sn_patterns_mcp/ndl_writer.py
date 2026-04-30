"""NDL writer — emits NDL text in the canonical block layout.

Single-attribute blocks render inline (`name { key = value }`); multi-attribute
blocks render multi-line with tab indentation. Roundtrip property:

    tree_a = NdlParser().parse_tree(ndl)
    out    = NdlWriter().write(tree_a)
    tree_b = NdlParser().parse_tree(out)
    assert blocks_equivalent(tree_a, tree_b)
"""
from __future__ import annotations

from typing import Any

from sn_patterns_mcp.ndl_parser import _Block, _UnQuoted


def escape_java(s: str) -> str:
    """Java-style string escaping. BMP characters become \\uXXXX; supplementary-plane characters become UTF-16 surrogate pairs."""
    out: list[str] = []
    for ch in s:
        c = ord(ch)
        if c > 0xFFFF:
            # Supplementary-plane character → encode as UTF-16 surrogate pair (Java semantics)
            adj = c - 0x10000
            high = 0xD800 + (adj >> 10)
            low = 0xDC00 + (adj & 0x3FF)
            out.append(f"\\u{high:04X}\\u{low:04X}")
        elif c > 0xFFF:
            out.append(f"\\u{c:04X}")
        elif c > 0xFF:
            out.append(f"\\u0{c:03X}")
        elif c > 0x7F:
            out.append(f"\\u00{c:02X}")
        elif c < 0x20:
            if ch == "\b":
                out.append("\\b")
            elif ch == "\f":
                out.append("\\f")
            elif ch in ("\n", "\t", "\r"):
                out.append(ch)
            elif c > 0xF:
                out.append(f"\\u00{c:02X}")
            else:
                out.append(f"\\u000{c:X}")
        elif ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        else:
            out.append(ch)
    return "".join(out)


def escape_value(v: Any) -> str:
    return escape_java(str(v))


class _Indentor:
    """Tracks inline/block rendering state and indent depth as text is built up."""
    __slots__ = ("indent", "parts", "stack", "inline", "_tab", "_nl")

    def __init__(self, tab: str = "\t", nl: str = "\n") -> None:
        self.indent = 0
        self.parts: list[str] = []
        self.stack: list[bool] = []
        self.inline = False
        self._tab = tab
        self._nl = nl

    def _print_indent(self) -> None:
        if self.parts and self.parts[-1] and self.parts[-1][-1] == "\n":
            self.parts.append(self._tab * self.indent)

    def _newline(self) -> None:
        if not self.inline:
            self.parts.append(self._nl)

    def begin_block(self, text: str) -> None:
        self.stack.append(self.inline)
        self.inline = False
        self._print_indent()
        self.indent += 1
        self.parts.append(text + self._nl)

    def begin_inline_block(self, text: str) -> None:
        self.stack.append(self.inline)
        self.inline = True
        self.inline_text(text)
        self.indent += 1

    def inline_text(self, text: str) -> None:
        self._print_indent()
        self.parts.append(text)

    def append(self, text: str) -> None:
        self.inline_text(text)
        self._newline()

    def end_block(self, text: str) -> None:
        self.indent -= 1
        self._print_indent()
        if self.stack:
            self.inline = self.stack.pop()
        self.parts.append(text)
        self._newline()

    def render(self) -> str:
        return "".join(self.parts)


class NdlWriter:
    """Emit NDL text from a parser _Block tree."""

    def __init__(self, tab: str = "\t", newline: str = "\n") -> None:
        self._tab = tab
        self._nl = newline

    def write(self, block: _Block) -> str:
        ind = _Indentor(tab=self._tab, nl=self._nl)
        self._print_block(block, ind)
        return ind.render()

    def write_value(self, value: Any) -> str:
        """Serialize a single attribute value (used for ndl_explain reverse-mode)."""
        if isinstance(value, _Block):
            return self.write(value).rstrip("\r\n")
        return self._format_scalar(value)

    # -- internal -------------------------------------------------------

    def _print_block(self, blk: _Block, ind: _Indentor) -> None:
        # NdlBlock.print: <=1 attribute → inline, else multi-line.
        if len(blk.items) <= 1:
            ind.begin_inline_block(blk.name + " {")
        else:
            ind.begin_block(blk.name + " {")
        for key, value in blk.items:
            if key is None:
                self._append_positional(value, ind)
            else:
                self._append_attribute(key, value, ind)
        ind.end_block("}")

    def _append_positional(self, value: Any, ind: _Indentor) -> None:
        # Positional value: nested blocks recurse; unquoted idents print bare; everything else is quoted+escaped.
        if isinstance(value, _Block):
            self._print_block(value, ind)
        elif isinstance(value, _UnQuoted):
            ind.append(value.value)
        elif isinstance(value, bool):
            # Defensive: NDL doesn't really have booleans, but stringify safely.
            ind.append('"' + escape_value(value) + '"')
        elif isinstance(value, int):
            ind.append(str(value))
        else:
            ind.append('"' + escape_value(value) + '"')

    def _append_attribute(self, key: str, value: Any, ind: _Indentor) -> None:
        # key=value attribute. Nested-block values render as `key = ` + nested block.
        if isinstance(value, _Block):
            ind.inline_text(key + " = ")
            self._print_block(value, ind)
            return
        if isinstance(value, list):
            ind.append(key + " = " + self._format_csv(value))
            return
        ind.append(key + " = " + self._format_scalar(value))

    def _format_scalar(self, value: Any) -> str:
        if isinstance(value, _UnQuoted):
            return value.value
        if isinstance(value, bool):
            return '"' + escape_value(value) + '"'
        if isinstance(value, int):
            return str(value)
        return '"' + escape_value(value) + '"'

    def _format_csv(self, values: list[Any]) -> str:
        return ",".join(self._format_scalar(v) for v in values)


__all__ = ["NdlWriter", "escape_java", "escape_value"]
