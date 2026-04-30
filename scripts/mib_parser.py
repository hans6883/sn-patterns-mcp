"""Lightweight regex-based parser for SMI MIB files.

Extracts OBJECT-TYPE, OBJECT IDENTIFIER, and MODULE-IDENTITY definitions —
enough to build an {oid → {name, syntax, access, description, mib}} index
without depending on pysmi. Tolerant of vendor quirks; on parse error it
records a warning and skips the entry rather than aborting the whole MIB.

Usage:
    parser = MibParser()
    parser.parse(mib_text, source_path="cisco/CISCO-PROCESS-MIB")
    # ... parse more MIBs into the same symbol table ...
    entries = parser.resolve()  # returns list of dicts in OidEntry shape
"""
from __future__ import annotations

import logging
import re
from collections.abc import Iterable
from dataclasses import dataclass, field

log = logging.getLogger(__name__)


# Well-known root OIDs — the foundation symbols every MIB resolves against.
# Source: ASN.1 dot notation ground truth (X.660 / RFC 2578).
_WELL_KNOWN_ROOTS: dict[str, str] = {
    "ccitt": "0",
    "itu-t": "0",
    "iso": "1",
    "joint-iso-ccitt": "2",
    "joint-iso-itu-t": "2",
    "org": "1.3",
    "dod": "1.3.6",
    "internet": "1.3.6.1",
    "directory": "1.3.6.1.1",
    "mgmt": "1.3.6.1.2",
    "mib-2": "1.3.6.1.2.1",
    "mib_2": "1.3.6.1.2.1",  # variant
    "experimental": "1.3.6.1.3",
    "private": "1.3.6.1.4",
    "enterprises": "1.3.6.1.4.1",
    "security": "1.3.6.1.5",
    "snmpV2": "1.3.6.1.6",
    "snmpDomains": "1.3.6.1.6.1",
    "snmpProxys": "1.3.6.1.6.2",
    "snmpModules": "1.3.6.1.6.3",
    # transmission media
    "transmission": "1.3.6.1.2.1.10",
    # widely-used named nodes from SNMPv2-SMI / SNMPv2-MIB
    "system": "1.3.6.1.2.1.1",
    "interfaces": "1.3.6.1.2.1.2",
    "ip": "1.3.6.1.2.1.4",
    "icmp": "1.3.6.1.2.1.5",
    "tcp": "1.3.6.1.2.1.6",
    "udp": "1.3.6.1.2.1.7",
    "egp": "1.3.6.1.2.1.8",
    "transmission-mib": "1.3.6.1.2.1.10",
    "snmp": "1.3.6.1.2.1.11",
    "host": "1.3.6.1.2.1.25",
    "rmon": "1.3.6.1.2.1.16",
    "ifMIB": "1.3.6.1.2.1.31",
    "entityMIB": "1.3.6.1.2.1.47",
    "zeroDotZero": "0.0",
}


# OBJECT-TYPE block — multiline; ends at "::= { parent N }"
_OBJECT_TYPE_RE = re.compile(
    r"(?P<name>[a-zA-Z][\w-]*)\s+OBJECT-TYPE\b"
    r"(?P<body>(?:[^:]|:(?!:=))*?)"
    r"::=\s*\{\s*(?P<parent>[a-zA-Z][\w-]*)\s+(?P<index>\d+)\s*\}",
    re.DOTALL,
)

# Bare OBJECT IDENTIFIER node — defines a tree node without a managed object
_OID_NODE_RE = re.compile(
    r"(?P<name>[a-zA-Z][\w-]*)\s+OBJECT\s+IDENTIFIER\s*"
    r"::=\s*\{\s*(?P<parent>[a-zA-Z][\w-]*)\s+(?P<index>\d+)\s*\}",
)

# MODULE-IDENTITY — declares the root of a MIB module
_MODULE_IDENTITY_RE = re.compile(
    r"(?P<name>[a-zA-Z][\w-]*)\s+MODULE-IDENTITY\b"
    r"(?P<body>(?:[^:]|:(?!:=))*?)"
    r"::=\s*\{\s*(?P<parent>[a-zA-Z][\w-]*)\s+(?P<index>\d+)\s*\}",
    re.DOTALL,
)

# OBJECT-IDENTITY — alternative root marker used by some MIBs
_OBJECT_IDENTITY_RE = re.compile(
    r"(?P<name>[a-zA-Z][\w-]*)\s+OBJECT-IDENTITY\b"
    r"(?P<body>(?:[^:]|:(?!:=))*?)"
    r"::=\s*\{\s*(?P<parent>[a-zA-Z][\w-]*)\s+(?P<index>\d+)\s*\}",
    re.DOTALL,
)

# Inside an OBJECT-TYPE body we extract these fields:
_SYNTAX_RE = re.compile(r"SYNTAX\s+(.+?)(?=\s+(?:UNITS|MAX-ACCESS|ACCESS|STATUS|DESCRIPTION|REFERENCE|INDEX|AUGMENTS|DEFVAL)\b)",
                        re.DOTALL)
_ACCESS_RE = re.compile(r"(?:MAX-ACCESS|ACCESS)\s+([\w-]+)")
_DESCRIPTION_RE = re.compile(r'DESCRIPTION\s+"((?:[^"]|"")*)"', re.DOTALL)


@dataclass
class _RawDef:
    """One raw symbol → (parent, index, optional managed-object fields)."""
    name: str
    parent: str
    index: int
    source_mib: str
    syntax: str = ""
    access: str = ""
    description: str = ""
    is_object_type: bool = False  # True for OBJECT-TYPE; False for plain OBJECT IDENTIFIER
    is_table: bool = False
    is_columnar: bool = False


@dataclass
class MibParser:
    """Two-phase parser: phase 1 collects raw definitions from each MIB,
    phase 2 resolves symbol names to dotted OIDs.

    Resolution uses the well-known roots plus all symbols defined across
    all parsed MIBs. Symbols that can't be resolved (typically because they
    reference imports we never saw) are skipped with a warning.
    """
    defs: dict[str, _RawDef] = field(default_factory=dict)
    parse_warnings: list[str] = field(default_factory=list)

    def parse(self, mib_text: str, source_mib: str) -> int:
        """Parse one MIB's text, accumulating definitions. Returns count added."""
        mib_text = self._strip_comments(mib_text)
        added = 0
        # OBJECT-TYPE and OBJECT-IDENTITY produce managed objects with bodies
        for regex, is_obj_type in (
            (_OBJECT_TYPE_RE, True),
            (_OBJECT_IDENTITY_RE, False),
            (_MODULE_IDENTITY_RE, False),
        ):
            for m in regex.finditer(mib_text):
                name = m.group("name")
                if name in self.defs:
                    continue  # first-write wins (typically the canonical MIB)
                body = m.group("body") or ""
                rd = _RawDef(
                    name=name,
                    parent=m.group("parent"),
                    index=int(m.group("index")),
                    source_mib=source_mib,
                    is_object_type=is_obj_type,
                )
                if is_obj_type:
                    self._extract_object_type_fields(rd, body)
                self.defs[name] = rd
                added += 1
        # Bare OBJECT IDENTIFIER nodes
        for m in _OID_NODE_RE.finditer(mib_text):
            name = m.group("name")
            if name in self.defs:
                continue
            self.defs[name] = _RawDef(
                name=name,
                parent=m.group("parent"),
                index=int(m.group("index")),
                source_mib=source_mib,
                is_object_type=False,
            )
            added += 1
        return added

    def resolve(self) -> list[dict]:
        """Resolve all collected definitions to OidEntry-shaped dicts.

        Uses BFS over a parent→children adjacency map — O(N), not O(N²) like
        a fixed-point loop would be on 700K+ symbols.
        """
        resolved: dict[str, str] = dict(_WELL_KNOWN_ROOTS)
        # Build adjacency: parent name → list of (child name, index)
        children: dict[str, list[tuple[str, int]]] = {}
        for name, rd in self.defs.items():
            children.setdefault(rd.parent, []).append((name, rd.index))

        # BFS from each well-known root
        from collections import deque
        queue: deque[str] = deque(resolved.keys())
        while queue:
            parent = queue.popleft()
            parent_oid = resolved.get(parent)
            if parent_oid is None:
                continue
            for child_name, child_index in children.get(parent, ()):
                if child_name in resolved:
                    continue
                resolved[child_name] = f"{parent_oid}.{child_index}"
                queue.append(child_name)

        # Mark tables and columnar entries based on naming convention + parent
        out: list[dict] = []
        for name, rd in self.defs.items():
            oid = resolved.get(name)
            if oid is None:
                self.parse_warnings.append(
                    f"could not resolve {name!r} from {rd.source_mib} (parent {rd.parent!r} unknown)"
                )
                continue
            is_table = name.endswith("Table") or "SEQUENCE OF" in rd.syntax
            is_columnar = (
                self.defs.get(rd.parent) is not None
                and self.defs[rd.parent].name.endswith("Entry")
            )
            entry = {
                "oid": oid,
                "name": name,
                "mib": rd.source_mib,
                "syntax": rd.syntax,
                "access": rd.access,
                "description": rd.description,
            }
            if is_table:
                entry["is_table"] = True
            if is_columnar:
                entry["is_columnar"] = True
            out.append(entry)
        return out

    # ------------------------------------------------------------------

    @staticmethod
    def _strip_comments(text: str) -> str:
        """SMI comments are -- to end of line."""
        # Remove block comments (rare but seen) -- ... -- inline
        # Just strip line-tail comments to be safe.
        return re.sub(r"--[^\n]*", "", text)

    @staticmethod
    def _extract_object_type_fields(rd: _RawDef, body: str) -> None:
        m = _SYNTAX_RE.search(body)
        if m:
            syntax = m.group(1).strip()
            # Compress whitespace
            rd.syntax = re.sub(r"\s+", " ", syntax)[:200]
        m = _ACCESS_RE.search(body)
        if m:
            rd.access = m.group(1).strip()
        m = _DESCRIPTION_RE.search(body)
        if m:
            desc = m.group(1).strip().replace('""', '"')
            rd.description = re.sub(r"\s+", " ", desc)[:1000]


def parse_mibs(sources: Iterable[tuple[str, str]]) -> tuple[list[dict], list[str]]:
    """Convenience: parse all (source_name, mib_text) tuples and return resolved entries + warnings."""
    parser = MibParser()
    for source, text in sources:
        try:
            parser.parse(text, source)
        except Exception as e:
            parser.parse_warnings.append(f"{source}: parser error {type(e).__name__}: {e}")
    entries = parser.resolve()
    return entries, parser.parse_warnings


__all__ = ["MibParser", "parse_mibs"]
