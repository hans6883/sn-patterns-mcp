"""Blueprint → SNMP fixture table.

Reads the `fixtures.snmp` section of a blueprint emitted by
`sn_patterns_mcp.emulator.blueprint(...)` and produces a flat list of
`SnmpFixtureEntry` records the responder can serve.

When the blueprint leaves a `value` field as the literal placeholder
`<scenario-value>`, this module infers a deterministic stub value from the
declared MIB SYNTAX. That keeps the emulator usable from a single
`emulator_blueprint` call without forcing the caller to hand-author every
value, while still allowing explicit overrides.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

# Canonical SNMP types the responder knows how to encode.
SNMP_TYPES = (
    "OCTET STRING",
    "Integer32",
    "Counter32",
    "Gauge32",
    "TimeTicks",
    "IpAddress",
    "OBJECT IDENTIFIER",
    "Counter64",
)

# Mapping from MIB SYNTAX keyword (anything starting with the key)
# to (default_value, canonical_snmp_type).
_SYNTAX_DEFAULTS: tuple[tuple[str, tuple[Any, str]], ...] = (
    ("DisplayString", ("stub-display", "OCTET STRING")),
    ("OCTET STRING", ("<stub>", "OCTET STRING")),
    ("Integer32", (0, "Integer32")),
    ("INTEGER", (0, "Integer32")),
    ("Counter32", (0, "Counter32")),
    ("Counter64", (0, "Counter64")),
    ("Gauge32", (0, "Gauge32")),
    ("Unsigned32", (0, "Gauge32")),
    ("TimeTicks", (0, "TimeTicks")),
    ("IpAddress", ("0.0.0.0", "IpAddress")),
    ("OBJECT IDENTIFIER", ("0.0", "OBJECT IDENTIFIER")),
)


@dataclass(frozen=True)
class SnmpFixtureEntry:
    """One OID → value mapping the emulator will serve.

    Attributes:
        oid: canonical dotted OID, e.g. "1.3.6.1.2.1.1.5.0"
        value: Python-native value; encoder will convert per `snmp_type`
        snmp_type: one of SNMP_TYPES
        name: optional human label (for recording readability)
    """

    oid: str
    value: Any
    snmp_type: str
    name: str = ""


def infer_default(syntax: str) -> tuple[Any, str]:
    """Return a deterministic (default_value, snmp_type) for a MIB SYNTAX string.

    `syntax` may carry trailing constraints like "OCTET STRING (SIZE (0..255))";
    we match on the leading type keyword.
    """
    if not syntax:
        return ("<stub>", "OCTET STRING")
    head = syntax.split("(")[0].strip()
    for prefix, default in _SYNTAX_DEFAULTS:
        if head.startswith(prefix):
            return default
    # Unknown syntax — render as octet string so we always produce a valid wire response.
    return ("<stub>", "OCTET STRING")


def fixtures_from_blueprint(blueprint: dict[str, Any]) -> list[SnmpFixtureEntry]:
    """Convert a blueprint's fixtures.snmp section into SnmpFixtureEntry records.

    Skips entries where the OID is dynamic (contains a NDL variable like "$foo")
    or is empty. Honors caller-supplied `value` when it's a real value (not the
    placeholder `<scenario-value>`).
    """
    raw = (blueprint.get("fixtures") or {}).get("snmp") or []
    out: list[SnmpFixtureEntry] = []
    for f in raw:
        oid = (f.get("oid") or "").strip()
        if not oid or "$" in oid:
            continue
        syntax = f.get("syntax", "")
        explicit_value = f.get("value")
        if isinstance(explicit_value, str) and explicit_value not in ("", "<scenario-value>"):
            value: Any = explicit_value
            snmp_type = f.get("snmp_type") or _type_for(syntax)
        elif isinstance(explicit_value, (int, list, bool)) and explicit_value not in (None,):
            value = explicit_value
            snmp_type = f.get("snmp_type") or _type_for(syntax)
        else:
            value, snmp_type = infer_default(syntax)
        out.append(SnmpFixtureEntry(
            oid=oid,
            value=value,
            snmp_type=snmp_type,
            name=f.get("name", "") or "",
        ))
    return out


def _type_for(syntax: str) -> str:
    _, snmp_type = infer_default(syntax)
    return snmp_type
