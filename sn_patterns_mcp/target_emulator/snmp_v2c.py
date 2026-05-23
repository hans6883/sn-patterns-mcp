"""Minimal hand-rolled SNMPv2c responder for Tier-3 sandbox testing.

Scope (intentional):
    * Receive GetRequest-PDU and GetNextRequest-PDU
    * Reply with Response-PDU
    * Encode the SNMPv2 simple types: INTEGER, OCTET STRING, NULL,
      OBJECT IDENTIFIER
    * Encode the application types: IpAddress, Counter32, Gauge32,
      TimeTicks, Counter64
    * v2c exception varbind values: noSuchObject, noSuchInstance, endOfMibView

Out of scope (deferred or by-design):
    * GetBulkRequest (Phase 3 may add)
    * SetRequest / InformRequest / Trap (sandbox is read-only)
    * SNMPv1, SNMPv3 (community-string + v2c is the SN Discovery default)
    * MIB compilation (we receive OIDs as dotted strings; fixtures supply values)

Why hand-rolled BER instead of pysnmp: this is a deterministic sandbox;
every byte we emit has to be predictable so a Phase 3 replay diff is
meaningful. pysnmp has its own dispatcher loops and quirks that make the
exact wire output sensitive to its internal state. We need ~300 LOC of
focused BER for the narrow protocol slice the sandbox actually answers.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

# ASN.1 BER tag bytes ---------------------------------------------------------
T_INTEGER = 0x02
T_OCTET_STRING = 0x04
T_NULL = 0x05
T_OID = 0x06
T_SEQUENCE = 0x30                # constructed UNIVERSAL 16

# APPLICATION class tags (constructed bit clear; primitive encoding)
T_IP_ADDRESS = 0x40              # [APPLICATION 0] IMPLICIT OCTET STRING(4)
T_COUNTER32 = 0x41               # [APPLICATION 1] IMPLICIT INTEGER 0..2^32-1
T_GAUGE32 = 0x42                 # [APPLICATION 2] IMPLICIT INTEGER 0..2^32-1
T_TIMETICKS = 0x43               # [APPLICATION 3] IMPLICIT INTEGER 0..2^32-1
T_COUNTER64 = 0x46               # [APPLICATION 6] IMPLICIT INTEGER 0..2^64-1

# CONTEXT class tags (constructed bit set for the request/response PDUs)
T_GET_REQUEST = 0xA0             # [0] IMPLICIT PDU
T_GETNEXT_REQUEST = 0xA1         # [1] IMPLICIT PDU
T_RESPONSE = 0xA2                # [2] IMPLICIT PDU

# v2c varbind exception values are CONTEXT-tagged NULLs (primitive)
T_NO_SUCH_OBJECT = 0x80          # [0] IMPLICIT NULL
T_NO_SUCH_INSTANCE = 0x81        # [1] IMPLICIT NULL
T_END_OF_MIB_VIEW = 0x82         # [2] IMPLICIT NULL

# Error-status codes (RFC 3416 §3)
ERR_NO_ERROR = 0
ERR_TOO_BIG = 1
ERR_GEN_ERR = 5

# SNMPv2c version field value is INTEGER 1.
SNMP_V2C_VERSION = 1


# ---------------------------------------------------------------------------
# BER length encoding / decoding
# ---------------------------------------------------------------------------

def _encode_length(n: int) -> bytes:
    if n < 0:
        raise ValueError("length must be non-negative")
    if n < 0x80:
        return bytes([n])
    out = b""
    while n:
        out = bytes([n & 0xFF]) + out
        n >>= 8
    return bytes([0x80 | len(out)]) + out


def _decode_length(buf: bytes, offset: int) -> tuple[int, int]:
    """Return (length, new_offset)."""
    if offset >= len(buf):
        raise SnmpDecodeError("truncated length")
    first = buf[offset]
    offset += 1
    if first < 0x80:
        return first, offset
    nbytes = first & 0x7F
    if nbytes == 0:
        raise SnmpDecodeError("indefinite length not supported")
    if offset + nbytes > len(buf):
        raise SnmpDecodeError("truncated long-form length")
    length = 0
    for b in buf[offset:offset + nbytes]:
        length = (length << 8) | b
    return length, offset + nbytes


def _wrap(tag: int, payload: bytes) -> bytes:
    return bytes([tag]) + _encode_length(len(payload)) + payload


# ---------------------------------------------------------------------------
# Integer encoding (signed, two's complement, minimal length)
# ---------------------------------------------------------------------------

def _encode_signed_int(value: int) -> bytes:
    """Two's-complement minimal-length encoding per X.690 §8.3.

    Encode at a generous width, then trim redundant leading bytes:
    drop a leading 0x00 if the next byte's high bit is 0 (positive
    preserved), or a leading 0xFF if the next byte's high bit is 1
    (negative preserved). This is the canonical minimal encoding.
    """
    if value == 0:
        return b"\x00"
    # A safe upper bound for the byte count: handles positives via .bit_length()
    # and the awkward -2^k boundary via `-value - 1`.
    headroom = max(value if value > 0 else -value - 1, 1).bit_length() + 1
    nbytes = (headroom + 7) // 8
    raw = value.to_bytes(nbytes, "big", signed=True)
    while len(raw) > 1:
        if raw[0] == 0x00 and (raw[1] & 0x80) == 0:
            raw = raw[1:]
        elif raw[0] == 0xFF and (raw[1] & 0x80) != 0:
            raw = raw[1:]
        else:
            break
    return raw


def _encode_unsigned_int(value: int) -> bytes:
    """Encode an unsigned integer for SNMP application types.

    Application types are nominally INTEGER but constrained to a non-negative
    range. We still write a leading 0x00 byte when the natural encoding's
    high bit is set, so a decoder reading it as a signed INTEGER yields the
    correct positive value.
    """
    if value < 0:
        raise ValueError("unsigned encoding for negative value")
    if value == 0:
        return b"\x00"
    nbytes = (value.bit_length() + 7) // 8
    raw = value.to_bytes(nbytes, "big")
    if raw[0] & 0x80:
        raw = b"\x00" + raw
    return raw


def _decode_signed_int(buf: bytes, offset: int, length: int) -> int:
    if length == 0:
        return 0
    return int.from_bytes(buf[offset:offset + length], "big", signed=True)


# ---------------------------------------------------------------------------
# OID encoding / decoding
# ---------------------------------------------------------------------------

def _encode_oid(dotted: str) -> bytes:
    parts = [int(p) for p in dotted.strip().split(".") if p != ""]
    if len(parts) < 2:
        raise ValueError(f"OID must have at least two arcs: {dotted!r}")
    if parts[0] not in (0, 1, 2):
        raise ValueError(f"first OID arc must be 0, 1, or 2: {dotted!r}")
    if parts[0] in (0, 1) and parts[1] >= 40:
        raise ValueError(f"second OID arc must be < 40 when first is 0 or 1: {dotted!r}")
    first = parts[0] * 40 + parts[1]
    body = _encode_subid(first)
    for arc in parts[2:]:
        if arc < 0:
            raise ValueError(f"negative OID arc in {dotted!r}")
        body += _encode_subid(arc)
    return body


def _encode_subid(n: int) -> bytes:
    if n < 0:
        raise ValueError("subid negative")
    if n == 0:
        return b"\x00"
    out: list[int] = []
    while n:
        out.append(n & 0x7F)
        n >>= 7
    out.reverse()
    # Set continuation bit on all but the last byte
    return bytes([(b | 0x80) for b in out[:-1]] + [out[-1]])


def _decode_oid(buf: bytes, offset: int, length: int) -> str:
    end = offset + length
    if end > len(buf):
        raise SnmpDecodeError("truncated OID")
    if length == 0:
        return ""
    parts: list[int] = []

    # The first subid is `40*arc0 + arc1` and is itself base-128 encoded with
    # continuation bits — so it may span multiple bytes when arc0=2 and arc1
    # is large enough (e.g. 2.50 → first_subid=130 → \x81\x02). Accumulate
    # continuation bytes BEFORE splitting into (arc0, arc1).
    i = offset
    acc = 0
    first_subid: int | None = None
    while i < end:
        b = buf[i]
        acc = (acc << 7) | (b & 0x7F)
        if not (b & 0x80):
            first_subid = acc
            i += 1
            break
        i += 1
    if first_subid is None:
        raise SnmpDecodeError("truncated OID first subid")
    if first_subid < 80:
        parts.extend((first_subid // 40, first_subid % 40))
    else:
        parts.extend((2, first_subid - 80))

    # Subsequent subids follow the same base-128 continuation-bit rule.
    acc = 0
    while i < end:
        b = buf[i]
        acc = (acc << 7) | (b & 0x7F)
        if not (b & 0x80):
            parts.append(acc)
            acc = 0
        i += 1
    return ".".join(str(p) for p in parts)


# ---------------------------------------------------------------------------
# High-level encoders
# ---------------------------------------------------------------------------

def enc_integer(value: int) -> bytes:
    return _wrap(T_INTEGER, _encode_signed_int(value))


def enc_octet_string(value: str | bytes) -> bytes:
    raw = value.encode("utf-8") if isinstance(value, str) else value
    return _wrap(T_OCTET_STRING, raw)


def enc_null() -> bytes:
    return _wrap(T_NULL, b"")


def enc_oid(dotted: str) -> bytes:
    return _wrap(T_OID, _encode_oid(dotted))


def enc_counter32(value: int) -> bytes:
    return _wrap(T_COUNTER32, _encode_unsigned_int(value & 0xFFFFFFFF))


def enc_counter64(value: int) -> bytes:
    return _wrap(T_COUNTER64, _encode_unsigned_int(value & 0xFFFFFFFFFFFFFFFF))


def enc_gauge32(value: int) -> bytes:
    return _wrap(T_GAUGE32, _encode_unsigned_int(value & 0xFFFFFFFF))


def enc_timeticks(value: int) -> bytes:
    return _wrap(T_TIMETICKS, _encode_unsigned_int(value & 0xFFFFFFFF))


def enc_ip_address(value: str | bytes) -> bytes:
    if isinstance(value, str):
        parts = [int(p) for p in value.split(".")]
        if len(parts) != 4 or any(p < 0 or p > 255 for p in parts):
            raise ValueError(f"invalid IpAddress: {value!r}")
        raw = bytes(parts)
    else:
        raw = bytes(value)
        if len(raw) != 4:
            raise ValueError("IpAddress must be 4 bytes")
    return _wrap(T_IP_ADDRESS, raw)


def enc_no_such_object() -> bytes:
    return _wrap(T_NO_SUCH_OBJECT, b"")


def enc_no_such_instance() -> bytes:
    return _wrap(T_NO_SUCH_INSTANCE, b"")


def enc_end_of_mib_view() -> bytes:
    return _wrap(T_END_OF_MIB_VIEW, b"")


def encode_value(snmp_type: str, value: Any) -> bytes:
    """Encode a Python value as the BER bytes for the named SNMP type."""
    t = snmp_type.strip()
    if t in ("OCTET STRING", "DisplayString"):
        return enc_octet_string(value if isinstance(value, (str, bytes)) else str(value))
    if t in ("Integer32", "INTEGER"):
        return enc_integer(int(value))
    if t == "Counter32":
        return enc_counter32(int(value))
    if t == "Counter64":
        return enc_counter64(int(value))
    if t in ("Gauge32", "Unsigned32"):
        return enc_gauge32(int(value))
    if t == "TimeTicks":
        return enc_timeticks(int(value))
    if t == "IpAddress":
        return enc_ip_address(value)
    if t == "OBJECT IDENTIFIER":
        return enc_oid(str(value))
    if t == "NULL":
        return enc_null()
    # Unknown type — last-resort OCTET STRING so we still produce a valid response
    return enc_octet_string(str(value))


# ---------------------------------------------------------------------------
# SNMP message-level structures
# ---------------------------------------------------------------------------

class SnmpDecodeError(Exception):
    pass


@dataclass(frozen=True)
class VarBind:
    """One (OID, value-bytes-or-NULL) pair inside a PDU."""

    oid: str
    value_bytes: bytes  # encoded TLV; NULL for requests, real value for responses

    @staticmethod
    def null(oid: str) -> VarBind:
        return VarBind(oid=oid, value_bytes=enc_null())


@dataclass
class SnmpMessage:
    version: int
    community: str
    pdu_type: int                  # T_GET_REQUEST | T_GETNEXT_REQUEST | T_RESPONSE
    request_id: int
    error_status: int
    error_index: int
    varbinds: list[VarBind]

    def is_get(self) -> bool:
        return self.pdu_type == T_GET_REQUEST

    def is_getnext(self) -> bool:
        return self.pdu_type == T_GETNEXT_REQUEST

    def is_response(self) -> bool:
        return self.pdu_type == T_RESPONSE


def encode_message(msg: SnmpMessage) -> bytes:
    """Serialize an SnmpMessage to BER bytes ready for the wire."""
    vb_list = b"".join(_wrap(T_SEQUENCE, enc_oid(v.oid) + v.value_bytes) for v in msg.varbinds)
    vb_seq = _wrap(T_SEQUENCE, vb_list)
    pdu_body = (
        enc_integer(msg.request_id)
        + enc_integer(msg.error_status)
        + enc_integer(msg.error_index)
        + vb_seq
    )
    pdu = _wrap(msg.pdu_type, pdu_body)
    outer = enc_integer(msg.version) + enc_octet_string(msg.community) + pdu
    return _wrap(T_SEQUENCE, outer)


def decode_message(raw: bytes) -> SnmpMessage:
    """Parse BER bytes from the wire into an SnmpMessage."""
    if not raw or raw[0] != T_SEQUENCE:
        raise SnmpDecodeError("not a SEQUENCE at top level")
    body, _ = _expect_sequence(raw, 0)

    version, off = _expect_integer(body, 0)
    community, off = _expect_octet_string(body, off)
    if off >= len(body):
        raise SnmpDecodeError("missing PDU")
    pdu_type = body[off]
    if pdu_type not in (T_GET_REQUEST, T_GETNEXT_REQUEST, T_RESPONSE):
        raise SnmpDecodeError(f"unsupported PDU type 0x{pdu_type:02x}")
    length, off = _decode_length(body, off + 1)
    pdu_body = body[off:off + length]

    request_id, off2 = _expect_integer(pdu_body, 0)
    error_status, off2 = _expect_integer(pdu_body, off2)
    error_index, off2 = _expect_integer(pdu_body, off2)
    vb_list_body, _ = _expect_sequence(pdu_body, off2)

    varbinds: list[VarBind] = []
    vboff = 0
    while vboff < len(vb_list_body):
        vb_body, vb_next = _expect_sequence(vb_list_body, vboff)
        oid, after_oid = _expect_oid(vb_body, 0)
        value_bytes = vb_body[after_oid:]
        varbinds.append(VarBind(oid=oid, value_bytes=value_bytes))
        vboff = vb_next

    return SnmpMessage(
        version=version,
        community=community,
        pdu_type=pdu_type,
        request_id=request_id,
        error_status=error_status,
        error_index=error_index,
        varbinds=varbinds,
    )


def _expect_tag(buf: bytes, offset: int, expected: int) -> tuple[bytes, int]:
    if offset >= len(buf) or buf[offset] != expected:
        raise SnmpDecodeError(f"expected tag 0x{expected:02x} at offset {offset}")
    length, new_off = _decode_length(buf, offset + 1)
    end = new_off + length
    if end > len(buf):
        raise SnmpDecodeError("truncated TLV")
    return buf[new_off:end], end


def _expect_sequence(buf: bytes, offset: int) -> tuple[bytes, int]:
    return _expect_tag(buf, offset, T_SEQUENCE)


def _expect_integer(buf: bytes, offset: int) -> tuple[int, int]:
    body, next_off = _expect_tag(buf, offset, T_INTEGER)
    return _decode_signed_int(body, 0, len(body)), next_off


def _expect_octet_string(buf: bytes, offset: int) -> tuple[str, int]:
    body, next_off = _expect_tag(buf, offset, T_OCTET_STRING)
    try:
        return body.decode("utf-8"), next_off
    except UnicodeDecodeError:
        return body.decode("latin-1"), next_off


def _expect_oid(buf: bytes, offset: int) -> tuple[str, int]:
    body, next_off = _expect_tag(buf, offset, T_OID)
    return _decode_oid(body, 0, len(body)), next_off


# ---------------------------------------------------------------------------
# Response building
# ---------------------------------------------------------------------------

def build_response(
    request: SnmpMessage,
    *,
    resolver,
) -> SnmpMessage:
    """Build a Response-PDU answering a Get / GetNext request.

    `resolver` is a callable:
        resolver(pdu_type: int, oid: str) -> (resolved_oid: str | None, value_bytes: bytes)

    For T_GET_REQUEST it should return exactly the requested OID (or a v2c
    exception varbind if not present). For T_GETNEXT_REQUEST it should
    return the lexicographically next OID it knows about, or end-of-MIB-view.
    """
    if request.pdu_type not in (T_GET_REQUEST, T_GETNEXT_REQUEST):
        # Defensive — shouldn't happen for incoming traffic
        return SnmpMessage(
            version=request.version,
            community=request.community,
            pdu_type=T_RESPONSE,
            request_id=request.request_id,
            error_status=ERR_GEN_ERR,
            error_index=1,
            varbinds=list(request.varbinds),
        )

    out: list[VarBind] = []
    for vb in request.varbinds:
        resolved_oid, value_bytes = resolver(request.pdu_type, vb.oid)
        if resolved_oid is None:
            # v2c convention: report exception in the varbind, not as PDU-level error
            out.append(VarBind(oid=vb.oid, value_bytes=value_bytes))
        else:
            out.append(VarBind(oid=resolved_oid, value_bytes=value_bytes))

    return SnmpMessage(
        version=request.version,
        community=request.community,
        pdu_type=T_RESPONSE,
        request_id=request.request_id,
        error_status=ERR_NO_ERROR,
        error_index=0,
        varbinds=out,
    )
