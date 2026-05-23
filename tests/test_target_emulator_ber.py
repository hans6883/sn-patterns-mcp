"""BER encoder/decoder round-trip tests for sn_patterns_mcp.target_emulator.snmp_v2c."""
from __future__ import annotations

import pytest

from sn_patterns_mcp.target_emulator import snmp_v2c as s

# ---------------------------------------------------------------------------
# Length encoding
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("n", [0, 1, 127, 128, 255, 256, 65535, 65536, 1 << 24])
def test_length_roundtrip(n):
    encoded = s._encode_length(n)
    out, off = s._decode_length(encoded, 0)
    assert out == n
    assert off == len(encoded)


def test_length_short_form_below_128():
    assert s._encode_length(0) == b"\x00"
    assert s._encode_length(127) == b"\x7f"


def test_length_long_form_at_128():
    assert s._encode_length(128) == b"\x81\x80"


def test_indefinite_length_rejected():
    with pytest.raises(s.SnmpDecodeError):
        s._decode_length(b"\x80", 0)


# ---------------------------------------------------------------------------
# Integer encoding (X.690 §8.3 — minimal length, two's complement)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("v,expected", [
    (0, b"\x00"),
    (1, b"\x01"),
    (127, b"\x7f"),
    (128, b"\x00\x80"),   # leading 00 to preserve positive sign
    (255, b"\x00\xff"),
    (256, b"\x01\x00"),
    (-1, b"\xff"),
    (-128, b"\x80"),
    (-129, b"\xff\x7f"),
])
def test_signed_integer_encoding(v, expected):
    raw = s._encode_signed_int(v)
    assert raw == expected
    out = s._decode_signed_int(raw, 0, len(raw))
    assert out == v


# ---------------------------------------------------------------------------
# OID encoding
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("dotted", [
    "1.3.6.1.2.1.1.5",
    "1.3.6.1.2.1.1.5.0",
    "1.3.6.1.4.1.9.9.13.1.3.1.3",
    "0.0",
    "2.16.840.1.101.3.4.2.1",   # SHA-256 OID — covers >127 subids
    # Regression: first subid > 127 (joint-iso-itu-t arc 2 with arc1 >= 48)
    # encodes as multi-byte continuation; the decoder must accumulate before
    # splitting into (arc0, arc1).
    "2.50",
    "2.999.1",
    "2.100.200.300",
])
def test_oid_roundtrip(dotted):
    raw = s._encode_oid(dotted)
    out = s._decode_oid(raw, 0, len(raw))
    assert out == dotted


def test_oid_first_two_arcs_combined():
    # 1.3 → first byte = 1*40+3 = 43 = 0x2B
    raw = s._encode_oid("1.3")
    assert raw == b"\x2b"


def test_oid_large_subid_uses_continuation_bytes():
    raw = s._encode_oid("1.3.840")
    # 840 = 0x348 → high 7 bits=0x06, low 7 bits=0x48 → encoded 0x86 0x48
    assert raw[-2:] == b"\x86\x48"


def test_oid_rejects_invalid_first_arc():
    with pytest.raises(ValueError):
        s._encode_oid("3.0")


# ---------------------------------------------------------------------------
# Application types
# ---------------------------------------------------------------------------

def test_ip_address_encoding():
    raw = s.enc_ip_address("10.0.0.1")
    # tag=0x40, length=0x04, then four address bytes
    assert raw == b"\x40\x04\x0a\x00\x00\x01"


def test_ip_address_rejects_bad_octet():
    with pytest.raises(ValueError):
        s.enc_ip_address("10.0.0.999")


def test_counter32_uses_app_tag_1():
    raw = s.enc_counter32(1)
    assert raw[0] == 0x41


def test_counter32_wraps_high_bit_with_leading_zero():
    raw = s.enc_counter32(0x80000000)
    # Tag 0x41, length 0x05, then 0x00 0x80 0x00 0x00 0x00 (leading zero
    # preserves the unsigned interpretation)
    assert raw == b"\x41\x05\x00\x80\x00\x00\x00"


def test_no_such_object_zero_length_null_with_context_tag_0():
    assert s.enc_no_such_object() == b"\x80\x00"


def test_end_of_mib_view_zero_length_null_with_context_tag_2():
    assert s.enc_end_of_mib_view() == b"\x82\x00"


# ---------------------------------------------------------------------------
# Whole-message round-trip
# ---------------------------------------------------------------------------

def test_get_request_roundtrip():
    msg = s.SnmpMessage(
        version=s.SNMP_V2C_VERSION,
        community="public",
        pdu_type=s.T_GET_REQUEST,
        request_id=42,
        error_status=0,
        error_index=0,
        varbinds=[s.VarBind.null("1.3.6.1.2.1.1.5.0")],
    )
    wire = s.encode_message(msg)
    parsed = s.decode_message(wire)
    assert parsed.version == s.SNMP_V2C_VERSION
    assert parsed.community == "public"
    assert parsed.pdu_type == s.T_GET_REQUEST
    assert parsed.request_id == 42
    assert len(parsed.varbinds) == 1
    assert parsed.varbinds[0].oid == "1.3.6.1.2.1.1.5.0"


def test_response_with_octet_string_varbind_roundtrip():
    msg = s.SnmpMessage(
        version=s.SNMP_V2C_VERSION,
        community="public",
        pdu_type=s.T_RESPONSE,
        request_id=99,
        error_status=0,
        error_index=0,
        varbinds=[
            s.VarBind(oid="1.3.6.1.2.1.1.5.0",
                      value_bytes=s.enc_octet_string("demo-router-01")),
        ],
    )
    wire = s.encode_message(msg)
    parsed = s.decode_message(wire)
    assert parsed.pdu_type == s.T_RESPONSE
    assert parsed.request_id == 99
    assert parsed.varbinds[0].oid == "1.3.6.1.2.1.1.5.0"
    # The varbind value is still raw TLV bytes — decode the OCTET STRING
    assert parsed.varbinds[0].value_bytes == s.enc_octet_string("demo-router-01")
