"""Target-emulator catalog and blueprint tests."""
from __future__ import annotations

import json

from sn_patterns_mcp.tools import emulator_blueprint, emulator_catalog

_WMI_NDL = r'''pattern {
    metadata {
        id = "00000000000000000000000000000077"
        name = "Windows Emulator Contract"
        citype = "cmdb_ci_win_server"
    }
    identification {
        name = "i"
        find_process_strategy {strategy = NONE}
        step {
            name = "get OS info"
            run_wmi_query_to_var {
                query = "SELECT Caption, Version FROM Win32_OperatingSystem"
                namespace = "root\cimv2"
                var_names = "os_info"
            }
        }
        step {
            name = "run hostname"
            runcmd_to_var {
                cmd = "hostname"
                var_names = "host"
            }
        }
    }
}'''


_SNMP_NDL = r'''pattern {
    metadata {
        id = "00000000000000000000000000000088"
        name = "SNMP Emulator Contract"
        citype = "cmdb_ci_netgear"
    }
    identification {
        name = "i"
        find_process_strategy {strategy = NONE}
        step {
            name = "get sysName"
            run_snmp_to_var {
                oid = "1.3.6.1.2.1.1.5"
                var_names = "hostname"
            }
        }
    }
}'''


def test_emulator_catalog_windows_includes_precise_wmi_ports() -> None:
    payload = json.loads(emulator_catalog(target="windows"))
    profile = payload["matches"][0]
    ports = {(p["protocol"], tuple(p["ports"])) for p in profile["ports"]}

    assert ("tcp", (135,)) in ports
    assert ("tcp", ("49152-65535",)) in ports
    assert ("tcp", (5985, 5986)) in ports


def test_emulator_catalog_alias_resolves_netscaler() -> None:
    payload = json.loads(emulator_catalog(target="citrix-adc"))

    assert payload["matches"][0]["target"] == "netscaler"
    assert payload["matches"][0]["mib_enterprises"] == ["1.3.6.1.4.1.5951"]


def test_emulator_blueprint_infers_windows_and_lists_pattern_fixtures() -> None:
    payload = json.loads(emulator_blueprint(ndl=_WMI_NDL))
    listener_services = {p["service"] for p in payload["required_listeners"]}

    assert payload["target_profile"]["target"] == "windows"
    assert "MSRPC endpoint mapper" in listener_services
    assert "MSRPC dynamic range" in listener_services
    assert payload["fixtures"]["wmi"][0]["query"] == "SELECT Caption, Version FROM Win32_OperatingSystem"
    assert payload["fixtures"]["commands"][0]["command"] == "hostname"
    assert payload["execution_contract"]["strict_mode"] is True


def test_emulator_blueprint_resolves_snmp_oid_fixture() -> None:
    payload = json.loads(emulator_blueprint(ndl=_SNMP_NDL))
    snmp = payload["fixtures"]["snmp"][0]

    assert payload["target_profile"]["target"] == "generic-snmp"
    assert snmp["oid"] == "1.3.6.1.2.1.1.5"
    assert snmp["name"] == "sysName"
    assert "mib" in snmp


def test_emulator_blueprint_accepts_mib_only_target() -> None:
    payload = json.loads(emulator_blueprint(target="snmp", oids=["1.3.6.1.2.1.2.2.1.5.42"]))
    snmp = payload["fixtures"]["snmp"][0]

    assert payload["target_profile"]["target"] == "generic-snmp"
    assert snmp["name"] == "ifSpeed"
    assert snmp["is_columnar"] is True


def test_emulator_blueprint_unknown_target_is_actionable_error() -> None:
    out = emulator_blueprint(target="made-up-appliance")

    assert out.startswith("ERROR:")
    assert "Known targets:" in out
