"""Target-emulator catalog and blueprint generation.

This module does not start listeners itself. It defines the precise contract a
sidecar/helper MCP would implement so an agent can test a ServiceNow Discovery
pattern against deterministic target responses instead of a live device.
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from typing import Any

from sn_patterns_mcp.pattern_model import Operation, Pattern


@dataclass(frozen=True)
class EmulatedPort:
    protocol: str
    ports: tuple[int | str, ...]
    service: str
    purpose: str
    required_for: tuple[str, ...] = ()
    notes: str = ""


@dataclass(frozen=True)
class EmulatedProfile:
    target: str
    aliases: tuple[str, ...]
    display_name: str
    description: str
    data_source_target: str | None
    ports: tuple[EmulatedPort, ...]
    mib_enterprises: tuple[str, ...] = ()
    fidelity_notes: tuple[str, ...] = ()


PROFILES: tuple[EmulatedProfile, ...] = (
    EmulatedProfile(
        target="windows",
        aliases=("win", "windows-server", "cmdb_ci_win_server"),
        display_name="Windows Server",
        description="Windows host surface for WMI/DCOM, WinRM, SMB/registry, PowerShell command, and SNMP tests.",
        data_source_target="windows",
        mib_enterprises=("1.3.6.1.4.1.311",),
        ports=(
            EmulatedPort("tcp", (135,), "MSRPC endpoint mapper", "DCOM bootstrap for WMI", ("run_wmi_query_to_var",)),
            EmulatedPort("tcp", ("49152-65535",), "MSRPC dynamic range", "WMI/DCOM object channels", ("run_wmi_query_to_var",),
                         "Use a narrowed deterministic sub-range in CI only if the MID pattern is configured to match it."),
            EmulatedPort("tcp", (445,), "SMB / remote registry", "Registry and admin-share style probes", ("find_registry_val_to_var",)),
            EmulatedPort("tcp", (5985, 5986), "WinRM", "PowerShell remoting over HTTP/HTTPS", ("runcmd_to_var",)),
            EmulatedPort("udp", (161, 162), "SNMP agent / traps", "Windows SNMP scalar and table responses", ("run_snmp_to_var", "run_snmp_walk_to_var")),
        ),
        fidelity_notes=(
            "WMI namespace, class, selected fields, row order, and timeout behavior must be fixture-controlled.",
            "DCOM dynamic ports are part of the target contract; hiding them changes discovery behavior.",
        ),
    ),
    EmulatedProfile(
        target="linux",
        aliases=("unix", "unix-server", "linux-server", "cmdb_ci_linux_server", "cmdb_ci_unix_server"),
        display_name="Linux / Unix Server",
        description="POSIX host surface for SSH command, file parse, process, package, network, and SNMP tests.",
        data_source_target="linux",
        mib_enterprises=("1.3.6.1.4.1.8072",),
        ports=(
            EmulatedPort("tcp", (22,), "SSH", "Shell command execution and file reads", ("runcmd_to_var", "parse_text_file_to_var")),
            EmulatedPort("tcp", (23,), "Telnet", "Legacy shell command execution when patterns still use telnet credentials", ("runcmd_to_var",)),
            EmulatedPort("udp", (161, 162), "SNMP agent / traps", "Host Resources, interface, process, and vendor SNMP", ("run_snmp_to_var", "run_snmp_walk_to_var")),
        ),
        fidelity_notes=(
            "Command fixtures must include stdout, stderr, exit status, locale, line endings, and execution timeout.",
            "Filesystem fixtures must preserve path case, symlink behavior, and permission-denied outcomes.",
        ),
    ),
    EmulatedProfile(
        target="f5",
        aliases=("big-ip", "bigip", "f5-bigip", "cmdb_ci_lb_f5"),
        display_name="F5 BIG-IP",
        description="F5 load balancer surface for tmsh, iControl REST, SSH, and F5-BIGIP MIB tests.",
        data_source_target="f5",
        mib_enterprises=("1.3.6.1.4.1.3375",),
        ports=(
            EmulatedPort("tcp", (22,), "SSH / tmsh", "tmsh command execution", ("runcmd_to_var",)),
            EmulatedPort("tcp", (443,), "iControl REST", "F5 REST inventory endpoints", ("http_invoke",)),
            EmulatedPort("tcp", (4353,), "iQuery", "BIG-IP device trust / GTM adjacency signal", ()),
            EmulatedPort("udp", (161, 162), "SNMP agent / traps", "F5-BIGIP MIB scalar and table responses", ("run_snmp_to_var", "run_snmp_walk_to_var")),
        ),
        fidelity_notes=(
            "tmsh output must preserve native table headings and continuation lines because patterns often parse text.",
            "SNMP and REST fixtures for the same object must agree on names, addresses, and partition paths.",
        ),
    ),
    EmulatedProfile(
        target="netscaler",
        aliases=("citrix-adc", "citrix-netscaler", "adc", "cmdb_ci_lb_netscaler"),
        display_name="Citrix ADC / NetScaler",
        description="Citrix ADC surface for nscli, NITRO REST, SSH, and NetScaler enterprise MIB tests.",
        data_source_target=None,
        mib_enterprises=("1.3.6.1.4.1.5951",),
        ports=(
            EmulatedPort("tcp", (22,), "SSH / nscli", "NetScaler CLI command execution", ("runcmd_to_var",)),
            EmulatedPort("tcp", (80, 443), "NITRO REST", "Citrix ADC REST inventory endpoints", ("http_invoke",)),
            EmulatedPort("udp", (161, 162), "SNMP agent / traps", "NS-ROOT-MIB and enterprise table responses", ("run_snmp_to_var", "run_snmp_walk_to_var")),
        ),
        fidelity_notes=(
            "NITRO JSON and SNMP table fixtures must use the same object identifiers and service names.",
        ),
    ),
    EmulatedProfile(
        target="cisco-ios",
        aliases=("cisco", "ios", "nx-os", "switch", "router", "cmdb_ci_ip_router", "cmdb_ci_ip_switch"),
        display_name="Cisco IOS / NX-OS",
        description="Cisco network-device surface for CLI, SNMP, NETCONF, SSH, and telnet discovery.",
        data_source_target="cisco-ios",
        mib_enterprises=("1.3.6.1.4.1.9",),
        ports=(
            EmulatedPort("tcp", (22,), "SSH", "show-command execution", ("runcmd_to_var",)),
            EmulatedPort("tcp", (23,), "Telnet", "Legacy show-command execution", ("runcmd_to_var",)),
            EmulatedPort("tcp", (830,), "NETCONF", "YANG/NETCONF device inventory where used", ("http_invoke",)),
            EmulatedPort("udp", (161, 162), "SNMP agent / traps", "Cisco enterprise and IETF MIB responses", ("run_snmp_to_var", "run_snmp_walk_to_var")),
        ),
        fidelity_notes=(
            "CLI prompts, privilege mode, paging markers, and command echo must be deterministic.",
        ),
    ),
    EmulatedProfile(
        target="esxi",
        aliases=("vmware-esxi", "vmware", "cmdb_ci_esx_server"),
        display_name="VMware ESXi",
        description="ESXi host surface for HTTPS API, SSH/esxcli, CIM/WBEM, and VMware MIB tests.",
        data_source_target="esxi",
        mib_enterprises=("1.3.6.1.4.1.6876",),
        ports=(
            EmulatedPort("tcp", (22,), "SSH / esxcli", "esxcli and vim-cmd command execution", ("runcmd_to_var",)),
            EmulatedPort("tcp", (443,), "vSphere HTTPS API", "SOAP/REST inventory calls", ("http_invoke",)),
            EmulatedPort("tcp", (5988, 5989), "CIM / WBEM", "Hardware and host inventory", ("http_invoke",)),
            EmulatedPort("udp", (161, 162), "SNMP agent / traps", "VMware enterprise MIB responses", ("run_snmp_to_var", "run_snmp_walk_to_var")),
        ),
        fidelity_notes=(
            "API and CLI fixtures must agree on host UUID, datastores, NICs, and VM identifiers.",
        ),
    ),
    EmulatedProfile(
        target="generic-snmp",
        aliases=("snmp", "mib", "mibs", "any-snmp"),
        display_name="Generic SNMP Device",
        description="MIB-driven SNMP surface for any device with a known OID tree.",
        data_source_target=None,
        mib_enterprises=(),
        ports=(
            EmulatedPort("udp", (161, 162), "SNMP agent / traps", "Scalar, table, GET-NEXT, and walk responses", ("run_snmp_to_var", "run_snmp_walk_to_var")),
        ),
        fidelity_notes=(
            "Every requested OID must resolve to a value, noSuchObject/noSuchInstance, or timeout exactly as declared.",
            "Columnar OID instances must preserve table index shape; this is what makes walks trustworthy.",
        ),
    ),
)

_PROFILES_BY_TARGET = {p.target: p for p in PROFILES}
_ALIAS_TO_TARGET = {alias: p.target for p in PROFILES for alias in (p.target, *p.aliases)}


def known_targets() -> list[str]:
    return [p.target for p in PROFILES]


def resolve_profile(target: str | None) -> EmulatedProfile | None:
    key = (target or "").strip().lower()
    if not key:
        return None
    return _PROFILES_BY_TARGET.get(_ALIAS_TO_TARGET.get(key, key))


def catalog(target: str | None = None, query: str | None = None) -> dict[str, Any]:
    """Return catalog entries filtered by target alias or text query."""
    q = (query or "").strip().lower()
    profiles = list(PROFILES)
    if target:
        profile = resolve_profile(target)
        profiles = [profile] if profile else []
    if q:
        profiles = [
            p for p in profiles
            if q in p.target
            or q in p.display_name.lower()
            or q in p.description.lower()
            or any(q in a for a in p.aliases)
            or any(q in port.service.lower() or q in port.purpose.lower() for port in p.ports)
        ]
    full_profiles = bool(target)
    return {
        "ok": True,
        "known_targets": known_targets(),
        "summary_only": not full_profiles,
        "matches": [_profile_payload(p) if full_profiles else _profile_summary(p) for p in profiles],
        "sidecar_mcp": _sidecar_contract(),
    }


def blueprint(
    *,
    target: str | None = None,
    pattern: Pattern | None = None,
    pattern_name: str = "",
    requested_oids: list[str] | None = None,
) -> dict[str, Any]:
    """Build a sidecar emulator blueprint for a target or concrete pattern."""
    observations = _pattern_observations(pattern) if pattern is not None else _empty_observations()
    inferred_target = target or _infer_target(pattern, observations)
    profile = resolve_profile(inferred_target) or resolve_profile("generic-snmp")
    assert profile is not None

    oid_inputs = list(requested_oids or [])
    for item in observations["snmp_oids"]:
        oid = item.get("oid", "")
        if oid and oid not in oid_inputs:
            oid_inputs.append(oid)

    return {
        "ok": True,
        "blueprint_version": "2026-04-30",
        "sidecar_mcp": _sidecar_contract(),
        "target_profile": _profile_payload(profile),
        "pattern": {
            "name": pattern_name or (pattern.metadata.name if pattern else ""),
            "ci_type": pattern.metadata.ci_type if pattern else "",
            "operation_fingerprint": sorted(observations["operation_fingerprint"]),
        },
        "required_listeners": [_port_payload(p) for p in _required_ports(profile, observations)],
        "fixtures": _fixtures_payload(observations, oid_inputs),
        "execution_contract": {
            "strict_mode": True,
            "port_binding": "Bind the declared TCP/UDP listeners on the emulator host; do not tunnel a protocol through a different port unless the discovery credential explicitly says so.",
            "determinism": "The same request sequence must return the same byte-for-byte response unless the scenario declares state transitions.",
            "negative_cases": "Fixtures must declare timeout, authentication failure, noSuchObject, command-not-found, permission-denied, and empty-result behavior explicitly.",
            "clock": "Use scenario time, not wall-clock time, for uptime, certificate-expiry, and last-change fields.",
        },
        "catalog_scope": _catalog_scope(profile),
    }


def _sidecar_contract() -> dict[str, Any]:
    return {
        "name": "sn-target-emulator-mcp",
        "role": "sidecar/helper MCP",
        "single_responsibility": "Emulate target systems for ServiceNow Discovery pattern execution tests.",
        "non_goals": (
            "No pattern authoring",
            "No live ServiceNow writes",
            "No heuristic pass/fail grading beyond recording exact target interactions",
        ),
        "minimum_tools": (
            "emulator_catalog",
            "emulator_start",
            "emulator_stop",
            "emulator_load_scenario",
            "emulator_interactions",
        ),
    }


def _profile_payload(profile: EmulatedProfile) -> dict[str, Any]:
    payload = asdict(profile)
    payload["ports"] = [_port_payload(p) for p in profile.ports]
    return payload


def _profile_summary(profile: EmulatedProfile) -> dict[str, Any]:
    return {
        "target": profile.target,
        "aliases": list(profile.aliases),
        "display_name": profile.display_name,
        "description": profile.description,
        "data_source_target": profile.data_source_target,
        "mib_enterprises": list(profile.mib_enterprises),
        "ports": [
            {
                "protocol": p.protocol,
                "ports": list(p.ports),
                "service": p.service,
            }
            for p in profile.ports
        ],
        "detail_hint": f"Call emulator_catalog with target='{profile.target}' for required_for and fidelity notes.",
    }


def _port_payload(port: EmulatedPort) -> dict[str, Any]:
    return {
        "protocol": port.protocol,
        "ports": list(port.ports),
        "service": port.service,
        "purpose": port.purpose,
        "required_for": list(port.required_for),
        "notes": port.notes,
    }


def _required_ports(profile: EmulatedProfile, observations: dict[str, Any]) -> list[EmulatedPort]:
    op_set = set(observations["operation_fingerprint"])
    if not op_set:
        return list(profile.ports)
    required: list[EmulatedPort] = []
    for port in profile.ports:
        if not port.required_for or op_set.intersection(port.required_for):
            required.append(port)
    if not required:
        return list(profile.ports)
    return required


def _catalog_scope(profile: EmulatedProfile) -> dict[str, Any]:
    scope: dict[str, Any] = {
        "data_source_target": profile.data_source_target,
        "mib_enterprises": list(profile.mib_enterprises),
    }
    if profile.data_source_target:
        from sn_patterns_mcp import data_sources
        scope["data_source_entries"] = len(data_sources.for_target(profile.data_source_target))
    try:
        from sn_patterns_mcp import oids
        scope["oid_entries_available"] = oids.REGISTRY.size()
    except Exception:
        scope["oid_entries_available"] = "unavailable"
    return scope


def _fixtures_payload(observations: dict[str, Any], oid_inputs: list[str]) -> dict[str, Any]:
    return {
        "wmi": observations["wmi_queries"],
        "commands": observations["commands"],
        "registry": observations["registry_reads"],
        "snmp": [_snmp_fixture(oid) for oid in oid_inputs],
        "files": observations["files"],
        "http": observations["http_calls"],
        "ldap": observations["ldap_queries"],
    }


def _snmp_fixture(oid: str) -> dict[str, Any]:
    from sn_patterns_mcp import oids
    entry = oids.lookup(oid) if oid and "$" not in oid else None
    vendor = oids.identify_vendor(oid) if oid and "$" not in oid else None
    payload = {
        "oid": oid,
        "response_required": True,
        "value": "<scenario-value>",
        "error": None,
        "table_index": "<required for columnar OIDs>" if entry and entry.is_columnar else "",
    }
    if entry:
        payload.update({
            "name": entry.name,
            "mib": entry.mib,
            "syntax": entry.syntax,
            "access": entry.access,
            "is_table": entry.is_table,
            "is_columnar": entry.is_columnar,
        })
    elif vendor:
        payload.update({"vendor": vendor.vendor, "vendor_prefix": vendor.prefix})
    elif oid:
        payload["resolution"] = "unresolved"
    return payload


def _pattern_observations(pattern: Pattern) -> dict[str, Any]:
    obs = _empty_observations()
    for step in pattern.all_steps():
        if step.operation is None:
            continue
        for op in _iter_ops(step.operation):
            kw = op.keyword
            obs["operation_fingerprint"].add(kw)
            step_name = step.name or "(unnamed)"
            if kw == "run_wmi_query_to_var":
                obs["wmi_queries"].append({
                    "step": step_name,
                    "namespace": op.attributes.get("namespace") or "root\\cimv2",
                    "query": _literal(op, "query") or "(query not literal)",
                })
            elif kw == "runcmd_to_var":
                obs["commands"].append({
                    "step": step_name,
                    "command": _literal(op, "cmd") or _literal(op, "command") or "(command not literal)",
                    "stdout": "<scenario-stdout>",
                    "stderr": "",
                    "exit_status": 0,
                })
            elif kw == "find_registry_val_to_var":
                obs["registry_reads"].append({
                    "step": step_name,
                    "hive": op.attributes.get("hive", ""),
                    "key": op.attributes.get("keyPath") or op.attributes.get("key", ""),
                    "value_name": op.attributes.get("valueName", ""),
                    "value": "<scenario-value>",
                })
            elif kw.startswith("run_snmp"):
                obs["snmp_oids"].append({
                    "step": step_name,
                    "oid": _literal(op, "oid") or "(oid not literal)",
                    "operation": kw,
                })
            elif kw in {"parse_file", "parse_text_file_to_var", "parse_xml_file_to_var", "parse_property_file_to_var", "parse_ini_file_to_var"}:
                obs["files"].append({
                    "step": step_name,
                    "path": op.attributes.get("filePath") or op.attributes.get("file") or "(path not literal)",
                    "content": "<scenario-file-content>",
                })
            elif kw == "http_invoke":
                obs["http_calls"].append({
                    "step": step_name,
                    "method": op.attributes.get("method", "GET"),
                    "url": _literal(op, "url") or op.attributes.get("url") or "(url not literal)",
                    "status": 200,
                    "body": "<scenario-response-body>",
                })
            elif kw == "ldap_query":
                obs["ldap_queries"].append({
                    "step": step_name,
                    "base_dn": op.attributes.get("baseDN") or op.attributes.get("base", ""),
                    "filter": op.attributes.get("filter", ""),
                    "entries": [],
                })
    obs["operation_fingerprint"] = sorted(obs["operation_fingerprint"])
    return obs


def _empty_observations() -> dict[str, Any]:
    return {
        "operation_fingerprint": set(),
        "wmi_queries": [],
        "commands": [],
        "registry_reads": [],
        "snmp_oids": [],
        "files": [],
        "http_calls": [],
        "ldap_queries": [],
    }


def _infer_target(pattern: Pattern | None, observations: dict[str, Any]) -> str:
    if pattern is not None:
        ci = (pattern.metadata.ci_type or "").lower()
        name = (pattern.metadata.name or "").lower()
        combined = f"{ci} {name}"
        for token, target in (
            ("win", "windows"),
            ("linux", "linux"),
            ("unix", "linux"),
            ("f5", "f5"),
            ("big-ip", "f5"),
            ("bigip", "f5"),
            ("netscaler", "netscaler"),
            ("citrix", "netscaler"),
            ("cisco", "cisco-ios"),
            ("ios", "cisco-ios"),
            ("esx", "esxi"),
            ("vmware", "esxi"),
        ):
            if token in combined:
                return target
    if observations["snmp_oids"]:
        return "generic-snmp"
    return "linux"


def _iter_ops(op: Operation):
    yield op
    for sub in op.operands.values():
        yield from _iter_ops(sub)
    for sub in op.list_operands:
        yield from _iter_ops(sub)


def _literal(op: Operation, key: str) -> str:
    if key in op.attributes and isinstance(op.attributes[key], str):
        return op.attributes[key]
    sub = op.operands.get(key)
    if sub is None:
        return ""
    val = sub.attributes.get("value")
    if isinstance(val, str):
        return val
    if sub.positional_args and isinstance(sub.positional_args[0], str):
        return sub.positional_args[0]
    return ""


def dumps(payload: dict[str, Any]) -> str:
    return json.dumps(payload, indent=2)


__all__ = [
    "EmulatedPort",
    "EmulatedProfile",
    "PROFILES",
    "known_targets",
    "resolve_profile",
    "catalog",
    "blueprint",
    "dumps",
]
