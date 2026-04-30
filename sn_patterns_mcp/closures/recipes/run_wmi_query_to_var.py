"""Recipes for run_wmi_query_to_var.

Limitations addressed:
  - WMI namespace existence is not validated; querying a non-existent namespace
    blocks for the WMI default-timeout (typically 10–30s). Probe it first.
  - WMI queries can return unbounded rows on heavily-populated providers
    (e.g. Win32_Printer on a print server). Push WHERE-clause filtering into
    the WMI query itself rather than post-filter.
"""
from __future__ import annotations

from sn_patterns_mcp.closures.recipes import Recipe, register

NAMESPACE_EXISTENCE_PROBE = register(Recipe(
    closure="run_wmi_query_to_var",
    name="namespace_existence_probe",
    purpose="Probe whether a WMI namespace exists before querying it.",
    addresses_limitation=(
        "run_wmi_query_to_var does not validate namespace existence; querying "
        "a non-existent namespace blocks for the WMI default timeout."
    ),
    parameters={
        "namespace": "WMI namespace name (e.g. 'MSCluster' or 'virtualization\\\\v2'). "
                     "The literal string is interpolated into the PowerShell command.",
        "out_var":   "Scalar var name to set: 'true' if the namespace exists, '' otherwise.",
    },
    requires_vars=[],
    declares_vars=["{out_var}"],
    # Single-line PowerShell to avoid newlines inside an NDL string.
    # Backslash-escaped quotes survive both NDL escaping and PowerShell escaping.
    ndl_template=(
        'step {{\n'
        '    name = "Probe {namespace} namespace exists"\n'
        '    runcmd_to_var {{\n'
        '        command = "powershell -NoProfile -Command \\"'
        'try {{ if (Get-WmiObject -Namespace root -Class __Namespace -Filter \\\\\\"Name=\'{namespace}\'\\\\\\" -EA SilentlyContinue) '
        '{{ \'true\' }} else {{ \'\' }} }} catch {{ \'\' }}\\""\n'
        '        var_names = scalar {{\n'
        '            name = "{out_var}"\n'
        '        }}\n'
        '        if_not_found_do = nop {{}}\n'
        '    }}\n'
        '}}'
    ),
))


WMI_QUERY_WITH_WHERE = register(Recipe(
    closure="run_wmi_query_to_var",
    name="wmi_query_with_where_optimization",
    purpose="Apply a WHERE clause inside the WMI query to bound the result set.",
    addresses_limitation=(
        "run_wmi_query_to_var has no row-cap or LIMIT primitive; large WMI providers "
        "(Win32_Printer on a print server, Win32_Process on a busy host) produce "
        "thousands of rows that then have to be parsed and filtered downstream."
    ),
    parameters={
        "namespace":  "WMI namespace (e.g. 'root\\\\CIMV2').",
        "select_cols": "Comma-separated columns: 'Name,DeviceID,PortName'.",
        "from_class": "WMI class: 'Win32_Printer'.",
        "where":      "WHERE clause body (no leading 'WHERE'): \"PortName LIKE 'IP_%'\".",
        "out_var":    "Output table var name.",
    },
    requires_vars=[],
    declares_vars=["{out_var}"],
    ndl_template=(
        'step {{\n'
        '    name = "Query {from_class} (filtered)"\n'
        '    run_wmi_query_to_var {{\n'
        '        namespace = "{namespace}"\n'
        '        query = "SELECT {select_cols} FROM {from_class} WHERE {where}"\n'
        '        var_names = table {{\n'
        '            name = "{out_var}"\n'
        '        }}\n'
        '        if_not_found_do = nop {{}}\n'
        '        cache_flag = 0\n'
        '    }}\n'
        '}}'
    ),
))
