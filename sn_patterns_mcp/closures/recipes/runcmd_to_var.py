"""Recipes for runcmd_to_var.

Limitations addressed:
  - The closure does not expose the shell exit code. To capture $? semantically,
    append `; echo $?` and parse the trailing line into a var.
"""
from __future__ import annotations

from sn_patterns_mcp.closures.recipes import Recipe, register

EXIT_STATUS_CAPTURE = register(Recipe(
    closure="runcmd_to_var",
    name="exit_status_capture",
    purpose="Capture the shell exit code ($?) of an arbitrary command.",
    addresses_limitation=(
        "runcmd_to_var does not expose the shell exit code; the closure assumes "
        "stdout-only command output. To branch on exit status, the command must "
        "echo $? and the output must be split."
    ),
    parameters={
        "command":      "Shell command, will be wrapped: '<command>; echo \"---EXIT---:$?\"'.",
        "out_stdout":   "Var to receive stdout.",
        "out_exit_var": "Var to receive parsed exit code as string ('0', '1', ...).",
    },
    requires_vars=[],
    declares_vars=["{out_stdout}", "{out_exit_var}"],
    ndl_template=(
        'step {{\n'
        '    name = "Run with exit-status capture"\n'
        '    runcmd_to_var {{\n'
        '        command = "{command}; echo \\"---EXIT---:$?\\""\n'
        '        var_names = scalar {{\n'
        '            name = "{out_stdout}"\n'
        '        }}\n'
        '        if_not_found_do = nop {{}}\n'
        '    }}\n'
        '}}'
    ),
))
