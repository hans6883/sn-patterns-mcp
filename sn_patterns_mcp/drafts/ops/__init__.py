"""Edit-op registry. Op classes register here for MCP dispatch."""
from sn_patterns_mcp.drafts.ops.base import (
    OP_REGISTRY,
    EditOp,
    EditResult,
    Severity,
    ValidationIssue,
    register_op,
)
from sn_patterns_mcp.drafts.ops.clone_library import CloneLibrary  # noqa: F401  (registers)
from sn_patterns_mcp.drafts.ops.insert_step import InsertStepAfter, InsertStepBefore  # noqa: F401
from sn_patterns_mcp.drafts.ops.modify_attr import ModifyClosureAttr  # noqa: F401
from sn_patterns_mcp.drafts.ops.redirect_ref import RedirectRef  # noqa: F401
from sn_patterns_mcp.drafts.ops.remove_step import RemoveStep  # noqa: F401
from sn_patterns_mcp.drafts.ops.wrap_in_guard import WrapInGuard  # noqa: F401

__all__ = [
    "OP_REGISTRY",
    "EditOp",
    "EditResult",
    "Severity",
    "ValidationIssue",
    "register_op",
    # Concrete ops
    "CloneLibrary",
    "InsertStepBefore",
    "InsertStepAfter",
    "ModifyClosureAttr",
    "RedirectRef",
    "RemoveStep",
    "WrapInGuard",
]
