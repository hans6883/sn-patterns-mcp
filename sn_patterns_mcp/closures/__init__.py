"""Closure (NDL operation) registry + semantic descriptors."""
from sn_patterns_mcp.closures.registry import (
    CLOSURE_REGISTRY,
    ClosureDescriptor,
    OperationCategory,
    all_keywords,
    by_class_name,
    get,
)

__all__ = [
    "ClosureDescriptor",
    "OperationCategory",
    "CLOSURE_REGISTRY",
    "get",
    "by_class_name",
    "all_keywords",
]
