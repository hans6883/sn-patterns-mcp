"""EditOp protocol + dispatch registry + ValidationIssue."""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Protocol

from sn_patterns_mcp.drafts.locator import StepLocator
from sn_patterns_mcp.drafts.store import Draft


class Severity(str, Enum):
    ERROR = "error"
    WARN = "warn"
    INFO = "info"


@dataclass(frozen=True)
class ValidationIssue:
    severity: Severity
    code: str                          # e.g. "VAR_READ_BEFORE_WRITE", "REFID_MISSING"
    message: str
    locator: StepLocator | None = None
    suggested_fix: dict[str, Any] | None = None  # {op_name, params} — agent can apply

    def to_dict(self) -> dict[str, Any]:
        return {
            "severity": self.severity.value,
            "code": self.code,
            "message": self.message,
            "locator": self.locator.to_dict() if self.locator else None,
            "suggested_fix": self.suggested_fix,
        }


@dataclass
class EditResult:
    ok: bool
    op_name: str
    issues: list[ValidationIssue] = field(default_factory=list)
    new_locators: dict[str, StepLocator] = field(default_factory=dict)
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "op_name": self.op_name,
            "issues": [i.to_dict() for i in self.issues],
            "new_locators": {k: v.to_dict() for k, v in self.new_locators.items()},
            "extra": self.extra,
        }


class EditOp(Protocol):
    """Protocol for an edit operation.

    Concrete ops are dataclasses registered via @register_op. apply() may
    mutate the draft tree; returning errors in EditResult is preferred over
    raising.
    """
    name: str  # class attribute — op identifier for dispatch

    def validate(self, draft: Draft, store: Any) -> list[ValidationIssue]: ...

    def apply(self, draft: Draft, store: Any) -> EditResult: ...

    @classmethod
    def from_params(cls, params: dict[str, Any]) -> EditOp: ...


# Op registry — name → class. Populated by register_op.
OP_REGISTRY: dict[str, type] = {}


def register_op(cls: type) -> type:
    """Decorator: register an op class by its `name` attribute."""
    op_name = getattr(cls, "name", None)
    if not op_name:
        raise ValueError(f"{cls.__name__} missing required `name` class attr")
    if op_name in OP_REGISTRY:
        raise ValueError(f"op already registered: {op_name}")
    OP_REGISTRY[op_name] = cls
    return cls


def dispatch(op_name: str, params: dict[str, Any]) -> EditOp:
    cls = OP_REGISTRY.get(op_name)
    if cls is None:
        raise KeyError(f"unknown op: {op_name!r} (known: {sorted(OP_REGISTRY)})")
    return cls.from_params(params)


# ---------------------------------------------------------------------------
# Common helpers used by ops
# ---------------------------------------------------------------------------

def parse_ndl_block(fragment: str) -> Any:
    """Parse a single NDL block fragment to a _Block. Used by ops accepting NDL strings."""
    from sn_patterns_mcp.ndl_parser import NdlParser
    return NdlParser().parse_tree(fragment)


def reindex_after_apply(fn: Callable) -> Callable:
    """Decorator that calls draft.reindex_steps() after a successful apply."""
    def _wrap(self: Any, draft: Draft, store: Any) -> EditResult:
        result = fn(self, draft, store)
        if result.ok:
            draft.reindex_steps()
        return result
    return _wrap
