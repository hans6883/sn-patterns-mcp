"""sn-patterns-mcp — ServiceNow Discovery pattern intelligence."""
from sn_patterns_mcp.ndl_parser import NdlParser, NdlSyntaxError
from sn_patterns_mcp.pattern_model import (
    ConnectionSection,
    Extension,
    FindProcessStrategy,
    Identification,
    Operation,
    Pattern,
    PatternMetadata,
    Step,
    Variable,
    VariableScope,
)

__version__ = "0.1.0"
__all__ = [
    "NdlParser", "NdlSyntaxError",
    "Pattern", "PatternMetadata", "Identification", "ConnectionSection",
    "Extension", "Step", "Operation", "Variable", "VariableScope",
    "FindProcessStrategy",
]
