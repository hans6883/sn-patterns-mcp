"""
Closure / Operation registry — semantic descriptors for every NDL operation keyword.

Each NDL block name (`runcmd_to_var`, `EVAL`, `refid`, `parse_text_file_to_var`,
`set_attr`, ...) corresponds to a runtime closure — a unit of pattern logic.
This registry catalogs each one so downstream tools can:

    - render meaningful step-by-step explanations (pattern_analyze)
    - check required-input completeness (pattern_validate)
    - flag SNMP / WMI / file / HTTP data sources (pattern_data_sources)
    - route debug guidance based on category (pattern_debug)

Each ClosureDescriptor carries:
    keyword:       the NDL block name ("runcmd_to_var", "EVAL", "refid", ...)
    class_name:    optional class-name hint (informational only)
    category:      OperationCategory — for routing to the right description
    summary:       one-line plain-English description
    inputs:        names of the attributes/operands the operation consumes
    outputs:       names of the attributes/operands it produces (often $var)
    failure_modes: common runtime errors worth surfacing in pattern_debug

Usage:
    from sn_patterns_mcp.closures import get
    d = get("runcmd_to_var")
    print(d.summary)
"""
from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from enum import Enum


class OperationCategory(str, Enum):
    COMMAND = "command"
    PARSE = "parse"
    PARSE_STRATEGY = "parse_strategy"
    TABLE = "table"
    CONTROL = "control"
    EVAL = "eval"
    VARIABLE = "variable"
    MATCH = "match"
    LIBRARY = "library"
    RELATIONSHIP = "relationship"
    HTTP = "http"
    LDAP = "ldap"
    ATTRIBUTE = "attribute"
    FILE = "file"
    META = "meta"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class ClosureDescriptor:
    keyword: str
    class_name: str
    category: OperationCategory
    summary: str
    inputs: tuple[str, ...] = ()
    outputs: tuple[str, ...] = ()
    failure_modes: tuple[str, ...] = ()


def _d(
    keyword: str,
    cls: str,
    category: OperationCategory,
    summary: str,
    inputs: tuple[str, ...] = (),
    outputs: tuple[str, ...] = (),
    failure_modes: tuple[str, ...] = (),
) -> ClosureDescriptor:
    return ClosureDescriptor(
        keyword=keyword,
        class_name=cls,           # Bare class-name hint; informational only
        category=category,
        summary=summary,
        inputs=inputs,
        outputs=outputs,
        failure_modes=failure_modes,
    )


# ---------------------------------------------------------------------------
# Registry — 90 closures covering the NDL operations supported by the runtime.
# ---------------------------------------------------------------------------

CLOSURE_REGISTRY: dict[str, ClosureDescriptor] = {
    # ---- Command execution ----
    "runcmd_to_var": _d(
        "runcmd_to_var", "RunCommandIntoVariableClosure", OperationCategory.COMMAND,
        "Run a shell/SSH command, optionally via applicative credentials, parse stdout into a variable.",
        inputs=("command", "commandParams", "credentialsClosure", "executionMode"),
        outputs=("variable_name",),
        failure_modes=(
            "FAILED_TO_OBTAIN_COMMAND_STRING — command expression evaluated to empty",
            "MISSING_APPLICATIVE_CREDENTIALS — no credential with matching ci_type_id",
            "CommandFailureException — non-zero exit or SSH failure (see sa_discovery_log)",
        ),
    ),
    "run_wmi_query_to_var": _d(
        "run_wmi_query_to_var", "RunWmiQueryToVariableClosure", OperationCategory.COMMAND,
        "Execute a WMI (WQL) query against a Windows target and store rows in a variable table.",
        inputs=("query", "namespace"),
        outputs=("variable_name",),
        failure_modes=("WMI timeout", "Namespace not registered on target", "Access denied for credential"),
    ),
    "run_wmi_invoke_method_to_var": _d(
        "run_wmi_invoke_method_to_var", "RunWmiMethodIntoVariableClosure", OperationCategory.COMMAND,
        "Invoke a WMI method on a Windows target (e.g. Win32_Service.StartService) and capture the result.",
        inputs=("class", "method", "params"),
        outputs=("variable_name",),
    ),
    "run_snmp_to_var": _d(
        "run_snmp_to_var", "RunSnmpToVariableClosure", OperationCategory.COMMAND,
        "SNMP walk/get against a device OID and store the results as a variable/table.",
        inputs=("oid", "community", "version"),
        outputs=("variable_name",),
        failure_modes=("SNMP timeout", "OID not supported on device", "Community/v3 credential mismatch"),
    ),
    "find_registry_val_to_var": _d(
        "find_registry_val_to_var", "FindRegistryToVariableClosure", OperationCategory.COMMAND,
        "Read a Windows registry key/value and store it in a variable.",
        inputs=("hive", "keyPath", "valueName"),
        outputs=("variable_name",),
    ),
    "find_process_to_var": _d(
        "find_process_to_var", "FindProcessToVariableClosure", OperationCategory.COMMAND,
        "Find processes on the target matching a filter and store PIDs + command lines.",
        inputs=("processFilter",),
        outputs=("variable_name",),
    ),

    # ---- Parsing (read into variable) ----
    "parse_file": _d(
        "parse_file", "ParseFileClosure", OperationCategory.PARSE,
        "Read a file from the target, apply a parsing strategy, store result in a variable.",
        inputs=("filePath", "parsingStrategy"),
        outputs=("variable_name",),
        failure_modes=("File not found", "Permission denied", "File larger than MID limit"),
    ),
    "parse_text_file_to_var": _d(
        "parse_text_file_to_var", "ParseTextFileToVariableClosure", OperationCategory.PARSE,
        "Read text file, apply delimited/regex strategy, store rows/values in a variable.",
        inputs=("filePath", "strategy"),
        outputs=("variable_name",),
    ),
    "parse_xml_file_to_var": _d(
        "parse_xml_file_to_var", "ParseXmlFileToVariableClosure", OperationCategory.PARSE,
        "Parse an XML file on target via XPath and store values in a variable.",
        inputs=("filePath", "xpath"),
        outputs=("variable_name",),
    ),
    "parse_property_file_to_var": _d(
        "parse_property_file_to_var", "ParsePropertyFileToVariableClosure", OperationCategory.PARSE,
        "Parse a Java .properties file, extract key/value pairs into a variable table.",
        inputs=("filePath", "keys"),
        outputs=("variable_name",),
    ),
    "parse_ini_file_to_var": _d(
        "parse_ini_file_to_var", "ParseIniFileToVariableClosure", OperationCategory.PARSE,
        "Parse INI file (sections + key/value) into a variable table.",
        inputs=("filePath", "section", "key"),
        outputs=("variable_name",),
    ),
    "parse_oracle_file_to_var": _d(
        "parse_oracle_file_to_var", "ParseOracleFileToVariableClosure", OperationCategory.PARSE,
        "Parse Oracle listener.ora / tnsnames.ora style files into variables.",
        inputs=("filePath", "strategy"),
        outputs=("variable_name",),
    ),
    "parse_process_info_to_var": _d(
        "parse_process_info_to_var", "ParseProcessInfoIntoVariableClosure", OperationCategory.PARSE,
        "Extract fields from the current running process info (cmdline, pid, path) into a variable.",
        inputs=("source", "field"),
        outputs=("variable_name",),
    ),
    "parse_url_to_var": _d(
        "parse_url_to_var", "ParseUrlToVariableClosure", OperationCategory.PARSE,
        "Parse a URL into host/port/path/query components stored as a variable.",
        inputs=("url",),
        outputs=("variable_name",),
    ),
    "parse_var_to_var": _d(
        "parse_var_to_var", "ParseVariableToVariableClosure", OperationCategory.PARSE,
        "Apply a parsing strategy to the contents of an existing variable, write to another variable.",
        inputs=("sourceVariable", "strategy"),
        outputs=("variable_name",),
    ),
    "parse_content_to_var": _d(
        "parse_content_to_var", "ParseContentToVariableClosure", OperationCategory.PARSE,
        "Base class for all content-to-variable parsers; rarely used directly in NDL.",
        inputs=("content", "strategy"),
        outputs=("variable_name",),
    ),

    # ---- Parsing strategies (nested inside parse_*) ----
    "parse_regex": _d(
        "parse_regex", "RegExParsingStrategyClosure", OperationCategory.PARSE_STRATEGY,
        "Apply a regex with named groups to content; each named group becomes a column.",
        inputs=("regex", "flags"),
    ),
    "parse_delimited": _d(
        "parse_delimited", "DelimitedParsingStrategyClosure", OperationCategory.PARSE_STRATEGY,
        "Split content by line separator then by column separator, with optional header row.",
        inputs=("lineSeperator", "colSeperator", "header"),
    ),
    "parse_xml_strategy": _d(
        "parse_xml_strategy", "XmlFileParsingStrategyClosure", OperationCategory.PARSE_STRATEGY,
        "XPath-based XML parsing strategy used by parse_xml_file_to_var.",
        inputs=("xpath", "namespaces"),
    ),
    "parse_ini_strategy": _d(
        "parse_ini_strategy", "IniFileParsingStrategyClosure", OperationCategory.PARSE_STRATEGY,
        "INI file parsing strategy (sections + keys).",
        inputs=("section", "key"),
    ),
    "parse_props_strategy": _d(
        "parse_props_strategy", "PropertiesFileParsingStrategyClosure", OperationCategory.PARSE_STRATEGY,
        "Java .properties file parsing strategy.",
        inputs=("keys",),
    ),
    "parse_vertical_strategy": _d(
        "parse_vertical_strategy", "VerticalFileParsingStrategyClosure", OperationCategory.PARSE_STRATEGY,
        "Vertical/key-on-left-value-on-right file parsing (e.g. `ps -ef` columns).",
        inputs=("keyPattern",),
    ),
    "parse_oracle_strategy": _d(
        "parse_oracle_strategy", "OracleFileParsingStrategyClosure", OperationCategory.PARSE_STRATEGY,
        "Oracle config file (listener.ora etc.) parsing strategy.",
        inputs=(),
    ),
    "parse_ldap_strategy": _d(
        "parse_ldap_strategy", "LdapParsingStrategyClosure", OperationCategory.PARSE_STRATEGY,
        "LDIF / LDAP search-result parsing strategy.",
        inputs=(),
    ),
    "parse_empty_strategy": _d(
        "parse_empty_strategy", "EmptyParsingStrategyClosure", OperationCategory.PARSE_STRATEGY,
        "Pass-through strategy — yields raw content unchanged.",
    ),
    "parse_custom_strategy": _d(
        "parse_custom_strategy", "CustomParsingStrategyClosure", OperationCategory.PARSE_STRATEGY,
        "Custom parsing strategy implemented by a sa_custom_parser script.",
        inputs=("custom_script",),
    ),
    "file_parsing_strategy": _d(
        "file_parsing_strategy", "FileParsingStrategyClosure", OperationCategory.PARSE_STRATEGY,
        "Base class for file parsing strategies.",
    ),
    "file_parsing_field": _d(
        "file_parsing_field", "FileParsingFieldClosure", OperationCategory.PARSE_STRATEGY,
        "Declaration of a single field-in-file (used inside file parsing strategies).",
        inputs=("name", "position"),
    ),
    "file_parsing_fields": _d(
        "file_parsing_fields", "FileParsingFieldsClosure", OperationCategory.PARSE_STRATEGY,
        "Declaration of a field collection inside a file parsing strategy.",
        inputs=("fields",),
    ),
    "custom_parsing_strategy": _d(
        "custom_parsing_strategy", "CustomParsingStrategy", OperationCategory.PARSE_STRATEGY,
        "Entity describing a custom parsing strategy binding.",
    ),

    # ---- Table operations ----
    "table": _d(
        "table", "TableClosure", OperationCategory.TABLE,
        "Literal table/variable wrapper — used inside filter/transform/merge operations.",
        inputs=("columns", "rows"),
    ),
    "filter_table": _d(
        "filter_table", "FilterTableClosure", OperationCategory.TABLE,
        "Filter a variable's rows by predicate; writes filtered subset to another variable.",
        inputs=("source", "predicate"),
        outputs=("variable_name",),
    ),
    "transform_table": _d(
        "transform_table", "TransformTableClosure", OperationCategory.TABLE,
        "Apply a row-wise transform to a variable-table; add/replace columns.",
        inputs=("source", "operations"),
        outputs=("variable_name",),
    ),
    "merge_table": _d(
        "merge_table", "MergeTableClosure", OperationCategory.TABLE,
        "Merge two tables on a key column into one row set.",
        inputs=("left", "right", "on"),
        outputs=("variable_name",),
    ),
    "merge_table_ref": _d(
        "merge_table_ref", "MergeTableReferenceClosure", OperationCategory.TABLE,
        "Merge table with reference lookup rows (CMDB reference resolution).",
    ),
    "merge_table_relation": _d(
        "merge_table_relation", "MergeTableRelationClosure", OperationCategory.TABLE,
        "Merge table rows into CMDB relation rows.",
    ),
    "merge_table_ref_and_relation": _d(
        "merge_table_ref_and_relation", "MergeTableReferenceAndRelationClosure", OperationCategory.TABLE,
        "Merge both reference and relation rows into a single output table.",
    ),
    "union_table": _d(
        "union_table", "UnionTableClosure", OperationCategory.TABLE,
        "Concatenate two variable-tables row-wise.",
    ),
    "transform_table_op": _d(
        "transform_table_op", "TransformTableOperationClosure", OperationCategory.TABLE,
        "Single row/column operation used inside transform_table (set, copy, regex-replace).",
    ),
    "simple_table_description": _d(
        "simple_table_description", "SimpleTableDescription", OperationCategory.TABLE,
        "Metadata describing a variable table's columns.",
    ),
    "set_field": _d(
        "set_field", "SetFieldClosure", OperationCategory.TABLE,
        "Set a single field on every row of a variable-table (or on a scalar).",
        inputs=("target", "field", "value"),
    ),
    "set_param_val": _d(
        "set_param_val", "SetParameterValueClosure", OperationCategory.VARIABLE,
        "Assign a value to a pattern parameter / variable by name.",
        inputs=("name", "value"),
    ),
    "language_variables_table": _d(
        "language_variables_table", "LanguageVariablesTableDescription", OperationCategory.TABLE,
        "Declaration of the language-level variable table at pattern start.",
    ),
    "delimited_parsing_result": _d(
        "delimited_parsing_result", "DelimitedParsingResultDTO", OperationCategory.PARSE_STRATEGY,
        "DTO carrying the result of delimited parsing back up the closure tree.",
    ),

    # ---- Control flow ----
    "if": _d(
        "if", "IfClosure", OperationCategory.CONTROL,
        "Conditional wrapper — execute inner operation only if the condition evaluates true.",
        inputs=("condition", "then", "else"),
    ),
    "alternatives": _d(
        "alternatives", "AlternativesClosure", OperationCategory.CONTROL,
        "Try each alternative in order; stop at the first that succeeds.",
        inputs=("alternatives",),
    ),
    "terminate": _d(
        "terminate", "TerminateClosure", OperationCategory.CONTROL,
        "Stop pattern execution — gracefully (skip remaining) or hard (failure).",
        inputs=("message", "mode"),
    ),
    "nop": _d(
        "nop", "NopClosure", OperationCategory.CONTROL,
        "No-op. Always succeeds. Used as a default not_found strategy.",
    ),
    "not_found": _d(
        "not_found", "NotFoundClosure", OperationCategory.CONTROL,
        "Strategy applied when a command/parse yields no result. May terminate or log-and-continue.",
    ),

    # ---- Script evaluation ----
    "EVAL": _d(
        "EVAL", "EvalClosure", OperationCategory.EVAL,
        "Evaluate a Groovy or JavaScript expression. Prefix 'javascript:' selects JS (Rhino) engine. "
        "${var} and $var placeholders are bound from ExecutionContext.",
        inputs=("groovyExpression",),
        outputs=("return value (string)",),
        failure_modes=("GroovyPatternException: JAVASCRIPT_CODE_FAILURE", "GroovyPatternException: GROOVY_CODE_FAILURE"),
    ),
    "custom_operation": _d(
        "custom_operation", "CustomOperationClosure", OperationCategory.EVAL,
        "Invoke a customer-defined operation declared in the sa_custom_operation table.",
        inputs=("operationName", "params"),
    ),

    # ---- Variables / expressions ----
    "constant": _d(
        "constant", "ConstantClosure", OperationCategory.VARIABLE,
        "Literal constant value (string or int). Used wherever a Closure<String>/Closure<Integer> is expected.",
    ),
    "null_constant": _d(
        "null_constant", "NullConstantClosure", OperationCategory.VARIABLE,
        "The NULL literal — evaluates to Java null at runtime.",
    ),
    "concat": _d(
        "concat", "ConcatClosure", OperationCategory.VARIABLE,
        "Concatenate two or more closure values into a single string.",
        inputs=("parts",),
    ),

    # ---- Match operations (used inside parse strategies) ----
    "match": _d(
        "match", "MatchClosure", OperationCategory.MATCH,
        "Match a single value against a pattern; extract the matched portion.",
    ),
    "match_using_strategy": _d(
        "match_using_strategy", "MatchUsingStrategyClosure", OperationCategory.MATCH,
        "Abstract strategy for pulling a field out of a command's stdout.",
    ),
    "match_after_keyword": _d(
        "match_after_keyword", "MatchUsingAfterFixedKeywordClosure", OperationCategory.MATCH,
        "Take the text after a fixed keyword.",
        inputs=("keyword",),
    ),
    "match_positional_from_start": _d(
        "match_positional_from_start", "MatchUsingPositionalFromStartClosure", OperationCategory.MATCH,
        "Positional match — Nth token from the start of the line.",
        inputs=("position",),
    ),
    "match_positional_from_end": _d(
        "match_positional_from_end", "MatchUsingPositionalFromEndClosure", OperationCategory.MATCH,
        "Positional match — Nth token from the end of the line.",
        inputs=("position",),
    ),
    "match_java_cmdline_arg": _d(
        "match_java_cmdline_arg", "MatchUsingJavaCommandLineArgClosure", OperationCategory.MATCH,
        "Extract a Java command-line argument (-Dfoo=bar style) from a process command line.",
        inputs=("argName",),
    ),
    "match_unix_cmdline_arg": _d(
        "match_unix_cmdline_arg", "MatchUsingUnixCommandLineArgClosure", OperationCategory.MATCH,
        "Extract a Unix-style flag argument (-x value / --long=val) from a command line.",
        inputs=("argName",),
    ),
    "get_param_val": _d(
        "get_param_val", "GetParameterValueClosure", OperationCategory.VARIABLE,
        "Read a named parameter from the pattern's parameter bag.",
        inputs=("name",),
    ),
    "get_files_by_pattern": _d(
        "get_files_by_pattern", "GetFilesByPatternClosure", OperationCategory.FILE,
        "List files matching a glob under a directory on the target.",
        inputs=("directory", "pattern"),
    ),

    # ---- Library references ----
    "refid": _d(
        "refid", "LibraryReferenceClosure", OperationCategory.LIBRARY,
        "Expand a shared library (ReferenceElement) at pattern-execution time. Library sys_id is the refid. "
        "Recursively inlined by DefaultPatternExecutor.",
        inputs=("id",),
    ),

    # ---- Relationships / credentials / events ----
    "create_connection": _d(
        "create_connection", "CreateConnectionClosure", OperationCategory.RELATIONSHIP,
        "Create an outgoing connection (APPLICATIVE, CLUSTER, STORAGE_FLOW) between CIs.",
        inputs=("category", "source", "target"),
    ),
    "create_event": _d(
        "create_event", "CreateEventClosure", OperationCategory.RELATIONSHIP,
        "Emit an event into em_event or the ecc_queue based on a condition.",
        inputs=("name", "source", "resource"),
    ),
    "change_user": _d(
        "change_user", "ChangeUserClosure", OperationCategory.RELATIONSHIP,
        "Switch the SSH/command session to a different user (sudo su) for subsequent steps.",
        inputs=("username",),
    ),
    "unchange_user": _d(
        "unchange_user", "UnchangeUserClosure", OperationCategory.RELATIONSHIP,
        "Revert a previous change_user — exit back to the base user.",
    ),
    "credentials": _d(
        "credentials", "CredentialsClosure", OperationCategory.RELATIONSHIP,
        "Select a credential of a given type/ci_type_id for the next command.",
        inputs=("ciTypeId", "credentialType"),
    ),

    # ---- HTTP / LDAP ----
    "http_invoke": _d(
        "http_invoke", "HttpInvokerClosure", OperationCategory.HTTP,
        "Perform an HTTP/HTTPS request from the MID; capture status, headers, body.",
        inputs=("url", "method", "headers", "body"),
        outputs=("variable_name",),
    ),
    "best_url_match": _d(
        "best_url_match", "BestUrlMatchClosure", OperationCategory.HTTP,
        "Pick the best URL from a list by probing (HEAD/GET) and selecting the successful one.",
    ),
    "extract_proxy_urls_to_var": _d(
        "extract_proxy_urls_to_var", "ExtractProxyUrlsToVariableClosure", OperationCategory.HTTP,
        "Extract a list of URLs from a reverse-proxy config snippet into a variable.",
    ),
    "ldap_query": _d(
        "ldap_query", "LdapQueryClosure", OperationCategory.LDAP,
        "Issue an LDAP search against AD / LDAP server; result to variable.",
        inputs=("baseDN", "filter", "scope"),
        outputs=("variable_name",),
    ),
    "base_ldap_query": _d(
        "base_ldap_query", "BaseLdapQuery", OperationCategory.LDAP,
        "Base helper for LDAP queries (not directly invoked in NDL).",
    ),
    "ldap_unique_attribute_search": _d(
        "ldap_unique_attribute_search", "LdapUniqueAttributeSearch", OperationCategory.LDAP,
        "LDAP search that requires a unique attribute match or errors out.",
    ),

    # ---- Attributes / events ----
    "attr_decl": _d(
        "attr_decl", "AttributeDeclarationClosure", OperationCategory.ATTRIBUTE,
        "Declare a single CI attribute value to attach to the produced CI.",
        inputs=("name", "value"),
    ),
    "attrs_decl": _d(
        "attrs_decl", "AttributesDeclarationClosure", OperationCategory.ATTRIBUTE,
        "Declare a set of CI attributes in one block.",
    ),
    "event_params": _d(
        "event_params", "EventParamsClosure", OperationCategory.ATTRIBUTE,
        "Parameter bag for create_event.",
    ),

    # ---- File ops ----
    "put_file": _d(
        "put_file", "PutFileClosure", OperationCategory.FILE,
        "Copy a file from MID to target (or target to target) via SSH/SMB.",
        inputs=("file", "destinationPath"),
        outputs=("variable_name",),  # full_path_var attribute receives the resolved path
    ),

    # ---- Listing helpers (AggregationFunction, SplitUtil) ----
    "aggregation_function": _d(
        "aggregation_function", "AggregationFunction", OperationCategory.TABLE,
        "Aggregation function descriptor (sum/count/avg) used by transform_table.",
    ),
    "list_based": _d(
        "list_based", "ListBasedClosure", OperationCategory.VARIABLE,
        "Abstract base for closures that produce lists (used internally).",
    ),
    "split_util": _d(
        "split_util", "SplitUtil", OperationCategory.VARIABLE,
        "Utility for splitting strings (used inside delimited strategies).",
    ),

    # ---- Infrastructure (non-user-facing but present in mapping) ----
    "predicate": _d(
        "predicate", "Predicate", OperationCategory.CONTROL,
        "Boolean predicate used inside filter_table / if conditions.",
    ),
    "operation_status": _d(
        "operation_status", "OperationStatus", OperationCategory.META,
        "Status returned by every closure: SUCCESS/FAILURE/MIXED/TERMINATION/GRACEFUL_TERMINATION/NOP.",
    ),
    "operation_status_type": _d(
        "operation_status_type", "OperationStatusType", OperationCategory.META,
        "Enum of statuses returned by closures.",
    ),
    "mid_script": _d(
        "mid_script", "IMidScript", OperationCategory.EVAL,
        "MID-side script runner interface (used by EVAL javascript: mode).",
    ),
    "file_system": _d(
        "file_system", "IFileSystem", OperationCategory.FILE,
        "MID-side file system abstraction used by put_file / parse_file.",
    ),
    "execution_ctx_attr": _d(
        "execution_ctx_attr", "ExecutionContextAttributeAware", OperationCategory.META,
        "Base interface for closures that read/write ExecutionContext attributes.",
    ),
    "ini_file_to_table_parsing_strategy": _d(
        "ini_file_to_table_parsing_strategy", "IniFileToTableParsingStrategy", OperationCategory.PARSE_STRATEGY,
        "Variant of INI parsing that emits a row-oriented table.",
    ),
    "position_in_text": _d(
        "position_in_text", "PositionInTextDTO", OperationCategory.PARSE_STRATEGY,
        "Position-in-text descriptor used by positional match strategies.",
    ),
}


# ---------------------------------------------------------------------------
# Lookup API
# ---------------------------------------------------------------------------

_BY_CLASS_NAME: dict[str, ClosureDescriptor] = {d.class_name: d for d in CLOSURE_REGISTRY.values()}


def get(keyword: str) -> ClosureDescriptor | None:
    """Look up by NDL keyword. Returns None if unknown.

    Unknown keywords are expected during initial roll-out; the pattern index
    builder logs them so we can correct the registry from real data.
    """
    if not keyword:
        return None
    # Preserve case for EVAL (the only uppercase keyword); everything else is lowercase.
    if keyword in CLOSURE_REGISTRY:
        return CLOSURE_REGISTRY[keyword]
    return CLOSURE_REGISTRY.get(keyword.lower())


def by_class_name(name: str) -> ClosureDescriptor | None:
    return _BY_CLASS_NAME.get(name)


def all_keywords() -> list[str]:
    return sorted(CLOSURE_REGISTRY.keys())


def iter_descriptors() -> Iterator[tuple[str, ClosureDescriptor]]:
    """Yield (keyword, descriptor) for all known closures."""
    yield from CLOSURE_REGISTRY.items()


__all__ = [
    "ClosureDescriptor",
    "OperationCategory",
    "CLOSURE_REGISTRY",
    "get",
    "by_class_name",
    "all_keywords",
    "iter_descriptors",
]
