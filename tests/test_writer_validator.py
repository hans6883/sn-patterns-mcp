"""Tests for ndl_writer, validator, pattern_validate, pattern_create."""
from __future__ import annotations

from pathlib import Path

import pytest

from sn_patterns_mcp.ndl_parser import NdlParser, blocks_equivalent
from sn_patterns_mcp.ndl_writer import NdlWriter, escape_java
from sn_patterns_mcp.tools import pattern_create, pattern_validate
from sn_patterns_mcp.validator import PatternValidator

FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture
def apache_unix_ndl() -> str:
    return (FIXTURES_DIR / "apache_unix.ndl").read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# Writer
# ---------------------------------------------------------------------------

class TestNdlWriter:
    def test_roundtrip_apache_unix(self, apache_unix_ndl: str) -> None:
        parser = NdlParser()
        writer = NdlWriter()
        tree_a = parser.parse_tree(apache_unix_ndl)
        out = writer.write(tree_a)
        tree_b = parser.parse_tree(out)
        assert blocks_equivalent(tree_a, tree_b)

    def test_inline_block_for_single_attribute(self) -> None:
        # Single-attribute block should be written inline: name {key = value}
        ndl = 'metadata {id = "abc"}'
        tree = NdlParser().parse_tree(ndl)
        out = NdlWriter().write(tree)
        assert "\n" not in out.rstrip("\n")  # one line
        assert out.startswith("metadata {")
        assert "}" in out

    def test_multi_attr_block_is_multiline(self) -> None:
        ndl = 'metadata {id = "a" name = "b"}'
        tree = NdlParser().parse_tree(ndl)
        out = NdlWriter().write(tree)
        assert out.count("\n") >= 2
        assert "\tid = " in out

    def test_positional_string_arg(self) -> None:
        # set_attr {"pid" get_attr {"process.pid"}} should roundtrip
        ndl = 'set_attr {"pid" get_attr {"process.pid"}}'
        tree = NdlParser().parse_tree(ndl)
        out = NdlWriter().write(tree)
        assert '"pid"' in out
        assert "get_attr" in out
        assert blocks_equivalent(tree, NdlParser().parse_tree(out))

    def test_escape_java_quotes(self) -> None:
        assert escape_java('say "hi"') == 'say \\"hi\\"'

    def test_escape_java_backslash(self) -> None:
        assert escape_java("a\\b") == "a\\\\b"

    def test_escape_java_unicode(self) -> None:
        # Char above 0x7f → \uXXXX
        assert "\\u" in escape_java("café")

    def test_escape_java_supplementary_plane(self) -> None:
        # Supplementary-plane (above 0xFFFF) → surrogate pair, never 5-digit \u
        result = escape_java(chr(0x1F600))  # 😀
        assert result == "\\uD83D\\uDE00"
        assert "\\u1" not in result  # no invalid 5-digit form

    def test_csv_list_attribute_roundtrips(self) -> None:
        # Comma-separated list values: apply_to_os_types = "linux","solaris"
        ndl = '''pattern {
            metadata {
                id = "abc"
                name = "x"
                citype = "cmdb_ci"
                apply_to_os_types = "linux","solaris","aix"
            }
        }'''
        tree_a = NdlParser().parse_tree(ndl)
        out = NdlWriter().write(tree_a)
        tree_b = NdlParser().parse_tree(out)
        assert blocks_equivalent(tree_a, tree_b)
        assert '"linux","solaris","aix"' in out


# ---------------------------------------------------------------------------
# Validator
# ---------------------------------------------------------------------------

class TestPatternValidator:
    def test_to_var_closures_all_exist_in_registry(self) -> None:
        """Cross-validate that _TO_VAR_CLOSURES references real registry keywords."""
        from sn_patterns_mcp.closures.registry import CLOSURE_REGISTRY
        from sn_patterns_mcp.validator import _TO_VAR_CLOSURES
        missing = _TO_VAR_CLOSURES - set(CLOSURE_REGISTRY.keys())
        assert not missing, f"_TO_VAR_CLOSURES contains unknown keywords: {missing}"

    def test_finding_severity_validated(self) -> None:
        """Finding rejects unknown severities at construction time."""
        from sn_patterns_mcp.validator import Finding
        with pytest.raises(ValueError):
            Finding(severity="HIGH", code="x", message="y")  # not a valid severity

    def test_filter_table_writes_var_no_false_warning(self) -> None:
        """Closures discovered via outputs marker (e.g. filter_table) shouldn't false-warn."""
        ndl = '''pattern {
            metadata {id = "a" name = "x" citype = "cmdb_ci_appl"}
            identification {
                name = "i"
                find_process_strategy {strategy = LISTENING_PORT}
                step {
                    name = "filter"
                    filter_table {
                        src_table_name = "raw"
                        var_names = "filtered"
                    }
                }
                step {
                    name = "use filtered"
                    set_attr {
                        "result"
                        get_attr {"filtered"}
                    }
                }
            }
        }'''
        result = PatternValidator().validate(ndl)
        assert not any(
            f.code == "var.read_before_write" and "filtered" in f.message
            for f in result.warnings
        )

    def test_valid_apache_unix_has_no_errors(self, apache_unix_ndl: str) -> None:
        result = PatternValidator().validate(apache_unix_ndl)
        assert result.is_valid
        assert not result.errors

    def test_refid_unresolved_warning_with_library_set(self) -> None:
        """When library_ids is provided, unresolved refids should warn."""
        ndl = '''pattern {
            metadata {id = "a" name = "x" citype = "cmdb_ci_appl"}
            identification {
                name = "i"
                find_process_strategy {strategy = LISTENING_PORT}
                step {
                    name = "use library"
                    refid = "deadbeefdeadbeefdeadbeefdeadbeef"
                }
            }
        }'''
        # No library_ids → no warn
        result = PatternValidator().validate(ndl)
        assert not any(f.code == "refid.unresolved" for f in result.warnings)
        # With library_ids that don't include this refid → warn
        result = PatternValidator(library_ids={"00000000000000000000000000000000"}).validate(ndl)
        assert any(f.code == "refid.unresolved" for f in result.warnings)

    def test_syntax_error_reported(self) -> None:
        result = PatternValidator().validate("pattern { metadata { id = }")
        assert not result.is_valid
        assert any(f.code == "syntax" for f in result.errors)

    def test_missing_metadata_id_is_error(self) -> None:
        ndl = '''pattern {
            metadata {name = "X" citype = "cmdb_ci_appl"}
            identification {name = "i" find_process_strategy {strategy = LISTENING_PORT}}
        }'''
        result = PatternValidator().validate(ndl)
        assert any(f.code == "metadata.id" for f in result.errors)

    def test_read_before_write_warning(self) -> None:
        # get_attr {"undefined"} before any set_attr/runcmd_to_var defines it
        ndl = '''pattern {
            metadata {id = "a" name = "x" citype = "cmdb_ci_appl"}
            identification {
                name = "i"
                find_process_strategy {strategy = LISTENING_PORT}
                step {
                    name = "use undefined"
                    set_attr {
                        "name"
                        get_attr {"never_set"}
                    }
                }
            }
        }'''
        result = PatternValidator().validate(ndl)
        assert any(
            f.code == "var.read_before_write" and "never_set" in f.message
            for f in result.warnings
        )

    def test_runcmd_to_var_writes_named_vars(self) -> None:
        # Reading a var that was just written by runcmd_to_var should NOT warn
        ndl = '''pattern {
            metadata {id = "a" name = "x" citype = "cmdb_ci_appl"}
            identification {
                name = "i"
                find_process_strategy {strategy = LISTENING_PORT}
                step {
                    name = "define"
                    runcmd_to_var {
                        cmd = "echo 1"
                        var_names = "myvar"
                    }
                }
                step {
                    name = "use"
                    set_attr {
                        "name"
                        get_attr {"myvar"}
                    }
                }
            }
        }'''
        result = PatternValidator().validate(ndl)
        assert not any(
            f.code == "var.read_before_write" and "myvar" in f.message
            for f in result.warnings
        )

    def test_put_file_writes_full_path_var(self) -> None:
        # put_file { full_path_var = "x" } should register x as written
        ndl = '''pattern {
            metadata {id = "a" name = "x" citype = "cmdb_ci_appl"}
            identification {
                name = "i"
                find_process_strategy {strategy = LISTENING_PORT}
                step {
                    name = "put"
                    put_file {
                        file = "myfile"
                        full_path_var = "myfile_path"
                    }
                }
                step {
                    name = "use"
                    set_attr {
                        "result"
                        get_attr {"myfile_path"}
                    }
                }
            }
        }'''
        result = PatternValidator().validate(ndl)
        assert not any(
            f.code == "var.read_before_write" and "myfile_path" in f.message
            for f in result.warnings
        )


# ---------------------------------------------------------------------------
# pattern_validate / pattern_create tools
# ---------------------------------------------------------------------------

class TestValidateTool:
    def test_returns_status_line(self, apache_unix_ndl: str) -> None:
        out = pattern_validate(apache_unix_ndl)
        assert out.startswith("Status: ")
        assert "Errors:" in out
        assert "Pattern: Apache on Unix" in out  # matches fixture

    def test_invalid_ndl_returns_invalid_status(self) -> None:
        out = pattern_validate("pattern { metadata { id = ")
        assert "Status: INVALID" in out
        assert "syntax" in out.lower()

    def test_verbose_flag_includes_info_findings(self) -> None:
        # Use a pattern that contains an unknown closure to trigger INFO findings.
        ndl = '''pattern {
            metadata {id = "a" name = "x" citype = "cmdb_ci_appl"}
            identification {
                name = "i"
                find_process_strategy {strategy = LISTENING_PORT}
                step {
                    name = "use unknown closure"
                    not_a_real_closure {something = "x"}
                }
            }
        }'''
        terse = pattern_validate(ndl, verbose=False)
        verbose = pattern_validate(ndl, verbose=True)
        assert "INFO" not in terse
        assert "INFO" in verbose


class TestCreateTool:
    def test_skeleton_emitted(self) -> None:
        out = pattern_create("Tomcat discovery", ci_type="cmdb_ci_app_server_tomcat",
                             index=None, chroma=None)
        assert "SKELETON" in out
        assert "pattern {" in out
        assert "cmdb_ci_app_server_tomcat" in out
        assert "metadata" in out

    def test_includes_relevant_closures(self) -> None:
        # "command" intent should surface command-running closures
        out = pattern_create("run shell command and parse output",
                             index=None, chroma=None)
        # Should match runcmd_to_var or similar via keyword scoring
        assert "RELEVANT CLOSURES" in out
