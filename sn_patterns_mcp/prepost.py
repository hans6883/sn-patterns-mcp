"""Pre/post script analyzer — extracts variables and side effects from the
JavaScript scripts in `sa_pattern_prepost_script`.

Pre-scripts run BEFORE the pattern's identification steps. Their main job:
populate the discovery context with variables the pattern then reads
(e.g. `g_signal_state`, `discovery_type`, custom credentials picks).

Post-scripts run AFTER the pattern. They can transform output, log, or
raise alerts.

This module is pure regex — we don't run a real JS parser. Good enough for
extracting:
  - CTX.setAttribute("name", ...) calls           → variables this script defines
  - CTX.getAttribute("name")     calls           → variables this script reads
  - g_signal_state mutations                       → flow-control side effects
  - current.<field> references                     → fields read from sa_discovery context
  - PatternUtils.* / SncSAPatternUtils.* helpers   → common idioms

The validator uses the defined-variables list to suppress false read-before-write
warnings on patterns whose pre-scripts inject context variables.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

# CTX.setAttribute("varname", ...) — variable injected into context
_CTX_SET_RE = re.compile(r"""(?:CTX|context|ctx)\s*\.\s*setAttribute\s*\(\s*["']([^"']+)["']""")
_CTX_GET_RE = re.compile(r"""(?:CTX|context|ctx)\s*\.\s*getAttribute\s*\(\s*["']([^"']+)["']""")
# `current.fieldname` reads from the SN GlideRecord context
_CURRENT_FIELD_RE = re.compile(r"\bcurrent\.([a-zA-Z_][a-zA-Z0-9_]*)")
# `g_pattern_loop`, `g_signal_state`, etc. — pattern flow-control globals
_PATTERN_GLOBAL_RE = re.compile(r"\bg_([a-z_]+)\b")
# `PatternUtils.somethingClever()` — common helpers
_HELPER_CALL_RE = re.compile(r"\b([A-Z][a-zA-Z]*Utils?)\s*\.\s*([a-zA-Z_][a-zA-Z0-9_]*)")


@dataclass(frozen=True)
class PrepostAnalysis:
    """What a pre/post script does."""
    sets: tuple[str, ...] = ()           # CTX.setAttribute() variable names
    reads: tuple[str, ...] = ()          # CTX.getAttribute() variable names
    current_fields: tuple[str, ...] = () # current.<field> reads from sa_discovery_log GlideRecord
    pattern_globals: tuple[str, ...] = () # g_signal_state, g_pattern_loop, etc.
    helpers: tuple[tuple[str, str], ...] = ()  # (Class, method) helper calls
    has_javascript: bool = False
    line_count: int = 0


@dataclass
class PatternPrepostContext:
    """Aggregated effect of all pre+post scripts for a single pattern.

    The validator + pattern_analyze use this to:
      - know which variables are pre-defined (no false read-before-write)
      - report what the script bundle does to the agent
    """
    pattern_sys_id: str
    pre_scripts: list[PrepostAnalysis] = field(default_factory=list)
    post_scripts: list[PrepostAnalysis] = field(default_factory=list)

    @property
    def all_predefined_vars(self) -> set[str]:
        """Union of every variable any pre-script sets via CTX.setAttribute()."""
        out: set[str] = set()
        for s in self.pre_scripts:
            out.update(s.sets)
        return out

    @property
    def all_read_vars(self) -> set[str]:
        out: set[str] = set()
        for s in self.pre_scripts + self.post_scripts:
            out.update(s.reads)
        return out


def analyze_script(script_text: str | None) -> PrepostAnalysis:
    """Extract a script's CTX setAttribute/getAttribute + helper-usage signals."""
    if not script_text:
        return PrepostAnalysis()
    text = script_text
    sets = tuple(sorted(set(_CTX_SET_RE.findall(text))))
    reads = tuple(sorted(set(_CTX_GET_RE.findall(text))))
    current_fields = tuple(sorted(set(_CURRENT_FIELD_RE.findall(text))))
    pattern_globals = tuple(sorted(set(_PATTERN_GLOBAL_RE.findall(text))))
    helpers = tuple(sorted(set(_HELPER_CALL_RE.findall(text))))
    return PrepostAnalysis(
        sets=sets,
        reads=reads,
        current_fields=current_fields,
        pattern_globals=pattern_globals,
        helpers=helpers,
        has_javascript=True,
        line_count=text.count("\n") + 1 if text.strip() else 0,
    )


def analyze_prepost_bundle(scripts: list[dict]) -> PatternPrepostContext:
    """Group scripts by phase (pre vs post) and analyze each.

    `scripts` is a list of sa_pattern_prepost_script rows. Phase comes from
    `phase` / `stage` / `type` field; default to 'pre' if unknown.
    """
    ctx = PatternPrepostContext(pattern_sys_id="")
    for row in scripts:
        if not isinstance(row, dict):
            continue
        ctx.pattern_sys_id = ctx.pattern_sys_id or str(row.get("pattern", ""))
        text = row.get("script") or row.get("script_preview") or ""
        analysis = analyze_script(text)
        phase = (
            row.get("phase") or row.get("stage") or row.get("type") or "pre"
        ).lower()
        if "post" in phase or "after" in phase:
            ctx.post_scripts.append(analysis)
        else:
            ctx.pre_scripts.append(analysis)
    return ctx


__all__ = [
    "PrepostAnalysis", "PatternPrepostContext",
    "analyze_script", "analyze_prepost_bundle",
]
