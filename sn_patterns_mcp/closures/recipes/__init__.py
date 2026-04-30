"""Closure-level recipe library.

Recipes are tested NDL fragments attached to specific closures, addressing
known limitations of those closures (NOT thread-specific solutions). The
LLM composes them via InsertStepBefore/After by closure + recipe name.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

log = logging.getLogger(__name__)


@dataclass(frozen=True)
class Recipe:
    """A parameterized NDL fragment that addresses a closure-level limitation.

    The fragment is rendered by .format(**params) on `ndl_template`. Parameter
    substitution uses Python str.format() — recipe authors must double curly
    braces ({{ }}) to emit literal NDL braces.
    """
    closure: str                       # NDL keyword this recipe attaches to (e.g. "run_wmi_query_to_var")
    name: str                          # recipe name within the closure
    purpose: str                       # one-liner: what gap this recipe fills
    addresses_limitation: str          # description of the closure-level limitation
    parameters: dict[str, str] = field(default_factory=dict)  # name → human description
    requires_vars: list[str] = field(default_factory=list)    # vars expected upstream
    declares_vars: list[str] = field(default_factory=list)    # vars produced (post-template-substitution)
    ndl_template: str = ""

    def materialize(self, params: dict[str, Any]) -> str:
        """Substitute params and return the rendered NDL fragment.

        Substitution is restricted: only `{name}` placeholders for `name` in
        self.parameters are replaced. `{{` and `}}` are literal-brace escapes.
        No format specs, no attribute access, no conversions — defense in
        depth in case templates ever come from a non-trusted source (Darwin,
        user-uploaded recipes).

        Raises ValueError on missing parameters.
        """
        missing = [p for p in self.parameters if p not in params]
        if missing:
            raise ValueError(
                f"recipe {self.closure}.{self.name} missing required params: {missing}"
            )
        return _safe_substitute(self.ndl_template, params, recipe_name=f"{self.closure}.{self.name}")

    def declared_var_names(self, params: dict[str, Any]) -> list[str]:
        """Vars this recipe will declare AFTER parameter substitution."""
        out: list[str] = []
        for raw in self.declares_vars:
            try:
                out.append(_safe_substitute(raw, params, recipe_name=self.name))
            except ValueError:
                out.append(raw)
        return out


def _safe_substitute(template: str, params: dict[str, Any], *, recipe_name: str) -> str:
    """Substitute `{name}` for `name` in params; `{{` and `}}` are literal braces.

    Rejects any `{` that is not part of `{{` or `{name}` where name is `[a-zA-Z_][a-zA-Z0-9_]*`.
    """
    out: list[str] = []
    i = 0
    n = len(template)
    while i < n:
        c = template[i]
        if c == "{":
            if i + 1 < n and template[i + 1] == "{":
                out.append("{")
                i += 2
                continue
            # Otherwise must be `{name}` where name is a valid identifier
            j = i + 1
            while j < n and (template[j].isalnum() or template[j] == "_"):
                j += 1
            if j == i + 1 or j >= n or template[j] != "}":
                raise ValueError(
                    f"recipe {recipe_name}: malformed substitution starting at offset {i} "
                    f"(only {{name}} or {{{{ allowed; got {template[i:i+10]!r})"
                )
            name = template[i + 1 : j]
            if name not in params:
                raise ValueError(
                    f"recipe {recipe_name}: template references unknown parameter {name!r}"
                )
            out.append(str(params[name]))
            i = j + 1
            continue
        if c == "}":
            if i + 1 < n and template[i + 1] == "}":
                out.append("}")
                i += 2
                continue
            raise ValueError(
                f"recipe {recipe_name}: stray closing brace at offset {i} "
                "(use '}}' for a literal closing brace)"
            )
        out.append(c)
        i += 1
    return "".join(out)


# Module-level recipe registry, keyed by (closure_keyword, recipe_name).
_REGISTRY: dict[tuple[str, str], Recipe] = {}


def register(recipe: Recipe) -> Recipe:
    key = (recipe.closure, recipe.name)
    if key in _REGISTRY:
        log.warning("recipe %s.%s re-registered (overwrite)", recipe.closure, recipe.name)
    _REGISTRY[key] = recipe
    return recipe


def get_recipe(closure: str, name: str) -> Recipe | None:
    return _REGISTRY.get((closure, name))


def list_recipes(closure: str | None = None) -> list[Recipe]:
    if closure is None:
        return list(_REGISTRY.values())
    return [r for r in _REGISTRY.values() if r.closure == closure]


def all_closure_keywords() -> list[str]:
    return sorted({r.closure for r in _REGISTRY.values()})


# Auto-register on import.
from sn_patterns_mcp.closures.recipes import (  # noqa: E402, F401
    run_wmi_query_to_var,
    runcmd_to_var,
)

__all__ = [
    "Recipe",
    "register",
    "get_recipe",
    "list_recipes",
    "all_closure_keywords",
]
