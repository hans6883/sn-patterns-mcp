"""
PDI client — direct REST calls against a ServiceNow Personal Developer Instance.

Contracts used by the MCP server:
    get_pattern(name_or_sys_id)                 -> dict (sa_pattern row) or None
    list_patterns(limit, offset)                -> list[dict]
    get_prepost_scripts(pattern_sys_id)          -> list[dict]
    get_classifiers_for_pattern(pattern_sys_id)  -> list[dict]
    get_library(sys_id)                          -> dict (sa_pattern row for a library)
    query(table, sysparm_query, fields)          -> list[dict] (generic)

Credentials:
    SN_INSTANCE    (e.g. "https://dev123456.service-now.com")
    SN_USERNAME
    SN_PASSWORD
Loaded from environment. If missing, every method raises PdiUnavailable and the
MCP server falls back to the local pattern_index.
"""
from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass
from typing import Any

log = logging.getLogger(__name__)

# Conservative whitelist for ServiceNow Table API name lookups — blocks ^/=/| etc.
# that would let a caller pivot the sysparm_query to other records.
_SAFE_NAME_RE = re.compile(r"^[A-Za-z0-9 _\-./()]+$")
_SYS_ID_RE = re.compile(r"^[0-9a-fA-F]{32}$")

# Track 2 sandbox: any pattern this MCP creates/updates/deletes MUST start with this.
# Refuses to touch real patterns even if the caller mistypes a name.
SANDBOX_PREFIX = "_sandbox_snmcp_"


class SandboxViolation(RuntimeError):
    """Raised when a write operation targets a pattern outside the sandbox prefix."""


def _ensure_sandbox(name: str) -> str:
    if not name.startswith(SANDBOX_PREFIX):
        raise SandboxViolation(
            f"Refusing to write to pattern {name!r}: name must start with {SANDBOX_PREFIX!r}. "
            f"This MCP server never modifies real patterns."
        )
    return _safe_name(name)


def _safe_name(s: str) -> str:
    if not _SAFE_NAME_RE.match(s):
        raise ValueError(f"Pattern name contains characters not allowed in PDI lookup: {s!r}")
    return s


class PdiUnavailable(RuntimeError):
    """Raised when PDI credentials/network are not available, or a request was rejected.

    `status` is the HTTP status code if the failure came from an HTTP response;
    None for client-side errors (timeouts, missing creds, JSON decode errors).
    """

    def __init__(self, message: str, status: int | None = None) -> None:
        super().__init__(message)
        self.status = status


@dataclass
class PdiConfig:
    instance: str
    username: str
    password: str
    timeout_seconds: int = 30


def _load_config() -> PdiConfig:
    instance = os.environ.get("SN_INSTANCE", "").strip()
    username = os.environ.get("SN_USERNAME", "").strip()
    password = os.environ.get("SN_PASSWORD", "")
    if not (instance and username and password):
        raise PdiUnavailable(
            "Missing SN_INSTANCE / SN_USERNAME / SN_PASSWORD in environment; "
            "set them to enable live PDI fallback."
        )
    return PdiConfig(instance=instance, username=username, password=password)


class PdiClient:
    """Live PDI client used for verification and on-demand pattern fetch."""

    def __init__(self, config: PdiConfig | None = None) -> None:
        self._config = config
        self._session = None

    def _get_session(self):
        if self._config is None:
            self._config = _load_config()
        if self._session is None:
            try:
                import requests
            except ImportError as e:
                raise PdiUnavailable("requests not installed") from e
            s = requests.Session()
            s.auth = (self._config.username, self._config.password)
            s.headers.update({
                "Accept": "application/json",
                "Content-Type": "application/json",
            })
            self._session = s
        return self._session

    def _base_url(self) -> str:
        host = self._config.instance
        if not host.startswith("http"):
            host = "https://" + host
        return host.rstrip("/")

    # -- Generic table query ---------------------------------------------------

    def query(
        self,
        table: str,
        sysparm_query: str = "",
        fields: list[str] | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        session = self._get_session()
        url = f"{self._base_url()}/api/now/table/{table}"
        params: dict[str, Any] = {
            "sysparm_limit": str(limit),
            "sysparm_offset": str(offset),
            "sysparm_display_value": "false",
            "sysparm_exclude_reference_link": "true",
        }
        if sysparm_query:
            params["sysparm_query"] = sysparm_query
        if fields:
            params["sysparm_fields"] = ",".join(fields)
        try:
            resp = session.get(url, params=params, timeout=self._config.timeout_seconds)
        except Exception as e:
            log.warning("PDI %s query failed: %s: %s", table, type(e).__name__, e)
            raise PdiUnavailable(f"PDI request failed ({type(e).__name__})") from e
        if resp.status_code in (401, 403):
            log.warning("PDI %s returned %s — credentials/role issue", table, resp.status_code)
            raise PdiUnavailable(f"PDI auth failed ({resp.status_code})", status=resp.status_code)
        if resp.status_code >= 400:
            log.warning("PDI %s returned %s for query=%r", table, resp.status_code, sysparm_query)
            raise PdiUnavailable(f"PDI HTTP {resp.status_code}", status=resp.status_code)
        try:
            body = resp.json()
        except ValueError as e:
            log.warning("PDI %s returned non-JSON (instance hibernating?): %s", table, e)
            raise PdiUnavailable("PDI returned non-JSON (instance may be hibernating)") from e
        return body.get("result", []) or []

    # -- High-level conveniences ----------------------------------------------

    def get_pattern(self, name_or_sys_id: str) -> dict[str, Any] | None:
        """Find one pattern by sys_id or by name. Names are sanitized to prevent sysparm_query injection."""
        if _looks_like_sysid(name_or_sys_id):
            rows = self.query("sa_pattern", f"sys_id={name_or_sys_id}", limit=1)
        else:
            safe = _safe_name(name_or_sys_id)
            rows = self.query("sa_pattern", f"name={safe}", limit=1)
            if not rows:
                rows = self.query("sa_pattern", f"nameLIKE{safe}", limit=5)
        return rows[0] if rows else None

    def list_patterns(self, limit: int = 1000, offset: int = 0) -> list[dict[str, Any]]:
        return self.query(
            "sa_pattern",
            sysparm_query="ORDERBYname",
            fields=["sys_id", "name", "description", "ci_type", "cpattern_type", "active", "version"],
            limit=limit,
            offset=offset,
        )

    def get_pattern_text(self, sys_id: str) -> str | None:
        # Try both possible field names for the NDL text — varies by release.
        if not _looks_like_sysid(sys_id):
            raise ValueError(f"sys_id must be 32 hex chars, got {sys_id!r}")
        rows = self.query("sa_pattern", f"sys_id={sys_id}", fields=["ndl", "pattern_text"], limit=1)
        if not rows:
            return None
        row = rows[0]
        return row.get("ndl") or row.get("pattern_text")

    def get_prepost_scripts(self, pattern_sys_id: str) -> list[dict[str, Any]]:
        if not _looks_like_sysid(pattern_sys_id):
            raise ValueError(f"sys_id must be 32 hex chars, got {pattern_sys_id!r}")
        return self.query(
            "sa_pattern_prepost_script",
            f"pattern={pattern_sys_id}^ORDERBYorder",
            limit=200,
        )

    def get_classifiers_for_pattern(self, pattern_sys_id: str) -> list[dict[str, Any]]:
        """Return classifiers that route discovery to this pattern.

        A pattern has no direct classifier FK. The relationship runs through the
        CI class: classifier.table (or .cmdb_ci_class on older releases) names a
        CI table, and sa_pattern.ci_type names the same. We:
          1. Look up the pattern's ci_type
          2. Query discovery_classifier (base table — covers all subclasses
             discovery_classy_proc / _snmp / _cim / _http_classifier / _ipid /
             _port_probe via class-table polymorphism) with table = ci_type
          3. Return the matching rows, including sys_class_name so the caller
             can tell which classifier method matched

        Returns [] if pattern is unknown, has no ci_type, or no classifiers
        route to it. Re-raises auth/network errors; swallows table-not-found.
        """
        if not _looks_like_sysid(pattern_sys_id):
            raise ValueError(f"sys_id must be 32 hex chars, got {pattern_sys_id!r}")

        # 1. Resolve the pattern's CI type
        pattern_rows = self.query(
            "sa_pattern", f"sys_id={pattern_sys_id}",
            fields=["sys_id", "name", "ci_type"], limit=1,
        )
        if not pattern_rows:
            return []
        ci_type = (pattern_rows[0].get("ci_type") or "").strip()
        if not ci_type:
            return []

        # 2. Query the polymorphic base table. Field name for CI type is
        #    `table` in modern releases, `cmdb_ci_class` in older ones.
        fields = [
            "sys_id", "name", "sys_class_name", "active",
            "table", "cmdb_ci_class",
            # Method-specific fields (only populated on matching subclass)
            "process_search", "process_match",
            "oid", "match_oid",
            "wbem_namespace", "wbem_class",
            "url_pattern", "match_url",
        ]
        for ci_field in ("table", "cmdb_ci_class"):
            try:
                rows = self.query(
                    "discovery_classifier",
                    f"{ci_field}={ci_type}^active=true",
                    fields=fields, limit=100,
                )
            except PdiUnavailable as e:
                # auth/network error → propagate so caller sees the real reason
                if "auth" in str(e).lower() or "request failed" in str(e).lower():
                    raise
                # HTTP 4xx (table or column missing on this release) → try next
                log.debug("classifier query on field %r failed: %s", ci_field, e)
                continue
            if rows:
                return rows
        return []

    def get_library(self, sys_id: str) -> dict[str, Any] | None:
        if not _looks_like_sysid(sys_id):
            raise ValueError(f"sys_id must be 32 hex chars, got {sys_id!r}")
        rows = self.query("sa_pattern", f"sys_id={sys_id}", limit=1)
        return rows[0] if rows else None

    # ------------------------------------------------------------------
    # Permission self-heal — discover the role required by sa_pattern's ACLs
    # at runtime — the role required for sa_pattern writes varies by release.
    # Falls back to a known set of candidate role names if ACL discovery fails.
    # ------------------------------------------------------------------

    # Fallback role set if ACL discovery fails (e.g., reading sys_security_acl
    # is itself ACL-blocked on hardened instances). Order = preference.
    _FALLBACK_WRITE_ROLES = ("pd_admin", "pattern_designer", "sam_core_admin")

    def _lookup_user_sys_id(self, username: str) -> str | None:
        rows = self.query(
            "sys_user",
            f"user_name={_safe_name(username)}",
            fields=["sys_id", "user_name"],
            limit=1,
        )
        return rows[0].get("sys_id") if rows else None

    def _lookup_role_sys_id(self, role_name: str) -> str | None:
        rows = self.query(
            "sys_user_role",
            f"name={_safe_name(role_name)}",
            fields=["sys_id", "name"],
            limit=1,
        )
        return rows[0].get("sys_id") if rows else None

    def _user_has_role(self, user_sys_id: str, role_sys_id: str) -> bool:
        rows = self.query(
            "sys_user_has_role",
            f"user={user_sys_id}^role={role_sys_id}",
            fields=["sys_id"],
            limit=1,
        )
        return bool(rows)

    def _grant_role(self, user_sys_id: str, role_sys_id: str) -> None:
        self._write("POST", "sys_user_has_role", sys_id=None,
                    body={"user": user_sys_id, "role": role_sys_id})

    def discover_required_roles(self, table: str, operations: tuple[str, ...] = ("write", "create")) -> list[str]:
        """Read sys_security_acl + sys_security_acl_role to find roles that gate this table's ops.

        Returns role names, deduplicated, with fallback to _FALLBACK_WRITE_ROLES if discovery
        finds nothing (e.g., ACL tables are themselves ACL-blocked).
        """
        try:
            acls = self.query(
                "sys_security_acl",
                f"name={_safe_name(table)}^operationIN{','.join(operations)}^active=true",
                fields=["sys_id", "operation"],
                limit=20,
            )
        except (PdiUnavailable, ValueError) as e:
            log.info("ACL discovery for %s unavailable (%s) — falling back to known role set", table, e)
            return list(self._FALLBACK_WRITE_ROLES)
        roles: list[str] = []
        for acl in acls:
            try:
                links = self.query(
                    "sys_security_acl_role",
                    f"sys_security_acl={acl['sys_id']}",
                    fields=["sys_user_role.name"],
                    limit=20,
                )
            except PdiUnavailable as e:
                log.debug("acl_role link table for %s unavailable: %s", acl["sys_id"], e)
                continue
            for link in links:
                name = link.get("sys_user_role.name")
                if name and name not in roles:
                    roles.append(name)
        if not roles:
            log.info("ACL discovery for %s returned no roles — falling back", table)
            return list(self._FALLBACK_WRITE_ROLES)
        return roles

    def ensure_write_permission(self, table: str = "sa_pattern") -> list[str]:
        """Idempotently grant ANY role that gates writes to `table` to the configured user.

        Discovers required roles via the ACL tables; falls back to known role names if
        discovery is blocked. We grant just one — whichever exists and isn't already held —
        so the user picks up minimum needed privilege.

        Returns the list of roles newly granted (empty if user already has at least one).
        """
        if self._config is None:
            self._config = _load_config()
        user_sys_id = self._lookup_user_sys_id(self._config.username)
        if not user_sys_id:
            raise PdiUnavailable(f"Could not resolve user_name={self._config.username!r} in sys_user")

        candidates = self.discover_required_roles(table)
        log.debug("required-role candidates for %s: %s", table, candidates)

        # Already have at least one of the required roles → nothing to do
        for role_name in candidates:
            role_sys_id = self._lookup_role_sys_id(role_name)
            if role_sys_id and self._user_has_role(user_sys_id, role_sys_id):
                log.info("User %s already has role %s — no grant needed", self._config.username, role_name)
                return []

        # Grant the first existing candidate
        newly_granted: list[str] = []
        for role_name in candidates:
            role_sys_id = self._lookup_role_sys_id(role_name)
            if not role_sys_id:
                log.debug("role %r not found on this PDI; trying next candidate", role_name)
                continue
            log.info("Granting role %s to user %s for %s writes", role_name, self._config.username, table)
            self._grant_role(user_sys_id, role_sys_id)
            newly_granted.append(role_name)
            # Drop the cached HTTP session — the existing session has stale role
            # memberships; the next request will re-auth and pick up the grant.
            self._session = None
            return newly_granted  # one grant is enough — minimum privilege

        # No candidate role even exists on this PDI
        raise PdiUnavailable(
            f"None of the candidate roles {candidates} exist on this PDI; "
            f"cannot self-heal write permission for {table}."
        )

    # ------------------------------------------------------------------
    # WRITE OPERATIONS — sandboxed. All require name to start with SANDBOX_PREFIX.
    # ------------------------------------------------------------------

    def _write(self, method: str, table: str, sys_id: str | None, body: dict | None) -> dict | None:
        """POST (sys_id=None) / PUT / DELETE against the Table API. Returns the parsed result row, or None for DELETE.

        Routing of 4xx responses:
          - 401 with no/auth body → PdiUnavailable (wrong password)
          - 403 with no/auth body → PdiUnavailable (missing role)
          - 4xx with structured {"error": {"message": ..., "detail": ...}} body → PdiRejected
            (this includes 403 when a Business Rule aborts the write, e.g., Validate NDL)
        """
        session = self._get_session()
        url = f"{self._base_url()}/api/now/table/{table}"
        if sys_id is not None:
            if not _looks_like_sysid(sys_id):
                raise ValueError(f"sys_id must be 32 hex chars, got {sys_id!r}")
            url = f"{url}/{sys_id}"
        try:
            resp = session.request(method, url, json=body, timeout=self._config.timeout_seconds)
        except Exception as e:
            log.warning("PDI %s %s failed: %s: %s", method, table, type(e).__name__, e)
            raise PdiUnavailable(f"PDI {method} failed ({type(e).__name__})") from e
        if method == "DELETE" and resp.status_code in (200, 204):
            return None

        # Distinguish an auth failure (no body, or generic auth body) from a structured
        # rejection (Business Rule aborted, dictionary violation, etc.).
        if resp.status_code >= 400:
            try:
                err_body = resp.json()
            except ValueError:
                err_body = None
            structured_error = (
                isinstance(err_body, dict)
                and isinstance(err_body.get("error"), dict)
                and err_body["error"].get("message")
            )
            if resp.status_code in (401, 403) and not structured_error:
                log.warning("PDI %s %s returned %s with no structured body — auth/role issue",
                            method, table, resp.status_code)
                raise PdiUnavailable(f"PDI auth failed ({resp.status_code})", status=resp.status_code)
            log.warning("PDI %s %s returned %s with structured error: %s",
                        method, table, resp.status_code, err_body)
            raise PdiRejected(status=resp.status_code, body=err_body or {"raw": resp.text[:500]})
        try:
            body_json = resp.json()
        except ValueError as e:
            log.warning("PDI %s %s returned non-JSON: %s", method, table, e)
            raise PdiUnavailable("PDI returned non-JSON (instance may be hibernating)") from e
        return body_json.get("result")

    def create_pattern(self, name: str, ndl: str, ci_type: str = "", description: str = "") -> dict[str, Any]:
        """POST a new sandbox row to sa_pattern. Returns the created row (incl. sys_id).

        The name must start with SANDBOX_PREFIX — refuses to create real patterns.
        Raises PdiRejected with the PDI error body if SN rejects the NDL.
        """
        safe = _ensure_sandbox(name)
        row = {
            "name": safe,
            "ndl": ndl,
            "ci_type": ci_type or "",
            "description": description or "Sandbox pattern created by sn-patterns-mcp test_compile",
            "active": "false",  # never make sandbox patterns active in discovery
        }
        result = self._write("POST", "sa_pattern", sys_id=None, body=row)
        if not result or not isinstance(result, dict):
            raise PdiUnavailable("create_pattern: PDI accepted but returned no result row")
        return result

    def update_pattern(self, sys_id: str, ndl: str, expected_name: str | None = None) -> dict[str, Any]:
        """PUT updated NDL to an existing sandbox row.

        If expected_name is provided, asserts the existing row's name matches AND has
        the sandbox prefix — protects against editing real patterns even if the sys_id
        is misremembered.
        """
        if not _looks_like_sysid(sys_id):
            raise ValueError(f"sys_id must be 32 hex chars, got {sys_id!r}")
        existing = self.get_library(sys_id)
        if existing is None:
            raise ValueError(f"sys_id {sys_id} not found in sa_pattern")
        existing_name = existing.get("name", "")
        if expected_name is not None and existing_name != expected_name:
            raise SandboxViolation(
                f"sys_id {sys_id} has name {existing_name!r}, expected {expected_name!r}"
            )
        _ensure_sandbox(existing_name)  # gate on the actual stored name
        result = self._write("PUT", "sa_pattern", sys_id=sys_id, body={"ndl": ndl})
        if not result or not isinstance(result, dict):
            raise PdiUnavailable("update_pattern: PDI accepted but returned no result row")
        return result

    def delete_pattern(self, sys_id: str, expected_name: str | None = None) -> None:
        """DELETE a sandbox row. Same protection as update_pattern — refuses to touch real rows."""
        if not _looks_like_sysid(sys_id):
            raise ValueError(f"sys_id must be 32 hex chars, got {sys_id!r}")
        existing = self.get_library(sys_id)
        if existing is None:
            log.info("delete_pattern: sys_id %s already absent", sys_id)
            return
        existing_name = existing.get("name", "")
        if expected_name is not None and existing_name != expected_name:
            raise SandboxViolation(
                f"sys_id {sys_id} has name {existing_name!r}, expected {expected_name!r}"
            )
        _ensure_sandbox(existing_name)
        self._write("DELETE", "sa_pattern", sys_id=sys_id, body=None)


class PdiRejected(RuntimeError):
    """PDI returned a 4xx with an error body — typically means malformed NDL or schema violation."""

    def __init__(self, status: int, body: dict) -> None:
        self.status = status
        self.body = body
        # ServiceNow error bodies look like: {"error": {"message": "...", "detail": "..."}, "status": "failure"}
        err = body.get("error") if isinstance(body, dict) else None
        if isinstance(err, dict):
            message = err.get("message", "?")
            detail = err.get("detail", "")
            super().__init__(f"PDI rejected ({status}): {message}; detail: {detail}")
        else:
            super().__init__(f"PDI rejected ({status}): {body!r}")


def _looks_like_sysid(s: str) -> bool:
    return bool(_SYS_ID_RE.match(s)) if s else False


# ---------------------------------------------------------------------------
# Graceful fallback when credentials aren't present
# ---------------------------------------------------------------------------

def try_create_client() -> PdiClient | None:
    """Return a PdiClient if credentials are available; else None."""
    try:
        return PdiClient(_load_config())
    except PdiUnavailable:
        return None


__all__ = [
    "PdiClient", "PdiConfig", "PdiUnavailable", "PdiRejected",
    "SandboxViolation", "SANDBOX_PREFIX", "try_create_client",
]
