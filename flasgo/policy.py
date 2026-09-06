from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import TYPE_CHECKING, Any

from .auth import AllowAny, HasScope, IsAuthenticated
from .ratelimit import endpoint_rate_limits
from .validation import SchemaRegistry

if TYPE_CHECKING:
    from .app import Flasgo


@dataclass(frozen=True, slots=True)
class PolicyIssue:
    code: str
    message: str
    severity: str = "warning"

    def to_dict(self) -> dict[str, str]:
        """
        Convert the policy issue to a dictionary.

        Returns:
                dict[str, str]: The issue code, message, and severity.
        """
        return asdict(self)


def _permission(permission: object) -> dict[str, Any]:
    """Serialize a permission declaration for inclusion in a policy snapshot.

    Parameters:
        permission (object): Permission declaration to serialize.

    Returns:
        dict[str, Any]: Serialized permission metadata, including its kind and any applicable configuration.
    """
    if type(permission) is HasScope:
        return {"kind": "scope", "scope": permission.scope}
    if type(permission) is IsAuthenticated:
        return {"kind": "authenticated"}
    if type(permission) is AllowAny:
        return {"kind": "allow_any"}
    name = getattr(permission, "__qualname__", type(permission).__qualname__)
    module = getattr(permission, "__module__", type(permission).__module__)
    return {"kind": "custom", "callable": f"{module}.{name}", "semantics": "application-owned"}


def _response_schema(model: object) -> dict[str, Any] | None:
    """
    Build a response schema representation for a configured model.

    Parameters:
        model (object): The model used to generate the response schema.

    Returns:
        dict[str, Any] | None: A dictionary containing the schema and registered components, or `None` when no model is configured.
    """
    if model is None:
        return None
    registry = SchemaRegistry()
    schema = registry.schema_for(model)
    return {"schema": schema, "components": registry.schemas}


def policy_snapshot(app: Flasgo) -> dict[str, Any]:
    """
    Create a deterministic, schema-versioned snapshot of the application's framework security configuration.

    The snapshot includes global controls, internal endpoint settings, HTTP and WebSocket routes, authentication and permission
    declarations, CSRF and CORS settings, rate limits, and response contracts. Secret values are excluded; custom authorization and
    middleware require application review.

    Returns:
        dict[str, Any]: A policy snapshot containing the schema version, security controls,
        internal endpoints, and indexed route configuration.
    """
    security = app.security
    routes = []
    for protocol, collection in (("http", app._routes), ("websocket", app._websocket_routes)):
        for route in collection:
            auth = app._route_auth.get(route.endpoint)
            cors = getattr(route, "cors", None)
            methods = sorted(getattr(route, "methods", ()))
            routes.append(
                {
                    "protocol": protocol,
                    "path": route.raw_path,
                    "methods": methods,
                    "name": route.name,
                    "declared_public": getattr(route, "public", False),
                    "authentication": auth.backend if auth else None,
                    "permissions": [_permission(item) for item in auth.permissions] if auth else [],
                    "csrf_methods": [method for method in methods if method not in security.csrf_safe_methods]
                    if security.csrf_enabled
                    else [],
                    "cors": {
                        "origins": sorted(cors.allow_origins),
                        "methods": sorted(cors.allow_methods),
                        "headers": sorted(cors.allow_headers),
                        "credentials": cors.allow_credentials,
                        "expose_headers": sorted(cors.expose_headers),
                        "max_age": cors.max_age,
                    }
                    if cors
                    else None,
                    "rate_limits": [
                        {
                            "requests": rule.requests,
                            "window_seconds": rule.window_seconds,
                            "scope": rule.scope,
                            "key": "application-owned" if rule.key_func else "client_ip",
                        }
                        for rule in endpoint_rate_limits(route.endpoint)
                    ],
                    "response_contract": _response_schema(getattr(route, "response_model", None)),
                }
            )
    routes.sort(key=lambda route: (route["protocol"], route["path"], route["methods"], route["name"] or ""))
    return {
        "schema_version": 1,
        "scope": "Framework configuration only; custom authorization and middleware require application review.",
        "controls": {
            "allowed_hosts": sorted(security.allowed_hosts),
            "enforce_allowed_hosts": security.enforce_allowed_hosts,
            "csrf_enabled": security.csrf_enabled,
            "csrf_check_origin": security.csrf_check_origin,
            "csrf_require_origin": security.csrf_require_origin,
            "csrf_trusted_origins": sorted(security.csrf_trusted_origins),
            "csrf_cookie_secure": security.csrf_cookie_secure,
            "session_cookie_secure": security.session_cookie_secure,
            "session_cookie_http_only": security.session_cookie_http_only,
            "session_cookie_same_site": security.session_cookie_same_site,
            "no_store": security.enforce_no_store_cache,
            "request_body_bytes": security.max_request_body_bytes,
            "request_head_bytes": security.max_request_head_bytes,
            "request_read_timeout_seconds": security.request_read_timeout_seconds,
            "multipart_parts": security.max_multipart_parts,
            "form_fields": security.max_form_fields,
            "security_failure_limit": security.security_failure_rate_limit,
            "security_failure_window_seconds": security.security_failure_window_seconds,
            "security_header_names": sorted(security.security_headers),
            "validation_depth": security.max_validation_depth,
            "validation_work": security.max_validation_work,
            "validation_issues": security.max_validation_issues,
            "websocket_origin_enforced": app.settings.WEBSOCKET_ENFORCE_ORIGIN,
            "websocket_missing_origin_allowed": app.settings.WEBSOCKET_ALLOW_MISSING_ORIGIN,
            "websocket_origins": sorted(app.settings.WEBSOCKET_ALLOWED_ORIGINS),
            "websocket_message_bytes": app.settings.WEBSOCKET_MAX_MESSAGE_BYTES,
            "websocket_messages_per_minute": app.settings.WEBSOCKET_MAX_MESSAGES_PER_MINUTE,
            "security_logging": security.log_security_events,
            "rate_limit_capacity": getattr(app._rate_limiter, "max_keys", None),
            "rate_limit_backend": type(app._rate_limiter).__name__,
            "session_backend": type(getattr(app, "_session_backend", None)).__name__
            if getattr(app, "_session_backend", None)
            else "signed_cookie",
        },
        "internal_endpoints": {
            "docs": {
                "enabled": app.settings.ENABLE_DOCS,
                "backend": app.settings.DOCS_AUTH_BACKEND,
                "paths": [app.settings.DOCS_PATH, app.settings.OPENAPI_PATH],
            },
            "metrics": {
                "enabled": app.settings.METRICS_ENABLED,
                "path": app.settings.METRICS_PATH,
                "authentication": "bearer",
            },
        },
        "routes": routes,
    }


def deployment_issues(app: Flasgo) -> list[PolicyIssue]:
    """
    Identify deployment configuration issues and routes with inconsistent access declarations.

    Parameters:
        app (Flasgo): The application whose security and route configuration is evaluated.

    Returns:
        list[PolicyIssue]: Detected deployment and route access policy issues.
    """
    security = app.security
    checks = (
        (app.settings.DEBUG, "FG001", "DEBUG is enabled."),
        (
            not security.enforce_allowed_hosts or "*" in security.allowed_hosts,
            "FG002",
            "Host validation is disabled or unrestricted.",
        ),
        (
            not security.session_cookie_secure or not security.session_cookie_http_only,
            "FG003",
            "Session cookies require Secure and HttpOnly for deployment.",
        ),
        (
            not security.csrf_enabled,
            "FG004",
            "CSRF is disabled; verify this application does not accept ambient browser credentials.",
        ),
        (
            security.csrf_enabled
            and (not security.csrf_cookie_secure or not security.csrf_check_origin or not security.csrf_require_origin),
            "FG005",
            "CSRF cookie or origin protections have been relaxed.",
        ),
        (
            app.settings.ENABLE_DOCS and not app.settings.DOCS_AUTH_BACKEND,
            "FG006",
            "Documentation endpoints are enabled without authentication.",
        ),
        (not security.log_security_events, "FG007", "Security event logging is disabled."),
        (
            bool(app._websocket_routes) and (not app.settings.WEBSOCKET_ENFORCE_ORIGIN or app.settings.WEBSOCKET_ALLOW_MISSING_ORIGIN),
            "FG008",
            "WebSocket browser origin protections have been relaxed.",
        ),
        (not security.enforce_no_store_cache, "FG009", "Default sensitive-response cache protection is disabled."),
    )
    issues = [PolicyIssue(code, message) for condition, code, message in checks if condition]
    for route in (*app._routes, *app._websocket_routes):
        auth = app._route_auth.get(route.endpoint)
        if route.public and auth is not None:
            issues.append(PolicyIssue("FG010", f"Route {route.raw_path} declares public access and authorization.", "error"))
        elif not route.public and auth is None:
            issues.append(PolicyIssue("FG011", f"Route {route.raw_path} has no declared access policy; use public=True or authorize()."))
    return issues


def compare_policy(before: object, after: dict[str, Any]) -> list[dict[str, Any]]:
    """
    Compare two version-1 policy snapshots and identify changes to controls, internal endpoints, and routes.

    Parameters:
        before (object): The earlier policy snapshot to validate and compare.
        after (dict[str, Any]): The later policy snapshot.

    Returns:
        list[dict[str, Any]]: Change records containing the affected section and its values before and after the change.

    Raises:
        ValueError: If the earlier snapshot is not a version-1 policy snapshot or the snapshot structure is invalid.
    """
    if not isinstance(before, dict) or type(before.get("schema_version")) is not int or before["schema_version"] != 1:
        raise ValueError("Expected a Flasgo policy snapshot with schema_version=1.")
    if set(before) != set(after) or not isinstance(before.get("routes"), list):
        raise ValueError("Policy snapshot has an invalid structure.")
    changes = [
        {"section": key, "before": before[key], "after": after[key]}
        for key in ("controls", "internal_endpoints")
        if before[key] != after[key]
    ]
    old_routes = _index_routes(before["routes"])
    new_routes = _index_routes(after["routes"])
    changes.extend(
        {"section": "routes", "route": key, "before": old_routes.get(key), "after": new_routes.get(key)}
        for key in sorted(old_routes.keys() | new_routes.keys())
        if old_routes.get(key) != new_routes.get(key)
    )
    return changes


def _index_routes(routes: list[Any]) -> dict[str, dict[str, Any]]:
    """
    Validate and index policy snapshot routes by protocol, path, and methods.

    Parameters:
        routes (list[Any]): Route entries from a policy snapshot.

    Returns:
        dict[str, dict[str, Any]]: Routes indexed by a serialized protocol, path, and sorted-methods key.

    Raises:
        ValueError: If a route is malformed, uses an unsupported protocol or non-string method, or duplicates another route.
    """
    import json

    indexed = {}
    for route in routes:
        if not isinstance(route, dict) or not isinstance(route.get("path"), str) or not isinstance(route.get("methods"), list):
            raise ValueError("Policy snapshot contains an invalid route.")
        if route.get("protocol") not in {"http", "websocket"} or not all(isinstance(method, str) for method in route["methods"]):
            raise ValueError("Policy snapshot contains an invalid route protocol or method.")
        key = json.dumps([route["protocol"], route["path"], sorted(route["methods"])])
        if key in indexed:
            raise ValueError("Policy snapshot contains duplicate routes.")
        indexed[key] = route
    return indexed
