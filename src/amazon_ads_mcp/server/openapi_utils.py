"""OpenAPI utilities for the MCP server.

This module provides utilities for processing OpenAPI specifications,
including slimming large descriptions and managing spec resources.
"""

import copy
import logging
import os
from typing import Any, Dict, Optional, Set

logger = logging.getLogger(__name__)


def truncate_text(text: Optional[str], max_len: int) -> Optional[str]:
    """Truncate text to a maximum length with ellipsis.

    :param text: Text to truncate
    :type text: Optional[str]
    :param max_len: Maximum length
    :type max_len: int
    :return: Truncated text or original if shorter
    :rtype: Optional[str]
    """
    if not isinstance(text, str):
        return text
    if len(text) <= max_len:
        return text
    tail = "…"
    return text[: max(0, max_len - len(tail))] + tail


def _env_flag(name: str) -> bool:
    """Return True if an environment variable is set to a truthy value."""
    return os.getenv(name, "").lower() in ("1", "true", "yes")


# ---------------------------------------------------------------------------
# Internal helpers for Phases 2-4
# ---------------------------------------------------------------------------

def _collect_all_refs(obj: Any, refs: Set[str]) -> None:
    """Recursively collect all ``$ref`` targets from a JSON-like structure."""
    if isinstance(obj, dict):
        ref = obj.get("$ref")
        if isinstance(ref, str) and ref.startswith("#/"):
            refs.add(ref)
        for value in obj.values():
            _collect_all_refs(value, refs)
    elif isinstance(obj, list):
        for item in obj:
            _collect_all_refs(item, refs)


def _resolve_transitive_refs(spec: Dict[str, Any], refs: Set[str]) -> Set[str]:
    """Expand *refs* to include transitively referenced schemas."""
    schemas = spec.get("components", {}).get("schemas", {})
    resolved: Set[str] = set()
    queue = list(refs)

    while queue:
        ref = queue.pop()
        if ref in resolved:
            continue
        resolved.add(ref)
        # Only follow component/schema refs
        prefix = "#/components/schemas/"
        if not ref.startswith(prefix):
            continue
        name = ref[len(prefix):]
        schema = schemas.get(name)
        if not isinstance(schema, dict):
            continue
        nested: Set[str] = set()
        _collect_all_refs(schema, nested)
        for nr in nested:
            if nr not in resolved:
                queue.append(nr)

    return resolved


def _strip_response_bodies(spec: Dict[str, Any]) -> None:
    """Phase 2: Strip response *content* (schemas) while keeping valid stubs.

    OpenAPI 3.0 requires ``responses`` on every operation, so we cannot
    remove the key entirely.  Instead we keep status codes and descriptions
    but drop ``content``, ``headers``, and ``links`` - the heavy parts that
    FastMCP uses to build ``outputSchema``.
    """
    for _path, methods in (spec.get("paths") or {}).items():
        if not isinstance(methods, dict):
            continue
        for method, op in methods.items():
            if not isinstance(op, dict):
                continue
            responses = op.get("responses")
            if not isinstance(responses, dict):
                continue
            for status, response in responses.items():
                if isinstance(response, dict):
                    desc = response.get("description", "OK")
                    response.clear()
                    response["description"] = desc

    components = spec.get("components")
    if isinstance(components, dict):
        components.pop("responses", None)


def _eliminate_dead_schemas(spec: Dict[str, Any]) -> None:
    """Phase 3: Remove component schemas not referenced anywhere in the spec."""
    schemas = spec.get("components", {}).get("schemas", {})
    if not schemas:
        return

    # Collect every $ref in paths + non-schema components
    live_refs: Set[str] = set()
    _collect_all_refs(spec.get("paths", {}), live_refs)
    components = spec.get("components", {})
    for section in ("parameters", "requestBodies", "headers"):
        _collect_all_refs(components.get(section, {}), live_refs)

    # Expand transitively
    live_refs = _resolve_transitive_refs(spec, live_refs)

    # Schema names that are still alive
    alive = {
        ref.split("/")[-1]
        for ref in live_refs
        if ref.startswith("#/components/schemas/")
    }

    for name in list(schemas.keys()):
        if name not in alive:
            del schemas[name]


def _clean_schema_metadata(obj: Any) -> None:
    """Phase 4: Strip noise fields from all schemas (component and inline)."""
    noise_keys = {"title", "xml", "deprecated", "example", "examples", "externalDocs"}
    if isinstance(obj, dict):
        for key in noise_keys:
            obj.pop(key, None)
        for value in obj.values():
            _clean_schema_metadata(value)
    elif isinstance(obj, list):
        for item in obj:
            _clean_schema_metadata(item)


def _validate_request_schemas(spec: Dict[str, Any]) -> bool:
    """Return True if every requestBody schema is non-empty.

    A schema is "non-empty" if it has at least one of ``type``, ``$ref``,
    or ``properties``.
    """
    for _path, methods in (spec.get("paths") or {}).items():
        if not isinstance(methods, dict):
            continue
        for method, op in methods.items():
            if not isinstance(op, dict):
                continue
            req = op.get("requestBody")
            if not isinstance(req, dict):
                continue
            content = req.get("content")
            if not isinstance(content, dict):
                continue
            for _media, media_obj in content.items():
                if not isinstance(media_obj, dict):
                    continue
                schema = media_obj.get("schema")
                if isinstance(schema, dict) and not (
                    schema.get("type")
                    or schema.get("$ref")
                    or schema.get("properties")
                ):
                    return False
    return True


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def slim_openapi_for_tools(spec: Dict[str, Any], max_desc: int = 200) -> None:
    """Reduce large descriptions in OpenAPI operations and parameters.

    This helps keep tool metadata small when clients ingest tool definitions.
    Modifies the spec in place.

    **Phase 1** (always): Auth header removal + description truncation.
    **Phase 2** (``SLIM_OPENAPI_STRIP_RESPONSES=true``): Strip response bodies.
    **Phase 3** (``SLIM_OPENAPI_AGGRESSIVE=true``): Dead schema elimination.
    **Phase 4** (``SLIM_OPENAPI_AGGRESSIVE=true``): Schema metadata cleanup.

    :param spec: OpenAPI specification to slim
    :type spec: Dict[str, Any]
    :param max_desc: Maximum description length
    :type max_desc: int
    """
    try:
        # ----------------------------------------------------------------
        # Phase 1 - Auth header removal + description truncation (always)
        # ----------------------------------------------------------------
        auth_header_names = {
            "Authorization",
            "Amazon-Advertising-API-ClientId",
            "Amazon-Advertising-API-Scope",
        }
        auth_parameter_keys: set[str] = set()

        def resolve_local_ref(ref: str) -> Any:
            if not ref.startswith("#/"):
                return None
            current: Any = spec
            for part in ref[2:].split("/"):
                if not isinstance(current, dict) or part not in current:
                    return None
                current = current[part]
            return current

        def is_auth_parameter_ref(ref: str) -> bool:
            if not ref.startswith("#/components/parameters/"):
                return False
            key = ref.split("/")[-1]
            return key in auth_parameter_keys

        def is_auth_header_param(param: Dict[str, Any]) -> bool:
            if (
                param.get("in") == "header"
                and param.get("name") in auth_header_names
            ):
                return True

            ref = param.get("$ref")
            if isinstance(ref, str) and ref.startswith("#/"):
                if is_auth_parameter_ref(ref):
                    return True
                resolved = resolve_local_ref(ref)
                if isinstance(resolved, dict):
                    return (
                        resolved.get("in") == "header"
                        and resolved.get("name") in auth_header_names
                    )
            return False

        spec.pop("externalDocs", None)

        # Fix server URLs that have descriptions in them
        if "servers" in spec and isinstance(spec["servers"], list):
            fixed_servers = []
            for server in spec["servers"]:
                if isinstance(server, dict) and "url" in server:
                    url = server["url"]
                    # Extract just the URL part if it contains description
                    if " (" in url:
                        url = url.split(" (")[0].strip()
                    fixed_servers.append({"url": url})
            if fixed_servers:
                # Use the first server as default (North America)
                spec["servers"] = [fixed_servers[0]]

        # Remove auth header params that are supplied by auth middleware/client
        components = spec.get("components")
        if isinstance(components, dict):
            params = components.get("parameters")
            if isinstance(params, dict):
                for key, param in params.items():
                    if isinstance(param, dict) and is_auth_header_param(param):
                        auth_parameter_keys.add(key)

        for p, methods in (spec.get("paths") or {}).items():
            if not isinstance(methods, dict):
                continue

            # Path-item parameters
            path_params = methods.get("parameters") or []
            if isinstance(path_params, list):
                filtered_path_params = []
                for prm in path_params:
                    if isinstance(prm, dict) and "description" in prm:
                        prm["description"] = truncate_text(prm.get("description"), max_desc)
                    if isinstance(prm, dict) and is_auth_header_param(prm):
                        continue
                    filtered_path_params.append(prm)
                methods["parameters"] = filtered_path_params

            for m, op in list(methods.items()):
                if not isinstance(op, dict):
                    continue
                # Trim top-level description
                if "description" in op:
                    op["description"] = truncate_text(op.get("description"), max_desc)
                # Prefer summary if description missing or too long
                if not op.get("description") and op.get("summary"):
                    op["description"] = truncate_text(op.get("summary"), max_desc)
                op.pop("externalDocs", None)
                # Parameters
                params = op.get("parameters") or []
                if isinstance(params, list):
                    filtered_params = []
                    for prm in params:
                        if isinstance(prm, dict) and "description" in prm:
                            prm["description"] = truncate_text(
                                prm.get("description"), max_desc
                            )
                        if isinstance(prm, dict) and is_auth_header_param(prm):
                            continue
                        filtered_params.append(prm)
                    op["parameters"] = filtered_params
                # Request body description
                req = op.get("requestBody")
                if isinstance(req, dict) and "description" in req:
                    req["description"] = truncate_text(req.get("description"), max_desc)

        if auth_parameter_keys and isinstance(components, dict):
            params = components.get("parameters")
            if isinstance(params, dict):
                for key in auth_parameter_keys:
                    params.pop(key, None)

        # ----------------------------------------------------------------
        # Phases 2-4 - Gated behind env flags (default off)
        # ----------------------------------------------------------------
        strip_responses = _env_flag("SLIM_OPENAPI_STRIP_RESPONSES")
        aggressive = _env_flag("SLIM_OPENAPI_AGGRESSIVE")

        if strip_responses or aggressive:
            # Snapshot for safety rollback
            snapshot = copy.deepcopy(spec)

            # Phase 2 - Strip response bodies
            if strip_responses:
                _strip_response_bodies(spec)

            # Phase 3 - Dead schema elimination
            if aggressive:
                _eliminate_dead_schemas(spec)

            # Phase 4 - Clean schema metadata
            if aggressive:
                _clean_schema_metadata(spec.get("components", {}).get("schemas", {}))
                # Also clean inline schemas in paths
                for _path, methods in (spec.get("paths") or {}).items():
                    if not isinstance(methods, dict):
                        continue
                    for method, op in methods.items():
                        if not isinstance(op, dict):
                            continue
                        req = op.get("requestBody")
                        if isinstance(req, dict):
                            _clean_schema_metadata(req)
                        for prm in op.get("parameters") or []:
                            if isinstance(prm, dict) and "schema" in prm:
                                _clean_schema_metadata(prm["schema"])

            # Safety: validate requestBody schemas are non-empty
            if not _validate_request_schemas(spec):
                logger.warning(
                    "Aggressive slim produced empty requestBody schema; reverted"
                )
                spec.clear()
                spec.update(snapshot)

    except Exception:
        # Do not fail mounting if slimming fails
        pass
