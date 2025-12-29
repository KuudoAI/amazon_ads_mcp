"""OpenAPI utilities for the MCP server.

This module provides utilities for processing OpenAPI specifications,
including slimming large descriptions and managing spec resources.
"""

from typing import Any, Dict, Optional


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


def slim_openapi_for_tools(spec: Dict[str, Any], max_desc: int = 200) -> None:
    """Reduce large descriptions in OpenAPI operations and parameters.

    This helps keep tool metadata small when clients ingest tool definitions.
    Modifies the spec in place.

    :param spec: OpenAPI specification to slim
    :type spec: Dict[str, Any]
    :param max_desc: Maximum description length
    :type max_desc: int
    """
    try:
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
    except Exception:
        # Do not fail mounting if slimming fails
        pass
