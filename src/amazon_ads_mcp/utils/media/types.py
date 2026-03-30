"""Media type registry and resolution for OpenAPI specifications.

This module provides functionality for managing and resolving media types
from OpenAPI specifications and sidecar files. It includes a registry
class that can build media type mappings from OpenAPI specs and resolve
content types for specific HTTP methods and URL paths.

The module handles both request and response media types, supports
templated paths, and provides caching for performance optimization.
"""

import re
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

from amazon_ads_mcp.utils.openapi import deref, oai_template_to_regex


class MediaTypeRegistry:
    """Registry for managing media types from OpenAPI specs and sidecars.

    This class maintains a registry of media types for both requests and
    responses, extracted from OpenAPI specifications and sidecar files.
    It provides methods to add media type mappings and resolve the
    appropriate content types for specific HTTP methods and URL paths.

    The registry supports templated paths and includes caching for
    improved performance when resolving media types.
    """

    def __init__(self) -> None:
        """Initialize the media type registry.

        Sets up internal storage for request entries, response entries,
        and a cache for resolved media type lookups.
        """
        self._req_entries: List[Dict[Tuple[str, str], str]] = []
        self._resp_entries: List[Dict[Tuple[str, str], List[str]]] = []
        self._cache: Dict[
            Tuple[str, str], Tuple[Optional[str], Optional[List[str]]]
        ] = {}
        self._bulk_loading: bool = False

    def begin_bulk_load(self) -> None:
        """Begin a bulk-loading phase.

        During bulk loading, cache invalidation is deferred until
        :meth:`end_bulk_load` is called. Use this when mounting
        multiple specs at startup to avoid redundant cache clears.
        """
        self._bulk_loading = True

    def end_bulk_load(self) -> None:
        """End the bulk-loading phase and invalidate the cache once.

        Call this after all specs have been registered during startup.
        """
        self._bulk_loading = False
        self._cache.clear()

    def add_from_spec(self, spec: dict) -> None:
        """Add media type mappings from an OpenAPI specification.

        Extracts request and response media types from the provided
        OpenAPI specification and adds them to the registry. Clears
        the internal cache to ensure fresh lookups (deferred during
        bulk loading).

        :param spec: OpenAPI specification dictionary
        :type spec: dict
        """
        req_map, resp_map = build_media_maps_from_spec(spec)
        self._req_entries.append(req_map)
        self._resp_entries.append(resp_map)
        if not self._bulk_loading:
            self._cache.clear()

    def add_from_sidecar(self, sidecar: dict) -> None:
        """Add media type mappings from a sidecar configuration file.

        Processes sidecar configuration to extract request and response
        media type mappings. The sidecar should contain 'requests' and
        'responses' sections with method+path keys and media type values.

        :param sidecar: Sidecar configuration dictionary
        :type sidecar: dict
        """
        req_map: Dict[Tuple[str, str], str] = {}
        resp_map: Dict[Tuple[str, str], List[str]] = {}
        for k, v in (sidecar.get("requests") or {}).items():
            m, p = split_method_path_key(k)
            if m and p and isinstance(v, str):
                req_map[(m, p)] = v
        for k, v in (sidecar.get("responses") or {}).items():
            m, p = split_method_path_key(k)
            if m and p and isinstance(v, list):
                resp_map[(m, p)] = list(v)
        if req_map or resp_map:
            self._req_entries.append(req_map)
            self._resp_entries.append(resp_map)
            if not self._bulk_loading:
                self._cache.clear()

    def resolve(
        self, method: str, url: str
    ) -> Tuple[Optional[str], Optional[List[str]]]:
        """Resolve media types for a specific HTTP method and URL.

        Attempts to find the appropriate request and response media
        types for the given method and URL. First checks for exact
        matches, then falls back to templated path matching. Results
        are cached for subsequent lookups.

        :param method: HTTP method (e.g., 'GET', 'POST')
        :type method: str
        :param url: URL to resolve media types for
        :type url: str
        :return: Tuple of (request_media_type, response_media_types)
        :rtype: Tuple[Optional[str], Optional[List[str]]]
        """
        m = (method or "get").lower()
        path = (urlparse(url).path or "/").rstrip("/") or "/"
        cache_key = (m, path)
        if cache_key in self._cache:
            return self._cache[cache_key]
        for req_map, resp_map in zip(self._req_entries, self._resp_entries):
            if (m, path) in req_map or (m, path) in resp_map:
                result = (req_map.get((m, path)), resp_map.get((m, path)))
                self._cache[cache_key] = result
                return result
        for req_map, resp_map in zip(self._req_entries, self._resp_entries):
            keys: Set[Tuple[str, str]] = set(req_map.keys()) | set(resp_map.keys())
            for mm, templated in keys:
                if mm != m:
                    continue
                if re.match(oai_template_to_regex(templated), path):
                    result = (
                        req_map.get((mm, templated)),
                        resp_map.get((mm, templated)),
                    )
                    self._cache[cache_key] = result
                    return result
        result = (None, None)
        self._cache[cache_key] = result
        return result


def split_method_path_key(key: str) -> Tuple[Optional[str], Optional[str]]:
    """Split a method+path key into separate method and path components.

    Parses keys in the format "METHOD /path" (e.g., "GET /users/{id}")
    and returns the method and path as separate components. Handles
    path normalization including leading slash addition and trailing
    slash removal.

    :param key: Method+path key string (e.g., "POST /api/users")
    :type key: str
    :return: Tuple of (method, path) or (None, None) if parsing fails
    :rtype: Tuple[Optional[str], Optional[str]]
    """
    parts = (key or "").strip().split(" ", 1)
    if len(parts) != 2:
        return None, None
    method = parts[0].lower()
    path = parts[1].strip()
    if not path.startswith("/"):
        path = "/" + path
    path = path.rstrip("/") or "/"
    return method, path


def build_media_maps_from_spec(
    openapi_spec: dict,
) -> Tuple[Dict[Tuple[str, str], str], Dict[Tuple[str, str], List[str]]]:
    """Build media type mappings from an OpenAPI specification.

    Extracts request and response media types from the OpenAPI spec's
    paths section. For each operation, it identifies the content types
    for request bodies and response content, building comprehensive
    mappings keyed by method and path.

    :param openapi_spec: OpenAPI specification dictionary
    :type openapi_spec: dict
    :return: Tuple of (request_media_map, response_media_map)
    :rtype: Tuple[Dict[Tuple[str, str], str], Dict[Tuple[str, str], List[str]]]
    """
    req_media: Dict[Tuple[str, str], str] = {}
    resp_media: Dict[Tuple[str, str], List[str]] = {}
    paths = openapi_spec.get("paths", {}) or {}
    for raw_path, ops in paths.items():
        if not isinstance(ops, dict):
            continue
        norm_path = (raw_path or "/").rstrip("/") or "/"
        for method, op in ops.items():
            if not isinstance(op, dict):
                continue
            m = method.lower()
            rb = deref(openapi_spec, op.get("requestBody"))
            rb_content = (rb or {}).get("content", {}) if isinstance(rb, dict) else {}
            if isinstance(rb_content, dict) and rb_content:
                ct = sorted(rb_content.keys())[0]
                req_media[(m, norm_path)] = ct
            responses = (op.get("responses") or {}) if isinstance(op, dict) else {}
            accepts: Set[str] = set()
            if isinstance(responses, dict):
                for _, r in responses.items():
                    r = deref(openapi_spec, r)
                    rc = (r or {}).get("content", {}) if isinstance(r, dict) else {}
                    if isinstance(rc, dict):
                        accepts.update(rc.keys())
            if accepts:
                resp_media[(m, norm_path)] = sorted(accepts)
    return req_media, resp_media


__all__ = [
    "MediaTypeRegistry",
    "split_method_path_key",
    "build_media_maps_from_spec",
]
