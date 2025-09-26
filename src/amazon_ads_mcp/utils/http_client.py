"""Enhanced HTTP client for Amazon Ads API authentication.

This module provides an authenticated HTTP client that manages headers
for Amazon Advertising API calls. The client automatically handles
authentication, regional routing, and content negotiation.

Key Features:

- Automatic authentication header injection
- Regional endpoint routing based on identity/marketplace
- Media type negotiation with OpenAPI specs
- Header scrubbing to remove conflicting headers
- Special handling for different API endpoints
- Response shaping for large AMC payloads

Examples:
    >>> client = AuthenticatedClient(auth_manager=auth_mgr)
    >>> response = await client.get("/v2/profiles")
"""

import json
import logging
import os
from contextvars import ContextVar
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

import httpx

from ..config.settings import Settings
from ..utils.export_content_type_resolver import (
    resolve_download_accept_headers,
)
from ..utils.header_resolver import HeaderNameResolver
from ..utils.media import MediaTypeRegistry
from ..utils.region_config import RegionConfig

logger = logging.getLogger(__name__)

# Context-local routing overrides/state to avoid cross-request leakage
_REGION_OVERRIDE_VAR: ContextVar[Optional[str]] = ContextVar(
    "amazon_ads_region_override", default=None
)
# Marketplace override removed - deprecated functionality
_ROUTING_STATE_VAR: ContextVar[Dict[str, Any]] = ContextVar(
    "amazon_ads_routing_state", default={}
)


class AuthenticatedClient(httpx.AsyncClient):
    """Enhanced HTTP client that manages Amazon Ads API authentication headers.

    This client extends httpx.AsyncClient to provide automatic header management for
    Amazon Advertising API calls. It handles header scrubbing, injection, and media
    type negotiation.

    The client intercepts all HTTP requests and performs:

    1. Media type negotiation based on OpenAPI specifications
    2. Removal of conflicting or polluted headers
    3. Injection of proper Amazon Ads authentication headers
    4. Regional endpoint routing based on identity/marketplace
    5. Special handling for different API endpoint families

    Key Features:

    - Removes polluted headers from FastMCP
    - Injects correct Amazon authentication headers
    - Handles media type negotiation
    - Manages client ID fallbacks
    - Supports profile-specific header rules
    - Automatic regional endpoint routing
    - Response shaping for large AMC responses

    :param auth_manager: Authentication manager for header generation
    :type auth_manager: Optional[AuthManager]
    :param media_registry: Registry for content type negotiation
    :type media_registry: Optional[MediaTypeRegistry]
    :param header_resolver: Resolver for header name variations
    :type header_resolver: Optional[HeaderNameResolver]
    :raises httpx.RequestError: When required auth headers are missing

    .. example::
       >>> auth_mgr = get_auth_manager()
       >>> client = AuthenticatedClient(auth_manager=auth_mgr)
       >>> response = await client.get("/v2/campaigns")
    """

    # anything we consider "polluted" and must remove if present
    _FORBID_SUBSTRS = (
        "authorization",  # bearer from MCP client
        "amazon-ads-clientid",
        "amazon-advertising-api-clientid",
        "amazon-advertising-api-scope",
        "amazon-ads-accountid",
        "x-amz-access-token",
    )

    def __init__(
        self,
        *args,
        auth_manager=None,
        media_registry=None,
        header_resolver=None,
        **kwargs,
    ):
        super().__init__(*args, **kwargs)
        self.auth_manager = auth_manager
        self.media_registry: Optional[MediaTypeRegistry] = media_registry
        self.header_resolver: HeaderNameResolver = (
            header_resolver or HeaderNameResolver()
        )

    async def send(self, request: httpx.Request, **kwargs) -> httpx.Response:
        """Single interception point for all HTTP requests.

        This method is called for ALL requests, whether from:
        - Direct client.request() calls (which build a Request then call send)
        - FastMCP's OpenAPITool (which builds a Request then calls send)

        It handles:
            1. Media type negotiation based on OpenAPI specs
            2. Header scrubbing to remove polluted auth headers
            3. Injection of correct Amazon authentication headers
            4. Special handling for profiles API endpoints

        :param request: The HTTP request to send
        :type request: httpx.Request
        :param kwargs: Additional arguments to pass to the parent send method
        :type kwargs: Dict[str, Any]
        :return: The HTTP response
        :rtype: httpx.Response
        :raises httpx.RequestError: When required auth headers are missing
        """
        # Check if already processed (idempotent) - CRITICAL for preventing double injection
        if request.extensions.get("auth_injected"):
            logger.debug(
                f"Request already processed, skipping injection: {request.method} {request.url}"
            )
            return await super().send(request, **kwargs)

        # Mark as processing to prevent concurrent/recursive injection
        request.extensions["auth_injected"] = True

        # Log incoming request for debugging (only once)
        logger.debug(f"=== SEND: {request.method} {request.url}")
        logger.debug(f"    Headers before injection: {list(request.headers.keys())}")

        # Inject headers (only once)
        await self._inject_headers(request)

        logger.debug(f"Headers injected for {request.method} {request.url}")
        logger.debug(f"    Headers after injection: {list(request.headers.keys())}")

        # Log critical headers for debugging
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug(f"    Accept: {request.headers.get('accept', 'NOT SET')}")
            logger.debug(
                f"    Content-Type: {request.headers.get('content-type', 'NOT SET')}"
            )
            # Verify auth header is present
            if "authorization" in request.headers:
                auth_val = request.headers["authorization"]
                logger.debug(
                    f"    Authorization present: Bearer [{len(auth_val) - 7} chars]"
                )

        # Log the actual request headers right before sending
        logger.debug("=== ACTUAL REQUEST BEING SENT ===")
        logger.debug(f"URL: {request.url}")
        logger.debug("Headers:")
        for k, v in request.headers.items():
            if k.lower() in [
                "authorization",
                "amazon-advertising-api-clientid",
            ]:
                logger.debug(f"  {k}: [REDACTED]")
            else:
                logger.debug(f"  {k}: {v}")

        # Call parent's send
        resp = await super().send(request, **kwargs)

        # Best-effort fallback shaping for AMC endpoints when FastMCP transforms are unavailable
        try:
            ct = (resp.headers.get("Content-Type") or "").lower()
            if (
                "application/json" in ct
                or "/json" in ct
                or ct.startswith("application/vnd.")
            ):
                shaped = self._maybe_shape_amc_response(request, resp)
                if shaped is not None:
                    # Create new response with shaped content (avoid _content manipulation)
                    payload = json.dumps(shaped, ensure_ascii=False).encode("utf-8")

                    # Build new response object
                    resp = httpx.Response(
                        status_code=resp.status_code,
                        headers=dict(resp.headers),
                        content=payload,
                        request=request,
                    )
                    resp.headers["content-length"] = str(len(payload))
        except Exception as e:
            # Log but don't fail
            logger.debug(f"AMC response shaping failed: {e}")

        return resp

    def _maybe_shape_amc_response(
        self, request: httpx.Request, response: httpx.Response
    ) -> Optional[dict]:
        """Truncate ONLY large AMC (Analytics/Measurement) JSON responses.

        This is a runtime fallback for environments where FastMCP's
        transform_tool is not supported, ensuring clients don't receive
        extremely large AMC payloads in chat context.

        IMPORTANT: This should NOT apply to regular API endpoints like
        /v2/profiles, /v2/campaigns, etc. as they have proper pagination
        and clients need the full data.
        """
        try:
            method = (request.method or "").upper()
            if method not in ("GET", "POST", "PUT"):
                return None
            url = str(request.url)
            path = urlparse(url).path or ""
            data = response.json()

            # Only shape dict/array JSON
            if not isinstance(data, (dict, list)):
                return None

            # Determine cap based on endpoint family
            cap = None
            p = path.lower()
            if "/amc/reporting/" in p:
                if p.endswith("/datasources") and method == "GET":
                    cap = 3
                elif "/datasources/" in p and method == "GET":
                    cap = 5
                elif p.endswith("/workflows") and method == "GET":
                    cap = 10
                elif "/workflowexecutions" in p and method == "GET":
                    cap = 10
                else:
                    cap = 10
            elif "/amc/audiences/" in p:
                if "/connections" in p and method == "GET":
                    cap = 10
                elif "/metadata/" in p and method == "GET":
                    cap = 10
                elif "/records/" in p and method == "GET":
                    cap = 10
                elif "/query" in p and method == "GET":
                    cap = 10
                else:
                    cap = 10

            # DO NOT shape regular v2 API endpoints - they have proper pagination
            # Response shaping should ONLY apply to known large AMC responses
            # that don't have good pagination support

            if cap is None:
                return None

            return self._truncate_lists(data, cap)
        except Exception:
            return None

    def _truncate_lists(self, data: Any, n: int) -> Any:
        try:

            def walk(obj: Any) -> Any:
                if isinstance(obj, list):
                    return [walk(x) for x in obj[: max(0, n)]]
                if isinstance(obj, dict):
                    return {k: walk(v) for k, v in obj.items()}
                return obj

            return walk(data)
        except Exception:
            return data

    def _map_auth_headers_to_spec(self, auth_headers: Dict[str, str]) -> Dict[str, str]:
        """Map authentication headers to their OpenAPI spec preferred names.

        This handles header name normalization, ensuring that various forms of
        header names (e.g., Client-Id, ClientId) map to the preferred form from
        the OpenAPI specification.

        The mapping process consolidates header variants into the preferred
        names defined by the header resolver, ensuring consistency across
        different API endpoints and specifications.

        :param auth_headers: Original authentication headers
        :type auth_headers: Dict[str, str]
        :return: Mapped headers using preferred names
        :rtype: Dict[str, str]

        .. example::
           >>> headers = {"Client-Id": "abc123", "Scope": "456"}
           >>> mapped = client._map_auth_headers_to_spec(headers)
           >>> # Returns {"Amazon-Advertising-API-ClientId": "abc123", ...}
        """
        out: Dict[str, str] = dict(auth_headers)

        pref_client = (
            self.header_resolver.prefer_client() or "Amazon-Advertising-API-ClientId"
        )
        pref_scope = (
            self.header_resolver.prefer_scope() or "Amazon-Advertising-API-Scope"
        )
        pref_acct = self.header_resolver.prefer_account() or "Amazon-Ads-AccountId"

        # Normalize to preferred keys when variants exist
        def move_first(src_keys: List[str], dest_key: str) -> None:
            for s in src_keys:
                if s in out and out[s]:
                    out[dest_key] = out.pop(s)
                    return

        move_first(
            [
                "Amazon-Advertising-API-ClientId",
                "Amazon-Ads-ClientId",
                "Client-Id",
                "ClientId",
            ],
            pref_client,
        )
        move_first(
            ["Amazon-Advertising-API-Scope", "Amazon-Ads-Scope", "Scope"],
            pref_scope,
        )
        move_first(
            ["Amazon-Ads-AccountId", "Account-Id", "AccountId"],
            pref_acct,
        )

        return out

    def _get_env_client_id(self, current_value: str = "") -> Optional[str]:
        """Get client ID from environment variables.

        Prefers `AMAZON_AD_API_CLIENT_ID` (new naming) and falls back to
        `AMAZON_ADS_CLIENT_ID` (legacy), returning the first non-empty value.

        This method handles client ID resolution when the authentication
        provider doesn't supply a client ID or provides a placeholder value
        like "openbridge".

        :param current_value: Current client ID value (empty or 'openbridge')
        :type current_value: str
        :return: Client ID from environment or None
        :rtype: Optional[str]

        .. note::
           AMAZON_AD_API_CLIENT_ID takes precedence over AMAZON_ADS_CLIENT_ID
        """
        preferred = os.getenv("AMAZON_AD_API_CLIENT_ID")
        legacy = os.getenv("AMAZON_ADS_CLIENT_ID")
        env_client_id = preferred or legacy

        if env_client_id:
            env_name = (
                "AMAZON_AD_API_CLIENT_ID" if preferred else "AMAZON_ADS_CLIENT_ID"
            )
            if not current_value:
                logger.info(f"Using {env_name} from environment")
            else:
                logger.info(
                    f"Replacing 'openbridge' placeholder with {env_name} from environment"
                )
            return env_client_id

        # Nothing set in environment
        if not current_value:
            logger.debug(
                "No ClientId provided and no environment variable set. "
                "Set AMAZON_AD_API_CLIENT_ID (preferred) or AMAZON_ADS_CLIENT_ID."
            )
        else:
            logger.debug(
                f"ClientId '{current_value}' provided but checking for env override"
            )
        return None

    async def _inject_headers(self, request: httpx.Request) -> None:
        """Inject authentication and media headers into a request.

        Handles media negotiation, header scrubbing, auth header injection,
        and profiles endpoint special-casing.

        This method performs the core request transformation:

        1. Media type negotiation using the media registry
        2. Removal of polluted/conflicting headers
        3. Regional endpoint routing based on marketplace/identity
        4. Authentication header injection
        5. Special handling for specific endpoints

        :param request: The HTTP request to modify
        :type request: httpx.Request
        :raises httpx.RequestError: When authentication fails or is missing

        .. note::
           This method modifies the request object in-place
        """
        method = request.method
        url = str(request.url)
        path = urlparse(url).path

        # 1) MEDIA NEGOTIATION
        if self.media_registry:
            content_type, accepts = self.media_registry.resolve(method, url)
            if content_type and method.lower() != "get":
                request.headers["Content-Type"] = content_type
            # Respect pre-existing Accept header from upstream transforms/tools
            if accepts and "Accept" not in request.headers:
                preferred = next(
                    (a for a in accepts if a.startswith("application/vnd.")),
                    accepts[0],
                )
                request.headers["Accept"] = preferred

        # Heuristic Accept override for known download/report endpoints
        if (
            "Accept" not in request.headers
            or (request.headers.get("Accept") or "").strip() == "*/*"
        ):
            try:
                overrides = resolve_download_accept_headers(method, url)
                if overrides:
                    if self.media_registry:
                        # Intersect with available accepts if we have them
                        _, accepts = self.media_registry.resolve(method, url)
                        if accepts:
                            for ct in overrides:
                                if ct in accepts:
                                    request.headers["Accept"] = ct
                                    break
                            else:
                                request.headers["Accept"] = overrides[0]
                        else:
                            request.headers["Accept"] = overrides[0]
                    else:
                        request.headers["Accept"] = overrides[0]
            except Exception as e:
                logger.debug("Accept override skipped: %s", e)

        # 2) STRIP POLLUTED HEADERS
        removed = []
        for key in list(request.headers.keys()):
            if any(s in key.lower() for s in self._FORBID_SUBSTRS):
                removed.append(key)
                del request.headers[key]
        if removed:
            logger.debug("🧹 Scrubbed headers from request: %s", removed)

        # 2a) Dynamic region routing for Amazon Ads endpoints based on marketplace/profile
        try:
            p = path or ""
            # Apply to all Amazon Ads API paths: /v2/, /reporting/, /amc/, etc.
            if p.startswith("/v2/") or p.startswith("/reporting/") or "/amc/" in p:
                # Determine desired region: explicit override header, marketplace mapping, or env
                hdr = request.headers
                # Marketplace override removed - deprecated functionality
                # 1) Explicit session override or env
                region_override = (
                    (
                        (_REGION_OVERRIDE_VAR.get() or "")
                        or os.getenv("ADS_REGION_OVERRIDE", "")
                    )
                    .strip()
                    .lower()
                )
                region = (
                    region_override if region_override in {"na", "eu", "fe"} else None
                )
                source = None
                if region:
                    source = "override"

                # 2) Map marketplace → region if provided
                mp = hdr.get("Amazon-Advertising-API-MarketplaceId") or hdr.get(
                    "Amazon-Ads-MarketplaceId"
                )
                if not region and mp:
                    mp = mp.strip()
                    eu_mps = {
                        "A1PA6795UKMFR9",  # DE
                        "A1F83G8C2ARO7P",  # UK
                        "A13V1IB3VIYZZH",  # FR
                        "APJ6JRA9NG5V4",  # IT
                        "A1RKKUPIHCS9HS",  # ES
                        "A1805IZSGTT6HS",  # NL
                        "A2NODRKZP88ZB9",  # SE
                        "A1C3SOZRARQ6R3",  # PL
                    }
                    na_mps = {
                        "ATVPDKIKX0DER",  # US
                        "A2EUQ1WTGCTBG2",  # CA
                        "A1AM78C64UM0Y8",  # MX
                    }
                    fe_mps = {
                        "A1VC38T7YXB528",  # JP
                        "A39IBJ37TRP1C6",  # AU
                        "A19VAU5U5O7RUS",  # SG
                    }
                    if mp in eu_mps:
                        region = "eu"
                        source = "marketplace"
                    elif mp in na_mps:
                        region = "na"
                        source = "marketplace"
                    elif mp in fe_mps:
                        region = "fe"
                        source = "marketplace"

                # 3) Active identity region
                if not region and self.auth_manager:
                    try:
                        active_identity = self.auth_manager.get_active_identity()
                        logger.debug(
                            f"Auth manager active identity: {active_identity.id if active_identity else None}"
                        )
                        ident_region = self.auth_manager.get_active_region()
                        logger.debug(f"Auth manager active region: {ident_region}")
                        if ident_region:
                            region = ident_region
                            source = "identity"
                    except Exception as e:
                        logger.debug(f"Failed to get active region: {e}")

                # 4) If still unknown, fall back to configured settings region
                if not region:
                    try:
                        region = Settings().amazon_ads_region
                    except Exception:
                        region = "na"
                    source = source or "fallback"

                # Compute desired host
                host = RegionConfig.get_api_host(region)
                if Settings().amazon_ads_sandbox_mode:
                    host = host.replace("advertising-api", "advertising-api-test")

                # Rewrite request URL host if different
                u = urlparse(str(request.url))
                if u.netloc and u.netloc != host:
                    new_url = urlunparse(
                        (u.scheme, host, u.path, u.params, u.query, u.fragment)
                    )
                    request.url = httpx.URL(new_url)
                    # IMPORTANT: Also update the Host header to match the new URL
                    request.headers["host"] = host
                _ROUTING_STATE_VAR.set(
                    {
                        "override": _REGION_OVERRIDE_VAR.get(),
                        "source": source,
                        "region": region,
                        "host": host,
                        "marketplace": None,  # Deprecated
                    }
                )
                logger.debug(
                    "Region routing decided: source=%s region=%s host=%s",
                    source,
                    region,
                    host,
                )
        except Exception:
            pass

        # 2b) Normalize AMC time query params to expected ISO format (no timezone suffix)
        try:
            p_lower = (path or "").lower()
            if "/amc/" in p_lower and "/workflowexecutions" in p_lower:
                url_obj = urlparse(url)
                q = dict(parse_qsl(url_obj.query, keep_blank_values=True))

                def to_amc_iso(val: str) -> str:
                    s = (val or "").strip()
                    if not s:
                        return s
                    # numeric seconds or ms -> convert to ISO 'YYYY-MM-DDTHH:MM:SS'
                    if s.isdigit():
                        n = int(s)
                        # scale seconds to ms if needed, then to UTC ISO (no 'Z')
                        if n < 10**12:
                            n *= 1000
                        dt = datetime.fromtimestamp(n / 1000, tz=timezone.utc)
                        return dt.strftime("%Y-%m-%dT%H:%M:%S")
                    # ISO formats and dates -> normalize to no-suffix ISO
                    try:
                        iso = s
                        if iso.endswith("Z"):
                            iso = iso[:-1] + "+00:00"
                        if len(iso) == 10 and iso.count("-") == 2:
                            iso = iso + "T00:00:00+00:00"
                        if len(s) == 8 and s.isdigit():
                            iso = f"{s[0:4]}-{s[4:6]}-{s[6:8]}T00:00:00+00:00"
                        dt = datetime.fromisoformat(iso)
                        if dt.tzinfo is None:
                            dt = dt.replace(tzinfo=timezone.utc)
                        return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")
                    except Exception:
                        return s

                changed = False
                for key in (
                    "minCreationTime",
                    "maxCreationTime",
                    "startTime",
                    "endTime",
                ):
                    if key in q:
                        newv = to_amc_iso(q[key])
                        if newv != q[key]:
                            q[key] = newv
                            changed = True
                if changed:
                    new_query = urlencode(q, doseq=True)
                    new_url = urlunparse(
                        (
                            url_obj.scheme,
                            url_obj.netloc,
                            url_obj.path,
                            url_obj.params,
                            new_query,
                            url_obj.fragment,
                        )
                    )
                    request.url = httpx.URL(new_url)
        except Exception:
            pass

        # 3) AUTH-AWARE REGIONAL ENDPOINT FIX AND CORRECT AUTH HEADERS (only for Amazon Ads API calls)
        # Get the current URL (may have been modified by previous steps)
        current_url = str(request.url)
        u_host = urlparse(current_url).netloc.lower()
        is_ads_api = (
            ("advertising-api" in u_host and "amazon.com" in u_host)
            or path.startswith("/v2/")
            or path.startswith("/reporting/")
            or ("/amc/" in path)
        )
        if is_ads_api:
            # Auth-aware URL rewriting
            if self.auth_manager:
                # Check if provider requires identity-based region routing
                requires_identity_routing = (
                    hasattr(
                        self.auth_manager.provider,
                        "requires_identity_region_routing",
                    )
                    and self.auth_manager.provider.requires_identity_region_routing()
                )

                if requires_identity_routing:
                    # Provider requires routing to match identity's region (EVERY request)
                    identity = self.auth_manager.get_active_identity()
                    if identity:
                        identity_region = identity.attributes.get(
                            "region", "na"
                        ).lower()

                        # Map region to correct endpoint
                        correct_host = RegionConfig.get_api_host(identity_region)

                        # ALWAYS update URL to match identity's region for this provider
                        parsed = urlparse(current_url)
                        if parsed.netloc != correct_host:
                            new_url = urlunparse(
                                (
                                    parsed.scheme,
                                    correct_host,
                                    parsed.path,
                                    parsed.params,
                                    parsed.query,
                                    parsed.fragment,
                                )
                            )
                            request.url = httpx.URL(new_url)
                            # Also update Host header to match
                            request.headers["host"] = correct_host
                            logger.debug(
                                f"{self.auth_manager.provider.provider_type}: Routing request to {identity_region.upper()} endpoint: {correct_host} (identity: {identity.id})"
                            )
                    else:
                        logger.warning(
                            f"{self.auth_manager.provider.provider_type}: No active identity set, cannot determine correct region"
                        )

                else:
                    # DIRECT AUTH: Do NOT rewrite host unless explicit override is set
                    region_override = _REGION_OVERRIDE_VAR.get()
                    if region_override and region_override in {
                        "na",
                        "eu",
                        "fe",
                    }:
                        override_host = RegionConfig.get_api_host(region_override)
                        parsed = urlparse(current_url)
                        if parsed.netloc != override_host:
                            new_url = urlunparse(
                                (
                                    parsed.scheme,
                                    override_host,
                                    parsed.path,
                                    parsed.params,
                                    parsed.query,
                                    parsed.fragment,
                                )
                            )
                            request.url = httpx.URL(new_url)
                            request.headers["host"] = override_host
                            logger.debug(
                                f"Direct auth: Applied region override to {region_override.upper()}: {override_host}"
                            )
                    # Otherwise, trust the base URL set during initialization for Direct auth

            # Get fresh auth headers for EVERY request (critical for OpenBridge)
            auth_headers: Dict[str, str] = {}
            if self.auth_manager is not None:
                logger.info(f"Getting auth headers for request to {path}")
                try:
                    headers = await self.auth_manager.get_headers()
                    logger.info(f"Got auth headers: {list(headers.keys())}")
                    auth_headers.update(headers)
                except Exception as e:
                    # Do not send unauthenticated requests to Amazon Ads API
                    raise httpx.RequestError(
                        f"Authentication required: {e}. Set an active identity or configure authentication.",
                        request=request,
                    )
            else:
                raise httpx.RequestError(
                    "Authentication manager unavailable; cannot build auth headers.",
                    request=request,
                )

            # Map to spec-preferred names
            auth_headers = self._map_auth_headers_to_spec(auth_headers)

            # Handle missing client ID (should not happen with properly configured OpenBridge)
            client_id = auth_headers.get("Amazon-Advertising-API-ClientId")
            if not client_id:
                # Try to get from environment as last resort
                env_client_id = self._get_env_client_id(current_value="")
                if env_client_id:
                    logger.warning(
                        "No client ID in auth headers, using environment variable"
                    )
                    auth_headers["Amazon-Advertising-API-ClientId"] = env_client_id

            # Validate mandatory headers
            if not (
                auth_headers.get("Authorization")
                or request.headers.get("Authorization")
            ):
                raise httpx.RequestError(
                    "Missing Authorization header for Amazon Ads API request.",
                    request=request,
                )
            if not (
                auth_headers.get("Amazon-Advertising-API-ClientId")
                or request.headers.get("Amazon-Advertising-API-ClientId")
            ):
                raise httpx.RequestError(
                    "Missing ClientId header. Set AMAZON_AD_API_CLIENT_ID (preferred) or AMAZON_ADS_CLIENT_ID, or ensure provider supplies ClientId.",
                    request=request,
                )

            # Profiles endpoint: do not inject scope on root listing
            if path.startswith("/v2/profiles") and path.strip("/") == "v2/profiles":
                for k in [
                    "Amazon-Advertising-API-Scope",
                    "Amazon-Ads-AccountId",
                ]:
                    auth_headers.pop(k, None)

            # Merge auth headers last
            logger.info("Adding auth headers to request:")
            for k, v in auth_headers.items():
                if v:
                    request.headers[k] = v
                    if "authorization" in k.lower():
                        # Log Bearer prefix and token length for debugging
                        if v.startswith("Bearer "):
                            token_len = len(v) - 7  # Subtract "Bearer " length
                            logger.info(f"  {k}: Bearer [token: {token_len} chars]")
                        else:
                            logger.warning(f"  {k}: MISSING 'Bearer ' prefix! Value starts with: {v[:10]}...")
                    else:
                        logger.info(f"  {k}: {v}")

            # Log final headers (for debugging)
            logger.debug("Final request headers:")
            for k, v in request.headers.items():
                if "authorization" in k.lower() or "token" in k.lower():
                    logger.debug(f"  {k}: [REDACTED]")
                else:
                    logger.debug(f"  {k}: {v}")

        # Ensure Accept header for JSON responses
        if "Accept" not in request.headers:
            request.headers["Accept"] = "application/json"


# Export global state accessors for routing tools
def get_region_override() -> Optional[str]:
    """Get the current region override.

    Returns the currently set region override from context-local storage.
    The override affects endpoint routing for Amazon Ads API requests.

    :return: Current region override ("na", "eu", "fe") or None
    :rtype: Optional[str]

    .. example::
       >>> region = get_region_override()
       >>> if region:
       ...     print(f"Current region override: {region}")
    """
    return _REGION_OVERRIDE_VAR.get()


def set_region_override(region: Optional[str]) -> None:
    """Set the region override.

    Sets a region override that affects endpoint routing for Amazon Ads API
    requests. Valid values are "na", "eu", "fe", or None to clear.

    :param region: Region code ("na", "eu", "fe") or None to clear
    :type region: Optional[str]

    .. example::
       >>> set_region_override("eu")  # Route to EU endpoints
       >>> set_region_override(None)  # Clear override
    """
    _REGION_OVERRIDE_VAR.set(region)


# Marketplace override functions removed - deprecated functionality
# Use set_active_region() from tools/region.py instead


def get_routing_state() -> Dict[str, Any]:
    """Get the current routing state.

    Returns the complete routing state including region, source, host,
    and marketplace information from the last request processed.

    :return: Dictionary containing routing state information
    :rtype: Dict[str, Any]

    .. example::
       >>> state = get_routing_state()
       >>> print(f"Region: {state.get('region')}")
       >>> print(f"Host: {state.get('host')}")
    """
    return _ROUTING_STATE_VAR.get()
