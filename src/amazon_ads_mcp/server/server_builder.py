"""Server builder module for creating configured MCP servers.

This module handles the complex server initialization process,
including middleware setup, client configuration, and resource mounting.
"""

import logging
import os
from pathlib import Path
from typing import Dict, Optional

from fastmcp import FastMCP

from ..auth.manager import get_auth_manager
from ..config.settings import settings
from ..middleware.authentication import (
    create_auth_middleware,
    create_openbridge_config,
)

try:
    from ..middleware.oauth import create_oauth_middleware
except ImportError:
    create_oauth_middleware = None
from ..utils.header_resolver import HeaderNameResolver
from ..utils.http_client import AuthenticatedClient
from ..utils.media import MediaTypeRegistry
from ..utils.region_config import RegionConfig
from .openapi_utils import slim_openapi_for_tools
from .sidecar_loader import _json_load as json_load

logger = logging.getLogger(__name__)


class ServerBuilder:
    """Builder class for creating configured MCP servers.

    This class encapsulates the complex server setup process,
    making it easier to test and maintain.
    """

    def __init__(self):
        """Initialize the server builder."""
        # Parser flag will be set at runtime in main(), not at import time
        self.server: Optional[FastMCP] = None
        self.auth_manager = get_auth_manager()
        self.media_registry = MediaTypeRegistry()
        self.header_resolver = HeaderNameResolver()
        self.mounted_servers: Dict[str, FastMCP] = {}

    async def build(self) -> FastMCP:
        """Build and configure the MCP server.

        :return: Configured FastMCP server instance
        :rtype: FastMCP
        """
        # Ensure default identity is loaded if configured
        await self._setup_default_identity()

        # Create the main server
        self.server = await self._create_main_server()

        # Setup middleware
        await self._setup_middleware()

        # Setup HTTP client
        self.client = await self._setup_http_client()

        # Mount resource servers
        await self._mount_resource_servers()

        # Setup built-in tools
        await self._setup_builtin_tools()

        # Setup built-in prompts
        await self._setup_builtin_prompts()

        # Setup OAuth callback route for HTTP transport
        await self._setup_oauth_callback()

        return self.server

    async def _setup_default_identity(self):
        """Setup default identity if configured."""
        if hasattr(self.auth_manager, "_default_identity_id"):
            await self.auth_manager.set_active_identity(
                self.auth_manager._default_identity_id
            )

    async def _create_main_server(self) -> FastMCP:
        """Create the main FastMCP server instance.

        :return: Main server instance
        :rtype: FastMCP
        """
        # Create server with appropriate configuration
        server = FastMCP("Amazon Ads MCP Server", version="1.0.0")

        # Setup server-side sampling handler if enabled
        if settings.enable_sampling:
            try:
                from .sampling_handler import create_sampling_handler

                # Create the sampling handler
                sampling_handler = create_sampling_handler()

                if sampling_handler:
                    # Use the sampling wrapper instead of private attribute
                    from ..utils.sampling_wrapper import (
                        configure_sampling_handler,
                    )

                    configure_sampling_handler(sampling_handler)
                    logger.info("Server-side sampling handler configured via wrapper")
                else:
                    logger.info(
                        "Server-side sampling not configured (missing config or disabled)"
                    )

            except Exception as e:
                logger.error(f"Failed to setup sampling handler: {e}")
        else:
            logger.info("Sampling is disabled in settings")

        return server

    async def _setup_middleware(self):
        """Setup server middleware."""
        middleware_list = []

        # Add sampling middleware if configured
        from ..utils.sampling_wrapper import get_sampling_wrapper

        wrapper = get_sampling_wrapper()
        if wrapper.has_handler():
            from ..middleware.sampling import create_sampling_middleware

            sampling_middleware = create_sampling_middleware()
            if sampling_middleware:
                middleware_list.append(sampling_middleware)
            logger.info("Added server-side sampling middleware")

        # Add OpenBridge middleware if using OpenBridge auth
        provider_type = getattr(self.auth_manager.provider, "provider_type", None)
        if provider_type == "openbridge":
            ob_config = create_openbridge_config()
            auth_middlewares = create_auth_middleware(
                ob_config, auth_manager=self.auth_manager
            )
            # create_auth_middleware returns a list, so extend instead of append
            middleware_list.extend(auth_middlewares)
            logger.info(
                f"Added {len(auth_middlewares)} OpenBridge authentication middleware components"
            )

        # Add OAuth middleware if credentials are available
        if create_oauth_middleware and all(
            [
                settings.oauth_client_id,
                settings.oauth_client_secret,
                settings.oauth_redirect_uri,
            ]
        ):
            oauth_middleware = create_oauth_middleware()
            middleware_list.append(oauth_middleware)
            logger.info("Added OAuth middleware for web authentication")

        # Apply middleware to server
        for middleware in middleware_list:
            self.server.middleware.append(middleware)

    async def _setup_http_client(self) -> AuthenticatedClient:
        """Setup the authenticated HTTP client.

        :return: Configured HTTP client
        :rtype: AuthenticatedClient
        """
        # Auth-aware base URL selection

        # Determine base URL based on auth provider type
        if self.auth_manager and hasattr(self.auth_manager.provider, "provider_type"):
            provider_type = self.auth_manager.provider.provider_type

            if provider_type == "openbridge":
                # For OpenBridge: Default to NA at startup
                # The real region will be determined from the identity at request time
                region = "na"
                logger.info(
                    "OpenBridge: Using default NA base URL at startup (per-request routing will override based on identity)"
                )
            else:
                # For Direct auth: use configured region from settings
                region = settings.amazon_ads_region
                logger.info(
                    f"Direct auth: Using configured region '{region}' from settings"
                )
        else:
            # Fallback to settings region if no auth manager
            region = settings.amazon_ads_region
            logger.warning(
                f"No auth manager available, using region '{region}' from settings"
            )

        base_url = RegionConfig.get_api_endpoint(region)

        import httpx

        return AuthenticatedClient(
            auth_manager=self.auth_manager,
            media_registry=self.media_registry,
            header_resolver=self.header_resolver,
            base_url=base_url,
            timeout=httpx.Timeout(
                # Allow longer timeouts for Amazon Ads API
                connect=10.0,  # Connection timeout
                read=60.0,  # Read timeout for response
                write=10.0,  # Write timeout for request
                pool=10.0,  # Pool timeout
            ),
        )

    async def _mount_resource_servers(self):
        """Mount resource servers for API isolation."""

        # Always prefer dist/ directory if it exists (minified specs)
        dist_resources = Path("dist/openapi/resources")
        source_resources = Path("openapi/resources")
        packaged_resources = Path(__file__).resolve().parent.parent / "resources"

        if dist_resources.exists():
            resources_dir = dist_resources
            logger.info(f"Using optimized resources from {resources_dir}")
        elif source_resources.exists():
            resources_dir = source_resources
            logger.info(f"Using source resources from {resources_dir}")
        elif packaged_resources.exists():
            resources_dir = packaged_resources
            logger.info(f"Using packaged resources from {resources_dir}")
        else:
            logger.warning("No resources directory found")
            return

        # Load namespace mapping and package allowlist (if any)
        namespace_mapping = await self._load_namespace_mapping(resources_dir)
        package_allowlist = await self._load_package_allowlist(resources_dir)

        # Process each resource file
        skip_files = {"packages.json", "manifest.json"}
        for spec_path in sorted(resources_dir.glob("*.json")):
            # Skip metadata files and sidecars
            if spec_path.name in skip_files:
                logger.debug(f"Skipping metadata file: {spec_path.name}")
                continue

            # Skip sidecar files (check suffix, not substring)
            if spec_path.stem.endswith((".media", ".manifest", ".transform")):
                logger.debug(f"Skipping sidecar file: {spec_path.name}")
                continue

            # Skip if not in package allowlist (when set)
            ns = spec_path.stem
            if package_allowlist:
                if ns not in package_allowlist:
                    logger.debug(
                        "Skipping %s - not in AMAZON_AD_API_PACKAGES allowlist",
                        ns,
                    )
                    continue

            await self._mount_single_resource(spec_path, namespace_mapping)

    async def _load_namespace_mapping(self, resources_dir: Path) -> Dict[str, str]:
        """Load namespace to prefix mapping from packages.json.

        :return: Namespace to prefix mapping
        :rtype: Dict[str, str]
        """
        # Try multiple locations for packages.json: alongside resources or project root
        candidates = [
            resources_dir.parent / "packages.json",
            resources_dir / "packages.json",
            Path("openapi/packages.json"),
        ]
        packages_path = next((p for p in candidates if p.exists()), None)
        if not packages_path:
            return {}

        try:
            data = json_load(packages_path)
            mapping: Dict[str, str] = {}

            # Preferred: explicit prefixes map
            prefixes = data.get("prefixes") if isinstance(data, dict) else None
            if isinstance(prefixes, dict):
                for ns, pref in prefixes.items():
                    if isinstance(ns, str) and isinstance(pref, str):
                        mapping[ns] = pref

            # Back-compat: some generators might emit a flat map with {ns: {prefix: "..."}}
            if not mapping:
                for ns, info in data.items() if isinstance(data, dict) else []:
                    if (
                        isinstance(info, dict)
                        and "prefix" in info
                        and isinstance(info["prefix"], str)
                    ):
                        mapping[ns] = info["prefix"]

            return mapping
        except Exception as e:
            logger.error(f"Failed to load packages.json: {e}")
            return {}

    async def _load_package_allowlist(
        self, resources_dir: Path
    ) -> Dict[str, None] | set:
        """Load allowed packages from environment and resolve to resource namespaces.

        Supports aliases defined in packages.json. Returns a set of allowed
        resource namespaces (matching the .json stem names). Empty set means
        no restriction.
        """
        # Load packages.json to resolve aliases -> namespaces and read defaults
        candidates = [
            resources_dir.parent / "packages.json",
            resources_dir / "packages.json",
            Path("openapi/packages.json"),
        ]
        packages_path = next((p for p in candidates if p.exists()), None)

        alias_map: Dict[str, str] = {}
        default_tokens: list[str] = []
        if packages_path:
            try:
                data = json_load(packages_path)
                # `aliases` is a map: alias_slug -> NamespaceName
                aliases = data.get("aliases") if isinstance(data, dict) else None
                if isinstance(aliases, dict):
                    for alias, ns in aliases.items():
                        if isinstance(alias, str) and isinstance(ns, str):
                            alias_map[alias.lower()] = ns
                # Optional defaults list (aliases or namespace stems)
                defaults_val = data.get("defaults") if isinstance(data, dict) else None
                if isinstance(defaults_val, list):
                    default_tokens = [str(v).strip().lower() for v in defaults_val if str(v).strip()]
            except Exception as e:
                logger.debug("Failed to read aliases/defaults from %s: %s", packages_path, e)

        # Determine requested tokens from env or defaults
        raw = os.getenv("AMAZON_AD_API_PACKAGES") or os.getenv("AD_API_PACKAGES")
        requested: set[str]
        if raw:
            raw = raw.strip()
            # Strip surrounding quotes if present (Windows compatibility)
            if (raw.startswith('"') and raw.endswith('"')) or (raw.startswith("'") and raw.endswith("'")):
                logger.debug("Stripping quotes from AMAZON_AD_API_PACKAGES value")
                raw = raw[1:-1]
            requested = {part.strip().lower() for part in raw.split(",") if part.strip()}
            logger.debug("Parsed AMAZON_AD_API_PACKAGES: %s", requested)
        else:
            # Use packages.json defaults when available; otherwise fall back to a safe minimal set
            fallback_defaults = ["profiles", "accounts-ads-accounts"]
            requested = set(default_tokens or fallback_defaults)
            logger.info("Using default package allowlist: %s", ", ".join(sorted(requested)))

        if not requested:
            # If we somehow ended up empty, do not restrict
            return set()

        # Build allowlist: map requested tokens using alias_map when possible.
        allow: set[str] = set()
        for token in requested:
            # Exact alias -> namespace
            if token in alias_map:
                allow.add(alias_map[token])
                continue
            # Accept tokens that are already namespace (file stem) names
            # Attempt case-insensitive match against available specs
            for spec_path in resources_dir.glob("*.json"):
                stem = spec_path.stem
                if stem.endswith((".media", ".manifest", ".transform")):
                    continue
                if spec_path.name in {"packages.json", "manifest.json"}:
                    continue
                if stem.lower() == token:
                    allow.add(stem)

        if allow:
            logger.info(
                "Package allowlist active (%d): %s",
                len(allow),
                ", ".join(sorted(allow)),
            )
        else:
            logger.warning(
                "No packages resolved from requested tokens; loading nothing.")
        return allow

    async def _mount_single_resource(
        self, spec_path: Path, namespace_mapping: Dict[str, str]
    ):
        """Mount a single resource server.

        :param spec_path: Path to the OpenAPI spec
        :type spec_path: Path
        :param namespace_mapping: Namespace to prefix mapping
        :type namespace_mapping: Dict[str, str]
        """
        try:
            # Load the spec
            spec = json_load(spec_path)

            # Validate it's an OpenAPI spec
            if not isinstance(spec, dict) or "openapi" not in spec:
                logger.warning(f"Skipping {spec_path.name} - not an OpenAPI spec")
                return

            # Determine namespace and prefix first (before using it)
            namespace = spec_path.stem

            # Populate registries from spec (media types and headers)
            self.media_registry.add_from_spec(spec)
            self.header_resolver.add_from_spec(spec)

            # Load and apply media type sidecar if it exists
            media_path = spec_path.with_suffix(".media.json")
            if media_path.exists():
                try:
                    media_spec = json_load(media_path)
                    self.media_registry.add_from_spec(media_spec)
                    logger.debug(f"Loaded media types from {media_path.name}")
                except Exception as e:
                    logger.warning(
                        f"Failed to load media sidecar {media_path.name}: {e}"
                    )

            # Slim the spec
            slim_openapi_for_tools(spec)

            # Auth-aware server URL configuration
            if self.auth_manager and hasattr(
                self.auth_manager.provider, "provider_type"
            ):
                provider_type = self.auth_manager.provider.provider_type

                if provider_type == "openbridge":
                    # For OpenBridge: Don't hardcode a regional server
                    # Runtime routing will override based on identity
                    spec["servers"] = [
                        {
                            "url": RegionConfig.get_api_endpoint("na"),
                            "description": "Runtime routing will override based on identity",
                        }
                    ]
                    logger.debug(
                        f"OpenBridge: Spec {namespace} servers will be overridden at runtime"
                    )
                else:
                    # For Direct auth: use configured region
                    region = settings.amazon_ads_region
                    # Use centralized region config
                    base_url = RegionConfig.get_api_endpoint(region)
                    spec["servers"] = [{"url": base_url}]
                    logger.debug(f"Direct auth: Spec {namespace} using {region} server")
            else:
                # Fallback to settings region
                region = settings.amazon_ads_region
                # Use centralized region config
                base_url = RegionConfig.get_api_endpoint(region)
                spec["servers"] = [{"url": base_url}]

            # Get prefix from mapping
            prefix = namespace_mapping.get(namespace, namespace)

            # Create sub-server from OpenAPI spec
            sub_server = FastMCP.from_openapi(
                openapi_spec=spec, client=self.client, name=prefix
            )

            # Mount the sub-server with prefix
            self.server.mount(server=sub_server, prefix=prefix)
            self.mounted_servers[namespace] = sub_server

            # Apply sidecars (transforms) to the mounted sub-server
            from .sidecar_loader import apply_sidecars

            await apply_sidecars(sub_server, spec_path)

            logger.info(f"Mounted {namespace} with prefix '{prefix}'")

        except Exception as e:
            logger.error(f"Failed to mount {spec_path}: {e}")

    async def _setup_builtin_tools(self):
        """Setup built-in tools for the server."""
        from ..server.builtin_tools import register_all_builtin_tools

        await register_all_builtin_tools(self.server)

    async def _setup_builtin_prompts(self):
        """Setup built-in prompts for the server."""
        from ..server.builtin_prompts import register_all_builtin_prompts

        await register_all_builtin_prompts(self.server)

    async def _setup_oauth_callback(self):
        """Setup OAuth callback route for HTTP transport."""
        # Only register OAuth callback route for HTTP transport
        # Check if server has custom_route method (HTTP transport)
        if hasattr(self.server, "custom_route"):
            import httpx
            from starlette.requests import Request
            from starlette.responses import HTMLResponse

            @self.server.custom_route("/auth/callback", methods=["GET"])
            async def oauth_callback(request: Request):
                """Handle OAuth callback from Amazon with secure state validation."""
                import os

                from ..auth.oauth_state_store import get_oauth_state_store

                code = request.query_params.get("code")
                state = request.query_params.get("state")
                scope = request.query_params.get("scope")
                error = request.query_params.get("error")
                error_description = request.query_params.get("error_description")

                # Handle OAuth errors from Amazon
                if error:
                    logger.error(f"OAuth error: {error} - {error_description}")
                    # Don't expose internal error details in HTML
                    from .html_templates import get_error_html

                    html = get_error_html(
                        title="Authorization Failed",
                        message="The authorization request could not be completed.",
                    )
                    return HTMLResponse(html, status_code=400)

                # Validate required parameters
                if not code or not state:
                    logger.error("Missing code or state in OAuth callback")
                    from .html_templates import get_missing_params_html

                    html = get_missing_params_html()
                    return HTMLResponse(html, status_code=400)

                # Extract user agent and IP for validation
                user_agent = request.headers.get("user-agent")
                ip_address = request.client.host if request.client else None

                logger.info(
                    f"OAuth callback received: code=[REDACTED], state=[REDACTED], scope={scope}"
                )

                try:
                    # Validate state with secure store
                    state_store = get_oauth_state_store()
                    is_valid, error_message = state_store.validate_state(
                        state=state,
                        user_agent=user_agent,
                        ip_address=ip_address,
                    )

                    if not is_valid:
                        logger.warning(f"Invalid OAuth state: {error_message}")
                        from .html_templates import get_validation_error_html

                        html = get_validation_error_html()
                        return HTMLResponse(html, status_code=403)

                    # State is valid, proceed with token exchange
                    token_url = RegionConfig.get_oauth_endpoint(
                        settings.amazon_ads_region
                    )

                    # Use explicit timeout for OAuth token exchange
                    timeout = httpx.Timeout(
                        connect=10.0, read=30.0, write=10.0, pool=10.0
                    )
                    async with httpx.AsyncClient(timeout=timeout) as client:
                        response = await client.post(
                            token_url,
                            data={
                                "grant_type": "authorization_code",
                                "code": code,
                                # Use PORT env var or request port or default
                                "redirect_uri": f"http://localhost:{os.getenv('PORT') or request.url.port or 9080}/auth/callback",
                                "client_id": settings.ad_api_client_id,
                                "client_secret": settings.ad_api_client_secret,
                            },
                        )

                    if response.status_code == 200:
                        tokens = response.json()

                        # Store tokens securely
                        try:
                            from datetime import datetime, timedelta, timezone

                            from ..auth.secure_token_store import (
                                get_secure_token_store,
                            )

                            secure_store = get_secure_token_store()

                            if "refresh_token" in tokens:
                                secure_store.store_token(
                                    token_id="oauth_refresh_token",
                                    token_value=tokens["refresh_token"],
                                    token_type="refresh",
                                    expires_at=datetime.now(timezone.utc)
                                    + timedelta(days=365),
                                    metadata={"scope": tokens.get("scope")},
                                )

                            if "access_token" in tokens:
                                secure_store.store_token(
                                    token_id="oauth_access_token",
                                    token_value=tokens["access_token"],
                                    token_type="access",
                                    expires_at=datetime.now(timezone.utc)
                                    + timedelta(seconds=tokens.get("expires_in", 3600)),
                                    metadata={
                                        "token_type": tokens.get("token_type", "Bearer")
                                    },
                                )

                            logger.info("Stored tokens in secure token store")
                        except Exception as e:
                            logger.error(f"Failed to store tokens securely: {e}")
                            # Don't expose internal error details
                            from .html_templates import (
                                get_token_storage_error_html,
                            )

                            html = get_token_storage_error_html()
                            return HTMLResponse(html, status_code=500)

                        # Store in auth manager if available
                        if self.auth_manager:
                            from datetime import datetime, timedelta, timezone

                            from ..auth.token_store import TokenKind

                            # Store refresh token
                            if "refresh_token" in tokens:
                                await self.auth_manager.set_token(
                                    provider_type="direct",
                                    identity_id="direct-auth",
                                    token_kind=TokenKind.REFRESH,
                                    token=tokens["refresh_token"],
                                    expires_at=datetime.now(timezone.utc)
                                    + timedelta(days=365),
                                    metadata={},
                                )

                            # Store access token
                            expires_at = datetime.now(timezone.utc) + timedelta(
                                seconds=tokens.get("expires_in", 3600)
                            )
                            await self.auth_manager.set_token(
                                provider_type="direct",
                                identity_id="direct-auth",
                                token_kind=TokenKind.ACCESS,
                                token=tokens["access_token"],
                                expires_at=expires_at,
                                metadata={"token_type": "Bearer"},
                            )

                            logger.info("Stored OAuth tokens in auth manager")

                        # Success response
                        from .html_templates import get_success_html

                        html = get_success_html()
                        return HTMLResponse(html)
                    else:
                        # Error response
                        error_msg = response.text
                        logger.error(
                            f"Token exchange failed: {response.status_code} - {error_msg}"
                        )

                        from .html_templates import (
                            get_token_exchange_error_html,
                        )

                        html = get_token_exchange_error_html()
                        return HTMLResponse(html, status_code=400)

                except Exception as e:
                    logger.error(f"OAuth callback error: {e}")
                    # Don't expose internal exception details
                    from .html_templates import get_server_error_html

                    html = get_server_error_html()
                    return HTMLResponse(html, status_code=500)

            logger.info("Registered OAuth callback route at /auth/callback")
