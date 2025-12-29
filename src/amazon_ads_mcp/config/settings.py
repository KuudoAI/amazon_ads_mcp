"""Configuration settings for Amazon Ads API MCP server.

This module defines the configuration settings for the Amazon Ads MCP server,
including authentication methods, API endpoints, and server configuration.
Settings are loaded from environment variables and .env files.
"""

from typing import Literal, Optional

from pydantic import AliasChoices, Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from ..utils.region_config import RegionConfig


class Settings(BaseSettings):
    """Application settings loaded from environment variables.

    Manages all configuration settings for the Amazon Ads MCP server.
    Supports both direct Amazon Ads API authentication and OpenBridge
    integration. Settings can be configured via environment variables
    or .env files.

    :param auth_method: Authentication method to use (direct/openbridge)
    :type auth_method: Literal["direct", "openbridge"]
    :param amazon_ads_client_id: Amazon Ads API Client ID for direct auth
    :type amazon_ads_client_id: Optional[str]
    :param amazon_ads_client_secret: Amazon Ads API Client Secret for direct auth
    :type amazon_ads_client_secret: Optional[str]
    :param amazon_ads_refresh_token: Amazon Ads API Refresh Token for direct auth
    :type amazon_ads_refresh_token: Optional[str]
    :param openbridge_refresh_token: OpenBridge API key (aka refresh token)
    :type openbridge_refresh_token: Optional[str]
    :param openbridge_remote_identity_id: OpenBridge remote identity ID
    :type openbridge_remote_identity_id: Optional[str]
    :param amazon_ads_region: Amazon Ads API region (na/eu/fe)
    :type amazon_ads_region: Literal["na", "eu", "fe"]
    :param amazon_ads_api_base_url: Base URL for Amazon Ads API
    :type amazon_ads_api_base_url: str
    :param amazon_ads_sandbox_mode: Enable sandbox mode for testing
    :type amazon_ads_sandbox_mode: bool
    :param mcp_server_name: Name of the MCP server
    :type mcp_server_name: str
    :param mcp_server_host: Host for the MCP server
    :type mcp_server_host: str
    :param mcp_server_port: Port for the MCP server
    :type mcp_server_port: int
    :param log_level: Logging level for the application
    :type log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",  # Ignore extra fields in .env file
    )

    # Authentication method
    auth_method: Literal["direct", "openbridge"] = Field(
        "openbridge", description="Authentication method to use"
    )

    # Direct Amazon Ads API Configuration (BYOA - Bring Your Own API)
    # These match the standard Amazon Ads API environment variables
    ad_api_client_id: Optional[str] = Field(
        None,
        alias="AMAZON_AD_API_CLIENT_ID",
        description="Amazon Ads API Client ID (for direct auth)",
    )
    ad_api_client_secret: Optional[str] = Field(
        None,
        alias="AMAZON_AD_API_CLIENT_SECRET",
        description="Amazon Ads API Client Secret (for direct auth)",
    )
    ad_api_refresh_token: Optional[str] = Field(
        None,
        alias="AMAZON_AD_API_REFRESH_TOKEN",
        description="Amazon Ads API Refresh Token (for direct auth)",
    )
    ad_api_profile_id: Optional[str] = Field(
        None,
        alias="AMAZON_AD_API_PROFILE_ID",
        description="Amazon Ads Profile ID (for direct auth)",
    )

    # Legacy field names for backward compatibility
    amazon_ads_client_id: Optional[str] = Field(
        None,
        description="Amazon Ads API Client ID (deprecated, use AMAZON_AD_API_CLIENT_ID)",
    )
    amazon_ads_client_secret: Optional[str] = Field(
        None,
        description="Amazon Ads API Client Secret (deprecated, use AMAZON_AD_API_CLIENT_SECRET)",
    )
    amazon_ads_refresh_token: Optional[str] = Field(
        None,
        description="Amazon Ads API Refresh Token (deprecated, use AMAZON_AD_API_REFRESH_TOKEN)",
    )

    # Openbridge Configuration
    openbridge_refresh_token: Optional[str] = Field(
        None,
        validation_alias=AliasChoices("OPENBRIDGE_REFRESH_TOKEN", "OPENBRIDGE_API_KEY"),
        description="OpenBridge API key (aka refresh token)",
    )
    openbridge_remote_identity_id: Optional[str] = Field(
        None, description="Openbridge Remote Identity ID for Amazon Ads"
    )
    amazon_ads_region: Literal["na", "eu", "fe"] = Field(
        "na", description="Amazon Ads API Region"
    )

    # API Configuration
    amazon_ads_api_base_url: str = Field(
        "https://advertising-api.amazon.com",
        description="Amazon Ads API Base URL",
    )
    amazon_ads_sandbox_mode: bool = Field(
        False, description="Enable sandbox mode for testing"
    )

    # MCP Server Configuration
    mcp_server_name: str = Field("amazon-ads-api", description="MCP Server Name")
    mcp_server_host: str = Field("localhost", description="MCP Server Host")
    mcp_server_port: int = Field(8000, description="MCP Server Port")

    # Runtime configuration (set by CLI or Docker)
    port: Optional[int] = Field(
        None, description="HTTP server port (from PORT env var or CLI)"
    )

    # Logging
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = Field(
        "INFO", description="Logging level"
    )

    # FastMCP Configuration
    fastmcp_use_experimental_parser: bool = Field(
        True,
        description="Enable FastMCP experimental OpenAPI parser for better performance",
    )

    # OAuth Configuration (optional, for web-based authentication flows)
    oauth_client_id: Optional[str] = Field(
        None,
        alias="OAUTH_CLIENT_ID",
        description="OAuth Client ID for web authentication flow",
    )
    oauth_client_secret: Optional[str] = Field(
        None,
        alias="OAUTH_CLIENT_SECRET",
        description="OAuth Client Secret for web authentication flow",
    )
    oauth_redirect_uri: Optional[str] = Field(
        None,
        alias="OAUTH_REDIRECT_URI",
        description="OAuth Redirect URI for web authentication flow",
    )

    # Sampling Configuration (optional, for testing)
    enable_sampling: bool = Field(
        False,
        alias="SAMPLING_ENABLED",
        description="Enable request/response sampling for testing",
    )
    sampling_config_path: Optional[str] = Field(
        None,
        alias="SAMPLING_CONFIG_PATH",
        description="Path to sampling configuration file",
    )
    default_sampling_rate: float = Field(
        0.1,
        alias="DEFAULT_SAMPLING_RATE",
        description="Default sampling rate (0.0-1.0)",
    )

    @field_validator("auth_method")
    @classmethod
    def auto_detect_auth_method(cls, v: str, info) -> str:
        """Auto-detect authentication method based on available credentials.

        If direct Amazon Ads API credentials are provided, automatically
        switch to 'direct' auth method. Prioritizes direct credentials
        over OpenBridge when both are available.

        :param v: The original auth method value
        :type v: str
        :param info: Validation info containing other field values
        :type info: Any
        :return: Detected or original authentication method
        :rtype: str
        """
        # Get the credential values
        client_id = info.data.get("ad_api_client_id") or info.data.get(
            "amazon_ads_client_id"
        )
        client_secret = info.data.get("ad_api_client_secret") or info.data.get(
            "amazon_ads_client_secret"
        )
        refresh_token = info.data.get("ad_api_refresh_token") or info.data.get(
            "amazon_ads_refresh_token"
        )

        # Check for direct API credentials (all three must be present and non-empty)
        has_direct_creds = all(
            [
                client_id and client_id.strip(),
                client_secret and client_secret.strip(),
                refresh_token and refresh_token.strip(),
            ]
        )

        if has_direct_creds:
            return "direct"

        # Check for OpenBridge credentials
        has_openbridge = info.data.get("openbridge_refresh_token")
        if has_openbridge and has_openbridge.strip():
            return "openbridge"

        # Check for partial direct credentials to provide helpful error
        has_partial_direct = any([client_id, client_secret, refresh_token])
        if has_partial_direct and not has_openbridge:
            missing = []
            if not client_id or not client_id.strip():
                missing.append("AMAZON_AD_API_CLIENT_ID")
            if not client_secret or not client_secret.strip():
                missing.append("AMAZON_AD_API_CLIENT_SECRET")
            if not refresh_token or not refresh_token.strip():
                missing.append("AMAZON_AD_API_REFRESH_TOKEN")

            if missing:
                # Return the original value, the provider setup will give detailed error
                return v

        return v  # Return the original value if no credentials detected

    @field_validator("amazon_ads_api_base_url")
    @classmethod
    def validate_api_base_url(cls, v: str, info) -> str:
        """Adjust API URL based on sandbox mode.

        Automatically modifies the API base URL to use the test endpoint
        when sandbox mode is enabled.

        :param v: The original API base URL
        :type v: str
        :param info: Validation info containing other field values
        :type info: Any
        :return: Modified API base URL for sandbox mode if enabled
        :rtype: str
        """
        if info.data.get("amazon_ads_sandbox_mode"):
            return v.replace("advertising-api", "advertising-api-test")
        return v

    @property
    def effective_client_id(self) -> Optional[str]:
        """Get the effective client ID (new or legacy).

        Returns the client ID from either the new AMAZON_AD_API_CLIENT_ID
        environment variable or the legacy amazon_ads_client_id.

        :return: Effective client ID or None
        :rtype: Optional[str]
        """
        return self.ad_api_client_id or self.amazon_ads_client_id

    @property
    def effective_client_secret(self) -> Optional[str]:
        """Get the effective client secret (new or legacy).

        Returns the client secret from either the new AMAZON_AD_API_CLIENT_SECRET
        environment variable or the legacy amazon_ads_client_secret.

        :return: Effective client secret or None
        :rtype: Optional[str]
        """
        return self.ad_api_client_secret or self.amazon_ads_client_secret

    @property
    def effective_refresh_token(self) -> Optional[str]:
        """Get the effective refresh token (new or legacy).

        Returns the refresh token from either the new AMAZON_AD_API_REFRESH_TOKEN
        environment variable or the legacy amazon_ads_refresh_token.

        NOTE: Using refresh tokens via environment variables is deprecated.
        Prefer OAuth flow or secure token storage for production use.

        :return: Effective refresh token or None
        :rtype: Optional[str]
        """
        token = self.ad_api_refresh_token or self.amazon_ads_refresh_token
        if token:
            import warnings

            warnings.warn(
                "Using refresh tokens via environment variables is deprecated and insecure. "
                "Please use OAuth flow or secure token storage instead.",
                DeprecationWarning,
                stacklevel=2,
            )
        return token

    @property
    def effective_profile_id(self) -> Optional[str]:
        """Get the effective profile ID.

        Returns the profile ID from the AMAZON_AD_API_PROFILE_ID
        environment variable.

        :return: Profile ID or None
        :rtype: Optional[str]
        """
        return self.ad_api_profile_id

    @property
    def region_endpoint(self) -> str:
        """Get the region-specific endpoint.

        Returns the appropriate Amazon Ads API endpoint based on the
        configured region and sandbox mode setting.

        :return: Region-specific API endpoint URL
        :rtype: str
        """
        base = RegionConfig.get_api_endpoint(self.amazon_ads_region)
        if self.amazon_ads_sandbox_mode:
            base = base.replace("advertising-api", "advertising-api-test")
        return base


settings = Settings()
"""Global settings instance for the Amazon Ads MCP server.

This instance is created once and used throughout the application
to access configuration settings.
"""
