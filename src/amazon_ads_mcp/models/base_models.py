"""Shared Pydantic models for the Amazon Ads MCP project.

This module contains all the data models used throughout the Amazon Ads MCP
server, including authentication tokens, identity management, API responses,
and OpenBridge integration models.

The models provide type safety and validation for:
- Authentication and token management
- Identity and profile management
- API request/response handling
- OpenBridge integration
"""

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


# Auth Models
class Token(BaseModel):
    """Authentication token model for Amazon Ads API access.

    Represents an OAuth2 access token with expiration and metadata.
    Used for authenticating requests to the Amazon Advertising API.

    :param value: The actual token string value
    :type value: str
    :param expires_at: When the token expires
    :type expires_at: datetime
    :param token_type: Type of token (default: "Bearer")
    :type token_type: str
    :param scope: Optional scope string for the token
    :type scope: Optional[str]
    :param metadata: Additional token metadata
    :type metadata: Dict[str, Any]
    """

    value: str
    expires_at: datetime
    token_type: str = "Bearer"
    scope: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class Identity(BaseModel):
    """Simplified identity model - passthrough from Openbridge.

    Represents a remote identity from OpenBridge with all
    attributes and relationships preserved.

    :param id: Unique identifier for the identity
    :type id: str
    :param type: Type of identity (default: "RemoteIdentity")
    :type type: str
    :param attributes: All attributes from Openbridge
    :type attributes: Dict[str, Any]
    :param relationships: All relationships from Openbridge
    :type relationships: Optional[Dict[str, Any]]
    """

    id: str
    type: str = "RemoteIdentity"
    attributes: Dict[str, Any]
    relationships: Optional[Dict[str, Any]] = None


class AuthCredentials(BaseModel):
    """Credentials for API access.

    Contains all necessary authentication information for making
    authenticated requests to the Amazon Advertising API.

    :param identity_id: ID of the identity these credentials belong to
    :type identity_id: str
    :param access_token: OAuth2 access token for API authentication
    :type access_token: str
    :param token_type: Type of token (default: "Bearer")
    :type token_type: str
    :param expires_at: When the access token expires
    :type expires_at: datetime
    :param base_url: Base URL for API requests (default: Amazon API URL)
    :type base_url: str
    :param headers: Additional headers to include in requests
    :type headers: Dict[str, str]
    """

    identity_id: str
    access_token: str
    token_type: str = "Bearer"
    expires_at: datetime
    base_url: str = "https://advertising-api.amazon.com"
    headers: Dict[str, str] = Field(default_factory=dict)


# API Models
class AccountInfo(BaseModel):
    """Account information model.

    Represents account information returned by the Amazon Advertising API.
    Contains marketplace details and account status information.

    :param marketplace_string_id: Marketplace identifier string
    :type marketplace_string_id: str
    :param id: Account ID
    :type id: str
    :param type: Type of account
    :type type: str
    :param name: Account name
    :type name: str
    :param valid_payment_method: Whether account has valid payment method
    :type valid_payment_method: Optional[bool]
    """

    marketplace_string_id: str = Field(alias="marketplaceStringId")
    id: str
    type: str
    name: str
    valid_payment_method: Optional[bool] = Field(
        alias="validPaymentMethod", default=None
    )


class Profile(BaseModel):
    """Amazon Ads Profile model.

    Represents an Amazon Advertising profile with location, currency,
    and budget information. Profiles are used to organize campaigns
    and manage advertising accounts.

    :param profile_id: Unique profile identifier
    :type profile_id: int
    :param country_code: ISO country code for the profile
    :type country_code: str
    :param currency_code: ISO currency code for the profile
    :type currency_code: str
    :param timezone: Timezone for the profile
    :type timezone: str
    :param daily_budget: Optional daily budget limit
    :type daily_budget: Optional[float]
    :param account_info: Associated account information
    :type account_info: AccountInfo
    """

    profile_id: int = Field(alias="profileId")
    country_code: str = Field(alias="countryCode")
    currency_code: str = Field(alias="currencyCode")
    timezone: str
    daily_budget: Optional[float] = Field(alias="dailyBudget", default=None)
    account_info: AccountInfo = Field(alias="accountInfo")

    model_config = {"populate_by_name": True}


# Request/Response Models
class IdentityListResponse(BaseModel):
    """Response model for identity list.

    Represents a paginated response containing a list of available
    identities that can be used for Amazon Ads API access.

    :param identities: List of available identities
    :type identities: List[Identity]
    :param total: Total number of identities available
    :type total: int
    :param has_more: Whether there are more identities to fetch
    :type has_more: bool
    """

    identities: List[Identity]
    total: int
    has_more: bool = False


class SetActiveIdentityRequest(BaseModel):
    """Request model for setting active identity.

    Used when requesting to set a specific identity as the active
    identity for Amazon Ads API operations.

    Note on backward compatibility: prior versions accepted a
    ``persist: bool`` field. It was a no-op (auth state is persisted
    automatically by ``AuthSessionStateMiddleware`` when an MCP
    session is available) and has been removed. Pydantic ignores
    unknown fields by default, so existing callers passing
    ``persist=True`` continue to construct successfully — the value
    is silently dropped, matching the prior observable behavior.
    Inspect ``state_scope`` / ``state_reason`` on the response to
    learn whether state will survive to the next tool call.

    :param identity_id: ID of the identity to activate
    :type identity_id: str
    """

    identity_id: str


class SetActiveIdentityResponse(BaseModel):
    """Response model for setting active identity.

    Response indicating the result of setting an identity as active,
    including whether credentials were successfully loaded and whether
    the state will outlive the current request.

    :param success: Whether the operation was successful
    :type success: bool
    :param identity: The identity that was set as active
    :type identity: Identity
    :param credentials_loaded: Whether credentials were loaded for identity
    :type credentials_loaded: bool
    :param message: Optional message about the operation result
    :type message: Optional[str]
    :param session_present: Whether this call ran inside an MCP session
        that will retain auth state across subsequent tool calls. Pure
        transport fact; ``None`` when not computed (e.g. core function
        called outside a tool wrapper).
    :type session_present: Optional[bool]
    :param state_scope: Caller directive: ``"session"`` when the
        transport will keep state across the next tool call in this
        connection, ``"request"`` when the caller must re-establish
        context every call. ``None`` when not computed.
    :type state_scope: Optional[str]
    :param state_reason: Diagnostic explaining why state is not
        sticky, or why state was wiped despite a session being
        present. Known values: ``"no_mcp_session"``,
        ``"token_swapped"``, ``"bridge_unavailable"``. ``None`` on
        the happy path.
    :type state_reason: Optional[str]
    """

    success: bool
    identity: Identity
    credentials_loaded: bool = False
    message: Optional[str] = None
    session_present: Optional[bool] = None
    state_scope: Optional[str] = None
    state_reason: Optional[str] = None


# OpenBridge API Models
# OpenbridgeIdentity is now just an alias for Identity since we're passing through
OpenbridgeIdentity = Identity
