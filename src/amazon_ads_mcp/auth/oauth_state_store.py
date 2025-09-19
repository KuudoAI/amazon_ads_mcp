"""Secure OAuth state store for CSRF protection."""

import hashlib
import hmac
import json
import logging
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Dict, Optional

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


class OAuthStateEntry(BaseModel):
    """OAuth state entry with metadata."""

    state: str = Field(description="OAuth state parameter")
    nonce: str = Field(description="Random nonce for additional entropy")
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc) + timedelta(minutes=10)
    )
    auth_url: str = Field(description="Authorization URL")
    user_agent: Optional[str] = Field(
        default=None, description="User agent for validation"
    )
    ip_address: Optional[str] = Field(
        default=None, description="IP address for validation"
    )
    completed: bool = Field(default=False, description="Whether callback was received")


class OAuthStateStore:
    """
    Secure store for OAuth state validation.

    This store provides CSRF protection by:
    1. Generating cryptographically secure state tokens
    2. Storing state with expiration and metadata
    3. Validating state on callback with timing checks
    4. Using HMAC signatures for state integrity

    For production, this should be replaced with Redis or similar.
    """

    def __init__(
        self,
        secret_key: Optional[str] = None,
        store_path: Optional[Path] = None,
    ):
        """
        Initialize OAuth state store.

        Args:
            secret_key: Secret for HMAC signatures (auto-generated if not provided)
            store_path: Path for persistent storage (memory-only if not provided)
        """
        self.secret_key = secret_key or secrets.token_hex(32)
        self.store_path = store_path
        self._memory_store: Dict[str, OAuthStateEntry] = {}

        # Load existing states if using file storage
        if self.store_path:
            self._load_store()

    def generate_state(
        self,
        auth_url: str,
        user_agent: Optional[str] = None,
        ip_address: Optional[str] = None,
        ttl_minutes: int = 10,
    ) -> str:
        """
        Generate a secure OAuth state token.

        Args:
            auth_url: The authorization URL
            user_agent: Optional user agent for validation
            ip_address: Optional IP address for validation
            ttl_minutes: Time-to-live in minutes

        Returns:
            Secure state token
        """
        # Generate random components
        state_base = secrets.token_urlsafe(32)
        nonce = secrets.token_hex(16)

        # Create HMAC signature
        message = f"{state_base}:{nonce}:{auth_url}"
        signature = hmac.new(
            self.secret_key.encode(), message.encode(), hashlib.sha256
        ).hexdigest()[:16]  # Use first 16 chars for brevity

        # Combine into final state
        state = f"{state_base}.{signature}"

        # Store state entry
        entry = OAuthStateEntry(
            state=state,
            nonce=nonce,
            auth_url=auth_url,
            user_agent=user_agent,
            ip_address=ip_address,
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=ttl_minutes),
        )

        self._memory_store[state] = entry
        self._save_store()

        logger.debug(f"Generated OAuth state with length: {len(state)}")
        return state

    def validate_state(
        self,
        state: str,
        user_agent: Optional[str] = None,
        ip_address: Optional[str] = None,
    ) -> tuple[bool, Optional[str]]:
        """
        Validate an OAuth state token.

        Args:
            state: The state token to validate
            user_agent: Optional user agent to verify
            ip_address: Optional IP address to verify

        Returns:
            Tuple of (is_valid, error_message)
        """
        # Clean expired states first
        self._clean_expired()

        # Check if state exists
        if state not in self._memory_store:
            return False, "Invalid or expired state"

        entry = self._memory_store[state]

        # Check if already used
        if entry.completed:
            logger.warning("Attempted reuse of OAuth state")
            return False, "State already used"

        # Check expiration
        if datetime.now(timezone.utc) > entry.expires_at:
            return False, "State expired"

        # Validate HMAC signature
        try:
            state_base, signature = state.rsplit(".", 1)
            message = f"{state_base}:{entry.nonce}:{entry.auth_url}"
            expected_signature = hmac.new(
                self.secret_key.encode(), message.encode(), hashlib.sha256
            ).hexdigest()[:16]

            if not hmac.compare_digest(signature, expected_signature):
                logger.warning("Invalid OAuth state signature")
                return False, "Invalid state signature"
        except (ValueError, KeyError) as e:
            logger.warning(f"Malformed OAuth state: {e}")
            return False, "Malformed state"

        # Optional: Validate user agent
        if entry.user_agent and user_agent and entry.user_agent != user_agent:
            logger.warning("User agent mismatch in OAuth callback")
            # Don't fail for user agent changes (browser updates, etc)

        # Optional: Validate IP address
        if entry.ip_address and ip_address and entry.ip_address != ip_address:
            logger.warning("IP address mismatch in OAuth callback")
            # Could be VPN, mobile network change, etc - log but don't fail

        # Mark as completed
        entry.completed = True
        self._save_store()

        return True, None

    def get_auth_url(self, state: str) -> Optional[str]:
        """Get the auth URL for a given state."""
        entry = self._memory_store.get(state)
        return entry.auth_url if entry else None

    def _clean_expired(self):
        """Remove expired state entries."""
        now = datetime.now(timezone.utc)
        expired = [
            state
            for state, entry in self._memory_store.items()
            if now > entry.expires_at + timedelta(hours=1)  # Grace period
        ]

        for state in expired:
            del self._memory_store[state]
            logger.debug("Cleaned expired OAuth state")

        if expired:
            self._save_store()

    def _load_store(self):
        """Load state store from file."""
        if not self.store_path or not self.store_path.exists():
            return

        try:
            with open(self.store_path, "r") as f:
                data = json.load(f)
                for state, entry_data in data.items():
                    # Parse datetime strings
                    entry_data["created_at"] = datetime.fromisoformat(
                        entry_data["created_at"]
                    )
                    entry_data["expires_at"] = datetime.fromisoformat(
                        entry_data["expires_at"]
                    )
                    self._memory_store[state] = OAuthStateEntry(**entry_data)
            logger.debug(
                f"Loaded {len(self._memory_store)} OAuth states from {self.store_path}"
            )
        except Exception as e:
            logger.warning(f"Could not load OAuth state store: {e}")

    def _save_store(self):
        """Save state store to file."""
        if not self.store_path:
            return

        try:
            # Ensure directory exists
            self.store_path.parent.mkdir(parents=True, exist_ok=True)

            # Convert to JSON-serializable format
            data = {}
            for state, entry in self._memory_store.items():
                entry_dict = entry.model_dump()
                # Convert datetime to ISO format
                entry_dict["created_at"] = entry_dict["created_at"].isoformat()
                entry_dict["expires_at"] = entry_dict["expires_at"].isoformat()
                data[state] = entry_dict

            # Write atomically
            tmp_path = self.store_path.with_suffix(".tmp")
            with open(tmp_path, "w") as f:
                json.dump(data, f, indent=2)
            tmp_path.replace(self.store_path)

        except Exception as e:
            logger.warning(f"Could not save OAuth state store: {e}")


# Global instance for the application
_oauth_state_store: Optional[OAuthStateStore] = None


def get_oauth_state_store() -> OAuthStateStore:
    """Get or create the global OAuth state store."""
    global _oauth_state_store
    if _oauth_state_store is None:
        # Use environment variable for secret if available
        import os

        secret_key = os.getenv("OAUTH_STATE_SECRET")

        # Use file storage in development, memory in production
        store_path = None
        if os.getenv("OAUTH_STATE_PERSIST") == "true":
            store_path = Path.home() / ".amazon_ads_mcp" / "oauth_states.json"

        _oauth_state_store = OAuthStateStore(
            secret_key=secret_key, store_path=store_path
        )

    return _oauth_state_store
