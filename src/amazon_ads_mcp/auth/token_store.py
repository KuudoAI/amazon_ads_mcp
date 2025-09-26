"""Token storage abstraction for unified token management.

This module provides a pluggable token storage system that serves as the
single source of truth for all authentication tokens across providers.
"""

import base64
import json
import logging
import os
import threading
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, Optional

try:
    from cryptography.fernet import Fernet

    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    CRYPTOGRAPHY_AVAILABLE = False

logger = logging.getLogger(__name__)


class TokenKind(Enum):
    """Types of tokens stored in the system."""

    REFRESH = "refresh"  # Long-lived refresh token
    ACCESS = "access"  # Short-lived access token
    PROVIDER_JWT = "provider_jwt"  # Provider-specific JWT (e.g., OpenBridge)


@dataclass
class TokenKey:
    """Composite key for token storage.

    Uniquely identifies a token by provider, identity, type, and scope.
    """

    provider_type: str  # e.g., "direct", "openbridge"
    identity_id: str  # e.g., "default", "direct-auth", remote identity ID
    token_kind: TokenKind  # Type of token
    region: Optional[str] = None  # e.g., "na", "eu", "fe"
    marketplace: Optional[str] = None  # e.g., "ATVPDKIKX0DER"
    profile_id: Optional[str] = None  # Amazon Ads profile ID

    def to_string(self) -> str:
        """Convert to a string key for storage."""
        parts = [
            self.provider_type,
            self.identity_id,
            self.token_kind.value,
            self.region or "global",
            self.marketplace or "none",
            self.profile_id or "none",
        ]
        return ":".join(parts)

    @classmethod
    def from_string(cls, key_str: str) -> "TokenKey":
        """Parse from a string key."""
        parts = key_str.split(":")
        if len(parts) != 6:
            raise ValueError(f"Invalid token key format: {key_str}")

        return cls(
            provider_type=parts[0],
            identity_id=parts[1],
            token_kind=TokenKind(parts[2]),
            region=parts[3] if parts[3] != "global" else None,
            marketplace=parts[4] if parts[4] != "none" else None,
            profile_id=parts[5] if parts[5] != "none" else None,
        )


@dataclass
class TokenEntry:
    """A stored token with metadata."""

    value: str  # The actual token
    expires_at: datetime  # When the token expires
    metadata: Dict[str, Any]  # Additional metadata (scope, token_type, etc.)
    created_at: datetime = None  # When entry was created

    def __post_init__(self):
        if self.created_at is None:
            self.created_at = datetime.now(timezone.utc)

    def is_expired(self, buffer_seconds: int = 300) -> bool:
        """Check if token is expired or will expire soon."""
        expiry_with_buffer = self.expires_at - timedelta(seconds=buffer_seconds)
        # Ensure both datetimes are timezone-aware for comparison
        now = datetime.now(timezone.utc)
        if expiry_with_buffer.tzinfo is None:
            expiry_with_buffer = expiry_with_buffer.replace(tzinfo=timezone.utc)
        return now >= expiry_with_buffer

    def to_dict(self) -> dict:
        """Serialize for storage."""
        return {
            "value": self.value,
            "expires_at": self.expires_at.isoformat(),
            "metadata": self.metadata,
            "created_at": self.created_at.isoformat(),
        }

    @classmethod
    def from_dict(cls, data: dict) -> "TokenEntry":
        """Deserialize from storage."""
        return cls(
            value=data["value"],
            expires_at=datetime.fromisoformat(data["expires_at"]),
            metadata=data.get("metadata", {}),
            created_at=datetime.fromisoformat(data["created_at"]),
        )


class TokenStore(ABC):
    """Abstract base class for token storage implementations."""

    @abstractmethod
    async def get(self, key: TokenKey) -> Optional[TokenEntry]:
        """Retrieve a token by key.

        Returns None if not found or expired (implementation may auto-cleanup).
        """
        pass

    @abstractmethod
    async def set(self, key: TokenKey, entry: TokenEntry) -> None:
        """Store or update a token."""
        pass

    @abstractmethod
    async def invalidate(self, key: TokenKey) -> None:
        """Invalidate a specific token."""
        pass

    @abstractmethod
    async def invalidate_pattern(
        self,
        provider_type: Optional[str] = None,
        identity_id: Optional[str] = None,
        token_kind: Optional[TokenKind] = None,
        region: Optional[str] = None,
    ) -> int:
        """Invalidate tokens matching a pattern.

        Returns the number of invalidated entries.
        """
        pass

    @abstractmethod
    async def clear(self) -> None:
        """Clear all stored tokens."""
        pass

    async def get_access_token(
        self,
        provider_type: str,
        identity_id: str,
        region: Optional[str] = None,
        profile_id: Optional[str] = None,
    ) -> Optional[TokenEntry]:
        """Convenience method to get an access token."""
        key = TokenKey(
            provider_type=provider_type,
            identity_id=identity_id,
            token_kind=TokenKind.ACCESS,
            region=region,
            profile_id=profile_id,
        )
        return await self.get(key)

    async def set_access_token(
        self,
        provider_type: str,
        identity_id: str,
        token: str,
        expires_at: datetime,
        metadata: Dict[str, Any] = None,
        region: Optional[str] = None,
        profile_id: Optional[str] = None,
    ) -> None:
        """Convenience method to set an access token."""
        key = TokenKey(
            provider_type=provider_type,
            identity_id=identity_id,
            token_kind=TokenKind.ACCESS,
            region=region,
            profile_id=profile_id,
        )
        entry = TokenEntry(value=token, expires_at=expires_at, metadata=metadata or {})
        await self.set(key, entry)


class InMemoryTokenStore(TokenStore):
    """In-memory token storage with TTL and automatic cleanup."""

    def __init__(
        self,
        max_entries: int = 1000,
        cleanup_interval: int = 300,  # 5 minutes
        default_ttl: int = 3600,  # 1 hour
    ):
        self._store: Dict[str, TokenEntry] = {}
        self._lock = threading.Lock()
        self._max_entries = max_entries
        self._cleanup_interval = cleanup_interval
        self._default_ttl = default_ttl
        self._last_cleanup = time.time()

    async def get(self, key: TokenKey) -> Optional[TokenEntry]:
        """Get token with automatic cleanup of expired entries."""
        now = time.time()

        # Periodic cleanup
        if now - self._last_cleanup > self._cleanup_interval:
            await self._cleanup()
            self._last_cleanup = now

        with self._lock:
            key_str = key.to_string()
            entry = self._store.get(key_str)

            if entry:
                if entry.is_expired():
                    # Remove expired entry
                    del self._store[key_str]
                    logger.debug(f"Removed expired token: {key_str}")
                    return None
                return entry

            return None

    async def set(self, key: TokenKey, entry: TokenEntry) -> None:
        """Store token with size limit enforcement."""
        with self._lock:
            # Enforce max entries (simple LRU by removing oldest)
            if len(self._store) >= self._max_entries:
                # Remove oldest entry
                oldest_key = min(
                    self._store.keys(), key=lambda k: self._store[k].created_at
                )
                del self._store[oldest_key]
                logger.debug(f"Evicted oldest token due to size limit: {oldest_key}")

            key_str = key.to_string()
            self._store[key_str] = entry
            logger.debug(f"Stored token: {key_str}")

    async def invalidate(self, key: TokenKey) -> None:
        """Remove a specific token."""
        with self._lock:
            key_str = key.to_string()
            if key_str in self._store:
                del self._store[key_str]
                logger.debug(f"Invalidated token: {key_str}")

    async def invalidate_pattern(
        self,
        provider_type: Optional[str] = None,
        identity_id: Optional[str] = None,
        token_kind: Optional[TokenKind] = None,
        region: Optional[str] = None,
    ) -> int:
        """Invalidate tokens matching pattern."""
        with self._lock:
            to_remove = []

            for key_str in self._store.keys():
                key = TokenKey.from_string(key_str)

                # Check pattern match
                if provider_type and key.provider_type != provider_type:
                    continue
                if identity_id and key.identity_id != identity_id:
                    continue
                if token_kind and key.token_kind != token_kind:
                    continue
                if region and key.region != region:
                    continue

                to_remove.append(key_str)

            # Remove matching entries
            for key_str in to_remove:
                del self._store[key_str]

            if to_remove:
                logger.info(f"Invalidated {len(to_remove)} tokens matching pattern")

            return len(to_remove)

    async def clear(self) -> None:
        """Clear all tokens."""
        with self._lock:
            count = len(self._store)
            self._store.clear()
            logger.info(f"Cleared {count} tokens from store")

    async def _cleanup(self) -> None:
        """Remove expired entries."""
        with self._lock:
            expired_keys = [
                key for key, entry in self._store.items() if entry.is_expired()
            ]

            for key in expired_keys:
                del self._store[key]

            if expired_keys:
                logger.info(f"Cleaned up {len(expired_keys)} expired tokens")


class PersistentTokenStore(InMemoryTokenStore):
    """Token storage with optional file-based persistence.

    Extends InMemoryTokenStore with file persistence for refresh tokens only.
    Access tokens are kept in memory for performance.
    """

    def __init__(
        self,
        storage_path: Optional[Path] = None,
        encrypt_at_rest: bool = True,
        **kwargs,
    ):
        super().__init__(**kwargs)

        # Determine storage path based on environment
        if storage_path is None:
            # Check for explicit cache directory from environment
            cache_dir = os.getenv("AMAZON_ADS_CACHE_DIR")
            if cache_dir:
                storage_path = Path(cache_dir) / "tokens.json"
                logger.info(
                    f"Using cache directory from AMAZON_ADS_CACHE_DIR: {storage_path}"
                )
            # Check if we're in a Docker container with /app/.cache available
            elif Path("/app/.cache").exists() and Path("/app/.cache").is_dir():
                storage_path = Path("/app/.cache") / "amazon-ads-mcp" / "tokens.json"
                logger.info(f"Using Docker cache directory: {storage_path}")
            else:
                # Fall back to home directory for local development
                storage_path = Path.home() / ".amazon-ads-mcp" / "tokens.json"
                logger.info(f"Using local cache directory: {storage_path}")

        self._storage_path = storage_path
        self._encrypt_at_rest = encrypt_at_rest
        self._cipher = None

        # Initialize encryption if requested and available
        if self._encrypt_at_rest:
            self._cipher = self._initialize_encryption()

        # Create directory with restricted permissions
        try:
            self._storage_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        except PermissionError:
            # In some Docker environments, we might not be able to set permissions
            self._storage_path.parent.mkdir(parents=True, exist_ok=True)
            logger.warning(
                f"Could not set restricted permissions on {self._storage_path.parent}"
            )

        # Load existing tokens on startup
        self._load_from_disk()

    async def set(self, key: TokenKey, entry: TokenEntry) -> None:
        """Store token, persisting refresh tokens to disk."""
        await super().set(key, entry)

        # Only persist refresh tokens
        if key.token_kind == TokenKind.REFRESH:
            await self._persist_to_disk()

    async def invalidate(self, key: TokenKey) -> None:
        """Invalidate token, updating persistence if needed."""
        await super().invalidate(key)

        # Update disk if it was a refresh token
        if key.token_kind == TokenKind.REFRESH:
            await self._persist_to_disk()

    async def clear(self) -> None:
        """Clear all tokens including persistent storage."""
        await super().clear()

        # Clear persistent storage
        if self._storage_path.exists():
            self._storage_path.unlink()
            logger.info(f"Cleared persistent token storage at {self._storage_path}")

    def _load_from_disk(self) -> None:
        """Load refresh tokens from disk on startup."""
        if not self._storage_path.exists():
            return

        try:
            with open(self._storage_path, "r") as f:
                data = json.load(f)

            # Decrypt if needed
            if self._encrypt_at_rest:
                data = self._decrypt_data(data)

            # Load refresh tokens into memory
            for key_str, entry_dict in data.items():
                key = TokenKey.from_string(key_str)

                # Only load refresh tokens
                if key.token_kind != TokenKind.REFRESH:
                    continue

                entry = TokenEntry.from_dict(entry_dict)

                # Skip expired tokens
                if not entry.is_expired():
                    self._store[key_str] = entry

            logger.info(f"Loaded {len(self._store)} tokens from persistent storage")

        except Exception as e:
            logger.error(f"Failed to load tokens from disk: {e}")

    async def _persist_to_disk(self) -> None:
        """Save refresh tokens to disk."""
        try:
            # Extract only refresh tokens
            refresh_tokens = {}
            with self._lock:
                for key_str, entry in self._store.items():
                    key = TokenKey.from_string(key_str)
                    if key.token_kind == TokenKind.REFRESH:
                        refresh_tokens[key_str] = entry.to_dict()

            # Encrypt if needed
            data = refresh_tokens
            if self._encrypt_at_rest:
                data = self._encrypt_data(data)

            # Write with atomic operation for safety
            temp_path = self._storage_path.with_suffix(".tmp")
            with open(temp_path, "w") as f:
                json.dump(data, f, indent=2)

            # Atomic move
            temp_path.replace(self._storage_path)

            # Try to set restrictive permissions (may fail in some Docker environments)
            try:
                self._storage_path.chmod(0o600)
            except (PermissionError, OSError):
                pass  # Permissions might not be settable in Docker

            logger.debug(f"Persisted {len(refresh_tokens)} refresh tokens to disk")

        except Exception as e:
            logger.error(f"Failed to persist tokens to disk: {e}")

    def _initialize_encryption(self) -> Optional[Any]:
        """Initialize encryption cipher for token storage.

        Uses Fernet symmetric encryption with a key derived from:
        1. Environment variable AMAZON_ADS_ENCRYPTION_KEY (if set)
        2. Machine-specific seed + app identifier (fallback)

        Returns:
            Fernet cipher instance or None if encryption unavailable
        """
        if not CRYPTOGRAPHY_AVAILABLE:
            # Check if plaintext persistence is explicitly allowed
            allow_plaintext = (
                os.getenv("AMAZON_ADS_ALLOW_PLAINTEXT_PERSIST", "false").lower()
                == "true"
            )

            error_msg = (
                "SECURITY ERROR: cryptography library not installed!\n"
                "Tokens would be stored in PLAINTEXT without encryption.\n"
                "Options:\n"
                "1. Install cryptography: pip install cryptography (RECOMMENDED)\n"
                "2. Disable persistence: AMAZON_ADS_TOKEN_PERSIST=false\n"
                "3. Allow plaintext (INSECURE): AMAZON_ADS_ALLOW_PLAINTEXT_PERSIST=true"
            )

            if not allow_plaintext:
                logger.error(error_msg)
                raise RuntimeError(
                    "Refusing to store tokens in plaintext. "
                    "Install cryptography or set AMAZON_ADS_ALLOW_PLAINTEXT_PERSIST=true (not recommended)"
                )
            else:
                logger.warning(
                    "WARNING: Plaintext token storage explicitly allowed!\n"
                    "This is INSECURE and should not be used in production.\n"
                    "Install cryptography: pip install cryptography"
                )
                return None

        try:
            # Try to get encryption key from environment
            env_key = os.getenv("AMAZON_ADS_ENCRYPTION_KEY")

            if env_key:
                # Use provided key (should be base64-encoded Fernet key)
                try:
                    # Validate key format
                    if (
                        len(env_key) != 44
                    ):  # Fernet keys are exactly 44 chars when base64-encoded
                        raise ValueError(
                            f"Invalid key length: {len(env_key)} (expected 44)"
                        )

                    cipher = Fernet(
                        env_key.encode() if isinstance(env_key, str) else env_key
                    )
                    logger.info("Using encryption key from AMAZON_ADS_ENCRYPTION_KEY")
                    return cipher
                except Exception as e:
                    logger.error(
                        f"CRITICAL: Invalid AMAZON_ADS_ENCRYPTION_KEY: {e}\n"
                        f"Previously encrypted tokens will be UNREADABLE!\n"
                        f'Generate a valid key with: python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"\n'
                        f"Falling back to auto-generated random key"
                    )

            # Generate and persist a strong random key
            # This ensures we always use strong encryption, never weak deterministic keys
            key_file = self._cache_dir / ".encryption.key"

            # Check if we're in production-like environment
            is_production = (
                os.getenv("ENV") in ["production", "prod", "staging"]
                or os.getenv("ENVIRONMENT") in ["production", "prod", "staging"]
                or os.getenv("NODE_ENV") in ["production", "prod", "staging"]
            )

            if is_production:
                # In production, warn but don't fail
                logger.warning(
                    "SECURITY WARNING: No AMAZON_ADS_ENCRYPTION_KEY set in production!\n"
                    "Using auto-generated key. For better security, set an explicit key:\n"
                    'Generate one with: python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"\n'
                    "Then set: export AMAZON_ADS_ENCRYPTION_KEY='<generated-key>'"
                )

            if key_file.exists():
                # Load existing key
                try:
                    with open(key_file, 'rb') as f:
                        key = f.read()
                    cipher = Fernet(key)
                    logger.info("Loaded persistent encryption key from cache")
                    return cipher
                except Exception as e:
                    logger.warning(f"Failed to load existing key: {e}, generating new one")

            # Generate a new random key with strong entropy
            key = Fernet.generate_key()
            cipher = Fernet(key)

            # Save the key for persistence
            try:
                key_file.parent.mkdir(parents=True, exist_ok=True)
                # Set restrictive permissions (owner read/write only)
                with open(key_file, 'wb') as f:
                    f.write(key)
                os.chmod(key_file, 0o600)
                logger.info(
                    f"Generated and saved new encryption key to {key_file}\n"
                    "This strong random key will be reused across sessions.\n"
                    "For explicit control, set AMAZON_ADS_ENCRYPTION_KEY environment variable."
                )
            except Exception as e:
                logger.warning(f"Could not persist encryption key: {e}")

            return cipher

        except Exception as e:
            logger.error(f"Failed to initialize encryption: {e}")
            return None

    def _encrypt_data(self, data: dict) -> dict:
        """Encrypt token data for at-rest storage.

        Uses Fernet symmetric encryption when available.
        Falls back to plaintext with warning if encryption unavailable.
        """
        if not self._cipher:
            if self._encrypt_at_rest:
                # Check if we explicitly allow plaintext
                allow_plaintext = (
                    os.getenv("AMAZON_ADS_ALLOW_PLAINTEXT_PERSIST", "false").lower()
                    == "true"
                )
                if not allow_plaintext:
                    raise RuntimeError(
                        "Cannot encrypt tokens - cryptography not available. "
                        "Install cryptography or set AMAZON_ADS_ALLOW_PLAINTEXT_PERSIST=true"
                    )
                logger.warning(
                    "SECURITY WARNING: Storing tokens in PLAINTEXT (encryption unavailable). "
                    "Install cryptography: pip install cryptography"
                )
            return data

        try:
            # Serialize data to JSON
            json_data = json.dumps(data, separators=(",", ":"))

            # Encrypt the JSON string
            encrypted_bytes = self._cipher.encrypt(json_data.encode())

            # Return as a dict with encrypted data
            return {
                "_encrypted": True,
                "_version": "1.0",
                "data": base64.b64encode(encrypted_bytes).decode("ascii"),
            }
        except Exception as e:
            # Encryption failure is critical - never fall back to plaintext
            logger.error(f"CRITICAL: Encryption failed: {e}")

            # Check if plaintext persistence is explicitly allowed (for testing only)
            if os.getenv("AMAZON_ADS_ALLOW_PLAINTEXT_PERSIST") == "true":
                logger.warning(
                    "AMAZON_ADS_ALLOW_PLAINTEXT_PERSIST is enabled - storing in plaintext.\n"
                    "This should ONLY be used for testing!"
                )
                return data

            # Raise the exception to prevent silent security downgrade
            raise ValueError(
                f"Token encryption failed: {e}\n"
                "Refusing to store tokens in plaintext.\n"
                "To allow plaintext storage for testing, set AMAZON_ADS_ALLOW_PLAINTEXT_PERSIST=true"
            ) from e

    def _decrypt_data(self, data: dict) -> dict:
        """Decrypt token data from storage.

        Handles both encrypted and plaintext data for compatibility.
        """
        # Check if data is encrypted
        if not isinstance(data, dict) or not data.get("_encrypted"):
            # Data is not encrypted, return as-is
            return data

        if not self._cipher:
            logger.error("Cannot decrypt data - encryption not available")
            return {}

        try:
            # Extract and decode the encrypted data
            encrypted_b64 = data.get("data", "")
            encrypted_bytes = base64.b64decode(encrypted_b64)

            # Decrypt the data
            decrypted_bytes = self._cipher.decrypt(encrypted_bytes)

            # Parse the JSON
            return json.loads(decrypted_bytes.decode())

        except Exception as e:
            logger.error(f"Decryption failed: {e}")
            return {}


# Factory function for creating token stores
def create_token_store(persist: bool = True, **kwargs) -> TokenStore:
    """Create a token store instance.

    SECURITY NOTE: Environment variable AMAZON_ADS_TOKEN_PERSIST overrides
    the persist parameter. Default is "false" for security (tokens in memory only).

    When persistence is enabled:
    - Tokens are ENCRYPTED at rest using Fernet (AES-128) if cryptography is installed
    - Falls back to PLAINTEXT with warnings if cryptography is unavailable
    - For production, set AMAZON_ADS_ENCRYPTION_KEY with a secure key

    The machine-derived key is for development/local use only and should NOT be
    relied upon for production security.

    Args:
        persist: Whether to enable persistent storage (overridden by env var)
        **kwargs: Additional configuration for the store

    Returns:
        TokenStore instance (InMemory or Persistent based on config)
    """
    # Check environment for persistence override
    # Default is False for security, but can be enabled by setting to "true"
    env_persist = os.getenv("AMAZON_ADS_TOKEN_PERSIST", "false").lower()
    if env_persist == "false":
        persist = False
    elif env_persist == "true":
        persist = True

    if persist:
        logger.info("Creating persistent token store")
        return PersistentTokenStore(**kwargs)
    else:
        logger.info("Creating in-memory token store")
        return InMemoryTokenStore(**kwargs)
