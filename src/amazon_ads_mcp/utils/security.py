"""Security utilities for sanitization, validation, and secure logging.

This module consolidates all security-related functionality including:
- Log sanitization and secure logging setup
- Input validation and sanitization
- Pattern matching for sensitive data
- SQL injection prevention
- XSS protection
- Secure logging with automatic redaction
"""

import copy
import html
import ipaddress
import logging
import os
import re
import socket
import sys
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse


# Import ValidationError - using a different approach to avoid circular imports
def _import_validation_error():
    """Import ValidationError from error module.

    :return: ValidationError class
    :rtype: Type[Exception]
    """
    from amazon_ads_mcp.utils.errors import ValidationError

    return ValidationError


# Get ValidationError class at module load time
try:
    # Try to import ValidationError from error module
    ValidationError = _import_validation_error()
except ImportError:
    # Fallback to local definition if circular import occurs
    class ValidationError(Exception):
        """Input validation error.

        Custom exception for validation errors with optional field
        information for better error reporting.

        :param message: Error message describing the validation failure
        :type message: str
        :param field: Optional field name that failed validation
        :type field: Optional[str]
        """

        def __init__(self, message: str, field: Optional[str] = None):
            super().__init__(message)
            self.field = field


# Patterns for sensitive data detection
SENSITIVE_PATTERNS = {
    "jwt_token": re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"),
    "bearer_token": re.compile(r"Bearer\s+[A-Za-z0-9_-]+", re.IGNORECASE),
    "api_key": re.compile(r"[A-Za-z0-9]{32,}"),
    "basic_auth": re.compile(r"Basic\s+[A-Za-z0-9+/=]+", re.IGNORECASE),
}

# Headers that should never be logged
SENSITIVE_HEADERS = {
    "authorization",
    "x-api-key",
    "x-auth-token",
    "cookie",
    "set-cookie",
    "x-csrf-token",
    "x-access-token",
    "x-refresh-token",
}

# SQL injection patterns
SQL_INJECTION_PATTERNS = [
    r"(\b(INSERT|UPDATE|DELETE|DROP|UNION|CREATE|ALTER|EXEC|EXECUTE)\b)",
    r"(--|\#|\/\*|\*\/)",  # SQL comments
    r"(\bOR\b.*=.*)",  # OR conditions
    r"(;.*\b(SELECT|INSERT|UPDATE|DELETE)\b)",  # Multiple statements
]

# XSS patterns
XSS_PATTERNS = [
    r"<script[^>]*>.*?</script>",
    r"javascript:",
    r"on\w+\s*=",  # Event handlers
    r"<iframe[^>]*>",
]

# =============================================================================
# String and Log Sanitization
# =============================================================================


def sanitize_string(value: str, partial: bool = False) -> str:
    """Sanitize a string containing potential sensitive data.

    Removes or redacts sensitive information like JWT tokens,
    API keys, and authentication headers from strings.

    :param value: String to sanitize
    :type value: str
    :param partial: If True, show length instead of full redaction
    :type partial: bool
    :return: Sanitized string with sensitive data redacted
    :rtype: str
    """
    if not value:
        return value
    for pattern_name, pattern in SENSITIVE_PATTERNS.items():
        if pattern.search(value):
            if partial and len(value) > 10:
                return f"<{pattern_name}:length={len(value)}>"
            else:
                return f"<{pattern_name}:REDACTED>"
    return value


def sanitize_headers(headers: Dict[str, Any]) -> Dict[str, Any]:
    """Sanitize HTTP headers for logging.

    Removes or redacts sensitive headers like Authorization,
    API keys, and cookies from header dictionaries.

    :param headers: Dictionary of HTTP headers
    :type headers: Dict[str, Any]
    :return: Sanitized headers dictionary
    :rtype: Dict[str, Any]
    """
    if not headers:
        return headers
    sanitized = copy.deepcopy(headers)
    for key, value in headers.items():
        lower_key = key.lower()
        if lower_key in SENSITIVE_HEADERS:
            if isinstance(value, str) and len(value) > 0:
                sanitized[key] = f"<REDACTED:length={len(value)}>"
            else:
                sanitized[key] = "<REDACTED>"
        elif isinstance(value, str):
            sanitized[key] = sanitize_string(value)
    return sanitized


def sanitize_url(url: str) -> str:
    """Sanitize URLs that might contain tokens or keys.

    Removes sensitive query parameters and path segments
    from URLs that might contain authentication tokens
    or API keys.

    :param url: URL to sanitize
    :type url: str
    :return: Sanitized URL with sensitive parameters redacted
    :rtype: str
    """
    if not url:
        return url
    sensitive_params = [
        "token",
        "key",
        "secret",
        "password",
        "auth",
        "access_token",
        "api_key",
        "client_secret",
    ]
    for param in sensitive_params:
        patterns = [
            rf"({param}=)[^&\s]+",
            rf"({param}/)[^/\s]+",
            rf"({param}:)[^/\s]+",
        ]
        for pattern in patterns:
            url = re.sub(pattern, r"\1<REDACTED>", url, flags=re.IGNORECASE)
    return url


def safe_log_dict(
    data: Dict[str, Any], sanitize_keys: List[str] = None
) -> Dict[str, Any]:
    """Create a safe version of a dictionary for logging.

    Recursively sanitizes dictionary values, removing sensitive
    data like passwords, tokens, and secrets.

    :param data: Dictionary to sanitize
    :type data: Dict[str, Any]
    :param sanitize_keys: Additional keys to sanitize beyond defaults
    :type sanitize_keys: List[str]
    :return: Sanitized dictionary safe for logging
    :rtype: Dict[str, Any]
    """
    if not data:
        return data
    default_keys = {"password", "token", "secret", "key", "auth"}
    if sanitize_keys:
        default_keys.update(sanitize_keys)
    sanitized = copy.deepcopy(data)

    def _sanitize_nested(obj: Any, path: str = "") -> Any:
        if isinstance(obj, dict):
            for key, value in obj.items():
                lower_key = key.lower()
                current_path = f"{path}.{key}" if path else key
                if any(sensitive in lower_key for sensitive in default_keys):
                    obj[key] = "<REDACTED>"
                elif isinstance(value, str):
                    obj[key] = sanitize_string(value)
                elif isinstance(value, (dict, list)):
                    obj[key] = _sanitize_nested(value, current_path)
        elif isinstance(obj, list):
            return [_sanitize_nested(item, path) for item in obj]
        return obj

    return _sanitize_nested(sanitized)


# =============================================================================
# Secure Logging Setup
# =============================================================================


class SanitizingFormatter(logging.Formatter):
    """Formatter that automatically sanitizes sensitive data.

    Custom logging formatter that automatically removes
    sensitive information from log messages and arguments.

    :param record: Log record to format
    :type record: logging.LogRecord
    :return: Formatted log message with sensitive data removed
    :rtype: str
    """

    def format(self, record: logging.LogRecord) -> str:
        """Format log record with automatic sanitization.

        Sanitizes both the log message and any arguments
        to remove sensitive information.

        :param record: Log record to format
        :type record: logging.LogRecord
        :return: Sanitized log message
        :rtype: str
        """
        try:
            # First get the formatted message to avoid format string errors
            # This handles cases where args don't match the format string
            if hasattr(record, "args") and record.args:
                # Try to format the message first
                try:
                    formatted_msg = record.msg % record.args
                    # Now sanitize the formatted message
                    record.msg = sanitize_string(formatted_msg)
                    record.args = None  # Clear args since we've already formatted
                except (TypeError, ValueError):
                    # If formatting fails, just sanitize the message and args separately
                    record.msg = sanitize_string(str(record.msg))
                    if record.args:
                        sanitized_args = []
                        for arg in record.args:
                            if isinstance(arg, str):
                                sanitized_args.append(sanitize_string(arg))
                            else:
                                sanitized_args.append(arg)
                        record.args = tuple(sanitized_args)
            else:
                # No args, just sanitize the message
                record.msg = sanitize_string(str(record.msg))

        except Exception as e:
            # If sanitization fails, log the error and use original message
            # This prevents the logging system from completely failing
            import sys

            print(f"Warning: Failed to sanitize log record: {e}", file=sys.stderr)

        return super().format(record)


# Global flag to track if logging has been set up
_LOGGING_CONFIGURED = False


def setup_secure_logging(level: str = "INFO") -> None:
    """Set up logging with automatic sanitization.

    Configures logging to automatically sanitize sensitive
    data in all log messages across the application.
    Uses a singleton pattern to prevent duplicate handlers.

    :param level: Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
    :type level: str
    :return: None
    :rtype: None
    """
    global _LOGGING_CONFIGURED

    # Skip if already configured (singleton pattern)
    if _LOGGING_CONFIGURED:
        logger = logging.getLogger(__name__)
        logger.debug("Logging already configured, skipping duplicate setup")
        return

    # Clear any existing handlers on root logger
    root_logger = logging.getLogger()
    root_logger.handlers.clear()

    # Create and configure our handler
    formatter = SanitizingFormatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(formatter)

    # Configure root logger with force=True to override any existing config
    logging.basicConfig(
        level=getattr(logging, level.upper()),
        handlers=[handler],
        force=True,  # Override any existing configuration
    )

    # Suppress duplicate logging from uvicorn/httpx if running in HTTP mode
    for logger_name in ["uvicorn", "uvicorn.access", "uvicorn.error"]:
        uv_logger = logging.getLogger(logger_name)
        uv_logger.handlers.clear()  # Remove default handlers
        uv_logger.propagate = True  # Let root logger handle it

    # Also configure specific loggers
    for logger_name in ["mcp_query_engine", "sql_tools", "auth_tools"]:
        logger = logging.getLogger(logger_name)
        logger.handlers = []
        logger.addHandler(handler)
        logger.setLevel(getattr(logging, level.upper()))

    _LOGGING_CONFIGURED = True

    # Log handler counts for diagnostics
    if level.upper() == "DEBUG":
        root_logger = logging.getLogger()
        logger = logging.getLogger(__name__)
        logger.debug(f"Root logger has {len(root_logger.handlers)} handler(s)")
        for key_logger in ["httpx", "mcp.server.lowlevel.server"]:
            test_logger = logging.getLogger(key_logger)
            logger.debug(
                f"Logger '{key_logger}' has {len(test_logger.handlers)} handler(s)"
            )


# =============================================================================
# Input Validation and Sanitization
# =============================================================================


def sanitize_sql_input(value: str, allow_wildcards: bool = False) -> str:
    """Sanitize input that will be used in SQL queries.

    Prevents SQL injection by detecting and rejecting
    dangerous patterns and escaping special characters.

    :param value: Input value to sanitize
    :type value: str
    :param allow_wildcards: Whether to allow SQL wildcards (% and _)
    :type allow_wildcards: bool
    :return: Sanitized value safe for SQL queries
    :rtype: str
    :raises ValidationError: If input contains dangerous patterns
    """
    if not value:
        return value

    # Check for SQL injection patterns
    for pattern in SQL_INJECTION_PATTERNS:
        if re.search(pattern, value, re.IGNORECASE):
            raise ValidationError(
                "Invalid input: potential SQL injection detected",
                field="query",
            )

    # Escape SQL special characters
    value = value.replace("'", "''")  # Escape single quotes

    if not allow_wildcards:
        value = value.replace("%", "\\%")  # Escape wildcards
        value = value.replace("_", "\\_")

    return value


def sanitize_html_input(value: str, allowed_tags: Optional[List[str]] = None) -> str:
    """Sanitize HTML input to prevent XSS.

    Removes potentially dangerous HTML elements and
    escapes HTML entities to prevent cross-site scripting.

    :param value: HTML input to sanitize
    :type value: str
    :param allowed_tags: List of allowed HTML tags
    :type allowed_tags: Optional[List[str]]
    :return: Sanitized HTML safe for display
    :rtype: str
    """
    if not value:
        return value

    # Default allowed tags
    if allowed_tags is None:
        allowed_tags = ["b", "i", "u", "em", "strong", "p", "br"]

    # Simple HTML sanitization (without bleach dependency)
    # Remove script tags and event handlers
    for pattern in XSS_PATTERNS:
        value = re.sub(pattern, "", value, flags=re.IGNORECASE)

    # Escape HTML entities
    value = html.escape(value)

    return value


def sanitize_filename(filename: str) -> str:
    """Sanitize filename to prevent directory traversal.

    Removes dangerous path components and limits filename
    length to prevent directory traversal attacks.

    :param filename: Filename to sanitize
    :type filename: str
    :return: Sanitized filename safe for file operations
    :rtype: str
    """
    if not filename:
        return filename

    # Remove any path components
    filename = filename.replace("..", "")
    filename = filename.replace("/", "")
    filename = filename.replace("\\", "")

    # Remove null bytes
    filename = filename.replace("\x00", "")

    # Limit length
    max_length = 255
    if len(filename) > max_length:
        name, ext = filename.rsplit(".", 1) if "." in filename else (filename, "")
        filename = (
            f"{name[: max_length - len(ext) - 1]}.{ext}" if ext else name[:max_length]
        )

    return filename


def validate_url(url: str, allowed_schemes: Optional[List[str]] = None) -> str:
    """Validate URL to prevent various attacks.

    Validates URL format and scheme to prevent
    dangerous URLs like javascript: or data: schemes.

    :param url: URL to validate
    :type url: str
    :param allowed_schemes: Allowed URL schemes
    :type allowed_schemes: Optional[List[str]]
    :return: Validated URL
    :rtype: str
    :raises ValidationError: If URL is invalid or dangerous
    """
    if not url:
        return url

    if allowed_schemes is None:
        allowed_schemes = ["http", "https"]

    # Basic URL validation
    url = url.strip()

    # Check scheme
    scheme = url.split(":", 1)[0].lower() if ":" in url else ""
    if scheme not in allowed_schemes:
        raise ValidationError(
            f"Invalid URL scheme. Allowed: {', '.join(allowed_schemes)}",
            field="url",
        )

    # Prevent javascript: and data: URLs
    if url.lower().startswith(("javascript:", "data:", "vbscript:")):
        raise ValidationError("Invalid URL: potentially dangerous scheme", field="url")

    return url


# --- SSRF Protection ---

# Default allowlist: Amazon Ads export URLs are always S3/CloudFront
_DEFAULT_ALLOWED_HOSTS = [
    ".amazonaws.com",
    ".cloudfront.net",
    ".amazon.com",
]

_BLOCKED_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),  # link-local / cloud metadata
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fe80::/10"),  # IPv6 link-local
    ipaddress.ip_network("fc00::/7"),  # IPv6 ULA (private)
    ipaddress.ip_network("fd00::/8"),
]


def _is_private_ip(ip_str: str) -> bool:
    """Check if an IP address falls within blocked (private/reserved) ranges."""
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return True  # unparseable → block
    return any(addr in net for net in _BLOCKED_NETWORKS)


def validate_download_url(
    url: str,
    allowed_host_suffixes: Optional[List[str]] = None,
) -> str:
    """Validate a URL is safe for server-side fetch (SSRF protection).

    Resolves the hostname and rejects private/reserved IPs, link-local
    addresses, and cloud metadata endpoints. Optionally restricts to an
    allowlist of host suffixes (e.g. ".amazonaws.com").

    :param url: URL to validate
    :param allowed_host_suffixes: If provided, hostname must end with one of
        these suffixes. Defaults to Amazon domains. Pass an empty list to
        allow any public host.
    :return: The validated URL (unchanged)
    :raises ValidationError: If the URL targets a private/reserved IP or
        fails the host allowlist check
    """
    ValidationError = _import_validation_error()

    if not url:
        raise ValidationError("Empty URL", field="url")

    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValidationError(
            f"Invalid scheme '{parsed.scheme}', must be http or https",
            field="url",
        )

    hostname = parsed.hostname
    if not hostname:
        raise ValidationError("No hostname in URL", field="url")

    # Host suffix allowlist (opt-out via AMAZON_ADS_ALLOW_PRIVATE_DOWNLOAD_HOSTS)
    bypass = os.environ.get("AMAZON_ADS_ALLOW_PRIVATE_DOWNLOAD_HOSTS", "").lower()
    if bypass in ("1", "true", "yes"):
        return url

    if allowed_host_suffixes is None:
        allowed_host_suffixes = _DEFAULT_ALLOWED_HOSTS

    if allowed_host_suffixes:
        hostname_lower = hostname.lower()
        if not any(
            hostname_lower.endswith(suffix) or hostname_lower == suffix.lstrip(".")
            for suffix in allowed_host_suffixes
        ):
            raise ValidationError(
                f"Host '{hostname}' not in allowed list for downloads",
                field="url",
            )

    # DNS resolution + private IP check
    try:
        addrinfos = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC)
    except socket.gaierror:
        raise ValidationError(
            f"Cannot resolve hostname '{hostname}'",
            field="url",
        )

    for family, _type, _proto, _canonname, sockaddr in addrinfos:
        ip_str = sockaddr[0]
        if _is_private_ip(ip_str):
            raise ValidationError(
                "URL resolves to private/reserved address",
                field="url",
            )

    return url


def sanitize_dict(
    data: Dict[str, Any], rules: Dict[str, callable], strict: bool = False
) -> Dict[str, Any]:
    """Sanitize dictionary values based on rules.

    Applies custom sanitization functions to dictionary
    values based on field-specific rules.

    :param data: Dictionary to sanitize
    :type data: Dict[str, Any]
    :param rules: Dictionary of field -> sanitization function
    :type rules: Dict[str, callable]
    :param strict: If True, reject unknown fields
    :type strict: bool
    :return: Sanitized dictionary
    :rtype: Dict[str, Any]
    :raises ValidationError: If strict mode and unknown field found
    """
    sanitized = {}

    for key, value in data.items():
        if key in rules:
            # Apply sanitization rule
            try:
                sanitized[key] = rules[key](value)
            except Exception as e:
                raise ValidationError(f"Invalid {key}: {e}", field=key)
        elif strict:
            raise ValidationError(f"Unknown field: {key}", field=key)
        else:
            # Pass through if no rule
            sanitized[key] = value

    return sanitized


# =============================================================================
# Validation Helpers
# =============================================================================


def validate_email(email: str) -> str:
    """Validate and normalize email address.

    Validates email format and normalizes to lowercase.

    :param email: Email address to validate
    :type email: str
    :return: Normalized email address
    :rtype: str
    :raises ValidationError: If email format is invalid
    """
    email = email.strip().lower()

    # Basic email regex
    pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    if not re.match(pattern, email):
        raise ValidationError("Invalid email address", field="email")

    return email


def validate_storage_key(key: str) -> str:
    """Validate storage key format.

    Ensures storage keys contain only safe characters
    and meet format requirements.

    :param key: Storage key to validate
    :type key: str
    :return: Validated storage key
    :rtype: str
    :raises ValidationError: If key format is invalid
    """
    if not key or not key.strip():
        raise ValidationError("Storage key is required", field="storage_key")

    # Check format (alphanumeric with underscores/hyphens)
    if not re.match(r"^[a-zA-Z0-9_-]+$", key):
        raise ValidationError(
            "Invalid storage key format. Use only letters, numbers, underscores, and hyphens.",
            field="storage_key",
        )

    return key.strip()


# =============================================================================
# Logging Convenience Functions
# =============================================================================


def log_headers(headers: Dict[str, Any], logger, level: str = "debug") -> None:
    """Log headers safely with sanitization.

    Logs HTTP headers with automatic sanitization of
    sensitive information.

    :param headers: HTTP headers to log
    :type headers: Dict[str, Any]
    :param logger: Logger instance to use
    :type logger: logging.Logger
    :param level: Log level (debug, info, warning, error)
    :type level: str
    :return: None
    :rtype: None
    """
    safe_headers = sanitize_headers(headers)
    getattr(logger, level)(f"Headers: {safe_headers}")


def log_request(url: str, headers: Dict[str, Any], body: Any, logger) -> None:
    """Log request details safely with sanitization.

    Logs complete HTTP request information with automatic
    sanitization of sensitive data.

    :param url: Request URL
    :type url: str
    :param headers: Request headers
    :type headers: Dict[str, Any]
    :param body: Request body
    :type body: Any
    :param logger: Logger instance to use
    :type logger: logging.Logger
    :return: None
    :rtype: None
    """
    safe_url = sanitize_url(url)
    safe_headers = sanitize_headers(headers)
    safe_body = (
        safe_log_dict(body) if isinstance(body, dict) else str(body)[:100] + "..."
    )
    logger.debug(f"Request to: {safe_url}")
    logger.debug(f"Headers: {safe_headers}")
    logger.debug(f"Body: {safe_body}")
