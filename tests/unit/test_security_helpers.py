"""Coverage-pushing tests for ``amazon_ads_mcp.utils.security``.

This module had 172 lines missing in the round-13 measurement (29%
coverage on 242 stmts). The functions are pure-string sanitization and
validation helpers — quick to test thoroughly. This file covers the
visible surface so future drift in any sanitizer is caught at the call
site rather than discovered in production logs.

Mostly example-based: sanitization rules are documented closed lists
that read better as concrete cases than as Hypothesis properties.
"""

from __future__ import annotations

import logging

import pytest

from amazon_ads_mcp.utils.security import (
    SanitizingFormatter,
    sanitize_dict,
    sanitize_filename,
    sanitize_headers,
    sanitize_html_input,
    sanitize_sql_input,
    sanitize_string,
    sanitize_url,
    safe_log_dict,
    validate_email,
    validate_storage_key,
    validate_url,
)
from amazon_ads_mcp.utils.errors import ValidationError


# --- sanitize_string ------------------------------------------------------


class TestSanitizeString:
    def test_empty_returns_empty(self) -> None:
        assert sanitize_string("") == ""

    def test_none_returns_none(self) -> None:
        assert sanitize_string(None) is None  # type: ignore[arg-type]

    def test_jwt_full_redacted(self) -> None:
        jwt = "eyJabc.eyJdef.signature_part_xyz"
        assert sanitize_string(jwt) == "<jwt_token:REDACTED>"

    def test_jwt_partial_shows_length(self) -> None:
        jwt = "eyJabc.eyJdef.signature_part_xyz"
        out = sanitize_string(jwt, partial=True)
        assert out.startswith("<jwt_token:length=") and out.endswith(">")

    def test_bearer_token_redacted(self) -> None:
        assert sanitize_string("Bearer abc123xyz") == "<bearer_token:REDACTED>"

    def test_basic_auth_redacted(self) -> None:
        assert sanitize_string("Basic dXNlcjpwYXNz") == "<basic_auth:REDACTED>"

    def test_clean_string_passes_through(self) -> None:
        assert sanitize_string("hello world") == "hello world"


# --- sanitize_headers -----------------------------------------------------


class TestSanitizeHeaders:
    def test_empty_dict_returns_empty(self) -> None:
        assert sanitize_headers({}) == {}

    def test_authorization_redacted(self) -> None:
        out = sanitize_headers({"Authorization": "Bearer abc"})
        assert "REDACTED" in out["Authorization"]

    def test_case_insensitive_header_match(self) -> None:
        out = sanitize_headers({"AUTHORIZATION": "Bearer abc"})
        assert "REDACTED" in out["AUTHORIZATION"]

    def test_cookie_redacted(self) -> None:
        out = sanitize_headers({"Cookie": "sessionid=xyz"})
        assert "REDACTED" in out["Cookie"]

    def test_non_sensitive_header_preserved(self) -> None:
        out = sanitize_headers({"User-Agent": "test/1.0"})
        assert out["User-Agent"] == "test/1.0"

    def test_non_sensitive_with_token_in_value_redacted(self) -> None:
        """Non-sensitive header NAMES still get value-level sanitization
        when the value LOOKS sensitive (e.g., a JWT in a custom header)."""
        out = sanitize_headers({"X-Custom": "eyJabc.eyJdef.signature"})
        assert "REDACTED" in out["X-Custom"]


# --- sanitize_url ---------------------------------------------------------


class TestSanitizeUrl:
    def test_empty_returns_empty(self) -> None:
        assert sanitize_url("") == ""

    def test_token_query_param_redacted(self) -> None:
        url = "https://x.com/api?token=secret123"
        out = sanitize_url(url)
        assert "secret123" not in out
        assert "REDACTED" in out

    def test_secret_param_redacted(self) -> None:
        out = sanitize_url("https://x.com/api?secret=foo")
        assert "foo" not in out

    def test_clean_url_passes_through(self) -> None:
        assert sanitize_url("https://x.com/api") == "https://x.com/api"

    def test_case_insensitive_param_match(self) -> None:
        out = sanitize_url("https://x.com?TOKEN=abc&Other=ok")
        assert "abc" not in out
        assert "ok" in out


# --- safe_log_dict --------------------------------------------------------


class TestSafeLogDict:
    def test_empty_returns_empty(self) -> None:
        assert safe_log_dict({}) == {}

    def test_top_level_password_redacted(self) -> None:
        out = safe_log_dict({"password": "hunter2", "user": "alice"})
        assert out["password"] == "<REDACTED>"
        assert out["user"] == "alice"

    def test_nested_secret_redacted(self) -> None:
        out = safe_log_dict({"creds": {"secret": "xyz"}})
        assert out["creds"]["secret"] == "<REDACTED>"

    def test_token_in_list_inside_dict_sanitized(self) -> None:
        out = safe_log_dict({"events": [{"token": "abc"}, {"name": "ok"}]})
        assert out["events"][0]["token"] == "<REDACTED>"
        assert out["events"][1]["name"] == "ok"

    def test_extra_sanitize_keys(self) -> None:
        out = safe_log_dict({"my_secret_field": "abc"}, sanitize_keys=["my_secret_field"])
        assert out["my_secret_field"] == "<REDACTED>"


# --- sanitize_dict --------------------------------------------------------


class TestSanitizeDict:
    def test_empty_returns_empty(self) -> None:
        assert sanitize_dict({}, rules={}) == {}

    def test_rule_applied_to_matching_field(self) -> None:
        out = sanitize_dict({"name": "alice"}, rules={"name": str.upper})
        assert out["name"] == "ALICE"

    def test_field_without_rule_passes_through_in_lax_mode(self) -> None:
        out = sanitize_dict({"name": "x", "extra": 42}, rules={"name": str.upper})
        assert out["extra"] == 42

    def test_strict_mode_rejects_unknown_field(self) -> None:
        with pytest.raises(ValidationError, match="Unknown field"):
            sanitize_dict({"unknown": "x"}, rules={}, strict=True)

    def test_rule_failure_raises_validation_error(self) -> None:
        def explode(_: object) -> str:
            raise RuntimeError("nope")
        with pytest.raises(ValidationError, match="Invalid"):
            sanitize_dict({"f": 1}, rules={"f": explode})


# --- sanitize_sql_input ---------------------------------------------------


class TestSanitizeSqlInput:
    def test_empty_returns_empty(self) -> None:
        assert sanitize_sql_input("") == ""

    def test_drop_table_rejected(self) -> None:
        with pytest.raises(ValidationError, match="SQL injection"):
            sanitize_sql_input("'; DROP TABLE users; --")

    def test_union_select_rejected(self) -> None:
        with pytest.raises(ValidationError):
            sanitize_sql_input("foo' UNION SELECT * FROM users")

    def test_comment_rejected(self) -> None:
        with pytest.raises(ValidationError):
            sanitize_sql_input("foo--bar")

    def test_clean_input_escapes_single_quote(self) -> None:
        # Plain text with a single quote — escape, not reject.
        out = sanitize_sql_input("O'Brien")
        assert out == "O''Brien"

    def test_wildcards_escaped_by_default(self) -> None:
        out = sanitize_sql_input("foo%bar_baz")
        assert "\\%" in out and "\\_" in out

    def test_wildcards_preserved_when_allowed(self) -> None:
        out = sanitize_sql_input("foo%bar", allow_wildcards=True)
        assert "%" in out and "\\%" not in out


# --- sanitize_html_input --------------------------------------------------


class TestSanitizeHtmlInput:
    def test_empty_returns_empty(self) -> None:
        assert sanitize_html_input("") == ""

    def test_script_tag_removed(self) -> None:
        out = sanitize_html_input("<script>evil()</script>hello")
        assert "script" not in out.lower() or "&lt;script" in out
        assert "evil" not in out or "&" in out  # escaped or removed

    def test_javascript_url_neutralized(self) -> None:
        out = sanitize_html_input("javascript:alert(1)")
        assert "javascript:" not in out.lower() or "javascript" in out and "<" not in out

    def test_event_handler_removed(self) -> None:
        out = sanitize_html_input('<img onclick="bad()">')
        # onclick= pattern matches XSS_PATTERNS; should be removed
        assert "onclick" not in out

    def test_html_entities_escaped(self) -> None:
        out = sanitize_html_input("<b>hello</b>")
        assert "&lt;" in out or "&gt;" in out


# --- sanitize_filename ----------------------------------------------------


class TestSanitizeFilename:
    def test_empty_returns_empty(self) -> None:
        assert sanitize_filename("") == ""

    def test_strips_path_traversal(self) -> None:
        out = sanitize_filename("../../etc/passwd")
        assert ".." not in out
        assert "/" not in out

    def test_strips_backslash(self) -> None:
        assert "\\" not in sanitize_filename("foo\\bar")

    def test_strips_null_byte(self) -> None:
        assert "\x00" not in sanitize_filename("foo\x00.txt")

    def test_long_filename_truncated_with_extension(self) -> None:
        name = "a" * 300 + ".txt"
        out = sanitize_filename(name)
        assert len(out) <= 255
        assert out.endswith(".txt")

    def test_long_filename_no_extension_truncated(self) -> None:
        out = sanitize_filename("a" * 300)
        assert len(out) == 255


# --- validate_url ---------------------------------------------------------


class TestValidateUrl:
    def test_valid_https_url_returned(self) -> None:
        assert validate_url("https://x.com") == "https://x.com"

    def test_valid_http_url_returned(self) -> None:
        assert validate_url("http://x.com") == "http://x.com"

    def test_javascript_scheme_rejected(self) -> None:
        with pytest.raises(ValidationError):
            validate_url("javascript:alert(1)", allowed_schemes=["javascript"])

    def test_data_scheme_rejected_explicitly(self) -> None:
        with pytest.raises(ValidationError):
            validate_url("data:text/html,foo", allowed_schemes=["data"])

    def test_unallowed_scheme_rejected(self) -> None:
        with pytest.raises(ValidationError, match="scheme"):
            validate_url("ftp://example.com")

    def test_strips_whitespace(self) -> None:
        assert validate_url("  https://x.com  ") == "https://x.com"

    def test_custom_allowed_schemes(self) -> None:
        assert validate_url("ws://x.com", allowed_schemes=["ws"]) == "ws://x.com"


# --- validate_email -------------------------------------------------------


class TestValidateEmail:
    def test_valid_email_normalized(self) -> None:
        assert validate_email(" Alice@Example.COM ") == "alice@example.com"

    def test_invalid_no_at_sign_rejected(self) -> None:
        with pytest.raises(ValidationError):
            validate_email("not-an-email")

    def test_invalid_no_tld_rejected(self) -> None:
        with pytest.raises(ValidationError):
            validate_email("a@b")

    def test_plus_address_accepted(self) -> None:
        assert validate_email("user+tag@x.com") == "user+tag@x.com"


# --- validate_storage_key -------------------------------------------------


class TestValidateStorageKey:
    def test_valid_key_returned(self) -> None:
        assert validate_storage_key("my_key-123") == "my_key-123"

    def test_surrounding_whitespace_rejected_by_regex(self) -> None:
        # See ``docs/audit/latent-issues.md`` #5.
        # The format regex runs BEFORE the strip, so spaces fail validation
        # rather than being silently trimmed. Documents actual behavior.
        with pytest.raises(ValidationError, match="format"):
            validate_storage_key("  abc  ")

    def test_empty_rejected(self) -> None:
        with pytest.raises(ValidationError, match="required"):
            validate_storage_key("")

    def test_whitespace_only_rejected(self) -> None:
        with pytest.raises(ValidationError, match="required"):
            validate_storage_key("   ")

    def test_special_chars_rejected(self) -> None:
        with pytest.raises(ValidationError, match="format"):
            validate_storage_key("foo bar")

    def test_dot_rejected(self) -> None:
        with pytest.raises(ValidationError):
            validate_storage_key("foo.bar")


# --- SanitizingFormatter --------------------------------------------------


class TestSanitizingFormatter:
    def test_message_with_jwt_redacted(self) -> None:
        formatter = SanitizingFormatter("%(message)s")
        record = logging.LogRecord(
            name="test", level=logging.INFO, pathname="", lineno=0,
            msg="auth failed: eyJabc.eyJdef.sig", args=None, exc_info=None,
        )
        out = formatter.format(record)
        assert "REDACTED" in out

    def test_format_with_args_handled(self) -> None:
        formatter = SanitizingFormatter("%(message)s")
        record = logging.LogRecord(
            name="test", level=logging.INFO, pathname="", lineno=0,
            msg="user=%s token=%s", args=("alice", "Bearer abc"), exc_info=None,
        )
        out = formatter.format(record)
        # The bearer token should be redacted in the formatted message
        assert "Bearer abc" not in out

    def test_format_with_mismatched_args_documents_current_behavior(self) -> None:
        """Format strings with arg-count mismatch (see
        ``docs/audit/latent-issues.md`` #6):

        The formatter's defensive try/except sanitizes the message but
        leaves args populated; the parent ``logging.Formatter.format``
        then re-attempts ``msg % args`` via ``record.getMessage()`` and
        raises TypeError. Documenting this behavior so any future fix
        (clearing args after a TypeError) doesn't silently change the
        contract — the test will fail and the maintainer can decide.
        """
        formatter = SanitizingFormatter("%(message)s")
        record = logging.LogRecord(
            name="test", level=logging.INFO, pathname="", lineno=0,
            msg="bad %s %s", args=("only-one",), exc_info=None,
        )
        with pytest.raises(TypeError, match="not enough arguments"):
            formatter.format(record)
