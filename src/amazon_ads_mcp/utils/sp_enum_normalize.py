"""SP v3 expression-type normalization helpers (response-side parsing).

Added 2026-05-05 after a weekly Marketing MCP run hit 9 false NOT FOUNDs because
execute scripts compared SP v3 expression types in camelCase. SP v3 actually
returns uppercase snake_case (ASIN_SAME_AS, QUERY_HIGH_REL_MATCHES, ...).
"""
from __future__ import annotations

SP_V3_EXPRESSION_TYPES: tuple[str, ...] = (
    "ASIN_SAME_AS",
    "QUERY_HIGH_REL_MATCHES",
    "QUERY_BROAD_REL_MATCHES",
    "ASIN_ACCESSORY_RELATED",
    "ASIN_SUBSTITUTE_RELATED",
)


def _key(value: str) -> str:
    return value.upper().replace("_", "")


_CANONICAL_BY_KEY: dict[str, str] = {_key(t): t for t in SP_V3_EXPRESSION_TYPES}


def normalize_expression_type(value: str) -> str:
    """Return the canonical SCREAMING_SNAKE_CASE form of an SP v3 expression type.

    Accepts the canonical form (ASIN_SAME_AS) or the camelCase alias the docs
    sometimes show (asinSameAs); both collapse to the canonical form. Raises
    KeyError if the value is not a known SP v3 expression type.
    """
    if not isinstance(value, str):
        raise KeyError(value)
    canonical = _CANONICAL_BY_KEY.get(_key(value))
    if canonical is None:
        raise KeyError(value)
    return canonical


def is_expression_type(value: str, target: str) -> bool:
    """Case- and separator-insensitive comparison for SP v3 expression types.

    Returns True when `value` and `target` refer to the same SP v3 expression
    type — accepting either canonical SCREAMING_SNAKE_CASE or camelCase on
    either side. Returns False on any non-string input.
    """
    if not isinstance(value, str) or not isinstance(target, str):
        return False
    return _key(value) == _key(target)
