"""Round 13 A-10 — polling-guidance single-source-of-truth tests.

Two tool descriptions previously carried hand-copied polling guidance
that drifted over time. These tests pin the contract:

  1. The canonical constants live in ``server._polling_guidance``.
  2. ``code_mode.EXECUTE_DESCRIPTION`` embeds
     ``SANDBOX_POLLING_GUIDANCE`` verbatim.
  3. The retrieve-report hint embeds
     ``RETRIEVE_TOOL_POLLING_GUIDANCE`` verbatim.

A contributor adding a third copy or rewording one site without
updating the constant fails these tests.
"""

from __future__ import annotations


def test_polling_guidance_module_exposes_both_constants() -> None:
    from amazon_ads_mcp.server import _polling_guidance

    assert isinstance(
        _polling_guidance.SANDBOX_POLLING_GUIDANCE, str
    ) and _polling_guidance.SANDBOX_POLLING_GUIDANCE.strip()
    assert isinstance(
        _polling_guidance.RETRIEVE_TOOL_POLLING_GUIDANCE, str
    ) and _polling_guidance.RETRIEVE_TOOL_POLLING_GUIDANCE.strip()


def test_execute_description_embeds_sandbox_guidance_verbatim() -> None:
    """``code_mode.EXECUTE_DESCRIPTION`` must contain the canonical
    sandbox-polling string. No drift, no rewording, no copy-paste."""
    from amazon_ads_mcp.server.code_mode import EXECUTE_DESCRIPTION
    from amazon_ads_mcp.server._polling_guidance import (
        SANDBOX_POLLING_GUIDANCE,
    )

    assert SANDBOX_POLLING_GUIDANCE in EXECUTE_DESCRIPTION, (
        "EXECUTE_DESCRIPTION must embed SANDBOX_POLLING_GUIDANCE verbatim. "
        "Do not duplicate the text inline; import and substitute."
    )


def test_retrieve_report_hint_embeds_retrieve_guidance_verbatim() -> None:
    """The ``AdsApiv1RetrieveReport`` hint must contain the canonical
    retrieve-tool polling string."""
    from amazon_ads_mcp.server.async_hints_transform import (
        ASYNC_OPERATION_HINTS,
    )
    from amazon_ads_mcp.server._polling_guidance import (
        RETRIEVE_TOOL_POLLING_GUIDANCE,
    )

    hint_text, _next = ASYNC_OPERATION_HINTS["AdsApiv1RetrieveReport"]
    assert RETRIEVE_TOOL_POLLING_GUIDANCE in hint_text, (
        "AdsApiv1RetrieveReport hint must embed "
        "RETRIEVE_TOOL_POLLING_GUIDANCE verbatim. Do not duplicate."
    )


def test_no_legacy_polling_phrases_outside_canonical_constants() -> None:
    """Catch a contributor who copy-pastes legacy phrasing into a third
    location instead of importing the constant. Scans the server package
    for the old standalone phrasings; fails if found anywhere except in
    ``_polling_guidance.py``."""
    import pathlib

    from amazon_ads_mcp.server import _polling_guidance

    server_pkg = pathlib.Path(_polling_guidance.__file__).parent
    canonical = pathlib.Path(_polling_guidance.__file__)

    # Legacy substrings that must only appear inside the canonical
    # module (and tests). Each was a hand-written variant before
    # consolidation.
    legacy_fragments = [
        "Don't sleep — chain `await call_tool`",
        "suggest checking back shortly rather than polling in a loop",
    ]

    offenders: list[tuple[str, str]] = []
    for path in server_pkg.rglob("*.py"):
        if path == canonical:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except Exception:
            continue
        for frag in legacy_fragments:
            # Allowed: the file imports & embeds the canonical constant.
            # That's verified by the verbatim-embed tests above. What we
            # forbid is a NAKED literal — i.e. the fragment appears in
            # source but the canonical constant is NOT also referenced.
            if frag in text:
                refs_canonical = (
                    "_polling_guidance" in text
                    or "SANDBOX_POLLING_GUIDANCE" in text
                    or "RETRIEVE_TOOL_POLLING_GUIDANCE" in text
                )
                if not refs_canonical:
                    offenders.append((str(path), frag))

    assert not offenders, (
        f"Legacy polling-guidance phrasing duplicated in {offenders}. "
        f"Import from amazon_ads_mcp.server._polling_guidance instead."
    )
