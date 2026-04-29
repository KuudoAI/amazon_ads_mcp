"""B1 + F3: Per-ad-product cap callout in tool descriptions.

These tests pin down the description-injection contract:

- The cap paragraph is appended to every QueryCampaign/QueryTarget-family
  tool so agents see the real per-product caps and the "one ad product
  per call" constraint at ``get_schema``-fetch time, not at call time.
- Non-targeted tools are untouched.
- The rendered table reflects ``_AD_PRODUCT_MAX_RESULTS_CAPS`` exactly —
  drift between renderer and table fails the test (single-source-of-truth
  guarantee for the cap data shared by description, validator, and
  runtime check).
- The rendered text mentions Amazon's upstream ``maxItems: 1`` constraint
  and lists the five allowed ad products (F3 — surface, don't wrap).
"""

from __future__ import annotations

from amazon_ads_mcp.middleware.schema_normalization import (
    _AD_PRODUCT_CAP_TOOL_SUFFIXES,
    _AD_PRODUCT_MAX_RESULTS_CAPS,
    render_ad_product_cap_description,
)
from amazon_ads_mcp.server.ad_product_cap_hints_transform import (
    _CAP_PARAGRAPH_SENTINEL,
    AdProductCapHintsTransform,
)


# ---------------------------------------------------------------------------
# Renderer: pure function, deterministic output
# ---------------------------------------------------------------------------


def test_render_includes_every_capped_product():
    """Every entry in ``_AD_PRODUCT_MAX_RESULTS_CAPS`` must appear in the
    rendered paragraph — drift would silently hide a real cap from agents."""
    text = render_ad_product_cap_description()
    for product, cap in _AD_PRODUCT_MAX_RESULTS_CAPS.items():
        assert f"{product}={cap}" in text, (
            f"renderer dropped {product}={cap}; cap table and renderer "
            "have drifted — they must be single-source-of-truth"
        )


def test_render_documents_max_items_constraint():
    """F3: the upstream ``maxItems: 1`` constraint must be surfaced so
    agents plan one call per product instead of being surprised."""
    text = render_ad_product_cap_description()
    assert "exactly one ad product per call" in text
    assert "maxItems" in text


def test_render_lists_all_five_allowed_ad_products():
    """F3: agents must see the full enumeration so they know which
    targeted calls to issue."""
    text = render_ad_product_cap_description()
    for product in (
        "SPONSORED_PRODUCTS",
        "SPONSORED_BRANDS",
        "SPONSORED_DISPLAY",
        "SPONSORED_TELEVISION",
        "AMAZON_DSP",
    ):
        assert product in text


def test_render_warns_amazon_dsp_cap_unenforced():
    """Honesty principle: AMAZON_DSP cap is unknown — say so."""
    text = render_ad_product_cap_description()
    assert "AMAZON_DSP" in text
    assert "not currently enforced" in text or "not enforced" in text


def test_render_mentions_schema_max_5000():
    """Schema's ``maximum: 5000`` is unchanged — note that it still
    applies as the floor for products without a documented per-product
    cap."""
    text = render_ad_product_cap_description()
    assert "5000" in text


# ---------------------------------------------------------------------------
# Transform: enriches targeted tools, leaves others alone
# ---------------------------------------------------------------------------


class _FakeTool:
    """Minimal stand-in for ``fastmcp.tools.tool.Tool`` for transform tests.

    The real Tool class enforces a Pydantic schema we don't need here;
    only ``name``, ``description``, and ``model_copy`` are exercised.
    """

    def __init__(self, name: str, description: str = "") -> None:
        self.name = name
        self.description = description

    def model_copy(self, *, update: dict) -> "_FakeTool":
        clone = _FakeTool(self.name, self.description)
        for key, value in update.items():
            setattr(clone, key, value)
        return clone


def test_transform_enriches_every_targeted_suffix():
    """Every tool whose name ends in a targeted suffix gets the
    cap paragraph appended."""
    transform = AdProductCapHintsTransform()
    for suffix in _AD_PRODUCT_CAP_TOOL_SUFFIXES:
        tool = _FakeTool(f"allv1_{suffix}", description="Original description.")
        enriched = transform._maybe_enrich(tool)
        assert _CAP_PARAGRAPH_SENTINEL in enriched.description
        assert enriched.description.startswith("Original description.")


def test_transform_skips_non_targeted_tools():
    """Tools that don't end in a targeted suffix must pass through
    unchanged — no description churn for unrelated tools."""
    transform = AdProductCapHintsTransform()
    untouched = _FakeTool("set_active_profile", description="Profile setter.")
    enriched = transform._maybe_enrich(untouched)
    # Identity, not a copy: the untargeted path returns the tool as-is.
    assert enriched is untouched
    assert _CAP_PARAGRAPH_SENTINEL not in enriched.description


def test_transform_is_idempotent():
    """Applying the transform twice must NOT duplicate the paragraph
    (defends against re-mount / repeated-transform scenarios)."""
    transform = AdProductCapHintsTransform()
    tool = _FakeTool("allv1_QueryCampaign", description="Query campaigns.")
    once = transform._maybe_enrich(tool)
    twice = transform._maybe_enrich(once)
    assert once.description.count(_CAP_PARAGRAPH_SENTINEL) == 1
    assert twice.description.count(_CAP_PARAGRAPH_SENTINEL) == 1


def test_transform_handles_none_description():
    """Some tools may have ``description=None`` (FastMCP allows it).
    The transform must not crash and must still append the paragraph."""
    transform = AdProductCapHintsTransform()
    tool = _FakeTool("allv1_QueryTarget")
    tool.description = None  # type: ignore[assignment]
    enriched = transform._maybe_enrich(tool)
    assert _CAP_PARAGRAPH_SENTINEL in enriched.description
