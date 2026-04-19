"""Pins the sandbox-path alias rewrite (Issue 6 real-deployment fix).

The Code Mode sandboxed ``await call_tool(name, params)`` dispatches via
``external_functions`` injected by ``MontySandboxProvider`` — it bypasses
the server's middleware chain. Agents using ``amazon_ads:execute`` would
have still seen the reportId 400 even with the middleware installed.

``apply_sidecar_input_transforms`` is a module-level accessor over the
same compiled-transforms map the middleware uses. The auth-bridging
wrapper calls it so both call surfaces share a single rewrite path.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from amazon_ads_mcp.server.sidecar_middleware import (
    SidecarTransformMiddleware,
    apply_sidecar_input_transforms,
    set_active_middleware,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
RESOURCES_DIR = REPO_ROOT / "openapi" / "resources"


@pytest.fixture(autouse=True)
def _reset_singleton():
    """Always return to an un-installed state so tests don't leak."""
    set_active_middleware(None)
    yield
    set_active_middleware(None)


@pytest.mark.asyncio
async def test_no_middleware_installed_returns_args_unchanged():
    result = await apply_sidecar_input_transforms(
        "allv1_AdsApiv1RetrieveReport",
        {"reportId": "abc"},
    )
    assert result == {"reportId": "abc"}


@pytest.mark.asyncio
async def test_installed_middleware_rewrites_alias_for_sandbox_path():
    middleware = SidecarTransformMiddleware(RESOURCES_DIR)
    set_active_middleware(middleware)

    result = await apply_sidecar_input_transforms(
        "allv1_AdsApiv1RetrieveReport",
        {"reportId": "sandbox-abc"},
    )
    # The canonical plural form must be populated so Amazon accepts the
    # request. The alias doesn't delete the singular key (the executor's
    # arg_aliases logic is additive); downstream HTTP clients ignore
    # unknown params — which is the safe behavior.
    assert result.get("reportIds") == ["sandbox-abc"]


@pytest.mark.asyncio
async def test_unknown_tool_name_passes_through_unmodified():
    middleware = SidecarTransformMiddleware(RESOURCES_DIR)
    set_active_middleware(middleware)

    payload = {"irrelevant": "data"}
    result = await apply_sidecar_input_transforms("nonexistent_tool", payload)
    assert result == payload


@pytest.mark.asyncio
async def test_middleware_rewrite_args_helper_is_symmetric():
    """The standalone helper and the middleware method must agree — both
    surfaces must rewrite identically."""
    middleware = SidecarTransformMiddleware(RESOURCES_DIR)
    set_active_middleware(middleware)

    via_helper = await apply_sidecar_input_transforms(
        "allv1_AdsApiv1RetrieveReport", {"reportId": "x"}
    )
    via_method = await middleware.rewrite_args(
        "allv1_AdsApiv1RetrieveReport", {"reportId": "x"}
    )
    # Symmetric output is the real invariant; exact shape is covered above.
    assert via_helper == via_method
    assert via_helper.get("reportIds") == ["x"]
