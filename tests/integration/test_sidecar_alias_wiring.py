"""End-to-end wiring check for the sidecar alias fix.

Constructs the full MCP server and asserts SidecarTransformMiddleware is
installed with the expected tool coverage. Covers the regression class
where the legacy transform path silently no-op'd on current FastMCP.
"""

from __future__ import annotations

import pathlib

import pytest
import pytest_asyncio

pytest.importorskip("fastmcp")


@pytest_asyncio.fixture
async def mcp_server(monkeypatch):
    root = pathlib.Path(__file__).parents[2]
    if not (root / "openapi" / "resources").exists():
        pytest.skip("No openapi/resources present in repo")

    # Mount just the AdsAPIv1All spec so the alias-bearing tool exists.
    monkeypatch.setenv("AMAZON_AD_API_PACKAGES", "AdsAPIv1All")

    from amazon_ads_mcp.server.mcp_server import create_amazon_ads_server

    return await create_amazon_ads_server()


@pytest.mark.asyncio
async def test_sidecar_middleware_is_installed(mcp_server):
    """ServerBuilder must install SidecarTransformMiddleware so the
    reportId alias actually fires. Legacy regression: previous versions
    used server.transform_tool (removed) and silently skipped every rule."""
    from amazon_ads_mcp.server.sidecar_middleware import SidecarTransformMiddleware

    # FastMCP exposes middlewares via the `middleware` attribute (list).
    installed = [
        m for m in getattr(mcp_server, "middleware", [])
        if isinstance(m, SidecarTransformMiddleware)
    ]
    assert installed, (
        "SidecarTransformMiddleware not installed — sidecar arg_aliases "
        "will not fire"
    )
    stats = installed[0].stats()
    assert stats["compiled_transforms"] >= 1
    assert stats["tools_with_transforms"] >= 1


@pytest.mark.asyncio
async def test_retrieve_report_tool_covered_by_middleware(mcp_server):
    """The specific regression target — reportId→reportIds alias — must
    be registered under the real tool name (allv1_AdsApiv1RetrieveReport)."""
    from amazon_ads_mcp.server.sidecar_middleware import SidecarTransformMiddleware

    installed = next(
        (m for m in getattr(mcp_server, "middleware", [])
         if isinstance(m, SidecarTransformMiddleware)),
        None,
    )
    assert installed is not None
    # Access the private map in-test to prove the tool name resolution is
    # correct. If this ever gets refactored, replace with a public helper.
    covered = set(installed._input_transforms.keys())
    assert "allv1_AdsApiv1RetrieveReport" in covered, (
        f"alias-bearing tool missing from middleware coverage. covered={sorted(covered)[:5]}..."
    )


@pytest.mark.asyncio
async def test_alias_rewrite_fires_at_the_wire(mcp_server):
    """End-to-end proof: when a client calls with reportId=..., a
    downstream observer middleware sees reportIds=[...]. Any auth or
    downstream failure short-circuits after this point; we only care
    that the rewrite happened in the middleware chain."""
    from fastmcp import Client
    from fastmcp.server.middleware import Middleware

    observed: dict = {}

    class CapturingMiddleware(Middleware):
        async def on_call_tool(self, context, call_next):
            observed["arguments"] = dict(
                getattr(context.message, "arguments", None) or {}
            )
            observed["tool"] = getattr(context.message, "name", None)
            # Short-circuit before auth so the test doesn't need real creds.
            # Return a minimal successful ToolResult-like object.
            from fastmcp.tools.tool import ToolResult
            from mcp.types import TextContent

            return ToolResult(content=[TextContent(type="text", text="{}")])

    # Install AFTER sidecar so we observe post-rewrite args.
    mcp_server.add_middleware(CapturingMiddleware())

    async with Client(mcp_server) as client:
        try:
            await client.call_tool(
                "allv1_AdsApiv1RetrieveReport",
                {"reportId": "wire-abc-999"},
            )
        except Exception:
            pass  # Downstream failures are expected; we only need the observation.

    assert observed, "capturing middleware was never invoked"
    assert observed["tool"] == "allv1_AdsApiv1RetrieveReport"
    # Canonical form must be populated; arg_aliases is additive (doesn't
    # delete the original singular). That's safe — HTTP clients ignore
    # unknown params — and preserves backward compat with callers that
    # might submit both forms.
    assert observed["arguments"].get("reportIds") == ["wire-abc-999"], (
        f"alias did not fire before downstream middleware saw the call. "
        f"observed={observed}"
    )
