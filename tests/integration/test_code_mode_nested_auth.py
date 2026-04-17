"""Integration tests for nested code-mode auth session behavior."""

import json

import pytest
import pytest_asyncio

pytest.importorskip("fastmcp")


class ScriptedSandbox:
    """Simple test sandbox that executes JSON-encoded tool operations."""

    async def run(self, code, *, external_functions=None, inputs=None):
        del inputs
        payload = json.loads(code)
        call_tool = external_functions["call_tool"]
        result = None
        for op in payload.get("ops", []):
            result = await call_tool(op["tool"], op.get("params", {}))
        return result


def _extract_text_payload(call_result):
    assert call_result.content, "Expected call result content"
    content = call_result.content[0]
    return json.loads(content.text) if hasattr(content, "text") else content


@pytest_asyncio.fixture
async def code_mode_server():
    from fastmcp import FastMCP

    from amazon_ads_mcp.auth.session_state import (
        get_active_identity,
        reset_all_session_state,
        set_active_identity as set_active_identity_ctx,
    )
    from amazon_ads_mcp.middleware.authentication import AuthSessionStateMiddleware
    from amazon_ads_mcp.models import Identity
    from amazon_ads_mcp.server.code_mode import (
        create_auth_bridging_sandbox_provider,
    )
    from fastmcp.experimental.transforms import code_mode as fm_code_mode

    reset_all_session_state()
    server = FastMCP(name="code-mode-auth-test")
    server.middleware.append(AuthSessionStateMiddleware())

    @server.tool
    async def set_active_identity(identity_id: str) -> dict:
        set_active_identity_ctx(Identity(id=identity_id, type="openbridge", attributes={}))
        return {"identity_id": identity_id}

    @server.tool
    async def page_profiles() -> dict:
        identity = get_active_identity()
        if not identity:
            raise RuntimeError("No active identity set. Use set_active_identity() first.")
        return {"identity_id": identity.id}

    transform = fm_code_mode.CodeMode(
        sandbox_provider=create_auth_bridging_sandbox_provider(ScriptedSandbox()),
        discovery_tools=[],
    )
    server.add_transform(transform)
    return server


@pytest.mark.asyncio
async def test_execute_persists_identity_across_calls(code_mode_server):
    from fastmcp import Client

    async with Client(code_mode_server) as client:
        set_result = await client.call_tool(
            "execute",
            {
                "code": json.dumps(
                    {
                        "ops": [
                            {
                                "tool": "set_active_identity",
                                "params": {"identity_id": "session-a"},
                            }
                        ]
                    }
                )
            },
        )
        set_payload = _extract_text_payload(set_result)
        assert set_payload["identity_id"] == "session-a"

        page_result = await client.call_tool(
            "execute",
            {"code": json.dumps({"ops": [{"tool": "page_profiles", "params": {}}]})},
        )
        page_payload = _extract_text_payload(page_result)
        assert page_payload["identity_id"] == "session-a"


@pytest.mark.asyncio
async def test_execute_intra_script_mutation_round_trip(code_mode_server):
    from fastmcp import Client

    async with Client(code_mode_server) as client:
        result = await client.call_tool(
            "execute",
            {
                "code": json.dumps(
                    {
                        "ops": [
                            {
                                "tool": "set_active_identity",
                                "params": {"identity_id": "mutated-id"},
                            },
                            {"tool": "page_profiles", "params": {}},
                        ]
                    }
                )
            },
        )
        payload = _extract_text_payload(result)
        assert payload["identity_id"] == "mutated-id"


@pytest.mark.asyncio
async def test_execute_session_isolation_under_concurrency(code_mode_server):
    import asyncio

    from fastmcp import Client

    async def run_session(identity_id: str) -> str:
        async with Client(code_mode_server) as client:
            await client.call_tool(
                "execute",
                {
                    "code": json.dumps(
                        {
                            "ops": [
                                {
                                    "tool": "set_active_identity",
                                    "params": {"identity_id": identity_id},
                                }
                            ]
                        }
                    )
                },
            )
            page_result = await client.call_tool(
                "execute",
                {"code": json.dumps({"ops": [{"tool": "page_profiles", "params": {}}]})},
            )
            return _extract_text_payload(page_result)["identity_id"]

    id_a, id_b = await asyncio.gather(
        run_session("client-a"),
        run_session("client-b"),
    )
    assert id_a == "client-a"
    assert id_b == "client-b"
