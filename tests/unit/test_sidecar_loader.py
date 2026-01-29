import json

import pytest

from amazon_ads_mcp.server import sidecar_loader


def test_resolve_tool_name_with_method_path():
    tools = {"GET_v2_items": object()}
    name = sidecar_loader.resolve_tool_name(
        {"method": "get", "path": "/v2/items"},
        {"tools": []},
        tools,
    )
    assert name == "GET_v2_items"


def test_resolve_tool_name_with_preferred_name():
    tools = {"custom_name": object()}
    manifest = {"tools": [{"operationId": "listItems", "preferred_name": "custom_name"}]}
    name = sidecar_loader.resolve_tool_name(
        {"operationId": "listItems"},
        manifest,
        tools,
    )
    assert name == "custom_name"


def test_resolve_tool_name_with_prefix_match():
    tools = {"sp_listItems": object()}
    manifest = {"tools": [{"operationId": "listItems"}]}
    name = sidecar_loader.resolve_tool_name(
        {"operationId": "listItems"},
        manifest,
        tools,
    )
    assert name == "sp_listItems"


@pytest.mark.asyncio
async def test_apply_sidecars_no_files(tmp_path):
    spec_path = tmp_path / "Spec.json"
    spec_path.write_text("{}")

    server = object()
    await sidecar_loader.apply_sidecars(server, spec_path)


@pytest.mark.asyncio
async def test_apply_sidecars_attaches_transforms(tmp_path):
    spec_path = tmp_path / "Spec.json"
    spec_path.write_text("{}")

    manifest_path = spec_path.with_suffix(".manifest.json")
    transform_path = spec_path.with_suffix(".transform.json")

    manifest_path.write_text(
        json.dumps(
            {
                "namespace": "Spec",
                "tools": [
                    {"operationId": "listItems", "preferred_name": "list_items"}
                ],
            }
        )
    )
    transform_path.write_text(
        json.dumps(
            {
                "version": "1.0",
                "tools": [
                    {
                        "match": {"operationId": "listItems"},
                        "output_transform": {"projection": ["items"]},
                        "args": {"expose": {"foo": True}},
                    }
                ],
            }
        )
    )

    calls = []

    class FakeServer:
        def get_tools(self):
            return {"list_items": object()}

        def transform_tool(self, name, **kwargs):
            calls.append({"name": name, "kwargs": kwargs})

    await sidecar_loader.apply_sidecars(FakeServer(), spec_path)

    assert calls
    assert calls[0]["name"] == "list_items"
    assert "output_transform" in calls[0]["kwargs"]
    assert calls[0]["kwargs"]["arg_schema"] == {"foo": True}
