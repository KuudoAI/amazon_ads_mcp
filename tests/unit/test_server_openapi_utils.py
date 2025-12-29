"""Unit tests for MCP server OpenAPI slimming utilities."""

from amazon_ads_mcp.server.openapi_utils import slim_openapi_for_tools


def test_slim_openapi_for_tools_removes_auth_header_params():
    spec = {
        "openapi": "3.0.0",
        "paths": {
            "/v2/test": {
                "get": {
                    "parameters": [
                        {
                            "in": "header",
                            "name": "Amazon-Advertising-API-ClientId",
                            "schema": {"type": "string"},
                        },
                        {"$ref": "#/components/parameters/ProfileScope"},
                        {
                            "in": "header",
                            "name": "X-Custom-Header",
                            "schema": {"type": "string"},
                        },
                    ]
                }
            }
        },
        "components": {
            "parameters": {
                "ProfileScope": {
                    "in": "header",
                    "name": "Amazon-Advertising-API-Scope",
                    "schema": {"type": "string"},
                }
            }
        },
    }

    slim_openapi_for_tools(spec)

    params = spec["paths"]["/v2/test"]["get"]["parameters"]
    assert {"$ref": "#/components/parameters/ProfileScope"} not in params
    assert not any(
        p.get("name") == "Amazon-Advertising-API-ClientId" for p in params if isinstance(p, dict)
    )
    assert any(
        p.get("name") == "X-Custom-Header" for p in params if isinstance(p, dict)
    )

    # Component parameter gets removed to avoid surfacing it in tool schemas.
    assert "ProfileScope" not in spec["components"]["parameters"]

