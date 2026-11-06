"""Unit tests for MCP server OpenAPI slimming utilities."""

import json
from collections.abc import AsyncIterator
from typing import Any

import httpx
import pytest
import pytest_asyncio
from fastmcp import Client, FastMCP

from amazon_ads_mcp.middleware.schema_validation import SchemaValidationMiddleware
from amazon_ads_mcp.server.openapi_utils import (
    _flatten_large_schemas,
    _truncate_enums,
    slim_openapi_for_tools,
)


def test_truncate_enums_drops_enforced_enum_but_keeps_type():
    """A large enum must not be left as a *truncated* enforced constraint —
    the pre-flight validator would reject valid values in the dropped middle
    (e.g. targetType="KEYWORD"). The enum is removed (type kept) and a sample
    recorded in the description."""
    vals = [f"V{i}" for i in range(27)]
    assert "V13" in vals  # a middle value that truncation would drop
    spec = {
        "components": {
            "schemas": {
                "BigEnum": {"type": "string", "enum": list(vals)},
                "SmallEnum": {"type": "string", "enum": ["A", "B", "C"]},
            }
        }
    }

    n = _truncate_enums(spec)
    assert n == 1

    big = spec["components"]["schemas"]["BigEnum"]
    assert "enum" not in big  # not enforced any more
    assert big["type"] == "string"  # type still validates
    assert "27 values total" in big["description"]

    # Small enums are left fully intact and still enforceable.
    small = spec["components"]["schemas"]["SmallEnum"]
    assert small["enum"] == ["A", "B", "C"]


def _large_filler(prefix: str, n: int) -> dict:
    """Build enough string props to push a schema over the flatten threshold."""
    return {
        f"{prefix}{i}": {
            "type": "string",
            "description": "x" * 60,
        }
        for i in range(n)
    }


@pytest_asyncio.fixture
async def slimmed_campaign_client(
    monkeypatch: pytest.MonkeyPatch,
) -> AsyncIterator[tuple[Client, list[dict[str, Any]]]]:
    """Exercise the mounting, MCP validation, and mocked HTTP request path."""
    monkeypatch.setenv("SLIM_OPENAPI_AGGRESSIVE", "true")
    requests: list[dict[str, Any]] = []

    def handle_request(request: httpx.Request) -> httpx.Response:
        requests.append(json.loads(request.content))
        return httpx.Response(200, json={"campaignId": "test-campaign"})

    spec = {
        "openapi": "3.0.3",
        "info": {"title": "Campaign regression", "version": "1.0"},
        "paths": {
            "/campaigns": {
                "post": {
                    "operationId": "CreateCampaign",
                    "requestBody": {
                        "required": True,
                        "content": {
                            "application/json": {
                                "schema": {
                                    "$ref": "#/components/schemas/CampaignCreate"
                                }
                            }
                        },
                    },
                    "responses": {"200": {"description": "Created"}},
                }
            }
        },
        "components": {
            "schemas": {
                "AdProduct": {
                    "type": "string",
                    "enum": ["SPONSORED_PRODUCTS", "SPONSORED_BRANDS"],
                },
                "CreateState": {"type": "string", "enum": ["ENABLED", "PAUSED"]},
                "MarketplaceScope": {
                    "type": "string",
                    "enum": ["GLOBAL", "SINGLE_MARKETPLACE"],
                },
                "TargetType": {
                    "type": "string",
                    "enum": [f"TYPE_{i}" for i in range(13)]
                    + ["KEYWORD"]
                    + [f"TYPE_{i}" for i in range(14, 27)],
                },
                "CampaignCreate": {
                    "type": "object",
                    "required": ["adProduct", "state", "marketplaceScope", "targetType"],
                    "properties": {
                        "adProduct": {"$ref": "#/components/schemas/AdProduct"},
                        "state": {"$ref": "#/components/schemas/CreateState"},
                        "marketplaceScope": {
                            "$ref": "#/components/schemas/MarketplaceScope"
                        },
                        "targetType": {"$ref": "#/components/schemas/TargetType"},
                        **_large_filler("pad", 40),
                    },
                },
            }
        },
    }
    slim_openapi_for_tools(spec)
    async with httpx.AsyncClient(
        base_url="https://ads.example.test",
        transport=httpx.MockTransport(handle_request),
    ) as http_client:
        server = FastMCP.from_openapi(openapi_spec=spec, client=http_client)
        server.add_middleware(SchemaValidationMiddleware())
        async with Client(server) as client:
            yield client, requests


@pytest.mark.asyncio
async def test_slimmed_campaign_accepts_scalar_refs_and_middle_enum_value(
    slimmed_campaign_client: tuple[Client, list[dict[str, Any]]],
) -> None:
    """Valid scalar values survive every slimming phase and reach the API."""
    client, requests = slimmed_campaign_client
    payload = {
        "adProduct": "SPONSORED_PRODUCTS",
        "state": "PAUSED",
        "marketplaceScope": "SINGLE_MARKETPLACE",
        "targetType": "KEYWORD",
    }
    result = await client.call_tool("CreateCampaign", payload)
    assert not result.is_error
    assert requests == [payload]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("adProduct", {}),
        ("state", {}),
        ("marketplaceScope", {}),
        ("adProduct", "UNKNOWN_PRODUCT"),
        ("state", "UNKNOWN_STATE"),
        ("marketplaceScope", "UNKNOWN_SCOPE"),
        ("targetType", 123),
    ],
)
async def test_slimmed_campaign_rejects_invalid_values_before_http(
    slimmed_campaign_client: tuple[Client, list[dict[str, Any]]],
    field: str,
    value: Any,
) -> None:
    """Preserved scalar types and small enums still reject invalid input."""
    client, requests = slimmed_campaign_client
    payload = {
        "adProduct": "SPONSORED_PRODUCTS",
        "state": "PAUSED",
        "marketplaceScope": "SINGLE_MARKETPLACE",
        "targetType": "KEYWORD",
    }
    result = await client.call_tool(
        "CreateCampaign", {**payload, field: value}, raise_on_error=False
    )
    assert result.is_error
    message = result.content[0].text
    assert "not one of" in message or "not of type" in message
    assert requests == []


def test_flatten_large_schema_preserves_scalar_ref_type_and_enum():
    """A $ref to a scalar enum must keep its scalar type + enum when its
    parent schema is flattened — not be mislabeled ``object`` (which would
    make constraint validation reject the correct scalar value)."""
    spec = {
        "components": {
            "schemas": {
                "AdProduct": {
                    "type": "string",
                    "enum": ["SPONSORED_PRODUCTS", "SPONSORED_BRANDS"],
                },
                "SettingsBlob": {  # object ref -> should stay object
                    "type": "object",
                    "properties": {"a": {"type": "string"}},
                },
                "CampaignCreate": {
                    "type": "object",
                    "required": ["adProduct"],
                    "properties": {
                        "adProduct": {"$ref": "#/components/schemas/AdProduct"},
                        "settings": {"$ref": "#/components/schemas/SettingsBlob"},
                        **_large_filler("pad", 40),
                    },
                },
            }
        }
    }

    flattened = _flatten_large_schemas(spec)
    assert flattened >= 1

    props = spec["components"]["schemas"]["CampaignCreate"]["properties"]
    # Scalar enum ref keeps its real type and (small) enum.
    assert props["adProduct"]["type"] == "string"
    assert props["adProduct"]["enum"] == [
        "SPONSORED_PRODUCTS",
        "SPONSORED_BRANDS",
    ]
    # Object ref still collapses to object.
    assert props["settings"]["type"] == "object"


def test_flatten_large_schema_keeps_scalar_ref_format():
    """A $ref to a scalar with a ``format`` (e.g. date-time) keeps type +
    format when flattened."""
    spec = {
        "components": {
            "schemas": {
                "Timestamp": {"type": "string", "format": "date-time"},
                "Big": {
                    "type": "object",
                    "properties": {
                        "when": {"$ref": "#/components/schemas/Timestamp"},
                        **_large_filler("pad", 40),
                    },
                },
            }
        }
    }

    _flatten_large_schemas(spec)
    when = spec["components"]["schemas"]["Big"]["properties"]["when"]
    assert when["type"] == "string"
    assert when["format"] == "date-time"


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


# ---------------------------------------------------------------------------
# Phase 2 tests
# ---------------------------------------------------------------------------


def test_slim_openapi_strips_response_bodies(monkeypatch):
    """Phase 2: responses removed from operations, params preserved."""
    monkeypatch.setenv("SLIM_OPENAPI_STRIP_RESPONSES", "true")

    spec = {
        "openapi": "3.0.0",
        "paths": {
            "/v2/campaigns": {
                "get": {
                    "parameters": [
                        {"in": "query", "name": "status", "schema": {"type": "string"}}
                    ],
                    "responses": {
                        "200": {
                            "description": "OK",
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": "#/components/schemas/CampaignList"}
                                }
                            },
                        }
                    },
                }
            }
        },
        "components": {
            "schemas": {
                "CampaignList": {
                    "type": "object",
                    "properties": {"items": {"type": "array"}},
                }
            },
            "responses": {
                "NotFound": {"description": "Not found"},
            },
        },
    }

    slim_openapi_for_tools(spec)

    op = spec["paths"]["/v2/campaigns"]["get"]
    # Responses still present (required by OpenAPI 3.0) but content stripped
    assert "responses" in op
    resp_200 = op["responses"]["200"]
    assert resp_200 == {"description": "OK"}  # only description remains
    assert "content" not in resp_200
    # Parameters preserved
    assert len(op["parameters"]) == 1
    assert op["parameters"][0]["name"] == "status"
    # Component responses removed
    assert "responses" not in spec["components"]


# ---------------------------------------------------------------------------
# Phase 3 tests
# ---------------------------------------------------------------------------


def test_slim_openapi_preserves_request_schemas(monkeypatch):
    """Phase 3: request schemas kept, response-only schemas removed."""
    monkeypatch.setenv("SLIM_OPENAPI_STRIP_RESPONSES", "true")
    monkeypatch.setenv("SLIM_OPENAPI_AGGRESSIVE", "true")

    spec = {
        "openapi": "3.0.0",
        "paths": {
            "/v2/campaigns": {
                "post": {
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/CreateCampaign"}
                            }
                        }
                    },
                    "responses": {
                        "200": {
                            "description": "OK",
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": "#/components/schemas/CampaignResponse"}
                                }
                            },
                        }
                    },
                }
            }
        },
        "components": {
            "schemas": {
                "CreateCampaign": {
                    "type": "object",
                    "properties": {
                        "name": {"type": "string"},
                        "budget": {"type": "number"},
                    },
                },
                "CampaignResponse": {
                    "type": "object",
                    "properties": {
                        "id": {"type": "string"},
                        "status": {"type": "string"},
                    },
                },
                "OrphanedSchema": {
                    "type": "object",
                    "description": "Not referenced anywhere",
                },
            }
        },
    }

    slim_openapi_for_tools(spec)

    schemas = spec["components"]["schemas"]
    # Request schema preserved
    assert "CreateCampaign" in schemas
    assert schemas["CreateCampaign"]["properties"]["name"]["type"] == "string"
    # Response-only schema removed (responses stripped, so ref is gone)
    assert "CampaignResponse" not in schemas
    # Unreferenced schema removed
    assert "OrphanedSchema" not in schemas


# ---------------------------------------------------------------------------
# Phase 4 tests
# ---------------------------------------------------------------------------


def test_slim_openapi_cleans_schema_metadata(monkeypatch):
    """Phase 4: title/xml/deprecated/example removed, type/properties kept."""
    monkeypatch.setenv("SLIM_OPENAPI_AGGRESSIVE", "true")

    spec = {
        "openapi": "3.0.0",
        "paths": {
            "/v2/items": {
                "post": {
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/Item"}
                            }
                        }
                    },
                }
            }
        },
        "components": {
            "schemas": {
                "Item": {
                    "type": "object",
                    "title": "ItemModel",
                    "xml": {"name": "item"},
                    "deprecated": True,
                    "example": {"name": "Widget"},
                    "externalDocs": {"url": "https://example.com"},
                    "properties": {
                        "name": {
                            "type": "string",
                            "title": "ItemName",
                            "example": "Widget",
                            "examples": ["A", "B"],
                        },
                        "price": {"type": "number", "format": "double"},
                    },
                }
            }
        },
    }

    slim_openapi_for_tools(spec)

    schema = spec["components"]["schemas"]["Item"]
    # Noise fields removed
    assert "title" not in schema
    assert "xml" not in schema
    assert "deprecated" not in schema
    assert "example" not in schema
    assert "externalDocs" not in schema
    # Structure preserved
    assert schema["type"] == "object"
    assert "name" in schema["properties"]
    assert schema["properties"]["name"]["type"] == "string"
    assert "title" not in schema["properties"]["name"]
    assert "example" not in schema["properties"]["name"]
    assert "examples" not in schema["properties"]["name"]
    assert schema["properties"]["price"]["format"] == "double"


def test_slim_openapi_dead_schema_keeps_transitive_refs(monkeypatch):
    """Phase 3: A -> B -> C chain; all kept when A is in a requestBody."""
    monkeypatch.setenv("SLIM_OPENAPI_STRIP_RESPONSES", "true")
    monkeypatch.setenv("SLIM_OPENAPI_AGGRESSIVE", "true")

    spec = {
        "openapi": "3.0.0",
        "paths": {
            "/v2/orders": {
                "post": {
                    "requestBody": {
                        "content": {
                            "application/json": {
                                "schema": {"$ref": "#/components/schemas/Order"}
                            }
                        }
                    },
                    "responses": {
                        "200": {
                            "description": "OK",
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": "#/components/schemas/OrderResponse"}
                                }
                            },
                        }
                    },
                }
            }
        },
        "components": {
            "schemas": {
                "Order": {
                    "type": "object",
                    "properties": {
                        "items": {
                            "type": "array",
                            "items": {"$ref": "#/components/schemas/LineItem"},
                        }
                    },
                },
                "LineItem": {
                    "type": "object",
                    "properties": {
                        "product": {"$ref": "#/components/schemas/Product"},
                        "quantity": {"type": "integer"},
                    },
                },
                "Product": {
                    "type": "object",
                    "properties": {
                        "sku": {"type": "string"},
                        "name": {"type": "string"},
                    },
                },
                "OrderResponse": {
                    "type": "object",
                    "properties": {"id": {"type": "string"}},
                },
                "Dangling": {
                    "type": "object",
                    "description": "No one references this",
                },
            }
        },
    }

    slim_openapi_for_tools(spec)

    schemas = spec["components"]["schemas"]
    # Transitive chain kept: Order -> LineItem -> Product
    assert "Order" in schemas
    assert "LineItem" in schemas
    assert "Product" in schemas
    # Response-only removed (responses stripped first)
    assert "OrderResponse" not in schemas
    # Unreferenced removed
    assert "Dangling" not in schemas
