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
