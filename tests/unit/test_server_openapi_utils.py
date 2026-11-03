"""Unit tests for MCP server OpenAPI slimming utilities."""

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
