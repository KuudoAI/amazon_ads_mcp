"""Coverage-pushing tests for ``utils.response_wrapper`` and
``utils.http.request``.

Round-13 coverage report had:
- ``response_wrapper`` at 51% (35 of 71 statements uncovered)
- ``http/request`` at 48% (25 of 48 statements uncovered)

Both modules are thin httpx wrappers — easy to exercise with real
``httpx.Response`` objects (no network).
"""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, patch

import httpx
import pytest

from amazon_ads_mcp.utils.http.request import HTTPResponse, make_request
from amazon_ads_mcp.utils.response_wrapper import (
    ResponseWrapper,
    shape_amc_response,
    wrap_response,
)


# --- ResponseWrapper -----------------------------------------------------


def _make_response(
    *, status: int = 200, body: bytes = b'{"ok":true}',
    content_type: str = "application/json",
) -> httpx.Response:
    """Build a real httpx.Response with a request attached.

    The request is required for ``raise_for_status`` and for any code path
    that builds a *new* response from this one (e.g., shape_amc_response).
    """
    return httpx.Response(
        status_code=status,
        headers={"content-type": content_type},
        content=body,
        request=httpx.Request("GET", "https://test.example.com/x"),
    )


class TestResponseWrapper:
    def test_status_code_passes_through(self) -> None:
        r = _make_response(status=204)
        assert ResponseWrapper(r).status_code == 204

    def test_headers_pass_through(self) -> None:
        r = _make_response()
        assert ResponseWrapper(r).headers["content-type"] == "application/json"

    def test_content_returns_original_when_unmodified(self) -> None:
        r = _make_response(body=b'{"k":"v"}')
        assert ResponseWrapper(r).content == b'{"k":"v"}'

    def test_json_returns_original_when_unmodified(self) -> None:
        r = _make_response(body=b'{"k":"v"}')
        assert ResponseWrapper(r).json() == {"k": "v"}

    def test_set_content_overrides_content(self) -> None:
        wr = ResponseWrapper(_make_response(body=b'{"k":1}'))
        wr.set_content(b'{"new":"data"}')
        assert wr.content == b'{"new":"data"}'

    def test_set_content_clears_json_cache(self) -> None:
        wr = ResponseWrapper(_make_response())
        wr.set_json({"first": 1})
        # Now overwrite via raw bytes — cached _modified_json should clear
        wr.set_content(b'{"second":2}')
        assert wr.json() == {"second": 2}

    def test_set_json_overrides_both_content_and_json(self) -> None:
        wr = ResponseWrapper(_make_response())
        wr.set_json({"new": [1, 2]})
        assert wr.json() == {"new": [1, 2]}
        assert json.loads(wr.content) == {"new": [1, 2]}

    def test_modify_json_with_modifier_function(self) -> None:
        wr = ResponseWrapper(_make_response(body=b'{"count":1}'))
        wr.modify_json(lambda d: {**d, "count": d["count"] + 1})
        assert wr.json() == {"count": 2}

    def test_modify_json_chains_self(self) -> None:
        wr = ResponseWrapper(_make_response(body=b'{"a":1}'))
        result = wr.modify_json(lambda d: d).modify_json(lambda d: d)
        assert result is wr

    def test_modify_json_swallows_modifier_errors(self) -> None:
        """Modifier raises → wrapper logs and returns self unchanged.

        This is the failure-soft contract: a buggy modifier on one
        response shouldn't break an entire stream of responses."""
        wr = ResponseWrapper(_make_response(body=b'{"k":"v"}'))
        wr.modify_json(lambda _: 1 / 0)  # ZeroDivisionError
        # Original content preserved
        assert wr.json() == {"k": "v"}


# --- wrap_response factory -----------------------------------------------


class TestWrapResponse:
    def test_returns_response_wrapper(self) -> None:
        wr = wrap_response(_make_response())
        assert isinstance(wr, ResponseWrapper)


# --- shape_amc_response --------------------------------------------------


class TestShapeAmcResponse:
    def test_non_200_passes_through_unchanged(self) -> None:
        r = _make_response(status=404, body=b'{"data":[{"x":1}]}')
        out = shape_amc_response(r)
        assert out is r

    def test_non_json_passes_through_unchanged(self) -> None:
        r = _make_response(content_type="text/csv", body=b"a,b,c")
        out = shape_amc_response(r)
        assert out is r

    def test_invalid_json_passes_through_unchanged(self) -> None:
        r = _make_response(body=b"not json")
        out = shape_amc_response(r)
        assert out is r

    def test_unwraps_single_element_data_list(self) -> None:
        r = _make_response(body=b'{"data":[{"campaignId":"123"}]}')
        out = shape_amc_response(r)
        # Returns a NEW response with unwrapped body
        assert out is not r
        assert json.loads(out.content) == {"campaignId": "123"}

    def test_does_not_unwrap_multi_element_data_list(self) -> None:
        body = b'{"data":[{"a":1},{"b":2}]}'
        r = _make_response(body=body)
        out = shape_amc_response(r)
        # Multi-element list: pass through unchanged
        assert out is r

    def test_does_not_unwrap_when_no_data_key(self) -> None:
        r = _make_response(body=b'{"foo":"bar"}')
        out = shape_amc_response(r)
        assert out is r

    def test_content_length_updated_on_unwrap(self) -> None:
        original = b'{"data":[{"campaignId":"123","name":"summer"}]}'
        r = _make_response(body=original)
        out = shape_amc_response(r)
        assert out.headers["content-length"] == str(len(out.content))
        # New content is shorter than original (unwrapped data)
        assert int(out.headers["content-length"]) < len(original)


# --- HTTPResponse --------------------------------------------------------


class TestHTTPResponseWrapper:
    def test_status_code_passes_through(self) -> None:
        r = _make_response(status=201)
        assert HTTPResponse(r).status_code == 201

    def test_headers_pass_through(self) -> None:
        r = _make_response()
        assert HTTPResponse(r).headers["content-type"] == "application/json"

    def test_text_passes_through(self) -> None:
        r = _make_response(body=b"hello")
        assert HTTPResponse(r).text == "hello"

    def test_json_caches_result(self) -> None:
        r = _make_response(body=b'{"v":1}')
        wr = HTTPResponse(r)
        first = wr.json()
        second = wr.json()
        # Same content; cache hit means same object identity
        assert first is second

    @pytest.mark.parametrize("status,is_success,is_client,is_server", [
        (200, True, False, False),
        (204, True, False, False),
        (299, True, False, False),
        (400, False, True, False),
        (404, False, True, False),
        (499, False, True, False),
        (500, False, False, True),
        (503, False, False, True),
        (599, False, False, True),
        (300, False, False, False),  # 3xx redirects: none of the above
        (100, False, False, False),  # 1xx informational
    ])
    def test_status_classification(
        self, status: int, is_success: bool, is_client: bool, is_server: bool
    ) -> None:
        wr = HTTPResponse(_make_response(status=status))
        assert wr.is_success() is is_success
        assert wr.is_client_error() is is_client
        assert wr.is_server_error() is is_server


# --- make_request --------------------------------------------------------


class TestMakeRequest:
    @pytest.mark.asyncio
    async def test_make_request_wraps_httpx_response(self) -> None:
        """make_request returns an HTTPResponse wrapping the underlying
        httpx response."""
        fake_response = _make_response(body=b'{"ok":1}')
        fake_client = AsyncMock()
        fake_client.request = AsyncMock(return_value=fake_response)

        with patch(
            "amazon_ads_mcp.utils.http.request.get_http_client",
            new=AsyncMock(return_value=fake_client),
        ):
            wr = await make_request("GET", "https://x/y")

        assert isinstance(wr, HTTPResponse)
        assert wr.status_code == 200
        assert wr.json() == {"ok": 1}

    @pytest.mark.asyncio
    async def test_make_request_passes_kwargs_through(self) -> None:
        """Headers, params, json_data, and timeout reach the underlying
        client.request call."""
        fake_response = _make_response()
        fake_client = AsyncMock()
        fake_client.request = AsyncMock(return_value=fake_response)

        with patch(
            "amazon_ads_mcp.utils.http.request.get_http_client",
            new=AsyncMock(return_value=fake_client),
        ):
            await make_request(
                "POST", "https://x/y",
                headers={"X-Custom": "1"},
                params={"q": "test"},
                json_data={"body": "data"},
                timeout=5.0,
            )

        kwargs = fake_client.request.await_args.kwargs
        assert kwargs["headers"] == {"X-Custom": "1"}
        assert kwargs["params"] == {"q": "test"}
        assert kwargs["json"] == {"body": "data"}
        assert kwargs["timeout"] == 5.0

    @pytest.mark.asyncio
    async def test_make_request_raises_on_non_2xx_after_retries(self) -> None:
        """raise_for_status fires when upstream returns a 4xx/5xx after
        all retry attempts are exhausted."""
        fake_response = httpx.Response(
            status_code=500,
            headers={"content-type": "application/json"},
            content=b'{"error":"oops"}',
            request=httpx.Request("GET", "https://x/y"),
        )
        fake_client = AsyncMock()
        fake_client.request = AsyncMock(return_value=fake_response)

        # Patch sleep so retry doesn't slow the test.
        with patch(
            "amazon_ads_mcp.utils.http.request.get_http_client",
            new=AsyncMock(return_value=fake_client),
        ), patch("asyncio.sleep", new=AsyncMock(return_value=None)):
            with pytest.raises(httpx.HTTPStatusError):
                await make_request("GET", "https://x/y")
