"""§8.3 "Retry ordinals": ResilientAuthenticatedClient's retries flow into
distinct metering events with correct ordinals (Task 22 ruling #6).

Verified-repo-fact correction (brief said "MockTransport scripted
500,500,200"): ``ResilientAuthenticatedClient.send()`` (see
``utils/http/resilient_client.py``) wraps ``send_with_retry`` with
``ResilientRetry`` (``utils/http/resilience.py``), whose retry loop only
triggers on a raised ``httpx.HTTPStatusError``/``RequestError``/
``TimeoutException`` -- but ``send_with_retry`` returns
``super().send(...)`` directly, without ever calling
``response.raise_for_status()``. A plain 500/503/429 *response* is
therefore returned on the first attempt with NO retry (verified
empirically: a MockTransport returning 500,500,200 makes exactly one
call). This is a pre-existing characteristic of this repo's resilient
client, orthogonal to Task 22's scope -- not something this task's brief
asked to change. What genuinely re-invokes ``send_with_retry`` (and thus
the retry-attribution closure) is a raised transport-level exception, so
this test scripts ``ConnectError, ConnectError, 200`` instead -- the same
"three events, retry_attempt 0/1/2, same logical_request_id, distinct
event ids" assertions the brief specifies, driven the way retries
actually happen in this codebase today.
"""

from __future__ import annotations

import asyncio
import sys

import httpx
import pytest

pytestmark = pytest.mark.skipif(
    sys.version_info < (3, 12), reason="metering requires Python>=3.12"
)

if sys.version_info >= (3, 12):
    from amazon_ads_mcp.metering.adapter import set_metering_runtime
    from amazon_ads_mcp.utils.http.resilient_client import ResilientAuthenticatedClient

    from ._support import ALLOWED_HOST, FakeAuthManager, RecordingIngestTransport, build_runtime


def test_retry_ordinals_flow_into_distinct_events(tmp_path) -> None:
    async def scenario():
        ingest = RecordingIngestTransport()
        runtime = await build_runtime(tmp_path, ingest=ingest)
        set_metering_runtime(runtime)
        try:
            calls = {"n": 0}

            def upstream_handler(request: httpx.Request) -> httpx.Response:
                calls["n"] += 1
                if calls["n"] < 3:
                    raise httpx.ConnectError("simulated unreachable upstream", request=request)
                return httpx.Response(200)

            client = ResilientAuthenticatedClient(
                transport=httpx.MockTransport(upstream_handler),
                auth_manager=FakeAuthManager(),
                interactive_mode=True,
            )
            try:
                request = client.build_request("GET", f"https://{ALLOWED_HOST}/v2/profiles")
                response = await client.send(request)
                assert response.status_code == 200
                assert calls["n"] == 3
            finally:
                await client.aclose()

            events = await ingest.wait_for_event_count(3)
        finally:
            set_metering_runtime(None)
            await runtime.aclose()

        assert len(events) == 3

        ordinals = sorted(e["data"]["mcp.usage.retry_attempt"] for e in events)
        assert ordinals == [0, 1, 2]

        logical_ids = {e["data"]["mcp.usage.logical_request_id"] for e in events}
        assert len(logical_ids) == 1  # same logical send across all 3 attempts

        event_ids = {e["id"] for e in events}
        assert len(event_ids) == 3  # distinct event ids

        outcomes_by_ordinal = {
            e["data"]["mcp.usage.retry_attempt"]: e["data"]["mcp.usage.outcome"] for e in events
        }
        assert outcomes_by_ordinal[0] == "transport_error"
        assert outcomes_by_ordinal[1] == "transport_error"
        assert outcomes_by_ordinal[2] == "response"

        is_retry_by_ordinal = {
            e["data"]["mcp.usage.retry_attempt"]: e["data"].get("mcp.usage.is_retry")
            for e in events
        }
        assert is_retry_by_ordinal == {0: False, 1: True, 2: True}

    asyncio.run(scenario())


def test_plain_authenticated_client_send_no_metering_extension(tmp_path) -> None:
    """Ruling #6: "Production path (plain client) sends no extension." The
    plain (non-resilient) AuthenticatedClient has no retry loop, so its
    single send() attaches no request.extensions["metering"] at all --
    retry_attempt/logical_request_id fall back to None on the resulting
    event, never a fabricated 0."""

    async def scenario():
        from amazon_ads_mcp.utils.http_client import AuthenticatedClient

        ingest = RecordingIngestTransport()
        runtime = await build_runtime(tmp_path, ingest=ingest)
        set_metering_runtime(runtime)
        try:
            client = AuthenticatedClient(
                transport=httpx.MockTransport(lambda request: httpx.Response(200)),
                auth_manager=FakeAuthManager(),
            )
            try:
                request = client.build_request("GET", f"https://{ALLOWED_HOST}/v2/profiles")
                assert "metering" not in request.extensions
                response = await client.send(request)
                assert response.status_code == 200
            finally:
                await client.aclose()

            events = await ingest.wait_for_event_count(1)
        finally:
            set_metering_runtime(None)
            await runtime.aclose()

        assert len(events) == 1
        assert events[0]["data"].get("mcp.usage.retry_attempt") is None
        assert events[0]["data"].get("mcp.usage.logical_request_id") is None

    asyncio.run(scenario())
