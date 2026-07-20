"""§8.3 "Regional rewrite interop": the metered transport sees the
POST-rewrite host, for every HTTP method (Task 22 controller: "interop --
does the conformance suite pass through the REAL client stack (post-rewrite
hosts)?").

``AuthenticatedClient._inject_headers`` rewrites ``request.url``/``Host``
to the identity/settings-resolved regional endpoint BEFORE calling
``super().send()`` (which dispatches through ``self._transport`` --
the metered transport, when a runtime is active). If the metering wrap
somehow captured the PRE-rewrite host, this test's requests -- built
against a deliberately "wrong-region" ``base_url`` -- would raise
``DisallowedHostError`` (metering.yaml's ``disallowed_host_action:
reject``, and only the NA host is in ``METERING_UPSTREAM_HOSTS``): the
absence of that exception, plus each event's recorded host, is the proof.
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
    from amazon_ads_mcp.utils.http_client import AuthenticatedClient

    from ._support import ALLOWED_HOST, FakeAuthManager, RecordingIngestTransport, build_runtime

# The client is constructed against the EU endpoint; with no active
# identity/marketplace override, `_inject_headers`'s region-routing block
# falls back to `Settings().amazon_ads_region` -- "na" per
# tests/conftest.py's autouse `mock_env_vars` -- and rewrites every /v2/
# request to the NA host BEFORE the transport ever sees it.
_WRONG_REGION_BASE_URL = "https://advertising-api-eu.amazon.com"


def test_all_five_methods_are_metered_against_the_post_rewrite_host(tmp_path) -> None:
    async def scenario():
        ingest = RecordingIngestTransport()
        runtime = await build_runtime(tmp_path, ingest=ingest)
        set_metering_runtime(runtime)
        try:
            upstream = httpx.MockTransport(lambda request: httpx.Response(200))
            client = AuthenticatedClient(
                base_url=_WRONG_REGION_BASE_URL,
                transport=upstream,
                auth_manager=FakeAuthManager(),
            )
            try:
                methods = ("GET", "POST", "PUT", "PATCH", "DELETE")
                for method in methods:
                    response = await client.request(method, "/v2/profiles")
                    assert response.status_code == 200
            finally:
                await client.aclose()

            events = await ingest.wait_for_event_count(len(methods))
        finally:
            set_metering_runtime(None)
            await runtime.aclose()

        assert len(events) == 5
        seen_methods = set()
        for event in events:
            # Proves the transport saw the POST-rewrite host: had it
            # observed advertising-api-eu.amazon.com (not in
            # METERING_UPSTREAM_HOSTS), the request would have raised
            # DisallowedHostError above instead of reaching here.
            assert event["data"]["server.address"] == ALLOWED_HOST
            seen_methods.add(event["data"]["http.request.method"])
        assert seen_methods == set(("GET", "POST", "PUT", "PATCH", "DELETE"))

    asyncio.run(scenario())


def test_wrong_region_base_url_without_rewrite_would_be_rejected(tmp_path) -> None:
    """Negative control: a path that `_inject_headers` does NOT rewrite
    (outside /v2/, /reporting/, /amc/) reaches the transport with the
    ORIGINAL (EU) host still in place, and IS rejected -- proving the
    metering policy's host allowlist is exact and that the positive test
    above is genuinely exercising the rewrite, not just an accident of a
    lenient policy."""

    async def scenario():
        ingest = RecordingIngestTransport()
        runtime = await build_runtime(tmp_path, ingest=ingest)
        set_metering_runtime(runtime)
        try:
            upstream = httpx.MockTransport(lambda request: httpx.Response(200))
            client = AuthenticatedClient(
                base_url=_WRONG_REGION_BASE_URL,
                transport=upstream,
                auth_manager=FakeAuthManager(),
            )
            try:
                from mcp_outbound_metering.transport import DisallowedHostError

                with pytest.raises(DisallowedHostError):
                    await client.get("/not-a-rewritten-path")
            finally:
                await client.aclose()
        finally:
            set_metering_runtime(None)
            await runtime.aclose()

    asyncio.run(scenario())
