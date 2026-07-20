"""§8.3 "Conformance + verify": `create_conformance_harness` builds the
REAL `AuthenticatedClient` stack over the harness's mock upstream, and
`ProducerConformanceSuite` (the shared 11-scenario contract suite, design
§3.5.5) passes 11/11 through it -- zero overrides, per the documented
subclass pattern (see `mcp_outbound_metering.conformance.suite`'s module
docstring and `examples/httpx/test_conformance.py` in the billing repo).

`test_cli_verify_subprocess.py` covers the second half of this §8.3
bullet (`mcp-metering verify` exits 0) as a separate subprocess test.
"""

from __future__ import annotations

import sys

import pytest

pytestmark = pytest.mark.skipif(
    sys.version_info < (3, 12), reason="metering requires Python>=3.12"
)

if sys.version_info >= (3, 12):
    from mcp_outbound_metering.conformance import ProducerConformanceSuite

    from amazon_ads_mcp.metering.conformance import create_conformance_harness


if sys.version_info >= (3, 12):

    class TestAmazonAdsMcpMeteringConformance(ProducerConformanceSuite):
        @pytest.fixture
        def harness_factory(self):
            return create_conformance_harness
