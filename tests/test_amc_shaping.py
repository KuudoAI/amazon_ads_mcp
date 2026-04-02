"""Tests for AMC response shaping and truncation.

This module tests the AMC response shaping functionality that
truncates large responses to prevent context overflow in LLM
conversations.
"""

import json
import unittest

import httpx

from amazon_ads_mcp.utils.http_client import AuthenticatedClient


class TestAMCFallbackShaping(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.client = AuthenticatedClient()

    def _make(self, method: str, path: str, payload: dict) -> tuple[httpx.Request, httpx.Response]:
        req = httpx.Request(method, f"https://example.com{path}")
        content = json.dumps(payload).encode("utf-8")
        resp = httpx.Response(200, headers={"Content-Type": "application/json"}, content=content)
        return req, resp

    async def test_list_datasources_truncated(self):
        data = {
            "dataSources": [
                {"id": f"ds{i}", "columns": list(range(20))} for i in range(5)
            ]
        }
        req, resp = self._make("GET", "/amc/reporting/abc/dataSources", data)
        shaped = self.client._maybe_shape_amc_response(req, resp)
        self.assertIsInstance(shaped, (dict, list))
        self.assertEqual(len(shaped["dataSources"]), 3)
        self.assertEqual(len(shaped["dataSources"][0]["columns"]), 3)

    async def test_get_datasource_truncated_to_5(self):
        data = {"columns": list(range(50))}
        req, resp = self._make("GET", "/amc/reporting/abc/dataSources/xyz", data)
        shaped = self.client._maybe_shape_amc_response(req, resp)
        self.assertEqual(len(shaped["columns"]), 5)

    async def test_list_workflows_truncated_to_10(self):
        data = {"items": list(range(25))}
        req, resp = self._make("GET", "/amc/reporting/abc/workflows", data)
        shaped = self.client._maybe_shape_amc_response(req, resp)
        # All lists truncated to 10
        self.assertEqual(len(shaped["items"]), 10)

    async def test_audiences_connections_truncated_to_10(self):
        data = {"connections": list(range(30))}
        req, resp = self._make("GET", "/amc/audiences/connections", data)
        shaped = self.client._maybe_shape_amc_response(req, resp)
        self.assertEqual(len(shaped["connections"]), 10)

    async def test_campaigns_v2_list_truncated(self):
        data = {"items": list(range(30))}
        req, resp = self._make("GET", "/v2/campaigns", data)
        shaped = self.client._maybe_shape_amc_response(req, resp)
        # v2 endpoints should not be shaped; shaping only applies to AMC endpoints
        self.assertIsNone(shaped)

    async def test_amc_instances_s3_bucket_region_null_normalized(self):
        data = {
            "instance": {
                "instanceId": "amcvo9oexox",
                "s3BucketRegion": None,
            }
        }
        req, resp = self._make("GET", "/amc/instances/amcvo9oexox", data)
        shaped = self.client._maybe_shape_amc_response(req, resp)
        self.assertEqual(shaped["instance"]["s3BucketRegion"], "")

    async def test_amc_instances_next_token_null_normalized(self):
        data = {
            "instances": [{"instanceId": "abc"}],
            "nextToken": None,
        }
        req, resp = self._make("GET", "/amc/instances", data)
        shaped = self.client._maybe_shape_amc_response(req, resp)
        self.assertEqual(shaped["nextToken"], "")


if __name__ == "__main__":
    unittest.main()
