"""§8.3 "Conformance + verify" (second half): `mcp-metering verify` exits
0 against the real harness, with the integration guide's §4 CI
environment block values (Task 22 ruling #9). Runs the installed
`mcp-metering` console script as a real subprocess -- the exact command
the CI `metering` job runs -- so this test also proves the console script
entry point itself resolves correctly in this repo's dependency closure,
not just that the Python API works when imported in-process (already
covered by `test_conformance.py`).

3.12 only, same as every other `tests/metering/` module: `mcp-metering`
is not installed at all on <3.12 (the dependency is conditional on
`python_version >= '3.12'`), so `sys.executable` (unconditionally the
CURRENT interpreter -- guaranteeing subprocess and pytest run under the
same interpreter) simply wouldn't have the script on <3.12.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys

import pytest

pytestmark = pytest.mark.skipif(
    sys.version_info < (3, 12), reason="metering requires Python>=3.12"
)

REPO_ROOT = None
if sys.version_info >= (3, 12):
    from pathlib import Path

    REPO_ROOT = Path(__file__).resolve().parents[2]

# Integration guide §4's CI environment block (conformance-only fakes,
# never a real credential/endpoint), adapted to this repo's provider
# name/allowed host.
_CI_ENV_BLOCK = {
    "METERING_ENABLED": "true",
    "METERING_UPSTREAM_HOSTS": "advertising-api.amazon.com",
    "METERING_UPSTREAM_SERVICE": "amazon_ads",
    "METERING_ENDPOINT": "https://ingest.example-metering.test/v1/usage/batches",
    "METERING_DEPLOYMENT_ID": "ci",
    "METERING_INSTANCE_ID": "ci-1",
    "METERING_KEY_ID": "ci-key-placeholder",
    "METERING_HMAC_SECRET": "ci-secret-placeholder",
    "METERING_OUTBOX_MAX_BYTES": "10000000",
}


@pytest.mark.slow
def test_mcp_metering_verify_exits_zero(tmp_path) -> None:
    env = dict(os.environ)
    env.update(_CI_ENV_BLOCK)
    env["METERING_OUTBOX_PATH"] = str(tmp_path / "outbox.db")
    json_path = tmp_path / "report.json"

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "mcp_outbound_metering.cli",
            "verify",
            "--config",
            "metering.yaml",
            "--harness",
            "amazon_ads_mcp.metering.conformance:create_conformance_harness",
            "--skip-ingest",
            "--json",
            str(json_path),
        ],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
    )

    assert result.returncode == 0, (
        f"mcp-metering verify exited {result.returncode}\n"
        f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )

    report = json.loads(json_path.read_text())
    assert report["summary"]["FAIL"] == 0
    assert report["summary"]["PASS"] >= 11  # every suite scenario + config/policy/outbox
