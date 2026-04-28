# Live Integration Tests

Tests in this directory hit a **real Amazon Ads sandbox account** to catch the
class of bugs that unit and in-memory integration tests cannot:

- **Schema drift** — Amazon adds/renames/removes fields in production responses
  without notice. Mocks frozen against last-quarter's schema pass; live calls
  fail loudly.
- **Auth quirks** — token refresh edge cases, region-routing quirks, profile
  switching that only manifests against the real OAuth servers.
- **Rate-limit behavior** — actual 429 patterns and `Retry-After` semantics
  that mocks approximate but don't reproduce.
- **Wire encoding** — header case sensitivity at the gateway, body encoding
  that the SDK normalizes but Amazon may reject.

## Default behavior: SKIPPED

Live tests are **default-skipped** in `tests/conftest.py` via
`pytest_collection_modifyitems`. Running `pytest` (locally or in standard CI)
collects but skips them.

To opt in:

```bash
export RUN_LIVE_TESTS=1
# Plus the sandbox credentials documented per-test
uv run pytest tests/live/ -v
```

## CI lane (fully opt-in)

A dedicated workflow `.github/workflows/live-integration.yml` runs the live
tests on a **weekly schedule** (Mondays 09:00 UTC) + manual dispatch. NOT on
every PR or push.

The workflow is **fully opt-in**: it checks for three repo secrets and
**skips cleanly with status success** if any are missing. This means:

- **Forks and PRs from forks** (which can't access secrets) — clean skip.
- **Repos that haven't onboarded sandbox creds yet** — clean skip; no red
  CI, no babysitting.
- **Repos that HAVE configured the secrets** — tests run weekly.

To enable, set all three secrets at
`https://github.com/<owner>/<repo>/settings/secrets/actions`:

- `SANDBOX_AMAZON_AD_API_CLIENT_ID`
- `SANDBOX_AMAZON_AD_API_CLIENT_SECRET`
- `SANDBOX_AMAZON_AD_API_REFRESH_TOKEN`

The weekly cadence is intentional: it surfaces drift within a week without
burning sandbox-account quota or CI minutes on every commit.

## LWA token-lifetime caveat (the operational reality)

Amazon's Login With Amazon (LWA) refresh tokens have an awkward property:

- They are **long-lived but not infinite**: expire after ~6 months of
  inactivity.
- They can be **revoked** by user action (account password change, app
  re-authorization) or by Amazon (suspicious activity, scope changes).
- They are **tied to a specific user × app × scope** tuple — you cannot
  re-mint one programmatically. A new token requires a human walking
  through the LWA consent screen in a browser.

What this means in practice: when the configured sandbox refresh token
eventually dies, the live lane goes red. Someone has to:

1. Run the OAuth consent flow in a browser with the sandbox account.
2. Capture the new refresh token from the redirect URL.
3. Update the `SANDBOX_AMAZON_AD_API_REFRESH_TOKEN` repo secret.

This is **manual ops toil, not a CI problem**. The opt-in design above
contains the blast radius (failures don't block PRs, just the weekly
drift detector), but the toil is unavoidable for human-account tokens.

### Upgrade paths (if the manual rotation toil is unacceptable)

1. **Service-account-style LWA**: ask the Amazon Ads partner team
   whether the sandbox account can issue a service-account refresh
   token. Service tokens don't expire on inactivity and can be rotated
   programmatically. Best long-term answer if available.
2. **Self-refreshing token cache**: run a long-lived process that
   exchanges the refresh token weekly and stores the latest in
   AWS Secrets Manager (or similar). Workflow fetches at run time
   instead of using a static secret. Non-trivial infrastructure.
3. **Demote to manual-only**: remove the `schedule:` trigger; engineers
   run the lane locally before releases. Zero infrastructure burden;
   relies on developer discipline.

Pick the path that matches your team's actual ops capacity. The
default opt-in design works for **all three**: the workflow exists and
is dormant until secrets land, regardless of how those secrets get
provisioned.

## How to write a live test

1. **Mark it `@pytest.mark.live`** so it skips by default.
2. **Use the standard sandbox credential env vars** documented in the auth
   provider tests (`AMAZON_AD_API_*` for direct, `OPENBRIDGE_REFRESH_TOKEN`
   for openbridge).
3. **Keep it small.** Each live test should test ONE concrete contract.
   Composite happy-path "does the whole thing work" tests are anti-patterns —
   when they fail you can't tell *which* part broke.
4. **Assert on contracts, not values.** Don't assert on a specific
   `campaignId` you read once. Do assert on response shape (every campaign
   has `campaignId`, `name`, `state`).
5. **Document the sandbox state assumed.** If the test depends on a specific
   profile existing or a specific advertiser being active, write that down at
   the top of the test.
6. **Skip cleanly when credentials are absent.** `pytest.importorskip` or
   `pytest.skip("AMAZON_AD_API_REFRESH_TOKEN not set")` — don't error out.

## Why a separate directory + marker (not just one or the other)

- The marker is the **gate**: respects `RUN_LIVE_TESTS=1` opt-in.
- The directory is the **organization**: makes it obvious which tests have
  external-service dependencies, lets `pytest tests/live/` target this lane
  specifically, and lets us point CI at one place instead of grepping for
  markers across the suite.

## What this lane does NOT replace

- Unit tests for our request-construction logic (still mocked, deterministic).
- In-memory MCP integration tests (`tests/integration/test_inmemory_mcp_client.py`).
- Wire-layer respx tests for header / URL contract validation.

Live tests are a **drift detector**, not a primary verification layer. The
test pyramid still puts unit tests at the base.

## Runtime budget

Target: full live lane runs in **under 5 minutes**. If we cross that, the
weekly schedule becomes painful to babysit and people will route around it.
Prefer narrow, focused tests over broad happy-path scenarios.
