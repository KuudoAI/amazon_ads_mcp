# Live Smoke Tests

Live smoke tests connect a real `fastmcp.Client` over HTTP to a running
`amazon-ads-mcp` server and exercise behaviors that **only the wire can
prove** — things in-memory unit tests cannot catch:

- Whether middleware-layered envelopes survive the FastMCP `Tool` wrap
  / unwrap path (see memory: `feedback_middleware_wire_shape` —
  unit tests with raw-dict mocks can stay green while the wire silently
  drops markers).
- Whether tool descriptions injected by transforms actually appear in
  `get_schema` output.
- Whether `tool_not_found` hints reference tool names that **really
  exist** on the server (FastMCP class names like `GetSchemas` register
  under different runtime tool names like `get_schema`).
- Whether the Code Mode sandbox's `MontyRuntimeError` chain produces
  the typed `sandbox_runtime` envelope we expect — including correct
  inner-exception unwrapping.

## When to run

Run live smoke:

- After any change to middleware that touches the v1 error envelope
  (`error_envelope.py`, `schema_normalization.py`).
- After any change to Code Mode (`code_mode.py`,
  `ad_product_cap_hints_transform.py`, `async_hints_transform.py`).
- After any change to discovery-tool registration or hint text.
- Before merging an MCP-client-feedback fix bundle.
- Whenever an in-memory test passes but you want wire-level
  confirmation (the cheap version of memory's
  `feedback_plan_discipline` "wire-level captures" rule).

You don't need to run them for pure refactors that don't touch
middleware / discovery / sandbox code paths.

## Prerequisites

1. `amazon-ads-mcp` running on `http://localhost:9080`:

   ```bash
   docker compose up -d
   # or
   uv run python -m amazon_ads_mcp.server --transport http --port 9080
   ```

2. Verify health: `curl -fsS http://localhost:9080/health` should
   return 200.

3. **For F6 / authenticated checks**: an OpenBridge Bearer token. The
   token is in `~/Library/Application Support/Claude/claude_desktop_config.json`
   under `mcpServers.amazon_ads.env.OPENBRIDGE_REFRESH_TOKEN` on
   developer machines. Never commit this token; never paste it into
   chat / PRs.

## Running the feedback-bundle smoke

The reference smoke for the B1/B2/B3/F3/F6 feedback bundle lives at
`.build/debug/live_smoke_feedback_bundle.py`. Per memory
`feedback_dotbuild_private`: this directory is **never committed** —
edit in place if needed.

```bash
# Unauthenticated checks (B1, B2, B3, F3 — all bug fixes + the F3 hint)
uv run python .build/debug/live_smoke_feedback_bundle.py

# Authenticated, includes F6 (set_active_profile metadata echo)
uv run python .build/debug/live_smoke_feedback_bundle.py "<bearer-token>"
```

Expected output: green PASS rows under each bug ID, ending in a SUMMARY
table. Exit code is `1` if any check failed.

## What the smoke proves vs. what it does NOT

**Proves (wire-level):**

- Tool descriptions reaching the client (`get_schema` output) carry
  the expected paragraphs.
- Error envelopes have the documented `error_kind` / `error_code` /
  hint shape on the wire — not just inside the classifier.
- Code Mode sandbox failures unwrap to typed envelopes, including
  inner `ModuleNotFoundError` name extraction.
- The `tool_not_found` hint names the **registered** discovery tool
  names (lowercase `tags`, `search`, `get_schema` — NOT the FastMCP
  class names `GetTags`, `Search`, `GetSchemas`).

**Does NOT prove:**

- Real Amazon Ads API behavior (use `tests/live/test_profile_listing_live.py`
  for that — those tests gate on `RUN_LIVE_TESTS=1` and need
  sandbox credentials).
- Multi-region / multi-identity scenarios (we exercise one identity per
  smoke run by design — keep the smoke fast).
- Performance / load (use the dedicated load-test scripts).

## Workflow

When iterating on a feedback-bundle fix:

1. Edit code, run unit tests: `uv run pytest tests/unit/ -v`.
2. Rebuild the server so it picks up your changes:
   ```bash
   docker compose up -d --build
   ```
   (or restart the `python -m amazon_ads_mcp.server` process if running outside Docker).
3. Run the live smoke:
   ```bash
   uv run python .build/debug/live_smoke_feedback_bundle.py "<token>"
   ```
4. If a check fails, **distinguish two cases**:
   - **Stale build**: the server's running code predates your edit.
     Rebuild and retry.
   - **Real wire-level bug**: your in-memory test was insufficient
     (e.g. the test asserted on an internal helper but the wire
     contract differs). Add a unit test that pins the wire shape;
     fix the code; re-run smoke.

   The B2 hint fix on this bundle is the canonical example of case 2:
   unit tests asserted the hint contained `GetTags`/`Search`/`GetSchemas`,
   which are FastMCP **class names**. The live smoke proved the hint
   pointed at non-existent tools because the **registered** names are
   lowercase. Tests were updated to assert the lowercase names; the
   hint string was corrected.

## Adding a new live smoke check

When fixing a new MCP-client-feedback bug:

1. Write the unit test first (as usual).
2. Add a `check_<bug_id>_<short_name>` function to
   `.build/debug/live_smoke_feedback_bundle.py`. Each check is a
   standalone async function returning `bool | None`:
   - `True` → pass
   - `False` → fail
   - `None` → skipped (e.g. needs auth and no token provided)
3. Use `_result_text` and `_try_parse_envelope` helpers — they handle
   both happy-path JSON and FastMCP `ToolError` envelope strings.
4. For non-meta tools (anything not `tags` / `search` / `get_schema` /
   `execute`), wrap the call in `execute(call_tool(...))` because
   CODE_MODE hides the catalog from direct calls. See the F3 / F6
   checks for the pattern.
5. Add the check to `main()`'s `results.append(...)` list so it shows
   up in the summary.

## Keeping smoke fast

The whole bundle should run in **under 30 seconds** end-to-end against
a warm server. Don't add checks that:

- Make multiple round trips per assertion (combine work into one
  `execute` block).
- Probe upstream Amazon API surfaces (those belong in `tests/live/`).
- Spin up new servers / containers per check.

If a check is slow, prefer compressing it into a single `execute`
block that does setup + assertion in one round trip.

## Comparison to other test lanes

| Lane | Location | What it proves | When to run |
|---|---|---|---|
| Unit | `tests/unit/` | In-process behavior of a single function/class | Every commit |
| Integration / smoke | `tests/integration/` | In-memory MCP client against an in-process server | Every commit (CI) |
| **Live smoke (this doc)** | `.build/debug/live_smoke_feedback_bundle.py` | Wire-level behavior against a real running server | Before merging middleware / discovery / sandbox changes |
| Live API | `tests/live/` (gated `RUN_LIVE_TESTS=1`) | Real Amazon Ads API contract | Weekly CI, before releases |
| Smoke gate | `tests/smoke/` (`pytest -m smoke`) | Server module imports + settings construct cleanly | First step in CI |
