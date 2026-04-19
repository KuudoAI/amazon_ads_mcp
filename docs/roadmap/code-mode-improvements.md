# Code Mode Improvements

**Priority:** Medium value, low urgency
**Scope:** `src/amazon_ads_mcp/server/code_mode.py`, `src/amazon_ads_mcp/config/settings.py`
**Reference:** https://gofastmcp.com/servers/transforms/code-mode

## Context

Code Mode is working well — tag-based discovery, configurable discovery tools, and sandbox limits are all solid. These are incremental improvements that tighten security, improve token efficiency, and add domain-specific guidance.

## Improvements

### 1. Expose additional Monty sandbox limits

The sandbox currently only configures `max_duration_secs` and `max_memory`. FastMCP's `MontySandboxProvider` supports two more limits that prevent runaway LLM-generated scripts.

**Add to `settings.py`:**

```python
code_mode_max_allocations: Optional[int] = Field(
    1_000_000,
    alias="CODE_MODE_MAX_ALLOCATIONS",
    description="Maximum object allocations per sandbox run",
)
code_mode_max_recursion_depth: Optional[int] = Field(
    100,
    alias="CODE_MODE_MAX_RECURSION_DEPTH",
    description="Maximum call stack depth per sandbox run",
)
```

**Update `code_mode.py`:**

```python
sandbox = MontySandboxProvider(
    limits={
        "max_duration_secs": float(settings.code_mode_max_duration_secs),
        "max_memory": settings.code_mode_max_memory,
        "max_allocations": settings.code_mode_max_allocations,
        "max_recursion_depth": settings.code_mode_max_recursion_depth,
    }
)
```

### 2. Configurable Search result limit

With 200+ tools, unbounded search results can flood the LLM context. Add a configurable cap.

**Add to `settings.py`:**

```python
code_mode_search_limit: int = Field(
    10,
    alias="CODE_MODE_SEARCH_LIMIT",
    description="Maximum tools returned per Search call in code mode",
)
```

**Update `code_mode.py`:**

```python
tools.extend([Search(default_limit=settings.code_mode_search_limit), GetSchemas()])
```

Confirm FastMCP's built-in default for `Search` is unbounded or higher than 10 before shipping.

### 3. Configurable Search detail level (opt-in, not default)

FastMCP supports `Search(default_detail="detailed")` which inlines parameter schemas in search results, saving a GetSchemas round-trip. However, many Ads API tools have heavy nested schemas — inline "detailed" results can cost more tokens than a targeted `GetSchemas` call, and the LLM may still need `detail="full"` for complex tools.

**Offer as a setting, not a default change:**

```python
code_mode_search_detail: str = Field(
    "brief",
    alias="CODE_MODE_SEARCH_DETAIL",
    description="Default detail level for Search results (brief, detailed, full)",
)
```

Keep `"brief"` as default. Users with smaller catalogs or simpler schemas can opt into `"detailed"`.

### 4. Custom execute_description with domain hints — **IMPLEMENTED**

Shipped with the catchable-errors change (§6 below). `code_mode.py` now
defines an `EXECUTE_DESCRIPTION` constant and passes it to
`CodeMode(execute_description=...)`. The wording covers `call_tool`'s
catch behavior plus the verified Monty sandbox guardrails (no network,
no FS I/O, `print()` may be discarded, `asyncio.sleep` unavailable by
design, `try/except` semantics, `with`/`json.dumps` caveats, and the
auth/region/profile contract).

### 5. Tag mutation contract (no change needed)

The tagging functions in `code_mode.py` use `tool.tags = {tag} | (tool.tags or set())` which directly mutates the registered tool instance via `get_tool()`. This is correct — `get_tool()` on FastMCP's local provider returns the registered instance, so in-place mutation is the supported path. The `model_copy` pattern in transforms is different because transforms return new tool objects.

No code change needed. Documented here for clarity.

## Files affected

| File | Change |
|------|--------|
| `src/amazon_ads_mcp/config/settings.py` | Add 4 new settings |
| `src/amazon_ads_mcp/server/code_mode.py` | Pass new settings to sandbox/Search/CodeMode |
| `.env.example` | Document new env vars |
| `CLAUDE.md` | Update Code Mode env var section |

## Verification

- `uv run pytest` — all tests pass
- Start server with `CODE_MODE=true`, verify 4 meta-tools appear
- Test `Search` returns capped results
- Test sandbox limits with a deliberately expensive script

## 6. Catchable `call_tool` errors — **IMPLEMENTED**

**Problem (verified by repro):** the upstream
`MontySandboxProvider.run_async()` path surfaces external-function
exceptions as a host-side `MontyRuntimeError` and aborts the script
*before* the in-sandbox `try/except` can catch. Effect: the LLM cannot
defensively probe N candidate tool names in one `execute` block — every
unknown name short-circuits the whole script and forces N round trips.

**Fix:** `code_mode.py` ships `MontyDispatchSandboxProvider`, which
drives Monty manually through `start()` + `FunctionSnapshot.resume(...)`.
The dispatch loop:

- For successful external calls: eagerly awaits the coroutine on the
  host, then resumes the `FunctionSnapshot` with `future=...` and
  immediately resolves the resulting `FutureSnapshot` with the value
  — so the sandbox's `await call_tool(...)` sees a real awaitable.
- For failing external calls: resumes the `FunctionSnapshot` directly
  with `exception=...`. This is the *only* injection path that
  propagates into the sandbox's surrounding `try/except` —
  `FutureSnapshot` exception injection bypasses it (verified probe).
- `AuthBridgingSandboxProvider` re-raises `original_call_tool` failures
  as `RuntimeError("<OriginalType>: <message>")` so the LLM has a
  single, builtin catch surface (`except RuntimeError:`).

**Why no `call_tool_safe` was added:** the `try/except` story now works
end-to-end with the standard `call_tool` surface. Adding a second
sandbox function (`call_tool_safe(...) -> {ok, result|error}`) would
double the API surface to solve a problem the dispatch fix already
removes. Considered and explicitly rejected to keep `execute`'s scope
to one external function.

**Test coverage:** `tests/integration/test_code_mode_error_handling.py`
- `test_unknown_tool_is_catchable_as_runtime_error`
- `test_failing_tool_does_not_abort_subsequent_calls`
- `test_probe_many_candidates_in_one_block`
