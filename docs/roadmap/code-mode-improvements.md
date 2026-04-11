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

### 4. Custom execute_description with domain hints

The `execute_description` parameter lets you inject domain-specific guidance into the execute tool's description. Keep it brief — this is not a place to duplicate AGENTS.md.

**Update `code_mode.py`:**

```python
transform = CodeMode(
    sandbox_provider=sandbox,
    discovery_tools=discovery_tools,
    execute_description=(
        "Execute Python code in a sandbox. Use `await call_tool(name, params)` "
        "to call tools and `return` the result. Tool responses are JSON. "
        "Authentication and profile context are handled automatically — do not "
        "pass auth headers. Set the active profile before making API calls."
    ),
)
```

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
