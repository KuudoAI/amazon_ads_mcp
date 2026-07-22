# Kuudo Session Reconciliation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Preserve a freshly selected Kuudo identity for credential loading and prevent code-mode nested calls from rehydrating stale tenant state.

**Architecture:** Treat the provider-derived request fingerprint as the authoritative request ownership signal. Centralize session hydration plus reconciliation so both normal middleware and code-mode nested dispatch apply the same tenant boundary before executing tools.

**Tech Stack:** Python 3.10+, ContextVars, FastMCP session state, pytest, Ruff, uv.

## Global Constraints

- Never persist or expose the raw Kuudo API key.
- Preserve the existing auth-provider pattern and provider-independent session bridge.
- Clear identity, credentials, and profiles on a fingerprint mismatch before downstream tool execution.
- Follow red-green TDD for both regressions.

---

### Task 1: Preserve Kuudo identity during initial credential fetch

**Files:**
- Modify: `tests/unit/test_auth_manager_advanced.py`
- Modify: `src/amazon_ads_mcp/auth/session_state.py`
- Modify: `src/amazon_ads_mcp/auth/manager.py`

**Interfaces:**
- Consumes: the fingerprint bound by `bind_request_tenant_fingerprint(fingerprint)`.
- Produces: `get_request_tenant_fingerprint() -> Optional[str]` for provider-neutral ownership checks.

- [ ] **Step 1: Write a failing test**

Add a Kuudo-style multi-identity provider test that binds a request fingerprint,
sets the same last-seen fingerprint, selects an identity without session
credentials, and asserts `get_active_credentials()` fetches that identity's
credentials without clearing it.

- [ ] **Step 2: Verify the red state**

Run:

```bash
uv run pytest tests/unit/test_auth_manager_advanced.py -k request_fingerprint_preserves_selected_identity -v
```

Expected: FAIL because the guard clears the selected identity when no refresh-token override or loaded credentials exist.

- [ ] **Step 3: Implement the minimal ownership check**

Expose the bound request fingerprint from `session_state.py`. In
`AuthManager.get_active_credentials()`, compare it with
`last_seen_token_fingerprint` before the legacy refresh-token checks. Preserve
the identity on equality and clear it on mismatch.

- [ ] **Step 4: Verify the green state**

Run the command from Step 2. Expected: PASS.

### Task 2: Reconcile every code-mode bridge hydration

**Files:**
- Modify: `tests/unit/test_code_mode.py`
- Modify: `src/amazon_ads_mcp/middleware/auth_session_bridge.py`
- Modify: `src/amazon_ads_mcp/middleware/authentication.py`
- Modify: `src/amazon_ads_mcp/server/code_mode.py`

**Interfaces:**
- Produces: `hydrate_and_reconcile_auth_from_mcp_session(context, logger_instance=None) -> bool`, returning whether tenant state was cleared.

- [ ] **Step 1: Write a failing test**

Seed parent session state with tenant A identity, credentials, profiles, and
fingerprint. Bind tenant B's request fingerprint, execute a bridged nested tool,
and assert the tool observes no tenant A state.

- [ ] **Step 2: Verify the red state**

Run:

```bash
uv run pytest tests/unit/test_code_mode.py -k bearer_swap -v
```

Expected: FAIL because `AuthBridgingSandboxProvider` hydrates tenant A without reconciliation.

- [ ] **Step 3: Implement shared hydrate-and-reconcile**

Add the shared helper to `auth_session_bridge.py`, use it from
`AuthSessionStateMiddleware`, and use it immediately before every nested
code-mode tool dispatch.

- [ ] **Step 4: Verify the green state**

Run the command from Step 2. Expected: PASS.

### Task 3: Repository verification and publication

**Files:**
- Verify all files modified in Tasks 1 and 2.

**Interfaces:**
- Consumes: the two passing regression tests.
- Produces: a validated commit on PR #100.

- [ ] **Step 1: Run focused auth and code-mode tests**

```bash
uv run pytest tests/unit/test_auth_manager_advanced.py tests/unit/test_session_state.py tests/unit/test_auth_session_bridge.py tests/unit/test_authentication_middleware.py tests/unit/test_inbound_auth.py tests/unit/test_kuudo_provider.py tests/unit/test_code_mode.py tests/integration/test_code_mode_nested_auth.py
```

- [ ] **Step 2: Run required repository validation in sequence**

```bash
uv sync
uv run ruff check --fix
uv run pytest
```

- [ ] **Step 3: Review and publish the focused diff**

Inspect `git diff`, commit with a focused Conventional Commit message, push the
existing PR branch, and inspect PR #100 checks and unresolved review threads.
