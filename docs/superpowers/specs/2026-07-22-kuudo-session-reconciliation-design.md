# Kuudo Session Reconciliation Design

## Problem

Kuudo binds each HTTP request to a provider-derived API-key fingerprint before
the MCP middleware chain runs. Two paths currently lose that binding:

1. `AuthManager.get_active_credentials()` recognizes refresh-token state but
   does not recognize the provider-derived request fingerprint. A freshly
   selected Kuudo identity therefore looks unverifiable before its credentials
   have been loaded and is cleared.
2. Code-mode nested `call_tool` dispatch hydrates the parent MCP session after
   the outer request has reconciled a bearer swap. Because the nested path does
   not reconcile after hydration, it can restore the previous tenant's state.

## Design

Expose the current request's already-derived tenant fingerprint through a
read-only session-state accessor. The credential guard will compare that value
with the persisted last-seen fingerprint before consulting provider-specific
fallback channels. Equality proves that the active identity belongs to the
current request, including the period before credentials have been fetched.

Add a shared `hydrate_and_reconcile_auth_from_mcp_session()` helper. It will
hydrate ContextVars and immediately reconcile them against the current request
fingerprint. Both normal request middleware and code-mode nested dispatch will
use this operation so no caller can hydrate tenant state without applying the
same ownership check before downstream execution.

The raw Kuudo API key remains provider-local. Session persistence continues to
contain only the derived fingerprint. Direct and OpenBridge behavior remains
unchanged when no provider-derived request fingerprint is bound.

## Error Handling

A mismatched or previously unbound session is cleared with the existing
`token_swapped` reset reason. A matching request fingerprint preserves the
selected identity and permits normal credential loading. Hydration failures
retain the existing fail-safe reset behavior before reconciliation binds the
current request fingerprint.

## Testing

- Reproduce a fresh multi-identity Kuudo selection with a matching request
  fingerprint and no preloaded credentials; credential fetch must retain the
  selected identity.
- Reproduce code-mode hydration of tenant A while tenant B is bound to the
  outer request; the nested tool must observe cleared identity, credentials,
  and profiles before it executes.
- Run focused auth tests, Ruff, and the full pytest suite.
