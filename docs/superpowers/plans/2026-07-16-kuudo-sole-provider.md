# Kuudo Sole Provider Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `kuudo.py` the sole registered Kuudo provider, remove the adapter and duplicate auth models, and clear CodeQL with a salted 600,000-iteration PBKDF2 fingerprint.

**Architecture:** `KuudoAmazonAdsProvider` will live in `auth/providers/kuudo.py`, directly implement the project base classes, register itself, and return the shared Pydantic auth models. `kuudo_ads.py` will be deleted with no shim. Cache discrimination remains provider-local and raw client API keys remain absent from cache keys.

**Tech Stack:** Python 3.10+, httpx, Pydantic project models, hashlib PBKDF2-HMAC-SHA256, pytest, Ruff, uv.

## Global Constraints

- `src/amazon_ads_mcp/auth/providers/kuudo.py` is the sole Kuudo provider module.
- Delete `src/amazon_ads_mcp/auth/providers/kuudo_ads.py`; create no compatibility module or shim.
- Use shared `Token`, `Identity`, and `AuthCredentials` models; remove the duplicate Kuudo dataclasses.
- Preserve public registry, token, identity, credential, region-routing, cache, and error behavior.
- Use a provider-local random 32-byte salt, PBKDF2-HMAC-SHA256, 600,000 iterations, and a 32-byte result.
- Derive the fingerprint at most once per top-level identity or credential operation.
- Retain no raw API key in token, identity, or credential cache keys.
- Use `apply_patch` for edits and run targeted tests before the full suite.

---

### Task 1: Consolidate the Registered Provider into `kuudo.py`

**Files:**
- Modify: `src/amazon_ads_mcp/auth/providers/kuudo.py`
- Modify: `src/amazon_ads_mcp/auth/providers/__init__.py`
- Delete: `src/amazon_ads_mcp/auth/providers/kuudo_ads.py`
- Modify: `tests/unit/test_kuudo_provider.py`
- Modify: `tests/test_auth_providers.py`

**Interfaces:**
- Consumes: `BaseAmazonAdsProvider`, `BaseIdentityProvider`, `ProviderConfig`, `register_provider`, and shared `Token`, `Identity`, `AuthCredentials`.
- Produces: `@register_provider("kuudo") class KuudoAmazonAdsProvider(BaseAmazonAdsProvider, BaseIdentityProvider)` from `amazon_ads_mcp.auth.providers.kuudo`.

- [ ] **Step 1: Point tests at the sole provider module and add ownership assertions**

Update both test imports to:

```python
from amazon_ads_mcp.auth.providers.kuudo import (
    KuudoAmazonAdsProvider,
    KuudoAuthError,
)
```

In `tests/test_auth_providers.py`, import only `KuudoAmazonAdsProvider` from that module. Extend the registry test with:

```python
assert KuudoAmazonAdsProvider.__module__ == "amazon_ads_mcp.auth.providers.kuudo"
```

- [ ] **Step 2: Run the ownership tests and verify RED**

Run:

```bash
uv run pytest tests/unit/test_kuudo_provider.py::test_kuudo_provider_is_registered tests/test_auth_providers.py::TestProviderRegistry::test_registry_creates_kuudo_provider -v
```

Expected: collection fails because `kuudo.py` does not yet export `KuudoAmazonAdsProvider`.

- [ ] **Step 3: Make `kuudo.py` project-native**

Replace the standalone model imports and generic class boundary with:

```python
from ...models import AuthCredentials, Identity, Token
from ..base import BaseAmazonAdsProvider, BaseIdentityProvider, ProviderConfig
from ..registry import register_provider


@register_provider("kuudo")
class KuudoAmazonAdsProvider(BaseAmazonAdsProvider, BaseIdentityProvider):
    """Provide Kuudo-managed Amazon Ads identities and credentials."""
```

Rename the existing `KuudoAuthProvider` class declaration to the class header above;
its constructor and provider methods become the body of the registered class. Remove
the local `Token`, `Identity`, and `AuthCredentials` dataclass definitions. Keep
`KuudoProviderConfig` for internal normalized configuration. Update `__all__` to
export `KuudoAmazonAdsProvider` and remove `KuudoAuthProvider`.

Keep the Kuudo-only identity filter inside the provider:

```python
async def list_identities(
    self,
    *,
    provider: str | None = None,
    api_key: str | None = None,
    force_refresh: bool = False,
    **params: Any,
) -> list[Identity]:
    params.pop("identity_type", None)
    effective_api_key = self._get_effective_api_key(api_key)
    fingerprint = self._fingerprint(effective_api_key)
    provider_filter = provider or self.config.provider
    query_params = {key: value for key, value in params.items() if value is not None}
    cache_key = (fingerprint, provider_filter, self._cacheable_params(query_params))
    cached = self._identities.get(cache_key)
    if cached and not force_refresh:
        cached_at, identities = cached
        if datetime.now(timezone.utc) < (
            cached_at + timedelta(seconds=self.config.identity_cache_ttl_seconds)
        ):
            return identities

    token = await self._get_token(effective_api_key, fingerprint)
    if provider_filter:
        query_params["provider"] = provider_filter

    client = await self._get_client()
    response = await client.get(
        self._url(self.config.identities_path),
        headers={"Authorization": f"Bearer {token.value}"},
        params=query_params or None,
    )
    self._raise_for_status(response, "identity list")
    identities = [
        self._parse_identity(item) for item in self._extract_items(response.json())
    ]
    self._remember(
        self._identities,
        cache_key,
        (datetime.now(timezone.utc), identities),
    )
    return identities
```

Construct the shared identity model directly in `_parse_identity`:

```python
resolved_region = (
    item.get("region")
    or item.get("marketplace_region")
    or attributes.get("region")
    or attributes.get("marketplace_region")
)
for key, value in (
    ("provider", item.get("provider") or attributes.get("provider")),
    ("status", item.get("status") or attributes.get("status")),
    ("region", resolved_region),
    ("display_name", str(display_name) if display_name else None),
):
    if value is not None:
        merged.setdefault(key, value)
merged.setdefault("raw", item)
return Identity(
    id=str(identity_id),
    type=item.get("type") or "AmazonConnection",
    attributes=merged,
    relationships=relationships or None,
)
```

Construct the shared credential model directly in `_parse_credentials`:

```python
return AuthCredentials(
    identity_id=identity_id,
    access_token=access_token,
    token_type=self._first_string(data, "token_type") or "Bearer",
    expires_at=expires_at,
    base_url=base_url,
    headers=headers,
)
```

- [ ] **Step 4: Switch package registration and remove the adapter**

Change `src/amazon_ads_mcp/auth/providers/__init__.py` to:

```python
from .kuudo import KuudoAmazonAdsProvider
```

Delete `src/amazon_ads_mcp/auth/providers/kuudo_ads.py` using `apply_patch`. Do not add an alias module.

- [ ] **Step 5: Run consolidation tests and verify GREEN**

Run:

```bash
uv run pytest tests/unit/test_kuudo_provider.py tests/test_auth_providers.py -v
```

Expected: all tests pass, public methods return the shared Pydantic models, identity metadata remains under `attributes`, and Kuudo omits `identity_type`.

- [ ] **Step 6: Verify no adapter references remain**

Run:

```bash
rg -n "kuudo_ads|KuudoAuthProvider" src tests
```

Expected: no matches.

- [ ] **Step 7: Commit the consolidation**

```bash
git add src/amazon_ads_mcp/auth/providers/kuudo.py src/amazon_ads_mcp/auth/providers/__init__.py src/amazon_ads_mcp/auth/providers/kuudo_ads.py tests/unit/test_kuudo_provider.py tests/test_auth_providers.py
git commit -m "refactor: consolidate Kuudo auth provider"
```

---

### Task 2: Finalize the CodeQL-Safe Cache Fingerprint

**Files:**
- Modify: `src/amazon_ads_mcp/auth/providers/kuudo.py`
- Modify: `tests/unit/test_kuudo_provider.py`

**Interfaces:**
- Consumes: `KuudoAmazonAdsProvider._fingerprint(value: str) -> str` and the provider token/identity/credential caches.
- Produces: deterministic provider-local PBKDF2 fingerprints and `_get_token(effective_api_key: str, fingerprint: str) -> Token` for nested cache reuse.

- [ ] **Step 1: Correct the interrupted PBKDF2 regression to the approved work factor**

In `test_kuudo_fingerprint_uses_provider_local_salted_pbkdf2_sha256`, require:

```python
assert hash_name == "sha256"
assert password == "clïent-supplied-token".encode("utf-8")
assert salt == provider._fingerprint_salt
assert len(salt) == 32
assert provider._fingerprint_salt != second_provider._fingerprint_salt
assert iterations == 600_000
assert dklen == 32
assert fingerprint == derived_key.hex()
```

Retain the one-derivation tests for `list_identities` and `get_identity_credentials`, the same-instance/cross-instance test, and the cache-key raw-secret test.

- [ ] **Step 2: Run the fingerprint regression and verify RED**

Run:

```bash
uv run pytest tests/unit/test_kuudo_provider.py::test_kuudo_fingerprint_uses_provider_local_salted_pbkdf2_sha256 -v
```

Expected: FAIL because the interrupted implementation still uses 100,000 iterations.

- [ ] **Step 3: Implement the approved PBKDF2 parameters and single derivation path**

Use:

```python
self._fingerprint_salt = secrets.token_bytes(32)

def _fingerprint(self, value: str) -> str:
    return hashlib.pbkdf2_hmac(
        "sha256",
        value.encode("utf-8"),
        self._fingerprint_salt,
        600_000,
        dklen=32,
    ).hex()
```

The public token method derives once and delegates:

```python
async def get_token(self, api_key: str | None = None) -> Token:
    effective_api_key = self._get_effective_api_key(api_key)
    fingerprint = self._fingerprint(effective_api_key)
    return await self._get_token(effective_api_key, fingerprint)
```

Both `list_identities` and `get_identity_credentials` must call `_get_token(effective_api_key, fingerprint)` after deriving their cache key. Remove `hmac` imports and every `hmac.new` call.

- [ ] **Step 4: Run fingerprint and Kuudo tests and verify GREEN**

Run:

```bash
uv run pytest tests/unit/test_kuudo_provider.py -v
```

Expected: all Kuudo tests pass; each top-level miss derives once and no cache key contains the raw API key.

- [ ] **Step 5: Commit the security change**

```bash
git add src/amazon_ads_mcp/auth/providers/kuudo.py tests/unit/test_kuudo_provider.py
git commit -m "fix: strengthen Kuudo cache fingerprints"
```

---

### Task 3: Validate the Consolidated Provider

**Files:**
- Verify only; edit production code only for failures caused by Tasks 1-2.

**Interfaces:**
- Consumes: the sole provider implementation and all existing authentication/tool consumers.
- Produces: validation evidence suitable for the PR handoff.

- [ ] **Step 1: Install the locked environment**

Run:

```bash
uv sync
```

Expected: dependency synchronization succeeds without lockfile changes.

- [ ] **Step 2: Run focused auth and routing tests**

Run:

```bash
uv run pytest tests/unit/test_kuudo_provider.py tests/test_auth_providers.py tests/unit/test_region_tools.py tests/unit/test_inbound_auth.py -v
```

Expected: all selected tests pass.

- [ ] **Step 3: Run required lint with autofix**

Run:

```bash
uv run ruff check --fix
```

Expected: Ruff reports no remaining errors. Review any autofix before continuing.

- [ ] **Step 4: Run the full suite**

Run:

```bash
uv run pytest
```

Expected: the full suite passes; existing warnings may remain unchanged.

- [ ] **Step 5: Verify source and diff invariants**

Run:

```bash
rg -n "kuudo_ads|KuudoAuthProvider|hmac\.new|hashlib\.sha256" src/amazon_ads_mcp/auth/providers tests
git diff --check
git status --short
```

Expected: no forbidden provider/hash references, no whitespace errors, and only intentional artifacts remain untracked.

- [ ] **Step 6: Push and verify CodeQL**

Push the current feature branch, then confirm the PR reruns `py/weak-sensitive-data-hashing` against the PBKDF2 implementation. If GitHub CLI authentication remains unavailable, report that CodeQL verification is pending the remote check while retaining the local source evidence.
