# Kuudo Sole Provider Design

## Goal

Make `src/amazon_ads_mcp/auth/providers/kuudo.py` the complete and only Kuudo
provider module. Remove the adapter module and duplicate authentication models
while preserving the current registry, identity, token-vending, region-routing,
and cache behavior.

## Chosen Architecture

`kuudo.py` will follow the same project-native pattern as `direct.py` and
`openbridge.py`:

- Import the shared `Token`, `Identity`, and `AuthCredentials` models.
- Subclass `BaseAmazonAdsProvider` and `BaseIdentityProvider` directly.
- Register `KuudoAmazonAdsProvider` with `@register_provider("kuudo")`.
- Own all Kuudo configuration, HTTP behavior, parsing, caching, and model
  construction in that class.
- Export the registered provider from `auth/providers/__init__.py` using
  `.kuudo`.
- Delete `kuudo_ads.py` without a compatibility shim.

The generic `KuudoAuthProvider` layer and its local dataclass copies will be
removed. This PR introduces Kuudo, so no released compatibility surface needs
to be preserved.

## Model Mapping

Kuudo identity metadata that does not have a dedicated field in the shared
`Identity` model will remain available under `Identity.attributes`. Provider,
status, region, display name, and raw response metadata will preserve the
current project-facing response shape.

Token vending will return the shared `AuthCredentials` model directly. The
provider will continue to calculate the regional base URL and complete Amazon
Ads headers before constructing that model.

## Credential Cache Fingerprint

The consolidated provider will replace HMAC-SHA-256 with a provider-local,
salted PBKDF2-HMAC-SHA-256 derivation so CodeQL recognizes the credential input
as passing through a password-oriented KDF. The derivation will use a random
32-byte salt, 100,000 iterations, and a 32-byte result.

Identity and credential cache misses currently derive the fingerprint twice
because they call the public token method after calculating their own cache
key. A private token helper will accept the already-derived fingerprint so
each top-level operation performs at most one derivation. Raw client API keys
will remain absent from cache keys.

## Error Handling

Existing Kuudo configuration, HTTP, payload-validation, identity-ID, and
expiration errors will retain their current exception types and messages.
Consolidation will not broaden fallback behavior or suppress malformed Kuudo
responses.

## Testing

Regression tests will prove:

- The registry resolves `kuudo` to the class defined in `kuudo.py`.
- No code imports `kuudo_ads`, and the file is removed.
- Public methods return the shared project models directly.
- Identity metadata and credential headers retain their current shape.
- The PBKDF2 parameters, provider-local salt, deterministic instance behavior,
  and cross-instance separation are correct.
- Each identity or credential cache miss derives one fingerprint.
- No raw API key is retained in cache keys.
- The existing Kuudo, provider-registry, region, inbound-auth, lint, and full
  test suites remain green.

## Rejected Alternatives

- Keeping `kuudo_ads.py`: preserves the architecture violation.
- Moving the adapter class into `kuudo.py` while retaining duplicate models:
  reduces file count but preserves unnecessary conversion layers.
- Keeping HMAC and dismissing CodeQL: cryptographically reasonable for a
  high-entropy M2M key, but leaves the PR alert open.
