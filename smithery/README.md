# Smithery publishing

Publish `kuudoai/amazon-ads` as an external HTTP server at `https://ads.kuudo.com/mcp`.

The public Python implementation in this repository is the older FastMCP 3 server. The hosted endpoint runs the separately maintained FastMCP 4 service. Publish the hosted URL, not this repository’s runtime, for this listing.

## Authentication

Users supply their own Kuudo API key as `Bearer sk_...`. The schema reads
`kuudo-api-key` and forwards its entire value to the upstream `Authorization`
header. Smithery reserves inbound `Authorization` for its own authentication.
There is no automatic Bearer prefix insertion: include it in the entered value.
Never put keys in URLs, schema defaults, release files, or repository content.

`server.json` at the repository root targets the MCP Registry; it is not a
Smithery deployment payload. `config.schema.json` is the Smithery configuration
schema, and `release.json` embeds the same schema for the publishing API. Keep
the two schema copies identical when updating authentication instructions.

## Publish

Authenticate the Smithery CLI, then run from this repository root:

```sh
smithery mcp publish 'https://ads.kuudo.com/mcp' \
  -n kuudoai/amazon-ads \
  --config-schema smithery/config.schema.json
```

For the API, submit `release.json` as the multipart `payload` field to
`PUT /servers/kuudoai%2Famazon-ads/releases`, after creating the server listing.
Use this repository URL as the listing's `repositoryUrl`. Authentication to
Smithery uses the operator's Smithery credential, not a Kuudo API key.

## Discovery prerequisite

Publishing is not complete until the release succeeds and the public listing
shows the deployed tools. The hosted service requires a bearer key; a 401 alone
can cause Smithery's scanner to attempt OAuth discovery. Providing this config
schema does not by itself fix that behavior.

Before publishing, serve a public metadata-only card at
`https://ads.kuudo.com/.well-known/mcp/server-card.json`. Populate it from the
actual hosted MCP initialization and discovery responses, with authentication
required and the bearer scheme. Do not use the catalog stub's tool list or
empty argument schemas to describe the live service. The card must contain no
credentials, account data, or tool execution results. `/mcp` remains protected.

The edge card is deployed separately in `KuudoAI/deployment`. This PR does not
deploy it, enable OAuth, or assert that the Smithery release is live. If Smithery
still requires authorization after the card is available, inspect the release
logs; do not disable server authentication to complete the scan.

After publishing, verify public tool metadata and test a separate connection
with a user-provided key. Anonymous tool execution must still fail.

References: [Publish](https://smithery.ai/docs/build/publish),
[Session configuration](https://smithery.ai/docs/build/session-config),
[Publishing API](https://smithery.ai/docs/api-reference/servers/publish-a-server).
