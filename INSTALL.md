
## Install The MCP Server: Choose your preferred installation method

### Path 1: Run with Python (Recommended for Development)

#### Prerequisites:
- Python 3.10 or higher
- Amazon Ads API access or Ads API Partner Provider (i.e. Openbridge)
- (Optional) `uv` for dependency management

#### Installation:

**Option A: Using uv (Recommended)**
```bash
# Install uv if you haven't already
curl -LsSf https://astral.sh/uv/install.sh | sh

# Clone the repository
git clone https://github.com/KuudoAI/amazon-ads-mcp.git
cd amazon-ads-mcp

# Install dependencies with uv
uv venv
uv sync

# Configure credentials and packages before starting
export AUTH_METHOD=direct
export AMAZON_AD_API_CLIENT_ID="your-client-id"
export AMAZON_AD_API_CLIENT_SECRET="your-client-secret"
export AMAZON_AD_API_REFRESH_TOKEN="your-refresh-token"
export AMAZON_ADS_REGION="na"  # Options: na, eu, fe
export AMAZON_AD_API_PACKAGES="profiles,accounts-ads-accounts,reporting-version-3,ads-api-v1-all"

# Run the server (stdio mode for Claude Desktop)
uv run python -m amazon_ads_mcp.server

# Or run with HTTP transport
uv run python -m amazon_ads_mcp.server --transport http --port 9080
```

**Option B: Using pip**
```bash
# Clone the repository
git clone https://github.com/KuudoAI/amazon-ads-mcp.git
cd amazon-ads-mcp

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install from pyproject.toml with the Code Mode sandbox runtime
pip install ".[code-mode]"

# Configure credentials and packages before starting
export AUTH_METHOD=direct
export AMAZON_AD_API_CLIENT_ID="your-client-id"
export AMAZON_AD_API_CLIENT_SECRET="your-client-secret"
export AMAZON_AD_API_REFRESH_TOKEN="your-refresh-token"
export AMAZON_ADS_REGION="na"  # Options: na, eu, fe
export AMAZON_AD_API_PACKAGES="profiles,accounts-ads-accounts,reporting-version-3,ads-api-v1-all"

# Run the server (stdio mode for Claude Desktop)
python -m amazon_ads_mcp.server

# Or run with HTTP transport
python -m amazon_ads_mcp.server --transport http --port 9080
```

If you install without the `code-mode` extra, startup still succeeds. When
`CODE_MODE=true` and the sandbox runtime is missing, the server logs a warning
and exposes the full tool catalog. Set `CODE_MODE=false` to make that full
catalog behavior explicit.

### Path 2: Run with Docker (Recommended for Production)

#### Prerequisites:
- 🐳 Docker and Docker Compose
- Amazon Ads API access or Ads API Partner Provider (i.e. Openbridge)

#### Installation:

```bash
# Clone the repository
git clone https://github.com/KuudoAI/amazon-ads-mcp.git
cd amazon-ads-mcp

# Copy the environment template
cp .env.example .env

# Edit .env with your credentials
# Set your Amazon Ads API credentials in .env file

# Start the server with Docker Compose
docker compose up -d

# The server will be available at http://localhost:9080 (see `PORT` in `.env`)
# Check logs
docker compose logs -f

# Stop the server
docker compose down
```

**Quick Docker Run (without compose):**
```bash
# Build the image
docker build -t amazon-ads-mcp .

# Run the container
docker run -d \
  --name amazon-ads-mcp \
  -p 9080:9080 \
  -e AUTH_METHOD=direct \
  -e AMAZON_AD_API_CLIENT_ID="your-client-id" \
  -e AMAZON_AD_API_CLIENT_SECRET="your-client-secret" \
  -e AMAZON_AD_API_REFRESH_TOKEN="your-refresh-token" \
  -e AMAZON_ADS_REGION="na" \
  -e AMAZON_AD_API_PACKAGES="profiles,accounts-ads-accounts,reporting-version-3,ads-api-v1-all" \
  amazon-ads-mcp
```

---
## 🔐 Authentication



### 2. Configure Your MCP Server

Set the following environment variables:

```bash
# Direct Amazon Ads authentication
export AUTH_METHOD=direct
export AMAZON_AD_API_CLIENT_ID="your-client-id"
export AMAZON_AD_API_CLIENT_SECRET="your-client-secret"

# Optional: a pre-authorized server-owner refresh token. Without it the
# server still starts — authenticate at runtime with the built-in OAuth
# tools (start_oauth_flow / check_oauth_status), which persist the token
# they obtain.
export AMAZON_AD_API_REFRESH_TOKEN="your-refresh-token"

# Region Configuration (optional, defaults to "na")
export AMAZON_ADS_REGION="na"  # Options: na, eu, fe

# API packages to expose as MCP tools
export AMAZON_AD_API_PACKAGES="profiles,accounts-ads-accounts,reporting-version-3,ads-api-v1-all"
```

Package notes:
- `reporting-version-3` exposes report tools such as `rp_createAsyncReport`
  and `rp_getAsyncReport`.
- `ads-api-v1-all` exposes merged v1 report tools such as
  `allv1_AdsApiv1CreateReport`.
- `ads-api-v1-sp` and `ads-api-v1-sb` expose product-specific v1 tools with
  `spv1_` and `sbv1_` prefixes.



The token process follows typical token exchange workflows:

```
  ┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐    ┌─────────────────┐
  │   AI Client     │    │   MCP Server     │    │   OpenBridge    │    │  Amazon Ads     │
  │  (Claude, GPT)  │    │  (This SDK)      │    │     API         │    │     API         │
  └────────┬────────┘    └────────┬─────────┘    └─────────┬───────┘    └─────────┬───────┘
           │                      │                        │                      │
           │ 1. Request Tool      │                        │                      │
           ├─────────────────────►│                        │                      │
           │   (e.g., list        │                        │                      │
           │    profiles)         │                        │                      │
           │                      │                        │                      │
           │                      │ 2. Check Auth          │                      │
           │                      ├──────┐                 │                      │
           │                      │      │                 │                      │
           │                      │◄─────┘                 │                      │
           │                      │ (needs token)          │                      │
           │                      │                        │                      │
           │                      │ 3. Request Bearer      │                      │
           │                      │    Token               │                      │
           │                      ├───────────────────────►│                      │
           │                      │ POST /openbridge/      │                      │
           │                      │   identities/{id}/     │                      │
           │                      │   auth/token           │                      │
           │                      │                        │                      │
           │                      │                        │ 4. Fetch/Refresh     │
           │                      │                        │    Amazon Token      │
           │                      │                        ├─────────────────────►│
           │                      │                        │  (if needed)         │
           │                      │                        │                      │
           │                      │                        │◄─────────────────────┤
           │                      │                        │  LWA Access Token    │
           │                      │                        │                      │
           │                      │◄───────────────────────┤                      │
           │                      │ 5. Return JWT          │                      │
           │                      │ {                      │                      │
           │                      │   "access_token":      │                      │
           │                      │     "eyJhbGc...",      │                      │
           │                      │   "expires_in": 3600,  │                      │
           │                      │   "token_type":"Bearer"│                      │
           │                      │ }                      │                      │
           │                      │                        │                      │
           │                      │ 6. Extract Headers     │                      │
           │                      ├──────┐                 │                      │
           │                      │      │ Decode JWT      │                      │
           │                      │◄─────┘ payload:        │                      │
           │                      │  - Authorization       │                      │
           │                      │  - ClientId            │                      │
           │                      │  - Scope/ProfileId     │                      │
           │                      │                        │                      │
           │                      │ 7. Call Amazon Ads API │                      │
           │                      ├────────────────────────┼─────────────────────►│
           │                      │ Headers:               │                      │
           │                      │ - Authorization: Bearer {LWA_token}           │
           │                      │ - Amazon-Advertising-API-ClientId: {client}   │
           │                      │ - Amazon-Advertising-API-Scope: {profile}     │
           │                      │                        │                      │
           │                      │◄───────────────────────┼──────────────────────┤
           │                      │ 8. API Response        │                      │
           │                      │                        │                      │
           │◄─────────────────────┤                        │                      │
           │ 9. Return Result     │                        │                      │
           │                      │                        │                      │
```


### Token Persistence

> **🔒 Security**: Token persistence is **disabled by default**. When enabled, tokens are **encrypted** using Fernet symmetric encryption (AES-128).

- **Disabled by default** - Tokens are kept in memory only (requires re-authentication on restart)
- **To enable persistence**: Set `AMAZON_ADS_TOKEN_PERSIST=true`
- **Encryption**: Tokens are encrypted at rest using:
  - Fernet symmetric encryption (requires `cryptography` library)
  - Machine-specific key derivation (PBKDF2-HMAC-SHA256)
  - Optional custom key via `AMAZON_ADS_ENCRYPTION_KEY` environment variable
- **Storage location** (when enabled):
  - Docker: `/app/.cache/amazon-ads-mcp/tokens.json`
  - Local: `~/.amazon-ads-mcp/tokens.json`
- **Custom cache directory**: Set `AMAZON_ADS_CACHE_DIR=/path/to/cache`

**Security Requirements**:

For **Development/Local**:
- Machine-specific keys are automatically generated (convenience only)
- Install `cryptography`: `pip install cryptography`

For **Production**:
- **REQUIRED**: Set `AMAZON_ADS_ENCRYPTION_KEY` with a secure key
- Generate a key: `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`
- Store the key securely (AWS Secrets Manager, HashiCorp Vault, etc.)
- Never commit encryption keys to version control

**Security Controls**:
- Missing `cryptography` library will **refuse** to persist tokens unless `AMAZON_ADS_ALLOW_PLAINTEXT_PERSIST=true` (not recommended)
- Invalid encryption keys trigger warnings and fallback to machine-derived keys
- Production environments (`ENV=production`) issue warnings when using machine-derived keys
