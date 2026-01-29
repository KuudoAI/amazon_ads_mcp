# Amazon Ads MCP Development Guidelines

> **Audience**: LLM-driven engineering agents and human developers

Amazon Ads MCP is a Python framework (Python ≥3.10) for integrating Amazon Advertising API with Model Context Protocol (MCP) servers. This project provides a complete toolkit for building AI-powered advertising applications with comprehensive campaign management, reporting, and optimization capabilities.

## Do This First (for Agents)

- Ensure Python ≥3.10 and uv are installed
- `uv sync` to install dependencies
- Start the server: `docker-compose up -d`
- Connect Claude to the MCP server (HTTP):
  - `claude mcp add amazon-ads-mcp -- python -m amazon_ads_mcp.server.mcp_server --transport http --port 9080`
- Verify: `claude mcp list` and use `/mcp` inside Claude

## Required Development Workflow

**CRITICAL**: Always run these commands in sequence before committing:

```bash
# Install dependencies
uv sync                              # Install dependencies

# Validate code
uv run ruff check --fix             # Lint and auto-fix
uv run pytest                        # Run full test suite
```

**All must pass** - tests/linting must be clean before committing.

## Agent Ops (LLM Guidance)

- Preambles: Send a brief 1–2 sentence note before running tool commands.
- Plans: Use `TodoWrite` for multi-step work; keep exactly one `in_progress` step.
- Edits: Use `Edit` or `MultiEdit` to modify files; keep changes focused and avoid unrelated edits.
- Testing: Run the smallest relevant tests first; do not fix unrelated failures.
- Sandboxing: Assume workspace-write FS and restricted network; prefer local resources over external APIs unless keys are present.

## Agent Success Playbook

Follow these steps for reliable outcomes in Claude contexts:

1) Understand & Plan
- Clarify task type: API integration, MCP connectivity, Docker, tests, or GitHub workflow.
- Post a short preamble and, for multi-step work, create a minimal `TodoWrite` with exactly one `in_progress` step.

2) Connect & Verify (MCP + Server)
- Start server: `docker-compose up -d` (Amazon Ads MCP at `http://localhost:9080`).
- Add MCP to Claude (HTTP):
  - `claude mcp add amazon-ads-mcp -- python -m amazon_ads_mcp.server.mcp_server --transport http --port 9080`
- Verify in Claude: `claude mcp list` then `/mcp` → run a tool (e.g., list profiles).

3) Implement Safely
- Prefer the smallest viable change; touch only relevant files.
- Use `Edit` or `MultiEdit` for edits. Only run `git` if explicitly requested.
- Keep environment secrets out of logs; mask sensitive data.

4) Test Incrementally
- Lint: `uv run ruff check --fix`.
- Targeted tests first: `uv run pytest tests/unit/test_specific.py`.
- Full suite if needed: `uv run pytest`.

5) Validate Behavior
- For MCP changes: exercise tools via `/mcp` in Claude.
- For Docker changes: `docker build -t amazon-ads-mcp .` and check logs.

6) Prepare Handoff
- If commits are requested: propose a branch name and show the exact commands; otherwise provide patch summary and affected files.
- Summarize changes, risks, and next steps in your final message.

Guardrails (Never Do)
- Do not push to `main` or force-push; avoid branch deletions.
- Do not log secrets (API keys, tokens) or large payloads.
- Do not widen scope or refactor unrelated code.

Escalation Prompts (When Blocked)
- "I need permission to run networked commands/install packages; approve or provide offline alternative?"
- "Tests rely on external API keys; provide keys or allow me to skip/mark accordingly?"
- "MCP output exceeds token limits; can I raise `MAX_MCP_OUTPUT_TOKENS`?"

Claude Command Cheatsheet
- List servers: `claude mcp list`
- Add server (HTTP): `claude mcp add amazon-ads-mcp -- python -m amazon_ads_mcp.server.mcp_server --transport http --port 9080`
- In-session MCP menu: `/mcp`
- Read files: `/read <path>`; Edit files: `/edit <path>`

## Repository Structure

| Path             | Purpose                                                |
| ---------------- | ------------------------------------------------------ |
| `src/amazon_ads_mcp/`| Library source code (Python ≥ 3.10)                |
| `├─server/`      | MCP server implementation and FastMCP integration     |
| `├─auth/`        | Authentication providers (Direct, Openbridge)         |
| `├─tools/`       | Amazon Ads tool implementations                       |
| `├─models/`      | Pydantic models for API responses                     |
| `├─middleware/`  | Authentication, OAuth, and sampling middleware        |
| `└─utils/`       | HTTP client, OpenAPI handling, security utilities     |
| `openapi/`       | OpenAPI specifications and transformations            |
| `├─resources/`   | Individual API resource definitions                   |
| `tests/`         | Pytest test suite                                     |
| `examples/`      | Example usage and demo scripts                        |
| `docker-compose.yml` | Docker service configuration                      |

## Claude / MCP Connectivity

- Amazon Ads MCP Server:
  - The MCP server runs on `localhost:9080` (HTTP transport).
  - It connects to Amazon Ads API with proper authentication.
- Quick connect from host:
  - `claude mcp add amazon-ads-mcp -- python -m amazon_ads_mcp.server.mcp_server --transport http --port 9080`
- Verification:
  - `claude mcp list` to check health
  - In Claude, run `/mcp` and call a tool (e.g., list profiles, get campaigns)

## Core Amazon Ads Operations

When modifying Amazon Ads functionality, changes typically affect:

- **Campaigns** (`cp_*` tools for campaign management)
- **Profiles** (Multi-account management and switching)
- **Reporting** (`reporting_*` tools for performance metrics)
- **DSP** (`dsp_*` tools for programmatic advertising)
- **AMC** (`amc_*` tools for Amazon Marketing Cloud)
- **Authentication** (OAuth flows, token management)
- **File Downloads** (HTTP download routes for exports and reports)

## File Downloads (HTTP Data Plane)

The MCP server provides HTTP endpoints for downloading exported files. This separates the control plane (MCP tools) from the data plane (HTTP file serving).

### Architecture

```
MCP Tools (Control Plane)          HTTP Routes (Data Plane)
─────────────────────────          ────────────────────────
list_downloads()          ──▶      GET /downloads
get_download_url()        ──▶      GET /downloads/{path}
download_export()         ──▶      Saves to profile-scoped storage
```

### Profile-Scoped Storage

All downloaded files are stored under profile-specific directories:

```
data/
├── profiles/
│   ├── {profile_id_1}/
│   │   ├── exports/campaigns/
│   │   └── reports/async/
│   └── {profile_id_2}/
│       └── ...
```

### Download Workflow

1. **Download a report**: Use `request_and_download_report` or `download_export`
2. **List available files**: Use `list_downloads` tool
3. **Get download URL**: Use `get_download_url` tool
4. **Download via HTTP**: Open URL in browser or use curl

### HTTP Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/downloads` | GET | List all files with download URLs |
| `/downloads/{path}` | GET | Download a specific file |
| `/downloads?type=reports` | GET | Filter by resource type |

### Security Features

- **Profile isolation**: Files scoped to active profile only
- **Path traversal prevention**: `Path.relative_to()` validation
- **Bearer token auth**: Optional `AMAZON_ADS_DOWNLOAD_AUTH_TOKEN`
- **Sensitive file blocking**: `.env`, credentials, keys blocked
- **Size limits**: Configurable max file size

## Writing Style

- Be brief and to the point. Focus on what the code does, not extensive explanations.
- **NEVER** use "This isn't..." or "not just..." constructions. State what something IS directly.
- When documenting Amazon Ads operations, focus on the API aspects and MCP integration.

## Testing Best Practices

### Amazon Ads-Specific Testing

- Mock external API calls for unit tests
- Use integration tests sparingly (require real credentials)
- Test authentication flows thoroughly
- Verify region routing works correctly
- Test error handling for API rate limits

### Test Structure

```python
import pytest
from amazon_ads_mcp.auth import AuthManager

async def test_auth_flow():
    auth_manager = AuthManager()
    token = await auth_manager.get_access_token(
        profile_id="test_profile"
    )
    assert token is not None
    # Clean up
    await auth_manager.cleanup()
```

### Docker Testing

```bash
# Build and test Docker image
docker build -t amazon-ads-mcp .
docker run --rm amazon-ads-mcp python -c "from amazon_ads_mcp import __version__; print('OK')"
```

## Troubleshooting MCP Connectivity

- Symptom: `Failed to connect http://localhost:9080`
  - Cause: Server not running or port mismatch.
  - Fix: Check `docker-compose up -d` and verify port mapping.
- Check Docker: `docker ps` should show `amazon-ads-mcp` on port 9080.
- Increase logs: Set debug environment variables in docker-compose.yml.

## Development Rules

### OpenAPI Management

- OpenAPI specs in `openapi/resources/` define available operations
- Run processing scripts after spec updates
- Use transformation files for customization
- Minify specs for production deployment

### Docker Workflow

```bash
# Step 1: Build Docker image
docker-compose build

# Step 2: Run container
docker-compose up -d

# Step 3: View logs
docker-compose logs -f
```

### Running the MCP Server

```bash
# Direct run with uv
uv run python -m amazon_ads_mcp.server.mcp_server --transport http --port 9080

# With Docker
docker-compose up -d
```

### Environment Variables

```bash
# Authentication
export AMAZON_ADS_AUTH_METHOD="direct"  # or "openbridge"
export AMAZON_ADS_CLIENT_ID="your-client-id"
export AMAZON_ADS_CLIENT_SECRET="your-client-secret"
export AMAZON_ADS_REFRESH_TOKEN="your-refresh-token"

# For Openbridge
export OPENBRIDGE_API_KEY="your-api-key"
export OPENBRIDGE_ACCOUNT_ID="your-account-id"

# Server configuration
export TRANSPORT="http"  # or "stdio"
export HOST="0.0.0.0"
export PORT="9080"
```

### MCP-Related Environment Variables

```bash
# MCP runtime behavior
export MCP_TIMEOUT=300
export MAX_MCP_OUTPUT_TOKENS=25000
export MCP_MASK_ERROR_DETAILS=true
export MCP_ON_DUPLICATE_TOOLS=warn
```

### File Download Environment Variables

```bash
# Download authentication (optional - if unset, auth is disabled)
export AMAZON_ADS_DOWNLOAD_AUTH_TOKEN="your-secret-token"

# Maximum file size for downloads (default: 512MB)
export AMAZON_ADS_DOWNLOAD_MAX_FILE_SIZE=536870912

# Allowed file extensions (optional whitelist, comma-separated)
export AMAZON_ADS_DOWNLOAD_ALLOWED_EXTENSIONS=".json,.csv,.txt,.gz"

# Base download directory (default: ./data)
export AMAZON_ADS_DOWNLOAD_DIR="./data"
```

### Security-Related Environment Variables

```bash
# Token Persistence (disabled by default for security)
# When false (default): Tokens stored in memory only, lost on restart
# When true: Refresh tokens cached to disk/volume, persist across restarts
export AMAZON_ADS_TOKEN_PERSIST="false"  # Set to "true" to enable persistence

# Token Encryption (required when AMAZON_ADS_TOKEN_PERSIST=true)
# If not set, a random key is auto-generated and stored alongside tokens
# For production: Generate with `python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"`
export AMAZON_ADS_ENCRYPTION_KEY="your-44-char-base64-key"

# Plaintext Storage (INSECURE - testing only!)
# Only enable if cryptography library is unavailable AND you accept the risk
export AMAZON_ADS_ALLOW_PLAINTEXT_PERSIST="false"  # Never set to "true" in production
```

**Security Implications of Token Persistence:**

When `AMAZON_ADS_TOKEN_PERSIST=true`:
- ✅ Convenience: Refresh tokens survive container restarts (no re-authentication)
- ⚠️ Risk: Tokens are encrypted but stored with their decryption key on same volume
- ⚠️ Risk: Anyone with filesystem/volume access can potentially extract tokens
- 🔒 Mitigation: Set `AMAZON_ADS_ENCRYPTION_KEY` from external secrets manager
- 🔒 Best Practice: Use in-memory storage (default) unless persistence is required

**Recommended Configurations:**

```bash
# Development (local laptop): In-memory is usually sufficient
AMAZON_ADS_TOKEN_PERSIST=false

# Shared/Production: Either in-memory OR persistence with external key
AMAZON_ADS_TOKEN_PERSIST=false  # Preferred if feasible
# OR
AMAZON_ADS_TOKEN_PERSIST=true
AMAZON_ADS_ENCRYPTION_KEY=${VAULT_SECRET}  # From secrets manager
```

### Code Standards

- Python ≥ 3.10 with full type annotations
- Use Pydantic for data models
- Follow Amazon Ads API patterns
- Security-first approach for credentials
- Efficient pagination for large result sets

### Commit Messages

- Reference Amazon Ads operations explicitly (e.g., "fix: campaign creation with targeting")
- Mention OpenAPI updates when relevant
- Include Docker changes if applicable
- Keep messages brief and focused

## GitHub Workflow (Branches, PRs, Merges)

### Branching Strategy

- Default branch is `main` (protected). Do not push directly to `main`.
- Create focused branches using kebab-case:
  - `feat/<area>-<short-desc>` (new capability)
  - `fix/<area>-<short-desc>` (bug fix)
  - `docs/<topic>` (documentation only)
  - `chore/<task>` (infra, deps, refactors)
- Optionally append issue ID: `feat/auth-oauth-flow-#123`.

### Commit Conventions

- Use Conventional Commits for clear history and automatic versioning:
  - `feat: ...` - New feature (triggers minor version bump)
  - `fix: ...` - Bug fix (triggers patch version bump)
  - `feat!: ...` or `BREAKING CHANGE:` - Breaking change (triggers major version bump)
  - `docs: ...` - Documentation only
  - `refactor: ...` - Code restructuring
  - `test: ...` - Adding tests
  - `chore: ...` - Maintenance tasks
  - `perf: ...` - Performance improvements
  - `ci: ...` - CI/CD changes
- Keep commits small and atomic; reference issues (e.g., `Closes #123`).

#### Commit Examples for Automatic Versioning
```bash
# Patch version bump (0.1.0 → 0.1.1)
git commit -m "fix: resolve token refresh issue"
git commit -m "fix: handle empty response from API"

# Minor version bump (0.1.0 → 0.2.0)
git commit -m "feat: add new authentication method"
git commit -m "feat: implement batch operations for campaigns"

# Major version bump (0.1.0 → 1.0.0)
git commit -m "feat!: redesign API interface (BREAKING CHANGE)"
git commit -m "feat: new auth system

BREAKING CHANGE: removed support for v1 authentication"
```

**Note**: Pushes to `main` automatically trigger releases based on commit messages.

### Pull Requests

- Open PRs early as Drafts; mark Ready when CI is green and reviews addressed.
- PR title follows Conventional Commit style (used for squash-merge title).
- Include in description:
  - Context/motivation and linked issues
  - Summary of changes (user-visible + internal)
  - Testing steps and results (commands, screenshots/log excerpts as needed)
  - Risk assessment and rollback plan
- Apply labels: `area:*`, `semver:*` (patch/minor/major), `type:*` (feat/fix/docs).

PR Checklist:

- [ ] `uv run ruff check --fix` clean
- [ ] `uv run pytest` green (or targeted subset justified)
- [ ] Docker builds if relevant (`docker build -t amazon-ads-mcp .`)
- [ ] Docs updated (README/AGENTS) if behavior changes

### Merging Policy

- Prefer Squash & Merge to keep a tidy history; ensure the squash title is a good Conventional Commit.
- Rebase from `main` before merging; resolve conflicts locally.
- Require at least one approval; two for high-risk changes (auth, API operations).

## Key Tools & Commands

### Environment Setup with uv

```bash
git clone <repo>
cd amazon-ads-mcp
uv sync
```

### Validation Commands

- **Linting**: `uv run ruff check --fix`
- **Type Checking**: `uv run mypy src/`
- **Testing**: `uv run pytest`
- **Coverage**: `uv run pytest --cov=amazon_ads_mcp`

### Docker Commands

```bash
# Build image
docker build -t amazon-ads-mcp .

# Run with docker-compose
docker-compose up -d

# Check logs
docker-compose logs -f

# Shell into container
docker exec -it amazon-ads-mcp /bin/bash
```

## Error Recovery Patterns

### Common Errors & Quick Fixes

#### MCP Connection Failed
```bash
# Error: "Failed to connect to MCP server" or "Connection refused"
# Recovery steps:
docker ps | grep amazon-ads                # Check if container running
docker-compose restart                     # Restart container
docker logs amazon-ads-mcp --tail 50      # Check for startup errors

# If still failing:
docker-compose down && docker-compose up -d
claude mcp list                           # Verify MCP connection
```

#### Authentication Errors
```bash
# Error: "401 Unauthorized" or "Invalid refresh token"
# Check environment variables
docker-compose exec amazon-ads-mcp env | grep AMAZON_ADS

# Test authentication directly
uv run python -c "
from amazon_ads_mcp.auth import AuthManager
auth = AuthManager()
print(auth.test_connection())
"
```

#### Test Failures
```bash
# Error: "FAILED tests/test_auth.py::test_oauth_flow"
# Debug approach:
uv run pytest -xvs tests/test_auth.py::test_oauth_flow  # Run single test verbose
uv run pytest --pdb tests/test_auth.py    # Drop into debugger on failure
```

#### Docker Build Failures
```bash
# Error: "failed to solve: executor failed running"
docker system prune -f                    # Clean Docker cache
docker build --no-cache -t amazon-ads-mcp .  # Force rebuild
```

## Performance Benchmarks

### Expected Timings (M1/M2 Mac, 16GB RAM)

| Operation | Expected Time | Warning Threshold | Action if Slow |
|-----------|--------------|-------------------|----------------|
| Docker Build | 2-3 min | >5 min | Clean Docker cache, check network |
| Unit Tests | 5-10s | >30s | Run subset, check fixtures |
| Integration Tests | 20-40s | >90s | Mock external calls |
| API Call (single) | <500ms | >2s | Check network, API throttling |
| Bulk Operation (100 items) | <5s | >15s | Use batch API endpoints |
| MCP Tool Call | <1s | >3s | Check payload size |

### Performance Quick Checks
```bash
# Profile slow tests
uv run pytest --durations=10

# Check Docker resource usage
docker stats amazon-ads-mcp --no-stream

# Monitor MCP response time
time claude mcp list
```

## Debug Commands Toolkit

### Amazon Ads API Health Checks
```bash
# Test API connectivity
curl -H "Amazon-Advertising-API-ClientId: $AMAZON_ADS_CLIENT_ID" \
     -H "Authorization: Bearer $ACCESS_TOKEN" \
     https://advertising-api.amazon.com/v2/profiles

# Check rate limits
uv run python -c "
from amazon_ads_mcp.utils import check_rate_limits
check_rate_limits()
"
```

### MCP Server Debugging
```bash
# Run MCP in debug mode
DEBUG=true uv run python -m amazon_ads_mcp.server.mcp_server

# Test MCP server directly
echo '{"jsonrpc":"2.0","method":"tools/list","id":1}' | \
  uv run python -m amazon_ads_mcp.server.mcp_server | jq

# Check registered tools
uv run python -c "
from amazon_ads_mcp.server import get_registered_tools
print(get_registered_tools())
"
```

### Environment Verification
```bash
# Check all required env vars
uv run python -c "
import os
required = ['AMAZON_ADS_CLIENT_ID', 'AMAZON_ADS_CLIENT_SECRET']
for var in required:
    val = os.getenv(var, 'NOT SET')
    print(f'{var}: {\"SET\" if val != \"NOT SET\" else \"NOT SET\"}')
"

# Verify Python and package versions
python --version
uv pip show amazon-ads-mcp | grep Version
```

## File Modification Safety Guide

### Safe to Modify (Core Development)
```
src/amazon_ads_mcp/**/*.py  # Main application code
tests/**/*.py               # Test files
openapi/resources/*.json   # API specifications
.env                       # Local environment (never commit)
examples/*.py              # Example scripts
```

### Generated/Cache (Don't Edit - Will Be Overwritten)
```
dist/*                     # Build artifacts
*.egg-info/*              # Package metadata
__pycache__/*            # Python bytecode
.pytest_cache/*          # Test cache
.ruff_cache/*            # Linter cache
.mypy_cache/*            # Type checker cache
```

### Modify with Caution (Coordinate Changes)
```
pyproject.toml            # Dependencies & metadata
Dockerfile               # Build process (test locally first)
docker-compose.yml       # Service configuration
.github/workflows/*      # CI/CD (test in fork first)
openapi/resources/*.transform.json  # API transformations
```

## Common Issues & Solutions

1. **Authentication fails**: Check environment variables and refresh token
2. **Region routing errors**: Verify profile region settings
3. **Docker build fails**: Ensure all dependencies in requirements.txt
4. **Import errors**: Run `uv sync` to install dependencies
5. **Rate limit errors**: Implement exponential backoff
6. **MCP timeout**: Increase `MCP_TIMEOUT` environment variable
7. **File download 401**: Set `AMAZON_ADS_DOWNLOAD_AUTH_TOKEN` or check Bearer token
8. **File download 404**: Verify active profile with `get_active_profile`, file may be in different profile
9. **Download "No active profile"**: Call `set_active_profile` before downloading files

## Performance Optimization

- Use batch operations for bulk API calls
- Implement caching for frequently accessed data
- Configure connection pooling for HTTP clients
- Use pagination efficiently for large result sets
- Minimize OpenAPI spec size in production

## Testing Checklist

Before committing, verify:

- [ ] All tests pass (`uv run pytest`)
- [ ] Linting clean (`uv run ruff check`)
- [ ] Docker builds successfully (`docker build -t amazon-ads-mcp .`)
- [ ] Environment variables documented for new features
- [ ] Security considerations addressed (credentials, API keys)

## Quick Reference (for Agents)

- Install deps: `uv sync`
- Start server: `docker-compose up -d`
- Add MCP to Claude (HTTP):
  - `claude mcp add amazon-ads-mcp -- python -m amazon_ads_mcp.server.mcp_server --transport http --port 9080`
- Verify: `claude mcp list` and `/mcp`
- Run tests: `uv run pytest`
- Lint: `uv run ruff check --fix`