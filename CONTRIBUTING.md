# Contributing to Amazon Ads MCP

Thank you for your interest in contributing to Amazon Ads MCP! This document provides guidelines and best practices for contributing to this project.

## Code of Conduct

By participating in this project, you agree to maintain a respectful and inclusive environment for all contributors.

## How to Contribute

### Reporting Issues

Before creating an issue:
1. **Search existing issues** to avoid duplicates
2. **Use issue templates** - Select the appropriate template (Bug Report or Feature Request)
3. **Provide complete information** - Fill out all sections of the template
4. **Include reproduction steps** - For bugs, provide minimal steps to reproduce
5. **Add logs and error messages** - Include relevant debugging information

### Issue Best Practices

#### Writing Good Bug Reports
- **One issue per bug** - Don't combine multiple bugs in one issue
- **Be specific** - "Authentication fails" is better than "doesn't work"
- **Include environment details** - Python version, OS, MCP client version
- **Provide code samples** - Minimal reproducible examples help tremendously
- **Attach logs** - Include relevant error messages and stack traces

#### Writing Good Feature Requests
- **Explain the problem first** - What challenge does this solve?
- **Provide use cases** - Real-world examples help evaluate importance
- **Consider alternatives** - Have you tried other approaches?
- **Think about compatibility** - How does this affect existing users?

### Pull Requests

#### Before You Start
1. **Open an issue first** - Discuss your proposal before coding
2. **Check the roadmap** - Ensure it aligns with project direction
3. **One PR per feature/fix** - Keep changes focused and reviewable

#### Development Setup
```bash
# Clone the repository
git clone https://github.com/KuudoAI/amazon_ads_mcp.git
cd amazon_ads_mcp

# Create a branch
git checkout -b feature/your-feature-name

# Install dependencies
uv venv
uv sync

# Set up pre-commit hooks (if available)
pre-commit install
```

#### Code Standards
- **Python 3.10+** - Use modern Python features appropriately
- **Type hints** - All functions should have type annotations
- **Docstrings** - Document all public APIs
- **Tests** - Add tests for new functionality
- **Linting** - Run `uv run ruff check --fix` before committing

#### Testing Requirements
```bash
# Run linting
uv run ruff check --fix

# Run tests
uv run pytest

# Run specific tests
uv run pytest tests/test_auth.py

# Run with coverage
uv run pytest --cov=amazon_ads_mcp
```

#### PR Checklist
- [ ] Issue number referenced in PR description
- [ ] Tests added/updated for changes
- [ ] Documentation updated if needed
- [ ] Code passes linting (`uv run ruff check`)
- [ ] All tests pass (`uv run pytest`)
- [ ] PR title follows conventional commits (feat:, fix:, docs:, etc.)
- [ ] Changes are focused and don't include unrelated modifications

### Commit Messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):
- `feat:` New feature
- `fix:` Bug fix
- `docs:` Documentation changes
- `test:` Test additions or fixes
- `refactor:` Code restructuring without behavior change
- `perf:` Performance improvements
- `chore:` Maintenance tasks

Examples:
```
feat: add DSP campaign creation tool
fix: handle OAuth token refresh errors
docs: update authentication guide
test: add unit tests for profile manager
```

## Documentation

- **Update README** for user-facing changes
- **Update CLAUDE.md** for development/agent guidance
- **Add docstrings** for new functions/classes
- **Include examples** for complex features

## Security

- **Never commit secrets** - API keys, tokens, passwords
- **Report vulnerabilities** privately to operations@openbridge.com
- **Validate inputs** - Sanitize user inputs
- **Follow OAuth best practices** - Secure token storage

## Questions?

- Open a [Discussion](https://github.com/KuudoAI/amazon_ads_mcp/discussions)
- Review existing [Issues](https://github.com/KuudoAI/amazon_ads_mcp/issues)
- Check the [Documentation](README.md)

## Recognition

Contributors will be recognized in:
- Release notes
- Contributors list
- Project documentation

Thank you for helping make Amazon Ads MCP better!