"""Build-time utilities for the amazon-ads-mcp package.

Modules in this subpackage are used by refresh/validate CLIs and by tests
against packaged catalog metadata. Runtime code paths must not import from
here — nothing under `amazon_ads_mcp.build` should be on a hot path.
"""
