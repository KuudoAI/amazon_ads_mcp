"""Amazon Ads MCP metering integration (Task 22).

Wires the ``mcp-outbound-metering`` producer package (billing repo,
``packages/python/mcp_outbound_metering``) into this server so every real
Amazon Ads API call is metered while internal/auth traffic stays untouched.

This ``__init__`` intentionally imports nothing eagerly: every submodule is
safe to import on its own, and ``compat.py`` is the only one that ever
touches ``mcp_outbound_metering`` -- keeping this package's import surface
inert avoids any accidental import-time coupling (or import cycle) between
e.g. ``adapter.py`` (imported from ``utils/http_client.py``) and
``context.py`` (which imports back from ``utils/http_client.py``).
"""

from __future__ import annotations
