#!/usr/bin/env python3
"""Start the Amazon Ads MCP server with HTTP/SSE transport on port 9080."""

import os
import sys
import subprocess

# Set environment variables for HTTP transport
env = os.environ.copy()
env.update({
    "MCP_TRANSPORT": "sse",
    "MCP_SSE_PORT": "9080",
    "MCP_SSE_HOST": "0.0.0.0",  # Listen on all interfaces
})

print("🚀 Starting Amazon Ads MCP server on http://localhost:9080")
print("=" * 60)
print("Server configuration:")
print(f"  - Transport: SSE (Server-Sent Events)")
print(f"  - Port: 9080")
print(f"  - Host: 0.0.0.0 (all interfaces)")
print("=" * 60)

# Run the dynamic server with SSE transport
try:
    subprocess.run([
        sys.executable, 
        "-m", 
        "amazon_ads_mcp.server.main_dynamic"
    ], env=env)
except KeyboardInterrupt:
    print("\n✋ Server stopped by user")
except Exception as e:
    print(f"\n❌ Error: {e}")