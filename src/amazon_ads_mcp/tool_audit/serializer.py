"""Wire-shape serialization for MCP tool definitions.

Serializes tool dicts to match the MCP tools/list wire format that
Claude actually receives. Uses subtractive re-serialization to compute
per-component token deltas without inconsistencies.
"""

import json
from copy import deepcopy

# Fields Claude receives for tool invocation
_STRICT_KEYS = {"name", "description", "inputSchema"}


def serialize_tool(tool_dict: dict, strict: bool = True) -> str:
    """Serialize a tool dict matching the MCP wire shape.

    :param tool_dict: Raw tool dict from tools/list response.
    :param strict: If True, keep only name/description/inputSchema.
    :return: Compact JSON string.
    """
    d = deepcopy(tool_dict)
    if strict:
        d = {k: v for k, v in d.items() if k in _STRICT_KEYS}
    return json.dumps(d, separators=(",", ":"), sort_keys=True)


def serialize_without(
    tool_dict: dict, exclude_key: str, strict: bool = True
) -> str:
    """Serialize a tool dict with one key removed for delta calculation.

    :param tool_dict: Raw tool dict from tools/list response.
    :param exclude_key: Key to remove before serialization.
    :param strict: If True, keep only name/description/inputSchema.
    :return: Compact JSON string with the key removed.
    """
    d = deepcopy(tool_dict)
    if strict:
        d = {k: v for k, v in d.items() if k in _STRICT_KEYS}
    d.pop(exclude_key, None)
    return json.dumps(d, separators=(",", ":"), sort_keys=True)
