"""MCP Tool Token Audit - CLI orchestrator.

Connects to a running MCP server, fetches all tool definitions, and
reports their token consumption. Identifies which tools are eating
the most context window.

Usage:
    python -m amazon_ads_mcp.tool_audit
    python -m amazon_ads_mcp.tool_audit --format json
    python -m amazon_ads_mcp.tool_audit --sort schema --limit 0
"""

import argparse
import asyncio
import json
import os
import pathlib
import re
import sys
from typing import Any

from .models import (
    AuditReport,
    CodeModeProbeReport,
    CodeModeSchemaProbeItem,
    GroupSummary,
    ToolTokenBreakdown,
)
from .report import render_console, render_json
from .serializer import serialize_tool, serialize_without
from .token_counter import TokenCounter

# Hardcoded fallback prefix set from packages.json
_FALLBACK_PREFIXES: set[str] = {
    "ac", "amc", "ams", "attr", "aud", "br", "bsm", "cm", "creat",
    "dp", "dsp", "dspv1", "export", "fc", "loc", "mmm", "mod", "mp",
    "pm", "prod", "ri", "rp", "sb", "sbv1", "sd", "sdv1", "sp",
    "spv1", "st", "stv1", "test",
}


_TOOL_NAME_RE = re.compile(r"\b[a-z][a-z0-9]*_[A-Za-z0-9_]+\b")


def _load_prefixes(prefixes_file: str | None) -> set[str]:
    """Load known tool prefixes from packages.json.

    :param prefixes_file: Path to packages.json, or None for default.
    :return: Set of known prefix strings.
    """
    if prefixes_file is None:
        # Try default location relative to project root
        candidates = [
            pathlib.Path.cwd() / "openapi" / "resources" / "packages.json",
            pathlib.Path(__file__).parents[3] / "openapi" / "resources" / "packages.json",
        ]
        for candidate in candidates:
            if candidate.exists():
                prefixes_file = str(candidate)
                break

    if prefixes_file is None or not pathlib.Path(prefixes_file).exists():
        if prefixes_file:
            print(
                f"WARNING: Prefixes file not found: {prefixes_file}. "
                f"Using hardcoded fallback.",
                file=sys.stderr,
            )
        return _FALLBACK_PREFIXES.copy()

    try:
        with open(prefixes_file) as f:
            data = json.load(f)
        prefixes_map = data.get("prefixes", {})
        return set(prefixes_map.values())
    except Exception as exc:
        print(
            f"WARNING: Failed to load prefixes from {prefixes_file}: "
            f"{exc}. Using hardcoded fallback.",
            file=sys.stderr,
        )
        return _FALLBACK_PREFIXES.copy()


def _extract_prefix(tool_name: str, known_prefixes: set[str]) -> str:
    """Extract prefix group from a tool name.

    :param tool_name: Full tool name (e.g., 'sp_POST_campaigns').
    :param known_prefixes: Set of known OpenAPI prefixes.
    :return: Prefix string or 'builtin'.
    """
    first_part = tool_name.split("_", 1)[0]
    if first_part in known_prefixes:
        return first_part
    return "builtin"


def _extract_strings(obj: Any) -> list[str]:
    """Recursively collect string values from arbitrary JSON-like data."""
    out: list[str] = []
    if isinstance(obj, str):
        out.append(obj)
        return out
    if isinstance(obj, dict):
        for v in obj.values():
            out.extend(_extract_strings(v))
        return out
    if isinstance(obj, list):
        for v in obj:
            out.extend(_extract_strings(v))
    return out


def _extract_tool_names_from_result(result: Any, exclude: set[str]) -> set[str]:
    """Extract likely tool names from call_tool result payload."""
    names: set[str] = set()
    raw_parts: list[str] = []

    # Prefer model_dump if available
    try:
        payload = result.model_dump(exclude_none=True)
    except Exception:
        payload = None

    if payload is not None:
        raw_parts.extend(_extract_strings(payload))
        for txt in raw_parts:
            try:
                parsed = json.loads(txt)
                if isinstance(parsed, dict):
                    maybe = parsed.get("name")
                    if isinstance(maybe, str):
                        names.add(maybe)
            except Exception:
                pass
    else:
        raw_parts.append(str(result))

    # Regex fallback across all collected text
    for txt in raw_parts:
        for match in _TOOL_NAME_RE.findall(txt):
            names.add(match)

    return {n for n in names if n not in exclude}


def _call_result_to_payload(result: Any) -> dict[str, Any]:
    """Normalize FastMCP CallToolResult-like objects into a serializable dict."""
    def _normalize_content_item(item: Any) -> Any:
        if hasattr(item, "model_dump"):
            try:
                return item.model_dump(exclude_none=True)
            except Exception:
                pass
        if hasattr(item, "dict"):
            try:
                return item.dict(exclude_none=True)
            except Exception:
                pass

        # Common MCP content object fields
        if hasattr(item, "text"):
            try:
                return {"type": getattr(item, "type", "text"), "text": getattr(item, "text")}
            except Exception:
                pass
        if isinstance(item, (str, int, float, bool)) or item is None:
            return item
        return str(item)

    if hasattr(result, "model_dump"):
        try:
            payload = result.model_dump(exclude_none=True)
            if isinstance(payload, dict):
                if isinstance(payload.get("content"), list):
                    payload["content"] = [_normalize_content_item(i) for i in payload["content"]]
                return payload
        except Exception:
            pass

    if hasattr(result, "dict"):
        try:
            payload = result.dict(exclude_none=True)
            if isinstance(payload, dict):
                if isinstance(payload.get("content"), list):
                    payload["content"] = [_normalize_content_item(i) for i in payload["content"]]
                return payload
        except Exception:
            pass

    content = getattr(result, "content", None)
    if isinstance(content, list):
        content = [_normalize_content_item(i) for i in content]
    elif content is not None:
        content = _normalize_content_item(content)
    is_error = getattr(result, "isError", None)
    structured = {
        "content": content if content is not None else str(result),
    }
    if is_error is not None:
        structured["isError"] = bool(is_error)
    return structured


def _pick_param_name(
    schema: dict[str, Any],
    candidates: list[str],
) -> str | None:
    """Pick a parameter name from inputSchema using candidate names first."""
    props = schema.get("properties") if isinstance(schema, dict) else None
    if not isinstance(props, dict):
        return None

    for c in candidates:
        if c in props:
            return c

    required = schema.get("required")
    if isinstance(required, list):
        for name in required:
            if isinstance(name, str) and name in props:
                return name

    for name, value in props.items():
        if isinstance(value, dict) and value.get("type") == "string":
            return name
    for name, value in props.items():
        if isinstance(value, dict) and value.get("type") == "array":
            items = value.get("items")
            if isinstance(items, dict) and items.get("type") == "string":
                return name
    return None


def _build_search_args(input_schema: dict[str, Any], query: str) -> dict[str, Any]:
    """Build best-effort args for code-mode search tool."""
    name = _pick_param_name(input_schema, ["query", "q", "text", "term"])
    if not name:
        return {}

    prop = input_schema.get("properties", {}).get(name, {})
    if isinstance(prop, dict) and prop.get("type") == "array":
        return {name: [query]}
    return {name: query}


def _build_schema_args(input_schema: dict[str, Any], tool_name: str) -> dict[str, Any]:
    """Build best-effort args for code-mode get_schema(s) tool."""
    name = _pick_param_name(
        input_schema,
        ["name", "tool", "tool_name", "toolName", "schema_name", "schemaName", "names", "tool_names"],
    )
    if not name:
        return {}

    prop = input_schema.get("properties", {}).get(name, {})
    if isinstance(prop, dict) and prop.get("type") == "array":
        return {name: [tool_name]}
    return {name: tool_name}


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse CLI arguments.

    :param argv: Argument list (default: sys.argv[1:]).
    :return: Parsed namespace.
    """
    parser = argparse.ArgumentParser(
        description="Audit MCP tool token usage to find context window killers",
        prog="python -m amazon_ads_mcp.tool_audit",
    )
    parser.add_argument(
        "--url",
        default="http://127.0.0.1:9080/mcp",
        help="MCP server URL (default: http://127.0.0.1:9080/mcp)",
    )
    parser.add_argument(
        "--token",
        default=None,
        help="Bearer token (default: $OPENBRIDGE_REFRESH_TOKEN)",
    )
    parser.add_argument(
        "--format",
        choices=["console", "json"],
        default="console",
        dest="output_format",
        help="Output format (default: console)",
    )
    parser.add_argument(
        "--threshold",
        type=int,
        default=1000,
        help="Token count threshold for warnings (default: 1000)",
    )
    parser.add_argument(
        "--context-window",
        type=int,
        default=200_000,
        help="Context window size for %% calculation (default: 200000)",
    )
    parser.add_argument(
        "--sort",
        choices=["total", "schema", "prefix", "name"],
        default="total",
        help="Sort order for tools (default: total)",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=20,
        help="Top N tools in console output, 0 for all (default: 20)",
    )
    parser.add_argument(
        "--encoding",
        default="cl100k_base",
        help="tiktoken encoding name (default: cl100k_base)",
    )
    parser.add_argument(
        "--include-meta",
        action="store_true",
        default=False,
        help="Include all wire fields, not just name/description/inputSchema",
    )
    parser.add_argument(
        "--prefixes-file",
        default=None,
        help="Path to packages.json for prefix mappings (default: auto-detect)",
    )
    parser.add_argument(
        "--code-mode-probe",
        action="store_true",
        default=False,
        help=(
            "When code mode meta-tools are present, call search/get_schema and "
            "measure schema-fetch token costs."
        ),
    )
    parser.add_argument(
        "--probe-limit",
        type=int,
        default=25,
        help="Max discovered tools to fetch schemas for in --code-mode-probe (default: 25)",
    )
    parser.add_argument(
        "--probe-queries",
        default="campaign,ad,report,profile,dsp,amc",
        help=(
            "Comma-separated search queries used by --code-mode-probe "
            "(default: campaign,ad,report,profile,dsp,amc)"
        ),
    )
    return parser.parse_args(argv)


async def run_audit(args: argparse.Namespace) -> AuditReport:
    """Connect to MCP server, fetch tools, and build the audit report.

    :param args: Parsed CLI arguments.
    :return: Complete audit report.
    :raises ConnectionError: If server is unreachable.
    :raises PermissionError: If authentication fails.
    """
    from fastmcp import Client
    from fastmcp.client.transports import StreamableHttpTransport

    token = args.token or os.environ.get("OPENBRIDGE_REFRESH_TOKEN")

    headers: dict[str, str] = {
        "Accept": "application/json,text/event-stream",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"

    transport = StreamableHttpTransport(
        url=args.url,
        headers=headers,
    )
    client = Client(transport)

    strict = not args.include_meta
    counter = TokenCounter(encoding_name=args.encoding)
    known_prefixes = _load_prefixes(args.prefixes_file)
    code_probe: CodeModeProbeReport | None = None

    # Fetch tools from server
    try:
        async with client:
            tools = await client.list_tools()

            if args.code_mode_probe:
                tool_map = {t.name: t for t in tools}
                meta_tool_names = sorted(
                    name for name in tool_map.keys() if name in {"tags", "search", "get_schema", "get_schemas", "execute"}
                )
                search_tool = "search" if "search" in tool_map else None
                schema_tool = (
                    "get_schema"
                    if "get_schema" in tool_map
                    else ("get_schemas" if "get_schemas" in tool_map else None)
                )
                code_probe = CodeModeProbeReport(
                    enabled=True,
                    meta_tools=meta_tool_names,
                    search_tool=search_tool,
                    schema_tool=schema_tool,
                )

                if search_tool and schema_tool:
                    queries = [q.strip() for q in str(args.probe_queries).split(",") if q.strip()]
                    code_probe.search_queries = queries
                    discovered: set[str] = set()
                    exclude = set(meta_tool_names)

                    search_schema = (
                        getattr(tool_map[search_tool], "inputSchema", None)
                        or {}
                    )
                    for q in queries:
                        try:
                            search_args = _build_search_args(search_schema, q)
                            result = await client.call_tool(search_tool, search_args)
                            discovered.update(_extract_tool_names_from_result(result, exclude))
                        except Exception:
                            continue

                    sampled = sorted(discovered)[: max(0, args.probe_limit)]
                    code_probe.sampled_tools = sampled
                    code_probe.sampled_tool_count = len(sampled)

                    schema_input = (
                        getattr(tool_map[schema_tool], "inputSchema", None)
                        or {}
                    )
                    fetches: list[CodeModeSchemaProbeItem] = []
                    for name in sampled:
                        try:
                            schema_args = _build_schema_args(schema_input, name)
                            schema_result = await client.call_tool(schema_tool, schema_args)
                            payload = _call_result_to_payload(schema_result)
                            payload_json = json.dumps(payload, separators=(",", ":"), ensure_ascii=False)
                            tokens = counter.count(payload_json)
                            fetches.append(
                                CodeModeSchemaProbeItem(
                                    tool_name=name,
                                    total_tokens=tokens,
                                    raw_chars=len(payload_json),
                                    ok=True,
                                )
                            )
                        except Exception as exc:
                            fetches.append(
                                CodeModeSchemaProbeItem(
                                    tool_name=name,
                                    total_tokens=0,
                                    raw_chars=0,
                                    ok=False,
                                    error=str(exc),
                                )
                            )

                    code_probe.schema_fetches = fetches
                    ok_fetches = [f for f in fetches if f.ok]
                    code_probe.total_schema_tokens = sum(f.total_tokens for f in ok_fetches)
                    code_probe.avg_schema_tokens = round(
                        code_probe.total_schema_tokens / len(ok_fetches), 1
                    ) if ok_fetches else 0.0
    except Exception as exc:
        exc_str = str(exc).lower()
        if "401" in exc_str or "unauthorized" in exc_str or "forbidden" in exc_str:
            raise PermissionError(
                "Authentication required. "
                "Set OPENBRIDGE_REFRESH_TOKEN or use --token <value>"
            ) from exc
        if "connect" in exc_str or "refused" in exc_str or "unreachable" in exc_str:
            raise ConnectionError(
                f"Could not connect to {args.url}. Is the server running?"
            ) from exc
        raise

    # Process each tool
    breakdowns: list[ToolTokenBreakdown] = []
    for tool in tools:
        # Get wire-shape dict from the Tool object
        tool_dict = tool.model_dump(exclude_none=True)

        # Serialize and count
        full_json = serialize_tool(tool_dict, strict=strict)
        total_tokens = counter.count(full_json)

        without_schema = serialize_without(
            tool_dict, "inputSchema", strict=strict
        )
        without_desc = serialize_without(
            tool_dict, "description", strict=strict
        )
        without_name = serialize_without(
            tool_dict, "name", strict=strict
        )

        schema_tokens = total_tokens - counter.count(without_schema)
        desc_tokens = total_tokens - counter.count(without_desc)
        name_tokens = total_tokens - counter.count(without_name)

        prefix = _extract_prefix(tool.name, known_prefixes)

        breakdowns.append(
            ToolTokenBreakdown(
                name=tool.name,
                prefix=prefix,
                total_tokens=total_tokens,
                schema_tokens=schema_tokens,
                description_tokens=desc_tokens,
                name_tokens=name_tokens,
                raw_chars=len(full_json),
                description_preview=(tool.description or "")[:80],
            )
        )

    # Sort
    if args.sort == "total":
        breakdowns.sort(key=lambda b: b.total_tokens, reverse=True)
    elif args.sort == "schema":
        breakdowns.sort(key=lambda b: b.schema_tokens, reverse=True)
    elif args.sort == "name":
        breakdowns.sort(key=lambda b: b.name)
    elif args.sort == "prefix":
        breakdowns.sort(key=lambda b: (b.prefix, -b.total_tokens))

    # Group by prefix
    groups_map: dict[str, list[ToolTokenBreakdown]] = {}
    for b in breakdowns:
        groups_map.setdefault(b.prefix, []).append(b)

    groups: list[GroupSummary] = []
    for prefix, members in sorted(
        groups_map.items(),
        key=lambda x: sum(m.total_tokens for m in x[1]),
        reverse=True,
    ):
        total = sum(m.total_tokens for m in members)
        largest = max(members, key=lambda m: m.total_tokens)
        groups.append(
            GroupSummary(
                prefix=prefix,
                tool_count=len(members),
                total_tokens=total,
                avg_tokens_per_tool=round(total / len(members), 1),
                largest_tool=largest.name,
                largest_tool_tokens=largest.total_tokens,
            )
        )

    total_tool_tokens = sum(b.total_tokens for b in breakdowns)
    violations = [
        b.name for b in breakdowns if b.total_tokens > args.threshold
    ]

    return AuditReport(
        server_url=args.url,
        tool_count=len(tools),
        encoding=counter.label,
        mode="full" if args.include_meta else "strict",
        tools=breakdowns,
        groups=groups,
        total_tool_tokens=total_tool_tokens,
        context_window_size=args.context_window,
        context_window_percent=round(
            total_tool_tokens / args.context_window * 100, 2
        )
        if args.context_window > 0
        else 0.0,
        threshold=args.threshold,
        threshold_violations=violations,
        code_mode_probe=code_probe,
    )


def main(argv: list[str] | None = None) -> None:
    """Entry point for the tool audit CLI.

    :param argv: Argument list (default: sys.argv[1:]).
    """
    args = parse_args(argv)

    try:
        report = asyncio.run(run_audit(args))
    except ConnectionError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)
    except PermissionError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        sys.exit(130)
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)

    if args.output_format == "json":
        render_json(report)
    else:
        render_console(
            report,
            threshold=args.threshold,
            limit=args.limit,
        )


if __name__ == "__main__":
    main()
