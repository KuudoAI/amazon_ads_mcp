"""Code Mode integration for Amazon Ads MCP.

Replaces the full tool catalog with meta-tools (discovery + execute) that let
the LLM discover tools on demand and write Python scripts using
``await call_tool(name, params)`` in a sandbox.

Measured token reduction: 98.4% (34,971 -> 547 tokens) across 55 tools.

Configuration is driven by ``Settings`` (env vars ``CODE_MODE``,
``CODE_MODE_INCLUDE_TAGS``, ``CODE_MODE_MAX_DURATION_SECS``,
``CODE_MODE_MAX_MEMORY``).

Integration point: ``ServerBuilder._apply_code_mode()`` calls helpers here.

See also: docs/code-mode.md
"""

from __future__ import annotations

import asyncio
import inspect
import logging
from typing import TYPE_CHECKING, Any, Dict, List

if TYPE_CHECKING:
    from fastmcp import FastMCP

from fastmcp.server.dependencies import get_context

from ..config.settings import settings
from ..middleware.auth_session_bridge import (
    hydrate_auth_from_mcp_session,
    persist_auth_to_mcp_session,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Prefix -> human-readable tag mapping
# ---------------------------------------------------------------------------
# Derived from packages.json groups and prefix assignments.
# Multiple prefixes can map to the same tag.
PREFIX_TO_TAG: Dict[str, str] = {
    "cm": "campaign-management",
    "sp": "sponsored-products",
    "spv1": "sponsored-products-v1",
    "sb": "sponsored-brands",
    "sbv1": "sponsored-brands-v1",
    "sd": "sponsored-display",
    "sdv1": "sponsored-display-v1",
    "dsp": "programmatic-dsp",
    "dspv1": "programmatic-dsp-v1",
    "amc": "amazon-marketing-cloud",
    "ac": "accounts",
    "rp": "reporting",
    "br": "brand-insights",
    "st": "stores",
    "stv1": "stores-v1",
    "aud": "audiences",
    "attr": "attribution",
    "ri": "recommendations-insights",
    "creat": "creative-assets",
    "dp": "data-provider",
    "pm": "products-metadata",
    "prod": "products-eligibility",
    "mod": "moderation",
    "ams": "marketing-stream",
    "loc": "locations",
    "export": "exports",
    "mmm": "marketing-mix-modeling",
    "mp": "media-planning",
    "fc": "forecasts",
    "bsm": "brand-stores",
    "test": "test-account",
}

BUILTIN_TAG = "server-management"


# Description shown to LLMs for the `execute` meta-tool. Keeps `call_tool` as
# the single sandbox surface and documents the catch behavior + the real
# Monty sandbox guardrails (verified by repro: `asyncio.sleep` raises
# AttributeError, network/FS modules unavailable, print() output is client-
# path dependent). Drift here will mislead callers — keep aligned with
# `AuthBridgingSandboxProvider.run` and the integration tests.
EXECUTE_DESCRIPTION = (
    "Run async Python in a sandboxed interpreter. The whole script runs as one\n"
    "turn; use `return` to produce the tool result.\n"
    "\n"
    "Available in scope:\n"
    "- `await call_tool(name: str, params: dict) -> Any` — calls any backend tool.\n"
    "  Failures raise `RuntimeError(\"<OriginalType>: <message>\")` and are\n"
    "  catchable with `try/except RuntimeError:` inside the script.\n"
    "\n"
    "Sandbox guardrails (Monty interpreter):\n"
    "- No network: no `urllib`, `requests`, `httpx`, `socket`. Use `call_tool`.\n"
    "- No filesystem I/O: `open()`, `pathlib`, `os.*` are blocked. Tool results\n"
    "  larger than ~1 MB may be auto-stashed by the host client.\n"
    "- `print()` output may be discarded depending on the client path; return\n"
    "  data via the script's final expression instead.\n"
    "- `asyncio.sleep` is unavailable by design in this sandbox path. Don't sleep —\n"
    "  chain `await call_tool` calls (e.g. poll a report-status tool) instead.\n"
    "- `try`/`except`/`finally` work normally. To probe many candidates in one\n"
    "  block, wrap each `await call_tool(...)` in its own `try/except RuntimeError`.\n"
    "- `with` works for pure-Python context managers (e.g. `decimal.localcontext()`).\n"
    "  It does NOT work for `open(...)` because file I/O is blocked.\n"
    "- `json.dumps(default=...)` may trip on Pydantic models; call `model_dump()` first.\n"
    "\n"
    "Auth, region, and active profile are managed by the server. Do not pass\n"
    "`Amazon-Ads-AccountId`, `Amazon-Advertising-API-Scope`, or bearer tokens in\n"
    "`params` — set them once via `set_active_identity` / `set_region` /\n"
    "`set_active_profile` and they ride every subsequent `call_tool`.\n"
    "\n"
    "Session-scope contract:\n"
    "- To detect the transport's scope, call `get_session_state` at the start\n"
    "  of a block. It is a read-only probe with no side effects.\n"
    "- Rule: Re-establish context before the next tool call iff `state_scope == 'request'` or `state_reason` is not null.\n"
    "- Within a block the scope cannot change; one probe per block is sufficient.\n"
    "- `state_reason` enumerates: `\"no_mcp_session\"` (request-scoped transport),\n"
    "  `\"token_swapped\"` (a different bearer/refresh token arrived mid-session\n"
    "  and the previous tenant's state was cleared — `state_scope` stays\n"
    "  `'session'` but you must re-establish context for the new tenant), and\n"
    "  `\"bridge_unavailable\"` (reserved; treat as `'request'`).\n"
)


def build_discovery_tools() -> list:
    """Build discovery tool instances based on settings.

    Default: ``[GetTags(), Search(), GetSchemas()]`` — the LLM can browse
    categories via tags, search by keyword, then fetch full schemas.

    Set ``CODE_MODE_INCLUDE_TAGS=false`` to drop ``GetTags`` (useful for
    small catalogs where tag browsing adds unnecessary round-trips).

    :return: List of discovery tool instances for CodeMode
    :rtype: list
    :raises ImportError: If ``fastmcp[code-mode]`` extra is not installed
    """
    try:
        from fastmcp.experimental.transforms.code_mode import (
            GetSchemas,
            GetTags,
            Search,
        )
    except ImportError as exc:
        raise ImportError(
            "Code mode requires the 'code-mode' extra. "
            "Install with: pip install 'fastmcp[code-mode]>=3.1.0'"
        ) from exc

    tools: list = []

    if settings.code_mode_include_tags:
        tools.append(GetTags())

    tools.extend([Search(), GetSchemas()])
    return tools


class MontyDispatchSandboxProvider:
    """Sandbox provider that drives Monty via the start/resume protocol.

    FastMCP's stock ``MontySandboxProvider`` calls ``Monty.run_async()``,
    which surfaces external-function exceptions as ``MontyRuntimeError``
    *outside* the sandbox — the script aborts before any in-sandbox
    ``try/except`` can catch them. This provider drives Monty manually
    through ``start()`` + ``FunctionSnapshot.resume(exception=...)`` so
    exceptions are injected back into the VM and ordinary Python
    ``try/except`` semantics work for ``call_tool`` failures.

    Verified by repro:
      - ``run_async`` path: in-sandbox ``try/except RuntimeError`` does NOT
        catch external errors.
      - ``start/resume`` path with ``resume(exception=RuntimeError(...))``:
        the in-sandbox ``except RuntimeError`` catches as expected and the
        exception type is preserved.

    External-function results that are coroutines are awaited on the host
    event loop. VM resume calls are offloaded to a worker thread (mirroring
    upstream ``Monty.run_async`` behavior) so a long-running sandbox
    snippet doesn't block the asyncio loop.

    :param limits: Resource limits (forwarded to ``Monty.start``).
    :type limits: dict | None
    """

    def __init__(self, *, limits: Any | None = None) -> None:
        self.limits = limits

    async def run(
        self,
        code: str,
        *,
        inputs: dict[str, Any] | None = None,
        external_functions: dict[str, Any] | None = None,
    ) -> Any:
        try:
            import pydantic_monty as pm
        except ImportError as exc:  # pragma: no cover - validated at startup
            raise ImportError(
                "MontyDispatchSandboxProvider requires pydantic-monty. "
                "Install with: pip install 'fastmcp[code-mode]>=3.1.0'"
            ) from exc

        inputs = inputs or {}
        externals = external_functions or {}

        monty = pm.Monty(code, inputs=list(inputs))
        snapshot = await asyncio.to_thread(
            monty.start,
            inputs=inputs or None,
            limits=self.limits,
        )

        # Pending future results, keyed by Monty call_id. A successful eager
        # await stashes the value here and we hand it to Monty when it asks
        # for the FutureSnapshot resolution. Failures take a different path
        # (FunctionSnapshot.resume(exception=...)) because Monty's
        # FutureSnapshot exception channel does NOT propagate to the
        # sandbox's surrounding try/except — only FunctionSnapshot exception
        # injection does. See class docstring + verified probes.
        pending: dict[int, dict[str, Any]] = {}

        while True:
            if isinstance(snapshot, pm.MontyComplete):
                return snapshot.output

            if isinstance(snapshot, pm.FunctionSnapshot):
                fn_name = snapshot.function_name
                fn = externals.get(fn_name)
                if fn is None:
                    snapshot = await asyncio.to_thread(
                        snapshot.resume,
                        exception=NameError(
                            f"name {fn_name!r} is not defined"
                        ),
                    )
                    continue

                call_id = snapshot.call_id
                try:
                    result = fn(*snapshot.args, **snapshot.kwargs)
                    if inspect.iscoroutine(result):
                        # Eagerly await on the host event loop. We do NOT
                        # park the coroutine and let Monty await via
                        # FutureSnapshot — Monty's future-exception path
                        # bypasses in-sandbox try/except, so we collapse
                        # async externals to a sync result + future-resolve
                        # for success, or sync exception injection for
                        # failure (which IS catchable inside the sandbox).
                        result = await result
                except Exception as exc:
                    snapshot = await asyncio.to_thread(
                        snapshot.resume, exception=exc
                    )
                    continue

                # Success path: signal that the call returned an awaitable
                # so the sandbox's `await call_tool(...)` evaluates without
                # a "object can't be awaited" TypeError, then immediately
                # resolve the future with the value we already computed.
                pending[call_id] = {"return_value": result}
                snapshot = await asyncio.to_thread(
                    snapshot.resume, future=...
                )
                continue

            if isinstance(snapshot, pm.FutureSnapshot):
                results: dict[int, dict[str, Any]] = {}
                for cid in snapshot.pending_call_ids:
                    entry = pending.pop(cid, None)
                    if entry is None:
                        # Monty asked for a future we never registered —
                        # treat as a programming error in the dispatch loop.
                        results[cid] = {
                            "exception": RuntimeError(
                                f"No pending future for call_id={cid}"
                            )
                        }
                    else:
                        results[cid] = entry
                snapshot = await asyncio.to_thread(snapshot.resume, results)
                continue

            if isinstance(snapshot, pm.NameLookupSnapshot):
                # Name not in our external set — let the sandbox raise NameError.
                snapshot = await asyncio.to_thread(snapshot.resume)
                continue

            raise RuntimeError(
                f"Unknown Monty snapshot type: {type(snapshot).__name__}"
            )


class AuthBridgingSandboxProvider:
    """Wrap a SandboxProvider and bridge auth state for nested call_tool."""

    def __init__(self, inner: Any):
        self._inner = inner

    async def run(
        self,
        code: str,
        *,
        inputs: dict[str, Any] | None = None,
        external_functions: dict[str, Any] | None = None,
    ) -> Any:
        wrapped_functions = dict(external_functions or {})
        original_call_tool = wrapped_functions.get("call_tool")
        parent_ctx = None

        try:
            parent_ctx = get_context()
        except RuntimeError:
            parent_ctx = None

        if parent_ctx is not None and original_call_tool is not None:
            call_lock = asyncio.Lock()

            async def bridged_call_tool(name: str, params: dict[str, Any]) -> Any:
                # Each nested call hydrates from parent MCP session and
                # persists back to parent session after completion.
                # Also applies sidecar input transforms (arg_aliases etc.)
                # — the sandboxed call_tool path doesn't go through the
                # server's middleware chain, so we run the same rewrite
                # pipeline here so singular→plural aliases like reportId
                # fire regardless of which call surface the LLM picked.
                from .sidecar_middleware import apply_sidecar_input_transforms

                async with call_lock:
                    await hydrate_auth_from_mcp_session(
                        parent_ctx, logger_instance=logger
                    )
                    try:
                        rewritten = await apply_sidecar_input_transforms(
                            name, params or {}
                        )
                        try:
                            return await original_call_tool(name, rewritten)
                        except Exception as exc:
                            # Re-raise as a builtin RuntimeError so Monty
                            # marshals it cleanly back into the sandbox where
                            # the LLM's `try/except RuntimeError:` can catch
                            # it. Without this normalization, ToolError /
                            # NotFoundError types aren't reliably reified
                            # inside the sandbox and the script aborts.
                            # Original type name is preserved in the message
                            # so callers can pattern-match on it.
                            raise RuntimeError(
                                f"{type(exc).__name__}: {exc}"
                            ) from None
                    finally:
                        await hydrate_auth_from_mcp_session(
                            parent_ctx, logger_instance=logger
                        )
                        await persist_auth_to_mcp_session(
                            parent_ctx, logger_instance=logger
                        )

            wrapped_functions["call_tool"] = bridged_call_tool

        return await self._inner.run(
            code,
            inputs=inputs,
            external_functions=wrapped_functions,
        )


def create_auth_bridging_sandbox_provider(inner: Any) -> AuthBridgingSandboxProvider:
    """Create auth-bridging sandbox wrapper for code-mode execution."""
    return AuthBridgingSandboxProvider(inner)


def create_code_mode_transform():
    """Create a configured CodeMode transform instance.

    :return: Configured CodeMode transform
    :raises ImportError: If ``fastmcp[code-mode]`` extra is not installed
        or the ``pydantic_monty`` runtime dependency is missing.
    """
    try:
        from fastmcp.experimental.transforms import code_mode as fastmcp_code_mode
    except ImportError as exc:
        raise ImportError(
            "Code mode requires the 'code-mode' extra. "
            "Install with: pip install 'fastmcp[code-mode]>=3.1.0'"
        ) from exc

    # MontyDispatchSandboxProvider lazy-imports pydantic_monty at .run() time.
    # Verify it is importable now so we fail loudly at server startup rather
    # than deep inside a tool call like `execute`.
    try:
        import pydantic_monty  # noqa: F401
    except ImportError as exc:
        raise ImportError(
            "Code mode is enabled (CODE_MODE=true) but the Monty sandbox "
            "runtime dependency 'pydantic_monty' is not installed. "
            "Install the code-mode extra with: "
            "pip install 'fastmcp[code-mode]>=3.1.0' "
            "(or set CODE_MODE=false to disable code mode)."
        ) from exc

    # NB: MontyDispatchSandboxProvider replaces FastMCP's MontySandboxProvider
    # because the upstream provider's run_async() path swallows external
    # exceptions before the sandbox can catch them. See class docstring.
    sandbox = MontyDispatchSandboxProvider(
        limits={
            "max_duration_secs": float(settings.code_mode_max_duration_secs),
            "max_memory": settings.code_mode_max_memory,
        }
    )

    discovery_tools = build_discovery_tools()

    transform = fastmcp_code_mode.CodeMode(
        sandbox_provider=create_auth_bridging_sandbox_provider(sandbox),
        discovery_tools=discovery_tools,
        execute_description=EXECUTE_DESCRIPTION,
    )

    logger.info(
        "Created CodeMode transform (timeout=%ds, memory=%dMB, discovery=%d tools, tags=%s)",
        settings.code_mode_max_duration_secs,
        settings.code_mode_max_memory // (1024 * 1024),
        len(discovery_tools),
        settings.code_mode_include_tags,
    )
    return transform


async def tag_tools_by_prefix(
    server: "FastMCP",
    mounted_servers: Dict[str, List["FastMCP"]],
) -> int:
    """Tag all OpenAPI-derived tools by their namespace prefix.

    Uses ``PREFIX_TO_TAG`` mapping for human-readable category names.
    Creates a new ``set`` before assigning to avoid mutating shared references.

    :param server: Main FastMCP server (unused, for API consistency)
    :param mounted_servers: Map of prefix -> list of sub-servers
    :return: Number of tools tagged
    :rtype: int
    """
    tagged = 0
    for prefix, sub_servers in mounted_servers.items():
        tag = PREFIX_TO_TAG.get(prefix, prefix)
        for sub_server in sub_servers:
            tools = await sub_server.list_tools()
            for tool_info in tools:
                try:
                    tool = await sub_server.get_tool(tool_info.name)
                    if tool:
                        # Safe: always create a new set to avoid mutating shared refs
                        tool.tags = {tag} | (tool.tags or set())
                        tagged += 1
                except Exception:
                    pass  # Skip tools that can't be accessed

    logger.info("Tagged %d OpenAPI tools across %d prefixes", tagged, len(mounted_servers))
    return tagged


async def tag_builtin_tools(server: "FastMCP") -> int:
    """Tag all builtin tools with 'server-management'.

    :param server: Main FastMCP server
    :return: Number of tools tagged
    :rtype: int
    """
    tagged = 0
    tools = await server.list_tools()
    for tool_info in tools:
        try:
            tool = await server.get_tool(tool_info.name)
            if tool:
                tool.tags = {BUILTIN_TAG} | (tool.tags or set())
                tagged += 1
        except Exception:
            pass
    logger.info("Tagged %d builtin tools as '%s'", tagged, BUILTIN_TAG)
    return tagged
