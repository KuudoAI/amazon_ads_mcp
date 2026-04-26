"""Sidecar transform middleware.

Bridges the declarative ``.transform.json`` sidecars to the current FastMCP
runtime. The legacy sidecar_loader looked for ``server.transform_tool``
(removed), so every ``input_transform`` / ``output_transform`` / ``arg_aliases``
rule silently became dead code. This middleware restores the contract
without regressing the schema surface the clients see.

What it does at call time:
  * ``on_call_tool`` runs BEFORE schema dispatch, so it sees the raw args
    the client sent — including ones like ``reportId`` that are not in
    the tool's published schema.
  * For every tool with a matching rule, it applies the ``input_transform``
    pipeline (preset, coercions, arg_aliases, defaults) to rewrite the
    args dict, then hands the rewritten args back to FastMCP for schema
    validation + dispatch.

Why a middleware rather than a Transform:
  * ``Transform.get_tool`` can rewrite the tool's schema and name but
    doesn't hook the call path at the moment the raw args are still
    available.
  * Middlewares with ``on_call_tool`` see the ``CallToolRequestParams``
    directly, which is exactly where we need to intercept.

The legacy ``sidecar_loader.attach_transforms_from_sidecars`` function
remains a no-op in the current runtime (it early-returns when
``server.transform_tool`` is absent). This module supersedes it.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Awaitable, Callable, Dict, List, Optional

from fastmcp.server.middleware import Middleware, MiddlewareContext

from .sidecar_loader import _json_load
from .transform_executor import DeclarativeTransformExecutor

logger = logging.getLogger(__name__)

#: Signature of a compiled input transform: args dict -> args dict.
InputTransform = Callable[[Dict[str, Any]], Awaitable[Dict[str, Any]]]

#: Process-wide singleton populated by ServerBuilder when the middleware is
#: installed. Code Mode's sandboxed ``call_tool`` bypasses FastMCP's server
#: middleware chain (it goes through external_functions injected by
#: MontySandboxProvider), so the auth-bridging wrapper must look this up
#: directly to apply the same input transforms. See
#: ``apply_sidecar_input_transforms`` below.
_ACTIVE_MIDDLEWARE: "Optional[SidecarTransformMiddleware]" = None


def _resolve_tool_name_for_rule(
    rule: Dict[str, Any],
    manifest: Dict[str, Any],
    namespace: str,
    prefix_map: Dict[str, str],
) -> Optional[str]:
    """Compute the final tool name a sidecar rule should apply to.

    Resolution order for the namespace prefix that gets prepended to the
    operationId (matching _mount_resource_servers / FastMCP mount):
      1. explicit ``match.name`` on the rule (full override)
      2. ``manifest.prefix`` (if the manifest sets one)
      3. ``packages.json::prefixes[namespace]`` — the mapping used by the
         actual mount path, e.g. AdsAPIv1All -> allv1.
      4. fallback to the bare namespace.
    """
    match = rule.get("match") or {}
    explicit = match.get("name")
    if isinstance(explicit, str) and explicit:
        return explicit
    op_id = match.get("operationId")
    if not isinstance(op_id, str) or not op_id:
        return None
    prefix = manifest.get("prefix") or prefix_map.get(namespace) or namespace
    return f"{prefix}_{op_id}" if prefix else op_id


class SidecarTransformMiddleware(Middleware):
    """Apply declarative sidecar input/output transforms at call time.

    Loads every ``*.transform.json`` under the configured resources
    directory once at construction and keeps a per-tool-name map of the
    compiled input-transform functions. Runtime cost per call is a single
    dict lookup plus whichever transforms match.
    """

    def __init__(
        self,
        resources_dir: Path,
        overlays_dir: Optional[Path] = None,
    ) -> None:
        self._input_transforms: Dict[str, List[InputTransform]] = {}
        self._loaded_rules = 0
        self._loaded_transforms = 0
        self._loaded_overlays = 0
        self._prefix_map: Dict[str, str] = {}

        self._load(resources_dir)
        # Overlays carry hand-authored alias / input_transform rules that
        # MUST survive the private .build/ regen of the primary transform
        # files. They're source-controlled under openapi/overlays/ and
        # loaded on top of whatever the transform files provided.
        if overlays_dir is not None:
            self._load_overlays(overlays_dir)

        logger.info(
            "SidecarTransformMiddleware: loaded %d base rules, %d overlays, "
            "%d compiled input transforms (%d tool names covered)",
            self._loaded_rules,
            self._loaded_overlays,
            self._loaded_transforms,
            len(self._input_transforms),
        )

    # ---------- load ------------------------------------------------------

    def _load_prefix_map(self, resources_dir: Path) -> Dict[str, str]:
        """Load packages.json namespace→prefix mapping.

        The mount path (``_mount_resource_servers``) uses this to compute
        real tool names (e.g. AdsAPIv1All → ``allv1_*``). The middleware
        must use the same map or its keys won't match the tools in the
        server.
        """
        for candidate in (
            resources_dir / "packages.json",
            resources_dir.parent / "packages.json",
            Path("openapi/resources/packages.json"),
            Path("dist/openapi/resources/packages.json"),
            Path("openapi/packages.json"),
        ):
            try:
                if candidate.exists():
                    pkg = _json_load(candidate)
                    return dict(pkg.get("prefixes") or {})
            except Exception:
                continue
        return {}

    def _register_rule(
        self,
        rule: Dict[str, Any],
        manifest: Dict[str, Any],
        namespace: str,
        executor: DeclarativeTransformExecutor,
    ) -> bool:
        """Compile a single rule and register it under prefixed +
        un-prefixed tool names. Returns True when a transform was compiled."""
        tool_name = _resolve_tool_name_for_rule(
            rule, manifest, namespace, self._prefix_map
        )
        if not tool_name:
            return False
        input_tx = executor.create_input_transform(rule)
        if input_tx is None:
            return False
        # Register under the prefixed name (MCP protocol path uses
        # namespaced names like `allv1_AdsApiv1RetrieveReport`) AND the
        # bare operationId (Code Mode's sandbox dispatches with the
        # un-prefixed operationId — observed in production tracebacks).
        # arg_aliases is additive+idempotent: double registration is safe
        # because the rewrite only writes the target key if absent.
        keys = [tool_name]
        op_id = (rule.get("match") or {}).get("operationId")
        if isinstance(op_id, str) and op_id and op_id != tool_name:
            keys.append(op_id)
        for key in keys:
            self._input_transforms.setdefault(key, []).append(input_tx)
        return True

    def _load(self, resources_dir: Path) -> None:
        if not resources_dir.exists():
            return
        self._prefix_map = self._load_prefix_map(resources_dir)

        for transform_path in sorted(resources_dir.glob("*.transform.json")):
            spec_path = transform_path.with_suffix("").with_suffix(".json")
            manifest_path = spec_path.with_suffix(".manifest.json")
            try:
                transform = _json_load(transform_path)
                manifest = _json_load(manifest_path) if manifest_path.exists() else {}
            except Exception as exc:
                logger.warning(
                    "SidecarTransformMiddleware: failed to load %s: %s",
                    transform_path.name,
                    exc,
                )
                continue

            namespace = manifest.get("namespace") or transform.get("namespace") or spec_path.stem
            executor = DeclarativeTransformExecutor(namespace=namespace, rules=transform)

            for rule in transform.get("tools", []) or []:
                self._loaded_rules += 1
                if self._register_rule(rule, manifest, namespace, executor):
                    self._loaded_transforms += 1

    # ---------- overlays --------------------------------------------------

    def _load_overlays(self, overlays_dir: Path) -> None:
        """Merge hand-authored overlay rules on top of base rules.

        Overlay file format (see openapi/overlays/README.md):
            {
              "namespace": "AdsAPIv1All",
              "tool_overlays": [
                {"match": {...}, "input_transform": {...}},
                ...
              ]
            }

        Overlay rules are treated exactly like regular transform rules —
        they're compiled through the same DeclarativeTransformExecutor,
        registered under the same prefixed + un-prefixed keys, and
        appended to whatever transforms the base rules produced.
        """
        if not overlays_dir.exists():
            return
        # Ensure prefix map is available even when no resources_dir rules loaded.
        if not self._prefix_map:
            self._prefix_map = self._load_prefix_map(overlays_dir)

        for overlay_path in sorted(overlays_dir.glob("*.json")):
            # Skip README-style or non-overlay files.
            try:
                data = _json_load(overlay_path)
            except Exception as exc:
                logger.warning(
                    "SidecarTransformMiddleware: failed to read overlay %s: %s",
                    overlay_path.name,
                    exc,
                )
                continue
            if not isinstance(data, dict):
                continue
            overlays = data.get("tool_overlays")
            if not isinstance(overlays, list):
                continue

            namespace = data.get("namespace") or overlay_path.stem
            # The executor wants a rules payload with a top-level version; a
            # minimal stub is fine because overlays don't use executor-level
            # preset caching.
            executor = DeclarativeTransformExecutor(
                namespace=namespace,
                rules={"version": "1.0", "tools": overlays},
            )
            manifest = {"namespace": namespace}

            for rule in overlays:
                if not isinstance(rule, dict):
                    continue
                self._loaded_overlays += 1
                if self._register_rule(rule, manifest, namespace, executor):
                    self._loaded_transforms += 1

    # ---------- shared rewrite helper -------------------------------------

    async def rewrite_args(
        self, tool_name: str, args: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Apply compiled input transforms for *tool_name* to *args*.

        Returns a new dict; does not mutate the caller's input. When no
        transforms match, returns ``args`` unchanged. Safe for use by the
        CodeMode sandbox bridge as well as the MCP middleware chain.
        """
        transforms = self._input_transforms.get(tool_name)
        if not transforms:
            return args
        rewritten = dict(args or {})
        for tx in transforms:
            try:
                next_args = await tx(rewritten)
                if next_args is not None:
                    rewritten = next_args
            except Exception as exc:
                logger.warning(
                    "SidecarTransformMiddleware: transform for %s raised %s",
                    tool_name,
                    exc,
                )
                return args
        return rewritten

    # ---------- stats (for debug builtins) --------------------------------

    def stats(self) -> Dict[str, int]:
        return {
            "rules": self._loaded_rules,
            "overlays": self._loaded_overlays,
            "compiled_transforms": self._loaded_transforms,
            "tools_with_transforms": len(self._input_transforms),
        }

    # ---------- call-time hook --------------------------------------------

    async def on_call_tool(
        self,
        context: MiddlewareContext,
        call_next: Callable[[MiddlewareContext], Awaitable[Any]],
    ) -> Any:
        message = getattr(context, "message", None)
        tool_name = getattr(message, "name", None)
        if not tool_name:
            return await call_next(context)

        # Capture starting args (after schema_normalization, before sidecar)
        raw_args: Dict[str, Any] = dict(getattr(message, "arguments", None) or {})
        final_args = raw_args

        transforms = self._input_transforms.get(tool_name)
        if transforms:
            rewritten = await self.rewrite_args(tool_name, raw_args)
            # Only mutate the payload if the rewrite actually changed anything.
            if rewritten != raw_args:
                try:
                    message.arguments = rewritten
                except Exception:
                    # Some pydantic versions make arguments frozen; rebuild.
                    try:
                        new_message = message.model_copy(
                            update={"arguments": rewritten}
                        )
                        context.message = new_message  # type: ignore[assignment]
                    except Exception as exc:  # pragma: no cover - defensive
                        logger.warning(
                            "SidecarTransformMiddleware: could not replace "
                            "arguments on %s: %s",
                            tool_name,
                            exc,
                        )
            final_args = rewritten

        # Strict unknown-field check runs AFTER both schema_normalization
        # (upstream middleware) AND sidecar alias rewrites (above), so it
        # only rejects fields that genuinely don't map to the tool's schema.
        # Sidecar-aliased fields like ``reportId`` → ``reportIds`` survive.
        # No-op when MCP_STRICT_UNKNOWN_FIELDS is false (default).
        from ..middleware.schema_normalization import (
            check_strict_unknown_fields,
        )

        await check_strict_unknown_fields(
            tool_name,
            final_args,
            fastmcp_context=getattr(context, "fastmcp_context", None),
        )

        return await call_next(context)


def set_active_middleware(middleware: "Optional[SidecarTransformMiddleware]") -> None:
    """Register the process-wide active middleware.

    Called by ``ServerBuilder._register_sidecar_middleware`` so the
    CodeMode sandbox bridge can reach the same compiled transforms
    without a direct dependency on ``ServerBuilder``.
    """
    global _ACTIVE_MIDDLEWARE
    _ACTIVE_MIDDLEWARE = middleware


async def apply_sidecar_input_transforms(
    tool_name: str, args: Dict[str, Any]
) -> Dict[str, Any]:
    """Apply the process-wide sidecar input transforms if any are installed.

    Used by the CodeMode sandbox bridge (see ``code_mode.py``) so that a
    sandboxed ``await call_tool(...)`` goes through the same alias and
    coercion pipeline as the top-level MCP call path. Returns ``args``
    unchanged when no middleware is active — safe to call from anywhere.
    """
    mw = _ACTIVE_MIDDLEWARE
    if mw is None:
        return args
    return await mw.rewrite_args(tool_name, args)
