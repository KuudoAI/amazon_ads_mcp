"""Transform executor for declarative tool transformations.

This module provides the DeclarativeTransformExecutor class that handles
executing declarative transform rules from sidecar files. It supports
input/output transformations, call transformations with pagination and
batching, and various data coercion operations.

The executor is designed to work with FastMCP servers and provides
safe fallbacks when transformations fail.
"""

import json
import logging
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from ..utils.async_compat import install_compatibility_policy

# Install compatibility policy if needed (no monkey-patching)
install_compatibility_policy()


class DeclarativeTransformExecutor:
    """Execute declarative transform rules from sidecars.

    This minimal executor supports:
    - parse_payload: json_or_yaml
    - apply_preset: (stub hook)
    - coerce: enum_case, date_yyyy_mm_dd (stub hooks)
    - compose: variable substitution "$var" within dict structures
    """

    def __init__(self, namespace: str, rules: Dict[str, Any]):
        """Initialize the transform executor with namespace and rules.

        :param namespace: Namespace identifier for the executor
        :type namespace: str
        :param rules: Dictionary containing transform rules and configuration
        :type rules: Dict[str, Any]
        """
        self.namespace = namespace
        self.rules = rules or {}
        self.version = rules.get("version", "1.0")
        self._preset_cache: Dict[str, Any] = {}
        self._logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")

    def create_input_transform(
        self, rule: Dict[str, Any]
    ) -> Optional[Callable[[Dict[str, Any]], Any]]:
        """Create an input transformation function from rule configuration.

        Generates an async function that applies various input transformations
        including payload parsing, preset application, data coercion, and
        default value injection.

        :param rule: Rule configuration dictionary containing input_transform
                     settings
        :type rule: Dict[str, Any]
        :return: Async transformation function or None if no input transform
                 is configured
        :rtype: Optional[Callable[[Dict[str, Any]], Any]]
        """
        cfg = rule.get("input_transform")
        if not cfg:
            return None

        async def _transform(args: Dict[str, Any]) -> Dict[str, Any]:
            try:
                a = dict(args or {})

                # parse payload if requested
                if cfg.get("parse_payload") == "json_or_yaml" and "payload" in a:
                    a["payload"] = self._parse_flexible(a.get("payload"))

                # apply presets
                if cfg.get("apply_preset") and a.get("preset_id"):
                    a["payload"] = await self._apply_preset(
                        a.get("payload"), a.get("preset_id")
                    )

                # coercions
                a = self._apply_coercions(a, cfg.get("coerce", []))

                # argument aliases (compatibility shims)
                # Example: {"from": "reportId", "to": "reportIds", "wrap": "list"}
                #
                # Round 4 #1: emit ``_meta.normalized`` events when an alias
                # fires so agents see the rewrite. Events flow through the
                # same per-call ``_CURRENT_NORMALIZATION_EVENTS`` ContextVar
                # the schema-driven middleware uses; the
                # ``MetaInjectionMiddleware`` reads it on success and
                # surfaces under ``_meta.normalized``.
                aliases = cfg.get("arg_aliases")
                if isinstance(aliases, list):
                    from ..middleware.schema_normalization import (
                        _CURRENT_NORMALIZATION_EVENTS as _NORM_EVENTS,
                    )

                    for alias in aliases:
                        if not isinstance(alias, dict):
                            continue
                        src = alias.get("from")
                        dst = alias.get("to")
                        wrap = alias.get("wrap")
                        if not isinstance(src, str) or not isinstance(dst, str):
                            continue
                        if dst in a and a.get(dst) not in (None, ""):
                            continue
                        if src not in a or a.get(src) in (None, ""):
                            continue
                        original_val = a.get(src)
                        val = original_val
                        if wrap == "list":
                            val = val if isinstance(val, list) else [val]
                        a[dst] = val

                        existing_events = _NORM_EVENTS.get() or []
                        new_events = list(existing_events)
                        new_events.append(
                            {
                                "kind": "renamed",
                                "from": src,
                                "to": dst,
                                "reason": "arg_alias",
                            }
                        )
                        if val is not original_val:
                            new_events.append(
                                {
                                    "kind": "coerced",
                                    "field": dst,
                                    "from_type": type(original_val).__name__,
                                    "to_type": type(val).__name__,
                                    "reason": "arg_alias_wrap",
                                }
                            )
                        _NORM_EVENTS.set(new_events)

                # defaults: relative time (e.g., set minCreationTime if missing)
                defaults = cfg.get("defaults") if isinstance(cfg, dict) else None
                if isinstance(defaults, dict):
                    rel = defaults.get("relative_time")
                    if isinstance(rel, dict):
                        import datetime as _dt

                        for key, spec in rel.items():
                            try:
                                if key not in a or a.get(key) in (None, ""):
                                    days = int((spec or {}).get("days_ago", 30))
                                    base = _dt.datetime.now(_dt.timezone.utc)
                                    target = base - _dt.timedelta(days=days)
                                    epoch = _dt.datetime(
                                        1970, 1, 1, tzinfo=_dt.timezone.utc
                                    )
                                    a[key] = int(
                                        (target - epoch).total_seconds() * 1000
                                    )
                            except Exception:
                                continue

                # require_any_of: ensure at least one of param groups is present
                require_any = (
                    cfg.get("require_any_of") if isinstance(cfg, dict) else None
                )
                if isinstance(require_any, list):
                    for group in require_any:
                        if isinstance(group, (list, tuple)):
                            if not any(
                                (g in a and a.get(g) not in (None, "")) for g in group
                            ):
                                # If none present, leave defaults to satisfy; otherwise pass-through
                                pass

                # compose final request dict
                composed = cfg.get("compose")
                if isinstance(composed, dict):
                    return self._compose_structure(composed, a)
                return a
            except Exception:
                # Fail-safe: return original args to avoid breaking calls
                return dict(args or {})

        return _transform

    def create_output_transform(
        self, rule: Dict[str, Any]
    ) -> Optional[Callable[[Any], Any]]:
        """Create an output transformation function from rule configuration.

        Generates an async function that applies output transformations
        including projection, sampling, summary wrapping, and artifact
        threshold handling.

        :param rule: Rule configuration dictionary containing output_transform
                     settings
        :type rule: Dict[str, Any]
        :return: Async transformation function or None if no output transform
                 is configured
        :rtype: Optional[Callable[[Any], Any]]
        """
        cfg = rule.get("output_transform")
        if not cfg:
            return None

        async def _transform(resp: Any) -> Any:
            try:
                out = resp
                # Projection
                projection = cfg.get("projection") if isinstance(cfg, dict) else None
                if projection and isinstance(out, dict):
                    out = {k: out.get(k) for k in projection}

                # Sampling of list fields
                sample_n = cfg.get("sample_n") if isinstance(cfg, dict) else None
                if isinstance(sample_n, int) and sample_n > 0:
                    out = self._truncate_lists(out, sample_n)

                # Summary wrapper
                summary = cfg.get("summary") if isinstance(cfg, dict) else None
                if summary and isinstance(out, dict):
                    out = {
                        "summary": {k: out.get(k) for k in summary},
                        "data": out,
                    }

                # Artifact threshold
                thresh = (
                    cfg.get("artifact_threshold_bytes")
                    if isinstance(cfg, dict)
                    else None
                )
                if isinstance(thresh, int) and thresh > 0:
                    try:
                        s = json.dumps(out, ensure_ascii=False)
                        size = len(s.encode("utf-8"))
                        if size > thresh:
                            base = Path.cwd() / "data" / "amc"
                            base.mkdir(parents=True, exist_ok=True)
                            from time import time

                            fpath = (
                                base / f"artifact_{self.namespace}_{int(time())}.json"
                            )
                            fpath.write_text(s, encoding="utf-8")
                            return {
                                "artifact_path": str(fpath),
                                "size_bytes": size,
                                "truncated": True,
                            }
                    except Exception:
                        pass

                return out
            except Exception:
                return resp

        return _transform

    def create_call_transform(
        self, rule: Dict[str, Any]
    ) -> Optional[Callable[..., Any]]:
        """Create a wrapper that can implement pagination and batching.

        Expected FastMCP call signature (subject to availability):
            async def call_transform(call_next, args: dict) -> any

        If unsupported in the current FastMCP build, sidecar_loader will skip.

        :param rule: Rule configuration dictionary containing pagination
                     and batching settings
        :type rule: Dict[str, Any]
        :return: Async call transformation function or None if no call
                 transform is needed
        :rtype: Optional[Callable[..., Any]]
        """
        pagination = rule.get("pagination") if isinstance(rule, dict) else None
        batch = rule.get("batch") if isinstance(rule, dict) else None
        output_cfg = rule.get("output_transform") if isinstance(rule, dict) else None
        if not pagination and not batch:
            # Still allow call-level shaping based on args if output_cfg exists
            if not output_cfg:
                return None

        async def _call(
            call_next: Callable[[Dict[str, Any]], Any], args: Dict[str, Any]
        ):
            # Apply batching first if configured and payload is a list
            if batch and isinstance(batch, dict):
                size = int(batch.get("size", 0) or 0)
                path = batch.get("path") or "payload"
                if size > 0:
                    lst = self._get_by_path(args, path)
                    if isinstance(lst, list) and len(lst) > size:
                        results: List[Any] = []
                        batch_errors: List[Dict[str, Any]] = []
                        for i in range(0, len(lst), size):
                            chunk = lst[i : i + size]
                            chunk_args = dict(args)
                            self._set_by_path(chunk_args, path, chunk)
                            try:
                                res = await call_next(chunk_args)
                                results.append(res)
                            except Exception as e:
                                batch_errors.append(
                                    {"chunk": i // size, "error": str(e)}
                                )
                                continue
                        # Smart aggregation
                        if all(isinstance(r, dict) for r in results):
                            if all(isinstance(r.get("items"), list) for r in results):
                                merged = []
                                for r in results:
                                    merged.extend(r.get("items", []))
                                out = {"items": merged, "count": len(merged)}
                                if batch_errors:
                                    out["batch_errors"] = batch_errors
                                return out
                            if all("errors" in r for r in results):
                                errs: List[Any] = []
                                for r in results:
                                    errs.extend(r.get("errors", []))
                                out = {
                                    "errors": errs,
                                    "batches_processed": len(results),
                                }
                                if batch_errors:
                                    out["batch_errors"] = batch_errors
                                return out
                        out = {"batches": len(results), "results": results}
                        if batch_errors:
                            out["batch_errors"] = batch_errors
                        return out

            # Pagination handling
            if (
                pagination
                and isinstance(pagination, dict)
                and pagination.get("all_pages")
            ):
                param_name = pagination.get("param_name") or "nextToken"
                response_key = pagination.get("response_key") or "nextToken"
                limit_param = pagination.get("limit_param")
                # Seed args (do not mutate original)
                cur_args = dict(args)
                if (
                    limit_param
                    and "default_limit" in pagination
                    and limit_param not in cur_args
                ):
                    # put limit into params if present
                    # Assume top-level arg schema; sidecar input_transform can also inject
                    cur_args[limit_param] = pagination.get("default_limit")

                pages: List[Any] = []
                next_token = None
                page_count = 0
                max_pages = int(pagination.get("max_pages", 100) or 100)
                while True:
                    if next_token:
                        cur_args[param_name] = next_token
                    res = await call_next(cur_args)
                    pages.append(res)
                    # Extract next token from response
                    next_token = None
                    if isinstance(res, dict):
                        next_token = res.get(response_key)
                    page_count += 1
                    if not next_token or page_count >= max_pages:
                        break
                shaped = {"pages": page_count, "results": pages}
                # Apply optional output shaping on aggregated results
                if output_cfg:
                    shaped = self._shape_output(shaped, output_cfg, args)
                return shaped

            # Default: single call
            res = await call_next(args)
            if output_cfg:
                res = self._shape_output(res, output_cfg, args)
            return res

        return _call

    def _compose_structure(self, template: Any, args: Dict[str, Any]) -> Any:
        """Compose a structure using template and variable substitution.

        Recursively processes a template structure, replacing variables
        starting with '$' with values from the args dictionary.

        :param template: Template structure (dict, list, or scalar)
        :type template: Any
        :param args: Arguments dictionary for variable substitution
        :type args: Dict[str, Any]
        :return: Composed structure with variables substituted
        :rtype: Any
        """
        if isinstance(template, dict):
            out = {}
            for k, v in template.items():
                out[k] = self._compose_structure(v, args)
            return out
        if isinstance(template, list):
            return [self._compose_structure(x, args) for x in template]
        if isinstance(template, str) and template.startswith("$"):
            return args.get(template[1:])
        return template

    def _apply_coercions(self, args: Dict[str, Any], kinds: Any) -> Dict[str, Any]:
        """Apply specified data type coercions to arguments.

        :param args: Arguments dictionary to apply coercions to
        :type args: Dict[str, Any]
        :param kinds: List of coercion types to apply
        :type kinds: Any
        :return: Arguments with coercions applied
        :rtype: Dict[str, Any]
        """
        if not kinds:
            return args
        data = dict(args)
        for kind in kinds:
            if kind == "enum_case":
                data = self._coerce_enum_case(data)
            elif kind == "date_yyyy_mm_dd":
                data = self._coerce_dates(data)
            elif kind == "number_to_string":
                data = self._coerce_numbers_to_strings(data)
            elif kind == "iso_to_epoch_ms":
                data = self._coerce_iso_to_epoch_ms(data)
        return data

    def _walk(self, obj: Any, fn: Callable[[Any], Any]) -> Any:
        """Recursively walk through a data structure applying a function.

        :param obj: Object to walk through (dict, list, or scalar)
        :type obj: Any
        :param fn: Function to apply to each scalar value
        :type fn: Callable[[Any], Any]
        :return: New structure with function applied to all scalar values
        :rtype: Any
        """
        if isinstance(obj, dict):
            return {k: self._walk(v, fn) for k, v in obj.items()}
        if isinstance(obj, list):
            return [self._walk(x, fn) for x in obj]
        return fn(obj)

    def _coerce_enum_case(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Convert string values to uppercase for enum-like fields.

        :param data: Data dictionary to process
        :type data: Dict[str, Any]
        :return: Data with string values converted to uppercase
        :rtype: Dict[str, Any]
        """

        def fn(v: Any) -> Any:
            if isinstance(v, str) and v.isalpha():
                return v.upper()
            return v

        return self._walk(data, fn)

    def _coerce_dates(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Convert various date formats to YYYY-MM-DD format.

        :param data: Data dictionary to process
        :type data: Dict[str, Any]
        :return: Data with date strings normalized to YYYY-MM-DD format
        :rtype: Dict[str, Any]
        """
        from datetime import datetime

        def fn(v: Any) -> Any:
            if isinstance(v, str):
                for fmt in (
                    "%Y-%m-%d",
                    "%Y/%m/%d",
                    "%m/%d/%Y",
                    "%Y-%m-%dT%H:%M:%S",
                    "%Y-%m-%dT%H:%M:%S.%fZ",
                ):
                    try:
                        dt = datetime.strptime(v, fmt)
                        return dt.strftime("%Y-%m-%d")
                    except Exception:
                        continue
            return v

        return self._walk(data, fn)

    def _coerce_numbers_to_strings(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Convert numeric values to strings.

        :param data: Data dictionary to process
        :type data: Dict[str, Any]
        :return: Data with numeric values converted to strings
        :rtype: Dict[str, Any]
        """

        def fn(v: Any) -> Any:
            if isinstance(v, (int, float)):
                return str(v)
            return v

        return self._walk(data, fn)

    def _coerce_iso_to_epoch_ms(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Convert ISO-like timestamps to epoch milliseconds for common time keys.

        This function targets specific time-related fields and converts
        various timestamp formats to epoch milliseconds for consistency.

        :param data: Data dictionary to process
        :type data: Dict[str, Any]
        :return: Data with time fields converted to epoch milliseconds
        :rtype: Dict[str, Any]
        """
        targets = {
            "minCreationTime",
            "maxCreationTime",
            "startTime",
            "endTime",
        }

        def to_epoch_ms(val: Any) -> Any:
            # Pass through if already int-like
            if isinstance(val, int):
                # Heuristic: assume seconds if < 10^12
                return val if val > 10**12 else val * 1000
            if isinstance(val, float):
                return int(val * 1000)
            if isinstance(val, str):
                s = val.strip()
                # Numeric string
                if s.isdigit():
                    n = int(s)
                    return n if n > 10**12 else n * 1000
                # Try ISO 8601
                try:
                    import datetime as _dt

                    iso = s
                    if iso.endswith("Z"):
                        iso = iso[:-1] + "+00:00"
                    # Date only → assume midnight UTC
                    if len(iso) == 10 and iso.count("-") == 2:
                        iso = iso + "T00:00:00+00:00"
                    # Compact date YYYYMMDD
                    if len(s) == 8 and s.isdigit():
                        iso = f"{s[0:4]}-{s[4:6]}-{s[6:8]}T00:00:00+00:00"
                    dt = _dt.datetime.fromisoformat(iso)
                    if dt.tzinfo is None:
                        dt = dt.replace(tzinfo=_dt.timezone.utc)
                    epoch = _dt.datetime(1970, 1, 1, tzinfo=_dt.timezone.utc)
                    return int((dt - epoch).total_seconds() * 1000)
                except Exception:
                    return val
            return val

        def walk(obj: Any) -> Any:
            if isinstance(obj, dict):
                out = {}
                for k, v in obj.items():
                    if k in targets:
                        out[k] = to_epoch_ms(v)
                    else:
                        out[k] = walk(v)
                return out
            if isinstance(obj, list):
                return [walk(x) for x in obj]
            return obj

        return walk(data)

    def _coerce_iso_to_amc(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Convert flexible timestamps to AMC ISO format 'YYYY-MM-DDTHH:MM:SS'.

        This function converts various timestamp formats to the AMC-specific
        ISO format for consistency across the system.

        :param data: Data dictionary to process
        :type data: Dict[str, Any]
        :return: Data with time fields converted to AMC ISO format
        :rtype: Dict[str, Any]
        """
        targets = {
            "minCreationTime",
            "maxCreationTime",
            "startTime",
            "endTime",
        }

        def to_iso(val: Any) -> Any:
            if isinstance(val, int):
                # assume ms if large
                n = val if val > 10**12 else val * 1000
                import datetime as _dt

                dt = _dt.datetime.fromtimestamp(n / 1000, tz=_dt.timezone.utc)
                return dt.strftime("%Y-%m-%dT%H:%M:%S")
            if isinstance(val, float):
                import datetime as _dt

                dt = _dt.datetime.fromtimestamp(val, tz=_dt.timezone.utc)
                return dt.strftime("%Y-%m-%dT%H:%M:%S")
            if isinstance(val, str):
                s = val.strip()
                if s.isdigit():
                    n = int(s)
                    if n < 10**12:
                        n *= 1000
                    import datetime as _dt

                    dt = _dt.datetime.fromtimestamp(n / 1000, tz=_dt.timezone.utc)
                    return dt.strftime("%Y-%m-%dT%H:%M:%S")
                try:
                    import datetime as _dt

                    iso = s
                    if iso.endswith("Z"):
                        iso = iso[:-1] + "+00:00"
                    if len(iso) == 10 and iso.count("-") == 2:
                        iso = iso + "T00:00:00+00:00"
                    if len(s) == 8 and s.isdigit():
                        iso = f"{s[0:4]}-{s[4:6]}-{s[6:8]}T00:00:00+00:00"
                    dt = _dt.datetime.fromisoformat(iso)
                    if dt.tzinfo is None:
                        dt = dt.replace(tzinfo=_dt.timezone.utc)
                    return dt.astimezone(_dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")
                except Exception:
                    return val
            return val

        def walk(obj: Any) -> Any:
            if isinstance(obj, dict):
                out = {}
                for k, v in obj.items():
                    if k in targets:
                        out[k] = to_iso(v)
                    else:
                        out[k] = walk(v)
                return out
            if isinstance(obj, list):
                return [walk(x) for x in obj]
            return obj

        return walk(data)

    async def _apply_preset(self, payload: Any, preset_id: Optional[str]) -> Any:
        """Merge preset data into payload if preset file exists.

        Preset search path: config/presets/<namespace>/<preset_id>.(json|yaml|yml)

        :param payload: Original payload data
        :type payload: Any
        :param preset_id: Identifier for the preset to apply
        :type preset_id: Optional[str]
        :return: Payload with preset data merged in
        :rtype: Any
        """
        if not preset_id:
            return payload
        base = Path.cwd() / "config" / "presets" / self.namespace
        candidates = [
            base / f"{preset_id}.json",
            base / f"{preset_id}.yaml",
            base / f"{preset_id}.yml",
        ]
        preset_data: Any = None
        for p in candidates:
            if p.exists():
                try:
                    if p.suffix == ".json":
                        preset_data = json.loads(p.read_text(encoding="utf-8"))
                    else:
                        import yaml  # type: ignore

                        preset_data = yaml.safe_load(p.read_text(encoding="utf-8"))
                except Exception:
                    preset_data = None
                break
        if isinstance(preset_data, dict):
            if not self._validate_preset(preset_data, str(preset_id)):
                self._logger.warning("Preset %s failed validation", preset_id)
                return payload
        if isinstance(preset_data, dict) and isinstance(payload, dict):
            return self._deep_merge_dicts(preset_data, payload)
        return payload

    def _parse_flexible(self, payload: Any) -> Any:
        """Parse payload as JSON or YAML if it's a string.

        :param payload: Payload to parse
        :type payload: Any
        :return: Parsed payload or original if parsing fails
        :rtype: Any
        """
        if isinstance(payload, (dict, list)):
            return payload
        if isinstance(payload, str):
            try:
                return json.loads(payload)
            except Exception:
                try:
                    import yaml  # type: ignore

                    return yaml.safe_load(payload)
                except Exception:
                    return payload
        return payload

    def _deep_merge_dicts(self, a: Dict[str, Any], b: Dict[str, Any]) -> Dict[str, Any]:
        """Deep merge dict b into a (without mutating inputs).

        :param a: Base dictionary
        :type a: Dict[str, Any]
        :param b: Dictionary to merge into base
        :type b: Dict[str, Any]
        :return: New merged dictionary
        :rtype: Dict[str, Any]
        """
        out: Dict[str, Any] = {}
        keys = set(a.keys()) | set(b.keys())
        for k in keys:
            va = a.get(k)
            vb = b.get(k)
            if isinstance(va, dict) and isinstance(vb, dict):
                out[k] = self._deep_merge_dicts(va, vb)
            elif vb is not None:
                out[k] = vb
            else:
                out[k] = va
        return out

    def _get_by_path(self, obj: Dict[str, Any], path: str) -> Any:
        """Get a value from a nested dictionary using dot notation path.

        :param obj: Dictionary to traverse
        :type obj: Dict[str, Any]
        :param path: Dot-separated path to the target value
        :type path: str
        :return: Value at the specified path or None if not found
        :rtype: Any
        """
        cur: Any = obj
        for part in path.split("."):
            if isinstance(cur, dict):
                cur = cur.get(part)
            else:
                return None
        return cur

    def _set_by_path(self, obj: Dict[str, Any], path: str, value: Any) -> None:
        """Set a value in a nested dictionary using dot notation path.

        :param obj: Dictionary to modify
        :type obj: Dict[str, Any]
        :param path: Dot-separated path to the target location
        :type path: str
        :param value: Value to set at the specified path
        :type value: Any
        """
        parts = path.split(".")
        cur: Any = obj
        for p in parts[:-1]:
            if p not in cur or not isinstance(cur[p], dict):
                cur[p] = {}
            cur = cur[p]
        cur[parts[-1]] = value

    def _validate_preset(self, preset_data: Dict[str, Any], preset_id: str) -> bool:
        """Basic preset validation hook.

        In absence of per-operation schemas, ensure it's a dict and non-empty.
        This can be extended to check required fields per operation.

        :param preset_data: Preset data to validate
        :type preset_data: Dict[str, Any]
        :param preset_id: Identifier for the preset being validated
        :type preset_id: str
        :return: True if preset is valid, False otherwise
        :rtype: bool
        """
        return isinstance(preset_data, dict) and len(preset_data) > 0

    def _shape_output(self, out: Any, cfg: Dict[str, Any], args: Dict[str, Any]) -> Any:
        """Apply output shaping rules with optional arg overrides.

        :param out: Output data to shape
        :type out: Any
        :param cfg: Output transform configuration
        :type cfg: Dict[str, Any]
        :param args: Input arguments that may override configuration
        :type args: Dict[str, Any]
        :return: Shaped output data
        :rtype: Any
        """
        try:
            result = out
            # Arg overrides
            view = (args or {}).get("view")
            include_columns = bool((args or {}).get("include_columns"))
            user_sample = (args or {}).get("sample_n")

            # Projection
            projection = cfg.get("projection") if isinstance(cfg, dict) else None
            if view == "full" or include_columns:
                projection = None
            if projection and isinstance(result, dict):
                result = {k: result.get(k) for k in projection}

            # Sampling
            sample_n = None
            if isinstance(user_sample, int) and user_sample > 0:
                sample_n = user_sample
            elif isinstance(cfg.get("sample_n"), int) and cfg.get("sample_n") > 0:
                sample_n = cfg.get("sample_n")
            if sample_n:
                result = self._truncate_lists(result, sample_n)

            # Summary wrapper
            summary = cfg.get("summary") if isinstance(cfg, dict) else None
            if summary and isinstance(result, dict):
                result = {
                    "summary": {k: result.get(k) for k in summary},
                    "data": result,
                }

            # Artifact threshold
            thresh = (
                cfg.get("artifact_threshold_bytes") if isinstance(cfg, dict) else None
            )
            if isinstance(thresh, int) and thresh > 0:
                try:
                    s = json.dumps(result, ensure_ascii=False)
                    size = len(s.encode("utf-8"))
                    if size > thresh:
                        base = Path.cwd() / "data" / "amc"
                        base.mkdir(parents=True, exist_ok=True)
                        from time import time

                        fpath = base / f"artifact_{self.namespace}_{int(time())}.json"
                        fpath.write_text(s, encoding="utf-8")
                        return {
                            "artifact_path": str(fpath),
                            "size_bytes": size,
                            "truncated": True,
                        }
                except Exception:
                    pass
            return result
        except Exception:
            return out

    def _truncate_lists(self, data: Any, n: int) -> Any:
        """Recursively truncate all lists in a structure to at most n items.

        This helps prevent extremely large responses from overwhelming
        the client context. Only list lengths are affected; scalars and
        dict keys are preserved. The function does not mutate the input.

        :param data: Arbitrary JSON-like structure (dict/list/scalars)
        :type data: Any
        :param n: Maximum number of items to keep in any list
        :type n: int
        :return: New structure with lists truncated to n items
        :rtype: Any
        """
        try:

            def walk(obj: Any) -> Any:
                if isinstance(obj, list):
                    return [walk(x) for x in obj[: max(0, n)]]
                if isinstance(obj, dict):
                    return {k: walk(v) for k, v in obj.items()}
                return obj

            return walk(data)
        except Exception:
            # Fail safe: return original if anything goes wrong
            return data
