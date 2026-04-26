#!/usr/bin/env python3
"""Audit helper: enumerate multi-version vendored ops in shipped specs.

Walks every ``dist/openapi/resources/*.json`` OpenAPI spec, identifies operations
that declare more than one version of the same vendored JSON content type
(or more than one distinct base in one accepts list), and prints rows usable
for the spec-contract test suite at
``tests/unit/test_accept_resolver_against_spec.py``.

This script is a tool for humans — pytest does NOT import from it. The test
suite commits explicit ``(method, path, expected_accept)`` rows verbatim.
Re-run this script after a spec regeneration to see whether expected values
have shifted; update the test rows by hand if they have. The deliberate split
keeps the test suite stable and reviewable while making maintenance easy.

Usage::

    uv run python scripts/dump_multi_version_ops.py
    uv run python scripts/dump_multi_version_ops.py --spec SponsoredProducts
    uv run python scripts/dump_multi_version_ops.py --spec AmazonDSPMeasurement
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

# Mirror the resolver's regex so this audit is consistent with runtime behavior.
_VENDORED_JSON_RE = re.compile(
    r"^application/vnd\.([A-Za-z0-9._-]+)\.v(\d+)(?:\.(\d+))?\+json$"
)

_REPO_ROOT = Path(__file__).resolve().parents[1]
_DIST_RESOURCES = _REPO_ROOT / "dist" / "openapi" / "resources"


def _parse_vendored_json(ct: str) -> tuple[str, int, int] | None:
    m = _VENDORED_JSON_RE.match(ct)
    if not m:
        return None
    return m.group(1).lower(), int(m.group(2)), int(m.group(3) or 0)


def _pick_highest(accepts: list[str]) -> str | None:
    """Mirror of ``pick_highest_vendored_json`` for audit output."""
    parsed = [(p, ct) for ct in accepts if (p := _parse_vendored_json(ct))]
    if not parsed:
        return None
    bases = {p[0] for p, _ in parsed}
    if len(bases) > 1:
        return None
    best = max(parsed, key=lambda x: (x[0][1], x[0][2]))
    return best[1]


def _walk_spec(spec_path: Path) -> tuple[list[tuple], list[tuple]]:
    """Return (multi_version_rows, mixed_base_rows) for one spec.

    multi_version_rows: ops declaring >1 version of a SINGLE base
    mixed_base_rows: ops declaring >1 distinct vendored base in one accepts list
    """
    with open(spec_path) as f:
        spec = json.load(f)

    multi_version = []
    mixed_base = []
    for path, ops in (spec.get("paths") or {}).items():
        if not isinstance(ops, dict):
            continue
        for method, op in ops.items():
            if not isinstance(op, dict):
                continue
            cts: set[str] = set()
            for _, resp in (op.get("responses") or {}).items():
                if isinstance(resp, dict):
                    cts.update((resp.get("content") or {}).keys())
            accepts = sorted(cts)  # mirror MediaTypeRegistry's lexical sort
            bases: dict[str, set[tuple[int, int]]] = {}
            for ct in accepts:
                parsed = _parse_vendored_json(ct)
                if parsed:
                    bases.setdefault(parsed[0], set()).add(
                        (parsed[1], parsed[2])
                    )
            if not bases:
                continue
            single_base = len(bases) == 1
            max_versions = max(len(v) for v in bases.values())
            row = (
                op.get("operationId", "?"),
                method.upper(),
                path,
                accepts,
                _pick_highest(accepts),
            )
            if single_base and max_versions > 1:
                multi_version.append(row)
            if len(bases) > 1:
                mixed_base.append(row)
    return multi_version, mixed_base


def _format_param_row(
    op_id: str, method: str, path: str, accepts: list[str], expected: str | None
) -> str:
    indent = "        "
    expected_str = f'"{expected}"' if expected else "None"
    return (
        f"{indent}# {op_id}\n"
        f'{indent}("{method}", "{path}",\n'
        f"{indent}    {expected_str}),"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--spec",
        help="Limit output to a single spec (e.g. SponsoredProducts)",
    )
    args = parser.parse_args()

    if not _DIST_RESOURCES.exists():
        print(f"ERROR: {_DIST_RESOURCES} not found.", file=sys.stderr)
        return 1

    spec_files = sorted(_DIST_RESOURCES.glob("*.json"))
    spec_files = [
        p
        for p in spec_files
        if not any(p.name.endswith(s) for s in (".media.json", ".manifest.json", ".transform.json"))
    ]
    if args.spec:
        spec_files = [p for p in spec_files if p.stem == args.spec]
        if not spec_files:
            print(f"ERROR: no spec named {args.spec!r} in {_DIST_RESOURCES}")
            return 1

    total_multi = 0
    total_mixed = 0
    for spec_path in spec_files:
        multi_version, mixed_base = _walk_spec(spec_path)
        if not multi_version and not mixed_base:
            continue
        print(f"\n=== {spec_path.name} ===")
        if multi_version:
            print(f"# {len(multi_version)} multi-version single-base ops")
            for row in multi_version:
                print(_format_param_row(*row))
            total_multi += len(multi_version)
        if mixed_base:
            print(f"\n# {len(mixed_base)} mixed-base ops (resolver abstains, returns first-listed)")
            for op_id, method, path, accepts, _ in mixed_base:
                first_listed = accepts[0] if accepts else None
                print(
                    _format_param_row(
                        op_id + " [mixed-base]", method, path, accepts, first_listed
                    )
                )
            total_mixed += len(mixed_base)

    print(
        f"\n# Totals: {total_multi} multi-version single-base ops, "
        f"{total_mixed} mixed-base ops, across "
        f"{len(spec_files)} spec(s)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
