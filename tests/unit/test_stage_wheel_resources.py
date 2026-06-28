"""Unit tests for the wheel resource staging module (issue #91).

Fast, hermetic tests against synthetic source/dest trees — no real dist
artifacts or wheel build required. The end-to-end "specs actually ship in
the wheel" guarantee lives in test_wheel_package_data.py (slow).
"""

from __future__ import annotations

from pathlib import Path

from amazon_ads_mcp.build import stage_wheel_resources as sw


def _seed_dist(tmp: Path) -> tuple[Path, Path, Path]:
    resources = tmp / "dist" / "openapi" / "resources"
    overlays = tmp / "dist" / "openapi" / "overlays"
    dest = tmp / "src" / "amazon_ads_mcp" / "resources"
    resources.mkdir(parents=True)
    overlays.mkdir(parents=True)
    dest.mkdir(parents=True)

    (resources / "AccountsProfiles.json").write_text("{}")
    (resources / "AccountsProfiles.media.json").write_text("{}")
    (resources / "packages.json").write_text("{}")
    (overlays / "AdsAPIv1All.json").write_text("{}")
    (overlays / "README.md").write_text("not json")  # must be ignored
    return resources, overlays, dest


def test_stage_copies_specs_and_overlays(tmp_path: Path):
    resources, overlays, dest = _seed_dist(tmp_path)

    counts = sw.stage(resources, overlays, dest)

    assert counts == {"resources": 3, "overlays": 1}
    assert (dest / "AccountsProfiles.json").exists()
    assert (dest / "packages.json").exists()
    assert (dest / "overlays" / "AdsAPIv1All.json").exists()
    # Non-JSON overlay sidecar must not be copied.
    assert not (dest / "overlays" / "README.md").exists()


def test_stage_preserves_committed_subpackages(tmp_path: Path):
    """Staging must not clobber the committed adsv1/ and contract/ trees."""
    resources, overlays, dest = _seed_dist(tmp_path)
    (dest / "adsv1").mkdir()
    (dest / "adsv1" / "metrics.json").write_text('{"keep": true}')
    (dest / "contract").mkdir()
    (dest / "contract" / "errors.json").write_text('{"keep": true}')

    sw.stage(resources, overlays, dest)

    assert (dest / "adsv1" / "metrics.json").read_text() == '{"keep": true}'
    assert (dest / "contract" / "errors.json").read_text() == '{"keep": true}'


def test_stage_is_noop_when_source_absent(tmp_path: Path):
    """Docker builder path: no dist/ present -> graceful no-op."""
    dest = tmp_path / "src" / "amazon_ads_mcp" / "resources"
    dest.mkdir(parents=True)

    counts = sw.stage(tmp_path / "missing", tmp_path / "missing_overlays", dest)

    assert counts == {"resources": 0, "overlays": 0}
    assert list(dest.iterdir()) == []


def test_clean_removes_only_staged_files(tmp_path: Path):
    resources, overlays, dest = _seed_dist(tmp_path)
    # A committed subpackage that clean() must leave alone.
    (dest / "adsv1").mkdir()
    (dest / "adsv1" / "metrics.json").write_text("{}")

    sw.stage(resources, overlays, dest)
    removed = sw.clean(dest)

    assert removed == 3  # the three top-level *.json staged above
    assert not (dest / "AccountsProfiles.json").exists()
    assert not (dest / "overlays").exists()
    # Committed subpackage survives.
    assert (dest / "adsv1" / "metrics.json").exists()


def test_stage_is_idempotent(tmp_path: Path):
    resources, overlays, dest = _seed_dist(tmp_path)

    first = sw.stage(resources, overlays, dest)
    second = sw.stage(resources, overlays, dest)

    assert first == second == {"resources": 3, "overlays": 1}
