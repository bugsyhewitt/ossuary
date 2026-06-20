"""v0.1 release ship-gate: build the wheel, install into a fresh venv, prove it works.

Skippable via `pytest -m "not ship_gate"`. Runs in the full v0.1 suite.
"""

from __future__ import annotations

import subprocess
import sys
import venv
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parent.parent
DIST = REPO_ROOT / "dist"

# Runtime deps the wheel itself declares in pyproject.toml [project.dependencies].
# Installing them into the fresh venv proves the wheel's metadata is complete.
_RUNTIME_DEPS = [
    "httpx>=0.27",
    "nmap-wrapper @ git+https://github.com/bugsyhewitt/nmap-wrapper",
]

# Public surface — every sub-module under src/ossuary/ (verified at wake).
_PUBLIC_MODULES = [
    "ossuary.cli",
    "ossuary.cruise",
    "ossuary.cves",
    "ossuary.db",
    "ossuary.discover",
    "ossuary.dump",
    "ossuary.enrich",
    "ossuary.findingdiff",
    "ossuary.fingerprint",
    "ossuary.probe",
    "ossuary.profiles",
    "ossuary.stale",
    "ossuary.stats",
    "ossuary.tags",
    "ossuary.vex",
    "ossuary.watch",
    "ossuary.web",
]

# Names the `ossuary profiles` subcommand must list — verified at wake.
_EXPECTED_PROFILES = {"default", "stealth", "aggressive", "web"}


def _run(cmd, **kw):
    return subprocess.run(cmd, check=True, capture_output=True, text=True, **kw)


def _ensure_build_available():
    """The `build` package is invoked as a subprocess; if absent in the test
    runner's venv, install it. This is the only state the test mutates outside
    its own tmp_path."""
    try:
        _run([sys.executable, "-m", "build", "--version"])
    except (subprocess.CalledProcessError, FileNotFoundError):
        _run([sys.executable, "-m", "pip", "install", "--quiet", "build"])


@pytest.mark.ship_gate
def test_wheel_builds_cleanly(tmp_path):
    """`python -m build --wheel --sdist` produces both artifacts with no error."""
    _ensure_build_available()
    out = tmp_path / "build-out"
    _run(
        [sys.executable, "-m", "build", "--wheel", "--sdist", "--outdir", str(out)],
        cwd=str(REPO_ROOT),
    )
    wheels = list(out.glob("ossuary-1.0.0-*.whl"))
    sdists = list(out.glob("ossuary-1.0.0.tar.gz"))
    assert wheels, f"wheel not built; got: {sorted(p.name for p in out.iterdir())}"
    assert sdists, f"sdist not built; got: {sorted(p.name for p in out.iterdir())}"
    test_wheel_builds_cleanly._wheel = wheels[0]


@pytest.mark.ship_gate
def test_wheel_installs_into_fresh_venv(tmp_path):
    """`pip install <wheel>` into a brand-new venv resolves the entry-point."""
    wheel = getattr(test_wheel_builds_cleanly, "_wheel", None)
    if wheel is None:
        pytest.skip("preceding test did not produce a wheel")
    venv_dir = tmp_path / "fresh-venv"
    venv.create(venv_dir, with_pip=True, clear=True)
    pip = venv_dir / "bin" / "pip"
    _run([str(pip), "install", "--quiet", str(wheel), "--no-deps"])
    _run([str(pip), "install", "--quiet", *_RUNTIME_DEPS])
    version = _run([str(venv_dir / "bin" / "ossuary"), "--version"]).stdout.strip()
    assert version == "ossuary 1.0.0", f"unexpected version output: {version!r}"
    test_wheel_installs_into_fresh_venv._venv_dir = venv_dir


@pytest.mark.ship_gate
def test_wheel_version_importable_in_fresh_venv():
    """`import ossuary; assert ossuary.__version__ == '1.0.0'` in fresh venv."""
    venv_dir = getattr(test_wheel_installs_into_fresh_venv, "_venv_dir", None)
    if venv_dir is None:
        pytest.skip("preceding test did not install a wheel")
    py = venv_dir / "bin" / "python"
    _run(
        [str(py), "-c", "import ossuary; assert ossuary.__version__ == '1.0.0'"]
    )


@pytest.mark.ship_gate
def test_installed_wheel_public_api():
    """Every public module in the wheel install is importable."""
    venv_dir = getattr(test_wheel_installs_into_fresh_venv, "_venv_dir", None)
    if venv_dir is None:
        pytest.skip("preceding test did not install a wheel")
    py = venv_dir / "bin" / "python"
    code = "import importlib; mods = " + repr(_PUBLIC_MODULES) + (
        "; [importlib.import_module(m) for m in mods]; print('OK', len(mods))"
    )
    out = _run([str(py), "-c", code])
    assert f"OK {len(_PUBLIC_MODULES)}" in out.stdout, (
        f"public-API import failed: {out.stderr}"
    )


@pytest.mark.ship_gate
def test_installed_wheel_profiles_subcommand():
    """The installed wheel, run from a fresh venv, lists the four named
    scan profiles — proving the wheel install is functionally equivalent
    to the editable install for a read-only, no-DB, no-network path."""
    venv_dir = getattr(test_wheel_installs_into_fresh_venv, "_venv_dir", None)
    if venv_dir is None:
        pytest.skip("preceding test did not install a wheel")
    binary = venv_dir / "bin" / "ossuary"
    out = _run([str(binary), "profiles"]).stdout
    listed = {line.strip() for line in out.splitlines() if line.strip()}
    missing = _EXPECTED_PROFILES - listed
    assert not missing, (
        f"profiles subcommand missing expected names: {missing}; "
        f"got {sorted(listed)}"
    )


@pytest.mark.ship_gate
def test_changelog_exists_with_v1_0_0_entry():
    """Repo-root CHANGELOG.md must contain a top-level `## [1.0.0] - 2026-06-20`
    Keep-a-Changelog v1.1.0 section so the v1.0 release contract is on disk and
    future releases that forget the CHANGELOG fail this ship-gate.
    """
    changelog = REPO_ROOT / "CHANGELOG.md"
    assert changelog.is_file(), f"CHANGELOG.md not found at {changelog}"
    text = changelog.read_text(encoding="utf-8")
    assert "## [1.0.0] - 2026-06-20" in text, (
        f"CHANGELOG.md missing v1.0.0 entry; first 200 chars: {text[:200]!r}"
    )
