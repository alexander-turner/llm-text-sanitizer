"""Guard the Python client's package version.

The Python distribution (`python/pyproject.toml`) versions the wrapper's own
API and is bumped BY HAND, independently of the npm release line (see the
comment on its ``version`` field). Hand-maintained version strings rot two ways:
a typo makes ``python -m build`` emit an unpublishable/mis-sorted wheel, and a
copy of the *npm* coupling assumption ("they must match") would be wrong here.
This pins the format and documents the policy so neither slips through.
"""

import re
import subprocess
from pathlib import Path

# Resolve the repo root via git rather than parent-walking from __file__, so the
# test keeps working if it is moved (per the project test conventions).
REPO_ROOT = Path(
    subprocess.run(
        ["git", "rev-parse", "--show-toplevel"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
)

# A normal PEP 440 *release* version (the only shape this project ships):
# 2-3 dot-separated integers, optionally a pre/post/dev suffix. Deliberately
# stricter than full PEP 440 — the client never ships epochs or local versions,
# so anything exotic is a mistake worth failing on.
_RELEASE_RE = re.compile(r"^\d+\.\d+(?:\.\d+)?(?:(?:a|b|rc|\.post|\.dev)\d+)?$")


def _read_version(pyproject: Path) -> str:
    """Pull the ``version = "..."`` line out of a pyproject without a TOML lib.

    Avoids ``tomllib`` so the guard runs unchanged on Python 3.10 (the package's
    floor; ``tomllib`` is 3.11+).
    """
    for line in pyproject.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        match = re.match(r'version\s*=\s*"(?P<value>[^"]+)"', stripped)
        if match:
            return match.group("value")
    raise AssertionError(f"no version field found in {pyproject}")


def test_python_client_version_is_a_valid_release() -> None:
    version = _read_version(REPO_ROOT / "python" / "pyproject.toml")
    assert _RELEASE_RE.match(version), (
        f"python/pyproject.toml version {version!r} is not a plain PEP 440 "
        "release (e.g. 1.2.6) — fix the version before publishing the wheel"
    )


def test_version_independence_policy_is_documented() -> None:
    """The independence-from-npm policy must stay written down next to the
    version, so a future maintainer who notices the two numbers differ reads
    *why* before "fixing" it into a wrong coupling.

    Asserts the rationale comment is present (a positive marker that we are on
    the intended line), not just that some text exists — a deleted comment is
    the regression. Pairs with a sanity check that the npm version is still
    parseable, proving the two files are genuinely independent inputs.
    """
    pyproject_text = (REPO_ROOT / "python" / "pyproject.toml").read_text(
        encoding="utf-8"
    )
    assert "NOT the npm release" in pyproject_text, (
        "the version-independence rationale comment was dropped from "
        "python/pyproject.toml — restore it before changing the version policy"
    )
    npm_version = re.search(
        r'"version":\s*"(?P<value>[^"]+)"',
        (REPO_ROOT / "package.json").read_text(encoding="utf-8"),
    )
    assert npm_version and npm_version.group("value"), (
        "npm package.json version missing"
    )
