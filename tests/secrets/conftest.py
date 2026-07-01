"""Path setup and shared fixtures for the secrets test suite."""

import shutil
import sys
import tempfile
from pathlib import Path

import pytest

# The distribution package lives under python/; put it on the path so
# `import agent_input_sanitizer.secrets` resolves to the working tree. The
# engine import in the fixture below (and in redactor_helpers) depends on this.
_PKG = Path(__file__).resolve().parents[2] / "python"
if str(_PKG) not in sys.path:
    sys.path.insert(0, str(_PKG))


@pytest.fixture
def eng():
    """The engine module (private helpers live here)."""
    import agent_input_sanitizer.secrets.engine as engine

    return engine


@pytest.fixture
def sock_dir():
    """A short-path directory for AF_UNIX sockets.

    macOS caps the AF_UNIX socket path at ~104 bytes; pytest's ``tmp_path``
    (``/private/var/folders/.../pytest-of-.../...``) overflows it, so a daemon
    test that binds there dies with ``OSError: AF_UNIX path too long``. ``/tmp``
    is short on both Linux and macOS, so socket-binding tests build their paths
    under a throwaway dir here instead of ``tmp_path``.
    """
    path = Path(tempfile.mkdtemp(dir="/tmp", prefix="rd-"))
    try:
        yield path
    finally:
        shutil.rmtree(path, ignore_errors=True)
