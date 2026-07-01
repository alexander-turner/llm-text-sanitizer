"""Path setup and the engine-module fixture for the secrets test suite."""

import sys
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
