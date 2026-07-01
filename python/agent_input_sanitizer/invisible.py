"""The payload-capable invisible-character charset, shared across languages.

This is the Python side of the single source of truth defined in
``src/invisible.mjs``. It reads the generated ``data/invisible-charset.json``
(the non-Cf "extra" code points — variation selectors, blank-rendering fillers,
zero-width combining marks) and unions them with the live general-category ``Cf``
set resolved from this interpreter's ``unicodedata``.

A consumer that must strip or match invisible characters — e.g.
``agent-secret-redactor`` — imports :func:`invisible_charset` here rather than
forking the list. A fork is a silent security regression: a code point added on
one side but not the other lets a payload spliced with it escape that layer. If
the packaged data file is missing this module raises at import time (fail
closed), never falling back to a partial set.
"""

import functools
import json
import unicodedata
from pathlib import Path

_CHARSET_FILE = Path(__file__).resolve().parent / "data" / "invisible-charset.json"


@functools.cache
def extra_codepoints() -> frozenset[int]:
    """The payload-capable code points that are NOT general-category ``Cf``,
    read from the generated SSOT. Raises if the data file is absent (fail closed —
    a partial charset silently under-matches)."""
    data = json.loads(_CHARSET_FILE.read_text())
    return frozenset(data["extra_codepoints"])


@functools.cache
def _live_cf_codepoints() -> frozenset[int]:
    """Every general-category ``Cf`` code point in this interpreter's Unicode data."""
    return frozenset(
        cp for cp in range(0x110000) if unicodedata.category(chr(cp)) == "Cf"
    )


@functools.cache
def invisible_charset() -> frozenset[int]:
    """The full set of payload-capable invisible code points: every ``Cf`` char
    (dynamic) UNION the generated non-Cf extras. This is the deletion set
    ``src/invisible.mjs`` strips, so a cross-language consumer that uses it cannot
    drift from the JS layer."""
    return _live_cf_codepoints() | extra_codepoints()


# The non-Cf extras as a frozenset, for callers that want to pin exactly the
# hand-curated part against the JS SSOT.
INVISIBLE_EXTRA = extra_codepoints()
