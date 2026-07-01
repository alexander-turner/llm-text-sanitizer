"""Invisible-character handling — charset SOURCED from agent-input-sanitizer.

The redactor strips payload-capable invisible characters before detection and
tolerates them spliced *between* the characters of an env-bound key (an attacker
who wedges a zero-width char into a leaked key must not slip it past exact-match
redaction). That charset is a cross-package security boundary: it MUST equal
agent-input-sanitizer's deletion set, or a key spliced with a code point one side
omits escapes BOTH layers.

So this module does NOT define the set — it imports it from the shared SSOT
(:mod:`agent_input_sanitizer.invisible`, the sibling package). There is
deliberately no local copy and no fallback: if the SSOT data file is absent,
:func:`default_charset` raises (fail closed) rather than silently under-matching
with a partial set.
"""

import functools
import re

# strip logic and the env-bound run-pattern live here; the CHARSET is imported.
from ..invisible import invisible_charset as _shared_charset


def default_charset() -> frozenset[int]:
    """The payload-capable invisible code points to strip / tolerate, from the
    shared agent-input-sanitizer SSOT. Raises (fail closed) if that dependency is
    unavailable — a partial charset silently under-matches, which is a security
    regression, so no fallback is offered."""
    return _shared_charset()


def strip_invisible(text: str, charset: frozenset[int] | None = None) -> str:
    """Delete every code point of ``charset`` from ``text`` (deletion only — the
    result is a subsequence of the input).

    ``charset`` defaults to :func:`default_charset` (the shared SSOT). Run before
    detection so a key with invisible chars spliced between its bytes is seen
    whole by every detector, not just the env-bound matcher's tolerance."""
    if charset is None:
        charset = default_charset()
    return "".join(ch for ch in text if ord(ch) not in charset)


@functools.cache
def invisible_run_pattern(charset: frozenset[int]) -> str:
    """A regex fragment matching an optional run of any code point in ``charset``
    (``[...]*``), for tolerating invisibles spliced between a value's characters.

    Cached per charset so the hot path never rebuilds it. Required literals sit
    between every optional run, so the pattern stays linear (no ReDoS)."""
    return "[" + "".join(re.escape(chr(cp)) for cp in sorted(charset)) + "]*"
