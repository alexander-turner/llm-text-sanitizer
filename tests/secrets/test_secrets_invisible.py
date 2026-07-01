"""Invisible-charset tests.

The charset is not defined here — it is imported from agent-input-sanitizer's
shared SSOT. These tests pin the sharing (the redactor's set equals the
sanitizer's), the strip semantics, and the fail-closed behaviour when the shared
dependency is unavailable.
"""

import unicodedata

import pytest

from agent_input_sanitizer.secrets import strip_invisible
from agent_input_sanitizer.secrets.invisible import (
    default_charset,
    invisible_run_pattern,
)

# Cf representatives by code point: zero-width, ZWNJ/ZWJ, word-joiner, BOM, soft
# hyphen, bidi override/isolate, TAG.
_STRIP_CF_CPS = [
    0x200B,
    0x200C,
    0x200D,
    0x2060,
    0xFEFF,
    0x00AD,
    0x202E,
    0x2066,
    0xE0001,
]


def _extra() -> frozenset[int]:
    from agent_input_sanitizer.invisible import INVISIBLE_EXTRA

    return INVISIBLE_EXTRA


# ─── The charset is shared, not copied ───────────────────────────────────────


def test_default_charset_is_live_cf_union_shared_extra():
    """The redactor's charset is exactly every live Cf code point UNION the shared
    non-Cf extras — no local list, so it cannot drift from the sanitizer."""
    live_cf = {c for c in range(0x110000) if unicodedata.category(chr(c)) == "Cf"}
    assert default_charset() == frozenset(live_cf) | _extra()


@pytest.mark.drift_guard
def test_shared_extra_matches_sanitizer_ssot():
    """The extra (non-Cf) set the redactor consumes is the one agent-input-sanitizer
    publishes from invisible.mjs (VS + BLANK_NON_CF): variation selectors, Hangul
    and Braille fillers, and the zero-width combining marks U+034F/U+17B4/U+17B5.
    A member dropped on either side diverges the two engines."""
    expected = (
        set(range(0xFE00, 0xFE10))
        | set(range(0xE0100, 0xE01F0))
        | {0x115F, 0x1160, 0x3164, 0xFFA0, 0x2800, 0x034F, 0x17B4, 0x17B5}
    )
    assert set(_extra()) == expected


def test_shared_extra_is_disjoint_from_cf():
    """The extras exist precisely to catch payload-capable blanks that are NOT Cf;
    a Cf char sneaking in would be dead weight and signal the two families drifted
    into overlap."""
    assert all(unicodedata.category(chr(cp)) != "Cf" for cp in _extra())


# ─── strip_invisible ─────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "cp", _STRIP_CF_CPS, ids=[f"Cf-U+{cp:04X}" for cp in _STRIP_CF_CPS]
)
def test_strip_invisible_deletes_each_cf_rep(cp):
    assert unicodedata.category(chr(cp)) == "Cf"
    assert strip_invisible("a" + chr(cp) + "b") == "ab"


def test_strip_invisible_deletes_every_extra_member():
    for cp in sorted(_extra()):
        assert strip_invisible("a" + chr(cp) + "b") == "ab", f"U+{cp:04X}"


def test_strip_invisible_preserves_visible_text():
    visible = "Hello, café — naïve 日本語 résumé! AKIA1234\t\nx"
    assert strip_invisible(visible) == visible


def _is_subsequence(sub: str, full: str) -> bool:
    it = iter(full)
    return all(ch in it for ch in sub)


def test_strip_invisible_is_idempotent_and_deletion_only():
    invis = [chr(cp) for cp in _STRIP_CF_CPS] + [chr(cp) for cp in sorted(_extra())]
    visible = list("the-quick-brown-fox-0123456789")
    woven = []
    for i, v in enumerate(visible):
        woven.append(v)
        if i < len(invis):
            woven.append(invis[i])
    text = "".join(woven) + "".join(invis[len(visible) :])
    once = strip_invisible(text)
    assert once == "".join(visible)
    assert strip_invisible(once) == once
    assert _is_subsequence(once, text)


def test_strip_invisible_explicit_charset_overrides_default():
    """A caller may pin a bespoke charset; only its members are stripped."""
    assert strip_invisible("a​b", frozenset({0x200B})) == "ab"
    assert strip_invisible("a​b", frozenset({0x2060})) == "a​b"


# ─── invisible_run_pattern domain ────────────────────────────────────────────


def test_env_invis_run_domain_equals_charset():
    """The env-bound run pattern tolerates EXACTLY the charset's code points — no
    subset (a splice using an omitted char would evade the matcher) and no
    superset (dead weight in the class)."""
    import re

    charset = default_charset()
    pattern = invisible_run_pattern(charset)
    inner = re.compile("[" + pattern[1:-2] + "]")
    for cp in sorted(charset):
        assert inner.match(chr(cp)), f"U+{cp:04X} missing from run pattern"
    assert not inner.match("a")
    assert not inner.match(" ")


# ─── Fail closed when the shared dependency is unavailable ───────────────────


def test_default_charset_fails_closed_without_shared_dep(monkeypatch):
    """If the shared SSOT cannot be read, resolution RAISES rather than falling
    back to a partial set — a silent under-match is a security regression."""
    import agent_input_sanitizer.invisible as inv
    import agent_input_sanitizer.secrets.invisible as redactor_inv

    def _boom():
        raise RuntimeError("shared charset unavailable")

    monkeypatch.setattr(redactor_inv, "_shared_charset", _boom)
    with pytest.raises(RuntimeError):
        redactor_inv.default_charset()
    # sanity: the real accessor works (guards against a typo neutering the test)
    inv.invisible_charset.cache_clear()
    assert inv.invisible_charset()
