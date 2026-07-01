"""Secret-detection and redaction engine.

detect-secrets (24 bundled detectors + custom gitleaks-sourced plugins for
formats it lacks, see ``detectors.py``) for known-prefix and quoted field-value
patterns, plus a regex for unquoted field-values KeywordDetector misses, PEM
collapse, cross-line reassembly, and exact-match redaction of caller-supplied
env-var values.

Everything environment-specific is supplied by the caller through
:class:`~agent_input_sanitizer.secrets.config.RedactorConfig` — the engine discovers
nothing on its own. detect-secrets is the ONE detection oracle; no second port to
keep in sync.

The detect-secrets ``secret_type -> class`` mapping is a process-global
``lru_cache(maxsize=1)`` built from whichever settings were active at the FIRST
scan. :func:`redact` / :func:`redact_map` clear and rebuild it per call so an
unrelated earlier scan can't leave the wrong plugin set primed; a hot-path caller
should instead configure ONCE with :func:`configure_plugins` and call
:func:`redact_configured` (this is what the daemon package does).
"""

import functools
import json
import re
from pathlib import Path

from detect_secrets.core.plugins.util import get_mapping_from_secret_type_to_class
from detect_secrets.core.potential_secret import PotentialSecret
from detect_secrets.core.scan import scan_line
from detect_secrets.settings import transient_settings

from . import detectors
from .config import RedactorConfig
from .invisible import invisible_run_pattern

PLUGINS = [
    {"name": n}
    for n in [
        "AWSKeyDetector",
        "ArtifactoryDetector",
        "AzureStorageKeyDetector",
        "BasicAuthDetector",
        "CloudantDetector",
        "DiscordBotTokenDetector",
        "IbmCloudIamDetector",
        "IbmCosHmacDetector",
        "KeywordDetector",
        "MailchimpDetector",
        "NpmDetector",
        "OpenAIDetector",
        "PrivateKeyDetector",
        "PypiTokenDetector",
        "SendGridDetector",
        "SlackDetector",
        "SoftlayerDetector",
        "SquareOAuthDetector",
        "StripeDetector",
        "TelegramBotTokenDetector",
        "TwilioKeyDetector",
    ]
]

# High-confidence subset: every detector whose match shape IS the credential,
# i.e. PLUGINS minus the fuzzy KeywordDetector (which fires on any
# ``keyword: value`` shape). A source-code scan uses this subset only — source
# legitimately references secret env vars and field names without holding a
# literal credential, so the keyword/field-value heuristics there are pure noise.
PLUGINS_HIGH_CONFIDENCE = [p for p in PLUGINS if p["name"] != "KeywordDetector"]

# Custom detectors for formats detect-secrets has no plugin for, loaded by file
# path. The list is DERIVED from the same SSOT detectors.py compiles its
# denylists from — data/secret-detectors.json — so a detector added there
# registers here automatically, with no hand-kept copy to drift.
# JwtFullTokenDetector is the lone exception: it subclasses a bundled detector
# and carries its regex inline (see detectors.py), so it has no JSON row and is
# appended explicitly. A JSON entry whose adapter class is missing from
# detectors.py fails loud when detect-secrets loads the plugin by name.
_PLUGIN_FILE = Path(detectors.__file__).resolve().as_uri()
_CONFIGURED_DETECTORS = [
    entry["const"]
    for entry in json.loads(detectors.DETECTORS_FILE.read_text())["detectors"]
]
CUSTOM_PLUGINS = [
    {"name": name, "path": _PLUGIN_FILE}
    for name in (*_CONFIGURED_DETECTORS, "JwtFullTokenDetector")
]


# ─── Placeholder↔secret map mode ─────────────────────────────────────────────
# In map mode each replacement site substitutes a unique private-use sentinel
# instead of the placeholder; after every layer has run, _resolve_marks swaps the
# sentinels back to the placeholder text while recording (placeholder, original,
# start offset) per occurrence. Detector matching runs against the pre-replacement
# text, so the resolved text equals the normal-mode output. The sentinel keeps a
# space inside so FIELD_VALUE_RE treats it like the space-bearing placeholder.
_MARK_OPEN = ""
_MARK_CLOSE = ""
_MARK_RE = re.compile(f"{_MARK_OPEN}(\\d+) {_MARK_CLOSE}")


def _mark(
    entries: list[tuple[str, str]] | None, placeholder: str, original: str
) -> str:
    """Replacement text for one redaction: the placeholder, or in map mode a
    unique sentinel that _resolve_marks later swaps back to it."""
    if entries is None:
        return placeholder
    entries.append((placeholder, original))
    return f"{_MARK_OPEN}{len(entries) - 1} {_MARK_CLOSE}"


def _expand_marks(text: str, entries: list[tuple[str, str]]) -> str:
    """Replace sentinels embedded in a recorded original with their disk text.

    A PEM block matched after env-bound redaction can swallow an earlier
    sentinel into its recorded original; env originals contain none, so the
    expansion bottoms out.
    """
    while _MARK_RE.search(text):
        text = _MARK_RE.sub(lambda m: entries[int(m.group(1))][1], text)
    return text


def _resolve_marks(text: str, entries: list[tuple[str, str]]) -> tuple[str, list[dict]]:
    """Swap sentinels back to placeholders, recording each occurrence's
    placeholder text, original disk text, and offset in the resolved text."""
    pairs: list[dict] = []
    out: list[str] = []
    pos = 0
    last = 0
    for m in _MARK_RE.finditer(text):
        seg = text[last : m.start()]
        out.append(seg)
        pos += len(seg)
        placeholder, original = entries[int(m.group(1))]
        pairs.append(
            {
                "placeholder": placeholder,
                "original": _expand_marks(original, entries),
                "start": pos,
            }
        )
        out.append(placeholder)
        pos += len(placeholder)
        last = m.end()
    out.append(text[last:])
    return "".join(out), pairs


# re.compile self-caches identical patterns, so dropping this decorator is a
# perf-only (correctness-equivalent) change the fast oracle cannot observe.
@functools.cache
def _env_value_re(value: str, charset: frozenset[int]) -> re.Pattern[str]:
    """Match ``value`` tolerating invisible chars (from ``charset``) spliced
    between its characters.

    Each interior gap allows zero-or-more invisibles, so the plain value still
    matches (a superset of exact substring). Required literals between every gap
    keep the pattern linear — no ReDoS."""
    run = invisible_run_pattern(charset)
    return re.compile(run.join(re.escape(c) for c in value))


def _env_mark(
    placeholder: str, entries: list[tuple[str, str]] | None, m: re.Match[str]
) -> str:
    """re.sub replacement: redact a matched key span, recording its actual bytes
    (m.group(0), not the clean value) so map-mode rehydration is byte-exact."""
    return _mark(entries, placeholder, m.group(0))


def _redact_env_bound(
    text: str,
    found: list[str],
    config: RedactorConfig,
    entries: list[tuple[str, str]] | None = None,
) -> str:
    """Redact the literal value of each configured env var from ``text``."""
    charset = config.resolved_charset()
    for name, value in config.env_secrets.items():
        if not value or len(value) < config.min_secret_len:
            continue
        repl = functools.partial(_env_mark, f"[REDACTED: {name}]", entries)
        new_text, hits = _env_value_re(value, charset).subn(repl, text)
        if hits:
            text = new_text
            found.append(name)
    return text


# detect-secrets' KeywordDetector knows only a fixed set of field names, omitting
# the token family (token/access_token/authorization/bearer); this regex carries
# them for both unquoted (`TOKEN=abc123…`) and quoted (`"token": "abc123…"`) forms.
_FIELD_NAMES = "|".join(
    [
        r"api[_-]?key",
        r"secret(?:[_-]?key)?",
        r"client[_-]?secret",
        r"access[_-]?(?:key|token)",
        r"private[_-]?key",
        r"auth(?:orization|[_-]?(?:key|token))",
        r"password",
        r"passwd",
        r"bearer",
        r"token",
    ]
)
FIELD_VALUE_RE = re.compile(
    # An optional quote after the field name absorbs a quoted KEY (`"token": …`),
    # and the value's own optional opening quote is captured so it can wrap
    # [REDACTED] — so `"token": "<v>"` and `bearer: '<v>'` redact, not just the
    # unquoted `token=<v>`. The closing quote is an OPTIONAL backreference: a
    # value whose closing quote is absent or mismatched (truncated/streamed log
    # output, a value split so the close lands on the next line the per-line scan
    # can't see) must still redact, not slip through because a symmetric close
    # failed to match — the value class excludes quotes, so a backtracked-empty
    # opening `quote` could never re-consume the literal `"`/`'` itself.
    # No leading-letter lookbehind so "mypassword: ..." still matches. The value
    # is non-whitespace/quote/backtick bytes minus the structural delimiters
    # {}()[] that open shell expansions ${VAR}, command substitutions $(...), code
    # calls foo(...), and subscripts/array literals a[i] / [x, y] — none occur
    # inside a contiguous secret token, so excluding them trims a class of
    # source-code false positives without shortening a real secret. Other specials
    # (!@#) stay allowed so a symbol inside a secret doesn't truncate the capture
    # below the length threshold, and the anchor avoids swallowing trailing prose.
    # No nested quantifier -> no catastrophic backtracking.
    #
    # The optional open/close bracket groups peel a wrapper that *encloses* the
    # value (`password = (<secret>)`, `key: {<secret>}`, `token: ["<secret>"]`):
    # without them a value that BEGINS with `(`/`{`/`[` (the three excluded from the
    # value class) left no ≥20-char run for secret_value to anchor on, so the whole
    # arm failed to match and the secret leaked verbatim. The brackets are matched
    # only at the value's edge, so the FP guards above are unchanged — `${VAR}`/
    # `$(...)`/`foo(...)` still begin with `$`/a letter, never the peeled bracket,
    # so they neither match here nor (as before) reach the length floor.
    # The assignment operator is `:` `=` or one of the multi-char forms `:=`
    # `=>` `==` (Go/Pascal walrus, Ruby/PHP hash-rocket, comparison-as-config).
    # A bare `[:=]` matched only the first char of `:=`/`=>`, leaving the value
    # to start at the second operator byte (`= "v"` / `> "v"`), which is <20
    # contiguous chars, so the arm failed and the secret leaked.
    #
    # `(?:[_-]\w+)*` after the keyword lets it be a PREFIX of a longer
    # underscore/hyphen-segmented identifier (`api_key_prod`, `secret_value`,
    # the env-suffixed `AWS_SECRET_ACCESS_KEY_OLD`) — without it the keyword had
    # to abut the operator and these extremely common names leaked verbatim. The
    # `[_-]` separator is REQUIRED (not a bare `\w*`), so a plain word that merely
    # starts with a keyword (`secretary` = `secret`+`ary`, `tokenizer`) is not
    # mistaken for a credential field.
    rf"(?P<field_prefix>(?:{_FIELD_NAMES})(?:[_-]\w+)*[\"']?\s*(?::=|==|=>|[:=])\s*"
    r"(?:(?:Bearer|Token|Basic)\s+)?)"
    r"(?P<openbracket>[(\[{]?)"
    r"(?P<quote>[\"']?)"
    r"(?P<secret_value>[^\s\"'`{}()\[\]]{20,})"
    r"(?P<closequote>(?P=quote)?)"
    r"(?P<closebracket>[)\]}]?)",
    re.IGNORECASE | re.MULTILINE,
)

# Pagination/cursor fields named "<prefix>token" are opaque page cursors, not
# credentials (Twitter/X next_token, GCP nextPageToken, AWS NextToken,
# Elasticsearch scroll). Their values are long and high-entropy, so the field
# regex above redacts them and corrupts ordinary paginated API output for no
# security gain. Skip redaction when the bare "token" keyword carries one of
# these prefixes. Credential tokens (access/auth/api/id/session/refresh/bearer)
# are deliberately absent, so they still redact.
_BENIGN_TOKEN_PREFIXES = frozenset(
    {"next", "page", "nextpage", "continuation", "scroll", "sync", "pagination"}
)


def _normalize_ident(s: str) -> str:
    return s.lower().replace("_", "").replace("-", "")


def _ident_run_start(s: str, end: int, seps: str) -> int:
    """Index where the run of identifier bytes (alnum plus any in ``seps``)
    ending at ``end`` begins."""
    while end > 0 and (s[end - 1].isalnum() or s[end - 1] in seps):
        end -= 1
    return end


def _is_benign_cursor(m: re.Match[str]) -> bool:
    """True when the matched field is a known non-secret pagination cursor."""
    keyword = _normalize_ident(
        re.split(r"[:=]", m.group("field_prefix"), maxsplit=1)[0].strip(" \t\"'")
    )
    if keyword != "token":
        return False
    # Walk back over the identifier characters glued before the bare keyword to
    # recover the full field name (e.g. "next" in "nextToken", "page_" in
    # "page_token"), which the no-lookbehind regex leaves outside group(1).
    text = m.string
    start = m.start("field_prefix")
    return (
        _normalize_ident(text[_ident_run_start(text, start, "_-") : start])
        in _BENIGN_TOKEN_PREFIXES
    )


# Documentation and examples name secrets without containing one: a metavariable
# (`YOUR_API_KEY`, `<paste-token-here>`, `{{ secrets.GH_TOKEN }}`), a well-known
# stand-in literal, or a repeated filler char carries no usable entropy, yet sits
# in exactly the `keyword = "value"` position the detectors target — redacting it
# corrupts docs/config examples for no security gain. Each shape is one a real
# credential cannot take: generated keys mix cases and digits, so a value that is
# wholly CAPS_WITH_UNDERSCORES words (no digits), bracket-wrapped, or one
# repeated character is not a key. Digit-bearing metavariables (`API_KEY_2`)
# stay redacted. Applied only to keyword-anchored detections; prefix detectors
# (AWS/Stripe/…), whose match *is* the credential shape, are never skipped.
_PLACEHOLDER_LITERALS = frozenset(
    {"example", "changeme", "change-me", "placeholder", "redacted", "dummy"}
)
# Leading (?<![A-Z_]) prevents recheck from flagging the nested quantifiers as
# polynomial backtracking. The lookbehind is always satisfied at the fullmatch
# start position (no preceding char) and after each \s+ separator (space is not
# in [A-Z_]), so the actual .fullmatch() semantics are unchanged.
_CAPS_WORDS = r"(?<![A-Z_])[A-Z]+(?:_[A-Z]+)+"
_PLACEHOLDER_RE = re.compile(
    rf"<[^<>]{{1,80}}>"  # <paste-token-here>
    rf"|\{{\{{[^{{}}]{{1,80}}\}}\}}"  # {{ secrets.GH_TOKEN }} (CI templates)
    rf"|{_CAPS_WORDS}(?:\s+{_CAPS_WORDS})*"  # YOUR_API_KEY / "GH_TOKEN OPENAI_API_KEY"
    r"|(?P<fill>.)(?P=fill){7,}"  # xxxxxxxx / 00000000
)


def _is_placeholder_value(value: str) -> bool:
    """True when the value is a documentation placeholder, not a credential."""
    return (
        _PLACEHOLDER_RE.fullmatch(value) is not None
        or value.lower() in _PLACEHOLDER_LITERALS
    )


# A field named `secret_type` / `token_name` / `key_label` holds metadata *about*
# a secret (its kind, its display name), not the secret itself — `secret_type =
# "Anthropic API Key"` trips KeywordDetector and corrupts ordinary code/test
# output. Skip when the identifier directly before the matched value's
# assignment ends in a metadata suffix. Real secrets live under the bare
# keyword fields, which have no such suffix.
_METADATA_SUFFIXES = ("type", "name", "label", "keyword", "kind")
_ASSIGN_OP_CHARS = "=:!>"


def _is_metadata_field(line: str, value: str) -> bool:
    """True when ``value`` is assigned to a metadata field, not a secret field.

    Walks the text before the value with plain string ops (no regex) so a long,
    no-match prefix of attacker-influenced output can't drive backtracking: peel
    a trailing quote/``@``, require a trailing assignment operator (``=`` ``:``
    ``=>`` ``:=`` ``==``), then read back the identifier and test its suffix.
    """
    idx = line.find(value)
    if idx <= 0:
        return False
    prefix = line[:idx].rstrip()
    if prefix[-1:] in "\"'@":
        prefix = prefix[:-1].rstrip()
    after_op = prefix.rstrip(_ASSIGN_OP_CHARS)
    if after_op == prefix:
        return False
    name = after_op.rstrip().rstrip("\"'")
    field = name[_ident_run_start(name, len(name), "_") :]
    return bool(field) and field.lower().endswith(_METADATA_SUFFIXES)


# KeywordDetector treats markdown inline-code delimiters (backticks) as string
# quotes, so a documentation line is captured whole as one "Secret Keyword"
# value. The over-capture shape is unmistakable and a real credential cannot take
# it: the value spans whitespace AND embeds a backtick. A contiguous credential
# has no internal whitespace; a spaced passphrase has no backtick — so skipping
# this shape can hide neither. Keyword-anchored only, and off web ingress.
def _is_markdown_code_prose(value: str) -> bool:
    """True when a keyword value is a backtick-bearing, whitespace-spanning span
    of markdown prose the KeywordDetector over-captured, not a credential."""
    return "`" in value and any(ch.isspace() for ch in value)


# A value that is *wholly* an environment-variable reference names a secret
# without holding it. Two families, both anchored (\Z) so the WHOLE value must be
# the reference — a real token that merely begins with one of these words still
# redacts, since its trailing key bytes break the anchor:
#   • Shell expansion ($API_KEY) and env-object access whose ROOT is unforgeable
#     — process.env.X, import.meta.env.X, os.environ["X"], Deno.env…, $ENV.X.
#   • A bare attribute chain rooted at settings./config./environ./self — the
#     Django/Flask/Pydantic idiom. This root IS forgeable, so it is trusted only
#     off web ingress; the prefix detectors run first and remain the floor.
# The attribute/index chain uses a POSSESSIVE quantifier (`*+`) so the trailing
# \Z can't drive O(n^2) backtracking on a long near-match.
_ENV_REFERENCE_RE = re.compile(
    r"(?:\$[A-Za-z_]\w*"
    r"|(?:process\.env|import\.meta\.env|os\.environ|Deno\.env"
    r"|settings|config|environ|self))"
    r"(?:\.[A-Za-z_]\w*|\[[^\[\]]*\])*+\Z"
)

# The bare-word roots (settings/config/environ/self) are a CONVENTION: an
# attacker who controls the value (web ingress) can write `config.<token>` to
# relabel a credential as a config read. The $VAR / process.env / os.environ /
# import.meta.env / Deno.env roots read as code wherever they appear, so they
# stay trusted; the bare-word roots are trusted only for local tool output.
_FORGEABLE_ENV_ROOT_RE = re.compile(r"(?:settings|config|environ|self)(?:[.\[]|\Z)")


def _is_env_reference(value: str, web_ingress: bool = False) -> bool:
    """True when the value is wholly an env-var / config reference, not a secret. On
    web ingress the forgeable bare-word roots are not trusted; the unambiguous
    code idioms are trusted everywhere."""
    if _ENV_REFERENCE_RE.fullmatch(value) is None:
        return False
    return not (web_ingress and _FORGEABLE_ENV_ROOT_RE.match(value))


# A value rooted at a conventional system/mount directory — optionally with a
# trailing mount mode (":ro") — is a config path, not a credential.
_FS_PATH_RE = re.compile(
    r"/(?:run|var|etc|home|root|opt|srv|mnt|media|tmp|usr|lib|proc|sys|dev|boot|data|workspace)"
    r"/[\w./-]+(?::\w+)?"
)


def _is_filesystem_path(m: re.Match[str]) -> bool:
    """True when the matched value is an absolute filesystem path, not a secret."""
    return _FS_PATH_RE.fullmatch(m.group("secret_value")) is not None


# A content-addressed digest is public data, not a credential: git/OCI object IDs
# and bare blockchain hashes. Two separate patterns (not one alternation): each is
# provably ReDoS-safe, but their union blows past recheck's node budget.
_ALGO_DIGEST_RE = re.compile(
    r"(?:sha1|sha224|sha256|sha384|sha512|md5|blake2[bs]):[0-9a-fA-F]{16,}"
)
_HEX_HASH_RE = re.compile(r"0x[0-9a-fA-F]{40}|0x[0-9a-fA-F]{64}")


def _is_content_digest(value: str) -> bool:
    """True when the value is an algorithm-prefixed or `0x`-hex content digest."""
    return (
        _ALGO_DIGEST_RE.fullmatch(value) is not None
        or _HEX_HASH_RE.fullmatch(value) is not None
    )


# A canonical 8-4-4-4-12 hex UUID is a public opaque identifier, not a credential.
_UUID_RE = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
)


def _is_uuid(value: str) -> bool:
    """True when the value is a canonical 8-4-4-4-12 hex UUID, not a credential."""
    return _UUID_RE.fullmatch(value) is not None


# detect-secrets' PrivateKeyDetector only matches the "-----BEGIN-----" header
# line, so a per-line scan leaves the base64 body unredacted. Match and collapse
# the whole PEM block. To FAIL SAFE on truncated output the body also terminates
# at the next "-----BEGIN" or end-of-string. The keyword is "PRIVATE KEY" only,
# so public material (certs, public keys, PGP messages) stays verbatim. The label
# runs are length-capped so a crafted header can't drive O(n^2) backtracking.
_PEM_LABEL_RUN = r"[A-Z0-9 ]{0,40}?"
PEM_BLOCK_RE = re.compile(
    r"-----BEGIN (?P<label>"
    + _PEM_LABEL_RUN
    + r"PRIVATE KEY"
    + _PEM_LABEL_RUN
    + r")-----"
    r"[\s\S]*?"
    r"(?:-----END (?P=label)-----|(?=-----BEGIN )|\Z)",
    re.IGNORECASE,
)


def _redact_pem_blocks(
    text: str, found: list[str], entries: list[tuple[str, str]] | None = None
) -> str:
    def _repl(m: re.Match[str]) -> str:
        found.append("Private Key")
        return _mark(entries, "[REDACTED: Private Key]", m.group(0))

    return PEM_BLOCK_RE.sub(_repl, text)


# Cross-line redaction scans a newline-free collapse of the text, so two adjacent
# lines whose tail and head abut into a token-shaped run could fuse into a false
# match. Restrict the per-line candidates to detector types whose match is a
# long, structurally-rigid token with a distinctive prefix — for those a
# cross-line hit is almost certainly a genuinely line-wrapped key. Excluded are
# the short/loose-prefix detectors and the keyword/keyword-context detectors,
# where two abutting tokens plausibly fuse.
_CROSS_LINE_ELIGIBLE_TYPES = frozenset(
    {
        "AWS Access Key",
        "GitHub Token",
        "GitHub Fine-Grained PAT",
        "Anthropic API Key",
        "Google API Key",
        "Slack Token",
        "OpenAI Token",
        "OpenRouter API Key",
        "Stripe Access Key",
        "GitLab Token",
        "Discord Bot Token",
        "JSON Web Token",
        "NPM tokens",
        "PyPI Token",
        "SendGrid API Key",
        "Square OAuth Secret",
        "Private Key",
        "DigitalOcean Token",
        "Cloudflare Origin CA Key",
        "Vault Token",
        "Terraform Cloud API Token",
    }
)


def _cross_line_candidate_spans(
    collapsed: str, config: RedactorConfig
) -> list[tuple[int, int, str, str]]:
    """``(start, end, placeholder, found_type)`` for every structural or env-bound
    secret found in the newline-free view ``collapsed``.

    Only detector types in ``_CROSS_LINE_ELIGIBLE_TYPES`` (long, structurally
    rigid) are eligible; the exact env-var values are always eligible.
    """
    spans: list[tuple[int, int, str, str]] = []
    for secret in scan_line(collapsed):
        if secret.type not in _CROSS_LINE_ELIGIBLE_TYPES:
            continue
        value = secret.secret_value
        if not value:
            continue
        start = collapsed.find(value)
        while start != -1:
            spans.append(
                (start, start + len(value), f"[REDACTED: {secret.type}]", secret.type)
            )
            start = collapsed.find(value, start + len(value))
    charset = config.resolved_charset()
    for name, value in config.env_secrets.items():
        if not value or len(value) < config.min_secret_len:
            continue
        for m in _env_value_re(value, charset).finditer(collapsed):
            spans.append((m.start(), m.end(), f"[REDACTED: {name}]", name))
    return spans


def _redact_cross_line(
    text: str,
    found: list[str],
    config: RedactorConfig,
    entries: list[tuple[str, str]] | None = None,
) -> str:
    """Redact a structural secret or configured value split across a newline.

    Scan a newline-free view of ``text`` (with an offset map back to the
    original) and redact only matches whose ORIGINAL span actually straddles a
    newline; a within-line match is left for the per-line pass, so nothing
    redacts twice. Must run inside the same ``transient_settings`` block as the
    per-line scan so ``scan_line`` sees the custom plugins.
    """
    if "\n" not in text:
        return text
    offsets = [i for i, ch in enumerate(text) if ch != "\n"]
    collapsed = text.replace("\n", "")

    accepted: list[tuple[int, int, str, str]] = []
    prev_end = -1
    for cs, ce, placeholder, found_type in sorted(
        _cross_line_candidate_spans(collapsed, config), key=lambda s: (s[0], -s[1])
    ):
        orig_start, orig_end = offsets[cs], offsets[ce - 1] + 1
        if "\n" not in text[orig_start:orig_end] or orig_start < prev_end:
            continue
        accepted.append((orig_start, orig_end, placeholder, found_type))
        prev_end = orig_end
    if not accepted:
        return text

    out = text
    for orig_start, orig_end, placeholder, _ in reversed(accepted):
        replacement = _mark(entries, placeholder, text[orig_start:orig_end])
        out = out[:orig_start] + replacement + out[orig_end:]
    found.extend(found_type for *_, found_type in accepted)
    return out


def _is_benign_keyword_match(
    secret: PotentialSecret, line: str, web_ingress: bool
) -> bool:
    """True when a ``Secret Keyword`` detection is not a credential: a value-shape
    skip (a documentation placeholder, or an env-var/config reference whose
    forgeable bare-word roots are dropped on web ingress), or — for local output,
    where the field NAME is trustworthy — a metadata field or markdown code
    prose. Prefix/format detectors are never benign."""
    if secret.type != "Secret Keyword":
        return False
    if not secret.secret_value:
        return False
    if _is_placeholder_value(secret.secret_value) or _is_env_reference(
        secret.secret_value, web_ingress
    ):
        return True
    if web_ingress:
        return False
    return _is_metadata_field(line, secret.secret_value) or _is_markdown_code_prose(
        secret.secret_value
    )


def _redact_line(
    line: str,
    web_ingress: bool,
    entries: list[tuple[str, str]] | None,
    found: list[str],
) -> str:
    """Redact every detected secret in one ``line``, appending each redacted type
    to ``found``.

    Redact the longest values first. ``str.replace`` rewrites every occurrence,
    so if a short secret that is a SUBSTRING of a longer one is redacted first,
    the longer secret's value is no longer present and its check below skips it —
    leaking the non-overlapping tail of the longer secret.
    """
    redacted = line
    for secret in sorted(
        scan_line(line), key=lambda s: len(s.secret_value or ""), reverse=True
    ):
        if not (secret.secret_value and secret.secret_value in redacted):
            continue
        if _is_benign_keyword_match(secret, redacted, web_ingress):
            continue
        redacted = redacted.replace(
            secret.secret_value,
            _mark(entries, f"[REDACTED: {secret.type}]", secret.secret_value),
        )
        found.append(secret.type)
    return redacted


def _redact_core(
    text: str,
    entries: list[tuple[str, str]] | None,
    config: RedactorConfig,
) -> tuple[str, list[str]]:
    """Core redaction over ``text``; return (redacted, found types).

    Assumes the detect-secrets plugin set is ALREADY configured and the
    secret_type->class mapping primed by the caller — :func:`_redact` does that
    per-call, :func:`configure_plugins` does it once for the daemon. This body
    therefore touches neither ``transient_settings`` nor the mapping cache.

    In map mode ``entries`` is a list and each replacement is a unique sentinel
    _resolve_marks later pairs back to its placeholder; otherwise ``entries`` is
    None and replacements are the plain placeholders.
    """
    web_ingress = config.web_ingress
    found: list[str] = []
    # Redact configured env-var values first, then collapse PEM blocks so the line
    # scan never sees the base64 key body.
    working = _redact_env_bound(text, found, config, entries)
    working = _redact_pem_blocks(working, found, entries)
    # Catch newline-split tokens first, then scan what remains line by line.
    working = _redact_cross_line(working, found, config, entries)
    lines = [
        _redact_line(line, web_ingress, entries, found) for line in working.split("\n")
    ]

    rejoined = "\n".join(lines)
    if config.high_confidence:
        # The field-value regex is a fuzzy keyword matcher; skip it here so the
        # high-confidence scan reports only structural detections.
        return rejoined, found

    def _replace_field(m: re.Match[str]) -> str:
        # Name-based skips (cursor / path / metadata field) are attacker-relabelable
        # on web ingress, so they only apply to local tool output; the value-shape
        # skips (placeholder, content-digest, UUID) are trustworthy regardless of
        # source and apply on web ingress too.
        name_skip = not web_ingress and (
            _is_benign_cursor(m)
            or _is_filesystem_path(m)
            or _is_metadata_field(m.group(0), m.group("secret_value"))
        )
        value = m.group("secret_value")
        if (
            name_skip
            or _is_env_reference(value, web_ingress)
            or _is_placeholder_value(value)
            or _is_content_digest(value)
            or _is_uuid(value)
        ):
            return m.group(0)
        found.append("named secret field")
        return (
            m.group("field_prefix")
            + m.group("openbracket")
            + m.group("quote")
            + _mark(entries, "[REDACTED]", value)
            + m.group("closequote")
            + m.group("closebracket")
        )

    return FIELD_VALUE_RE.sub(_replace_field, rejoined), found


def configure_plugins(high_confidence: bool = False):
    """Context manager that configures the detect-secrets plugin set for the
    duration of the block and primes the secret_type->class mapping cache.

    A hot-path caller (the daemon) enters this ONCE at startup and then calls
    :func:`redact_configured` per request, avoiding the per-call cache churn
    :func:`redact` pays. ``high_confidence`` selects the structural-only subset.
    """
    plugins = PLUGINS_HIGH_CONFIDENCE if high_confidence else PLUGINS

    class _Ctx:
        def __enter__(self):
            self._settings = transient_settings(
                {"plugins_used": plugins + CUSTOM_PLUGINS}
            )
            self._settings.__enter__()
            get_mapping_from_secret_type_to_class.cache_clear()
            return self

        def __exit__(self, *exc):
            try:
                get_mapping_from_secret_type_to_class.cache_clear()
            finally:
                return self._settings.__exit__(*exc)

    return _Ctx()


def redact_configured(
    text: str, entries: list[tuple[str, str]] | None, config: RedactorConfig
) -> tuple[str, list[str]]:
    """Redact assuming the plugin set is ALREADY configured (inside a
    :func:`configure_plugins` block). This is the daemon's per-request entry — it
    skips the per-call ``transient_settings`` + cache-clear dance :func:`redact`
    performs, which is the whole reason the daemon exists."""
    return _redact_core(text, entries, config)


def _redact(
    text: str, entries: list[tuple[str, str]] | None, config: RedactorConfig
) -> tuple[str, list[str]]:
    """One-shot wrapper: configure the detect-secrets plugin set for THIS call and
    clear the secret_type->class mapping cache around the scan.

    detect-secrets caches that mapping in a process-global lru_cache(maxsize=1),
    built from whatever settings were active at the FIRST scan in the
    interpreter. An earlier in-process scan with different settings can populate
    it WITHOUT our file-based custom plugins, after which scan_line raises
    TypeError. Clear it so the mapping is rebuilt against the plugins we just
    configured; clear again on exit so our custom mapping doesn't leak into a
    later caller's default-plugin scan.
    """
    with configure_plugins(config.high_confidence):
        return _redact_core(text, entries, config)


# ─── Public API ──────────────────────────────────────────────────────────────


def redact(text: str, config: RedactorConfig | None = None) -> tuple[str, list[str]]:
    """Redact every detected secret in ``text``; return ``(redacted, found)``.

    ``config`` defaults to a bare :class:`RedactorConfig` (built-in charset, no
    env-bound values, local tool output). ``found`` lists each redacted
    detector's type in redaction order (not deduped). This is the one-shot
    in-process entry: it configures detect-secrets per call. For a hot path,
    enter :func:`configure_plugins` once and call :func:`redact_configured`.
    """
    return _redact(text, None, config or RedactorConfig())


def redact_map(text: str, config: RedactorConfig | None = None) -> dict:
    """Redact ``text`` and return a rehydration map instead of just the text.

    Returns ``{"text", "pairs", "found"}`` where each pair is
    ``{"placeholder", "original", "start"}`` — the placeholder as it
    appears in ``text``, the exact original bytes it replaced, and the offset of
    the placeholder in ``text``. Substituting every ``original`` at its
    ``start`` reconstructs the input byte-for-byte (the rehydration
    contract). ``found`` is deduped in first-seen order.

    If ``text`` already contains the private-use sentinel characters the map
    machinery reserves, returns ``{"unmappable": <reason>}`` (fail closed rather
    than mis-pair placeholders with secrets).
    """
    return _redact_map(text, config or RedactorConfig(), _redact)


def _redact_map(text: str, config: RedactorConfig, engine) -> dict:
    """Shared map-mode dispatch for :func:`redact_map` and the daemon.

    ``engine`` is :func:`_redact` (one-shot, configures per call) or
    :func:`redact_configured` (daemon, already configured), so the result is
    identical either way.
    """
    if not text:
        return {"text": "", "pairs": [], "found": []}
    if _MARK_OPEN in text or _MARK_CLOSE in text:
        return {"unmappable": "input contains reserved sentinel characters"}
    entries: list[tuple[str, str]] = []
    redacted, found = engine(text, entries, config)
    resolved, pairs = _resolve_marks(redacted, entries)
    return {"text": resolved, "pairs": pairs, "found": list(dict.fromkeys(found))}


def detected_secret_values(
    text: str, config: RedactorConfig | None = None
) -> list[str]:
    """Raw values of every secret :func:`redact` would remove from ``text``,
    de-duped in first-seen order (never the placeholders).

    Runs the engine in map mode purely to harvest the recorded originals — the
    redacted text is discarded. Useful for hashing detected values into an
    ignore list without ever surfacing the value itself.
    """
    entries: list[tuple[str, str]] = []
    _redact(text, entries, config or RedactorConfig())
    return list(
        dict.fromkeys(
            _expand_marks(original, entries) for _placeholder, original in entries
        )
    )


# Cap a preview line so a minified/one-line file can't dump a huge span into a
# warning; the mask keeps the field/context, not the value.
_PREVIEW_MAX_LEN = 88
_MASK = "********"


def _clip_preview(display: str) -> str:
    """Clip an over-long preview to ``_PREVIEW_MAX_LEN``, anchored so the first
    masked span stays visible at the right edge with the field/context that
    precedes it. A dropped head is marked with a leading ellipsis."""
    if len(display) <= _PREVIEW_MAX_LEN:
        return display
    mask_end = display.find(_MASK) + len(_MASK)
    start = max(0, mask_end - (_PREVIEW_MAX_LEN - 3))
    clipped = display[start:mask_end]
    return "..." + clipped if start > 0 else clipped


def mask_secret_lines(text: str, values: list[str]) -> list[str]:
    """One masked line per line of ``text`` that contains a detected secret: the
    line with every value in ``values`` replaced by a fixed run of asterisks,
    whitespace-trimmed, length-capped, de-duped in first-seen order.

    The secret bytes never appear — only the surrounding field/context — so a
    warning can show *where* a secret sits without leaking it. The mask is
    fixed-width, so it reveals nothing about the value's length.
    """
    if not values:
        return []
    mask = ""  # private-use sentinel, swapped to asterisks after masking
    masked = text
    # Longest first so a short value isn't masked inside a longer value's span.
    for value in sorted(values, key=len, reverse=True):
        masked = masked.replace(value, mask)
    previews: list[str] = []
    seen: set[str] = set()
    for line in masked.split("\n"):
        if mask not in line:
            continue
        display = _clip_preview(line.replace(mask, _MASK).strip())
        if display not in seen:
            seen.add(display)
            previews.append(display)
    return previews


def secret_previews(text: str, config: RedactorConfig | None = None) -> list[str]:
    """Masked one-line previews of each line of ``text`` holding a detected secret
    (see :func:`mask_secret_lines`), for a credential-warning context display."""
    return mask_secret_lines(text, detected_secret_values(text, config))


def handle_request(
    text: str,
    map_mode: bool,
    config: RedactorConfig,
    engine=_redact,
) -> dict | None:
    """Decide the response for one redaction request; the single place the modes
    are dispatched, shared by the daemon and a one-shot CLI.

    Returns the response object, or ``None`` for "nothing to emit" (plain mode,
    nothing redacted). ``engine`` is :func:`_redact` for a one-shot caller
    (configures detect-secrets per call) and :func:`redact_configured` for the
    daemon (configured once by :func:`configure_plugins`).
    """
    if map_mode:
        return _redact_map(text, config, engine)
    if not text:
        return None
    redacted, found = engine(text, None, config)
    if redacted == text:
        return None
    return {"text": redacted, "found": list(dict.fromkeys(found))}
