"""Tests for the Python client (`python/agent_input_sanitizer`).

The client is a thin bridge to the Node CLI, so these assert the bridge holds:
Layer 1 strips, the html flag reaches Layers 2/3, the persistent worker agrees
with the one-shot path, and a missing Node fails loudly. The sanitization
verdicts themselves are owned by the JS suite — here the CLI is the source of
truth and the client must faithfully relay it.
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
from collections.abc import Iterator
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "python"))

import agent_input_sanitizer as ais  # noqa: E402
from agent_input_sanitizer import (  # noqa: E402
    PromptVerdict,
    Sanitizer,
    SanitizeResult,
    TextResult,
    classify_prompt,
    clean_file,
    sanitize,
    sanitize_text,
    scan_instruction_files,
    shutdown_worker,
)

ESC = "\x1b"

pytestmark = pytest.mark.skipif(
    shutil.which("node") is None, reason="Node.js required for the CLI bridge"
)

ZERO_WIDTH_SPACE = "​"
HIDDEN_HTML = '<div style="display:none">leak</div>'


@pytest.fixture(autouse=True)
def _no_shared_worker_leak() -> Iterator[None]:
    """Each test starts and ends with no shared worker, so persistence state
    can't bleed across tests."""
    shutdown_worker()
    assert ais._worker is None
    yield
    shutdown_worker()


def test_strips_invisible_layer1() -> None:
    result = sanitize(f"a{ZERO_WIDTH_SPACE}b")
    assert result.cleaned == "ab"
    assert result.found == ["cf-format"]
    assert result.warnings  # any change carries a warning


def test_clean_text_passes_through_unchanged() -> None:
    result = sanitize("hello world")
    assert result == SanitizeResult(cleaned="hello world", found=[], warnings=[])


def test_empty_input() -> None:
    assert sanitize("") == SanitizeResult(cleaned="", found=[], warnings=[])


def test_html_flag_reaches_layer2() -> None:
    assert "leak" in sanitize(HIDDEN_HTML, html=False).cleaned  # Layer 1 only
    assert "leak" not in sanitize(HIDDEN_HTML, html=True).cleaned  # hidden removed


def test_html_amortizes_load_via_shared_worker() -> None:
    # Default persist=None ⇒ html calls reuse one warm worker: the ~200 ms
    # module-load is paid once, not per call.
    first = sanitize(HIDDEN_HTML, html=True)
    worker = ais._worker
    assert worker is not None and worker.is_alive()
    second = sanitize(f"a{ZERO_WIDTH_SPACE}b", html=True)
    assert ais._worker is worker  # same process reused, not respawned
    assert "leak" not in first.cleaned
    assert second.cleaned == "ab"


def test_shared_worker_self_heals_after_death() -> None:
    # The riskiest path: a dead shared worker must be reaped and respawned, not
    # left wedging every later persistent call on a corpse.
    sanitize(HIDDEN_HTML, html=True)
    dead = ais._worker
    assert dead is not None
    dead._proc.kill()
    dead._proc.wait()
    assert not dead.is_alive()

    result = sanitize(f"a{ZERO_WIDTH_SPACE}b", html=True, persist=True)
    assert ais._worker is not None and ais._worker.is_alive()
    assert ais._worker is not dead  # a fresh process, not the corpse
    assert result.cleaned == "ab"


def test_layer1_default_stays_oneshot() -> None:
    # A caller that never touches HTML must not leave a process running.
    sanitize(f"a{ZERO_WIDTH_SPACE}b")
    assert ais._worker is None


def test_persist_true_forces_worker_for_layer1() -> None:
    sanitize("plain", persist=True)
    assert ais._worker is not None and ais._worker.is_alive()


def test_persist_false_forces_oneshot_for_html() -> None:
    result = sanitize(HIDDEN_HTML, html=True, persist=False)
    assert ais._worker is None
    assert "leak" not in result.cleaned


def test_shutdown_worker_is_idempotent() -> None:
    sanitize("x", persist=True)
    assert ais._worker is not None
    shutdown_worker()
    assert ais._worker is None
    shutdown_worker()  # second call is a no-op, not an error
    assert ais._worker is None


def test_worker_matches_oneshot() -> None:
    texts = [f"a{ZERO_WIDTH_SPACE}b", "plain", HIDDEN_HTML]
    with Sanitizer() as worker:
        for text in texts:
            assert worker.sanitize(text, html=True) == sanitize(text, html=True)


def test_worker_preserves_embedded_newlines() -> None:
    text = f"line1\nline2{ZERO_WIDTH_SPACE}"
    with Sanitizer() as worker:
        assert worker.sanitize(text) == sanitize(text)


def test_missing_node_fails_loudly() -> None:
    with pytest.raises(RuntimeError, match="Node.js"):
        sanitize("x", node="definitely-not-a-real-node-binary")


def test_worker_missing_node_fails_loudly() -> None:
    with pytest.raises(RuntimeError, match="Node.js"):
        with Sanitizer(node="definitely-not-a-real-node-binary"):
            pass


def test_missing_cli_fails_with_clear_message(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(ais, "_CLI", REPO_ROOT / "bin" / "does-not-exist.mjs")
    with pytest.raises(RuntimeError, match="sanitize CLI not found"):
        sanitize("x")


def test_worker_error_response_becomes_runtime_error() -> None:
    # A CLI `{error}` response (here: a non-string text) must surface as a clear
    # exception, not a malformed SanitizeResult.
    with Sanitizer() as worker:
        with pytest.raises(RuntimeError, match="text must be a string"):
            worker.sanitize(123)  # type: ignore[arg-type]


def test_oneshot_error_becomes_runtime_error() -> None:
    with pytest.raises(RuntimeError, match="sanitize CLI failed"):
        sanitize(123, persist=False)  # type: ignore[arg-type]


def test_drain_stderr_reads_back_worker_stderr() -> None:
    # The death-diagnostic path: a child process writes to the worker's stderr
    # temp file via its fd; _drain_stderr must read it back across that fd.
    worker = Sanitizer()
    worker._stderr = tempfile.SpooledTemporaryFile(mode="w+", encoding="utf-8")
    node = shutil.which("node")
    assert node is not None
    subprocess.run(
        [node, "-e", "process.stderr.write('diag-from-child')"],
        stderr=worker._stderr,
        check=True,
    )
    assert worker._drain_stderr() == "diag-from-child"
    worker._stderr.close()


def test_killed_worker_raises_loudly_on_next_use() -> None:
    # A worker that WAS started then died mid-use must not claim it was never
    # used as a context manager — it reports the unexpected exit (bug #2).
    with Sanitizer() as worker:
        worker._proc.kill()
        worker._proc.wait()
        with pytest.raises(RuntimeError, match="worker exited unexpectedly"):
            worker.sanitize("x")


def test_never_started_worker_says_use_as_context_manager() -> None:
    # The original message is still correct for a worker that genuinely never
    # ran: distinguish "not started" from "started then died".
    worker = Sanitizer()
    with pytest.raises(RuntimeError, match="use it as a context manager"):
        worker.request({"text": "x"})


def test_shared_worker_not_shared_across_fork() -> None:
    # Simulate inheriting a worker across os.fork: a pid mismatch must force a
    # fresh process, never reuse the parent's pipe.
    sanitize("x", persist=True)
    inherited = ais._worker
    assert inherited is not None
    inherited._pid = -1  # pretend this worker was spawned by another process

    sanitize("y", persist=True)
    assert ais._worker is not None and ais._worker is not inherited
    assert ais._worker._pid == os.getpid()
    # The "inherited" worker was abandoned, not reaped — still running.
    assert inherited.is_alive()
    inherited.close()


# ─── Additional self-contained entry points (op dispatch) ────────────────────


def test_classify_prompt_pass() -> None:
    assert classify_prompt("hello world") == PromptVerdict(action="pass")


def test_classify_prompt_note_on_sgr_only() -> None:
    # A purely cosmetic color sequence is usable: note, not block.
    assert classify_prompt(f"{ESC}[31mred{ESC}[0m") == PromptVerdict(action="note")


def test_classify_prompt_block_carries_reason() -> None:
    verdict = classify_prompt(f"{ESC}[2Jwipe")  # non-SGR escape → block
    assert verdict.action == "block"
    assert verdict.reason


def test_sanitize_text_layer1() -> None:
    result = sanitize_text(f"a{ZERO_WIDTH_SPACE}b")
    assert result == TextResult(
        cleaned="ab",
        warnings=result.warnings,  # exact text owned by JS suite
        modified=True,
        sgr_note=False,
    )
    assert result.warnings


def test_sanitize_text_clean_passthrough() -> None:
    assert sanitize_text("hello") == TextResult(
        cleaned="hello", warnings=[], modified=False, sgr_note=False
    )


def test_sanitize_text_html_layer() -> None:
    assert "leak" not in sanitize_text(HIDDEN_HTML, html=True).cleaned


def test_scan_and_clean_instruction_files(tmp_path: Path) -> None:
    payload = f"intro {ZERO_WIDTH_SPACE * 100} outro\n"
    (tmp_path / "NOTES.md").write_text(payload, encoding="utf-8")
    (tmp_path / "CLEAN.md").write_text("nothing hidden here\n", encoding="utf-8")

    findings = scan_instruction_files(["*.md"], cwd=str(tmp_path))
    assert [f.file for f in findings] == ["NOTES.md"]
    assert findings[0].findings  # non-empty hidden-Unicode hits

    assert clean_file(str(tmp_path / "NOTES.md")) is True
    assert clean_file(str(tmp_path / "NOTES.md")) is False  # already clean now
    assert clean_file(str(tmp_path / "CLEAN.md")) is False
    assert scan_instruction_files(["*.md"], cwd=str(tmp_path)) == []


def test_sanitize_text_uses_shared_worker_for_html() -> None:
    sanitize_text(HIDDEN_HTML, html=True)
    assert ais._worker is not None and ais._worker.is_alive()


# ─── Robustness: framing, concurrency, death, DoS, error surfaces ─────────────


def test_blank_request_does_not_hang_and_framing_survives() -> None:
    # A blank request line must come back as a single structured error, never a
    # silent skip that leaves the client's readline waiting forever. We bound the
    # read so the unfixed worker (which skips the blank line, emitting nothing)
    # fails fast as a timeout instead of hanging the whole suite.
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(Sanitizer, "_READ_TIMEOUT_S", 8.0)
        with Sanitizer() as worker:
            # A literally blank request line: the worker must answer it (with a
            # structured error), not skip it and leave the read hanging.
            worker._proc.stdin.write("\n")
            worker._proc.stdin.flush()
            line = worker._read_response_line()
            assert line != ""
            assert "error" in json.loads(line)
            # Framing intact: a normal request right after still answers.
            assert worker.sanitize(f"a{ZERO_WIDTH_SPACE}b").cleaned == "ab"


def test_concurrent_threads_get_uncorrupted_responses() -> None:
    # Drive the SHARED persistent worker from many threads at once: the
    # per-request lock must serialize each write+read so no response is
    # interleaved with another's, and every thread gets exactly its own answer.
    inputs = [f"thread-{i}{ZERO_WIDTH_SPACE}" for i in range(40)]
    results: dict[int, str] = {}
    errors: list[Exception] = []
    barrier = threading.Barrier(len(inputs))

    def worker(i: int) -> None:
        try:
            barrier.wait()  # maximize contention: all fire together
            results[i] = sanitize(inputs[i], persist=True).cleaned
        except Exception as exc:  # noqa: BLE001 — collect for assertion
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(len(inputs))]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert errors == []
    # Each thread's cleaned text must be exactly its own input minus the ZWS — a
    # corrupted/interleaved response would mismatch.
    assert results == {i: f"thread-{i}" for i in range(len(inputs))}


def test_killed_worker_includes_stderr_not_raw_ioerror() -> None:
    # A worker killed mid-use must raise a clear sanitizer error carrying its
    # stderr — never a bare ValueError/BrokenPipeError leaking I/O internals.
    with Sanitizer() as worker:
        worker._proc.kill()
        worker._proc.wait()
        with pytest.raises(RuntimeError, match="worker exited unexpectedly"):
            worker.sanitize("x")


def test_oversized_input_oneshot_raises_clear_error() -> None:
    with pytest.MonkeyPatch.context() as mp:
        mp.setenv("AGENT_SANITIZER_MAX_INPUT_BYTES", "100")
        with pytest.raises(RuntimeError, match="request too large"):
            sanitize("A" * 500, persist=False)


def test_oversized_input_worker_raises_clear_error() -> None:
    with pytest.MonkeyPatch.context() as mp:
        mp.setenv("AGENT_SANITIZER_MAX_INPUT_BYTES", "100")
        with Sanitizer() as worker:
            with pytest.raises(RuntimeError, match="request too large"):
                worker.sanitize("A" * 500)
            # Worker survives the oversized request and still serves.
            assert worker.sanitize("ok").cleaned == "ok"


def test_non_json_stdout_raises_wrapped_error() -> None:
    # A CLI (or fake) that prints non-JSON must surface as a clear sanitizer
    # error naming the offending output, not a bare json.JSONDecodeError.
    node = shutil.which("node")
    assert node is not None
    fake_cli = Path(tempfile.mkdtemp()) / "fake-cli.mjs"
    fake_cli.write_text(
        "process.stdin.resume();\nconsole.log('not json at all');\n",
        encoding="utf-8",
    )
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr(ais, "_CLI", fake_cli)
        with pytest.raises(RuntimeError, match="non-JSON output"):
            sanitize("x", persist=False)
