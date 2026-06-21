"""Tests for .github/scripts/validate-config.sh."""

import json
import subprocess
from pathlib import Path
from typing import Callable

import pytest


def write_settings(sandbox: Path, settings: dict) -> None:
    (sandbox / ".claude").mkdir(exist_ok=True)
    (sandbox / ".claude" / "settings.json").write_text(json.dumps(settings))


def make_hook(sandbox: Path, rel_path: str, executable: bool = True) -> Path:
    path = sandbox / rel_path
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("#!/usr/bin/env bash\n")
    path.chmod(0o755 if executable else 0o644)
    return path


def run_validator(
    sandbox: Path, copy_script: Callable[[str, Path], Path]
) -> subprocess.CompletedProcess:
    scripts_dir = sandbox / ".github" / "scripts"
    scripts_dir.mkdir(parents=True, exist_ok=True)
    copy_script("validate-config.sh", scripts_dir)
    return subprocess.run(
        ["bash", ".github/scripts/validate-config.sh"],
        cwd=sandbox,
        capture_output=True,
        text=True,
    )


def _command(path: str) -> dict:
    return {
        "hooks": {"SessionStart": [{"hooks": [{"type": "command", "command": path}]}]}
    }


@pytest.mark.parametrize(
    "settings, hooks_to_create, expected_returncode, expected_substring",
    [
        # Happy path
        (
            _command('"$CLAUDE_PROJECT_DIR"/.claude/hooks/session-setup.sh'),
            [(".claude/hooks/session-setup.sh", True), (".hooks/pre-commit", True)],
            0,
            "All checks passed",
        ),
        # Referenced hook script doesn't exist
        (
            _command('"$CLAUDE_PROJECT_DIR"/.claude/hooks/missing.sh'),
            [(".hooks/pre-commit", True)],
            1,
            "missing.sh",
        ),
        # Hook file exists but isn't executable (.hooks/)
        (
            {"hooks": {}},
            [(".hooks/pre-commit", False)],
            1,
            "not executable",
        ),
        # Hook file under .claude/hooks/ isn't executable
        (
            {"hooks": {}},
            [(".claude/hooks/session-setup.sh", False)],
            1,
            "not executable",
        ),
    ],
    ids=["valid", "missing-hook", "non-executable-hook", "non-executable-claude-hook"],
)
def test_validate_config(
    tmp_path: Path,
    copy_script,
    settings: dict,
    hooks_to_create: list[tuple[str, bool]],
    expected_returncode: int,
    expected_substring: str,
) -> None:
    write_settings(tmp_path, settings)
    for rel_path, executable in hooks_to_create:
        make_hook(tmp_path, rel_path, executable=executable)
    result = run_validator(tmp_path, copy_script)
    assert result.returncode == expected_returncode, result.stdout + result.stderr
    assert expected_substring in result.stdout + result.stderr


def test_fails_when_settings_missing(tmp_path: Path, copy_script) -> None:
    make_hook(tmp_path, ".hooks/pre-commit", executable=True)
    result = run_validator(tmp_path, copy_script)
    assert result.returncode == 1
    assert ".claude/settings.json not found" in result.stdout


def test_fails_when_settings_json_is_malformed(tmp_path: Path, copy_script) -> None:
    """Corrupted settings.json must be reported as an error for both jq call sites,
    not silently swallowed."""
    (tmp_path / ".claude").mkdir(exist_ok=True)
    (tmp_path / ".claude" / "settings.json").write_text("{not valid json}")
    make_hook(tmp_path, ".hooks/pre-commit", executable=True)
    result = run_validator(tmp_path, copy_script)
    assert result.returncode == 1
    assert (result.stdout + result.stderr).count("could not be parsed") == 2


def test_rejects_hook_with_syntax_error(tmp_path: Path, copy_script) -> None:
    """Hook scripts with bash syntax errors must be caught with a useful message."""
    write_settings(tmp_path, {"hooks": {}})
    path = tmp_path / ".hooks" / "bad.sh"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("#!/usr/bin/env bash\nif [[\n")  # unclosed [[ is a syntax error
    path.chmod(0o755)
    result = run_validator(tmp_path, copy_script)
    assert result.returncode == 1
    assert "has a bash syntax error" in result.stdout + result.stderr


def _pretooluse_settings(cmd: str) -> dict:
    return {
        "hooks": {
            "PreToolUse": [
                {
                    "matcher": "Bash(git push*)",
                    "hooks": [{"type": "command", "command": cmd}],
                }
            ]
        }
    }


def test_pretooluse_without_safe_launch_fails(tmp_path: Path, copy_script) -> None:
    """PreToolUse hooks that bypass safe-launch.sh must be rejected. Both hook
    files exist so the failure isolates check 3, not the missing-file check."""
    cmd = '"$CLAUDE_PROJECT_DIR"/.claude/hooks/pre-push-check.sh'
    write_settings(tmp_path, _pretooluse_settings(cmd))
    make_hook(tmp_path, ".claude/hooks/safe-launch.sh")
    make_hook(tmp_path, ".claude/hooks/pre-push-check.sh")
    result = run_validator(tmp_path, copy_script)
    assert result.returncode == 1
    assert "not invoked through safe-launch.sh" in result.stdout + result.stderr


def test_pretooluse_with_safe_launch_passes(tmp_path: Path, copy_script) -> None:
    """PreToolUse hooks properly wrapped with safe-launch.sh must pass."""
    cmd = '"$CLAUDE_PROJECT_DIR"/.claude/hooks/safe-launch.sh "$CLAUDE_PROJECT_DIR"/.claude/hooks/pre-push-check.sh'
    write_settings(tmp_path, _pretooluse_settings(cmd))
    make_hook(tmp_path, ".claude/hooks/safe-launch.sh")
    make_hook(tmp_path, ".claude/hooks/pre-push-check.sh")
    result = run_validator(tmp_path, copy_script)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "All checks passed" in result.stdout
