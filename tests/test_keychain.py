"""Tests for the macOS Keychain password helper.

These tests are CI-safe: ``subprocess.run`` is monkeypatched so the real
``security`` binary and the developer's actual login Keychain are never touched.
They pin down three things the rest of the code (and the security policy) depend
on:

* the EXACT ``security`` argv — the ``forti-vpn-<profile>`` service-name
  convention must match the sibling AppleScript repo so pre-existing Keychain
  items keep working (see SPIKE.md section 6);
* whitespace handling — only the single trailing newline ``security`` appends is
  stripped, so a password that legitimately ends in spaces survives intact;
* the error contract — a non-zero exit becomes a ``KeychainError`` whose message
  tells the user how to add the item and, critically, never leaks the secret.
"""

import subprocess
from types import SimpleNamespace

import pytest

from fortivpn.errors import KeychainError
from fortivpn.keychain import get_password


def _fake_run(returncode, stdout="", stderr=""):
    """Return a stand-in for ``subprocess.run`` that records its argv.

    The replacement captures the positional ``args`` (the command list) so a
    test can assert the exact argv, then returns a ``CompletedProcess``-like
    object with the canned outcome. We deliberately do NOT shell out.
    """
    calls = []

    def runner(args, *posargs, **kwargs):
        calls.append({"args": args, "posargs": posargs, "kwargs": kwargs})
        return SimpleNamespace(args=args, returncode=returncode, stdout=stdout, stderr=stderr)

    runner.calls = calls
    return runner


def test_builds_exact_security_argv(monkeypatch):
    runner = _fake_run(returncode=0, stdout="whatever\n")
    monkeypatch.setattr(subprocess, "run", runner)

    get_password("office", "alice")

    assert len(runner.calls) == 1
    assert runner.calls[0]["args"] == [
        "security",
        "find-generic-password",
        "-s",
        "forti-vpn-office",
        "-a",
        "alice",
        "-w",
    ]


def test_runs_without_shell_and_captures_text(monkeypatch):
    runner = _fake_run(returncode=0, stdout="x\n")
    monkeypatch.setattr(subprocess, "run", runner)

    get_password("office", "alice")

    kwargs = runner.calls[0]["kwargs"]
    # No shell injection surface, and decoded text output rather than bytes.
    assert kwargs.get("shell", False) is False
    assert kwargs.get("capture_output") is True
    assert kwargs.get("text") is True


def test_success_strips_trailing_newline(monkeypatch):
    runner = _fake_run(returncode=0, stdout="s3cret\n")
    monkeypatch.setattr(subprocess, "run", runner)

    assert get_password("office", "alice") == "s3cret"


def test_trailing_spaces_in_password_are_preserved(monkeypatch):
    # ``security`` appends exactly one newline; rstrip("\n") must remove that and
    # ONLY that, so a password ending in spaces is returned untouched.
    runner = _fake_run(returncode=0, stdout="p4ss  \n")
    monkeypatch.setattr(subprocess, "run", runner)

    assert get_password("office", "alice") == "p4ss  "


def test_password_without_trailing_newline_is_returned_verbatim(monkeypatch):
    runner = _fake_run(returncode=0, stdout="nonl")
    monkeypatch.setattr(subprocess, "run", runner)

    assert get_password("office", "alice") == "nonl"


def test_nonzero_exit_raises_keychain_error(monkeypatch):
    runner = _fake_run(returncode=1, stdout="", stderr="not found")
    monkeypatch.setattr(subprocess, "run", runner)

    with pytest.raises(KeychainError):
        get_password("office", "alice")


def test_error_message_includes_add_guidance(monkeypatch):
    runner = _fake_run(returncode=1)
    monkeypatch.setattr(subprocess, "run", runner)

    with pytest.raises(KeychainError) as excinfo:
        get_password("office", "alice")

    message = str(excinfo.value)
    # Actionable: name the missing item and how to create it.
    assert "forti-vpn-office" in message
    assert "alice" in message
    assert "security add-generic-password" in message


def test_error_message_never_leaks_the_secret(monkeypatch):
    # Even though no password exists on the failure path, guard the contract:
    # whatever ``security`` wrote to stdout/stderr must not appear in the error.
    secret = "TOPSECRET-should-never-appear"
    runner = _fake_run(returncode=1, stdout=secret, stderr=secret)
    monkeypatch.setattr(subprocess, "run", runner)

    with pytest.raises(KeychainError) as excinfo:
        get_password("office", "alice")

    assert secret not in str(excinfo.value)
