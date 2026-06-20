"""Tests for the connect-time history (``fvpnctl.history``).

CI-safe and isolated: every test points ``$FVPNCTL_STATE_DIR`` at a per-test
``tmp_path`` (autouse fixture), so nothing reads or writes the developer's real
``~/.local/state/fvpnctl``. The store is a tiny JSON file, so the tests exercise
it end to end (record → reload → average) plus the resolution and resilience
edges (env overrides, missing file, corrupt file, recent-window trimming).
"""

import json

import pytest

from fvpnctl import history


@pytest.fixture(autouse=True)
def isolated_state(monkeypatch, tmp_path):
    monkeypatch.setenv("FVPNCTL_STATE_DIR", str(tmp_path / "state"))
    # XDG must not leak in and override the explicit dir under test.
    monkeypatch.delenv("XDG_STATE_HOME", raising=False)
    return tmp_path


def test_average_is_none_on_first_run():
    # No file yet → empty history → no ETA (CLI falls back to the throbber).
    assert history.average("apoz") is None


def test_record_then_average_round_trips():
    history.record("apoz", 12.0)
    history.record("apoz", 8.0)
    assert history.average("apoz") == pytest.approx(10.0)


def test_history_is_per_profile():
    history.record("apoz", 30.0)
    history.record("office", 4.0)
    assert history.average("apoz") == pytest.approx(30.0)
    assert history.average("office") == pytest.approx(4.0)


def test_only_recent_n_samples_are_kept_and_averaged():
    for _ in range(history._HISTORY_LEN):
        history.record("apoz", 2.0)
    # An 11th very different sample evicts the oldest; the window stays at N and
    # the mean reflects only the recent window, not all-time.
    history.record("apoz", 24.0)
    samples = history.load()["apoz"]
    assert len(samples) == history._HISTORY_LEN
    expected = (2.0 * (history._HISTORY_LEN - 1) + 24.0) / history._HISTORY_LEN
    assert history.average("apoz") == pytest.approx(expected)


def test_state_dir_prefers_explicit_override(monkeypatch, tmp_path):
    monkeypatch.setenv("FVPNCTL_STATE_DIR", str(tmp_path / "explicit"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "xdg"))
    assert history.state_dir() == (tmp_path / "explicit")


def test_state_dir_falls_back_to_xdg_then_home(monkeypatch, tmp_path):
    monkeypatch.delenv("FVPNCTL_STATE_DIR", raising=False)
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "xdg"))
    assert history.state_dir() == (tmp_path / "xdg" / "fvpnctl")
    monkeypatch.delenv("XDG_STATE_HOME", raising=False)
    monkeypatch.setattr(history.Path, "home", classmethod(lambda cls: tmp_path / "home"))
    assert history.state_dir() == (tmp_path / "home" / ".local" / "state" / "fvpnctl")


def test_corrupt_file_makes_average_raise():
    path = history._path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("{not json", encoding="utf-8")
    with pytest.raises(ValueError):
        history.average("apoz")


def test_record_self_heals_a_corrupt_file():
    path = history._path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("garbage", encoding="utf-8")
    # record() must not propagate the corruption: it resets and writes a valid file.
    history.record("apoz", 5.0)
    assert json.loads(path.read_text(encoding="utf-8")) == {"apoz": [5.0]}
    assert history.average("apoz") == pytest.approx(5.0)


def test_save_is_atomic_no_tmp_left_behind():
    history.record("apoz", 3.0)
    leftovers = list(history.state_dir().glob("*.tmp"))
    assert leftovers == []
