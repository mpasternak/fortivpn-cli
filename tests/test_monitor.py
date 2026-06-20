"""Tests for the live monitor (``fvpnctl.monitor``).

CI-safe: no real terminal, no real socket, no sleeping. The render helpers are
pure (data in, string out) and tested directly. The poll loop is driven through
a fake ``FortiVPN`` whose ``state()`` returns a scripted sequence, with
``monitor.time.sleep``/``monitor.time.monotonic`` monkeypatched so the loop runs
instantly and deterministically. Output is captured by passing an ``io.StringIO``
as the stream — its ``isatty()`` is False, so the loop selects the ANSI-free
``plain`` mode and assertions can match exact text.
"""

import io

import pytest

from fvpnctl import monitor
from fvpnctl.errors import CDPEvaluateError
from fvpnctl.monitor import Snapshot


class FakeState:
    """Stand-in for ``ConnectionState`` exposing what the monitor reads."""

    def __init__(self, ipsec_state, name="office", state_label=None):
        self.ipsec_state = ipsec_state
        self.name = name
        self.state_label = state_label or ("CONNECTED" if ipsec_state == 2 else "DISCONNECTED")


class FakeVPN:
    """Scripted fake controller.

    ``states`` is consumed one per ``state()`` call (the last value repeats once
    exhausted). ``info``/``ip`` are returned by the enrichment reads, or raised
    if set to an exception. ``calls`` records method names for routing asserts.
    """

    def __init__(self, states, info=None, ip=None):
        self._states = list(states)
        self.info = info if info is not None else {}
        self.ip = ip if ip is not None else {}
        self.calls = []

    def state(self):
        self.calls.append("state")
        if len(self._states) > 1:
            return self._states.pop(0)
        return self._states[0]

    def connection_info(self, name, ctype):
        self.calls.append("connection_info")
        if isinstance(self.info, BaseException):
            raise self.info
        return self.info

    def connection_ip(self, name, ctype):
        self.calls.append("connection_ip")
        if isinstance(self.ip, BaseException):
            raise self.ip
        return self.ip


@pytest.fixture(autouse=True)
def no_sleep(monkeypatch):
    """Make the loop instant and deterministic.

    ``sleep`` is a no-op with a call ceiling so a logic bug cannot hang the suite
    in an infinite loop; ``monotonic`` advances by a fixed step each call so rate
    maths is reproducible.
    """
    sleeps = {"n": 0}

    def fake_sleep(_seconds):
        sleeps["n"] += 1
        if sleeps["n"] > 1000:
            raise AssertionError("monitor.run looped without terminating")

    ticks = {"t": 0.0}

    def fake_monotonic():
        ticks["t"] += 1.0
        return ticks["t"]

    monkeypatch.setattr(monitor.time, "sleep", fake_sleep)
    monkeypatch.setattr(monitor.time, "monotonic", fake_monotonic)
    return sleeps


# -- human_bytes / human_rate ------------------------------------------------


@pytest.mark.parametrize(
    "n,expected",
    [
        (None, "—"),
        (0, "0 B"),
        (512, "512 B"),
        (1024, "1.0 KB"),
        (1536, "1.5 KB"),
        (1048576, "1.0 MB"),
        (1073741824, "1.0 GB"),
    ],
)
def test_human_bytes(n, expected):
    assert monitor.human_bytes(n) == expected


def test_human_rate():
    assert monitor.human_rate(None) == "—"
    assert monitor.human_rate(0) == "0 B/s"
    assert monitor.human_rate(1536) == "1.5 KB/s"


# -- sparkline ---------------------------------------------------------------


def test_sparkline_empty_is_empty():
    assert monitor.sparkline([]) == ""


def test_sparkline_all_zero_uses_lowest_block():
    assert monitor.sparkline([0, 0, 0]) == "▁▁▁"


def test_sparkline_max_is_full_block_and_width_limited():
    spark = monitor.sparkline([1, 2, 3, 4, 8], width=16)
    assert len(spark) == 5
    assert spark[-1] == "█"  # the maximum scales to the tallest block


def test_sparkline_respects_width():
    spark = monitor.sparkline(list(range(100)), width=10)
    assert len(spark) == 10


# -- visible length / padding (ANSI-aware) -----------------------------------


def test_pad_ignores_ansi_width():
    colored = f"{monitor._GREEN}hi{monitor._RESET}"
    padded = monitor._pad(colored, 10)
    # 2 visible chars -> 8 trailing spaces, ANSI codes do not count.
    assert padded == colored + " " * 8
    assert monitor._visible_len(padded) == 10


# -- render modes ------------------------------------------------------------


def _connected_snap(**over):
    base = dict(
        ipsec_state=2,
        state_label="CONNECTED",
        name="apoz",
        vpn_ip="10.10.115.1",
        duration="00:10:54",
        traffic_in=782548,
        traffic_out=883792,
        rate_in=12595.2,
        rate_out=4198.4,
        stats_ok=True,
    )
    base.update(over)
    return Snapshot(**base)


def test_render_plain_connected_has_fields():
    line = monitor.render_plain(_connected_snap())
    assert "CONNECTED" in line
    assert "apoz" in line
    assert "10.10.115.1" in line
    assert "00:10:54" in line
    assert "in=782548" in line
    assert "out=883792" in line
    # No ANSI escapes in plain mode.
    assert "\x1b[" not in line


def test_render_plain_disconnected_is_label_only():
    snap = Snapshot(ipsec_state=0, state_label="DISCONNECTED", name="")
    assert monitor.render_plain(snap) == "DISCONNECTED"


def test_render_plain_marks_stats_unavailable():
    snap = _connected_snap(stats_ok=False, traffic_in=None, traffic_out=None, rate_in=None)
    line = monitor.render_plain(snap)
    assert "stats unavailable" in line


def test_render_line_is_single_line_with_color():
    line = monitor.render_line(_connected_snap(), color=True)
    assert "\n" not in line
    assert "CONNECTED" in line
    assert "10.10.115.1" in line
    assert "\x1b[" in line  # colored


def test_render_line_plain_when_color_off():
    line = monitor.render_line(_connected_snap(), color=False)
    assert "\x1b[" not in line


def test_render_card_has_box_and_fields():
    card = monitor.render_card(_connected_snap(), "▁▂▃█", color=False, interval=2.0)
    assert "┌" in card and "┐" in card and "└" in card and "┘" in card
    assert "fvpnctl monitor" in card
    assert "CONNECTED" in card
    assert "10.10.115.1" in card
    assert "▁▂▃█" in card  # sparkline embedded
    assert "polling every 2s" in card
    # Every box line is the same visible width.
    box_lines = [ln for ln in card.splitlines() if ln.startswith(("┌", "│", "└"))]
    widths = {monitor._visible_len(ln) for ln in box_lines}
    assert len(widths) == 1


def test_render_card_disconnected_omits_stats():
    snap = Snapshot(ipsec_state=0, state_label="DISCONNECTED", name="apoz")
    card = monitor.render_card(snap, "", color=False, interval=2.0)
    assert "DISCONNECTED" in card
    assert "throughput" not in card


# -- build_snapshot / rate maths ---------------------------------------------


def test_build_snapshot_disconnected_skips_enrichment():
    vpn = FakeVPN(states=[FakeState(0, name="", state_label="DISCONNECTED")])
    snap = monitor.build_snapshot(vpn, prev_in=None, prev_out=None, prev_t=None, now=1.0)
    assert snap.connected is False
    assert vpn.calls == ["state"]  # no connection_info/connection_ip


def test_build_snapshot_first_tick_has_no_rate():
    vpn = FakeVPN(
        states=[FakeState(2)],
        info={"duration": "00:00:05", "traffic_in": 1000, "traffic_out": 2000},
        ip={"vpn_ip": "10.0.0.2"},
    )
    snap = monitor.build_snapshot(vpn, prev_in=None, prev_out=None, prev_t=None, now=1.0)
    assert snap.connected
    assert snap.vpn_ip == "10.0.0.2"
    assert snap.traffic_in == 1000
    assert snap.rate_in is None  # no previous sample


def test_build_snapshot_computes_rate_from_delta():
    vpn = FakeVPN(
        states=[FakeState(2)],
        info={"duration": "00:00:06", "traffic_in": 3000, "traffic_out": 5000},
        ip={"vpn_ip": "10.0.0.2"},
    )
    # 2000 bytes in over 2 seconds = 1000 B/s; 3000 out over 2s = 1500 B/s.
    snap = monitor.build_snapshot(vpn, prev_in=1000, prev_out=2000, prev_t=4.0, now=6.0)
    assert snap.rate_in == 1000.0
    assert snap.rate_out == 1500.0


def test_build_snapshot_clamps_counter_reset_to_zero():
    vpn = FakeVPN(
        states=[FakeState(2)],
        info={"duration": "00:00:01", "traffic_in": 10, "traffic_out": 10},
        ip={"vpn_ip": "10.0.0.2"},
    )
    # Counter went backwards (reconnect) -> rate clamps to 0, never negative.
    snap = monitor.build_snapshot(vpn, prev_in=9999, prev_out=9999, prev_t=1.0, now=2.0)
    assert snap.rate_in == 0
    assert snap.rate_out == 0


def test_build_snapshot_coerces_string_counters():
    vpn = FakeVPN(
        states=[FakeState(2)],
        info={"duration": "x", "traffic_in": "3000", "traffic_out": "5000"},
        ip={"vpn_ip": "10.0.0.2"},
    )
    snap = monitor.build_snapshot(vpn, prev_in=1000, prev_out=2000, prev_t=4.0, now=6.0)
    assert snap.traffic_in == 3000
    assert snap.rate_in == 1000.0


def test_build_snapshot_tolerates_enrichment_failure():
    vpn = FakeVPN(states=[FakeState(2)], info=CDPEvaluateError("busy"))
    snap = monitor.build_snapshot(vpn, prev_in=None, prev_out=None, prev_t=None, now=1.0)
    assert snap.connected
    assert snap.stats_ok is False
    assert snap.traffic_in is None


def test_build_snapshot_propagates_state_failure():
    """A failing state() means FortiClient is gone — it must NOT be swallowed."""

    class Gone:
        def state(self):
            raise CDPEvaluateError("CDP socket closed mid-frame.")

    with pytest.raises(CDPEvaluateError):
        monitor.build_snapshot(Gone(), prev_in=None, prev_out=None, prev_t=None, now=1.0)


# -- mode / color selection --------------------------------------------------


class _Tty:
    def __init__(self, tty):
        self._tty = tty

    def isatty(self):
        return self._tty


def test_select_mode_plain_when_not_tty():
    assert monitor.select_mode(io.StringIO()) == "plain"


def test_select_mode_card_when_wide(monkeypatch):
    monkeypatch.setattr(
        monitor.shutil, "get_terminal_size", lambda: type("S", (), {"columns": 120})()
    )
    assert monitor.select_mode(_Tty(True)) == "card"


def test_select_mode_line_when_narrow(monkeypatch):
    monkeypatch.setattr(
        monitor.shutil, "get_terminal_size", lambda: type("S", (), {"columns": 40})()
    )
    assert monitor.select_mode(_Tty(True)) == "line"


def test_color_disabled_by_no_color_env(monkeypatch):
    monkeypatch.setenv("NO_COLOR", "1")
    assert monitor._color_enabled(_Tty(True)) is False


# -- the run loop ------------------------------------------------------------


def test_run_exits_zero_on_disconnect():
    # CONNECTED for one tick, then DISCONNECTED -> render both, exit 0.
    vpn = FakeVPN(
        states=[FakeState(2), FakeState(0, state_label="DISCONNECTED")],
        info={"duration": "00:00:05", "traffic_in": 1000, "traffic_out": 2000},
        ip={"vpn_ip": "10.0.0.2"},
    )
    out = io.StringIO()
    rc = monitor.run(vpn, interval=2.0, stream=out)
    assert rc == 0
    text = out.getvalue()
    assert "CONNECTED" in text
    assert "DISCONNECTED" in text


def test_run_exits_immediately_when_already_disconnected():
    vpn = FakeVPN(states=[FakeState(0, state_label="DISCONNECTED")])
    out = io.StringIO()
    rc = monitor.run(vpn, interval=2.0, stream=out)
    assert rc == 0
    # Exactly one rendered line; loop never slept.
    assert out.getvalue().strip() == "DISCONNECTED"


def test_run_plain_mode_emits_one_line_per_tick(no_sleep):
    vpn = FakeVPN(
        states=[FakeState(2), FakeState(2), FakeState(0, state_label="DISCONNECTED")],
        info={"duration": "00:00:05", "traffic_in": 1000, "traffic_out": 2000},
        ip={"vpn_ip": "10.0.0.2"},
    )
    out = io.StringIO()
    monitor.run(vpn, interval=1.0, stream=out)
    lines = [ln for ln in out.getvalue().splitlines() if ln]
    assert len(lines) == 3  # two CONNECTED ticks + final DISCONNECTED
    assert no_sleep["n"] == 2  # slept only between connected ticks


def test_run_propagates_keyboard_interrupt_and_restores_cursor(monkeypatch):
    # A TTY stream so the loop hides the cursor; Ctrl-C during sleep must still
    # restore it (and drop a newline) via the finally before propagating.
    vpn = FakeVPN(
        states=[FakeState(2)],
        info={"duration": "00:00:05", "traffic_in": 1, "traffic_out": 1},
        ip={"vpn_ip": "10.0.0.2"},
    )

    def boom(_seconds):
        raise KeyboardInterrupt

    monkeypatch.setattr(monitor.time, "sleep", boom)
    monkeypatch.setattr(monitor, "select_mode", lambda _s: "line")

    out = io.StringIO()
    with pytest.raises(KeyboardInterrupt):
        monitor.run(vpn, interval=1.0, stream=out)
    text = out.getvalue()
    assert monitor._HIDE_CURSOR in text
    assert monitor._SHOW_CURSOR in text  # cursor restored despite Ctrl-C
