"""Tests for the connect throbber (``fvpnctl.spinner``).

CI-safe: no real terminal, no real sleeping that the suite depends on. The pure
helpers (:func:`spinner.render_frame`, :func:`spinner.select_mode`) are tested
directly. The :class:`spinner.Spinner` context manager is driven over a fake
stream whose ``isatty()`` is scripted, so each of the three modes
(``off``/``static``/``animate``) is exercised deterministically:

* ``off``   — ``enabled=False`` (the ``--quiet`` path): writes nothing.
* ``static``— a non-TTY stream (pipe/log): one plain line, no ANSI, no ``\\r``.
* ``animate``— a TTY stream: hides the cursor, paints frame 0 *synchronously* on
  enter (so at least one frame is deterministic without waiting on the thread),
  and on exit wipes the line and restores the cursor.

The animate test uses a deliberately huge ``interval`` so the background thread
is still parked in its first ``wait`` when ``__exit__`` sets the stop event —
that makes "exactly the synchronous frame 0 was painted" reliable rather than
racing the thread's clock.
"""

import io

from fvpnctl import spinner


class FakeStream(io.StringIO):
    """A ``StringIO`` with a scripted ``isatty()`` so mode selection is testable."""

    def __init__(self, *, tty):
        super().__init__()
        self._tty = tty

    def isatty(self):
        return self._tty


# -- pure helpers ------------------------------------------------------------


def test_render_frame_carries_braille_message_and_elapsed():
    out = spinner.render_frame("⠋", "Connecting profile apoz…", 7)
    assert out.startswith("\r")
    assert "⠋" in out
    assert "Connecting profile apoz…" in out
    assert "7s" in out
    # Clears to end of line so a shrinking message never leaves stale tail chars.
    assert out.endswith(spinner._CLEAR_EOL)


def test_select_mode_off_when_disabled_even_on_tty():
    assert spinner.select_mode(FakeStream(tty=True), enabled=False) == "off"


def test_select_mode_static_on_non_tty():
    assert spinner.select_mode(FakeStream(tty=False), enabled=True) == "static"


def test_select_mode_animate_on_tty():
    assert spinner.select_mode(FakeStream(tty=True), enabled=True) == "animate"


# -- context manager: the three modes ----------------------------------------


def test_off_mode_writes_nothing():
    stream = FakeStream(tty=True)
    with spinner.Spinner("Connecting profile apoz…", stream=stream, enabled=False):
        pass
    assert stream.getvalue() == ""


def test_static_mode_writes_one_plain_line():
    stream = FakeStream(tty=False)
    with spinner.Spinner("Connecting profile apoz…", stream=stream, enabled=True):
        pass
    out = stream.getvalue()
    assert out == "Connecting profile apoz…\n"
    # No ANSI, no carriage-return animation in the pipe/log path.
    assert "\x1b" not in out
    assert "\r" not in out


def test_animate_mode_paints_frame0_and_cleans_up():
    stream = FakeStream(tty=True)
    # Huge interval: the worker thread parks in its first wait() and never paints
    # a second frame before __exit__ stops it — so only the synchronous frame 0
    # is guaranteed, making the assertions deterministic.
    with spinner.Spinner("Connecting profile apoz…", stream=stream, enabled=True, interval=1000):
        pass
    out = stream.getvalue()
    assert spinner._HIDE_CURSOR in out  # cursor hidden on enter
    assert spinner._FRAMES[0] in out  # first braille frame painted synchronously
    assert "Connecting profile apoz…" in out
    assert spinner._SHOW_CURSOR in out  # cursor restored on exit
    # The line is wiped on exit so the next print starts clean.
    assert out.rstrip().endswith(spinner._SHOW_CURSOR) or spinner._CLEAR_EOL in out


def test_animate_mode_restores_cursor_even_on_exception():
    stream = FakeStream(tty=True)
    try:
        with spinner.Spinner(
            "Connecting profile apoz…", stream=stream, enabled=True, interval=1000
        ):
            raise RuntimeError("connect blew up")
    except RuntimeError:
        pass
    out = stream.getvalue()
    # A failed connect (ConnectTimeout etc.) must still leave a clean terminal.
    assert spinner._SHOW_CURSOR in out
