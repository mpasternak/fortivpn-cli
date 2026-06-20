"""Connect progress indicators — a Braille throbber and an ETA progress bar.

Why this exists
---------------
``fvpnctl connect <profile>`` (without ``--no-wait``) blocks in
:meth:`FortiVPN._wait_for_connection`, which polls ``getConnectionState`` once a
second for up to ``--timeout`` seconds while the daemon negotiates the IPsec
tunnel. That loop is silent, so a slow handshake looks like a frozen process.
This module paints live feedback so the user can see the wait is *working*:

* :class:`Spinner` — an indeterminate Braille throbber + elapsed seconds, used
  the first time a profile is connected (no timing history to estimate against).
* :class:`ProgressBar` — a determinate bar that fills toward an ETA, used once
  ``history`` has recorded past connect times for the profile (the ETA is their
  mean; see ``history.average``).

Both share the lifecycle in :class:`_Animated`; they differ only in the single
line they paint each tick (:meth:`_Animated._line`).

How they stay out of the controller's way
-----------------------------------------
The poll loop lives in ``controller.py`` and must stay UI-agnostic (the same
controller/transport/render split the rest of the codebase follows — see
``monitor.py``). So the indicator does **not** reach into the loop: the CLI wraps
the blocking ``connect()`` call in the context manager, the indicator animates on
a daemon thread while the main thread does the CDP I/O, and ``__exit__`` tears
the animation down. The controller is untouched.

Three modes, chosen from the stream + verbosity (:func:`select_mode`)
---------------------------------------------------------------------
* **off**    — ``--quiet`` (``enabled=False``): write nothing at all.
* **static** — verbose but the stream is not a TTY (piped / redirected): one
  plain ``message`` line, no ANSI and no ``\\r`` spam, so logs stay readable.
* **animate**— verbose on a real TTY: hide the cursor, paint the first frame
  synchronously (instant feedback, and one deterministic frame for tests), then
  animate on a background thread until ``__exit__``.

stderr, never stdout
--------------------
Like ``cli.report``, indicators write to **stderr** so stdout stays the
machine-readable channel (``CONNECTED <profile> <ip>``, ``--json``, pipelines).
``__exit__`` wipes the line and restores the cursor *before* the caller prints
its result/error, so success and failure both start on a clean line.

Pure vs. I/O
------------
:func:`render_frame`, :func:`render_bar` and :func:`select_mode` are pure (data
in, string out) and unit-tested directly; only :class:`_Animated` touches a
stream, a thread, and the clock.
"""

import sys
import threading
import time

# Braille "dots" spinner — ten frames that read as a smooth rotation. Zero
# dependencies (project rule): the frames are just literal Unicode here.
_FRAMES = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"

# ANSI control sequences (defined locally so this module stays standalone, like
# ``monitor.py`` keeps its own copy). Named so the I/O below reads as intent.
_HIDE_CURSOR = "\x1b[?25l"
_SHOW_CURSOR = "\x1b[?25h"
_CLEAR_EOL = "\x1b[K"

# Progress-bar geometry and glyphs.
_BAR_W = 24
_BAR_FILL = "█"
_BAR_EMPTY = "░"
# Never paint a full bar while the connect is still running — 100% is reserved
# for "actually finished". The bar saturates just below full and the elapsed/ETA
# tail keeps counting, so a slower-than-usual connect reads as "nearly there,
# overdue" rather than a bar stuck at 100%.
_BAR_CAP = 0.99


def render_frame(frame: str, message: str, elapsed: int) -> str:
    """Build one throbber line: ``\\r<frame> <message>  <elapsed>s`` + clear-to-EOL.

    Leads with ``\\r`` so each frame overwrites the previous in place, and ends
    with :data:`_CLEAR_EOL` so a shrinking line never leaves stale trailing
    characters. Pure — no I/O.
    """
    return f"\r{frame} {message}  {elapsed:d}s{_CLEAR_EOL}"


def render_bar(message: str, elapsed: float, eta: float, *, width: int = _BAR_W) -> str:
    """Build one progress-bar line filled to ``elapsed/eta`` (capped below 100%).

    The fraction is clamped to :data:`_BAR_CAP` and at least one cell is always
    left empty while running, so the bar never claims completion before the
    connect actually returns. The ``<elapsed>s / ~<eta>s`` tail stays honest when
    a connect overruns its estimate (e.g. ``41s / ~30s`` at 99%). Pure — no I/O.
    """
    frac = 0.0 if eta <= 0 else min(elapsed / eta, _BAR_CAP)
    filled = int(frac * width)
    if frac < 1.0:
        filled = min(filled, width - 1)  # keep one empty cell until truly done
    bar = _BAR_FILL * filled + _BAR_EMPTY * (width - filled)
    pct = int(frac * 100)
    tail = f"{int(elapsed)}s / ~{int(round(eta))}s"
    return f"\r{message}  [{bar}] {pct:>2d}%  {tail}{_CLEAR_EOL}"


def select_mode(stream, *, enabled: bool) -> str:
    """Choose ``off``/``static``/``animate`` from verbosity + the stream.

    ``enabled`` is the CLI's verbose flag: ``False`` (``--quiet``) → ``off``
    regardless of the stream. Otherwise a real TTY animates and anything else
    (a pipe, a file, a captured test buffer) gets the single static line.
    """
    if not enabled:
        return "off"
    isatty = getattr(stream, "isatty", None)
    if isatty and isatty():
        return "animate"
    return "static"


class _Animated:
    """Shared lifecycle for the connect indicators: mode, thread, cursor, cleanup.

    Subclasses implement :meth:`_line` to render one frame for a given elapsed
    time and tick count. In ``animate`` mode a daemon thread repaints every
    ``interval`` seconds; ``__exit__`` stops it, joins it, wipes the line and
    restores the cursor — including when the wrapped block raises (a
    ``ConnectTimeout``/``ConnectFailed`` must still leave a clean terminal).
    """

    def __init__(self, message: str, *, stream=None, enabled: bool = True, interval: float = 0.1):
        self._message = message
        self._stream = stream if stream is not None else sys.stderr
        self._interval = interval
        self._mode = select_mode(self._stream, enabled=enabled)
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._start: float | None = None
        self._tick = 0

    def _line(self, elapsed: float, tick: int) -> str:
        """Return the full ``\\r…`` line to paint this frame (subclass hook)."""
        raise NotImplementedError

    def __enter__(self) -> "_Animated":
        if self._mode == "off":
            return self
        if self._mode == "static":
            # Pipe/log path: one plain line, no animation.
            self._stream.write(self._message + "\n")
            self._stream.flush()
            return self
        # animate: hide the cursor and paint the first frame right away so there
        # is instant feedback (and one deterministic frame for the tests) before
        # the background thread takes over.
        self._start = time.monotonic()
        self._stream.write(_HIDE_CURSOR)
        self._paint()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        return self

    def _paint(self) -> None:
        """Write one frame for the current elapsed time + tick, then flush."""
        elapsed = time.monotonic() - self._start if self._start is not None else 0.0
        self._stream.write(self._line(elapsed, self._tick))
        self._stream.flush()
        self._tick += 1

    def _run(self) -> None:
        """Background loop: repaint every ``interval`` until stopped.

        Uses ``Event.wait(interval)`` rather than ``time.sleep`` so ``__exit__``
        setting the stop event ends the wait *immediately* — teardown never
        delays the caller by up to ``interval``.
        """
        while not self._stop.wait(self._interval):
            self._paint()

    def __exit__(self, *exc) -> bool:
        if self._mode != "animate":
            return False
        self._stop.set()
        if self._thread is not None:
            self._thread.join()
        # Wipe the line and bring the cursor back so the caller's next write
        # (result on stdout / error on stderr) starts on a clean line.
        self._stream.write("\r" + _CLEAR_EOL + _SHOW_CURSOR)
        self._stream.flush()
        return False  # never suppress the wrapped block's exception


class Spinner(_Animated):
    """Indeterminate Braille throbber — used when there is no ETA to estimate."""

    def _line(self, elapsed: float, tick: int) -> str:
        return render_frame(_FRAMES[tick % len(_FRAMES)], self._message, int(elapsed))


class ProgressBar(_Animated):
    """Determinate progress bar driven by ``eta`` (mean of past connect times)."""

    def __init__(
        self,
        message: str,
        eta: float,
        *,
        stream=None,
        enabled: bool = True,
        interval: float = 0.1,
    ):
        super().__init__(message, stream=stream, enabled=enabled, interval=interval)
        self._eta = eta

    def _line(self, elapsed: float, tick: int) -> str:
        return render_bar(self._message, elapsed, self._eta)
