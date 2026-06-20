"""Connect throbber — a Braille spinner for the blocking ``connect`` wait.

Why this exists
---------------
``fvpnctl connect <profile>`` (without ``--no-wait``) blocks in
:meth:`FortiVPN._wait_for_connection`, which polls ``getConnectionState`` once a
second for up to ``--timeout`` seconds while the daemon negotiates the IPsec
tunnel. That loop is silent, so a slow handshake looks like a frozen process.
This module paints a live Braille spinner + elapsed-seconds counter so the user
can see the wait is *working*, not hung.

How it stays out of the controller's way
----------------------------------------
The poll loop lives in ``controller.py`` and must stay UI-agnostic (the same
controller/transport/render split the rest of the codebase follows — see
``monitor.py``). So the spinner does **not** reach into the loop: the CLI wraps
the blocking ``connect()`` call in a :class:`Spinner` context manager, the
spinner animates on a daemon thread while the main thread does the CDP I/O, and
``__exit__`` tears the animation down. The controller is untouched.

Three modes, chosen from the stream + verbosity (:func:`select_mode`)
---------------------------------------------------------------------
* **off**    — ``--quiet`` (``enabled=False``): write nothing at all.
* **static** — verbose but the stream is not a TTY (piped / redirected): one
  plain ``message`` line, no ANSI and no ``\\r`` spam, so logs stay readable.
* **animate**— verbose on a real TTY: hide the cursor, paint frame 0
  synchronously (instant first feedback, and one deterministic frame for tests),
  then animate the remaining frames on a background thread until ``__exit__``.

stderr, never stdout
--------------------
Like ``cli.report``, the spinner writes to **stderr** so stdout stays the
machine-readable channel (``CONNECTED <profile> <ip>``, ``--json``, pipelines).
``__exit__`` wipes the spinner line and restores the cursor *before* the caller
prints its result/error, so success and failure both start on a clean line.

Pure vs. I/O
------------
:func:`render_frame` and :func:`select_mode` are pure (data in, string out) and
unit-tested directly; only :class:`Spinner` touches a stream, a thread, and the
clock.
"""

import itertools
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


def render_frame(frame: str, message: str, elapsed: int) -> str:
    """Build one spinner line: ``\\r<frame> <message>  <elapsed>s`` + clear-to-EOL.

    Leads with ``\\r`` so each frame overwrites the previous one in place, and
    ends with :data:`_CLEAR_EOL` so a shrinking ``message`` (or a smaller elapsed
    count) never leaves stale characters trailing on the line. Pure — no I/O.
    """
    return f"\r{frame} {message}  {elapsed:d}s{_CLEAR_EOL}"


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


class Spinner:
    """Context manager that animates a Braille throbber around a blocking call.

    Usage::

        with Spinner("Connecting profile apoz…", stream=sys.stderr, enabled=verbose):
            state = fvpnctl.connect(...)   # blocks; the spinner animates meanwhile

    The mode is fixed at construction from ``stream`` + ``enabled`` (see
    :func:`select_mode`). In ``animate`` mode a daemon thread paints a frame
    every ``interval`` seconds; ``__exit__`` stops it, joins it, wipes the line
    and restores the cursor — including when the wrapped block raises (a
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

    def __enter__(self) -> "Spinner":
        if self._mode == "off":
            return self
        if self._mode == "static":
            # Pipe/log path: one plain line, no animation. Mirrors the old
            # ``report("Connecting profile …")`` behaviour exactly.
            self._stream.write(self._message + "\n")
            self._stream.flush()
            return self
        # animate: hide the cursor and paint the first frame right away so there
        # is instant feedback (and one deterministic frame for the tests) before
        # the background thread takes over.
        self._start = time.monotonic()
        self._stream.write(_HIDE_CURSOR)
        self._paint(_FRAMES[0])
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        return self

    def _paint(self, frame: str) -> None:
        """Write one frame for the current elapsed time, then flush."""
        elapsed = int(time.monotonic() - self._start) if self._start is not None else 0
        self._stream.write(render_frame(frame, self._message, elapsed))
        self._stream.flush()

    def _run(self) -> None:
        """Background loop: advance the frame every ``interval`` until stopped.

        Uses ``Event.wait(interval)`` rather than ``time.sleep`` so ``__exit__``
        setting the stop event ends the wait *immediately* — the spinner never
        delays the caller by up to ``interval`` on teardown.
        """
        for frame in itertools.cycle(_FRAMES[1:] + _FRAMES[:1]):
            if self._stop.wait(self._interval):
                return
            self._paint(frame)

    def __exit__(self, *exc) -> bool:
        if self._mode != "animate":
            return False
        self._stop.set()
        if self._thread is not None:
            self._thread.join()
        # Wipe the spinner line and bring the cursor back so the caller's next
        # write (result on stdout / error on stderr) starts on a clean line.
        self._stream.write("\r" + _CLEAR_EOL + _SHOW_CURSOR)
        self._stream.flush()
        return False  # never suppress the wrapped block's exception
