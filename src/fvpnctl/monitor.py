"""Live tunnel monitor — the ``fvpnctl monitor`` render + poll loop.

What this is
------------
``run(fvpnctl, ...)`` polls a connected :class:`~fvpnctl.controller.FortiVPN` on
an interval and renders the tunnel status in place until the tunnel drops, then
exits 0. It is the moving-picture companion to the one-shot ``status`` command:
where ``status`` prints raw cumulative byte counters once, ``monitor`` derives
live **throughput rates** from the deltas between polls (the genuinely useful
upgrade) and redraws a compact, colored view.

Three render modes, chosen from the output stream (:func:`select_mode`)
----------------------------------------------------------------------
* **plain** — output is not a TTY (piped / redirected): one status line per
  poll, appended, so the stream stays greppable and loggable.
* **line** — a TTY too narrow for the card: a single ``\\r``-refreshed line.
* **card** — a wide TTY: a boxed, colored dashboard redrawn in place, with a
  Unicode-block throughput sparkline.

Why the loop lives here and not in ``cli.py``
---------------------------------------------
``cli.py`` owns argument parsing and the one-shot command bodies; the monitor is
a self-contained unit with its own rendering vocabulary (ANSI, box drawing,
sparklines, rate maths). Keeping it in its own module mirrors the existing
controller/transport split and keeps every render helper here pure and unit
testable (no socket, no real terminal): :func:`human_bytes`, :func:`human_rate`,
:func:`sparkline`, :func:`render_card` / :func:`render_line` / :func:`render_plain`
all take data in and return strings. Only :func:`run` does I/O.

Error handling (project policy: never swallow silently)
-------------------------------------------------------
``state()`` raising :class:`~fvpnctl.errors.CDPEvaluateError` means FortiClient
went away (the transport surfaces a closed socket as that type) — it is **not**
caught here; it propagates to the CLI's top-level handler which prints it and
exits 6. Only the *enrichment* reads (``connection_info``/``connection_ip``) are
tolerated per-tick: if they throw while the state still reports CONNECTED, the
affected fields render as ``—`` with a visible ``(stats unavailable)`` note and
the loop continues — degraded but never silent. ``time`` is referenced as a
module attribute so tests can monkeypatch ``monitor.time.sleep`` /
``monitor.time.monotonic`` for instant, deterministic runs.
"""

import os
import re
import shutil
import sys
import time
from dataclasses import dataclass

from fvpnctl.errors import CDPEvaluateError

# ``ipsec_state`` value meaning "tunnel up" (mirrors cli._CONNECTED /
# controller._CONNECTED; the monitor only needs the CONNECTED sentinel).
_CONNECTED = 2
_IPSEC = "ipsec"

# Card geometry. The card needs this many columns; below it we fall back to the
# single refreshing line. ``_CARD_W`` is the inner width between the │ borders.
_CARD_W = 50
_CARD_MIN_WIDTH = _CARD_W + 4
_SPARK_WIDTH = 16

# ANSI control sequences. Kept as named constants so the redraw logic in run()
# reads as intent, not magic strings.
_RESET = "\x1b[0m"
_BOLD = "\x1b[1m"
_DIM = "\x1b[2m"
_GREEN = "\x1b[32m"
_YELLOW = "\x1b[33m"
_RED = "\x1b[31m"
_CYAN = "\x1b[36m"
_HIDE_CURSOR = "\x1b[?25l"
_SHOW_CURSOR = "\x1b[?25h"
_CLEAR_EOL = "\x1b[K"

_DOT = "●"
_BLOCKS = "▁▂▃▄▅▆▇█"
_ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")


@dataclass
class Snapshot:
    """One poll's worth of tunnel state, with rates already derived.

    Rates are bytes/second computed from the delta against the previous poll;
    they are ``None`` on the first poll (no previous sample) and whenever the
    enrichment reads failed. ``stats_ok`` is ``False`` exactly when the
    CONNECTED state could not be enriched with ``connection_info``/
    ``connection_ip`` this tick — the render layer shows a degraded view rather
    than crashing the loop.
    """

    ipsec_state: int
    state_label: str
    name: str
    vpn_ip: str | None = None
    duration: str | None = None
    traffic_in: int | None = None
    traffic_out: int | None = None
    rate_in: float | None = None
    rate_out: float | None = None
    stats_ok: bool = True

    @property
    def connected(self) -> bool:
        return self.ipsec_state == _CONNECTED


# -- pure formatting helpers (no I/O) ---------------------------------------


def human_bytes(n: int | float | None) -> str:
    """Format a byte count as ``B``/``KB``/``MB``/... (``—`` for unknown)."""
    if n is None:
        return "—"
    value = float(n)
    units = ("B", "KB", "MB", "GB", "TB", "PB")
    i = 0
    while value >= 1024 and i < len(units) - 1:
        value /= 1024
        i += 1
    if i == 0:
        return f"{int(value)} B"
    return f"{value:.1f} {units[i]}"


def human_rate(bytes_per_s: float | None) -> str:
    """Format a throughput as ``human_bytes(...)/s`` (``—`` for unknown)."""
    if bytes_per_s is None:
        return "—"
    return f"{human_bytes(bytes_per_s)}/s"


def sparkline(values: list[float], width: int = _SPARK_WIDTH) -> str:
    """Render the last ``width`` ``values`` as Unicode block bars.

    Scaled to the maximum in the window, so the tallest bar is always ``█`` and
    a flat-zero history renders as the lowest block. Empty input → empty string.
    """
    if not values:
        return ""
    window = values[-width:]
    hi = max(window)
    if hi <= 0:
        return _BLOCKS[0] * len(window)
    top = len(_BLOCKS) - 1
    return "".join(_BLOCKS[max(0, min(top, round(v / hi * top)))] for v in window)


def _visible_len(s: str) -> int:
    """Length of ``s`` as displayed — ANSI escapes count as zero width."""
    return len(_ANSI_RE.sub("", s))


def _pad(s: str, width: int) -> str:
    """Right-pad ``s`` with spaces to ``width`` visible columns."""
    return s + " " * max(0, width - _visible_len(s))


def _color(text: str, code: str, enabled: bool) -> str:
    """Wrap ``text`` in ``code``/reset when ``enabled``, else return it plain."""
    return f"{code}{text}{_RESET}" if enabled else text


def _status_color(label: str) -> str:
    """ANSI color for a state label: green up, yellow transitional, red down."""
    if label == "CONNECTED":
        return _GREEN
    if label in ("CONNECTING", "RECONNECTING", "XAUTH"):
        return _YELLOW
    return _RED


# -- render modes ------------------------------------------------------------


def render_plain(snap: Snapshot) -> str:
    """One greppable status line for non-TTY output (no ANSI).

    Connected lines mirror the ``status`` command's shape and append live rates
    when known; a disconnected snapshot is just its label.
    """
    if not snap.connected:
        return snap.state_label
    tin = snap.traffic_in if snap.traffic_in is not None else "?"
    tout = snap.traffic_out if snap.traffic_out is not None else "?"
    line = (
        f"{snap.state_label} {snap.name} {snap.vpn_ip or ''} "
        f"({snap.duration or '—'}, in={tin} out={tout}"
    )
    if snap.rate_in is not None:
        line += f", ↓{human_rate(snap.rate_in)} ↑{human_rate(snap.rate_out)}"
    line += ")"
    if not snap.stats_ok:
        line += " (stats unavailable)"
    return line


def render_line(snap: Snapshot, *, color: bool) -> str:
    """A single refreshing status line for a narrow TTY."""
    dot = _color(_DOT, _status_color(snap.state_label), color)
    label = _color(snap.state_label, _status_color(snap.state_label), color)
    if not snap.connected:
        return f"{dot} {label}  {snap.name}".rstrip()
    return (
        f"{dot} {label}  {snap.name}  {snap.vpn_ip or '—'}  "
        f"up {snap.duration or '—'}  ↓ {human_rate(snap.rate_in)}  "
        f"↑ {human_rate(snap.rate_out)}"
    )


def render_card(snap: Snapshot, spark: str, *, color: bool, interval: float) -> str:
    """The boxed dashboard for a wide TTY, returned as one multi-line string.

    Includes the footer line below the box so the whole frame is one unit the
    redraw logic in :func:`run` can move over wholesale.
    """
    scol = _status_color(snap.state_label)
    title = "─ fvpnctl monitor "
    top = "┌" + title + "─" * (_CARD_W - len(title)) + "┐"
    bottom = "└" + "─" * _CARD_W + "┘"

    status = f"  {_color(_DOT, scol, color)} {_color(snap.state_label, scol + _BOLD, color)}"
    if snap.name:
        status += f"   {snap.name}"

    rows = [status]
    if snap.connected:
        rows.append("")
        rows.append(f"    IP        {snap.vpn_ip or '—'}")
        rows.append(f"    Uptime    {snap.duration or '—'}")
        rows.append(
            f"    Down   ↓  {human_rate(snap.rate_in):>11}   total {human_bytes(snap.traffic_in)}"
        )
        rows.append(
            f"    Up     ↑  {human_rate(snap.rate_out):>11}   total {human_bytes(snap.traffic_out)}"
        )
        if not snap.stats_ok:
            rows.append(_color("    (stats unavailable)", _DIM, color))
        rows.append("")
        rows.append(f"    {_color(spark, _CYAN, color)}  {_color('throughput', _DIM, color)}")

    body = [top]
    for row in rows:
        body.append("│" + _pad(row, _CARD_W) + "│")
    body.append(bottom)
    footer = _color(f"  polling every {interval:g}s · Ctrl-C to quit", _DIM, color)
    body.append(footer)
    return "\n".join(body)


# -- snapshot building -------------------------------------------------------


def _to_int(value) -> int | None:
    """Best-effort coerce a traffic counter (int or numeric string) to int."""
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def build_snapshot(
    fvpnctl,
    *,
    prev_in: int | None,
    prev_out: int | None,
    prev_t: float | None,
    now: float,
) -> Snapshot:
    """Read one snapshot, deriving rates from the previous poll's totals.

    ``state()`` is read unguarded: if it raises, FortiClient is gone and the
    error must propagate (see the module docstring). The enrichment reads are
    wrapped narrowly — a :class:`CDPEvaluateError` there yields ``stats_ok=False``
    and a degraded snapshot rather than ending the loop.
    """
    state = fvpnctl.state()
    if state.ipsec_state != _CONNECTED:
        return Snapshot(
            ipsec_state=state.ipsec_state,
            state_label=state.state_label,
            name=state.name,
        )

    stats_ok = True
    try:
        info = fvpnctl.connection_info(state.name, _IPSEC)
        ipd = fvpnctl.connection_ip(state.name, _IPSEC)
    except CDPEvaluateError:
        # FortiClient answered "state=CONNECTED" but rejected the stats calls this
        # tick (transient). Degrade visibly instead of killing a long-running
        # monitor; the next tick retries.
        stats_ok = False
        info, ipd = {}, {}

    tin = _to_int(info.get("traffic_in"))
    tout = _to_int(info.get("traffic_out"))
    rate_in = rate_out = None
    if prev_t is not None and tin is not None and prev_in is not None:
        dt = now - prev_t
        if dt > 0:
            # Clamp to >=0 so a counter reset on reconnect never shows negative.
            rate_in = max(0, tin - prev_in) / dt
            rate_out = max(0, (tout or 0) - (prev_out or 0)) / dt

    return Snapshot(
        ipsec_state=state.ipsec_state,
        state_label=state.state_label,
        name=state.name,
        vpn_ip=ipd.get("vpn_ip"),
        duration=info.get("duration"),
        traffic_in=tin,
        traffic_out=tout,
        rate_in=rate_in,
        rate_out=rate_out,
        stats_ok=stats_ok,
    )


# -- mode / color selection --------------------------------------------------


def select_mode(stream) -> str:
    """Choose ``plain``/``line``/``card`` from the output stream.

    Not a TTY → ``plain`` (pipe-safe). A TTY at least ``_CARD_MIN_WIDTH`` columns
    wide → ``card``; anything narrower → the single ``line``.
    """
    if not _is_tty(stream):
        return "plain"
    width = shutil.get_terminal_size().columns
    return "card" if width >= _CARD_MIN_WIDTH else "line"


def _is_tty(stream) -> bool:
    isatty = getattr(stream, "isatty", None)
    return bool(isatty and isatty())


def _color_enabled(stream) -> bool:
    """Color only on a real TTY with ``NO_COLOR`` unset (the NO_COLOR standard)."""
    return _is_tty(stream) and not os.environ.get("NO_COLOR")


# -- the loop ----------------------------------------------------------------


def run(fvpnctl, *, interval: float = 2.0, stream=None) -> int:
    """Poll ``fvpnctl`` every ``interval`` seconds, redraw, exit 0 on disconnect.

    Returns 0 once a non-CONNECTED state is observed (including immediately, if
    the tunnel is already down at launch). ``KeyboardInterrupt`` is left to
    propagate to the CLI (which maps it to exit 130) — but not before the
    ``finally`` restores the cursor and drops to a fresh line, so Ctrl-C never
    leaves a hidden cursor or a half-drawn frame behind.
    """
    stream = stream if stream is not None else sys.stdout
    mode = select_mode(stream)
    color = _color_enabled(stream)

    spark_data: list[float] = []
    prev_in = prev_out = prev_t = None
    prev_lines = 0
    cursor_hidden = False

    try:
        if mode in ("card", "line"):
            stream.write(_HIDE_CURSOR)
            cursor_hidden = True

        while True:
            now = time.monotonic()
            snap = build_snapshot(
                fvpnctl, prev_in=prev_in, prev_out=prev_out, prev_t=prev_t, now=now
            )
            prev_in, prev_out, prev_t = snap.traffic_in, snap.traffic_out, now

            if mode == "plain":
                stream.write(render_plain(snap) + "\n")
            elif mode == "line":
                stream.write("\r" + _CLEAR_EOL + render_line(snap, color=color))
            else:
                if snap.connected:
                    spark_data.append((snap.rate_in or 0) + (snap.rate_out or 0))
                frame = render_card(snap, sparkline(spark_data), color=color, interval=interval)
                _redraw_card(stream, frame, prev_lines)
                prev_lines = frame.count("\n")
            stream.flush()

            if not snap.connected:
                return 0
            time.sleep(interval)
    finally:
        if cursor_hidden:
            stream.write(_SHOW_CURSOR)
        if mode in ("card", "line"):
            stream.write("\n")
        stream.flush()


def _redraw_card(stream, frame: str, prev_lines: int) -> None:
    """Overwrite the previous card in place (move up, clear down, repaint)."""
    if prev_lines:
        stream.write(f"\x1b[{prev_lines}A\r\x1b[J")
    stream.write(frame)
