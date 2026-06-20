"""Connect-time history — per-profile durations that feed the progress bar.

What this is
------------
``fvpnctl connect`` blocks while the daemon negotiates the tunnel. The first time
a profile is connected there is nothing to estimate against, so the CLI shows an
indeterminate Braille throbber (``spinner.Spinner``). Every *successful* waited
connect records its wall-clock duration here; on the next connect the CLI reads
back the mean of the recent samples and shows a **determinate progress bar**
(``spinner.ProgressBar``) that fills toward that ETA.

Why per-profile, why a recent window
------------------------------------
Different gateways have very different handshake times, so durations are keyed by
``connection_name``. Only the last :data:`_HISTORY_LEN` samples are kept and
averaged, so the estimate tracks *current* network conditions instead of being
dragged by months-old measurements.

Where it lives
--------------
A small JSON file under the per-user XDG *state* dir (these are derived numbers
fvpnctl can always rebuild — state, not config). The location is resolved by
:func:`state_dir`; ``$FVPNCTL_STATE_DIR`` overrides everything (the test suite
points it at a tmp dir so it never touches real user state).

Error policy (project rule: never swallow silently)
---------------------------------------------------
A *missing* file is the normal first-run case and yields an empty history — not
an error. A *corrupt* file makes :func:`load`/:func:`average` raise ``ValueError``
so the CLI can surface it (``cli._connect_eta`` reports it and falls back to the
throbber). :func:`record` additionally self-heals a corrupt file rather than
failing a connect that just succeeded — the one place a narrow catch is justified.
"""

import json
import os
from pathlib import Path

# Keep at most this many recent measurements per profile; the progress-bar ETA is
# their mean. A recent window (not all-time) so the estimate adapts to changing
# network conditions.
_HISTORY_LEN = 10

_FILENAME = "connect-durations.json"


def state_dir() -> Path:
    """Resolve the directory holding fvpnctl's persistent state.

    Order: ``$FVPNCTL_STATE_DIR`` (explicit override; used by the tests), then
    ``$XDG_STATE_HOME/fvpnctl``, else ``~/.local/state/fvpnctl``.
    """
    override = os.environ.get("FVPNCTL_STATE_DIR")
    if override:
        return Path(override).expanduser()
    xdg = os.environ.get("XDG_STATE_HOME")
    base = Path(xdg).expanduser() if xdg else Path.home() / ".local" / "state"
    return base / "fvpnctl"


def _path() -> Path:
    return state_dir() / _FILENAME


def load() -> dict[str, list]:
    """Load the per-profile duration history.

    :returns: the raw ``{profile: [seconds, ...]}`` mapping (``{}`` when no file
        exists yet — the normal first-run case).
    :raises ValueError: the file exists but is not valid JSON, or is valid JSON of
        the wrong shape (``json.JSONDecodeError`` is a ``ValueError`` subclass).
        Callers surface this rather than mask it.
    """
    try:
        raw = _path().read_text(encoding="utf-8")
    except FileNotFoundError:
        return {}
    data = json.loads(raw)
    if not isinstance(data, dict):
        raise ValueError(f"{_path()} is not a JSON object")
    return data


def average(profile: str) -> float | None:
    """Mean recorded connect duration for ``profile`` — the progress-bar ETA.

    :returns: the mean of the stored samples, or ``None`` when the profile has no
        usable history yet. Non-numeric stray entries are ignored defensively so a
        single bad value never breaks the estimate.
    :raises ValueError: if the underlying store is corrupt (propagated from
        :func:`load`).
    """
    samples = [float(x) for x in load().get(profile, []) if isinstance(x, (int, float))]
    if not samples:
        return None
    return sum(samples) / len(samples)


def record(profile: str, seconds: float) -> None:
    """Append one connect duration for ``profile`` and persist (keep last N).

    :raises OSError: if the store cannot be written (caller decides whether to
        surface or ignore — a failed write must never undo a successful connect).
    """
    try:
        data = load()
    except ValueError:
        # A corrupt history file is non-critical: reset rather than fail the
        # connect that just succeeded. This measurement re-creates a valid file.
        data = {}
    samples = data.get(profile)
    if not isinstance(samples, list):
        samples = []
    samples.append(round(float(seconds), 1))
    data[profile] = samples[-_HISTORY_LEN:]
    save(data)


def save(data: dict) -> None:
    """Atomically write the history JSON (``mkdir -p`` + temp file + rename).

    The temp-file-then-``replace`` keeps the file readable at all times: a crash
    mid-write leaves the previous good file intact rather than a truncated one.
    """
    path = _path()
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(data), encoding="utf-8")
    tmp.replace(path)
