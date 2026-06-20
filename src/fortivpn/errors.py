"""Exception hierarchy for fortivpn.

Why this module exists
----------------------
Every external failure (FortiClient not running, a CDP evaluation throwing, the
Keychain refusing, a tunnel that never negotiates) must surface as a *specific*
exception that the CLI can translate into an actionable stderr message and a
distinct process exit code — never a bare traceback and never a silently
swallowed error (see the project error-handling policy and design spec section 6).

How it is used
--------------
Each subclass carries an integer class attribute ``exit_code``. The top-level CLI
handler does, in effect::

    try:
        ...
    except FortiError as e:
        print(e, file=sys.stderr)
        sys.exit(e.exit_code)

So the *type* selects the exit code and the *message* (passed to ``__init__`` as
usual) is what the user sees. Library callers can instead catch the precise
subclass and react programmatically. The exit-code values match design spec
section 5; do not change them without updating the CLI contract.
"""


class FortiError(Exception):
    """Base class for every error raised by fortivpn.

    Why: gives callers (and the CLI) a single type to catch for *expected*,
    user-facing failures, keeping them distinct from genuine bugs (which should
    propagate as ordinary exceptions). Raised directly only as a last resort
    when no more specific subclass applies; in that case the CLI exits ``1``.
    """

    exit_code: int = 1


class NotRunningError(FortiError):
    """FortiClient is not reachable over the CDP debugging port.

    Why / when raised: ``CDPSession.connect()`` raises this when the debugging
    port is unreachable or exposes no debuggable ``page`` target — i.e. the user
    has not launched FortiClient with ``--remote-debugging-port``, or launched it
    on a different port. The message should tell them how to start it headless +
    debug. Exits ``3`` so scripts can distinguish "VPN client absent" from other
    failures.
    """

    exit_code: int = 3


class KeychainError(FortiError):
    """Reading the VPN password from the macOS login Keychain failed.

    Why / when raised: ``keychain.get_password()`` raises this when
    ``security find-generic-password`` exits non-zero — typically the
    ``forti-vpn-<profile>`` item does not exist or access was denied. The message
    should guide the user on adding the Keychain item. Exits ``4``. The secret
    itself is never included in the error.
    """

    exit_code: int = 4


class UnsupportedError(FortiError):
    """The requested operation is intentionally out of scope for v1.

    Why / when raised: guards the validated-only happy path. ``connect()`` raises
    this for SSL profiles (untested in the spike) and when the daemon enters the
    ``XAUTH`` state ("2FA not supported in v1"). It signals a deliberate
    limitation, not a bug, so the user is not misled into retrying. Exits ``5``.
    """

    exit_code: int = 5


class ConnectFailed(FortiError):
    """The tunnel started negotiating but then failed.

    Why / when raised: ``connect()`` raises this when the connection state
    reaches a non-zero (negotiating/connected-ish) value and then drops back to
    ``0`` — an active rejection by the gateway (e.g. bad credentials, policy
    denial) as opposed to a silent never-started case (see ConnectTimeout).
    Exits ``6`` (shared with CDPEvaluateError: both mean "the operation was
    attempted and the far side reported failure").
    """

    exit_code: int = 6


class CDPEvaluateError(FortiError):
    """A ``Runtime.evaluate`` call returned ``exceptionDetails``.

    Why / when raised: ``CDPSession.evaluate()`` raises this when the FortiClient
    renderer reports a JavaScript exception while running a ``window.guimessenger``
    call — meaning the request reached FortiClient but the in-page API rejected or
    threw on it. Distinguishing this from transport-level failures keeps "the VPN
    client errored" separate from "I couldn't reach the VPN client". Exits ``6``.
    """

    exit_code: int = 6


class ConnectTimeout(FortiError):
    """The tunnel did not reach CONNECTED within the allotted time.

    Why / when raised: ``connect(wait=True)`` raises this when the timeout elapses
    before ``ipsec_state == 2`` — **including the case where the state never left
    ``0``** (a silent rejection where the daemon never even begins negotiating;
    see SPIKE.md / design spec section 4.2). Kept separate from ConnectFailed so
    callers can distinguish "negotiated then failed" from "never moved" and retry
    accordingly. Exits ``7``.
    """

    exit_code: int = 7
