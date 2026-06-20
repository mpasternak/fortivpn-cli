"""Attended live integration test against a real headless + debug FortiClient.

WARNING — this test BREAKS THE LIVE TUNNEL. It connects, reads status, and then
disconnects a real IPsec profile against an actual FortiClient instance launched
with ``--hide-gui --remote-debugging-port``. It is *attended*: run it knowingly,
on purpose, when you are willing to have your VPN connection torn down.

For that reason it is skipped by default. It is collected by pytest like any
other test, but the module-level ``skipif`` turns every test here into a SKIP
unless you opt in explicitly::

    FORTI_LIVE=1 FORTI_PROFILE=office FORTI_USER=alice uv run pytest tests/manual/test_live.py

Configuration (read from the environment, *not* at import time):

- ``FORTI_LIVE=1``     — required gate; without it the whole module skips.
- ``FORTI_PROFILE``    — the IPsec profile name to exercise (required when live).
- ``FORTI_USER``       — the VPN username (optional; defaults to the profile's
                         stored username, with the password coming from the
                         ``forti-vpn-<profile>`` Keychain item).
- ``FORTI_CDP_PORT``   — CDP debug port (optional; defaults to 9222).

By design this module performs **no network or CDP I/O at import time** — only
``os.environ`` lookups — so importing it (and collecting it in the normal suite)
is safe and always results in a clean SKIP when nothing live is configured.
"""

import os

import pytest

from fortivpn.cdp import CDPSession
from fortivpn.controller import FortiVPN

pytestmark = pytest.mark.skipif(
    os.environ.get("FORTI_LIVE") != "1",
    reason="attended live test; set FORTI_LIVE=1 (breaks the tunnel)",
)


def _port() -> int:
    """CDP debug port from ``FORTI_CDP_PORT`` (default 9222)."""
    return int(os.environ.get("FORTI_CDP_PORT", "9222"))


def _profile() -> str:
    """Required IPsec profile name from ``FORTI_PROFILE`` when running live."""
    profile = os.environ.get("FORTI_PROFILE")
    if not profile:
        pytest.skip("set FORTI_PROFILE to the IPsec profile name to exercise")
    return profile


def test_connect_status_disconnect():
    """Exercise the full connect -> status -> disconnect cycle on a live tunnel.

    Uses the library directly (``CDPSession`` + ``FortiVPN``), the same path the
    CLI drives. Connects the configured profile, asserts it reaches CONNECTED and
    reports a tunnel IP, then always disconnects in a ``finally`` so the test does
    not leave a half-open tunnel behind even if an assertion fails.
    """
    profile = _profile()
    username = os.environ.get("FORTI_USER")  # None -> use the profile's stored username

    with CDPSession(port=_port()) as session:
        vpn = FortiVPN(session)

        # connect (password comes from the forti-vpn-<profile> Keychain item).
        state = vpn.connect(profile, username=username, wait=True)
        try:
            assert state.ipsec_state == 2, f"expected CONNECTED, got {state.state_label}"

            # status: state() should also report CONNECTED, with a tunnel IP.
            live = vpn.state()
            assert live.ipsec_state == 2, f"expected CONNECTED, got {live.state_label}"

            ip = vpn.connection_ip(live.name, "ipsec")
            assert ip.get("vpn_ip"), f"no vpn_ip reported: {ip!r}"
        finally:
            # Always tear the tunnel down, even on assertion failure.
            vpn.disconnect(profile)

        # After disconnect the tunnel should be back to DISCONNECTED.
        final = vpn.state()
        assert final.ipsec_state == 0, f"expected DISCONNECTED, got {final.state_label}"
