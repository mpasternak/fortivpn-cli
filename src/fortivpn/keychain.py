"""Read the VPN password from the macOS login Keychain.

How
---
The single public function shells out to Apple's ``security`` tool::

    security find-generic-password -s forti-vpn-<profile> -a <username> -w

via ``subprocess.run`` with ``capture_output=True`` and ``text=True`` and
**without** a shell (``args`` is a list, never a string), so the profile and
username can never be interpreted as shell syntax. The ``-w`` flag makes
``security`` print *only* the password to stdout, which it terminates with a
single newline; we strip exactly that newline (see ``rstrip("\\n")`` below).

Why the ``forti-vpn-<profile>`` service-name convention
-------------------------------------------------------
This naming is inherited verbatim from the sibling AppleScript repository that
drove FortiClient before this tool existed (confirmed working — see docs/how-it-works.md
section 6). Keeping the same generic-password *service* name (``-s``) and
*account* name (``-a``) means every Keychain item a user already created for the
old tool keeps working here with no re-entry — they are the same item.

Why the secret is never logged
------------------------------
A VPN password is a long-lived secret. It is returned to the caller and nowhere
else: it is never printed, never logged, and — crucially — never placed in an
exception message. The failure path raises ``KeychainError`` built purely from
the *non-secret* identifiers (profile and username), so a stray traceback or log
line can never expose the password. The password also never reaches argv or the
environment; only ``security`` itself ever holds it.
"""

import subprocess

from fortivpn.errors import KeychainError


def get_password(profile: str, username: str) -> str:
    """Return the VPN password stored under ``forti-vpn-<profile>`` for ``username``.

    Runs ``security find-generic-password -s forti-vpn-<profile> -a <username>
    -w`` (no shell) and returns its stdout with the single trailing newline that
    ``security`` appends removed. ``rstrip("\\n")`` is used deliberately instead
    of a bare ``strip()`` so a password that legitimately ends in spaces (or
    other whitespace) survives unchanged.

    Raises
    ------
    KeychainError
        If ``security`` exits non-zero — typically the item does not exist or
        access was denied. The message names the missing item and tells the user
        how to add it, e.g. ``security add-generic-password -s forti-vpn-<profile>
        -a <username> -w``. The error never contains the password (nor any
        captured stdout/stderr), so it is safe to print or log.
    """
    service = f"forti-vpn-{profile}"
    result = subprocess.run(
        ["security", "find-generic-password", "-s", service, "-a", username, "-w"],
        capture_output=True,
        text=True,
    )

    if result.returncode != 0:
        # Build the message from non-secret identifiers only; never include
        # result.stdout/stderr, which could echo sensitive material.
        raise KeychainError(
            f"No Keychain item '{service}' for account '{username}'. "
            f"Add it with: security add-generic-password "
            f"-s {service} -a {username} -w"
        )

    # security terminates the password with exactly one newline under -w. Strip
    # only that newline so trailing spaces in the password are preserved.
    return result.stdout.rstrip("\n")
