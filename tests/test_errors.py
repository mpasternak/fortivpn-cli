"""Tests for the fortivpn exception hierarchy.

These pin down the two things the CLI depends on: that every error is a
``FortiError`` (so a single ``except`` catches them all) and that each type maps
to the documented exit code (design spec section 5). They also confirm an
instance still behaves like a normal exception carrying its message.
"""

import pytest

from fortivpn.errors import (
    CDPEvaluateError,
    ConnectFailed,
    ConnectTimeout,
    FortiClientNotFoundError,
    FortiError,
    KeychainError,
    NotRunningError,
    UnsupportedError,
)

ALL_SUBCLASSES = [
    NotRunningError,
    CDPEvaluateError,
    UnsupportedError,
    KeychainError,
    ConnectFailed,
    ConnectTimeout,
    FortiClientNotFoundError,
]

# The exit-code contract from the design spec (section 5).
EXPECTED_EXIT_CODES = {
    FortiError: 1,
    NotRunningError: 3,
    KeychainError: 4,
    UnsupportedError: 5,
    ConnectFailed: 6,
    CDPEvaluateError: 6,
    ConnectTimeout: 7,
    FortiClientNotFoundError: 8,
}


@pytest.mark.parametrize("cls", ALL_SUBCLASSES)
def test_subclasses_inherit_from_base(cls):
    assert issubclass(cls, FortiError)
    assert issubclass(cls, Exception)


def test_base_is_an_exception():
    assert issubclass(FortiError, Exception)


@pytest.mark.parametrize("cls, expected", EXPECTED_EXIT_CODES.items())
def test_exit_code_matches_contract(cls, expected):
    # The attribute must be readable both on the class and on an instance,
    # because the CLI reads it off the caught instance (`e.exit_code`).
    assert cls.exit_code == expected
    assert cls("boom").exit_code == expected


@pytest.mark.parametrize("cls", [FortiError, *ALL_SUBCLASSES])
def test_instance_carries_message(cls):
    err = cls("something went wrong")
    assert str(err) == "something went wrong"
    assert err.args == ("something went wrong",)


def test_exit_codes_have_expected_distinct_values():
    # ConnectFailed and CDPEvaluateError deliberately share 6; everything else
    # is distinct. Guard against an accidental future collision.
    codes = {cls: cls.exit_code for cls in EXPECTED_EXIT_CODES}
    assert codes[ConnectFailed] == codes[CDPEvaluateError] == 6
    non_six = [c for cls, c in codes.items() if c != 6]
    assert len(non_six) == len(set(non_six))
