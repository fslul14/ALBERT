"""The test-suite safety nets themselves are active (no live hosts, DNS or APIs in tests)."""

import socket

import pytest


def test_non_loopback_name_resolution_is_blocked() -> None:
    with pytest.raises(OSError, match="must not touch live hosts"):
        socket.getaddrinfo("example.com", 443)


def test_loopback_resolution_still_works() -> None:
    assert socket.getaddrinfo("localhost", 443)
