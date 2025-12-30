"""Filtering primitives for pearcer.

This module will eventually implement a powerful filter language to
select packets by IP, port, protocol, payload patterns, and security
indicators.
"""

from typing import Protocol

from ..capture.live_capture import Packet


class Predicate(Protocol):
    """Packet predicate used for filtering."""

    def __call__(self, packet: Packet) -> bool:  # pragma: no cover - placeholder
        ...


def ip_equals(ip: str) -> Predicate:
    """Return a predicate that matches packets with the given IP.

    Placeholder implementation for now.
    """

    def _predicate(packet: Packet) -> bool:
        return False

    return _predicate
