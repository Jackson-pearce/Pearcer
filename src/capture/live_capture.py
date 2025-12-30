"""Live packet capture backend for pearcer.

This module will provide abstractions over platform-specific capture
libraries (e.g., libpcap/Npcap via scapy or pyshark) and expose a
unified async/iterator-style API to the rest of the app.
"""

from typing import Iterable, Protocol


class Packet(Protocol):
    """Protocol representing a captured packet.

    Concrete implementations will wrap library-specific packet objects.
    """

    timestamp: float


class CaptureSource(Protocol):
    """Abstract interface for a live capture source (e.g., eth0, Wi‑Fi, etc.)."""

    name: str

    def packets(self) -> Iterable[Packet]:
        """Iterate over captured packets.

        Implementations should be efficient and may yield packets
        indefinitely until capture is stopped.
        """


def open_live_capture(interface: str) -> CaptureSource:
    """Open a live capture on the given network interface.

    This is a placeholder; the real implementation will plug into a
    capture backend and support options like custom speeds and filters.
    """

    raise NotImplementedError("live capture backend not implemented yet")
