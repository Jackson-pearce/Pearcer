"""Attack and anomaly detection primitives for pearcer.

This module will house heuristics and rule-based detectors to spot
suspicious activity (e.g., port scans, brute-force attempts, protocol
misuse) and surface them to the GUI via highlighting and alerts.
"""

from ..capture.live_capture import Packet


def detect_suspicious(packet: Packet) -> list[str]:
    """Analyze a packet and return a list of detection rule IDs.

    This is a stub; real logic will be added later.
    """

    return []
