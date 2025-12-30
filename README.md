# pearcer

Pearcer is a high-performance, cross-platform network packet analysis tool inspired by Wireshark but focused on extreme speed and modern workflows.

## Goals
- Capture and analyze network packets faster than Wireshark on typical workloads.
- Provide a professional, customizable GUI comparable to Wireshark.
- Support both live capture and offline analysis across multiple interfaces (Ethernet, Wi‑Fi, Bluetooth, USB CDC, etc.).
- Enable deep security analysis: detect malicious activity, identify vulnerabilities, and analyze potential exploits.

## Core Features (Planned)
- **Live Capture & Offline Analysis**
  - Real-time capture from multiple interfaces.
  - Load and analyze saved capture files.
- **Protocol Support**
  - Common protocols: TCP, UDP, DCCP, TLS, HTTP, HTTP/2, QUIC, WebSocket, SIP, USB CDC, and more.
- **Powerful Filtering**
  - Advanced filter syntax for IPs, ports, protocols, payload patterns, and security indicators.
  - Quick filters for common tasks (e.g., show only HTTP, show only errors).
- **Attack & Anomaly Detection**
  - Heuristics and rule-based detection for suspicious flows.
  - Highlighting and tagging of potential attacks or misconfigurations.
- **GUI & UX**
  - Professional multi-pane layout (packet list, details, hex view, statistics).
  - Coloring rules, customizable themes, and layout presets.
  - Customizable logos/widgets (e.g., weather, calculator) for dashboard-style views.
- **Security & Diagnostics Use Cases**
  - Capturing unencrypted data (passwords, logins) during authorized security reviews.
  - Diagnosing network connectivity and performance problems.

## Tech Stack (Initial Plan)
- **Language:** Python (for rapid development and rich ecosystem).
- **Packet capture backend:** libraries such as `scapy`, `pyshark`, or a thin wrapper over `libpcap`/`Npcap`.
- **GUI:** Qt-based toolkit (e.g., PySide6/PyQt6) for a native-feeling, cross-platform desktop UI.

## Project Layout
- `src/pearcer/`
  - `capture/` – live capture and offline parsing.
  - `analysis/` – filtering, statistics, and detection logic.
  - `gui/` – main application windows, views, themes, and widgets.
  - `protocols/` – protocol-specific helpers and decoders.
- `tests/` – automated tests.

This is an early scaffold; functionality will be added iteratively, starting with basic live capture and a minimal GUI, then expanding toward the full feature set described above.