# WARP.md

This file provides guidance to WARP (warp.dev) when working with code in this repository.

## Project overview

pearcer is a high-performance, cross-platform network packet analysis tool inspired by Wireshark but focused on speed and modern workflows. It targets both live capture and offline analysis, with a professional multi-pane GUI (packet list, details, hex view, statistics) and security-focused features such as protocol-aware filtering and attack/anomaly detection.

The repository currently contains:
- A monolithic prototype implementation in `pearcer.py` with a working Tk-based GUI and CLI fallback.
- A newer, modular package scaffold under `src/pearcer/` that will house the long-term architecture (capture backends, analysis, GUI, protocol helpers).
- A configuration file `pearcer_config.json` used at runtime by `pearcer.py`.
- An empty `tests/` directory reserved for future automated tests.

## Commands & workflows

### Python environment

- The repo is Python-based and includes a `.venv` directory at the project root.
- In PowerShell, you can activate that environment with:
  - `./.venv/Scripts/Activate.ps1`
- Use `python` from an activated virtual environment when running any commands below.

### Run the interactive analyzer (current implementation)

From the repository root:
- Start the analyzer (GUI when `tkinter` is available, otherwise CLI):
  - `python pearcer.py`

`pearcer.py` will:
- Load configuration from `pearcer_config.json` (or fall back to `DEFAULT_CONFIG` embedded in `pearcer.py`).
- Attempt to use Scapy for capture when available, otherwise fall back to raw sockets.
- Launch a rich Tk GUI when `tkinter` is importable; otherwise run a text-based CLI that prints live statistics and optionally saves a PCAP on exit.

### Tests, linting, and packaging

- As of now there is **no configured test runner**, **no lint/format tooling**, and **no packaging metadata** (`pyproject.toml`, `setup.cfg`, etc.) in the repo.
- The `tests/` directory is present but empty, so there are no commands for running a test suite or a single test yet.
- When adding a test framework (e.g., `pytest` or `unittest`) or linting tools, update this section with the exact commands (for example, how to run all tests vs. a single test file or test case).

## High-level architecture

### Legacy prototype vs. modular package

There are two parallel structures in this codebase:

1. **`pearcer.py` (legacy/prototype implementation)**
   - Contains a complete, working implementation of:
     - Interface discovery (Windows-specific via `netsh`, Unix via `fcntl`/raw sockets).
     - Live capture using Scapy when available, falling back to raw sockets.
     - Packet parsing (Ethernet, IPv4, TCP/UDP/ICMP/DCCP) using `struct` and `socket`.
     - Protocol classification (HTTP, TLS, QUIC, WebSocket, SIP, DNS, etc.).
     - Heuristic/rule-based attack detection (blacklist, thresholds, simple pattern matching).
     - Logging to console, log file, and in-memory PCAP buffer, with export to a `.pcap` file.
     - A Tkinter GUI with multiple tabs: Live Capture, Statistics, Visualization, and Settings.
     - A CLI mode (`cli_mode()`) used when the GUI stack is not available.
   - This file is currently the **only fully functional entrypoint** and is what `python pearcer.py` executes.

2. **`src/pearcer/` (emerging modular architecture)**
   - `src/pearcer/__init__.py` documents the intent of the package: live capture, offline analysis, protocol decoding, attack detection, and GUI.
   - `src/pearcer/__main__.py` defines `main()` and calls `run_gui()` from `pearcer.gui.app`. It is the intended future CLI entrypoint (`python -m pearcer`) once packaging is set up, but `run_gui()` is currently a stub.
   - `src/pearcer/gui/app.py` exports `run_gui()`, which currently only prints a placeholder message. Eventually this module should own all GUI-related setup (windows, views, themes, widgets) and talk to capture/analysis layers via well-defined APIs.
   - `src/pearcer/capture/live_capture.py` defines:
     - A `Packet` protocol (timestamped packet abstraction).
     - A `CaptureSource` protocol with a `packets()` iterator.
     - `open_live_capture(interface: str) -> CaptureSource`, which currently raises `NotImplementedError` and is the hook where Scapy/libpcap/Npcap or other backends should be wrapped.
   - `src/pearcer/analysis/filters.py` introduces:
     - A `Predicate` protocol (callable over `Packet`).
     - A stub `ip_equals(ip: str) -> Predicate` that always returns `False` for now.
   - `src/pearcer/analysis/detection.py` defines `detect_suspicious(packet: Packet) -> list[str]`, which is a stub and intended to house rule/heuristic IDs for anomalies or attacks.
   - `src/pearcer/protocols/__init__.py` exists as a placeholder namespace for future protocol-specific helpers and decoders.

**Guidance for future changes:**
- Treat `pearcer.py` as the current reference implementation for behavior (capture, parsing, detection, and GUI flows).
- New work should generally target the modular package under `src/pearcer/`:
  - Move reusable logic (capture, parsing, protocol detection, attack heuristics) out of `pearcer.py` into `src/pearcer/capture` and `src/pearcer/analysis` as focused, testable units.
  - Keep `src/pearcer/gui` responsible only for presentation and user interaction, depending on capture/analysis modules instead of duplicating logic.
- When moving behavior, keep `pearcer.py` functioning (or thin it into a small adapter) until the `src/pearcer` package is ready to be the primary entrypoint.

### Configuration and runtime behavior

- Runtime configuration is handled by `pearcer.py` via:
  - `DEFAULT_CONFIG` (embedded in code) and `pearcer_config.json` in the repo root.
  - Keys include interface selection, BPF-style filters, black/whitelists, attack thresholds, highlight colors, log/pcap filenames, capture speed, theme, and per-protocol enable flags.
- GUI elements (Treeviews, hex view, stats, etc.) rely on global variables set up in `pearcer.py` and updated by the packet capture thread and helper functions like `show_details()` and `update_stats_gui()`.
- Optional features (Bluetooth/USB capture, VoIP analysis, decryption, advanced visualizations) are currently implemented as placeholders that print or show installation instructions for additional libraries.

### Tests and quality gates

- The `tests/` directory is currently empty and there is no test configuration in the repo.
- When adding tests, prefer to:
  - Exercise the modular package under `src/pearcer/` (capture/analysis/protocol helpers) rather than the monolithic `pearcer.py` GUI.
  - Document the exact test command(s) you introduce in the **Commands & workflows** section above so future Warp instances can run them automatically.
