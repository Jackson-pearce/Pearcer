# Pearcer - Professional Packet Analyzer

Pearcer is a **free and open-source (GPLv3)** professional network packet analysis tool. It combines the deep visibility of Wireshark with modern, real-time cyber threat detection and active pentesting capabilities.

**License**: GNU General Public License v3.0
**Author**: Jackson Pearce


## 🚀 Key Features

### 📡 Live Packet Capture
- **Multi-interface support**: Capture from Ethernet, Wi-Fi, Loopback, and more.
- **Android Support**: Capture traffic directly from connected Android devices via ADB (`tcpdump`).
- **Promiscuous Mode**: Capture all traffic on the wire.
- **Real-time Parsing**: Instant protocol decoding (TCP, UDP, HTTP, DNS, TLS, QUIC, etc.).
- **Deep Packet Inspection**: Full recursive dissection of every protocol layer (Ethernet -> IP -> TCP -> Payload), viewable in a detailed tree structure.

### 🛡️ Advanced Security Analysis
- **Threat Detection**: Automatically identifies:
  - 🔴 **Real Attacks**: SQL Injection, XSS, C2 Beaconing, Malware, Spoofing (ARP/DNS).
  - 🟠 **Suspicious Activity**: High traffic volume, weak TLS, large outbound transfers, plain Base64.
- **Strict Coloring**: 
    - **Red**: Reserved for critical, confirmed attacks/exploits.
    - **Orange**: Suspicious anomalies requiring investigation.
- **Vulnerability Scanner**: Integrated NVD CVE lookup and rudimentary port scanner.

### 🛠️ Utilities
- **Decoder Tool**: Built-in tab for Base64, URL, Hex, HTML, and Binary encoding/decoding.
- **Process Mapping**: Correlates local traffic to running processes (`chrome.exe`, `python`, etc.).

### ⚔️ Active Attack Suite
Turn Pearcer from a passive analyzer into an active pentesting tool:
- **Packet Replayer**: Right-click any packet -> "Edit & Resend". Modify IP, Ports, and Payload on the fly.
- **WiFi Monitor & Deauth**: 
    - **Monitor Mode**: Toggle monitor mode (Cross-platform: `WlanHelper` on Windows, native `iwconfig` on Linux).
    - **Deauth Flood**: Flood dissociation frames to kick users offline.
- **Professional UI**: 
    - Wireshark-like 3-pane layout (List, Details, Hex).
    - Simplified columns (merged Host/Dest).
    - Dark Mode.

## 📦 Requirements
- Windows (Primary support) or Linux (Root required)
- Python 3.8+
- [Npcap](https://npcap.com/) (Required for Windows sniffing)
- ADB (for Android capture)

## 🔧 Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/H4CKRD/pearcer.git
   cd pearcer
   ```

2. **Create a virtual environment (optional)**:
   ```bash
   python -m venv .venv
   # Windows:
   .venv\Scripts\Activate.ps1
   # Linux/Mac:
   source .venv/bin/activate
   ```

3. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```
   *Note: On Windows, ensure you have Npcap installed for packet capture.*

## 🏃 Usage
Run the main script:
```bash
python pearcer.py
```
- **Live Capture**: Select your interface from the list.
- **Android Capture**: Go to `Capture -> From Android Device...`.
- **Decoder**: Use the `Decoder` tab for crypto operations.
- **Analytics**: Switch to the Analytics tab for graphs.

## 🤝 Contributing
Contributions are welcome! Please feel free to open issues or submit pull requests.

## 📄 License
GPL-3.0# Pearcer
# Pearcer
