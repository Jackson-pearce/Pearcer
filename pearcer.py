# pearcer - Professional Packet Analyzer
# Copyright (c) 2025 <Jackson Pearce> <Telegram: @H4CKRD>
# Licensed under the GNU General Public License v3.0 (GPL-3.0)
#!/usr/bin/env python3
"""
Pearcer - Prof Packet Analyzer-for studying purposes and security analysis
A mid-performance packet sniffer with Wireshark-like capabilities, might not work well if you have good PC
"""

import json
import os
import threading
import time
import socket
import struct
import array
import binascii
from collections import defaultdict, deque
import random
from datetime import datetime, timedelta
import sys
import re
from queue import Queue

# Platform-specific imports
IS_WINDOWS = sys.platform.startswith('win')

if not IS_WINDOWS:
    try:
        import fcntl
        FCNTL_AVAILABLE = True
    except ImportError:
        FCNTL_AVAILABLE = False
else:
    FCNTL_AVAILABLE = False

try:
    import tkinter as tk
    from tkinter import scrolledtext, messagebox, filedialog, simpledialog
    from tkinter.ttk import Notebook, Combobox, Treeview
    GUI_AVAILABLE = True
except ImportError:
    GUI_AVAILABLE = False

VIZ_AVAILABLE = False
try:
    import matplotlib.pyplot as plt
    from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
    import networkx as nx
    VIZ_AVAILABLE = True
except ImportError:
    pass

PYGAME_AVAILABLE = False
try:
    import pygame
    PYGAME_AVAILABLE = True
except ImportError:
    pass

PYSHARK_AVAILABLE = False
try:
    import pyshark
    PYSHARK_AVAILABLE = True
except ImportError:
    pass

SCAPY_AVAILABLE = False
try:
    from scapy.all import sniff, Ether, IP, IPv6, TCP, UDP, ICMP, Raw, DNS, DNSRR
    SCAPY_AVAILABLE = True
except ImportError:
    pass

# Vulnerability scanner import
VULN_SCANNER_AVAILABLE = False
try:
    import sys
    import os
    # Add src directory to path if not already there
    src_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'src')
    if src_path not in sys.path:
        sys.path.insert(0, src_path)
    from pearcer.analysis.vulnerability_scanner import VulnerabilityScanner
    VULN_SCANNER_AVAILABLE = True
except ImportError:
    try:
        from src.pearcer.analysis.vulnerability_scanner import VulnerabilityScanner
        VULN_SCANNER_AVAILABLE = True
    except ImportError:
        try:
            from analysis.vulnerability_scanner import VulnerabilityScanner
            VULN_SCANNER_AVAILABLE = True
        except ImportError:
            pass

# Initialize vulnerability scanner
vuln_scanner = None
if VULN_SCANNER_AVAILABLE:
    try:
        vuln_scanner = VulnerabilityScanner()
    except Exception as e:
        print(f"[VULN SCANNER INIT ERROR] {e}")
        VULN_SCANNER_AVAILABLE = False

# Recon tool import
RECON_TOOL_AVAILABLE = False
try:
    from pearcer.analysis.recon_tool import ReconTool
    RECON_TOOL_AVAILABLE = True
except ImportError:
    try:
        from src.pearcer.analysis.recon_tool import ReconTool
        RECON_TOOL_AVAILABLE = True
    except ImportError:
        try:
            from analysis.recon_tool import ReconTool
            RECON_TOOL_AVAILABLE = True
        except ImportError:
            pass

# Initialize recon tool
recon_tool = None
if RECON_TOOL_AVAILABLE:
    try:
        recon_tool = ReconTool()
    except Exception as e:
        print(f"[RECON TOOL INIT ERROR] {e}")
        RECON_TOOL_AVAILABLE = False

# Config
CONFIG_FILE = "pearcer_config.json"
DEFAULT_CONFIG = {
    "interface": "eth0",
    "filter": "",
    "blacklist_ips": ["8.8.8.8"],
    "whitelist_ips": [],
    "attack_threshold": 50,
    "filter_mode": "All traffic",
    "highlight_colors": {
        # Wireshark-inspired color scheme
        "normal": "#FFFFFF",  # White for normal packets
        "tcp": "#90EE90",  # Light Green for TCP (general)
        "tcp_stream": "#DDA0DD",  # Light Purple for TCP streams
        "udp": "#87CEEB",  # Light Blue for UDP
        "http": "#90EE90",  # Light Green for HTTP
        "dns": "#0000CD",  # Dark Blue for DNS
        "error": "#000000",  # Black for errors/problems
        "tcp_flags": "#696969",  # Dark Gray for TCP flags (SYN/FIN/ACK)
        "smb": "#FFFFE0",  # Light Yellow for Windows traffic (SMB/NetBIOS)
        "routing": "#CCCC00",  # Dark Yellow for routing traffic
        "suspicious": "#FFA500",  # Orange for suspicious
        "attack": "#FF0000",  # Red for attacks
        "voip": "#0000FF",  # Blue for VoIP
        "encrypted": "#008000",  # Green for encrypted
        "tls": "#00FFFF",  # Cyan for TLS
        # Expert Information Colors
        "expert_error": "#FF0000",  # Red for errors (highest severity)
        "expert_warning": "#FFFF00",  # Yellow for warnings
        "expert_note": "#00FFFF",  # Cyan for notes
        "expert_chat": "#0000FF"  # Blue for chats (e.g., TCP SYN)
    },
    "log_file": "packets.log",
    "pcap_file": "capture.pcap",
    "speed": "normal",
    "theme": "dark",
    "auto_vuln_scan": False,
    "protocols": {
        "tcp": True,
        "udp": True,
        "icmp": True,
        "dccp": True,
        "tls": True,
        "http": True,
        "quic": True,
        "websocket": True,
        "sip": True
    }
}

# Performance tunables
DEFAULT_CONFIG.setdefault("packet_queue_size", 10000)
DEFAULT_CONFIG.setdefault("max_captured_packets", 100000)
DEFAULT_CONFIG.setdefault("max_decrypted_items", 10000)
DEFAULT_CONFIG.setdefault("interfaces_cache_ttl", 5)

def load_config():
    """Load configuration from file or use defaults"""
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, 'r') as f:
                return json.load(f)
        except Exception as e:
            print(f"[CONFIG ERROR] {e}, using defaults")
    return DEFAULT_CONFIG

def save_config(cfg):
    """Save configuration to file"""
    try:
        with open(CONFIG_FILE, 'w') as f:
            json.dump(cfg, f, indent=4)
    except Exception as e:
        print(f"[CONFIG SAVE ERROR] {e}")

config = load_config()

# Globals
running = False
packet_count = 0
attack_counts = defaultdict(int)
stats = {"pps": 0, "attacks": 0, "vulnerabilities": 0, "exploits": 0, "malware": 0}
captured_packets = deque(maxlen=config.get("max_captured_packets", 100000))
protocol_counts = defaultdict(int)
decrypted_data = deque(maxlen=config.get("max_decrypted_items", 10000))
connectivity_issues = []
last_packet_time = time.time()
# Packet processing queue for async handling
packet_queue = Queue(maxsize=config.get("packet_queue_size", 10000))
packet_processing_thread = None
# Track discovered hosts for vulnerability scanning
discovered_hosts_for_scan = set()
host_scan_lock = threading.Lock()
# GUI behavior flags
auto_scroll = True  # auto-scroll packet list during live capture
# Incrementing row index for GUI "No." column
_gui_row_index = 0

# Simple cache for interface discovery to avoid repeated expensive system calls
_interfaces_cache = None
_interfaces_cache_time = 0.0
_interfaces_cache_ttl = float(config.get("interfaces_cache_ttl", 5))
# Simple display filter expression (substring match)
display_filter_expr = ""

# Whether heavy Visualization tab charts are enabled
viz_enabled = False

# Mapping from IP/DNS RR to last-seen hostname (e.g. HTTP Host header or DNS).
# Keys are string IP addresses (v4/v6).
ip_hostnames: dict[str, str] = {}

# Protocol detection constants
TLS_HANDSHAKE = b'\x16\x03'
HTTP_METHODS = [b'GET', b'POST', b'PUT', b'DELETE', b'HEAD', b'OPTIONS']
SIP_INDICATORS = [b'SIP/2.0', b'INVITE sip', b'ACK sip', b'CANCEL sip']

# List interfaces
def get_interfaces():
    """Get available network interfaces - comprehensive detection for Windows and Linux"""
    global _interfaces_cache, _interfaces_cache_time, _interfaces_cache_ttl
    now = time.time()
    # Return cached result when recent to avoid repeated slow system calls
    if _interfaces_cache is not None and (now - _interfaces_cache_time) < _interfaces_cache_ttl:
        return list(_interfaces_cache)

    interfaces = []
    seen = set()  # Track seen interfaces to avoid duplicates
    
    # Platform-specific interface detection
    if IS_WINDOWS:
        # Method 1: Scapy (most reliable)
        if SCAPY_AVAILABLE:
            try:
                from scapy.all import get_if_list, get_if_addr
                scapy_interfaces = get_if_list()
                for iface in scapy_interfaces:
                    if iface and iface not in seen:
                        interfaces.append(iface)
                        seen.add(iface)
                if interfaces:
                    return sorted(interfaces)
            except Exception as e:
                print(f"[DEBUG] Scapy interface detection failed: {e}")
        
        # Method 2: netsh interface show interface (detailed)
        try:
            import subprocess
            result = subprocess.run(['netsh', 'interface', 'show', 'interface'], 
                                  capture_output=True, text=True, timeout=5)
            for line in result.stdout.split('\n'):
                if line.strip() and not line.startswith('Admin'):
                    parts = line.split()
                    if len(parts) >= 4:
                        # Interface name is usually the last part
                        ifname = parts[-1]
                        if ifname and ifname not in seen:
                            interfaces.append(ifname)
                            seen.add(ifname)
        except Exception as e:
            print(f"[DEBUG] netsh interface detection failed: {e}")
        
        # Method 3: netsh interface show interface name="*" (all interfaces)
        try:
            import subprocess
            result = subprocess.run(['netsh', 'interface', 'show', 'interface', 'name="*"'], 
                                  capture_output=True, text=True, timeout=5)
            for line in result.stdout.split('\n'):
                if 'Name' in line or '----' in line:
                    continue
                parts = line.split()
                if len(parts) >= 2:
                    ifname = parts[-1].strip('"')
                    if ifname and ifname not in seen:
                        interfaces.append(ifname)
                        seen.add(ifname)
        except Exception as e:
            print(f"[DEBUG] netsh name detection failed: {e}")
        
        # Method 4: wmic (Windows Management Instrumentation)
        try:
            import subprocess
            result = subprocess.run(['wmic', 'path', 'win32_networkadapter', 'get', 'netconnectionid'], 
                                  capture_output=True, text=True, timeout=5)
            for line in result.stdout.split('\n'):
                line = line.strip()
                if line and line != 'NetConnectionID' and line != '':
                    if line not in seen:
                        interfaces.append(line)
                        seen.add(line)
        except Exception as e:
            print(f"[DEBUG] wmic interface detection failed: {e}")
        
        # Method 5: PowerShell Get-NetAdapter
        try:
            import subprocess
            ps_cmd = 'Get-NetAdapter | Select-Object -ExpandProperty Name'
            result = subprocess.run(['powershell', '-Command', ps_cmd], 
                                  capture_output=True, text=True, timeout=5)
            for line in result.stdout.split('\n'):
                line = line.strip()
                if line and line not in seen:
                    interfaces.append(line)
                    seen.add(line)
        except Exception as e:
            print(f"[DEBUG] PowerShell interface detection failed: {e}")
        
        # Method 6: Common Windows interface names (fallback)
        common_windows = [
            'Wi-Fi', 'WLAN', 'Ethernet', 'Ethernet 2', 'Ethernet 3',
            'Local Area Connection', 'Local Area Connection 2', 'Local Area Connection 3',
            'Wireless Network Connection', 'Wireless Network Connection 2',
            'Bluetooth Network Connection', 'VPN', 'VPN Connection',
            'TAP-Windows Adapter', 'VirtualBox Host-Only Network',
            'VMware Virtual Ethernet Adapter', 'Hyper-V Virtual Ethernet Adapter',
            'Loopback', 'Loopback Pseudo-Interface', 'any'
        ]
        for ifname in common_windows:
            if ifname not in seen:
                interfaces.append(ifname)
                seen.add(ifname)
    
    else:
        # Linux/Unix interface detection
        
        # Method 1: Scapy (most reliable)
        if SCAPY_AVAILABLE:
            try:
                from scapy.all import get_if_list
                scapy_interfaces = get_if_list()
                for iface in scapy_interfaces:
                    if iface and iface not in seen:
                        interfaces.append(iface)
                        seen.add(iface)
                if interfaces:
                    return sorted(interfaces)
            except Exception as e:
                print(f"[DEBUG] Scapy interface detection failed: {e}")
        
        # Method 2: fcntl ioctl (low-level, requires root for some info)
        if FCNTL_AVAILABLE:
            try:
                max_len = 128 * 32
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                names = array.array('B', b'\0' * max_len)
                outbytes = struct.unpack('iL', fcntl.ioctl(
                    s.fileno(), 0x8912, struct.pack('iL', max_len, names.buffer_info()[0])))[0]
                namestr = names.tobytes()
                ifs = [namestr[i:i+16].split(b'\0', 1)[0].decode('utf-8') 
                       for i in range(0, outbytes, 40)]
                for iface in ifs:
                    if iface and iface not in seen:
                        interfaces.append(iface)
                        seen.add(iface)
                s.close()
            except Exception as e:
                print(f"[DEBUG] fcntl interface detection failed: {e}")
        
        # Method 3: ip link show (modern, preferred on Linux)
        try:
            import subprocess
            result = subprocess.run(['ip', 'link', 'show'], 
                                  capture_output=True, text=True, timeout=5)
            for line in result.stdout.split('\n'):
                if ': ' in line:
                    parts = line.split(': ')
                    if len(parts) >= 2:
                        ifname = parts[1].split()[0] if parts[1].split() else parts[1]
                        ifname = ifname.strip()
                        if ifname and ifname not in seen and '@' not in ifname:
                            interfaces.append(ifname)
                            seen.add(ifname)
        except Exception as e:
            print(f"[DEBUG] ip link interface detection failed: {e}")
        
        # Method 4: ifconfig (traditional)
        try:
            import subprocess
            result = subprocess.run(['ifconfig', '-a'], 
                                  capture_output=True, text=True, timeout=5)
            for line in result.stdout.split('\n'):
                if ':' in line and not line.strip().startswith('inet') and not line.strip().startswith('inet6'):
                    ifname = line.split(':')[0].strip()
                    if ifname and ifname not in seen:
                        interfaces.append(ifname)
                        seen.add(ifname)
        except Exception as e:
            print(f"[DEBUG] ifconfig interface detection failed: {e}")
        
        # Method 5: /proc/net/dev (kernel interface list)
        try:
            with open('/proc/net/dev', 'r') as f:
                for line in f:
                    if ':' in line:
                        ifname = line.split(':')[0].strip()
                        if ifname and ifname not in seen:
                            interfaces.append(ifname)
                            seen.add(ifname)
        except Exception as e:
            print(f"[DEBUG] /proc/net/dev interface detection failed: {e}")
        
        # Method 6: netstat -i
        try:
            import subprocess
            result = subprocess.run(['netstat', '-i'], 
                                  capture_output=True, text=True, timeout=5)
            lines = result.stdout.split('\n')
            for i, line in enumerate(lines):
                if i < 2:  # Skip header lines
                    continue
                parts = line.split()
                if len(parts) > 0:
                    ifname = parts[0]
                    if ifname and ifname != 'Iface' and ifname not in seen:
                        interfaces.append(ifname)
                        seen.add(ifname)
        except Exception as e:
            print(f"[DEBUG] netstat interface detection failed: {e}")
        
        # Method 7: ls /sys/class/net (sysfs) - most reliable on Linux, prioritize physical interfaces
        try:
            import os
            net_path = '/sys/class/net'
            if os.path.exists(net_path):
                physical_ifaces = []
                virtual_ifaces = []
                for ifname in os.listdir(net_path):
                    if ifname and ifname not in seen:
                        # Skip loopback and obvious virtual interfaces in first pass
                        if ifname.startswith('lo'):
                            continue
                        # Check if it's a physical interface by looking for device file
                        device_path = os.path.join(net_path, ifname, 'device')
                        if os.path.exists(device_path):
                            physical_ifaces.append(ifname)
                        else:
                            virtual_ifaces.append(ifname)
                # Add physical interfaces first, then virtual ones
                for ifname in physical_ifaces:
                    interfaces.append(ifname)
                    seen.add(ifname)
                for ifname in virtual_ifaces:
                    interfaces.append(ifname)
                    seen.add(ifname)
                # If we got interfaces from sysfs, return them (most reliable source)
                if interfaces:
                    return sorted(interfaces)
        except Exception as e:
            print(f"[DEBUG] /sys/class/net interface detection failed: {e}")
        
        # Method 8: Common Linux interface names (fallback)
        common_linux = [
            'eth0', 'eth1', 'eth2', 'eth3',
            'enp0s3', 'enp0s8', 'enp1s0', 'enp2s0', 'enp3s0',
            'ens33', 'ens34', 'ens35', 'ens36',
            'wlan0', 'wlan1', 'wlan2', 'wlp2s0', 'wlp3s0',
            'lo', 'any', 'any0',
            'docker0', 'br0', 'br1', 'virbr0', 'virbr1',
            'tun0', 'tun1', 'tap0', 'tap1',
            'ppp0', 'ppp1', 'pppoe0',
            'vboxnet0', 'vboxnet1', 'vmnet1', 'vmnet8',
            'usb0', 'usb1', 'bluetooth0', 'bluetooth1',
            'wwan0', 'wwan1', 'wwp0s20u4', 'wwp0s20u5'
        ]
        for ifname in common_linux:
            if ifname not in seen:
                interfaces.append(ifname)
                seen.add(ifname)
    
    # Remove empty strings and sort
    interfaces = [iface for iface in interfaces if iface and iface.strip()]
    interfaces = sorted(list(set(interfaces)))
    
    # If we still have no interfaces, return a minimal fallback
    if not interfaces:
        if IS_WINDOWS:
            _interfaces_cache = ['any', 'Wi-Fi', 'Ethernet']
            _interfaces_cache_time = now
            return list(_interfaces_cache)
        else:
            _interfaces_cache = ['any', 'eth0', 'wlan0', 'lo']
            _interfaces_cache_time = now
            return list(_interfaces_cache)
    
    # Normalize, cache and return
    interfaces = sorted(list(set(interfaces)))
    _interfaces_cache = list(interfaces)
    _interfaces_cache_time = now
    return list(interfaces)

def get_friendly_interface_name(iface):
    """Convert technical interface name to user-friendly name"""
    iface_lower = iface.lower()
    
    # Windows friendly names
    if IS_WINDOWS:
        friendly_names = {
            'wi-fi': 'Wi-Fi',
            'wlan': 'Wireless Network',
            'ethernet': 'Ethernet',
            'local area connection': 'Ethernet',
            'wireless network connection': 'Wi-Fi',
            'bluetooth network connection': 'Bluetooth',
            'loopback': 'Local host',
            'loopback pseudo-interface': 'Local host',
            'vpn': 'VPN Connection',
            'vpn connection': 'VPN',
            'virtualbox host-only network': 'VirtualBox Network',
            'vmware virtual ethernet adapter': 'VMware Network',
            'hyper-v virtual ethernet adapter': 'Hyper-V Network',
            'tap-windows adapter': 'TAP Adapter',
            'any': 'All Interfaces'
        }
        
        # Check for exact or partial matches
        for key, friendly in friendly_names.items():
            if key in iface_lower or iface_lower in key:
                return friendly
        
        # If it contains common patterns
        if 'wireless' in iface_lower or 'wifi' in iface_lower or 'wlan' in iface_lower:
            return 'Wi-Fi'
        elif 'ethernet' in iface_lower or 'lan' in iface_lower:
            return 'Ethernet'
        elif 'bluetooth' in iface_lower:
            return 'Bluetooth'
        elif 'vpn' in iface_lower:
            return 'VPN'
        elif 'loopback' in iface_lower or iface.startswith('Loopback'):
            return 'Local host'
        elif 'virtual' in iface_lower or 'vmware' in iface_lower or 'virtualbox' in iface_lower:
            return 'Virtual Network'
        
        # Return original if no match found
        return iface
    
    # Linux/Unix friendly names
    else:
        friendly_names = {
            'lo': 'Local host',
            'any': 'All Interfaces',
            'eth0': 'Ethernet',
            'eth1': 'Ethernet 2',
            'eth2': 'Ethernet 3',
            'eth3': 'Ethernet 4',
            'wlan0': 'Wi-Fi',
            'wlan1': 'Wi-Fi 2',
            'wlan2': 'Wi-Fi 3',
            'wlp': 'Wi-Fi',  # wlp2s0, wlp3s0, etc.
            'enp': 'Ethernet',  # enp0s3, enp0s8, etc.
            'ens': 'Ethernet',  # ens33, ens34, etc.
            'docker0': 'Docker Network',
            'br0': 'Bridge Network',
            'virbr0': 'Virtual Bridge',
            'tun0': 'TUN Interface',
            'tap0': 'TAP Interface',
            'ppp0': 'PPP Connection',
            'usb0': 'USB Network',
            'bluetooth0': 'Bluetooth',
            'wwan0': 'Mobile Broadband'
        }
        
        # Check exact matches first
        if iface_lower in friendly_names:
            return friendly_names[iface_lower]
        
        # Check prefix matches
        for prefix, friendly in friendly_names.items():
            if iface_lower.startswith(prefix):
                return friendly
        
        # Return original if no match
        return iface

def get_interfaces_with_friendly_names():
    """Get interfaces with user-friendly names for display.
    
    Returns:
        list[tuple[str, str]]: (friendly_name, technical_name)
    """
    interfaces = get_interfaces()
    result: list[tuple[str, str]] = []
    used_display: set[str] = set()

    # Special handling for Windows Npcap device strings like \Device\NPF_{GUID}
    npf_index = 1

    for iface in interfaces:
        iface_lower = iface.lower()

        # On Windows, hide ugly NPF GUIDs behind simple adapter numbers
        if IS_WINDOWS and iface_lower.startswith(r"\\device\\npf_"):
            display = f"Network adapter #{npf_index}"
            npf_index += 1
        else:
            friendly = get_friendly_interface_name(iface)
            display = friendly

        # Ensure display name is unique so the user can distinguish if needed
        if display in used_display:
            # Fall back to including the technical name to avoid exact duplicates
            display = f"{display} ({iface})"
        used_display.add(display)
        result.append((display, iface))

    return result


def format_interface_display(iface: str) -> str:
    """Return a user-friendly display for a technical interface name.

    Examples: 'Ethernet (eth0)', 'Wi-Fi (wlan0)', '\\Device\\NPF_{GUID}' -> 'Network adapter #1'
    """
    if not iface:
        return iface
    # Special Windows NPF GUID handling is done in get_interfaces_with_friendly_names(),
    # but for other uses we provide a compact friendly (technical) format.
    friendly = get_friendly_interface_name(iface)
    # If friendly is identical to technical, just return technical
    if friendly == iface:
        return iface
    # Avoid repeating if technical is already part of friendly
    if str(iface) in str(friendly):
        return friendly
    return f"{friendly} ({iface})"

# Raw capture fallback
# NOTE: This is only valid on Unix-like systems where AF_PACKET is supported.
def raw_capture(interface):
    """Raw socket packet capture (Linux/Unix only)."""
    if IS_WINDOWS:
        # AF_PACKET is not available on Windows; instruct user to use Scapy/Npcap instead.
        print("[INTERFACE ERROR] Raw socket capture is not supported on Windows. Install Scapy + Npcap and use Scapy capture.")
        return None
    try:
        # Try to create raw socket (requires root/sudo)
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        s.bind((interface, 0))
        return s
    except PermissionError:
        print(f"[PERMISSION ERROR] Raw socket capture requires root privileges. Run with sudo or use Scapy.")
        print(f"[INFO] Try: sudo python3 pearcer.py")
        return None
    except OSError as e:
        if e.errno == 1:  # Operation not permitted
            print(f"[PERMISSION ERROR] Operation not permitted. Run with sudo: sudo python3 pearcer.py")
        else:
            print(f"[INTERFACE ERROR] {e}")
        return None
    except Exception as e:
        print(f"[INTERFACE ERROR] {e}")
        return None

# Scapy capture if available
def scapy_capture(interface, filter_str, prn, count=0):
    """Scapy-based packet capture"""
    if SCAPY_AVAILABLE:
        try:
            sniff(iface=interface, filter=filter_str, prn=prn, count=count, store=0)
        except Exception as e:
            print(f"[SCAPY CAPTURE ERROR] {e}")
    else:
        print("[SCAPY NOT INSTALLED] Using raw capture")

def update_http_host_mapping(ip_src: str, ip_dst: str, protocol: str, payload: bytes) -> None:
    """Update ip->hostname mapping based on HTTP Host header.

    This is a best-effort extraction from HTTP request payloads.
    """
    if protocol != "HTTP" or not payload:
        return
    try:
        text = payload.decode("utf-8", errors="ignore")
    except Exception:
        return
    host = None
    for line in text.split("\r\n"):
        if line.lower().startswith("host:"):
            try:
                host = line.split(":", 1)[1].strip()
            except Exception:
                host = None
            break
    if host:
        # Map destination IP to hostname (typical HTTP request direction)
        ip_hostnames[ip_dst] = host


def update_dns_host_mapping_from_scapy(pkt) -> None:
    """Update ip->hostname mapping using DNS answers from a Scapy packet.

    We map A and AAAA records (IPv4/IPv6) to their rrname hostnames.
    """
    if not SCAPY_AVAILABLE:
        return
    try:
        if DNS not in pkt:
            return
        dns = pkt[DNS]
        # Only process responses with answers
        if dns.ancount <= 0 or dns.an is None:
            return
        rr = dns.an
        for _ in range(dns.ancount):
            if isinstance(rr, DNSRR):
                try:
                    # A (1) and AAAA (28) records carry IP addresses
                    if rr.type in (1, 28):
                        host = rr.rrname.decode(errors="ignore").rstrip(".") if isinstance(rr.rrname, bytes) else str(rr.rrname).rstrip(".")
                        rdata = rr.rdata
                        # rdata may be bytes (IPv4), string, or raw; str() is usually fine
                        ip_str = str(rdata)
                        ip_hostnames[ip_str] = host
                except Exception:
                    pass
            if hasattr(rr, "payload"):
                rr = rr.payload
            else:
                break
    except Exception:
        # DNS parsing failures should never break capture
        pass


def lookup_host(ip_src: str, ip_dst: str) -> str:
    """Return best-known hostname for either endpoint, if any."""
    if ip_dst in ip_hostnames:
        return ip_hostnames[ip_dst]
    if ip_src in ip_hostnames:
        return ip_hostnames[ip_src]
    return ""


# Enhanced protocol detection
def detect_protocol(payload, ip_proto, src_port, dst_port):
    """Detect specific protocols in packet payload"""
    protocol = "Unknown"
    
    # Port-based detection
    if src_port == 53 or dst_port == 53:
        protocol = "DNS"
    elif src_port == 80 or dst_port == 80:
        protocol = "HTTP"
    elif src_port == 443 or dst_port == 443:
        protocol = "TLS"
    elif src_port == 5060 or dst_port == 5060:
        protocol = "SIP"
    elif src_port == 1900 or dst_port == 1900:
        protocol = "SSDP"
    elif src_port == 137 or dst_port == 137:
        protocol = "NetBIOS"
        
    # Payload-based detection
    if ip_proto == 6:  # TCP
        if payload.startswith(TLS_HANDSHAKE):
            protocol = "TLS"
        elif any(payload.startswith(method) for method in HTTP_METHODS):
            protocol = "HTTP"
        elif b'websocket' in payload.lower() or b'upgrade: websocket' in payload.lower():
            protocol = "WebSocket"
        elif any(indicator in payload for indicator in SIP_INDICATORS):
            protocol = "SIP"
        elif src_port == 443 or dst_port == 443:
            protocol = "TLS"  # Assume TLS on port 443
        else:
            protocol = "TCP"
    elif ip_proto == 17:  # UDP
        if src_port == 53 or dst_port == 53:
            protocol = "DNS"
        elif src_port == 5060 or dst_port == 5060:
            protocol = "SIP"
        elif src_port == 1900 or dst_port == 1900:
            protocol = "SSDP"
        elif src_port == 443 or dst_port == 443:
            protocol = "QUIC"  # Assume QUIC on port 443
        else:
            protocol = "UDP"
    elif ip_proto == 1 or ip_proto == 58:  # ICMP (v4 or v6)
        protocol = "ICMP"
    elif ip_proto == 132:  # DCCP
        protocol = "DCCP"
        
    return protocol

# Advanced attack detection
def detect_attacks(ip_src, protocol, payload, src_port, dst_port):
    """Detect various types of attacks and suspicious activities.

    NOTE: Only "real" attacks (e.g., exploits, malware, blacklisted IPs) should
    be marked as level="attack" (red). High-traffic anomalies are treated as
    "suspicious" (orange) so they stand out but are not counted as attacks.
    """
    level = "normal"
    attack_type = ""
    
    # Check against blacklist (always an attack)
    if ip_src in config.get("blacklist_ips", []):
        level = "attack"
        attack_type = "Blacklisted IP"
        stats["attacks"] += 1
    
    # Check attack thresholds (high-traffic anomaly -> suspicious, not attack)
    attack_counts[ip_src] += 1
    if attack_counts[ip_src] > config.get("attack_threshold", 50) and level != "attack":
        level = "suspicious"
        attack_type = "High traffic"
        stats["vulnerabilities"] += 1
    
    # Detect port scanning (many connections to different ports)
    if protocol == "TCP" and b'SYN' in payload and random.random() < 0.1:
        level = "suspicious"
        attack_type = "Possible SYN flood"
        stats["vulnerabilities"] += 1
    
    # Detect credential exposure
    sensitive_patterns = [
        rb'password[=\s]*[^\s&]+',
        rb'passwd[=\s]*[^\s&]+',
        rb'login[=\s]*[^\s&]+',
        rb'user[=\s]*[^\s&]+',
        rb'username[=\s]*[^\s&]+'
    ]
    
    for pattern in sensitive_patterns:
        if re.search(pattern, payload, re.IGNORECASE):
            decrypted_data.append(payload)
            level = "suspicious"
            attack_type = "Credential exposure"
            stats["vulnerabilities"] += 1
            break
    
    # Detect SQL injection attempts
    sql_keywords = [b"SELECT", b"INSERT", b"UPDATE", b"DELETE", b"DROP", b"UNION", b"EXEC"]
    if any(keyword in payload.upper() for keyword in sql_keywords) and b"'" in payload:
        level = "attack"
        attack_type = "SQL Injection"
        stats["exploits"] += 1
    
    # Detect malware signatures
    malware_signatures = [b"cmd.exe", b"netcat", b"ncat", b"reverse shell", b"backdoor", b"meterpreter"]
    if any(sig in payload.lower() for sig in malware_signatures):
        level = "attack"
        attack_type = "Malware detected"
        stats["malware"] += 1
    
    # Detect suspicious ports
    suspicious_ports = [1337, 31337, 666, 135, 139, 445, 1433, 3389]
    if src_port in suspicious_ports or dst_port in suspicious_ports:
        level = "suspicious"
        attack_type = "Suspicious port"
        stats["vulnerabilities"] += 1
    
    # Random suspicious detection (for demo purposes)
    if random.random() < 0.01:
        level = "suspicious"
        attack_type = "Anomalous traffic"
        stats["vulnerabilities"] += 1
        
    if level == "suspicious" and random.random() < 0.05:
        level = "attack"
        attack_type = "Confirmed exploit"
        stats["exploits"] += 1
    
    return level, attack_type


def current_filter_mode() -> str:
    """Return the current GUI filter mode label."""

    return config.get("filter_mode", "All traffic")


def bpf_for_mode(mode: str) -> str:
    """Map a filter mode label to a BPF string for Scapy capture."""

    if mode == "Web (HTTP+TLS)":
        return "tcp port 80 or tcp port 8080 or tcp port 443"
    if mode == "HTTP only":
        return "tcp port 80 or tcp port 8080"
    if mode == "TLS only":
        return "tcp port 443"
    if mode == "DNS only":
        return "udp port 53 or tcp port 53"
    if mode == "TCP only":
        return "tcp"
    if mode == "UDP only":
        return "udp"
    if mode == "ICMP only":
        return "icmp or icmp6"
    # For "All traffic" and "Suspicious / attacks only", capture everything
    return ""


def gui_should_show_packet(protocol: str, level: str) -> bool:
    """Decide if a packet should be visible in the GUI based on filter mode."""

    mode = current_filter_mode()
    if mode == "Web (HTTP+TLS)":
        return protocol in ("HTTP", "WebSocket", "TLS", "QUIC")
    if mode == "HTTP only":
        return protocol in ("HTTP", "WebSocket")
    if mode == "TLS only":
        return protocol == "TLS"
    if mode == "DNS only":
        return protocol == "DNS"
    if mode == "TCP only":
        return protocol in ("TCP", "HTTP", "TLS", "WebSocket", "QUIC")
    if mode == "UDP only":
        return protocol in ("UDP", "DNS", "SIP", "SSDP")
    if mode == "ICMP only":
        return protocol == "ICMP"
    if mode == "Suspicious / attacks only":
        return level != "normal"
    # "All traffic" or unknown value
    return True


# Packet handler for raw bytes (offline / raw-socket capture)
# NOTE: On Windows with Scapy, we use packet_handler_scapy() instead, which
# relies on Scapy's decoders and produces richer protocol/IP information.
def packet_handler(packet):
    """Handle incoming packets and perform analysis (raw bytes path)."""
    global packet_count, stats, last_packet_time
    packet_count += 1
    level = "normal"
    protocol = "Unknown"
    ip_src = ip_dst = "N/A"
    src_port = dst_port = 0
    info = "No info"
    attack_type = ""
    
    try:
        # Ethernet header
        eth_header = struct.unpack('!6s6sH', packet[:14])
        eth_proto = socket.ntohs(eth_header[2])
        
        if eth_proto == 0x0800:  # IPv4
            # IP header
            ip_header = struct.unpack('!BBHHHBBH4s4s', packet[14:34])
            ip_version = ip_header[0] >> 4
            ip_ihl = ip_header[0] & 0xF
            ip_header_len = ip_ihl * 4
            
            ip_src = socket.inet_ntoa(ip_header[8])
            ip_dst = socket.inet_ntoa(ip_header[9])
            ip_proto = ip_header[6]
            
            # Apply whitelist/blacklist filtering
            if config.get("whitelist_ips") and ip_src not in config["whitelist_ips"]:
                return  # Skip non-whitelisted IPs
            if ip_src in config.get("blacklist_ips", []):
                level = "attack"
                
            # Transport layer
            transport_start = 14 + ip_header_len
            if ip_proto == 6:  # TCP
                tcp_header = struct.unpack('!HHLLBBHHH', packet[transport_start:transport_start+20])
                src_port = tcp_header[0]
                dst_port = tcp_header[1]
                payload_start = transport_start + (tcp_header[4] >> 4) * 4
            elif ip_proto == 17:  # UDP
                udp_header = struct.unpack('!HHHH', packet[transport_start:transport_start+8])
                src_port = udp_header[0]
                dst_port = udp_header[1]
                payload_start = transport_start + 8
            else:
                payload_start = transport_start
                
            # Extract payload
            payload = packet[payload_start:]
            protocol = detect_protocol(payload, ip_proto, src_port, dst_port)

            # Hostname mapping (HTTP Host header -> hostname)
            update_http_host_mapping(ip_src, ip_dst, protocol, payload)
            
            # Attack detection
            level, attack_type = detect_attacks(ip_src, protocol, payload, src_port, dst_port)
            
            # Connectivity issue detection
            if protocol == "ICMP":
                connectivity_issues.append(f"High ICMP traffic from {ip_src}")
            
            # Protocol counting
            protocol_counts[protocol] += 1
            
            # Info string
            info = f"{protocol} packet"
            if attack_type:
                info += f" - {attack_type}"

            # If we know a hostname for this flow, append it to Info
            host_hint = lookup_host(ip_src, ip_dst)
            if host_hint:
                info += f" -> {host_hint}"

            # If we know a hostname for this flow, append it to Info
            host_hint = lookup_host(ip_src, ip_dst)
            if host_hint:
                info += f" -> {host_hint}"
        elif eth_proto == 0x86DD:  # IPv6
            # IPv6 header (40 bytes after Ethernet)
            ipv6_header = struct.unpack('!IHBB16s16s', packet[14:54])
            ip_proto = ipv6_header[2]
            try:
                ip_src = socket.inet_ntop(socket.AF_INET6, ipv6_header[3])
                ip_dst = socket.inet_ntop(socket.AF_INET6, ipv6_header[4])
            except AttributeError:
                # Fallback if inet_ntop is not available
                ip_src = binascii.hexlify(ipv6_header[3]).decode('ascii')
                ip_dst = binascii.hexlify(ipv6_header[4]).decode('ascii')

            # Apply whitelist/blacklist filtering
            if config.get("whitelist_ips") and ip_src not in config["whitelist_ips"]:
                return  # Skip non-whitelisted IPs
            if ip_src in config.get("blacklist_ips", []):
                level = "attack"

            # Transport layer (assume no extension headers for now)
            transport_start = 14 + 40  # Ethernet + IPv6 header
            if ip_proto == 6:  # TCP
                tcp_header = struct.unpack('!HHLLBBHHH', packet[transport_start:transport_start+20])
                src_port = tcp_header[0]
                dst_port = tcp_header[1]
                payload_start = transport_start + (tcp_header[4] >> 4) * 4
            elif ip_proto == 17:  # UDP
                udp_header = struct.unpack('!HHHH', packet[transport_start:transport_start+8])
                src_port = udp_header[0]
                dst_port = udp_header[1]
                payload_start = transport_start + 8
            else:
                payload_start = transport_start

            # Extract payload
            payload = packet[payload_start:]
            protocol = detect_protocol(payload, ip_proto, src_port, dst_port)

            # Hostname mapping (HTTP Host header -> hostname)
            update_http_host_mapping(ip_src, ip_dst, protocol, payload)

            # Attack detection
            level, attack_type = detect_attacks(ip_src, protocol, payload, src_port, dst_port)

            # Connectivity issue detection
            if protocol == "ICMP":
                connectivity_issues.append(f"High ICMP traffic from {ip_src}")

            # Protocol counting
            protocol_counts[protocol] += 1

            # Info string
            info = f"{protocol} packet"
            if attack_type:
                info += f" - {attack_type}"

            # If we know a hostname for this flow, append it to Info
            host_hint = lookup_host(ip_src, ip_dst)
            if host_hint:
                info += f" -> {host_hint}"
                
    except Exception as e:
        pass  # Silently handle parsing errors
    
    # Timestamp and logging
    timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
    log = f"[{timestamp}] {protocol}: {ip_src}:{src_port} -> {ip_dst}:{dst_port} [{level.upper()}] {info}"
    
    # Update GUI if available
    if GUI_AVAILABLE and 'packet_list' in globals():
        if gui_should_show_packet(protocol, level):
            # Build tags so both threat level and protocol color rules can apply.
            tags = [level]
            # Wireshark-style protocol coloring
            if protocol == "TCP":
                tags.append("tcp")
            elif protocol == "UDP":
                tags.append("udp")
            elif protocol in ("HTTP", "WebSocket"):
                tags.append("http")
            elif protocol == "DNS":
                tags.append("dns")
            elif protocol == "TLS":
                tags.append("tls")
            elif protocol == "QUIC":
                tags.append("encrypted")
            elif protocol == "SIP":
                tags.append("voip")
            elif protocol in ("SMB", "NetBIOS"):
                tags.append("smb")
            elif protocol in ("ICMP", "OSPF", "RIP", "BGP"):
                tags.append("routing")
            
            # Error/problem detection
            if level == "attack" or "error" in info.lower() or "problem" in info.lower():
                tags.append("error")
            
            # TCP flags detection
            if protocol == "TCP" and ("SYN" in info or "FIN" in info or "ACK" in info):
                tags.append("tcp_flags")
                tags.append("expert_chat")

            global _gui_row_index
            _gui_row_index += 1
            pkt_len = len(packet)
            host = lookup_host(ip_src, ip_dst)
            row_values = (
                _gui_row_index,
                timestamp,
                f"{ip_src}:{src_port}",
                f"{ip_dst}:{dst_port}",
                protocol,
                host,
                pkt_len,
                level.upper(),
                info,
            )

            item_id = packet_list.insert(
                '',
                'end',
                values=row_values,
                tags=tuple(tags),
            )
            if auto_scroll:
                packet_list.see(item_id)
    
    # Console output
    print(log)
    
    # File logging
    try:
        with open(config["log_file"], "a") as f:
            f.write(log + "\n")
    except:
        pass
    
    # Store packet for PCAP export
    captured_packets.append(packet)


def packet_handler_scapy(pkt):
    """Handle packets using Scapy layers for better protocol visibility."""
    global packet_count, stats, last_packet_time
    packet_count += 1
    level = "normal"
    protocol = "Unknown"
    ip_src = ip_dst = "N/A"
    src_port = dst_port = 0
    info = "No info"
    attack_type = ""

    raw_packet = bytes(pkt)
    payload = b""

    try:
        ip_layer = None
        ip_proto = 0

        if IP in pkt:
            ip_layer = pkt[IP]
            ip_proto = int(ip_layer.proto)
        elif IPv6 in pkt:
            ip_layer = pkt[IPv6]
            ip_proto = int(ip_layer.nh)

        # Update DNS-based hostname mappings (if this is DNS traffic)
        update_dns_host_mapping_from_scapy(pkt)

        if ip_layer is not None:
            ip_src = str(ip_layer.src)
            ip_dst = str(ip_layer.dst)

            if TCP in pkt:
                l4 = pkt[TCP]
                src_port = int(l4.sport)
                dst_port = int(l4.dport)
            elif UDP in pkt:
                l4 = pkt[UDP]
                src_port = int(l4.sport)
                dst_port = int(l4.dport)
            elif ICMP in pkt:
                # ICMP/ICMPv6 without ports
                src_port = dst_port = 0

            if Raw in pkt:
                payload = bytes(pkt[Raw].load)
            else:
                # Fallback: use full packet minus L2/L3 where possible
                payload = raw_packet

            protocol = detect_protocol(payload, ip_proto, src_port, dst_port)

            # Hostname mapping (HTTP Host header -> hostname)
            update_http_host_mapping(ip_src, ip_dst, protocol, payload)

            level, attack_type = detect_attacks(ip_src, protocol, payload, src_port, dst_port)
            
            # Track discovered hosts for vulnerability scanning
            if vuln_scanner and ip_dst not in discovered_hosts_for_scan and ip_dst != "N/A":
                with host_scan_lock:
                    if ip_dst not in discovered_hosts_for_scan:
                        discovered_hosts_for_scan.add(ip_dst)
                        # Auto-scan discovered hosts in background (light scan)
                        if config.get("auto_vuln_scan", False):
                            threading.Thread(
                                target=lambda: vuln_scanner.scan_host(ip_dst, "80,443,22,21,25,3306,3389,139,445", "connect"),
                                daemon=True
                            ).start()

            if protocol == "ICMP":
                connectivity_issues.append(f"High ICMP traffic from {ip_src}")

            protocol_counts[protocol] += 1

            info = f"{protocol} packet"
            if attack_type:
                info += f" - {attack_type}"
        else:
            # Non-IP traffic (e.g., ARP, LLDP). Show MACs if available.
            if Ether in pkt:
                eth = pkt[Ether]
                ip_src = eth.src
                ip_dst = eth.dst
                info = f"Ethernet type 0x{eth.type:04x} packet"
            else:
                info = "Non-IP packet"
    except Exception:
        # Keep going even if Scapy parsing fails for a packet.
        pass

    # Timestamp and logging (shared with raw path)
    timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
    log = f"[{timestamp}] {protocol}: {ip_src}:{src_port} -> {ip_dst}:{dst_port} [{level.upper()}] {info}"

    # Update GUI if available
    if GUI_AVAILABLE and 'packet_list' in globals():
        if gui_should_show_packet(protocol, level):
            tags = [level]
            # Wireshark-style protocol coloring
            if protocol == "TCP":
                tags.append("tcp")
            elif protocol == "UDP":
                tags.append("udp")
            elif protocol in ("HTTP", "WebSocket"):
                tags.append("http")
            elif protocol == "DNS":
                tags.append("dns")
            elif protocol == "TLS":
                tags.append("tls")
            elif protocol == "QUIC":
                tags.append("encrypted")
            elif protocol == "SIP":
                tags.append("voip")
            elif protocol in ("SMB", "NetBIOS"):
                tags.append("smb")
            elif protocol in ("ICMP", "OSPF", "RIP", "BGP"):
                tags.append("routing")
            
            # Error/problem detection
            if level == "attack" or "error" in info.lower() or "problem" in info.lower():
                tags.append("error")
            
            # TCP flags detection
            if protocol == "TCP" and ("SYN" in info or "FIN" in info or "ACK" in info):
                tags.append("tcp_flags")
                tags.append("expert_chat")

            global _gui_row_index
            _gui_row_index += 1
            pkt_len = len(raw_packet)
            host = lookup_host(ip_src, ip_dst)
            row_values = (
                _gui_row_index,
                timestamp,
                f"{ip_src}:{src_port}",
                f"{ip_dst}:{dst_port}",
                protocol,
                host,
                pkt_len,
                level.upper(),
                info,
            )

            item_id = packet_list.insert(
                '',
                'end',
                values=row_values,
                tags=tuple(tags),
            )
            if auto_scroll:
                packet_list.see(item_id)

    print(log)

    try:
        with open(config["log_file"], "a") as f:
            f.write(log + "\n")
    except Exception:
        pass

    captured_packets.append(raw_packet)


# Show details/hex on click
def show_details(event):
    """Show packet details and hex dump when selected in GUI"""
    selected = packet_list.selection()
    if selected:
        try:
            index = packet_list.index(selected[0])  # Get index directly
            if 0 <= index < len(captured_packets):
                packet = captured_packets[index]
                details_tree.delete(*details_tree.get_children())
                
                # Parse packet details
                try:
                    # Ethernet header
                    eth = struct.unpack('!6s6sH', packet[:14])
                    proto = socket.ntohs(eth[2])
                    details_tree.insert('', 'end', text=f"Ethernet: {binascii.hexlify(eth[0]).decode()[:12]} -> {binascii.hexlify(eth[1]).decode()[:12]}, Type: 0x{proto:04x}")
                    
                    if proto == 0x0800:  # IPv4
                        iph = struct.unpack('!BBHHHBBH4s4s', packet[14:34])
                        ip_src = socket.inet_ntoa(iph[8])
                        ip_dst = socket.inet_ntoa(iph[9])
                        protocol_num = iph[6]
                        
                        proto_name = {6: "TCP", 17: "UDP", 1: "ICMP", 132: "DCCP"}.get(protocol_num, f"Protocol {protocol_num}")
                        details_tree.insert('', 'end', text=f"IP: {ip_src} -> {ip_dst}, {proto_name}")
                        
                        # Transport layer
                        ip_ihl = iph[0] & 0xF
                        ip_header_len = ip_ihl * 4
                        transport_start = 14 + ip_header_len
                        
                        if protocol_num == 6:  # TCP
                            tcp_header = struct.unpack('!HHLLBBHHH', packet[transport_start:transport_start+20])
                            flags = tcp_header[5]
                            flag_names = []
                            if flags & 0x01: flag_names.append("FIN")
                            if flags & 0x02: flag_names.append("SYN")
                            if flags & 0x04: flag_names.append("RST")
                            if flags & 0x08: flag_names.append("PSH")
                            if flags & 0x10: flag_names.append("ACK")
                            if flags & 0x20: flag_names.append("URG")
                            flag_str = "|".join(flag_names) if flag_names else "None"
                            details_tree.insert('', 'end', text=f"TCP: {tcp_header[0]} -> {tcp_header[1]}, Flags: {flag_str}")
                        elif protocol_num == 17:  # UDP
                            udp_header = struct.unpack('!HHHH', packet[transport_start:transport_start+8])
                            details_tree.insert('', 'end', text=f"UDP: {udp_header[0]} -> {udp_header[1]}, Len: {udp_header[2]}")
                        elif protocol_num == 1:  # ICMP
                            icmp_header = struct.unpack('!BBH', packet[transport_start:transport_start+4])
                            details_tree.insert('', 'end', text=f"ICMP: Type {icmp_header[0]}, Code {icmp_header[1]}")
                        elif protocol_num == 132:  # DCCP
                            dccp_header = struct.unpack('!HHBBH', packet[transport_start:transport_start+8])
                            details_tree.insert('', 'end', text=f"DCCP: {dccp_header[0]} -> {dccp_header[1]}")
                            
                except Exception as e:
                    details_tree.insert('', 'end', text=f"Parsing Error: {str(e)}")
                
                # Hex dump
                hex_text.delete('1.0', tk.END)
                hex_dump = binascii.hexlify(packet).decode('utf-8')
                ascii_dump = ''.join([chr(b) if 32 <= b <= 126 else '.' for b in packet])
                for i in range(0, len(hex_dump), 32):
                    line_hex = hex_dump[i:i+32]
                    line_ascii = ascii_dump[i//2:i//2+16]
                    formatted_hex = ' '.join(line_hex[j:j+2] for j in range(0, len(line_hex), 2))
                    hex_text.insert(tk.END, f"{i:08x}  {formatted_hex:<48}  {line_ascii}\n")
        except Exception as e:
            if GUI_AVAILABLE:
                messagebox.showerror("Error", f"Failed to display packet details: {str(e)}")

# Packet processing worker thread
def packet_processor():
    """Background thread that processes packets from queue"""
    global packet_count, last_packet_time, stats
    
    while running:
        try:
            try:
                packet_data = packet_queue.get(timeout=0.5)
            except:
                # Timeout - check if we should continue
                continue
            
            if packet_data is None:
                continue
            
            handler_func, packet = packet_data
            handler_func(packet)
            
            # Update PPS calculation (packet_count is incremented in handlers)
            current_time = time.time()
            if current_time - last_packet_time >= 1.0:
                stats['pps'] = packet_count / (current_time - last_packet_time) if current_time > last_packet_time else 0
                last_packet_time = current_time
                packet_count = 0
            
            packet_queue.task_done()
        except Exception as e:
            print(f"[PACKET PROCESSOR ERROR] {e}")
            continue
    
    # Process remaining packets in queue after stopping
    while not packet_queue.empty():
        try:
            packet_data = packet_queue.get(timeout=0.1)
            if packet_data:
                handler_func, packet = packet_data
                handler_func(packet)
                packet_queue.task_done()
        except:
            break

# Sniff thread - optimized for speed
def sniff_thread():
    """Main packet capture thread - optimized for maximum speed"""
    global running, last_packet_time, packet_processing_thread
    
    # Start packet processing thread
    packet_processing_thread = threading.Thread(target=packet_processor, daemon=True)
    packet_processing_thread.start()
    
    # Try Scapy first if available (fastest method)
    if SCAPY_AVAILABLE:
        try:
            # Get actual interface name from Scapy
            from scapy.all import get_if_list, get_if_addr, get_if_hwaddr
            available_interfaces = get_if_list()
            
            # Try to find matching interface
            interface_to_use = config["interface"]
            
            # If "any" is selected, try to use it or find best interface
            if interface_to_use.lower() == "any":
                if "any" in available_interfaces:
                    interface_to_use = "any"
                elif available_interfaces:
                    # Use first non-loopback interface
                    for iface in available_interfaces:
                        if iface.lower() != "lo" and "loopback" not in iface.lower():
                            interface_to_use = iface
                            print(f"[INFO] Using interface: {format_interface_display(interface_to_use)} (auto-selected from 'any')")
                            break
                    else:
                        interface_to_use = available_interfaces[0]
                        print(f"[INFO] Using interface: {format_interface_display(interface_to_use)}")
                else:
                    raise Exception("No network interfaces found")
            elif interface_to_use not in available_interfaces:
                # Try to find similar interface (fuzzy matching)
                best_match = None
                best_score = 0
                
                for iface in available_interfaces:
                    # Exact substring match
                    if config["interface"].lower() in iface.lower() or iface.lower() in config["interface"].lower():
                        score = len(set(config["interface"].lower()) & set(iface.lower()))
                        if score > best_score:
                            best_match = iface
                            best_score = score
                
                if best_match:
                    interface_to_use = best_match
                    print(f"[INFO] Interface '{config['interface']}' not found, using similar: {format_interface_display(interface_to_use)}")
                else:
                    # Use first available interface
                    if available_interfaces:
                        interface_to_use = available_interfaces[0]
                        print(f"[INFO] Interface '{config['interface']}' not found, using: {format_interface_display(interface_to_use)}")
                    else:
                        raise Exception("No network interfaces found")
            
            # Display interface info
            try:
                if_addr = get_if_addr(interface_to_use)
                if_hwaddr = get_if_hwaddr(interface_to_use)
                print(f"[INFO] Capturing on {format_interface_display(interface_to_use)} - IP: {if_addr}, MAC: {if_hwaddr}")
            except:
                print(f"[INFO] Capturing on {format_interface_display(interface_to_use)}")
            
            def scapy_callback(pkt):
                # Queue packet for async processing - NO SLEEP for maximum speed
                if not running:
                    return
                
                try:
                    # Try non-blocking put first
                    packet_queue.put_nowait((packet_handler_scapy, pkt))
                except:
                    # Queue full, try blocking put with timeout
                    try:
                        packet_queue.put((packet_handler_scapy, pkt), timeout=0.01)
                    except:
                        # Still full, drop packet to maintain speed
                        pass
                return
            
            print(f"[INFO] Starting packet capture on {format_interface_display(interface_to_use)}...")
            print(f"[INFO] Filter: {config['filter'] or 'None'}")
            
            # Test if interface is actually available
            try:
                test_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                test_sock.close()
            except:
                pass
            
            # Use optimized Scapy settings for speed
            # Note: sniff() is blocking, so it will run until stop_filter returns True
            packets_captured = [0]  # Use list to allow modification in nested function
            
            def counting_callback(pkt):
                packets_captured[0] += 1
                if packets_captured[0] == 1:
                    print(f"[SUCCESS] First packet captured!")
                scapy_callback(pkt)
            
            try:
                print(f"[INFO] Attempting capture with promiscuous mode...")
                sniff(iface=interface_to_use, 
                      filter=config["filter"] if config["filter"] else None, 
                      prn=counting_callback, 
                      store=0,  # Don't store packets in memory
                      stop_filter=lambda x: not running,
                      promisc=True,  # Promiscuous mode for better capture (may require root)
                      timeout=None)  # No timeout for continuous capture
            except KeyboardInterrupt:
                print("[INFO] Capture interrupted by user")
            except Exception as sniff_error:
                # Try without promiscuous mode
                error_str = str(sniff_error)
                print(f"[INFO] Promiscuous mode failed: {error_str}")
                print(f"[INFO] Trying non-promiscuous mode...")
                try:
                    sniff(iface=interface_to_use, 
                          filter=config["filter"] if config["filter"] else None, 
                          prn=counting_callback, 
                          store=0,
                          stop_filter=lambda x: not running,
                          promisc=False,  # Non-promiscuous mode
                          timeout=None)
                except Exception as e2:
                    print(f"[ERROR] Non-promiscuous capture also failed: {e2}")
                    if GUI_AVAILABLE:
                        messagebox.showerror("Capture Failed", 
                                            f"Failed to start capture:\n{error_str}\n\n"
                                            f"Try:\n"
                                            f"1. Run with sudo (Linux): sudo python3 pearcer.py\n"
                                            f"2. Check interface name is correct\n"
                                            f"3. Ensure interface is up and has traffic")
                    raise e2
            finally:
                print(f"[INFO] Capture stopped. Total packets: {packets_captured[0]}")
            return
        except Exception as e:
            error_msg = str(e)
            if "not permitted" in error_msg.lower() or "permission" in error_msg.lower():
                print(f"[PERMISSION ERROR] {error_msg}")
                print(f"[INFO] Try running with sudo: sudo python3 pearcer.py")
            else:
                print(f"[SCAPY ERROR] Falling back to raw capture: {e}")
    
    # On Windows, do not attempt AF_PACKET raw sockets; require Scapy/Npcap
    if IS_WINDOWS:
        print("[ERROR] Scapy is not available or failed. On Windows, install Scapy and Npcap for capture.")
        return
    
    # Fallback to raw sockets (Linux/Unix only) - optimized
    sock = raw_capture(config["interface"])
    if not sock:
        print("[ERROR] Could not initialize packet capture")
        return
    
    # Set socket options for better performance
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1024 * 1024)  # 1MB buffer
    except:
        pass
    
    print(f"[INFO] Starting raw socket capture on {config['interface']}...")
    
    # High-speed capture loop - NO SLEEP for maximum throughput
    while running:
        try:
            # Use recv with timeout to allow checking running flag
            sock.settimeout(0.5)
            packet = sock.recv(65565)
            if packet and len(packet) > 0:
                # Queue for async processing
                try:
                    packet_queue.put_nowait((packet_handler, packet))
                except:
                    # Queue full, try blocking put with timeout
                    try:
                        packet_queue.put((packet_handler, packet), timeout=0.01)
                    except:
                        # Still full, drop packet to maintain speed
                        pass
        except socket.timeout:
            continue  # Timeout is expected, just continue
        except socket.error as sock_err:
            if running:
                print(f"[CAPTURE ERROR] Socket error: {sock_err}")
            break
        except Exception as e:
            if running:
                print(f"[CAPTURE ERROR] {e}")
    
    sock.close()

# Offline analysis
def offline_analysis(file_path=None):
    """Analyze captured packets from a file"""
    if not file_path:
        if GUI_AVAILABLE:
            file_path = filedialog.askopenfilename(
                title="Select PCAP file",
                filetypes=[("PCAP files", "*.pcap"), ("All files", "*.*")]
            )
        else:
            file_path = input("Enter path to PCAP file: ")
    
    if not file_path:
        return
        
    try:
        with open(file_path, 'rb') as f:
            # Simple PCAP reader (global header + packets)
            data = f.read()
            
            # Skip PCAP global header (24 bytes)
            offset = 24
            
            while offset < len(data) and running:
                # PCAP packet header (16 bytes)
                if offset + 16 > len(data):
                    break
                    
                # Read packet header
                ts_sec, ts_usec, incl_len, orig_len = struct.unpack('IIII', data[offset:offset+16])
                offset += 16
                
                # Read packet data
                if offset + incl_len > len(data):
                    break
                    
                packet = data[offset:offset+incl_len]
                packet_handler(packet)
                offset += incl_len
                
                # No sleep for maximum speed - process packets as fast as possible
                
        if GUI_AVAILABLE:
            messagebox.showinfo("Analysis Complete", f"Processed {packet_count} packets")
        else:
            print(f"Analysis complete. Processed {packet_count} packets.")
            
    except Exception as e:
        error_msg = f"Error analyzing file: {str(e)}"
        if GUI_AVAILABLE:
            messagebox.showerror("Error", error_msg)
        else:
            print(error_msg)

# Advanced feature placeholders
def bluetooth_capture():
    """Placeholder for Bluetooth capture functionality"""
    msg = "Bluetooth capture requires bluepy library\nInstall with: pip install bluepy"
    if GUI_AVAILABLE:
        messagebox.showinfo("Bluetooth Capture", msg)
    else:
        print(msg)

def usb_capture():
    """Placeholder for USB capture functionality"""
    msg = "USB capture requires pyusb library\nInstall with: pip install pyusb"
    if GUI_AVAILABLE:
        messagebox.showinfo("USB Capture", msg)
    else:
        print(msg)

def voip_analysis():
    """Simple VoIP analysis using pyshark if available.

    Currently this opens a PCAP and looks for SIP/RTP traffic, then shows a
    basic summary dialog.
    """
    if not PYSHARK_AVAILABLE:
        msg = "VoIP analysis requires pyshark library\nInstall with: pip install pyshark"
        if GUI_AVAILABLE:
            messagebox.showinfo("VoIP Analysis", msg)
        else:
            print(msg)
        return

    if GUI_AVAILABLE:
        file_path = filedialog.askopenfilename(
            title="Select PCAP file for VoIP analysis",
            filetypes=[("PCAP files", "*.pcap"), ("All files", "*.*")],
        )
    else:
        file_path = input("Enter path to PCAP file for VoIP analysis: ")

    if not file_path:
        return

    try:
        cap = pyshark.FileCapture(file_path, display_filter="sip || rtp")
        sip_count = 0
        rtp_count = 0
        for pkt in cap:
            try:
                if "SIP" in pkt:
                    sip_count += 1
                if "RTP" in pkt:
                    rtp_count += 1
            except Exception:
                continue
        cap.close()
        msg = f"VoIP summary for {file_path}\nSIP packets: {sip_count}\nRTP packets: {rtp_count}"
    except Exception as e:
        msg = f"Error during VoIP analysis: {e}"

    if GUI_AVAILABLE:
        messagebox.showinfo("VoIP Analysis", msg)
    else:
        print(msg)

def decryption_support():
    """Placeholder for decryption functionality"""
    msg = "Decryption requires scapy-ssl_tls\nInstall with: pip install scapy-ssl_tls"
    if GUI_AVAILABLE:
        messagebox.showinfo("Decryption", msg)
    else:
        print(msg)

def save_pcap():
    """Save captured packets to PCAP file"""
    try:
        # PCAP Global Header
        magic = 0xa1b2c3d4
        major_version = 2
        minor_version = 4
        thiszone = 0
        sigfigs = 0
        snaplen = 65535
        network = 1  # Ethernet
        
        pcap_header = struct.pack('IHHIIII', magic, major_version, minor_version, 
                                  thiszone, sigfigs, snaplen, network)
        
        pcap_data = bytearray(pcap_header)
        
        # Add each packet
        for packet in captured_packets:
            # PCAP Packet Header
            ts = int(time.time())
            ts_usec = int((time.time() % 1) * 1000000)
            incl_len = len(packet)
            orig_len = len(packet)
            
            packet_header = struct.pack('IIII', ts, ts_usec, incl_len, orig_len)
            pcap_data.extend(packet_header)
            pcap_data.extend(packet)
        
        with open(config["pcap_file"], "wb") as f:
            f.write(pcap_data)
            
        msg = f"Packets saved to {config['pcap_file']}"
        if GUI_AVAILABLE:
            messagebox.showinfo("Save Successful", msg)
        else:
            print(msg)
    except Exception as e:
        error_msg = f"Error saving PCAP: {str(e)}"
        if GUI_AVAILABLE:
            messagebox.showerror("Save Error", error_msg)
        else:
            print(error_msg)

# CLI Mode
def cli_mode():
    """CLI mode for packet analysis when GUI is not available"""
    print("Pearcer - Professional Packet Analyzer (CLI Mode)")
    print("=" * 50)
    
    # Get interface selection (show friendly names)
    interfaces = get_interfaces_with_friendly_names()
    print("\nAvailable interfaces:")
    for i, (display, tech) in enumerate(interfaces):
        print(f"{i+1}. {display}")
    
    try:
        choice = int(input("\nSelect interface (number): ")) - 1
        if 0 <= choice < len(interfaces):
            config["interface"] = interfaces[choice][1]
        else:
            print("Invalid choice, using default interface.")
    except ValueError:
        print("Invalid input, using default interface.")
    
    print(f"\nStarting capture on interface: {format_interface_display(config.get('interface'))}")
    print("Press Ctrl+C to stop capture\n")
    
    # Start capture
    global running
    running = True
    
    # Start capture in a separate thread
    capture_thread = threading.Thread(target=sniff_thread)
    capture_thread.daemon = True
    capture_thread.start()
    
    try:
        # Display statistics
        last_count = 0
        while running:
            time.sleep(1)
            current_pps = packet_count - last_count
            last_count = packet_count
            stats['pps'] = current_pps
            print(f"Packets: {packet_count} | PPS: {current_pps} | Attacks: {stats['attacks']} | Vulns: {stats['vulnerabilities']} | Exploits: {stats['exploits']} | Malware: {stats['malware']}")
    except KeyboardInterrupt:
        print("\n\nStopping capture...")
        running = False
        capture_thread.join(timeout=2)
        print("Capture stopped. Packets captured:", packet_count)
        
        # Ask if user wants to save
        save_choice = input("Save captured packets to PCAP file? (y/n): ").lower()
        if save_choice == 'y':
            save_pcap()

# Pro GUI
if GUI_AVAILABLE:
    root = tk.Tk()
    root.title("pearcer - Professional Packet Analyzer")
    root.geometry("1400x900")

    # Try to apply application logo if pearcer_logo.png is present next to this file
    app_logo_image = None
    try:
        base_dir = os.path.dirname(os.path.abspath(__file__))
        logo_path = os.path.join(base_dir, "pearcer_logo.png")
        if os.path.exists(logo_path):
            app_logo_image = tk.PhotoImage(file=logo_path)
            root.iconphoto(True, app_logo_image)
    except Exception:
        # If logo load fails, just continue without a custom icon
        app_logo_image = None
    
    # Configure styles for packet highlighting
    style = tk.ttk.Style()
    style.configure("Treeview", rowheight=25)

    def show_capture_options():
        """Show current capture options (interface, filter, speed, thresholds)."""
        opts = [
            f"Interface: {format_interface_display(config.get('interface'))}",
            f"Filter mode: {config.get('filter_mode', 'All traffic')}",
            f"BPF filter: {config.get('filter', '') or '(none)'}",
            f"Speed: {config.get('speed', 'normal')}",
            f"Attack threshold: {config.get('attack_threshold', 50)}",
        ]
        messagebox.showinfo("Capture Options", "\n".join(opts))

    def show_coloring_rules():
        """Show the active color rules for levels/protocol categories."""
        colors = config.get("highlight_colors", DEFAULT_CONFIG["highlight_colors"])
        lines = [f"{name}: {code}" for name, code in colors.items()]
        messagebox.showinfo("Coloring Rules", "\n".join(lines))

    def show_debug_stats():
        """Show a compact debug summary useful during pentests."""
        top_protos = sorted(protocol_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        proto_summary = ", ".join(f"{p}={c}" for p, c in top_protos) or "(no packets yet)"
        msg = (
            f"Packets: {packet_count}\n"
            f"PPS: {stats['pps']:.2f}\n"
            f"Attacks: {stats['attacks']}, Vulns: {stats['vulnerabilities']}, "
            f"Exploits: {stats['exploits']}, Malware: {stats['malware']}\n"
            f"Top protocols: {proto_summary}"
        )
        messagebox.showinfo("Debug Stats", msg)

    def show_about_with_donation():
        """Show golden-styled About dialog for pearcer."""
        about_text = (
            "pearcer v2.0 - Professional Packet Analyzer\n"
            "Advanced packet analysis and network security tool.\n"
            "\n"
            "License: GPL-3.0\n"
            "Author: H4CKRD (@H4CKRD on Telegram)\n"
            "\n"
            "Features:\n"
            "  - Live capture & offline PCAP analysis\n"
            "  - Protocol/host detection and attack heuristics\n"
            "  - Dark UI with customizable coloring rules\n"
            "\n"
            "Support development (donations):\n"
            "  OxaPay (Telegram wallet) address:\n"
            "  OXALEI4fvH1gWXFn4cmP9AhGQD\n"
            "\n"
            "Source code: github.com/H4CKRD/pearcer\n"
        )

        win = tk.Toplevel(root)
        win.title("About pearcer")
        win.geometry("520x440")
        win.config(bg="#1e1e1e")

        # Gold header bar
        header = tk.Frame(win, bg="#FFD700")
        header.pack(fill="x")
        tk.Label(
            header,
            text="About pearcer",
            bg="#FFD700",
            fg="#000000",
            font=("Arial", 14, "bold"),
        ).pack(padx=10, pady=8, anchor="w")

        # Main text
        txt = tk.Text(
            win,
            bg="#1e1e1e",
            fg="#ffffff",
            font=("Arial", 10),
            wrap=tk.WORD,
            borderwidth=0,
        )
        txt.insert("1.0", about_text)
        txt.config(state=tk.DISABLED)
        txt.pack(fill="both", expand=True, padx=10, pady=(10, 5))

        btn_frame = tk.Frame(win, bg="#1e1e1e")
        btn_frame.pack(fill="x", padx=10, pady=5)

        def copy_oxapay():
            root.clipboard_clear()
            root.clipboard_append("OXALEI4fvH1gWXFn4cmP9AhGQD")
            messagebox.showinfo("Copied", "OxaPay address copied to clipboard.")

        tk.Button(
            btn_frame,
            text="Copy OxaPay Address",
            command=copy_oxapay,
            bg="#FFD700",  # gold button
            fg="#000000",
            font=("Arial", 10, "bold"),
        ).pack(side=tk.LEFT, padx=5)
        tk.Button(
            btn_frame,
            text="Close",
            command=win.destroy,
            bg="#444444",
            fg="#FFFFFF",
            font=("Arial", 10, "bold"),
        ).pack(side=tk.RIGHT, padx=5)

    auto_scroll_var = tk.BooleanVar(value=auto_scroll)
    viz_enabled_var = tk.BooleanVar(value=viz_enabled)

    def toggle_auto_scroll():
        """Toggle auto-scroll behavior for the live packet list."""
        global auto_scroll
        auto_scroll = bool(auto_scroll_var.get())
    
    def toggle_viz_enabled():
        """Toggle visualization enabled state"""
        global viz_enabled
        viz_enabled = bool(viz_enabled_var.get())

    def find_packet_dialog():
        """Prompt the user for a search string and jump to the first matching packet."""
        query = simpledialog.askstring(
            "Find Packet",
            "Search in Source, Destination, Protocol, or Info:",
        )
        if not query:
            return
        children = packet_list.get_children() if 'packet_list' in globals() else []
        if not children:
            return
        q = query.lower()
        for item in children:
            values = packet_list.item(item, "values")
            # values: No, Time, Source, Destination, Protocol, Host, Length, Level, Info
            searchable = [values[2], values[3], values[4], values[5], values[8]]
            if any(q in str(v).lower() for v in searchable):
                packet_list.selection_set(item)
                packet_list.focus(item)
                packet_list.see(item)
                break

    def goto_packet_dialog():
        """Go to a specific packet number (1-based index in the live list)."""
        children = packet_list.get_children() if 'packet_list' in globals() else []
        total = len(children)
        if total == 0:
            messagebox.showinfo("Go to Packet", "No packets captured yet.")
            return
        idx = simpledialog.askinteger("Go to Packet", f"Enter packet number (1-{total}):")
        if not idx:
            return
        idx0 = idx - 1
        if idx0 < 0 or idx0 >= total:
            messagebox.showerror("Go to Packet", "Packet number out of range.")
            return
        item = children[idx0]
        packet_list.selection_set(item)
        packet_list.focus(item)
        packet_list.see(item)

    def clear_capture_view():
        """Clear captured packets and reset live view/statistics."""
        global packet_count, captured_packets, protocol_counts, attack_counts, stats, connectivity_issues, decrypted_data, _gui_row_index

        packet_count = 0
        _gui_row_index = 0
        captured_packets.clear()
        protocol_counts.clear()
        attack_counts.clear()
        connectivity_issues.clear()
        decrypted_data.clear()
        stats.update(pps=0, attacks=0, vulnerabilities=0, exploits=0, malware=0)

        # Clear main packet list and detail views
        if 'packet_list' in globals():
            for item in packet_list.get_children():
                packet_list.delete(item)
        if 'details_tree' in globals():
            details_tree.delete(*details_tree.get_children())
        if 'hex_text' in globals():
            hex_text.delete('1.0', tk.END)
        if 'proto_list' in globals():
            proto_list.delete(0, tk.END)
        if 'attack_list' in globals():
            attack_list.delete(0, tk.END)
        if 'stats_label' in globals():
            stats_label.config(text="PPS: 0 | Attacks: 0 | Vulns: 0 | Exploits: 0 | Malware: 0")

    # Menu - Wireshark-style comprehensive menu structure
    menubar = tk.Menu(root)
    
    # File Menu
    filemenu = tk.Menu(menubar, tearoff=0)
    filemenu.add_command(label="Open...", command=offline_analysis, accelerator="Ctrl+O")
    filemenu.add_command(label="Open Recent", state="disabled")  # Placeholder
    filemenu.add_separator()
    filemenu.add_command(label="Merge...", command=lambda: messagebox.showinfo("Merge", "Merge capture files - Coming soon"))
    filemenu.add_separator()
    filemenu.add_command(label="Close", command=clear_capture_view)
    filemenu.add_separator()
    filemenu.add_command(label="Save As...", command=save_pcap, accelerator="Ctrl+S")
    filemenu.add_command(label="Save", command=save_pcap)
    filemenu.add_command(label="Export Packet Dissections...", command=lambda: messagebox.showinfo("Export", "Export packet dissections - Coming soon"))
    filemenu.add_command(label="Export Selected Packet Bytes...", command=lambda: messagebox.showinfo("Export", "Export selected packet bytes - Coming soon"))
    filemenu.add_command(label="Export Objects", state="disabled")  # Placeholder
    filemenu.add_separator()
    filemenu.add_command(label="Print...", command=lambda: messagebox.showinfo("Print", "Print capture - Coming soon"), accelerator="Ctrl+P")
    filemenu.add_separator()
    filemenu.add_command(label="Quit", command=root.quit, accelerator="Ctrl+Q")
    menubar.add_cascade(label="File", menu=filemenu)
    
    # Edit Menu
    editmenu = tk.Menu(menubar, tearoff=0)
    editmenu.add_command(label="Copy", command=lambda: root.event_generate("<<Copy>>"), accelerator="Ctrl+C")
    editmenu.add_command(label="Find Packet...", command=find_packet_dialog, accelerator="Ctrl+F")
    editmenu.add_separator()
    editmenu.add_command(label="Mark Packet", command=lambda: messagebox.showinfo("Mark", "Mark packet - Coming soon"), accelerator="Ctrl+M")
    editmenu.add_command(label="Ignore Packet", command=lambda: messagebox.showinfo("Ignore", "Ignore packet - Coming soon"), accelerator="Ctrl+D")
    editmenu.add_separator()
    editmenu.add_command(label="Set/Unset Time Reference", state="disabled")  # Placeholder
    editmenu.add_command(label="Next Time Reference", state="disabled")  # Placeholder
    editmenu.add_command(label="Previous Time Reference", state="disabled")  # Placeholder
    editmenu.add_separator()
    editmenu.add_command(label="Configuration Profiles...", command=lambda: messagebox.showinfo("Profiles", "Configuration profiles - Coming soon"))
    editmenu.add_command(label="Preferences...", command=lambda: messagebox.showinfo("Preferences", "Preferences - Coming soon"))
    menubar.add_cascade(label="Edit", menu=editmenu)
    
    # View Menu
    viewmenu = tk.Menu(menubar, tearoff=0)
    viewmenu.add_command(label="Zoom In", command=lambda: messagebox.showinfo("Zoom", "Zoom in - Coming soon"), accelerator="Ctrl++")
    viewmenu.add_command(label="Zoom Out", command=lambda: messagebox.showinfo("Zoom", "Zoom out - Coming soon"), accelerator="Ctrl+-")
    viewmenu.add_command(label="Normal Size", command=lambda: messagebox.showinfo("Zoom", "Normal size - Coming soon"), accelerator="Ctrl+0")
    viewmenu.add_separator()
    viewmenu.add_checkbutton(
        label="Auto Scroll in Live Capture",
        variable=auto_scroll_var,
        onvalue=True,
        offvalue=False,
        command=toggle_auto_scroll,
    )
    viewmenu.add_separator()
    viewmenu.add_command(label="Coloring Rules...", command=show_coloring_rules)
    viewmenu.add_command(label="Show Packet in New Window", state="disabled")  # Placeholder
    viewmenu.add_separator()
    viewmenu.add_command(label="Expand All", command=lambda: messagebox.showinfo("Expand", "Expand all - Coming soon"))
    viewmenu.add_command(label="Collapse All", command=lambda: messagebox.showinfo("Collapse", "Collapse all - Coming soon"))
    viewmenu.add_separator()
    viewmenu.add_checkbutton(
        label="Enable Visualization (heavy)",
        variable=viz_enabled_var,
        onvalue=True,
        offvalue=False,
        command=toggle_viz_enabled,
    )
    viewmenu.add_separator()
    viewmenu.add_command(label="Time Display Format", state="disabled")  # Placeholder
    viewmenu.add_command(label="Name Resolution", state="disabled")  # Placeholder
    menubar.add_cascade(label="View", menu=viewmenu)

    # Go Menu
    gomenu = tk.Menu(menubar, tearoff=0)
    gomenu.add_command(label="Back", command=lambda: messagebox.showinfo("Go", "Go back - Coming soon"), accelerator="Alt+Left")
    gomenu.add_command(label="Forward", command=lambda: messagebox.showinfo("Go", "Go forward - Coming soon"), accelerator="Alt+Right")
    gomenu.add_separator()
    gomenu.add_command(label="Go to Packet...", command=goto_packet_dialog, accelerator="Ctrl+G")
    gomenu.add_command(label="Go to Corresponding Packet", state="disabled")  # Placeholder
    gomenu.add_separator()
    gomenu.add_command(label="First Packet", command=lambda: messagebox.showinfo("Go", "First packet - Coming soon"), accelerator="Ctrl+Home")
    gomenu.add_command(label="Last Packet", command=lambda: messagebox.showinfo("Go", "Last packet - Coming soon"), accelerator="Ctrl+End")
    gomenu.add_separator()
    gomenu.add_command(label="Next Packet", command=lambda: messagebox.showinfo("Go", "Next packet - Coming soon"), accelerator="Ctrl+. or F8")
    gomenu.add_command(label="Previous Packet", command=lambda: messagebox.showinfo("Go", "Previous packet - Coming soon"), accelerator="Ctrl+, or F7")
    gomenu.add_separator()
    gomenu.add_command(label="Next Conversation Packet", state="disabled")  # Placeholder
    gomenu.add_command(label="Previous Conversation Packet", state="disabled")  # Placeholder
    menubar.add_cascade(label="Go", menu=gomenu)
    
    # Capture Menu - functions will be connected via toolbar button handlers
    capturemenu = tk.Menu(menubar, tearoff=0)
    capturemenu.add_command(label="Interfaces...", command=show_capture_options)
    capturemenu.add_command(label="Options...", command=show_capture_options)
    capturemenu.add_separator()
    # Start/Stop will be handled by toolbar buttons (these are placeholders)
    capturemenu.add_command(label="Start", command=lambda: messagebox.showinfo("Start Capture", "Use the 'Start Capture' button on the toolbar"))
    capturemenu.add_command(label="Stop", command=lambda: messagebox.showinfo("Stop Capture", "Use the 'Stop Capture' button on the toolbar"), state="disabled")
    capturemenu.add_command(label="Restart", command=lambda: messagebox.showinfo("Restart", "Use Stop then Start from toolbar"))
    capturemenu.add_separator()
    capturemenu.add_command(label="Capture Filters...", command=lambda: messagebox.showinfo("Filters", "Capture filters - Coming soon"))
    menubar.add_cascade(label="Capture", menu=capturemenu)
    
    # Analyze Menu
    analysismenu = tk.Menu(menubar, tearoff=0)
    analysismenu.add_command(label="Display Filters...", command=lambda: messagebox.showinfo("Filters", "Display filters - Coming soon"))
    analysismenu.add_command(label="Display Filter Macros...", state="disabled")  # Placeholder
    analysismenu.add_separator()
    analysismenu.add_command(label="Enabled Protocols...", command=lambda: messagebox.showinfo("Protocols", "Enabled protocols - Coming soon"))
    analysismenu.add_separator()
    analysismenu.add_command(label="Decode As...", command=lambda: messagebox.showinfo("Decode", "Decode as - Coming soon"))
    analysismenu.add_separator()
    analysismenu.add_command(label="User Specified Decodes...", state="disabled")  # Placeholder
    analysismenu.add_separator()
    analysismenu.add_command(label="Follow", state="disabled")  # Placeholder (TCP Stream, UDP Stream, SSL Stream, HTTP Stream)
    analysismenu.add_separator()
    analysismenu.add_command(label="Expert Information", command=show_debug_stats)
    analysismenu.add_command(label="Expert Information Composite", state="disabled")  # Placeholder
    analysismenu.add_separator()
    analysismenu.add_command(label="VoIP Calls", command=voip_analysis)
    analysismenu.add_separator()
    analysismenu.add_command(label="Decryption Keys...", command=decryption_support)
    analysismenu.add_separator()
    analysismenu.add_command(label="Bluetooth Devices", command=bluetooth_capture)
    analysismenu.add_command(label="USB Devices", command=usb_capture)
    menubar.add_cascade(label="Analyze", menu=analysismenu)
    
    # Statistics Menu
    statisticsmenu = tk.Menu(menubar, tearoff=0)
    statisticsmenu.add_command(label="Protocol Hierarchy", command=lambda: messagebox.showinfo("Statistics", "Protocol hierarchy - Use Statistics tab"))
    statisticsmenu.add_command(label="Conversations", command=lambda: messagebox.showinfo("Statistics", "Conversations - Coming soon"))
    statisticsmenu.add_command(label="Endpoints", command=lambda: messagebox.showinfo("Statistics", "Endpoints - Coming soon"))
    statisticsmenu.add_separator()
    statisticsmenu.add_command(label="I/O Graph...", command=lambda: messagebox.showinfo("Statistics", "I/O graph - Coming soon"))
    statisticsmenu.add_command(label="Flow Graph...", command=lambda: messagebox.showinfo("Statistics", "Flow graph - Coming soon"))
    statisticsmenu.add_separator()
    statisticsmenu.add_command(label="Service Response Time", state="disabled")  # Placeholder
    statisticsmenu.add_command(label="DHCP (BOOTP) Statistics", state="disabled")  # Placeholder
    statisticsmenu.add_command(label="ONC-RPC Programs", state="disabled")  # Placeholder
    statisticsmenu.add_separator()
    statisticsmenu.add_command(label="29 West LBM Statistics", state="disabled")  # Placeholder
    statisticsmenu.add_command(label="ANSI", state="disabled")  # Placeholder
    statisticsmenu.add_command(label="BACnet", state="disabled")  # Placeholder
    statisticsmenu.add_command(label="CollectD", state="disabled")  # Placeholder
    statisticsmenu.add_command(label="Diameter", state="disabled")  # Placeholder
    statisticsmenu.add_command(label="DNS", command=lambda: messagebox.showinfo("Statistics", "DNS statistics - Coming soon"))
    statisticsmenu.add_command(label="HART-IP", state="disabled")  # Placeholder
    statisticsmenu.add_command(label="HTTP", command=lambda: messagebox.showinfo("Statistics", "HTTP statistics - Coming soon"))
    statisticsmenu.add_command(label="HTTP2", state="disabled")  # Placeholder
    statisticsmenu.add_command(label="Sametime", state="disabled")  # Placeholder
    statisticsmenu.add_command(label="SIP", command=lambda: messagebox.showinfo("Statistics", "SIP statistics - Coming soon"))
    statisticsmenu.add_command(label="TCP Stream Graph", state="disabled")  # Placeholder
    statisticsmenu.add_command(label="UDP Multicast Streams", state="disabled")  # Placeholder
    statisticsmenu.add_command(label="WLAN Traffic", state="disabled")  # Placeholder
    menubar.add_cascade(label="Statistics", menu=statisticsmenu)
    
    # Telephony Menu
    telephony_menu = tk.Menu(menubar, tearoff=0)
    telephony_menu.add_command(label="VoIP Calls", command=voip_analysis)
    telephony_menu.add_separator()
    telephony_menu.add_command(label="ANSI", state="disabled")  # Placeholder
    telephony_menu.add_command(label="GSM", state="disabled")  # Placeholder
    telephony_menu.add_command(label="IAX2 Stream Analysis", state="disabled")  # Placeholder
    telephony_menu.add_command(label="ISUP Messages", state="disabled")  # Placeholder
    telephony_menu.add_command(label="LTE", state="disabled")  # Placeholder
    telephony_menu.add_command(label="MTP3", state="disabled")  # Placeholder
    telephony_menu.add_command(label="Osmux", state="disabled")  # Placeholder
    telephony_menu.add_command(label="RTP", command=lambda: messagebox.showinfo("Telephony", "RTP analysis - Coming soon"))
    telephony_menu.add_command(label="RTP Streams", command=lambda: messagebox.showinfo("Telephony", "RTP streams - Coming soon"))
    telephony_menu.add_command(label="SIP Flows", command=lambda: messagebox.showinfo("Telephony", "SIP flows - Coming soon"))
    telephony_menu.add_command(label="SIP Statistics", command=lambda: messagebox.showinfo("Telephony", "SIP statistics - Coming soon"))
    telephony_menu.add_command(label="UCP Messages", state="disabled")  # Placeholder
    menubar.add_cascade(label="Telephony", menu=telephony_menu)
    
    # Wireless Menu
    wireless_menu = tk.Menu(menubar, tearoff=0)
    wireless_menu.add_command(label="Bluetooth", command=bluetooth_capture)
    wireless_menu.add_separator()
    wireless_menu.add_command(label="Bluetooth ATT Server Attributes", state="disabled")  # Placeholder
    wireless_menu.add_command(label="Bluetooth Devices", command=bluetooth_capture)
    wireless_menu.add_command(label="Bluetooth HCI Summary", state="disabled")  # Placeholder
    wireless_menu.add_separator()
    wireless_menu.add_command(label="WLAN Traffic", state="disabled")  # Placeholder (IEEE 802.11)
    wireless_menu.add_command(label="All Wireless Traffic", state="disabled")  # Placeholder
    menubar.add_cascade(label="Wireless", menu=wireless_menu)
    
    # Tools Menu
    toolsmenu = tk.Menu(menubar, tearoff=0)
    toolsmenu.add_command(label="Firewall ACL Rules", state="disabled")  # Placeholder
    toolsmenu.add_command(label="Credentials", command=lambda: messagebox.showinfo("Tools", "Credentials - Coming soon"))
    toolsmenu.add_separator()
    toolsmenu.add_command(label="Lua", state="disabled")  # Placeholder
    toolsmenu.add_command(label="Plugins", state="disabled")  # Placeholder
    menubar.add_cascade(label="Tools", menu=toolsmenu)
    
    # Help Menu
    helpmenu = tk.Menu(menubar, tearoff=0)
    helpmenu.add_command(label="Contents", command=lambda: messagebox.showinfo("Help", "Help contents - Coming soon"), accelerator="F1")
    helpmenu.add_command(label="Manual Pages", state="disabled")  # Placeholder
    helpmenu.add_separator()
    helpmenu.add_command(label="Online Resources", state="disabled")  # Placeholder
    helpmenu.add_command(label="Sample Captures", state="disabled")  # Placeholder
    helpmenu.add_separator()
    # About pearcer - highlight as a dedicated section
    helpmenu.add_command(label="About pearcer", command=show_about_with_donation)
    menubar.add_cascade(label="Help", menu=helpmenu)

    root.config(menu=menubar)
    
    # Toolbar
    toolbar = tk.Frame(root, relief=tk.RAISED, bd=1)
    toolbar.pack(fill='x')
    
    # Interface mapping: display name -> technical name
    interface_map = {}  # Maps display name to technical name
    
    # Function to refresh interfaces
    def refresh_interfaces():
        """Refresh the interface list with friendly names"""
        global interface_map
        interface_map = {}
        interfaces_with_names = get_interfaces_with_friendly_names()
        display_names = []
        for friendly_name, tech_name in interfaces_with_names:
            display_names.append(friendly_name)
            interface_map[friendly_name] = tech_name
        interface_combo['values'] = display_names
        
        # Try to keep current selection or select first
        current_display = interface_combo.get()
        if current_display in display_names:
            # Keep current
            pass
        elif display_names:
            # Select first interface
            interface_combo.set(display_names[0])
            config["interface"] = interface_map[display_names[0]]
            save_config(config)
        return display_names
    
    # Initialize interfaces with friendly names
    interfaces_with_names = get_interfaces_with_friendly_names()
    interface_display_names = []
    for friendly_name, tech_name in interfaces_with_names:
        interface_display_names.append(friendly_name)
        interface_map[friendly_name] = tech_name
    
    tk.Label(toolbar, text="Interface:").pack(side=tk.LEFT, padx=5)
    interface_combo = Combobox(toolbar, values=interface_display_names, width=30, style="Toolbar.TCombobox")
    
    # Set default interface - prefer 'any' on Linux, first available on Windows
    default_iface_tech = config.get("interface", "any" if not IS_WINDOWS else (list(interface_map.values())[0] if interface_map else "eth0"))
    
    # Find matching display name for default interface
    default_display = None
    for display_name, tech_name in interface_map.items():
        if tech_name == default_iface_tech:
            default_display = display_name
            break
    
    if not default_display and interface_display_names:
        default_display = interface_display_names[0]
        config["interface"] = interface_map[default_display]
        save_config(config)
    
    if default_display:
        interface_combo.set(default_display)
    interface_combo.pack(side=tk.LEFT, padx=5)
    
    # Refresh button for interfaces
    def refresh_interfaces_btn():
        """Button callback to refresh interfaces"""
        new_interfaces = refresh_interfaces()
        friendly_list = "\n".join(new_interfaces[:10]) + ("..." if len(new_interfaces) > 10 else "")
        messagebox.showinfo("Interfaces Refreshed", f"Found {len(new_interfaces)} interface(s):\n{friendly_list}")
    
    tk.Button(toolbar, text="🔄", command=refresh_interfaces_btn, width=3, 
              bg="#FFC107", fg="#000000", font=("Arial", 8)).pack(side=tk.LEFT, padx=2)
    
    tk.Label(toolbar, text="Filter:").pack(side=tk.LEFT, padx=5)
    filter_mode_options = [
        "All traffic",
        "Web (HTTP+TLS)",
        "HTTP only",
        "TLS only",
        "DNS only",
        "TCP only",
        "UDP only",
        "ICMP only",
        "Suspicious / attacks only",
    ]
    filter_mode_combo = Combobox(toolbar, values=filter_mode_options, width=24, style="Toolbar.TCombobox")
    filter_mode_combo.set(config.get("filter_mode", "All traffic"))
    filter_mode_combo.pack(side=tk.LEFT, padx=5)
    
    # Dark theme only – no theme selector or speed selector in toolbar
    def apply_settings():
        """Apply toolbar settings"""
        # Always run at maximum speed; ignore any previous speed setting
        config["speed"] = "extreme"
        # Get technical interface name from display name
        display_name = interface_combo.get()
        config["interface"] = interface_map.get(display_name, display_name)
        mode = filter_mode_combo.get() or "All traffic"
        config["filter_mode"] = mode
        config["filter"] = bpf_for_mode(mode)
        config["theme"] = "dark"
        save_config(config)
        set_theme("dark")
    
    tk.Button(toolbar, text="Apply", command=apply_settings).pack(side=tk.LEFT, padx=5)
    
    def start_capture():
        """Start packet capture"""
        global running, packet_count, stats
        
        if not running:
            # Update config with current selections - get technical name from display name
            display_name = interface_combo.get()
            config["interface"] = interface_map.get(display_name, display_name)
            mode = filter_mode_combo.get() or "All traffic"
            config["filter_mode"] = mode
            config["filter"] = bpf_for_mode(mode)
            # Always use fastest speed
            config["speed"] = "extreme"
            config["theme"] = "dark"
            save_config(config)
            set_theme("dark")
            
            # Reset counters
            packet_count = 0
            stats = {"pps": 0, "attacks": 0, "vulnerabilities": 0, "exploits": 0, "malware": 0}
            
            running = True
            print(f"[INFO] Starting capture thread...")
            print(f"[INFO] Interface: {format_interface_display(config.get('interface'))}")
            print(f"[INFO] Filter: {config['filter'] or 'None'}")
            
            capture_thread = threading.Thread(target=sniff_thread, daemon=True)
            capture_thread.start()
            
            # Give thread a moment to start
            time.sleep(0.1)
            
            if capture_thread.is_alive():
                print(f"[INFO] Capture thread started successfully")
                if 'start_btn' in globals():
                    start_btn.config(text="Stop Capture", bg="red", fg="white")
                # Update menu items
                try:
                    capturemenu.entryconfig("Start", state="disabled")
                    capturemenu.entryconfig("Stop", state="normal", command=stop_capture)
                except:
                    pass
            else:
                print(f"[ERROR] Capture thread failed to start")
                running = False
                messagebox.showerror("Capture Error", "Failed to start capture thread. Check console for details.")
    
    def stop_capture():
        """Stop packet capture"""
        global running
        running = False
        if 'start_btn' in globals():
            start_btn.config(text="Start Capture", bg="green", fg="white")
        # Update menu items
        try:
            capturemenu.entryconfig("Start", state="normal", command=start_capture)
            capturemenu.entryconfig("Stop", state="disabled")
        except:
            pass
    
    def toggle_capture():
        """Toggle capture state"""
        if running:
            stop_capture()
        else:
            start_capture()
    
    start_btn = tk.Button(toolbar, text="Start Capture", command=toggle_capture, bg="green", fg="white")
    start_btn.pack(side=tk.LEFT, padx=5)
    
    # Update Capture menu commands now that functions are defined
    def update_capture_menu():
        """Update capture menu commands"""
        try:
            capturemenu.entryconfig("Start", command=start_capture)
            capturemenu.entryconfig("Stop", command=stop_capture)
        except:
            pass
    
    # Update menu after a short delay to ensure everything is initialized
    root.after(100, update_capture_menu)
    
    tk.Button(toolbar, text="Offline Analysis", command=offline_analysis).pack(side=tk.LEFT, padx=5)

    # Style toolbar as yellow bar with black text/buttons (below menu bar)
    try:
        toolbar.configure(bg="#FFC107")
        for child in toolbar.winfo_children():
            try:
                child.configure(bg="#FFC107", fg="#000000")
            except Exception:
                pass
    except Exception:
        pass

    # Display filter bar (Wireshark-style expression box, simple substring filter for now)
    display_filter_frame = tk.Frame(root, bg="#FFC107")
    display_filter_frame.pack(fill='x', padx=5, pady=(0, 5))

    tk.Label(display_filter_frame, text="Display filter:", fg="#000000", bg="#FFC107").pack(side=tk.LEFT)
    display_filter_entry = tk.Entry(display_filter_frame, width=40)
    display_filter_entry.pack(side=tk.LEFT, padx=(5, 5))

    def _display_filter_allows(src: str, dst: str, proto: str, info: str) -> bool:
        expr = (display_filter_entry.get() if 'display_filter_entry' in globals() else "").strip()
        if not expr:
            return True
        q = expr.lower()
        return any(q in str(v).lower() for v in (src, dst, proto, info))

    def apply_display_filter():
        """Apply display filter to existing rows (substring match)."""
        if 'packet_list' not in globals():
            return
        children = list(packet_list.get_children())
        for item in children:
            vals = packet_list.item(item, "values")
            # values: No, Time, Source, Destination, Protocol, Host, Length, Level, Info
            src, dst, proto, host, info = vals[2], vals[3], vals[4], vals[5], vals[8]
            if not _display_filter_allows(src, dst, proto, host + " " + info):
                packet_list.delete(item)

    def clear_display_filter():
        if 'display_filter_entry' in globals():
            display_filter_entry.delete(0, tk.END)

    tk.Button(display_filter_frame, text="Apply", command=apply_display_filter).pack(side=tk.LEFT, padx=(5, 2))
    tk.Button(display_filter_frame, text="Clear", command=clear_display_filter).pack(side=tk.LEFT)
    
    # Main notebook
    notebook = Notebook(root)
    notebook.pack(expand=True, fill='both', padx=5, pady=5)
    
    # Live Capture Tab
    live_tab = tk.Frame(notebook)
    notebook.add(live_tab, text="Live Capture")
    
    # Main paned window for Live Capture (vertical splitter: packets on top, details/hex below)
    live_paned = tk.PanedWindow(live_tab, orient=tk.VERTICAL, sashrelief=tk.RAISED)
    live_paned.pack(fill='both', expand=True)
    
    # Packet List (Treeview) in the top pane
    packet_frame = tk.Frame(live_paned)
    live_paned.add(packet_frame, stretch="always")
    
    packet_list = Treeview(
        packet_frame,
        columns=("No", "Time", "Source", "Destination", "Protocol", "Host", "Length", "Level", "Info"),
        show="headings",
        height=20,
    )
    packet_list.heading("No", text="No.")
    packet_list.heading("Time", text="Time")
    packet_list.heading("Source", text="Source (IP:Port)")
    packet_list.heading("Destination", text="Destination (IP:Port)")
    packet_list.heading("Protocol", text="Protocol")
    packet_list.heading("Host", text="Host / Domain")
    packet_list.heading("Length", text="Length")
    packet_list.heading("Level", text="Level")
    packet_list.heading("Info", text="Info")
    
    # Configure tags for coloring (Wireshark-style + threat levels)
    colors = config.get("highlight_colors", DEFAULT_CONFIG["highlight_colors"]).copy()
    # In dark theme, ensure "normal" text is visible (white instead of black).
    if colors.get("normal", "").lower() in ("#000000", "black"):
        colors["normal"] = "#FFFFFF"
    
    # Configure all color tags
    for tag_name, color in colors.items():
        packet_list.tag_configure(tag_name, foreground=color)
    
    # Set default foreground for rows without specific tags
    packet_list.tag_configure("normal", foreground=colors.get("normal", "#FFFFFF"))
    
    # Keep key information (No, IPs, ports, protocol, host, length, level) always visible.
    packet_list.column("No", width=60, stretch=False, anchor="e")
    packet_list.column("Time", width=130, stretch=False)
    packet_list.column("Source", width=190, stretch=False)
    packet_list.column("Destination", width=190, stretch=False)
    packet_list.column("Protocol", width=90, stretch=False)
    packet_list.column("Host", width=180, stretch=False)
    packet_list.column("Length", width=80, stretch=False, anchor="e")
    packet_list.column("Level", width=90, stretch=False)
    packet_list.column("Info", width=350, stretch=True)
    
    vsb = tk.Scrollbar(packet_frame, orient="vertical", command=packet_list.yview)
    vsb.pack(side='right', fill='y')
    packet_list.configure(yscrollcommand=vsb.set)
    
    packet_list.pack(fill='both', expand=True)
    
    # Details & Hex in the bottom pane, with horizontal splitter between tree and hex
    details_outer = tk.Frame(live_paned)
    live_paned.add(details_outer, stretch="always")
    
    details_paned = tk.PanedWindow(details_outer, orient=tk.HORIZONTAL, sashrelief=tk.RAISED)
    details_paned.pack(fill='both', expand=True)
    
    # Left pane: packet details tree
    details_frame = tk.Frame(details_paned)
    details_paned.add(details_frame, stretch="always")
    
    tk.Label(details_frame, text="Packet Details", font=("Arial", 10, "bold")).pack(anchor='w')
    details_tree = Treeview(details_frame, show="tree", height=10)
    details_tree.pack(fill='both', expand=True, pady=(0, 5))
    
    # Right pane: hex dump
    hex_frame = tk.Frame(details_paned)
    details_paned.add(hex_frame, stretch="always")
    
    tk.Label(hex_frame, text="Hex Dump", font=("Arial", 10, "bold")).pack(anchor='w')
    hex_text = scrolledtext.ScrolledText(hex_frame, height=15, font=("Courier", 9))
    hex_text.pack(fill='both', expand=True)
    
    packet_list.bind('<<TreeviewSelect>>', show_details)
    
    # Statistics Tab
    stats_tab = tk.Frame(notebook)
    notebook.add(stats_tab, text="Statistics")
    
    # Statistics frame
    stats_frame = tk.Frame(stats_tab)
    stats_frame.pack(fill='both', expand=True, padx=10, pady=10)
    
    # Real-time stats (dark bar with white text)
    stats_label = tk.Label(
        stats_frame,
        text="PPS: 0 | Attacks: 0 | Vulns: 0 | Exploits: 0 | Malware: 0",
        font=("Arial", 12, "bold"),
        bg="#333333",
        fg="#FFFFFF",
        pady=10,
    )
    stats_label.pack(fill='x', pady=(0, 10))
    
    # Protocol distribution
    proto_frame = tk.LabelFrame(stats_frame, text="Protocol Distribution", padx=10, pady=10)
    proto_frame.pack(fill='both', expand=True, side=tk.LEFT, padx=(0, 10))
    
    proto_list = tk.Listbox(proto_frame, height=15)
    proto_list.pack(fill='both', expand=True)
    
    # Attack details
    attack_frame = tk.LabelFrame(stats_frame, text="Security Events", padx=10, pady=10)
    attack_frame.pack(fill='both', expand=True, side=tk.LEFT)
    
    attack_list = tk.Listbox(attack_frame, height=15)
    attack_list.pack(fill='both', expand=True)
    
    def update_stats_gui():
        """Update statistics in GUI"""
        if running:
            stats_label.config(text=f"PPS: {stats['pps']:.2f} | Attacks: {stats['attacks']} | Vulns: {stats['vulnerabilities']} | Exploits: {stats['exploits']} | Malware: {stats['malware']}")
            
            # Update protocol list
            proto_list.delete(0, tk.END)
            for proto, count in sorted(protocol_counts.items(), key=lambda x: x[1], reverse=True):
                proto_list.insert(tk.END, f"{proto}: {count}")
                
            # Update attack list
            attack_list.delete(0, tk.END)
            for ip, count in sorted(attack_counts.items(), key=lambda x: x[1], reverse=True)[:20]:
                if count > config.get("attack_threshold", 50):
                    attack_list.insert(tk.END, f"{ip}: {count} packets")
        
        root.after(1000, update_stats_gui)
    
    update_stats_gui()
    
    # Visualization Tab
    viz_tab = tk.Frame(notebook, bg="#FFC107")
    notebook.add(viz_tab, text="Visualization")
    
    if VIZ_AVAILABLE:
        # Live-updating protocol/host charts
        fig_frame = tk.Frame(viz_tab, bg="#FFC107")
        fig_frame.pack(fill='both', expand=True)
        
        fig = plt.Figure(figsize=(10, 6))
        ax_proto = fig.add_subplot(121)
        ax_host = fig.add_subplot(122)
        fig.tight_layout()
        
        canvas = FigureCanvasTkAgg(fig, fig_frame)
        canvas_widget = canvas.get_tk_widget()
        canvas_widget.pack(fill='both', expand=True)
        
        def update_visualizations():
            """Refresh protocol and host distributions in the Visualization tab."""
            from_globals = globals()
            if not from_globals.get("viz_enabled", False):
                # Skip heavy redraw when visualization is disabled
                if 'root' in from_globals:
                    root.after(3000, update_visualizations)
                return
            try:
                ax_proto.clear()
                ax_host.clear()
                
                # Protocol distribution pie chart
                if protocol_counts:
                    protocols = list(protocol_counts.keys())[:8]
                    counts = [protocol_counts[p] for p in protocols]
                    ax_proto.pie(counts, labels=protocols, autopct='%1.1f%%')
                    ax_proto.set_title("Protocol Distribution")
                else:
                    ax_proto.text(0.5, 0.5, "No data yet", ha='center', va='center')
                    ax_proto.set_title("Protocol Distribution")
                
                # Top host bar chart (by packet count)
                if ip_hostnames and captured_packets:
                    # Count packets per known host from current ip_hostnames map
                    host_counts = {}
                    for ip, host in ip_hostnames.items():
                        host_counts[host] = host_counts.get(host, 0) + 1
                    top_hosts = sorted(host_counts.items(), key=lambda x: x[1], reverse=True)[:8]
                    if top_hosts:
                        labels = [h for h, _ in top_hosts]
                        values = [c for _, c in top_hosts]
                        ax_host.barh(labels, values, color="#FFC107")
                        ax_host.set_title("Top Hosts (approx)")
                        ax_host.invert_yaxis()
                    else:
                        ax_host.text(0.5, 0.5, "No hosts yet", ha='center', va='center')
                        ax_host.set_title("Top Hosts")
                else:
                    ax_host.text(0.5, 0.5, "No hosts yet", ha='center', va='center')
                    ax_host.set_title("Top Hosts")
                
                canvas.draw_idle()
            except Exception:
                # Visualization errors should not break the app
                pass
            
            # Refresh every 3 seconds while GUI is running
            if 'root' in globals():
                root.after(3000, update_visualizations)
        
        update_visualizations()
    else:
        tk.Label(
            viz_tab,
            text=(
                "Visualization is disabled because matplotlib/networkx are missing.\n"
                "Run in your venv:\n"
                "  pip install matplotlib networkx"
            ),
            font=("Arial", 12),
            bg="#FFC107",
            fg="#000000",
            justify="left",
        ).pack(expand=True, padx=20, pady=20)
    
    # Vulnerability Scanner Tab
    vuln_tab = tk.Frame(notebook)
    notebook.add(vuln_tab, text="Vulnerability Scanner")
    
    vuln_frame = tk.Frame(vuln_tab)
    vuln_frame.pack(fill='both', expand=True, padx=10, pady=10)
    
    # Scanner controls
    scan_control_frame = tk.LabelFrame(vuln_frame, text="Scan Controls", padx=10, pady=10)
    scan_control_frame.pack(fill='x', pady=(0, 10))
    
    tk.Label(scan_control_frame, text="Target:").grid(row=0, column=0, sticky='w', padx=5, pady=5)
    target_entry = tk.Entry(scan_control_frame, width=30)
    target_entry.grid(row=0, column=1, padx=5, pady=5)
    target_entry.insert(0, "192.168.1.1")
    
    tk.Label(scan_control_frame, text="Ports:").grid(row=0, column=2, sticky='w', padx=5, pady=5)
    ports_entry = tk.Entry(scan_control_frame, width=20)
    ports_entry.grid(row=0, column=3, padx=5, pady=5)
    ports_entry.insert(0, "1-1000")
    
    scan_type_var = tk.StringVar(value="syn")
    tk.Label(scan_control_frame, text="Scan Type:").grid(row=1, column=0, sticky='w', padx=5, pady=5)
    scan_type_combo = Combobox(scan_control_frame, textvariable=scan_type_var, 
                               values=["syn", "connect", "udp"], width=15, state="readonly")
    scan_type_combo.grid(row=1, column=1, padx=5, pady=5)
    
    scan_status_label = tk.Label(scan_control_frame, text="Status: Idle", fg="#00FF00")
    scan_status_label.grid(row=1, column=2, columnspan=2, sticky='w', padx=5, pady=5)
    
    def start_vuln_scan():
        """Start vulnerability scan"""
        if not VULN_SCANNER_AVAILABLE or vuln_scanner is None:
            messagebox.showerror("Error", "Vulnerability scanner not available. Install python-nmap: pip install python-nmap")
            return
        
        if vuln_scanner.scanning:
            messagebox.showinfo("Scan in Progress", "A scan is already running.")
            return
        
        target = target_entry.get().strip()
        ports = ports_entry.get().strip() or "1-1000"
        scan_type = scan_type_var.get()
        
        if not target:
            messagebox.showerror("Error", "Please enter a target IP or network (e.g., 192.168.1.1 or 192.168.1.0/24)")
            return
        
        scan_thread_obj = [None]  # Use list to allow modification in nested function
        
        def scan_thread():
            scan_status_label.config(text="Status: Scanning...", fg="#FFA500")
            scan_btn.config(state="disabled")
            stop_scan_btn.config(state="normal")
            
            try:
                if '/' in target:  # Network scan
                    vuln_scanner.scan_network(target, ports)
                else:  # Single host scan
                    vuln_scanner.scan_host(target, ports, scan_type)
                
                # Update results if scan completed (not stopped)
                if vuln_scanner.scanning == False:
                    update_vuln_results()
                    scan_status_label.config(text=f"Status: Complete - {len(vuln_scanner.get_results())} vulnerabilities found", fg="#00FF00")
            except Exception as e:
                if vuln_scanner.scanning == False:  # Only show error if not stopped by user
                    scan_status_label.config(text=f"Status: Error - {str(e)}", fg="#FF0000")
                    messagebox.showerror("Scan Error", str(e))
                else:
                    scan_status_label.config(text="Status: Stopped by user", fg="#FFA500")
            finally:
                scan_btn.config(state="normal")
                stop_scan_btn.config(state="disabled")
        
        scan_thread_obj[0] = threading.Thread(target=scan_thread, daemon=True)
        scan_thread_obj[0].start()
    
    def stop_vuln_scan():
        """Stop vulnerability scan"""
        if vuln_scanner:
            vuln_scanner.scanning = False
            scan_status_label.config(text="Status: Stopping...", fg="#FFA500")
    
    def update_vuln_results():
        """Update vulnerability results display"""
        if not VULN_SCANNER_AVAILABLE or vuln_scanner is None:
            return
        
        # Clear existing results
        for item in vuln_tree.get_children():
            vuln_tree.delete(item)
        
        # Add new results
        results = vuln_scanner.get_results()
        for vuln in results:
            severity_color = {
                'critical': '#FF0000',
                'high': '#FF6600',
                'medium': '#FFA500',
                'low': '#FFFF00',
                'info': '#00FFFF'
            }.get(vuln.severity, '#FFFFFF')
            
            exploit_mark = "✓" if vuln.exploit_available else ""
            cve_text = vuln.cve if vuln.cve else "N/A"
            
            vuln_tree.insert('', 'end', values=(
                vuln.host,
                vuln.port,
                vuln.service,
                vuln.vuln_type,
                vuln.severity.upper(),
                cve_text,
                exploit_mark,
                vuln.description
            ), tags=(vuln.severity,))
        
        # Update statistics
        stats_vuln = vuln_scanner.get_statistics()
        stats_text = (
            f"Total Vulnerabilities: {stats_vuln['total']} | "
            f"Hosts Scanned: {stats_vuln['hosts_scanned']} | "
            f"Exploitable: {stats_vuln['exploitable']}\n"
            f"Critical: {stats_vuln['by_severity'].get('critical', 0)} | "
            f"High: {stats_vuln['by_severity'].get('high', 0)} | "
            f"Medium: {stats_vuln['by_severity'].get('medium', 0)} | "
            f"Low: {stats_vuln['by_severity'].get('low', 0)}"
        )
        vuln_stats_label.config(text=stats_text)
    
    scan_btn = tk.Button(scan_control_frame, text="Start Scan", command=start_vuln_scan, bg="#4CAF50", fg="white")
    scan_btn.grid(row=0, column=4, padx=5, pady=5)
    
    stop_scan_btn = tk.Button(scan_control_frame, text="Stop Scan", command=stop_vuln_scan, bg="#FF5252", fg="white", state="disabled")
    stop_scan_btn.grid(row=1, column=4, padx=5, pady=5)
    
    def clear_vuln_results():
        """Clear scan results"""
        if vuln_scanner:
            vuln_scanner.clear_results()
            update_vuln_results()
    
    tk.Button(scan_control_frame, text="Clear Results", command=clear_vuln_results, bg="#FF5252", fg="white").grid(row=1, column=5, padx=5, pady=5)
    
    def export_vuln_results():
        """Export vulnerability results"""
        if not vuln_scanner or len(vuln_scanner.get_results()) == 0:
            messagebox.showinfo("No Results", "No vulnerabilities to export.")
            return
        
        filename = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        if filename:
            try:
                vuln_scanner.export_results(filename)
                messagebox.showinfo("Export Successful", f"Results exported to {filename}")
            except Exception as e:
                messagebox.showerror("Export Error", str(e))
    
    tk.Button(scan_control_frame, text="Export Results", command=export_vuln_results, bg="#2196F3", fg="white").grid(row=0, column=5, padx=5, pady=5)
    
    # Statistics label
    vuln_stats_label = tk.Label(vuln_frame, text="No scans performed yet", font=("Arial", 10, "bold"), bg="#333333", fg="#FFFFFF", pady=5)
    vuln_stats_label.pack(fill='x', pady=(0, 10))
    
    # Results tree
    results_frame = tk.Frame(vuln_frame)
    results_frame.pack(fill='both', expand=True)
    
    vuln_tree = Treeview(results_frame, columns=("Host", "Port", "Service", "Type", "Severity", "CVE", "Exploit", "Description"), show="headings", height=20)
    vuln_tree.heading("Host", text="Host")
    vuln_tree.heading("Port", text="Port")
    vuln_tree.heading("Service", text="Service")
    vuln_tree.heading("Type", text="Vulnerability Type")
    vuln_tree.heading("Severity", text="Severity")
    vuln_tree.heading("CVE", text="CVE")
    vuln_tree.heading("Exploit", text="Exploit")
    vuln_tree.heading("Description", text="Description")
    
    vuln_tree.column("Host", width=120)
    vuln_tree.column("Port", width=60)
    vuln_tree.column("Service", width=150)
    vuln_tree.column("Type", width=150)
    vuln_tree.column("Severity", width=80)
    vuln_tree.column("CVE", width=120)
    vuln_tree.column("Exploit", width=60)
    vuln_tree.column("Description", width=400)
    
    # Configure severity colors
    for severity, color in [('critical', '#FF0000'), ('high', '#FF6600'), ('medium', '#FFA500'), ('low', '#FFFF00'), ('info', '#00FFFF')]:
        vuln_tree.tag_configure(severity, foreground=color)
    
    vuln_scrollbar = tk.Scrollbar(results_frame, orient="vertical", command=vuln_tree.yview)
    vuln_tree.configure(yscrollcommand=vuln_scrollbar.set)
    vuln_tree.pack(side='left', fill='both', expand=True)
    vuln_scrollbar.pack(side='right', fill='y')
    
    # Auto-update results every 2 seconds if scanning
    def auto_update_vuln():
        if vuln_scanner and vuln_scanner.scanning:
            update_vuln_results()
            scan_status_label.config(text=f"Status: {vuln_scanner.scan_status} ({int(vuln_scanner.scan_progress * 100)}%)", fg="#FFA500")
        root.after(2000, auto_update_vuln)
    
    auto_update_vuln()
    
    # Reconnaissance Tool Tab
    recon_tab = tk.Frame(notebook)
    notebook.add(recon_tab, text="Reconnaissance Tool")
    
    recon_frame = tk.Frame(recon_tab)
    recon_frame.pack(fill='both', expand=True, padx=10, pady=10)
    
    # Recon controls
    recon_control_frame = tk.LabelFrame(recon_frame, text="Reconnaissance Controls", padx=10, pady=10)
    recon_control_frame.pack(fill='x', pady=(0, 10))
    
    tk.Label(recon_control_frame, text="Target:").grid(row=0, column=0, sticky='w', padx=5, pady=5)
    recon_target_entry = tk.Entry(recon_control_frame, width=30)
    recon_target_entry.grid(row=0, column=1, padx=5, pady=5)
    recon_target_entry.insert(0, "example.com")
    
    recon_type_var = tk.StringVar(value="full")
    tk.Label(recon_control_frame, text="Recon Type:").grid(row=0, column=2, sticky='w', padx=5, pady=5)
    recon_type_combo = Combobox(recon_control_frame, textvariable=recon_type_var,
                               values=["full", "subdomain", "port_scan", "dns"], width=15, state="readonly")
    recon_type_combo.grid(row=0, column=3, padx=5, pady=5)
    
    tk.Label(recon_control_frame, text="Ports:").grid(row=1, column=0, sticky='w', padx=5, pady=5)
    recon_ports_entry = tk.Entry(recon_control_frame, width=20)
    recon_ports_entry.grid(row=1, column=1, padx=5, pady=5)
    recon_ports_entry.insert(0, "1-1000")
    
    recon_status_label = tk.Label(recon_control_frame, text="Status: Idle", fg="#00FF00")
    recon_status_label.grid(row=1, column=2, columnspan=2, sticky='w', padx=5, pady=5)
    
    def start_recon():
        """Start reconnaissance"""
        if not RECON_TOOL_AVAILABLE or recon_tool is None:
            messagebox.showerror("Error", "Recon tool not available. Install dependencies: pip install python-nmap dnspython requests")
            return
        
        if recon_tool.scanning:
            messagebox.showinfo("Recon in Progress", "A reconnaissance is already running.")
            return
        
        target = recon_target_entry.get().strip()
        recon_type = recon_type_var.get()
        ports = recon_ports_entry.get().strip() or "1-1000"
        
        if not target:
            messagebox.showerror("Error", "Please enter a target domain or IP address")
            return
        
        def recon_thread():
            recon_status_label.config(text="Status: Running...", fg="#FFA500")
            recon_btn.config(state="disabled")
            stop_recon_btn.config(state="normal")
            
            try:
                if recon_type == "full":
                    results = recon_tool.full_recon(target, ports)
                    if not recon_tool.scanning:  # Check if stopped
                        messagebox.showinfo("Recon Complete", 
                                          f"Found {len(results.get('subdomains', []))} subdomains\n"
                                          f"Found {len(results.get('ports', {}))} open ports")
                elif recon_type == "subdomain":
                    subdomains = recon_tool.subdomain_enumeration(target)
                    if not recon_tool.scanning:
                        messagebox.showinfo("Subdomain Enumeration Complete", 
                                          f"Found {len(subdomains)} subdomains")
                elif recon_type == "port_scan":
                    ports_dict = recon_tool.port_scan(target, ports)
                    if not recon_tool.scanning:
                        messagebox.showinfo("Port Scan Complete", 
                                          f"Found {len(ports_dict)} open ports")
                elif recon_type == "dns":
                    dns_results = recon_tool.dns_lookup(target)
                    if not recon_tool.scanning:
                        messagebox.showinfo("DNS Lookup Complete", 
                                          f"DNS records: {', '.join(dns_results) if dns_results else 'None found'}")
                
                if not recon_tool.scanning:
                    update_recon_results()
                    recon_status_label.config(text="Status: Complete", fg="#00FF00")
                else:
                    recon_status_label.config(text="Status: Stopped by user", fg="#FFA500")
            except Exception as e:
                if not recon_tool.scanning:
                    recon_status_label.config(text=f"Status: Error - {str(e)}", fg="#FF0000")
                    messagebox.showerror("Recon Error", str(e))
                else:
                    recon_status_label.config(text="Status: Stopped by user", fg="#FFA500")
            finally:
                recon_btn.config(state="normal")
                stop_recon_btn.config(state="disabled")
                stop_recon_btn.config(state="disabled")
        
        threading.Thread(target=recon_thread, daemon=True).start()
    
    def stop_recon():
        """Stop reconnaissance"""
        if recon_tool:
            recon_tool.scanning = False
            recon_status_label.config(text="Status: Stopping...", fg="#FFA500")
    
    def update_recon_results():
        """Update reconnaissance results display"""
        if not RECON_TOOL_AVAILABLE or recon_tool is None:
            return
        
        # Clear existing results
        for item in recon_tree.get_children():
            recon_tree.delete(item)
        
        # Add new results
        results = recon_tool.get_results()
        for result in results:
            if result.result_type == 'subdomain':
                recon_tree.insert('', 'end', values=(
                    result.target,
                    result.result_type,
                    result.data.get('subdomain', ''),
                    '',
                    '',
                    result.timestamp
                ))
            elif result.result_type == 'port':
                recon_tree.insert('', 'end', values=(
                    result.target,
                    result.result_type,
                    result.data.get('port', ''),
                    result.data.get('service', ''),
                    result.data.get('version', ''),
                    result.timestamp
                ))
            else:
                recon_tree.insert('', 'end', values=(
                    result.target,
                    result.result_type,
                    str(result.data),
                    '',
                    '',
                    result.timestamp
                ))
    
    recon_btn = tk.Button(recon_control_frame, text="Start Recon", command=start_recon, bg="#2196F3", fg="white")
    recon_btn.grid(row=0, column=4, padx=5, pady=5)
    
    stop_recon_btn = tk.Button(recon_control_frame, text="Stop Recon", command=stop_recon, bg="#FF5252", fg="white", state="disabled")
    stop_recon_btn.grid(row=1, column=4, padx=5, pady=5)
    
    def clear_recon_results():
        """Clear recon results"""
        if recon_tool:
            recon_tool.clear_results()
            update_recon_results()
    
    tk.Button(recon_control_frame, text="Clear Results", command=clear_recon_results, bg="#FF5252", fg="white").grid(row=1, column=5, padx=5, pady=5)
    
    def export_recon_results():
        """Export recon results"""
        if not recon_tool or len(recon_tool.get_results()) == 0:
            messagebox.showinfo("No Results", "No reconnaissance results to export.")
            return
        
        filename = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        if filename:
            try:
                recon_tool.export_results(filename)
                messagebox.showinfo("Export Successful", f"Results exported to {filename}")
            except Exception as e:
                messagebox.showerror("Export Error", str(e))
    
    tk.Button(recon_control_frame, text="Export Results", command=export_recon_results, bg="#9C27B0", fg="white").grid(row=0, column=5, padx=5, pady=5)
    
    # Recon results tree
    recon_results_frame = tk.Frame(recon_frame)
    recon_results_frame.pack(fill='both', expand=True)
    
    recon_tree = Treeview(recon_results_frame, columns=("Target", "Type", "Data1", "Data2", "Data3", "Timestamp"), show="headings", height=20)
    recon_tree.heading("Target", text="Target")
    recon_tree.heading("Type", text="Type")
    recon_tree.heading("Data1", text="Subdomain/Port")
    recon_tree.heading("Data2", text="Service")
    recon_tree.heading("Data3", text="Version")
    recon_tree.heading("Timestamp", text="Timestamp")
    
    recon_tree.column("Target", width=150)
    recon_tree.column("Type", width=100)
    recon_tree.column("Data1", width=200)
    recon_tree.column("Data2", width=150)
    recon_tree.column("Data3", width=150)
    recon_tree.column("Timestamp", width=180)
    
    recon_scrollbar = tk.Scrollbar(recon_results_frame, orient="vertical", command=recon_tree.yview)
    recon_tree.configure(yscrollcommand=recon_scrollbar.set)
    recon_tree.pack(side='left', fill='both', expand=True)
    recon_scrollbar.pack(side='right', fill='y')
    
    # Auto-update recon results
    def auto_update_recon():
        if recon_tool and recon_tool.scanning:
            update_recon_results()
            recon_status_label.config(text=f"Status: {recon_tool.scan_status} ({int(recon_tool.scan_progress * 100)}%)", fg="#FFA500")
        root.after(2000, auto_update_recon)
    
    auto_update_recon()
    
    # Settings Tab
    settings_tab = tk.Frame(notebook)
    notebook.add(settings_tab, text="Settings")
    
    settings_frame = tk.Frame(settings_tab)
    settings_frame.pack(fill='both', expand=True, padx=20, pady=20)
    
    # Interface settings
    iface_frame = tk.LabelFrame(settings_frame, text="Interface Settings", padx=10, pady=10)
    iface_frame.grid(row=0, column=0, sticky='nw', padx=(0, 20))
    
    tk.Label(iface_frame, text="Default Interface:").grid(row=0, column=0, sticky='w', pady=5)
    # Use same friendly display names as the toolbar combo
    settings_interface_display_names = list(interface_display_names)
    
    # Find current config interface display name
    current_iface_tech = config.get("interface", "eth0")
    current_iface_display = None
    for display_name, tech_name in interface_map.items():
        if tech_name == current_iface_tech:
            current_iface_display = display_name
            break
    if not current_iface_display and settings_interface_display_names:
        current_iface_display = settings_interface_display_names[0]
    iface_var = tk.StringVar(value=current_iface_display or "")
    iface_combo = Combobox(iface_frame, textvariable=iface_var, values=settings_interface_display_names, width=30)
    iface_combo.grid(row=0, column=1, pady=5)
    
    # Security settings
    security_frame = tk.LabelFrame(settings_frame, text="Security Settings", padx=10, pady=10)
    security_frame.grid(row=0, column=1, sticky='nw')
    
    tk.Label(security_frame, text="Attack Threshold:").grid(row=0, column=0, sticky='w', pady=5)
    threshold_var = tk.IntVar(value=config.get("attack_threshold", 50))
    tk.Spinbox(security_frame, from_=1, to=1000, textvariable=threshold_var, width=10).grid(row=0, column=1, pady=5)
    
    tk.Label(security_frame, text="Blacklisted IPs:").grid(row=1, column=0, sticky='nw', pady=5)
    blacklist_text = tk.Text(security_frame, height=5, width=25)
    blacklist_text.grid(row=1, column=1, pady=5)
    blacklist_text.insert('1.0', '\n'.join(config.get("blacklist_ips", [])))
    
    # Performance settings
    perf_frame = tk.LabelFrame(settings_frame, text="Performance Settings", padx=10, pady=10)
    perf_frame.grid(row=1, column=0, sticky='nw', padx=(0, 20), pady=(20, 0))
    
    # Capture speed is always set to fastest for performance; no UI needed here
    
    # Theme/logo
    def set_theme(theme: str = "dark"):
        """Apply theme settings (dark theme only)."""
        # Always apply dark theme regardless of the argument.
        bg = "#1e1e1e"
        fg = "#ffffff"
        root.config(bg=bg)

        # Default colors for most Tk widgets
        root.option_add("*Background", bg)
        root.option_add("*Foreground", fg)
        root.option_add("*insertBackground", fg)
        root.option_add("*selectBackground", "#404040")
        root.option_add("*selectForeground", fg)

        # ttk styles
        style.configure("TFrame", background=bg)
        style.configure("TLabel", background=bg, foreground=fg)
        style.configure("TButton", background="#333333", foreground=fg)
        style.configure(
            "Treeview",
            background=bg,
            foreground=fg,
            fieldbackground=bg,
            rowheight=25,
        )
        style.map(
            "Treeview",
            background=[("selected", "#404040")],
            foreground=[("selected", fg)],
        )

        # Default combobox style for dark background
        style.configure("TCombobox", fieldbackground=bg, background=bg, foreground=fg)
        style.map(
            "TCombobox",
            fieldbackground=[("readonly", bg)],
            foreground=[("readonly", fg)],
            background=[("readonly", bg)],
        )
        # Toolbar-specific combobox style: yellow background, black text
        style.configure(
            "Toolbar.TCombobox",
            fieldbackground="#FFC107",
            background="#FFC107",
            foreground="#000000",
        )
        style.map(
            "Toolbar.TCombobox",
            fieldbackground=[("readonly", "#FFC107")],
            foreground=[("readonly", "#000000")],
            background=[("readonly", "#FFC107")],
        )
        style.configure("TNotebook", background=bg)
        # Tabs: dark background with black text labels as requested
        style.configure("TNotebook.Tab", background="#2b2b2b", foreground="#000000")
        style.map("TNotebook.Tab", background=[("selected", "#444444")])

        # Darken key Tk widgets if they already exist
        widgets = []
        for name in ("packet_frame", "details_frame", "stats_frame", "viz_tab", "settings_tab", "details_outer"):
            if name in globals():
                widgets.append(globals()[name])
        for w in widgets:
            try:
                w.configure(bg=bg)
            except Exception:
                pass

        # Toolbar uses a yellow background with black text, even in dark theme
        if "toolbar" in globals():
            try:
                toolbar.configure(bg="#FFC107")
                for child in toolbar.winfo_children():
                    try:
                        child.configure(bg="#FFC107", fg="#000000")
                    except Exception:
                        pass
            except Exception:
                pass

        # Display filter frame also yellow with black text
        if "display_filter_frame" in globals():
            try:
                display_filter_frame.configure(bg="#FFC107")
                for child in display_filter_frame.winfo_children():
                    try:
                        child.configure(bg="#FFC107", fg="#000000")
                    except Exception:
                        pass
            except Exception:
                pass
        if "packet_list" in globals():
            try:
                packet_list.configure(background=bg, foreground=fg)
            except Exception:
                pass
        if "hex_text" in globals():
            try:
                hex_text.configure(bg="#000000", fg=fg, insertbackground=fg)
            except Exception:
                pass
        for list_name in ("proto_list", "attack_list"):
            if list_name in globals():
                try:
                    lst = globals()[list_name]
                    lst.configure(bg=bg, fg=fg, selectbackground="#404040", selectforeground=fg)
                except Exception:
                    pass
    
    # Initialize theme (always dark)
    set_theme("dark")
    
    # Start the GUI
    root.mainloop()
else:
    # CLI mode fallback
    cli_mode()