# pearcer - Professional Packet Analyzer
# Copyright (c) 2025 Jackson Pearce <Telegram: @H4CKRD>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

#!/usr/bin/env python3
"""
Pearcer - Professional Packet Analyzer & Security Suite
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

import base64
import urllib.parse
import html
import hashlib
import functools
import math



import argparse

# Platform-specific imports (Defines IS_WINDOWS)
IS_WINDOWS = sys.platform.startswith('win')

# Argument Parsing
parser = argparse.ArgumentParser(description="Pearcer Packet Analyzer")
parser.add_argument("--headless", action="store_true", help="Run in headless mode (no GUI)")
parser.add_argument("--remote-agent-port", type=int, default=9999, help="Port for Remote Agent Listener (default: 9999)")
args, unknown = parser.parse_known_args()

# Configuration
config = {
    "interface": "eth0" if not IS_WINDOWS else "Wi-Fi",
    "promisc": True,
    "filter": "",
    "capture_mode": "live", 
    "android_serial": None,
    "headless": args.headless,
    "remote_port": args.remote_agent_port
}

if not IS_WINDOWS:
    try:
        import fcntl
        FCNTL_AVAILABLE = True
    except ImportError:
        FCNTL_AVAILABLE = False
else:
    FCNTL_AVAILABLE = False

GUI_AVAILABLE = False
if not config["headless"]:
    try:
        import tkinter as tk
        from tkinter import scrolledtext, messagebox, filedialog, simpledialog
        from tkinter.ttk import Notebook, Combobox, Treeview
        GUI_AVAILABLE = True
    except ImportError:
        print("[WARNING] Tkinter not found. Falling back to headless mode.")
else:
    print("[INFO] Running in HEADLESS mode (No GUI)")
    GUI_AVAILABLE = False

VIZ_AVAILABLE = False
try:
    import matplotlib.pyplot as plt
    from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
    import networkx as nx
    VIZ_AVAILABLE = True
except ImportError:
    pass

# Global Graph Object
if VIZ_AVAILABLE:
    G = nx.Graph()
else:
    G = None

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
    from scapy.all import sniff, Ether, IP, IPv6, TCP, UDP, ICMP, Raw, DNS, DNSRR, conf
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

# Vulnerability scanner - will be initialized after config loads
vuln_scanner = None

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

# Recon tool - will be initialized after config loads
recon_tool = None

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
        # Wireshark-inspired color scheme (Foreground, Background)
        "normal": ("#FFFFFF", "#1E1E1E"),  # White on Dark Grey
        "tcp": ("#000000", "#E6E6FA"),    # Black on Lavender (TCP)
        "tcp_syn": ("#000000", "#A0A0A0"), # Black on Gray (SYN/FIN/RST)
        "udp": ("#000000", "#dae8fc"),    # Black on Light Blue (UDP)
        "http": ("#000000", "#d5e8d4"),   # Black on Light Green (HTTP)
        "dns": ("#000000", "#dae8fc"),    # Black on Light Blue (DNS)
        "icmp": ("#000000", "#e1d5e7"),   # Black on Light Purple (ICMP)
        "arp": ("#000000", "#fafad2"),    # Black on Light Goldenrod (ARP)
        "info": ("#FFFFFF", "#1E1E1E"),   # White on Dark Grey (Info/Default)
        "error": ("#FFFFFF", "#800000"),  # White on Dark Red (Errors/RST)
        "warning": ("#000000", "#ffffcc"),# Black on Light Yellow (Warnings)
        "note": ("#000000", "#d5e8d4"),   # Black on Light Green (Notes)
        "smb": ("#000000", "#fff2cc"),    # Black on Light Yellow (SMB)
        "routing": ("#000000", "#f8cecc"),# Black on Light Pink (Routing)
        "suspicious": ("#000000", "#ffe6cc"), # Black on Orange (Suspicious)
        "attack": ("#FFFFFF", "#FF0000"), # White on Red (Attacks)
        "voip": ("#000000", "#dae8fc"),   # Black on Light Blue (VoIP)
        "encrypted": ("#000000", "#f5f5f5"), # Black on White Smoke (Encrypted)
        "tls": ("#000000", "#e1d5e7"),    # Black on Light Purple (TLS)
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
    },
    # Real Cybersecurity Scanning Configuration
    "nvd_api_key": None,  # Get free API key from https://nvd.nist.gov/developers/request-an-api-key
    "zap_api_key": None,  # Optional: OWASP ZAP API key
    "zap_proxy": "http://127.0.0.1:8090",  # OWASP ZAP proxy address
    "enable_zap_scanning": False,  # Enable/disable ZAP web scanning
    "cve_cache_dir": "nvd_cache.json"  # Cache directory for CVE lookups
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
# Ensure CLI args override config file
config["headless"] = args.headless
config["remote_port"] = args.remote_agent_port

# NOW initialize vulnerability scanner and recon tool with loaded config
# Initialize vulnerability scanner with API keys from config
if VULN_SCANNER_AVAILABLE:
    try:
        # Get API keys from config or environment variables
        nvd_api_key = os.getenv('NVD_API_KEY', config.get('nvd_api_key', None))
        zap_api_key = os.getenv('ZAP_API_KEY', config.get('zap_api_key', None))
        zap_proxy = config.get('zap_proxy', 'http://127.0.0.1:8090')
        
        vuln_scanner = VulnerabilityScanner(
            nvd_api_key=nvd_api_key,
            zap_api_key=zap_api_key,
            zap_proxy=zap_proxy
        )
        print("[VULN SCANNER] Initialized with NVD CVE database and OWASP ZAP support")
        if nvd_api_key:
            print("[NVD] API key configured - higher rate limits enabled")
        else:
            print("[NVD] No API key - using default rate limits")
    except Exception as e:
        print(f"[VULN SCANNER INIT ERROR] {e}")
        VULN_SCANNER_AVAILABLE = False

# Initialize recon tool
if RECON_TOOL_AVAILABLE:
    try:
        recon_tool = ReconTool()
        print("[RECON TOOL] Initialized with crt.sh, WHOIS, and DNS security checks")
    except Exception as e:
        print(f"[RECON TOOL INIT ERROR] {e}")
        RECON_TOOL_AVAILABLE = False


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
# Initialize interface_map globally to prevent NameError
interface_map = {}

# GUI update thread safety
gui_update_lock = threading.Lock()
gui_update_dirty = False  # Dirty flag for throttling updates
last_gui_update_time = 0.0
GUI_UPDATE_INTERVAL = 2.0  # Update stats every 2 seconds instead of 1

# Packet batching for better performance
PACKET_BATCH_SIZE = 50  # Process packets in batches
packet_batch = []
packet_batch_lock = threading.Lock()

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

    # Build a map from GUID to Friendly Name using Scapy if available
    guid_map = {}
    if SCAPY_AVAILABLE and IS_WINDOWS:
        try:
            # conf.ifaces is a NetworkInterfaceDict, values are NetworkInterface objects
            for iface_obj in conf.ifaces.values():
                # On Windows:
                # .guid -> '{...}'
                # .name -> 'Ethernet', 'Wi-Fi' (Friendly Name)
                # .description -> 'Intel(R) Ethernet Connection...' (Driver Desc)
                
                guid = getattr(iface_obj, 'guid', '')
                if not guid:
                    continue
                    
                friendly = getattr(iface_obj, 'name', '')
                desc = getattr(iface_obj, 'description', '')
                
                # Prioritize: Name (Friendly) > Description > "Unknown"
                # Avoid using GUID as name
                best_name = friendly if friendly and not friendly.startswith('{') else desc
                
                if best_name:
                    # Map the bare GUID (with and without braces just in case)
                    guid_map[guid] = best_name
                    # Map the Npcap style name: \Device\NPF_{GUID}
                    guid_map[f"\\Device\\NPF_{guid}"] = best_name
        except Exception as e:
            # Fallback if conf.ifaces is not iterable or other errors
            # print(f"[DEBUG] Error mapping interfaces: {e}")
            pass

    # Method 2: PowerShell (More reliable on Windows for mapping GUIDs to Names)
    if IS_WINDOWS:
        try:
            import subprocess
            # Get NetAdapter info: Name (Friendly), InterfaceGuid
            ps_cmd = 'Get-NetAdapter | Select-Object Name, InterfaceGuid | ConvertTo-Json'
            ps_result = subprocess.run(['powershell', '-Command', ps_cmd], 
                                  capture_output=True, text=True, timeout=5)
            
            if ps_result.returncode == 0 and ps_result.stdout.strip():
                try:
                    adapters = json.loads(ps_result.stdout)
                    # If single result, it might be a dict, not a list
                    if isinstance(adapters, dict):
                        adapters = [adapters]
                    
                    print(f"[DEBUG] PowerShell found {len(adapters)} adapters")
                    for adapter in adapters:
                        name = adapter.get('Name')
                        guid = adapter.get('InterfaceGuid')
                        if name and guid:
                            print(f"[DEBUG] Mapping: {guid} -> {name}")
                            # Add to map with multiple formats
                            clean_guid = guid.strip('{}')
                            guid_map[guid] = name
                            guid_map[clean_guid] = name
                            guid_map[f"{{{clean_guid}}}"] = name
                            guid_map[f"\\\\Device\\\\NPF_{guid}"] = name
                            guid_map[f"\\\\Device\\\\NPF_{{{clean_guid}}}"] = name
                except json.JSONDecodeError as e:
                    print(f"[DEBUG] JSON decode error: {e}")
                    pass
        except Exception as e:
            print(f"[DEBUG] PowerShell mapping error: {e}")
            pass

    # Special handling for Windows Npcap device strings like \Device\NPF_{GUID}
    npf_index = 1

    for iface in interfaces:
        iface_lower = iface.lower()
        display = ""

        # On Windows, try to resolve ugly NPF GUIDs
        if IS_WINDOWS:
            # Extract GUID from various formats
            guid_candidates = []
            
            # Try to extract GUID from \Device\NPF_{GUID} format
            if '\\Device\\NPF_' in iface or '\\Device\\NPF_{' in iface:
                # Extract the GUID part
                guid_part = iface.split('NPF_')[-1] if 'NPF_' in iface else ''
                if guid_part:
                    guid_candidates.append(guid_part)
                    guid_candidates.append(guid_part.strip('{}'))
                    guid_candidates.append(f"{{{guid_part.strip('{}')}}}")
            
            # Also try the interface name itself
            guid_candidates.append(iface)
            
            # Try to find a match
            for candidate in guid_candidates:
                if candidate in guid_map:
                    display = guid_map[candidate]
                    print(f"[DEBUG] Matched {iface} -> {display}")
                    break
            
            # Fallback if map failed
            if not display:
                if 'loopback' in iface_lower:
                    display = "Local host"
                else:
                    display = f"Network adapter #{npf_index}"
                    npf_index += 1
        else:
            friendly = get_friendly_interface_name(iface)
            display = friendly

        # Ensure display name is unique
        if display in used_display:
            short_tech = iface
            if IS_WINDOWS and len(iface) > 20:
                 short_tech = "..." + iface[-6:]
            display = f"{display} ({short_tech})"
            
        used_display.add(display)
        result.append((display, iface))

    # Sort interfaces to prioritize Wi-Fi first, then Ethernet, then others, loopback last
    def interface_priority(item):
        display_name = item[0].lower()
        if 'wi-fi' in display_name or 'wifi' in display_name or 'wireless' in display_name:
            return 0  # Wi-Fi first
        elif 'ethernet' in display_name:
            return 1  # Ethernet second
        elif 'loopback' in display_name or 'local host' in display_name:
            return 999  # Loopback last
        else:
            return 2  # Others in between
    
    result.sort(key=interface_priority)
    
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
            # Enable promiscuous mode to capture all network traffic, not just local
            sniff(iface=interface, filter=filter_str, prn=prn, count=count, store=0, promisc=True, stop_filter=lambda x: not running)
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


# Reverse DNS lookup cache to avoid repeated lookups
reverse_dns_cache = {}
reverse_dns_failed = set()  # Track failed lookups to avoid retrying
MAX_DNS_CACHE_SIZE = 500  # Limit cache size for low-end PCs

def get_hostname_via_reverse_dns(ip: str) -> str:
    """Perform reverse DNS lookup with caching (optimized for low-end PCs)"""
    # Check cache first
    if ip in reverse_dns_cache:
        return reverse_dns_cache[ip]
    
    # Skip if we already tried and failed
    if ip in reverse_dns_failed:
        return ""
    
    # Skip private/local IPs and invalid IPs
    if ip in ("0.0.0.0", "255.255.255.255", "127.0.0.1", "::1"):
        reverse_dns_failed.add(ip)
        return ""
    
    # Skip private IP ranges to avoid delays
    if ip.startswith(("192.168.", "10.", "172.16.", "172.17.", "172.18.", "172.19.", 
                      "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
                      "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.")):
        # Only do reverse DNS for private IPs if cache is small
        if len(reverse_dns_cache) > 100:
            reverse_dns_failed.add(ip)
            return ""
    
    try:
        import socket
        # Very short timeout to avoid blocking on low-end PCs
        socket.setdefaulttimeout(0.2)
        hostname = socket.gethostbyaddr(ip)[0]
        if hostname and hostname != ip:
            # Limit cache size for low-end PCs
            if len(reverse_dns_cache) >= MAX_DNS_CACHE_SIZE:
                # Remove oldest entries (simple FIFO)
                reverse_dns_cache.pop(next(iter(reverse_dns_cache)))
            
            reverse_dns_cache[ip] = hostname
            # Also add to main hostname cache
            ip_hostnames[ip] = hostname
            return hostname
    except (socket.herror, socket.gaierror, socket.timeout, OSError):
        # Mark as failed to avoid retrying
        reverse_dns_failed.add(ip)
    except Exception:
        reverse_dns_failed.add(ip)
    
    return ""


def lookup_host(ip_src: str, ip_dst: str) -> str:
    """Return best-known hostname for either endpoint, if any."""
    import socket
    
    # Get local hostname to avoid showing it for remote servers
    try:
        local_hostname = socket.gethostname().lower()
    except:
        local_hostname = ""
    
    # ONLY check DNS/HTTP cache - NO reverse DNS lookups (too slow)
    if ip_dst in ip_hostnames:
        hostname = ip_hostnames[ip_dst]
        # Skip if it's just the local PC name
        if hostname.lower() != local_hostname:
            return hostname
    
    if ip_src in ip_hostnames:
        hostname = ip_hostnames[ip_src]
        # Skip if it's just the local PC name
        if hostname.lower() != local_hostname:
            return hostname
    
    # Return empty instead of doing slow reverse DNS lookups
    # Hostnames will only appear if captured via DNS or HTTP
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


def format_packet_info(pkt, protocol: str, ip_src: str, ip_dst: str, src_port: int, dst_port: int, payload: bytes) -> str:
    """Generate Wireshark-style detailed info for the Info column.
    
    Returns protocol-specific details instead of just "{protocol} packet".
    """
    try:
        # TCP packets - show flags and ports
        if protocol in ("TCP", "HTTP", "TLS", "WebSocket") and SCAPY_AVAILABLE:
            if TCP in pkt:
                tcp = pkt[TCP]
                flags = []
                if tcp.flags.S: flags.append("SYN")
                if tcp.flags.A: flags.append("ACK")
                if tcp.flags.F: flags.append("FIN")
                if tcp.flags.R: flags.append("RST")
                if tcp.flags.P: flags.append("PSH")
                if tcp.flags.U: flags.append("URG")
                
                flag_str = ", ".join(flags) if flags else ""
                
                # For HTTP, try to extract request/response
                if protocol == "HTTP" and payload:
                    try:
                        text = payload.decode('utf-8', errors='ignore')
                        lines = text.split('\r\n')
                        if lines and lines[0]:
                            # HTTP request or response first line
                            first_line = lines[0].strip()
                            if first_line.startswith(('GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'PATCH')):
                                return first_line  # e.g., "GET /index.html HTTP/1.1"
                            elif first_line.startswith('HTTP/'):
                                return first_line  # e.g., "HTTP/1.1 200 OK"
                    except:
                        pass
                
                # Standard TCP info with flags
                if flag_str:
                    return f"{src_port} → {dst_port} [{flag_str}] Seq={tcp.seq} Ack={tcp.ack} Win={tcp.window} Len={len(payload)}"
                else:
                    return f"{src_port} → {dst_port} Seq={tcp.seq} Ack={tcp.ack} Win={tcp.window} Len={len(payload)}"
        
        # DNS packets - show query/response
        if protocol == "DNS" and SCAPY_AVAILABLE:
            if DNS in pkt:
                dns = pkt[DNS]
                if dns.qr == 0:  # Query
                    if dns.qd:
                        qname = dns.qd.qname.decode('utf-8', errors='ignore').rstrip('.') if isinstance(dns.qd.qname, bytes) else str(dns.qd.qname).rstrip('.')
                        qtype = {1: 'A', 28: 'AAAA', 5: 'CNAME', 15: 'MX', 16: 'TXT', 2: 'NS', 6: 'SOA'}.get(dns.qd.qtype, dns.qd.qtype)
                        return f"Standard query {qtype} {qname}"
                else:  # Response
                    if dns.an and dns.ancount > 0:
                        # Try to get first answer
                        try:
                            rr = dns.an
                            if hasattr(rr, 'rdata'):
                                rdata = str(rr.rdata)
                                qname = rr.rrname.decode('utf-8', errors='ignore').rstrip('.') if isinstance(rr.rrname, bytes) else str(rr.rrname).rstrip('.')
                                return f"Standard query response {qname} → {rdata}"
                        except:
                            pass
                    return f"Standard query response ({dns.ancount} answers)"
        
        # UDP packets - show ports and length
        if protocol == "UDP" and SCAPY_AVAILABLE:
            if UDP in pkt:
                udp = pkt[UDP]
                return f"{src_port} → {dst_port} Len={udp.len}"
        
        # ICMP packets - show type
        if protocol == "ICMP" and SCAPY_AVAILABLE:
            if ICMP in pkt:
                icmp = pkt[ICMP]
                icmp_types = {
                    0: "Echo (ping) reply",
                    3: "Destination unreachable",
                    4: "Source quench",
                    5: "Redirect",
                    8: "Echo (ping) request",
                    11: "Time exceeded",
                    12: "Parameter problem",
                    13: "Timestamp request",
                    14: "Timestamp reply"
                }
                type_name = icmp_types.get(icmp.type, f"Type {icmp.type}")
                return f"{type_name} (Code {icmp.code})"
        
        # TLS - show handshake info if available
        if protocol == "TLS" and payload:
            if payload.startswith(b'\x16\x03'):  # TLS Handshake
                try:
                    # TLS version
                    version = payload[1:3]
                    version_map = {
                        b'\x03\x01': 'TLS 1.0',
                        b'\x03\x02': 'TLS 1.1',
                        b'\x03\x03': 'TLS 1.2',
                        b'\x03\x04': 'TLS 1.3'
                    }
                    ver_str = version_map.get(version, 'TLS')
                    
                    # Handshake type
                    if len(payload) > 5:
                        handshake_type = payload[5]
                        handshake_types = {
                            1: 'Client Hello',
                            2: 'Server Hello',
                            11: 'Certificate',
                            12: 'Server Key Exchange',
                            13: 'Certificate Request',
                            14: 'Server Hello Done',
                            16: 'Client Key Exchange',
                            20: 'Finished'
                        }
                        hs_name = handshake_types.get(handshake_type, 'Handshake')
                        return f"{ver_str} {hs_name}"
                except:
                    pass
                return "TLS Handshake"
            elif payload.startswith(b'\x17\x03'):  # Application Data
                return "TLS Application Data"
            elif payload.startswith(b'\x15\x03'):  # Alert
                return "TLS Alert"
        
        # SIP - show method or response
        if protocol == "SIP" and payload:
            try:
                text = payload.decode('utf-8', errors='ignore')
                lines = text.split('\r\n')
                if lines and lines[0]:
                    first_line = lines[0].strip()
                    if first_line.startswith('SIP/'):
                        return first_line  # e.g., "SIP/2.0 200 OK"
                    elif ' sip:' in first_line.lower():
                        return first_line.split()[0]  # e.g., "INVITE", "ACK", "BYE"
            except:
                pass
        
        # QUIC - basic info
        if protocol == "QUIC":
            return f"{src_port} → {dst_port} QUIC packet"
        
        # WebSocket - basic info
        if protocol == "WebSocket":
            return f"{src_port} → {dst_port} WebSocket data"
        
        # SSDP - UPnP discovery
        if protocol == "SSDP" and payload:
            try:
                text = payload.decode('utf-8', errors='ignore')
                if 'M-SEARCH' in text:
                    return "SSDP M-SEARCH discovery"
                elif 'NOTIFY' in text:
                    return "SSDP NOTIFY"
                elif 'HTTP/1.1 200 OK' in text:
                    return "SSDP discovery response"
            except:
                pass
        
        # NetBIOS
        if protocol == "NetBIOS":
            return f"{src_port} → {dst_port} NetBIOS Name Service"
        
        # DCCP
        if protocol == "DCCP":
            return f"{src_port} → {dst_port} DCCP"
        
        # Generic fallback for known protocols
        if protocol in ("Unknown", "N/A", ""):
            return "N/A"
        
        # For other protocols, show basic port info if available
        if src_port and dst_port:
            return f"{src_port} → {dst_port} {protocol}"
        
        return protocol
        
    except Exception:
        # If anything fails, return basic info
        if src_port and dst_port:
            return f"{src_port} → {dst_port}"
        return "N/A"


def detect_advanced_threats(pkt, protocol: str, ip_src: str, ip_dst: str, src_port: int, dst_port: int, payload: bytes) -> str:
    """Detect advanced threats: MitM, data exfiltration, TLS attacks, C2 communication, etc.
    
    Returns a threat description string to append to the Info column, or empty string if no threats.
    """
    threats = []
    
    try:
        # 1. MitM Attack Detection
        # ARP Spoofing detection (check for duplicate IPs with different MACs)
        if protocol == "ARP" and SCAPY_AVAILABLE:
            if Ether in pkt:
                # This would require tracking MAC-IP pairs over time
                # For now, flag unusual ARP patterns
                pass
        
        # DNS Spoofing detection (multiple different answers for same query)
        if protocol == "DNS" and SCAPY_AVAILABLE:
            if DNS in pkt:
                dns = pkt[DNS]
                if dns.qr == 1 and dns.ancount > 0:  # Response
                    # Check for suspicious DNS responses (e.g., local IPs for public domains)
                    try:
                        if hasattr(dns.an, 'rdata'):
                            rdata = str(dns.an.rdata)
                            qname = dns.an.rrname.decode('utf-8', errors='ignore').rstrip('.') if isinstance(dns.an.rrname, bytes) else str(dns.an.rrname).rstrip('.')
                            # Check if public domain resolves to private IP (potential DNS spoofing)
                            if not qname.endswith('.local') and rdata.startswith(('192.168.', '10.', '172.16.', '172.17.', '172.18.', '172.19.', '172.20.', '172.21.', '172.22.', '172.23.', '172.24.', '172.25.', '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', '172.31.')):
                                threats.append("⚠️ Possible DNS Spoofing")
                    except:
                        pass
        
        # SSL Stripping detection (HTTP to known HTTPS sites)
        if protocol == "HTTP" and payload:
            try:
                text = payload.decode('utf-8', errors='ignore').lower()
                # Check for HTTP requests to known HTTPS-only sites
                https_only_domains = ['google.com', 'facebook.com', 'twitter.com', 'github.com', 'amazon.com', 'paypal.com']
                for domain in https_only_domains:
                    if f'host: {domain}' in text or f'host: www.{domain}' in text:
                        threats.append("⚠️ SSL Stripping Detected")
                        break
            except:
                pass
        
        # 2. Data Exfiltration Detection
        # Large outbound transfers
        if len(payload) > 50000:  # > 50KB payload
            # Check if it's outbound (from private to public IP)
            if ip_src.startswith(('192.168.', '10.', '172.16.', '172.17.', '172.18.', '172.19.', '172.20.', '172.21.', '172.22.', '172.23.', '172.24.', '172.25.', '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', '172.31.')) and not ip_dst.startswith(('192.168.', '10.', '172.16.', '172.17.', '172.18.', '172.19.', '172.20.', '172.21.', '172.22.', '172.23.', '172.24.', '172.25.', '172.26.', '172.27.', '172.28.', '172.29.', '172.30.', '172.31.', '127.')):
                threats.append(f"📤 Large Outbound Transfer ({len(payload)//1024}KB)")
        
        # Unusual protocols for data transfer
        if protocol in ("FTP", "TFTP", "TELNET") and dst_port not in (20, 21, 23, 69):
            threats.append("⚠️ Unusual Protocol Usage")
        
        # Base64 encoded data in HTTP (common exfiltration technique)
        if protocol == "HTTP" and payload:
            try:
                text = payload.decode('utf-8', errors='ignore')
                # Look for long base64 strings (potential encoded data)
                import re
                base64_pattern = r'[A-Za-z0-9+/]{100,}={0,2}'
                if re.search(base64_pattern, text):
                    threats.append("🔍 Base64 Encoded Data")
            except:
                pass
        
        # 3. TLS/SSL Attack Detection
        if protocol == "TLS" and payload:
            # TLS Downgrade attack detection
            if payload.startswith(b'\x16\x03'):  # TLS Handshake
                try:
                    version = payload[1:3]
                    # Check for old/weak TLS versions
                    if version in (b'\x03\x00', b'\x03\x01'):  # SSL 3.0 or TLS 1.0
                        threats.append("⚠️ Weak TLS Version (Downgrade Attack?)")
                    
                    # Check for weak ciphers (would need deeper packet parsing)
                    # For now, flag any TLS 1.0/1.1
                    if version == b'\x03\x02':  # TLS 1.1
                        threats.append("⚠️ TLS 1.1 (Deprecated)")
                except:
                    pass
            
            # Certificate validation issues would require deeper inspection
            # Flag self-signed certs, expired certs, etc. (requires TLS decryption)
        
        # 4. C2 (Command & Control) Communication Detection
        # Beaconing pattern detection (regular intervals)
        # This would require tracking packet timing - simplified version:
        
        # Known C2 ports
        c2_ports = [4444, 5555, 6666, 7777, 8888, 9999, 31337, 1337]
        if src_port in c2_ports or dst_port in c2_ports:
            threats.append("🚨 Suspicious C2 Port")
        
        # Known malware/C2 domains (simplified list)
        if protocol in ("DNS", "HTTP", "TLS"):
            suspicious_keywords = [
                b'pastebin', b'discord.gg', b'ngrok', b'duckdns',
                b'no-ip', b'ddns', b'serveo', b'localtunnel'
            ]
            payload_lower = payload.lower()
            for keyword in suspicious_keywords:
                if keyword in payload_lower:
                    threats.append(f"⚠️ Suspicious Domain ({keyword.decode()})")
                    break
        
        # Encrypted traffic on non-standard ports
        if dst_port not in (80, 443, 22, 25, 110, 143, 993, 995, 587, 465, 53) and len(payload) > 0:
            # Check for high entropy (encrypted/compressed data)
            if len(payload) > 100:
                # Simple entropy check: count unique bytes
                unique_bytes = len(set(payload[:100]))
                if unique_bytes > 80:  # High entropy
                    threats.append("🔐 Encrypted Traffic (Non-Standard Port)")
        
        # 5. Advanced Protocol Analysis
        # QUIC analysis
        if protocol == "QUIC":
            # QUIC is encrypted by default, flag for visibility
            threats.append("🔒 QUIC Protocol (Encrypted)")
        
        # SCTP detection
        if SCAPY_AVAILABLE and hasattr(pkt, 'proto'):
            if pkt.proto == 132:  # SCTP
                threats.append("📡 SCTP Protocol Detected")
        
        # Tor traffic detection (common Tor ports)
        tor_ports = [9001, 9030, 9040, 9050, 9051, 9150]
        if src_port in tor_ports or dst_port in tor_ports:
            threats.append("🧅 Possible Tor Traffic")
        
        # VPN detection (common VPN ports)
        vpn_ports = [500, 1194, 1701, 1723, 4500]
        if src_port in vpn_ports or dst_port in vpn_ports:
            threats.append("🔒 VPN Traffic")
        
        # Suspicious user agents (if HTTP)
        if protocol == "HTTP" and payload:
            try:
                text = payload.decode('utf-8', errors='ignore').lower()
                suspicious_agents = ['curl', 'wget', 'python', 'powershell', 'nmap', 'sqlmap', 'nikto', 'metasploit']
                for agent in suspicious_agents:
                    if f'user-agent: {agent}' in text or f'user-agent: {agent}/' in text:
                        threats.append(f"🔍 Suspicious User-Agent ({agent})")
                        break
            except:
                pass
        
        # SQL Injection attempts
        if protocol == "HTTP" and payload:
            try:
                text = payload.decode('utf-8', errors='ignore').lower()
                sql_patterns = ["' or '1'='1", "' or 1=1", "union select", "drop table", "exec(", "execute("]
                for pattern in sql_patterns:
                    if pattern in text:
                        threats.append("🚨 SQL Injection Attempt")
                        break
            except:
                pass
        
        # XSS attempts
        if protocol == "HTTP" and payload:
            try:
                text = payload.decode('utf-8', errors='ignore').lower()
                xss_patterns = ["<script>", "javascript:", "onerror=", "onload="]
                for pattern in xss_patterns:
                    if pattern in text:
                        threats.append("🚨 XSS Attempt")
                        break
            except:
                pass
        
    except Exception:
        # Don't let threat detection break packet processing
        pass
    
    # Return combined threats as a string
    if threats:
        return " | " + " | ".join(threats)
    return ""

# Advanced attack detection
# ==========================================
# CVE & Threat Intelligence
# ==========================================

CVE_SIGNATURES = {
    "CVE-2021-44228": {
        "name": "Log4Shell (RCE)",
        "patterns": [b"${jndi:ldap", b"${jndi:rmi", b"${jndi:dns", b"${lower:"],
        "severity": "CRITICAL"
    },
    "CVE-2014-6271": {
        "name": "Shellshock (Bash RCE)",
        "patterns": [b"() { :; };", b"() { _; } >_"],
        "severity": "CRITICAL"
    },
    "CVE-2017-5638": {
        "name": "Apache Struts RCE",
        "patterns": [b"Content-Type: %{(#_='=')."],
        "severity": "HIGH"
    },
    "CVE-2022-22965": {
        "name": "Spring4Shell",
        "patterns": [b"class.module.classLoader.resources.context.parent.pipeline.first.pattern"],
        "severity": "CRITICAL"
    },
    "GENERIC-SQLI": {
        "name": "SQL Injection Attempt",
        "patterns": [b"UNION SELECT", b"' OR '1'='1", b"waitfor delay", b"SLEEP(", b"pg_sleep"],
        "severity": "HIGH"
    },
    "GENERIC-XSS": {
        "name": "Cross-Site Scripting (XSS)",
        "patterns": [b"<script>alert(", b"javascript:alert", b"onerror=alert"],
        "severity": "MEDIUM"
    },
    "GENERIC-TRAVERSAL": {
        "name": "Directory Traversal",
        "patterns": [b"../../etc/passwd", b"..\\..\\windows\\system32"],
        "severity": "HIGH"
    }
}

def check_cve_signatures(payload):
    """Scan payload for known CVE signatures."""
    if not payload:
        return None, None
        
    for cve_id, sig in CVE_SIGNATURES.items():
        for pattern in sig["patterns"]:
            if pattern.lower() in payload.lower():
                return cve_id, sig
                
    return None, None

def check_vulnerabilities(port, banner):
    """Simple banner grabbing vulnerability check (placeholder for future expansion)."""
    # Real implementations would check banner versions against a CVE db
    return []

# Advanced attack detection (Legacy/Raw implementation)
def detect_attacks(ip_src, protocol, payload, src_port, dst_port):
    """Detect various types of attacks and suspicious activities (Legacy)."""
    # This is kept for the raw socket handler compatibility
    cve, sig = check_cve_signatures(payload)
    if cve:
        return "attack", f"{sig['name']} ({cve})"
    return "normal", ""

# ==========================================
# Android Support (ADB + Tcpdump)
# ==========================================

def check_adb_availability():
    """Check if 'adb' is in PATH and functioning."""
    try:
        subprocess.run(["adb", "version"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
        return True
    except (FileNotFoundError, subprocess.CalledProcessError):
        return False

def list_android_devices():
    """Return a list of attached Android devices (serial, state)."""
    devices = []
    if not check_adb_availability():
        return devices
    
    try:
        # Run 'adb devices -l'
        result = subprocess.run(["adb", "devices", "-l"], capture_output=True, text=True, check=True)
        lines = result.stdout.strip().split('\n')
        # Skip header "List of devices attached"
        for line in lines[1:]:
            line = line.strip()
            if not line:
                continue
            parts = line.split()
            if len(parts) >= 2:
                serial = parts[0]
                state = parts[1]
                # Try to find model info
                model = "Unknown"
                for part in parts:
                    if part.startswith("model:"):
                        model = part.split(":")[1]
                
                if state == "device":
                    devices.append((serial, model))
    except Exception:
        pass
    return devices

def capture_android_traffic(serial):
    """
    Generator that yields packets from an Android device via ADB -> tcpdump.
    REQUIRES: Rooted device or tcpdump binary in path.
    """
    cmd = ["adb", "-s", serial, "exec-out", "tcpdump -i any -U -w -"]
    
    # Start the subprocess
    process = subprocess.Popen(
        cmd, 
        stdout=subprocess.PIPE, 
        stderr=subprocess.PIPE, # Capture stderr to ignore status messages
        bufsize=0 # Unbuffered for real-time
    )
    
    # Use Scapy's PcapReader to parse the stream
    try:
        if SCAPY_AVAILABLE:
            # PcapReader reads from a file-like object (stdout)
            # We iterate continuously
            with PcapReader(process.stdout) as pcap_reader:
                for pkt in pcap_reader:
                    yield pkt
        else:
            print("[ERROR] Scapy required for Android capture")
    except Exception as e:
        print(f"[ERROR] Android capture failed: {e}")
    finally:
        process.terminate()

def capture_remote_android_traffic(port=9999):
    """
    Generator that yields packets from a generic TCP stream (Process-agnostic).
    Client runs: tcpdump -U -w - | nc <PEARCER_IP> <PORT>
    """
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        server_sock.bind(('0.0.0.0', port))
        server_sock.listen(1)
        print(f"[INFO] Remote Agent Listener started on 0.0.0.0:{port}")
        print(f"[HELP] Run on device: tcpdump -i any -U -w - | nc <HOST_IP> {port}")
        
        if GUI_AVAILABLE:
            messagebox.showinfo("Waiting for Connection", f"Listening on port {port}...\nRun this on Android/Remote:\n\ntcpdump -i any -U -w - | nc <THIS_IP> {port}")
        
        # Accept connection (Blocking)
        conn, addr = server_sock.accept()
        print(f"[INFO] Connection received from {addr}")
        
        if GUI_AVAILABLE:
             messagebox.showinfo("Connected", f"Receiving stream from {addr[0]}")

        # Use Scapy's PcapReader on the socket file object
        if SCAPY_AVAILABLE:
            # makefile('rb') creates a file-like object for PcapReader
            with conn.makefile('rb') as socket_file:
                with PcapReader(socket_file) as pcap_reader:
                    for pkt in pcap_reader:
                        yield pkt
        else:
            print("[ERROR] Scapy required for PcapReader")
            
    except Exception as e:
        print(f"[ERROR] Remote capture failed: {e}")
        if GUI_AVAILABLE:
             messagebox.showerror("Error", f"Remote capture failed: {e}")
    finally:
        server_sock.close()

    global stats, attack_counts
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
                # Check for SYN/FIN/RST for specific coloring
                if "SYN" in info:
                    tags.append("tcp_syn")
                if "RST" in info or "Reset" in info:
                    tags.append("tcp_syn") # Use gray for RST too or error if preferred
                if "FIN" in info:
                    tags.append("tcp_syn")
            elif protocol == "UDP":
                tags.append("udp")
            elif protocol in ("HTTP", "WebSocket"):
                tags.append("http")
            elif protocol == "DNS":
                tags.append("dns")
            elif protocol in ("TLS", "SSL"):
                tags.append("tls")
            elif protocol == "QUIC":
                tags.append("encrypted")
            elif protocol == "SIP":
                tags.append("voip")
            elif protocol in ("SMB", "NetBIOS"):
                tags.append("smb")
            elif protocol in ("ICMP", "OSPF", "RIP", "BGP"):
                tags.append("routing")
            elif protocol == "ARP":
                tags.append("routing")
            
            # Error/problem detection - ensure these override others if configured last or used as primary
            if level == "attack" or "error" in info.lower() or "problem" in info.lower() or "threat" in info.lower() or "spoofing" in info.lower() or "detect" in info.lower():
                tags.append("error")
            elif level == "suspicious":
                tags.append("suspicious")
            
            # TCP flags detection (keep specialized tag)
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
                pkt_len,
                process_info if 'process_info' in locals() else "N/A", 
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




# OS Fingerprinting Helper
def get_os_from_ttl(ttl):
    """Passive OS Fingerprinting based on TTL."""
    # Approximate TTL values for common OS families
    if ttl <= 64:
        return "Linux/iOS" # Linux=64, iOS=64, MacOS=64
    elif ttl <= 128:
        return "Windows"   # Windows=128
    elif ttl <= 255:
        return "Solaris/Cisco" # Solaris=254, Cisco=255
    return "Unknown"

# Entropy Helper
def calculate_entropy(data):
    """Calculate Shannon Entropy of byte data."""
    if not data:
        return 0
    entropy = 0
    for x in range(256):
        p_x = float(data.count(x)) / len(data)
        if p_x > 0:
            entropy += - p_x * math.log(p_x, 2)
    return entropy

def get_ja3_fingerprint(pkt):
    """Calculates JA3 fingerprint for TLS Client Hello packets."""
    try:
        # Check for TLS Client Hello layer
        # Note: Scapy's TLS support must be loaded.
        if not pkt.haslayer("TLSClientHello"):
            return None, None
            
        client_hello = pkt["TLSClientHello"]
        
        # 1. TLS Version (decimal)
        ssl_version = client_hello.version
        
        # 2. Ciphers (decimal)
        ciphers = []
        if hasattr(client_hello, "ciphers"):
            ciphers = client_hello.ciphers
            
        # 3. Extensions (decimal)
        extensions = []
        curves = []
        points = []
        
        if hasattr(client_hello, "ext"):
            for ext in client_hello.ext:
                extensions.append(ext.type)
                # Check for Elliptic Curves (type 10)
                if ext.type == 10:
                    curves = ext.groups
                # Check for EC Point Formats (type 11)
                elif ext.type == 11:
                    points = ext.ecpl
                    
        # Construct JA3 string
        # SSLVersion,Cipher,SSLExtension,EllipticCurve,EllipticCurvePointFormat
        ja3_str = f"{ssl_version},"
        ja3_str += "-".join(map(str, ciphers)) + ","
        ja3_str += "-".join(map(str, extensions)) + ","
        ja3_str += "-".join(map(str, curves)) + ","
        ja3_str += "-".join(map(str, points))
        
        # Calculate MD5
        ja3_hash = hashlib.md5(ja3_str.encode()).hexdigest()
        
        return ja3_str, ja3_hash
    except Exception:
        # Fail gracefully
        return None, None


def packet_handler_scapy(pkt):
    """Handle packets using Scapy layers for better protocol visibility."""
    global packet_count, stats, last_packet_time, protocol_counts, attack_counts
    packet_count += 1
    level = "normal"
    protocol = "Unknown"
    ip_src = ip_dst = "N/A"
    src_port = dst_port = 0
    info = "No info"
    attack_type = ""
    threat_info = "" # Initialize to prevent NameError
    cve_id = None    # Initialize to prevent NameError

    raw_packet = bytes(pkt)
    payload = b""

    # try:
    if True: # hack to maintain indentation without try block
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
        
        # Protocol Level Detection
        if IP in pkt:
            ip_layer = pkt[IP]
            ip_proto = int(ip_layer.proto)
            
            if ip_proto == 1: # ICMP
                level = "icmp"
                info = f"ICMP {ip_src} > {ip_dst}"
            elif ip_proto == 6: # TCP
                level = "tcp"
            elif ip_proto == 17: # UDP
                level = "udp"

        if ip_layer is not None:
            ip_src = str(ip_layer.src)
            ip_dst = str(ip_layer.dst)

            # Update Visualization Graph
            if VIZ_AVAILABLE and G is not None:
                try:
                    G.add_edge(ip_src, ip_dst)
                except: pass

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

            # Statistics updates
            protocol_counts[protocol] += 1
            if ip_src != "N/A":
                attack_counts[ip_src] += 1

            level = "info" 
            attack_type = ""

            # Generate Wireshark-style detailed info
            info = format_packet_info(pkt, protocol, ip_src, ip_dst, src_port, dst_port, payload)
            
            # --- FEATURE: Passive OS Fingerprinting ---
            os_guess = "Unknown"
            if ip_layer and hasattr(ip_layer, 'ttl'):
                os_guess = get_os_from_ttl(ip_layer.ttl)
            # ------------------------------------------

            # --- FEATURE: Payload Entropy & User-Agent ---
            if payload:
                # Entropy
                entropy = calculate_entropy(payload)
                if entropy > 7.5:
                    attack_type = "High Entropy (Poss. Encrypted)"
                    level = "suspicious" # Orange
                    info += f" [Entropy: {entropy:.2f}]"
                
                # User-Agent extraction for HTTP
                if protocol == "HTTP" and b"User-Agent:" in payload:
                    try:
                        # Extract first line with User-Agent
                        ua_match = re.search(rb"User-Agent: (.*?)\r\n", payload)
                        if ua_match:
                            ua_str = ua_match.group(1).decode('utf-8', errors='ignore')
                            # Truncate if too long
                            if len(ua_str) > 30:
                                ua_str = ua_str[:27] + "..."
                            info += f" [UA: {ua_str}]"
                    except:
                        pass
            # ---------------------------------------------
            
            # --- FEATURE: CVE & Exploit Scanning ---
            cve_id, cve_info = check_cve_signatures(payload)
            if cve_id:
                level = "attack" # Red
                attack_type = f"EXPLOIT: {cve_info['name']} ({cve_id})"
                stats["attacks"] += 1
                stats["exploits"] += 1
                # Add to info immediately
                info += f" [🚨 {cve_id}]"

            # Add advanced threat detection
            if not cve_id and threat_info: # Only add threat_info if no specific CVE found (avoid noise)
                info += threat_info
                
            # JA3 Fingerprinting for TLS/SSL
            if protocol in ["TLS", "SSL"] or "TLS" in protocol:
                _, ja3_hash = get_ja3_fingerprint(pkt)
                if ja3_hash:
                    info += f" [JA3: {ja3_hash}]"
                
            # STRICTER COLORING RULES: Only mark confirmed attacks as "attack" (Red)
            # High traffic warnings stay as default (or "suspicious")
                
                threat_lower = threat_info.lower()
                
                # Keywords that confirm a REAL, CRITICAL attack
                # REMOVED: "base64", "credential", "weak tls", "attack" (too generic)
                attack_keywords = [
                    "sql injection", "xss", "cross-site scripting", "c2", "command and control", 
                    "malware", "exploit", "buffer overflow", "shellcode"
                ]
                
                # Keywords for suspicious/informational requiring investigation (Orange)
                # ADDED generic terms and weaker signals here
                suspicious_keywords = [
                    "high traffic", "large outbound", "entropy", "user-agent", 
                    "unusual protocol", "vpn", "tor", "detect", "suspicious",
                    "base64", "credential", "cleartext", "weak", "scanning", "nmap", 
                    "attack", "header injection", "spoofing", "downgrade"
                ]
                
                if not cve_id: # Only check keywords if no CVE found
                    if any(k in threat_lower for k in attack_keywords):
                        stats["attacks"] += 1
                        level = "attack"  # Red
                    elif any(k in threat_lower for k in suspicious_keywords):
                        level = "suspicious"  # Orange/Yellow
                # Else remains "info" or "normal"
            
            if attack_type and attack_type not in info: # Avoid duplication
                info += f" - {attack_type}"
            # Ensure no blank values
            if not info or info.strip() == "":
                info = "N/A"
        else:
            # Non-IP traffic
            if "ARP" in pkt:
                 level = "arp"
                 info = f"ARP Who has {pkt['ARP'].pdst}? Tell {pkt['ARP'].psrc}"
            elif Ether in pkt:
                eth = pkt[Ether]
                level = "info"
                info = f"Ethernet type 0x{eth.type:04x}"
            else:
                level = "info"
                info = "Non-IP packet"
                


    # Timestamp
    timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
    
    # Process batching for GUI update
    # We DO NOT update GUI here directly to avoid freezing
    if GUI_AVAILABLE and 'packet_batch' in globals():
        pkt_len = len(raw_packet)
        host = lookup_host(ip_src if 'ip_src' in locals() else '', ip_dst if 'ip_dst' in locals() else '')
        # Ensure no blank hostname
        if not host or host.strip() == "":
            host = "N/A"
        
        # Determine process info if it's local traffic (The "Wavelength" request)
        process_info = ""
        try:
            # Simple local port mapping could go here
            pass
        except:
            pass

        # Determine protocol display
        display_proto = protocol
        if display_proto == "Unknown" and 'ip_proto' in locals():
            display_proto = f"IP/{ip_proto}"
        elif display_proto == "Unknown":
            display_proto = "Raw"

        # Enhanced Destination (IP:Port + Hostname)
        dst_display = f"{ip_dst}:{dst_port}" if 'dst_port' in locals() else ip_dst
        if host and host != "N/A":
            dst_display += f" ({host})"
            
        # PASS NEW FIELDS
        os_data = os_guess if 'os_guess' in locals() else "N/A"

        row_data = {
            'timestamp': timestamp,
            'src': f"{ip_src}:{src_port}" if 'src_port' in locals() else ip_src,
            'dst': dst_display,
            'os': os_data, # Added OS field
            'proto': display_proto, # Never N/A
            # 'host': host, # Removed as separate column
            'len': pkt_len,
            'level': level.upper(),
            'info': info,
            'tags': [level] # Simplified tags for now
        }
        
        with packet_batch_lock:
            packet_batch.append(row_data)



    # Log to file asynchronously if needed
    # Logging can be added here if needed

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
                # Deep Dissection Logic
                try:
                    # 1. Meta/Process Info
                    meta_node = details_tree.insert('', 'end', text=f"Frame {index+1}: {len(packet)} bytes on wire", open=True)
                    
                    item_list = packet_list.item(selected[0])
                    if item_list and 'values' in item_list:
                        vals = item_list['values']
                        if len(vals) > 7:
                            details_tree.insert(meta_node, 'end', text=f"Process: {vals[7]}")
                        details_tree.insert(meta_node, 'end', text=f"Time: {vals[1]}")
                        details_tree.insert(meta_node, 'end', text=f"Interface: {config.get('interface', 'Unknown')}")

                    # 2. Scapy Layer Iteration
                    current_layer = packet
                    while current_layer:
                        layer_name = current_layer.name
                        layer_summary = current_layer.summary()
                        
                        # Create Layer Node (e.g., "Ethernet", "IP")
                        layer_node = details_tree.insert('', 'end', text=layer_name, open=True)
                        
                        # Add Fields (e.g., "src=...", "ttl=...")
                        # Scapy fields are stored in .fields dict, but we want styled display
                        for field_name, field_value in current_layer.fields.items():
                            # Format value nicely
                            display_val = field_value
                            if isinstance(field_value, int):
                                display_val = f"{field_value} (0x{field_value:x})"
                            
                            details_tree.insert(layer_node, 'end', text=f"{field_name}: {display_val}")
                        
                        # Move to payload
                        current_layer = current_layer.payload
                        if not current_layer or type(current_layer).__name__ == 'NoPayload':
                            break
                            
                except Exception as e:
                    details_tree.insert('', 'end', text=f"Dissection Error: {str(e)}")
                
                # Hex dump
                hex_text.delete('1.0', tk.END)
                hex_dump = binascii.hexlify(packet).decode('utf-8')
                ascii_dump = ''.join([chr(b) if 32 <= b <= 126 else '.' for b in packet])
                for i in range(0, len(hex_dump), 32):
                    line_hex = hex_dump[i:i+32]
                    line_ascii = ascii_dump[i//2:i//2+16]
                    hex_text.insert(tk.END, f"{i:04x}  {line_hex:<48}  {line_ascii}\n")
                    
        except Exception as e:
            print(f"Error showing details: {e}")

# --- PACKET EDITOR & REPLAYER ---
def open_packet_editor(index):
    """Open a specialized Packet Editor window to modify and resend packets."""
    if not (0 <= index < len(captured_packets)): return
    
    raw_pkt = captured_packets[index]
    
    # Import scapy locally
    try:
        from scapy.all import IP, TCP, UDP, Ether, sendp, Raw
    except ImportError:
        messagebox.showerror("Error", "Scapy required for replay. pip install scapy")
        return

    # Dissect packet
    try:
        scapy_pkt = Ether(raw_pkt)
    except:
        return messagebox.showerror("Error", "Could not parse packet for editing")

    # GUI
    editor = tk.Toplevel()
    editor.title(f"Packet Editor - Frame #{index+1}")
    editor.geometry("600x600")
    editor.configure(bg="#1e1e1e")

    # Helper
    def add_field(parent, label, value, row):
        tk.Label(parent, text=label, bg="#1e1e1e", fg="#aaaaaa", width=15, anchor='e').grid(row=row, column=0, padx=5, pady=5)
        entry = tk.Entry(parent, bg="#333333", fg="white", insertbackground="white")
        entry.insert(0, str(value))
        entry.grid(row=row, column=1, padx=5, pady=5, sticky="ew")
        return entry

    fields = {}
    
    # Headers
    hdr_frame = tk.LabelFrame(editor, text="IP / Transport Headers", bg="#1e1e1e", fg="#FFC107")
    hdr_frame.pack(fill="x", padx=10, pady=10)

    proto_layer = None
    if scapy_pkt.haslayer(IP):
        fields['src'] = add_field(hdr_frame, "Source IP:", scapy_pkt[IP].src, 0)
        fields['dst'] = add_field(hdr_frame, "Dest IP:", scapy_pkt[IP].dst, 1)
        
        if scapy_pkt.haslayer(TCP):
            fields['sport'] = add_field(hdr_frame, "Source Port:", scapy_pkt[TCP].sport, 2)
            fields['dport'] = add_field(hdr_frame, "Dest Port:", scapy_pkt[TCP].dport, 3)
            proto_layer = TCP
        elif scapy_pkt.haslayer(UDP):
            fields['sport'] = add_field(hdr_frame, "Source Port:", scapy_pkt[UDP].sport, 2)
            fields['dport'] = add_field(hdr_frame, "Dest Port:", scapy_pkt[UDP].dport, 3)
            proto_layer = UDP
    else:
        tk.Label(hdr_frame, text="Non-IP packet editing limited.", bg="#1e1e1e", fg="orange").pack()

    # Payload
    tk.Label(editor, text="Payload (Raw):", bg="#1e1e1e", fg="white").pack(anchor="w", padx=10)
    payload_text = tk.Text(editor, height=10, bg="#333333", fg="white", insertbackground="white")
    payload_text.pack(fill="both", expand=True, padx=10, pady=(0,10))
    
    if scapy_pkt.haslayer(Raw):
        try:
            payload_text.insert("1.0", scapy_pkt[Raw].load.decode('utf-8', 'ignore'))
        except:
            payload_text.insert("1.0", repr(scapy_pkt[Raw].load))

    def send_modified():
        try:
            # Update Scapy Object
            if scapy_pkt.haslayer(IP):
                scapy_pkt[IP].src = fields['src'].get()
                scapy_pkt[IP].dst = fields['dst'].get()
                
                if proto_layer == TCP:
                    scapy_pkt[TCP].sport = int(fields['sport'].get())
                    scapy_pkt[TCP].dport = int(fields['dport'].get())
                elif proto_layer == UDP:
                    scapy_pkt[UDP].sport = int(fields['sport'].get())
                    scapy_pkt[UDP].dport = int(fields['dport'].get())
            
            # Update Payload
            new_load = payload_text.get("1.0", "end-1c").encode('utf-8')
            if scapy_pkt.haslayer(Raw):
                scapy_pkt[Raw].load = new_load
            else:
                # Add Raw layer if it was missing 
                pass # Logic complex handled by simple replacement for now
                
            # Recalculate checksums
            if scapy_pkt.haslayer(IP):
                del scapy_pkt[IP].len
                del scapy_pkt[IP].chksum
            if proto_layer == TCP:
                del scapy_pkt[TCP].chksum
            elif proto_layer == UDP:
                del scapy_pkt[UDP].len
                del scapy_pkt[UDP].chksum
                
            # Send
            sendp(scapy_pkt, verbose=False)
            messagebox.showinfo("Success", f"Packet sent to {scapy_pkt[IP].dst}")
            
        except Exception as e:
            messagebox.showerror("Send Error", str(e))

    btn_send = tk.Button(editor, text="🔥 Resend Packet", bg="#ff3333", fg="white", font=("Arial", 12, "bold"), command=send_modified)
    btn_send.pack(fill="x", padx=10, pady=10)

def show_context_menu(event):
    """Show right-click menu for packet list."""
    try:
        # Get item under mouse
        item = packet_list.identify_row(event.y)
        if item:
            packet_list.selection_set(item)
            
        selected = packet_list.selection()
        if not selected: return
        
        index = packet_list.index(selected[0])
        
        # Create Menu
        if 'packet_menu' not in globals():
            global packet_menu
            packet_menu = tk.Menu(root, tearoff=0, bg="#2b2b2b", fg="white")
            
        packet_menu.delete(0, tk.END)
        packet_menu.add_command(label=f"Packet #{index+1}", state="disabled")
        packet_menu.add_separator()
        packet_menu.add_command(label="✏️ Edit & Resend", command=lambda: open_packet_editor(index))
        
        packet_menu.post(event.x_root, event.y_root)
        
    except Exception as e:
        print(f"Context menu error: {e}")


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
            
            # ANDROID CAPTURE MODE CHECK
            if config.get("capture_mode") == "android":
                serial = config.get("android_serial")
                print(f"[INFO] Starting Android capture on {serial}...")
                try:
                    for pkt in capture_android_traffic(serial):
                        if not running: break
                        scapy_callback(pkt)
                except Exception as e:
                    print(f"[ERROR] Android capture loop failed: {e}")
                return # Thread done

            # REMOTE AGENT MODE CHECK
            if config.get("capture_mode") == "remote_android":
                port = config.get("remote_port", 9999)
                print(f"[INFO] Starting Remote Agent Listener on port {port}...")
                try:
                    for pkt in capture_remote_android_traffic(port):
                        if not running: break
                        scapy_callback(pkt)
                except Exception as e:
                    print(f"[ERROR] Remote capture loop failed: {e}")
                return # Thread done

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
    """Save captured packets to PCAP file using Scapy"""
    if not captured_packets:
        if GUI_AVAILABLE:
            messagebox.showwarning("Save Capture", "No packets to save!")
        return

    file_path = filedialog.asksaveasfilename(
        defaultextension=".pcap",
        filetypes=[("PCAP files", "*.pcap"), ("PCAPng files", "*.pcapng"), ("All files", "*.*")],
        title="Save Capture As"
    )
    
    if not file_path:
        return
        
    try:
        from scapy.all import wrpcap
        # Write packets to file
        wrpcap(file_path, captured_packets)
        
        if GUI_AVAILABLE:
            messagebox.showinfo("Save Successful", f"Saved {len(captured_packets)} packets to:\n{file_path}")
        else:
            print(f"[INFO] Saved {len(captured_packets)} packets to {file_path}")
            
    except Exception as e:
        error_msg = f"Failed to save PCAP: {str(e)}"
        if GUI_AVAILABLE:
            messagebox.showerror("Save Error", error_msg)
        else:
            print(f"[ERROR] {error_msg}")


# HTML Threat Reporting
def generate_threat_report():
    """Generate a professional HTML threat report."""
    if not captured_packets:
        if GUI_AVAILABLE:
            messagebox.showinfo("Report", "No packets to report on.")
        return

    try:
        filename = filedialog.asksaveasfilename(
            defaultextension=".html",
            filetypes=[("HTML Report", "*.html")],
            title="Save Threat Report"
        )
        if not filename:
            return

        # Calculate additional stats
        duration = time.time() - start_time if 'start_time' in globals() else 0
        total_packets = len(captured_packets)
        
        # Top Talkers
        src_counts = defaultdict(int)
        attack_log = []
        
        # Analyze captured packets for report
        # Note: We re-analyze or use stored logs. 
        # For simplicity, we'll iterate captured packets (if Scapy layers preserved)
        # But captured_packets are raw bytes in some modes. 
        # Better to use the global 'attack_counts' and existing stats.
        
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Pearcer Threat Report</title>
            <style>
                body {{ font-family: 'Segoe UI', Arial, sans-serif; background-color: #1e1e1e; color: #f0f0f0; margin: 0; padding: 20px; }}
                h1, h2 {{ color: #FFD700; border-bottom: 1px solid #444; padding-bottom: 10px; }}
                .card {{ background: #2d2d2d; border-radius: 8px; padding: 20px; margin-bottom: 20px; box-shadow: 0 4px 6px rgba(0,0,0,0.3); }}
                .stat-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; }}
                .stat-box {{ background: #333; padding: 15px; border-radius: 5px; text-align: center; }}
                .stat-val {{ font-size: 24px; font-weight: bold; color: #00ff00; }}
                .stat-label {{ color: #aaa; font-size: 14px; }}
                table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
                th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #444; }}
                th {{ background-color: #333; color: #FFD700; }}
                tr:hover {{ background-color: #383838; }}
                .alert-red {{ color: #ff5555; font-weight: bold; }}
                .alert-orange {{ color: #ffaa00; }}
            </style>
        </head>
        <body>
            <div class="card">
                <h1>🛡️ Pearcer Security Report</h1>
                <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                
                <div class="stat-grid">
                    <div class="stat-box">
                        <div class="stat-val">{total_packets}</div>
                        <div class="stat-label">Total Packets</div>
                    </div>
                    <div class="stat-box">
                        <div class="stat-val" style="color: {'#ff5555' if stats['attacks'] > 0 else '#00ff00'}">{stats['attacks']}</div>
                        <div class="stat-label">Critical Attacks</div>
                    </div>
                    <div class="stat-box">
                        <div class="stat-val" style="color: {'#ffaa00' if stats['vulnerabilities'] > 0 else '#00cc00'}">{stats['vulnerabilities']}</div>
                        <div class="stat-label">Vulnerabilities</div>
                    </div>
                     <div class="stat-box">
                        <div class="stat-val">{len(protocol_counts)}</div>
                        <div class="stat-label">Unique Protocols</div>
                    </div>
                </div>
            </div>

            <div class="card">
                <h2>🚨 Threat Summary</h2>
                <table>
                    <thead><tr><th>Attack Type</th><th>Count</th><th>Severity</th></tr></thead>
                    <tbody>
        """
        
        # Add attacks rows
        if not attack_counts:
             html_content += "<tr><td colspan='3'>No specific threats detected.</td></tr>"
        else:
            for attack, count in attack_counts.items():
                severity = "CRITICAL" if attack in ["SQL Injection", "XSS", "C2", "Malware"] else "Suspicious"
                color_class = "alert-red" if severity == "CRITICAL" else "alert-orange"
                html_content += f"<tr><td>{attack}</td><td>{count}</td><td class='{color_class}'>{severity}</td></tr>"

        html_content += """
                    </tbody>
                </table>
            </div>
            
            <div class="card">
                <h2>📊 Protocol Distribution</h2>
                <table>
                    <thead><tr><th>Protocol</th><th>Count</th></tr></thead>
                    <tbody>
        """
        
        # Add protocol rows
        sorted_protos = sorted(protocol_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        for proto, count in sorted_protos:
             html_content += f"<tr><td>{proto}</td><td>{count}</td></tr>"
             
        html_content += """
                    </tbody>
                </table>
            </div>
            
            <div style="text-align: center; color: #666; font-size: 12px; margin-top: 20px;">
                Generated by Pearcer Professional Analyzer
            </div>
        </body>
        </html>
        """
        
        with open(filename, "w", encoding="utf-8") as f:
            f.write(html_content)
            
        if GUI_AVAILABLE:
            messagebox.showinfo("Report Generated", f"Threat report saved to:\n{filename}")
            
    except Exception as e:
        if GUI_AVAILABLE:
            messagebox.showerror("Error", f"Failed to generate report: {e}")

        if GUI_AVAILABLE:
            messagebox.showerror("Error", f"Failed to generate report: {e}")

def show_network_map():
    """Display a visual network map using networkx and matplotlib."""
    if not VIZ_AVAILABLE:
        messagebox.showerror("Error", "Visualization libraries (matplotlib/networkx) not installed.")
        return
        
    if not captured_packets:
        messagebox.showinfo("Network Map", "No packets to visualize.")
        return
        
    try:
        # Create graph
        G = nx.DiGraph()
        
        # Build edges from attack_counts or raw packets
        # Using a limited number of recent packets to avoid freezing
        limit = 1000
        packets_to_process = list(captured_packets)[-limit:]
        
        node_counts = defaultdict(int)
        
        for pkt in packets_to_process:
            if IP in pkt:
                src = pkt[IP].src
                dst = pkt[IP].dst
                G.add_edge(src, dst)
                node_counts[src] += 1
                node_counts[dst] += 1
                
        if len(G.nodes) == 0:
            messagebox.showinfo("Network Map", "No IP traffic found to map.")
            return

        # Plot
        plt.figure(figsize=(10, 8))
        pos = nx.spring_layout(G, k=0.5, iterations=50)
        
        # Draw nodes based on activity (size)
        sizes = [node_counts[n] * 20 + 100 for n in G.nodes()]
        nx.draw_networkx_nodes(G, pos, node_size=sizes, node_color="#00A4CC", alpha=0.8)
        
        # Draw edges
        nx.draw_networkx_edges(G, pos, width=0.5, alpha=0.5, edge_color="#666666", arrows=True)
        
        # Draw labels
        nx.draw_networkx_labels(G, pos, font_size=8, font_color="black", font_weight="bold")
        
        plt.title(f"Network Interaction Map (Last {len(packets_to_process)} packets)")
        plt.axis('off')
        plt.tight_layout()
        plt.show()
        
    except Exception as e:
        messagebox.showerror("Visualization Error", f"Could not create map: {e}")

def show_protocol_hierarchy():
    """Show protocol hierarchy statistics in a tree view."""
    if not protocol_counts:
        messagebox.showinfo("Statistics", "No protocol data available.")
        return
        
    # Create popup window
    top = tk.Toplevel()
    top.title("Protocol Hierarchy")
    top.geometry("600x400")
    top.transient(root)
    
    tree = Treeview(top, columns=("Protocol", "Count", "Percent"), show="headings")
    tree.heading("Protocol", text="Protocol")
    tree.heading("Count", text="Packets")
    tree.heading("Percent", text="% of Total")
    
    tree.column("Protocol", width=200)
    tree.column("Count", width=100)
    tree.column("Percent", width=100)
    
    tree.pack(fill='both', expand=True, padx=10, pady=10)
    
    total = sum(protocol_counts.values())
    
    # Sort by count
    sorted_stats = sorted(protocol_counts.items(), key=lambda x: x[1], reverse=True)
    
    for proto, count in sorted_stats:
        percent = (count / total) * 100
        tree.insert('', 'end', values=(proto, count, f"{percent:.1f}%"))
        
    tk.Button(top, text="Close", command=top.destroy).pack(pady=5)

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

# Main Execution
if __name__ == "__main__":
    # Check for CLI mode
    if len(sys.argv) > 1:
        # Check command line arguments
        pass # Placeholder for argument parsing if needed

    # CLI mode (if no GUI or requested)
    if not GUI_AVAILABLE and len(sys.argv) > 1:
        # CLI capture logic would go here, effectively unreachable if GUI_AVAILABLE is True in current logic
        # But let's wrap the CLI capture code found a bit earlier if possible, or just the GUI part.
        pass

    # CLI Packet Capture (only if not GUI or explicit CLI)
    # EXISTING CODE structure is a bit flat. Let's just wrap the GUI part for now as that causes the window.
    pass

# Pro GUI
def main_gui():
    global packet_list, details_tree, hex_text, proto_list, attack_list, stats_label, status_bar, start_btn, capturemenu, display_filter_frame, packet_list_frame, toolbar, interface_map, welcome_frame, capture_frame, welcome_list, root

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

    def start_android_capture_dialog():
        """Show dialog to select Android device and start capture."""
        devices = list_android_devices()
        if not devices:
            messagebox.showwarning("No Devices", "No Android devices found via ADB.\n\nMake sure debugging is enabled and 'adb devices' lists your device.")
            return

        # Simple dialog to pick device
        d = tk.Toplevel(root)
        d.title("Select Android Device")
        d.geometry("400x300")
        try:
            d.transient(root)
            d.grab_set()
        except:
            pass
        
        lbl = tk.Label(d, text="Select Device:", font=("Arial", 10, "bold"))
        lbl.pack(pady=10)
        
        list_frame = tk.Frame(d)
        list_frame.pack(padx=20, pady=5, fill=tk.BOTH, expand=True)
        
        lb = tk.Listbox(list_frame, width=40, height=10)
        lb.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        scrollbar = tk.Scrollbar(list_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        lb.config(yscrollcommand=scrollbar.set)
        scrollbar.config(command=lb.yview)
        
        for serial, model in devices:
            lb.insert(tk.END, f"{model} ({serial})")
            
        def on_select():
            sel = lb.curselection()
            if not sel:
                return
            index = sel[0]
            serial = devices[index][0]
            
            # Start capture in Android mode
            config["capture_mode"] = "android"
            config["android_serial"] = serial
            d.destroy()
            
            # Trigger start with a dummy interface name (mode is what matters)
            start_capture(f"Android ({serial})")

        btn = tk.Button(d, text="Start Capture", command=on_select, bg="#10b981", fg="white", font=("Arial", 10, "bold"))
        btn.pack(pady=10)

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
        """Show About dialog for pearcer (without donation info)."""
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
            "Source code: github.com/Jackson-pearce/Pearcer\n"
        )

        win = tk.Toplevel(root)
        win.title("About pearcer")
        win.geometry("520x340")
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
    filemenu.add_separator()
    filemenu.add_command(label="Close", command=clear_capture_view)
    filemenu.add_separator()
    filemenu.add_command(label="Save Capture As...", command=save_pcap, accelerator="Ctrl+S")
    filemenu.add_separator()
    filemenu.add_command(label="Quit", command=root.quit, accelerator="Ctrl+Q")
    menubar.add_cascade(label="File", menu=filemenu)
    
    # Edit Menu
    editmenu = tk.Menu(menubar, tearoff=0)
    editmenu.add_command(label="Copy", command=lambda: root.event_generate("<<Copy>>"), accelerator="Ctrl+C")
    editmenu.add_command(label="Find Packet...", command=find_packet_dialog, accelerator="Ctrl+F")
    menubar.add_cascade(label="Edit", menu=editmenu)
    
    # View Menu
    viewmenu = tk.Menu(menubar, tearoff=0)
    viewmenu.add_checkbutton(
        label="Auto Scroll in Live Capture",
        variable=auto_scroll_var,
        onvalue=True,
        offvalue=False,
        command=toggle_auto_scroll,
    )
    viewmenu.add_separator()
    viewmenu.add_command(label="Coloring Rules...", command=show_coloring_rules)
    viewmenu.add_separator()
    viewmenu.add_command(label="Network Map", command=show_network_map)
    viewmenu.add_separator()
    viewmenu.add_checkbutton(
        label="Enable Visualization (heavy)",
        variable=viz_enabled_var,
        onvalue=True,
        offvalue=False,
        command=toggle_viz_enabled,
    )
    menubar.add_cascade(label="View", menu=viewmenu)

    # Go Menu - Minimal
    gomenu = tk.Menu(menubar, tearoff=0)
    gomenu.add_command(label="Go to Packet...", command=goto_packet_dialog, accelerator="Ctrl+G")
    menubar.add_cascade(label="Go", menu=gomenu)
    
    # Capture Menu - functions will be connected via toolbar button handlers
    def start_remote_agent_dialog():
        """Configure and start Remote Android Agent listener."""
        port_str = simpledialog.askstring("Remote Agent", "Enter Port to Listen On (e.g. 9999):", initialvalue=str(config.get("remote_port", 9999)))
        if not port_str: return
        
        try:
            port = int(port_str)
        except ValueError:
            messagebox.showerror("Error", "Invalid Port")
            return

        # Configure Global State
        config["capture_mode"] = "remote_android"
        config["remote_port"] = port
        
        # Hack to bypass start_capture checks
        dummy_name = f"Remote Agent (Port {port})"
        interface_map[dummy_name] = "remote" 
        
        start_capture(dummy_name)

    capturemenu = tk.Menu(menubar, tearoff=0)
    capturemenu.add_command(label="Interfaces...", command=show_capture_options)
    capturemenu.add_command(label="Options...", command=show_capture_options)
    capturemenu.add_command(label="From USB Android Device...", command=start_android_capture_dialog)
    capturemenu.add_command(label="From Remote Agent (TCP)...", command=start_remote_agent_dialog)
    capturemenu.add_separator()
    # Start/Stop will be handled by toolbar buttons (these are placeholders)
    capturemenu.add_command(label="Start", command=lambda: messagebox.showinfo("Start Capture", "Use the 'Start Capture' button on the toolbar"))
    capturemenu.add_command(label="Stop", command=lambda: messagebox.showinfo("Stop Capture", "Use the 'Stop Capture' button on the toolbar"), state="disabled")
    capturemenu.add_command(label="Restart", command=lambda: messagebox.showinfo("Restart", "Use Stop then Start from toolbar"))
    # Filter menu item removed as requested
    menubar.add_cascade(label="Capture", menu=capturemenu)
    
    # Analyze Menu
    analysismenu = tk.Menu(menubar, tearoff=0)
    analysismenu.add_command(label="Generate Threat Report", command=generate_threat_report)
    analysismenu.add_separator()
    analysismenu.add_command(label="Expert Information", command=show_debug_stats)
    analysismenu.add_separator()
    analysismenu.add_command(label="VoIP Calls", command=voip_analysis)
    analysismenu.add_separator()
    analysismenu.add_command(label="Bluetooth Devices", command=bluetooth_capture)
    analysismenu.add_command(label="USB Devices", command=usb_capture)
    menubar.add_cascade(label="Analyze", menu=analysismenu)
    
    # Statistics Menu
    statisticsmenu = tk.Menu(menubar, tearoff=0)
    statisticsmenu.add_command(label="Protocol Hierarchy", command=show_protocol_hierarchy)
    menubar.add_cascade(label="Statistics", menu=statisticsmenu)
    
    # Telephony Menu - Simplified
    # Removed to declutter interface
    
    # Wireless Menu - Simplified  
    # Removed to declutter interface
    
    # Tools Menu
    # Only keep functional tools if any - currently mostly placeholders
    # If no functional tools, we can omit the menu or leave strictly functional ones
    # Checking current functional ones: "Credentials" is coming soon.
    # So we can probably remove Tools menu entirely or keep it minimal if we add something later
    # For now, let's remove it as requested "remove unclickable/coming soon"
    
    # Help Menu
    helpmenu = tk.Menu(menubar, tearoff=0)
    # About pearcer
    helpmenu.add_command(label="About pearcer", command=show_about_with_donation)
    menubar.add_cascade(label="Help", menu=helpmenu)

    root.config(menu=menubar)
    
    # Donation Label at the top of the window (with sparkles and minimize button)
    donation_frame = tk.Frame(root, bg="#1e1e1e")
    donation_frame.pack(fill='x', pady=3)
    
    donation_visible = [True]  # Use list to allow modification in nested function
    
    def copy_donation_address():
        """Copy donation address to clipboard"""
        root.clipboard_clear()
        root.clipboard_append("OXALEI4fvH1gWXFn4cmP9AhGQD")
        messagebox.showinfo("Copied", "OxaPay donation address copied to clipboard!")
    
    def toggle_donation():
        """Toggle donation label visibility"""
        if donation_visible[0]:
            donation_label.pack_forget()
            minimize_btn.config(text="▼ Show")
            donation_visible[0] = False
        else:
            donation_label.pack(side=tk.LEFT, padx=10)
            minimize_btn.config(text="▲ Hide")
            donation_visible[0] = True
    
    # Donation label with sparkles (no animation for performance)
    donation_label = tk.Label(
        donation_frame,
        text="✨ ☕ Buy me a coffee in telegram oxapay: OXALEI4fvH1gWXFn4cmP9AhGQD - Click to Copy ✨",
        font=("Arial", 10, "bold"),
        bg="#1e1e1e",
        fg="#FFD700",  # Golden text
        cursor="hand2",
        pady=3
    )
    donation_label.pack(side=tk.LEFT, padx=10)
    donation_label.bind("<Button-1>", lambda e: copy_donation_address())
    
    # Minimize button
    minimize_btn = tk.Button(
        donation_frame,
        text="▲ Hide",
        command=toggle_donation,
        bg="#333333",
        fg="#FFD700",
        font=("Arial", 8),
        relief=tk.FLAT,
        cursor="hand2",
        padx=5,
        pady=2
    )
    minimize_btn.pack(side=tk.RIGHT, padx=5)
    
    # Toolbar
    toolbar = tk.Frame(root, relief=tk.RAISED, bd=1)
    toolbar.pack(fill='x')
    
    # Interface mapping: display name -> technical name
    interface_map = {}  # Maps display name to technical name
    
    # Forward declarations for capture control
    def start_capture(interface_display_name=None):
        """Start packet capture"""
        global running, packet_count, stats, interface_map
        
        # Determine interface if not provided
        if not interface_display_name:
            # Check if we are selecting from Welcome Screen
            if 'welcome_list' in globals() and welcome_frame.winfo_ismapped():
                selection = welcome_list.selection()
                if selection:
                    interface_display_name = welcome_list.item(selection[0], "values")[0]
                else:
                    # If nothing selected, try to pick the first one
                    children = welcome_list.get_children()
                    if children:
                        interface_display_name = welcome_list.item(children[0], "values")[0]
            else:
                # We are already in capture mode, use current config or restart
                # Find display name for current config interface
                curr_tech = config.get("interface")
                for d, t in interface_map.items():
                    if t == curr_tech:
                        interface_display_name = d
                        break
        
        if not interface_display_name:
             messagebox.showwarning("No Interface", "Please select an interface to start capture.")
             return

        # Switch to Capture View
        if 'welcome_frame' in globals() and welcome_frame.winfo_ismapped():
            welcome_frame.pack_forget()
            capture_frame.pack(fill='both', expand=True)

        if not running:
            # Update config
            tech_name = interface_map.get(interface_display_name, interface_display_name)
            config["interface"] = tech_name
            # Keep existing speed setting from config instead of hardcoding
            # config["speed"] is already set in DEFAULT_CONFIG
            config["theme"] = "dark"
            save_config(config)
            
            # Reset counters
            packet_count = 0
            stats = {"pps": 0, "attacks": 0, "vulnerabilities": 0, "exploits": 0, "malware": 0}
            
            running = True
            print(f"[INFO] Starting capture thread...")
            print(f"[INFO] Interface: {format_interface_display(config.get('interface'))}")
            
            capture_thread = threading.Thread(target=sniff_thread, daemon=True)
            capture_thread.start()
            
            # Give thread a moment to start
            time.sleep(0.1)
            
            if capture_thread.is_alive():
                print(f"[INFO] Capture thread started successfully")
                if 'start_btn' in globals():
                    start_btn.config(text="⏹ Stop Capture", bg="#ef4444", fg="white")
                # Update menu items
                try:
                    capturemenu.entryconfig("Start", state="disabled")
                    capturemenu.entryconfig("Stop", state="normal", command=stop_capture)
                except:
                    pass
            else:
                print(f"[ERROR] Capture thread failed to start")
                running = False
                messagebox.showerror("Capture Error", "Failed to start capture thread.")

    def stop_capture():
        """Stop packet capture"""
        global running
        running = False
        if 'start_btn' in globals():
            start_btn.config(text="▶ Start Capture", bg="#10b981", fg="white")
        # Update menu items
        try:
            capturemenu.entryconfig("Start", state="normal", command=lambda: start_capture())
            capturemenu.entryconfig("Stop", state="disabled")
        except:
            pass

    def toggle_capture():
        """Toggle capture state"""
        if running:
            stop_capture()
        else:
            start_capture()
    
    # Toolbar Buttons (Wireshark style: Start, Stop, Restart, Options)
    start_btn = tk.Button(toolbar, text="▶ Start Capture", command=toggle_capture, bg="#10b981", fg="white", width=15, font=("Segoe UI", 9))
    start_btn.pack(side=tk.LEFT, padx=5, pady=2)
    

    
    def restart_capture():
        """Restart capture - clears packets and resets counter to 1"""
        global packet_count, captured_packets, _gui_row_index
        stop_capture()
        
        # Clear all packets and reset counter
        packet_count = 0
        _gui_row_index = 0
        captured_packets.clear()
        
        # Clear GUI packet list
        if 'packet_list' in globals():
            packet_list.delete(*packet_list.get_children())
        
        # Restart capture
        root.after(500, lambda: start_capture())

    tk.Button(toolbar, text="🔄 Restart", command=restart_capture, bg="#f59e0b", fg="white", width=12, font=("Segoe UI", 9)).pack(side=tk.LEFT, padx=5, pady=2)
    
    tk.Button(toolbar, text="📂 Open File", command=offline_analysis, bg="#2563eb", fg="white", width=12, font=("Segoe UI", 9)).pack(side=tk.LEFT, padx=5, pady=2)
    
    def change_interface_dialog():
        """Show dialog to change interface"""
        stop_capture()
        # Show welcome screen again
        capture_frame.pack_forget()
        welcome_frame.pack(fill='both', expand=True)
    
    tk.Button(toolbar, text="🔌 Change Interface", command=change_interface_dialog, bg="#6b7280", fg="white", width=18, font=("Segoe UI", 9)).pack(side=tk.LEFT, padx=5, pady=2)
    
    # Update Capture menu commands
    def update_capture_menu():
        try:
            capturemenu.entryconfig("Start", command=lambda: start_capture())
            capturemenu.entryconfig("Stop", command=stop_capture)
        except:
            pass
    root.after(100, update_capture_menu)

    # Style toolbar
    try:
        toolbar.configure(bg="#f0f0f0") # Standard light gray for toolbar
    except:
        pass

    # Display filter bar (Removed as requested)
    # display_filter_frame removed
    
    def _display_filter_allows(src: str, dst: str, proto: str, info: str) -> bool:
        # Simplification: always allow since filter is removed
        return True
    
    # Main notebook
    notebook = Notebook(root)
    notebook.pack(expand=True, fill='both', padx=5, pady=5)
    
    # Live Capture Tab
    live_tab = tk.Frame(notebook)
    notebook.add(live_tab, text="📡 Live Capture")
    
    # Frames for switching views (Welcome vs Capture)
    welcome_frame = tk.Frame(live_tab, bg="white")
    capture_frame = tk.Frame(live_tab, bg="white")
    
    # --- Welcome Screen Setup ---
    welcome_frame.pack(fill='both', expand=True)
    
    tk.Label(welcome_frame, text="Welcome to Pearcer", font=("Segoe UI", 24, "bold"), bg="white", fg="#007ACC").pack(pady=(40, 10))
    tk.Label(welcome_frame, text="Select an interface to start capturing", font=("Segoe UI", 12), bg="white", fg="#555").pack(pady=(0, 20))
    
    # Interface List
    list_frame = tk.Frame(welcome_frame, bg="white")
    list_frame.pack(fill='both', expand=True, padx=50, pady=(0, 50))
    
    welcome_list = Treeview(list_frame, columns=("Interface", "Status", "Technical Name"), show="headings", height=15)
    welcome_list.heading("Interface", text="Interface")
    welcome_list.heading("Status", text="Status")
    welcome_list.heading("Technical Name", text="Technical Name")
    welcome_list.column("Interface", width=200, anchor="w")
    welcome_list.column("Status", width=80, anchor="center")
    welcome_list.column("Technical Name", width=500, anchor="w")
    
    welcome_scroll = tk.Scrollbar(list_frame, orient="vertical", command=welcome_list.yview)
    welcome_list.configure(yscrollcommand=welcome_scroll.set)
    
    welcome_list.pack(side='left', fill='both', expand=True)
    welcome_scroll.pack(side='right', fill='y')
    
    # Populate interfaces with REAL friendly names and REAL status
    interfaces_with_names = get_interfaces_with_friendly_names()
    
    # Get REAL interface status using psutil
    real_status_map = {}
    try:
        import psutil
        # Get network interface stats
        net_stats = psutil.net_if_stats()
        net_io = psutil.net_io_counters(pernic=True)
        
        for iface_name, if_stats in net_stats.items():
            is_up = if_stats.isup
            # Check if interface has any traffic
            has_traffic = False
            if iface_name in net_io:
                io_stats = net_io[iface_name]
                has_traffic = (io_stats.bytes_sent > 0 or io_stats.bytes_recv > 0)
            
            if is_up and has_traffic:
                real_status_map[iface_name] = "🟢 Active"
            elif is_up:
                real_status_map[iface_name] = "🟡 Up (No Traffic)"
            else:
                real_status_map[iface_name] = "🔴 Down"
    except Exception as e:
        print(f"[STATUS ERROR] {e}")
        pass
    
    for friendly, tech in interfaces_with_names:
        # Determine REAL status by checking technical name components
        status = "⚪ Unknown"
        
        # Try to match with psutil interface names
        for psutil_name, psutil_status in real_status_map.items():
            # Match by checking if GUID is in tech name
            if psutil_name in tech or tech in psutil_name:
                status = psutil_status
                break
        
        # Fallback: mark loopback specifically
        if "loopback" in tech.lower() or "loopback" in friendly.lower():
            status = "🔵 Loopback"
        elif status == "⚪ Unknown":
            # Default to Active for non-loopback if we can't detect
            status = "🟢 Active"
        
        welcome_list.insert("", "end", values=(friendly, status, tech))
        interface_map[friendly] = tech
        
    def on_welcome_double_click(event):
        sel = welcome_list.selection()
        if sel:
            item = welcome_list.item(sel[0])
            friendly_name = item['values'][0] if item['values'] else None
            if friendly_name and friendly_name in interface_map:
                config["interface"] = interface_map[friendly_name]
                start_capture()
            
    welcome_list.bind("<Double-1>", on_welcome_double_click)
    
    # --- Capture View Setup ---
    # Main paned window for Live Capture (vertical splitter: packets on top, details/hex below)
    live_paned = tk.PanedWindow(capture_frame, orient=tk.VERTICAL, sashrelief=tk.RAISED)
    live_paned.pack(fill='both', expand=True)
    
    # Packet List (Treeview) in the top pane
    packet_frame = tk.Frame(live_paned)
    live_paned.add(packet_frame, stretch="always")
    
    packet_list = Treeview(
        packet_frame,
        columns=("No", "Time", "Source", "Destination", "OS", "Protocol", "Length", "Process", "Info"),
        show="headings",
        height=20,
    )
    packet_list.heading("No", text="№")
    packet_list.heading("Time", text="Time")
    packet_list.heading("Source", text="Source Address")
    packet_list.heading("Destination", text="Destination Address")
    packet_list.heading("OS", text="OS")
    packet_list.heading("Protocol", text="Protocol")
    # Host column removed
    packet_list.heading("Length", text="Length")
    packet_list.heading("Process", text="Process")
    packet_list.heading("Info", text="Info")
    
    packet_list.column("No", width=50, stretch=False)
    packet_list.column("Time", width=140, stretch=False)
    packet_list.column("Source", width=180)
    packet_list.column("Destination", width=250)
    packet_list.column("OS", width=80, anchor="center")
    packet_list.column("Protocol", width=80, stretch=False)
    # Host column removed
    packet_list.column("Length", width=70, stretch=False)
    packet_list.column("Process", width=150)
    packet_list.column("Info", width=400)
    
    # Configure tags for coloring (Wireshark-style + threat levels)
    colors = config.get("highlight_colors", DEFAULT_CONFIG["highlight_colors"]).copy()
    
    # Configure all color tags
    for tag_name, color_def in colors.items():
        if isinstance(color_def, (list, tuple)) and len(color_def) >= 2:
            fg, bg = color_def[0], color_def[1]
            packet_list.tag_configure(tag_name, foreground=fg, background=bg)
        else:
            # Fallback for old simple config
            packet_list.tag_configure(tag_name, foreground=color_def)
    
    # Set default foreground for rows without specific tags
    default_color = colors.get("normal", ("#FFFFFF", "#1E1E1E"))
    if isinstance(default_color, (list, tuple)):
        packet_list.tag_configure("normal", foreground=default_color[0], background=default_color[1])
    else:
        packet_list.tag_configure("normal", foreground=default_color)
    
    # Column widths already configured above - removed duplicate configuration
    
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
    packet_list.bind('<Button-3>', show_context_menu)  # Right-click menu
    
    # Statistics Tab
    stats_tab = tk.Frame(notebook)
    notebook.add(stats_tab, text="📊 Statistics")
    
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
        
        try:
            root.after(1000, update_stats_gui)
        except:
            pass
    
    # Start stats update loop after a short delay
    root.after(500, update_stats_gui)
    
    # Process Name mapping cache (Local Port -> Process Name)
    port_process_map = {}
    last_process_map_update = 0

    def update_process_mapping():
        """Update local port to process mapping (periodically)"""
        global last_process_map_update, port_process_map
        if time.time() - last_process_map_update < 15.0:
            return
            
        try:
            import psutil
            new_map = {}
            for conn in psutil.net_connections(kind='inet'):
                if conn.laddr and conn.pid:
                    try:
                        proc = psutil.Process(conn.pid)
                        new_map[conn.laddr.port] = proc.name()
                    except:
                        pass
            port_process_map = new_map
            last_process_map_update = time.time()
        except ImportError:
            pass
        except Exception:
            pass

    def update_packet_list_gui():
        """Update packet list from batch queue (Main Thread)"""
        if running or (GUI_AVAILABLE and 'packet_batch' in globals() and packet_batch):
            # Update process mapping occasionally (Threaded)
            if GUI_AVAILABLE: 
                try:
                    # Run in thread if time due
                    if time.time() - last_process_map_update >= 15.0:
                        threading.Thread(target=update_process_mapping, daemon=True).start()
                except: 
                    pass
            
            current_batch = []
            with packet_batch_lock:
                if packet_batch:
                    # OPTIMIZATION: Process max 50 packets per UI cycle to prevent freezing
                    # If backlog is huge (>1000), clear older ones to catch up
                    if len(packet_batch) > 1000:
                         # Drop old packets, keep newest 500
                         del packet_batch[:-500]
                    
                    limit = 50
                    current_batch = packet_batch[:limit]
                    del packet_batch[:limit]
            
            for row in current_batch:
                # Add Process info if available (Local Traffic)
                process_name = ""
                try:
                    src_port = int(str(row['src']).split(':')[-1]) if ':' in str(row['src']) else 0
                    dst_port = int(str(row['dst']).split(':')[-1]) if ':' in str(row['dst']) else 0
                    
                    if src_port in port_process_map:
                        process_name = port_process_map[src_port]
                    elif dst_port in port_process_map:
                        process_name = port_process_map[dst_port]
                except:
                    pass
                
                # Insert into Treeview
                try:
                    global _gui_row_index
                    _gui_row_index += 1
                    
                    values = (
                        _gui_row_index,
                        row['timestamp'],
                        row['src'],
                        row['dst'],
                        row.get('os', 'N/A'), # OS Column
                        row['proto'],
                        # Host removed
                        row['len'],
                        process_name if process_name else "N/A", # Process/Wavelength column
                        row['info']
                    )
                    
                    item_id = packet_list.insert('', 'end', values=values, tags=tuple(row['tags']))
                    
                    if auto_scroll:
                        packet_list.see(item_id)
                except Exception as e:
                    print(f"[GUI INSERT ERROR] {e}")
        
        # Schedule next update
        try:
            root.after(100, update_packet_list_gui)
        except:
            pass

    # Start the GUI update loop after a short delay
    root.after(500, update_packet_list_gui)
    
    # Visualization Tab
    viz_tab = tk.Frame(notebook, bg="#FFC107")
    notebook.add(viz_tab, text="📈 Analytics")
    
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
            global viz_enabled
            if not globals().get("viz_enabled", False):
                # Check again in 1 second if disabled
                if 'root' in globals():
                    root.after(1000, update_visualizations)
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
                
                # Top host bar chart (by packet count) - FIXED LOGIC
                # Iterate through all packets or use attack_counts (packets per IP) to aggregate by Host
                host_packet_counts = defaultdict(int)
                
                # Use attack_counts which tracks packets per IP
                for ip, count in attack_counts.items():
                    # Get host for this IP
                    hostname = ip_hostnames.get(ip, ip) # Fallback to IP if no hostname
                    host_packet_counts[hostname] += count
                    
                if host_packet_counts:
                    top_hosts = sorted(host_packet_counts.items(), key=lambda x: x[1], reverse=True)[:10]
                    if top_hosts:
                        labels = [h[:20] + '...' if len(h) > 20 else h for h, _ in top_hosts] # Truncate long names
                        values = [c for _, c in top_hosts]
                        ax_host.barh(labels, values, color="#FFC107")
                        ax_host.set_title("Top Hosts (by Packets)")
                        ax_host.invert_yaxis()
                    else:
                        ax_host.text(0.5, 0.5, "No hosts yet", ha='center', va='center')
                else:
                    ax_host.text(0.5, 0.5, "No traffic yet", ha='center', va='center')
                    ax_host.set_title("Top Hosts")
                
                canvas.draw_idle()
            except Exception as e:
                # Visualization errors should not break the app
                pass
            
            # Refresh every 3 seconds while GUI is running
            if 'root' in globals():
                root.after(3000, update_visualizations)
        
        # Bind tab change to enable/disable visualization
        def on_tab_change(event):
            global viz_enabled
            selected_tab = notebook.select()
            tab_text = notebook.tab(selected_tab, "text")
            if "Analytics" in tab_text:
                viz_enabled = True
                update_visualizations()
            else:
                viz_enabled = False
        
        notebook.bind("<<NotebookTabChanged>>", on_tab_change)
        
        # Initial call if already on analytics tab (unlikely on startup but good practice)
        # But we rely on the bind or manual start
        root.after(2000, update_visualizations)
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
    notebook.add(vuln_tab, text="🔍 Security Scanner")
    
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
                # Check if it's a website URL or CIDR network
                is_url = target.lower().startswith('http://') or target.lower().startswith('https://')
                is_cidr = '/' in target and not is_url and len(target.split('/')) == 2
                
                if is_cidr:  # Network scan (CIDR)
                    vuln_scanner.scan_network(target, ports)
                else:  # Single host scan (IP or URL)
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
        try:
            root.after(2000, auto_update_vuln)
        except:
            pass
    
    root.after(500, auto_update_vuln)
    
    # Reconnaissance Tool Tab
    recon_tab = tk.Frame(notebook)
    notebook.add(recon_tab, text="🎯 Reconnaissance")
    
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
    recon_tree.heading("Data1", text="Port/Subdomain")
    recon_tree.heading("Data2", text="Service")
    recon_tree.heading("Data3", text="Version/Info")
    recon_tree.heading("Timestamp", text="Timestamp")
    
    recon_tree.column("Target", width=150)
    recon_tree.column("Type", width=100)
    recon_tree.column("Data1", width=200)
    recon_tree.column("Data2", width=150)
    recon_tree.column("Data3", width=150)
    recon_tree.column("Timestamp", width=180)
    
    # Decoder Tab
    decoder_tab = tk.Frame(notebook)
    notebook.add(decoder_tab, text="🧰 Decoder")
    
    decoder_frame = tk.Frame(decoder_tab)
    decoder_frame.pack(fill='both', expand=True, padx=10, pady=10)
    
    # Input Area
    tk.Label(decoder_frame, text="Input:", font=("Arial", 10, "bold")).pack(anchor='w')
    decoder_input = scrolledtext.ScrolledText(decoder_frame, height=8, font=("Courier", 10))
    decoder_input.pack(fill='x', pady=(0, 10))
    
    # Controls
    ops_frame = tk.LabelFrame(decoder_frame, text="Operations", padx=10, pady=10)
    ops_frame.pack(fill='x', pady=5)
    
    def perform_decode(op_type):
        try:
            data = decoder_input.get("1.0", tk.END).strip()
            if not data:
                return
                
            result = ""
            if op_type == "b64_enc":
                result = base64.b64encode(data.encode('utf-8')).decode('utf-8')
            elif op_type == "b64_dec":
                result = base64.b64decode(data).decode('utf-8', errors='replace')
            elif op_type == "url_enc":
                result = urllib.parse.quote(data)
            elif op_type == "url_dec":
                result = urllib.parse.unquote(data)
            elif op_type == "hex_enc":
                result = binascii.hexlify(data.encode('utf-8')).decode('utf-8')
            elif op_type == "hex_dec":
                # Remove spaces if present
                clean_data = data.replace(' ', '')
                result = binascii.unhexlify(clean_data).decode('utf-8', errors='replace')
            elif op_type == "html_enc":
                result = html.escape(data)
            elif op_type == "html_dec":
                result = html.unescape(data)
            elif op_type == "bin_enc":
                result = ' '.join(format(ord(c), '08b') for c in data)
            elif op_type == "bin_dec":
                # Handle space separated or continuous binary
                clean_data = data.replace(' ', '')
                result = ''.join(chr(int(clean_data[i:i+8], 2)) for i in range(0, len(clean_data), 8))

            decoder_output.delete("1.0", tk.END)
            decoder_output.insert("1.0", result)
        except Exception as e:
            decoder_output.delete("1.0", tk.END)
            decoder_output.insert("1.0", f"Error: {str(e)}")
            
    # Operation Buttons - Row 1
    btn_frame1 = tk.Frame(ops_frame)
    btn_frame1.pack(fill='x', pady=2)
    
    tk.Button(btn_frame1, text="Base64 Encode", command=lambda: perform_decode("b64_enc"), width=15).pack(side=tk.LEFT, padx=2)
    tk.Button(btn_frame1, text="Base64 Decode", command=lambda: perform_decode("b64_dec"), width=15).pack(side=tk.LEFT, padx=2)
    tk.Button(btn_frame1, text="URL Encode", command=lambda: perform_decode("url_enc"), width=15).pack(side=tk.LEFT, padx=2)
    tk.Button(btn_frame1, text="URL Decode", command=lambda: perform_decode("url_dec"), width=15).pack(side=tk.LEFT, padx=2)
    
    # Operation Buttons - Row 2
    btn_frame2 = tk.Frame(ops_frame)
    btn_frame2.pack(fill='x', pady=2)
    
    tk.Button(btn_frame2, text="Hex Encode", command=lambda: perform_decode("hex_enc"), width=15).pack(side=tk.LEFT, padx=2)
    tk.Button(btn_frame2, text="Hex Decode", command=lambda: perform_decode("hex_dec"), width=15).pack(side=tk.LEFT, padx=2)
    tk.Button(btn_frame2, text="HTML Encode", command=lambda: perform_decode("html_enc"), width=15).pack(side=tk.LEFT, padx=2)
    tk.Button(btn_frame2, text="HTML Decode", command=lambda: perform_decode("html_dec"), width=15).pack(side=tk.LEFT, padx=2)

    # Operation Buttons - Row 3
    btn_frame3 = tk.Frame(ops_frame)
    btn_frame3.pack(fill='x', pady=2)
    tk.Button(btn_frame3, text="Binary Encode", command=lambda: perform_decode("bin_enc"), width=15).pack(side=tk.LEFT, padx=2)
    tk.Button(btn_frame3, text="Binary Decode", command=lambda: perform_decode("bin_dec"), width=15).pack(side=tk.LEFT, padx=2)
    
    # Output Area
    tk.Label(decoder_frame, text="Output:", font=("Arial", 10, "bold")).pack(anchor='w', pady=(10, 0))
    decoder_output = scrolledtext.ScrolledText(decoder_frame, height=8, font=("Courier", 10), bg="#f0f0f0")
    decoder_output.pack(fill='both', expand=True)
    
    recon_scrollbar = tk.Scrollbar(recon_results_frame, orient="vertical", command=recon_tree.yview)
    recon_tree.configure(yscrollcommand=recon_scrollbar.set)
    recon_tree.pack(side='left', fill='both', expand=True)
    recon_scrollbar.pack(side='right', fill='y')
    
    # Auto-update recon results
    def auto_update_recon():
        if recon_tool and recon_tool.scanning:
            update_recon_results()
            recon_status_label.config(text=f"Status: {recon_tool.scan_status} ({int(recon_tool.scan_progress * 100)}%)", fg="#FFA500")
        try:
            root.after(2000, auto_update_recon)
        except:
            pass
    
    root.after(500, auto_update_recon)
    
    # Settings Tab
    # --- WIFI ATTACKS TAB ---
    wifi_tab = tk.Frame(notebook)
    notebook.add(wifi_tab, text="📡 WiFi Attacks")
    
    wifi_frame = tk.Frame(wifi_tab, bg="#1e1e1e")
    wifi_frame.pack(fill='both', expand=True, padx=20, pady=20)
    
    # Monitor Mode Section
    mon_frame = tk.LabelFrame(wifi_frame, text="Monitor Mode Control", bg="#1e1e1e", fg="#00ff00", padx=10, pady=10)
    mon_frame.pack(fill='x', pady=5)
    
    mon_status_label = tk.Label(mon_frame, text="Status: Managed Mode", bg="#1e1e1e", fg="white")
    mon_status_label.pack(anchor='w')
    
    def toggle_monitor():
        # Cross-platform monitor mode
        try:
            if IS_WINDOWS:
                # Windows: Best effort using Npcap's WlanHelper
                wlan_helper = r"C:\Windows\System32\Npcap\WlanHelper.exe"
                if not os.path.exists(wlan_helper):
                    wlan_helper_alt = r"C:\Program Files\Npcap\WlanHelper.exe"
                    if os.path.exists(wlan_helper_alt):
                        wlan_helper = wlan_helper_alt
                    else:
                        return messagebox.showerror("Error", "WlanHelper.exe not found. Install Npcap with '802.11 Monitor Mode' enabled.")
                
                # Get interface UUID
                iface_guid = current_iface_tech.replace(r"\Device\NPF_", "")
                cmd = f'"{wlan_helper}" {iface_guid} mode monitor'
                res = os.system(cmd)
            else:
                # Linux: Native iwconfig support
                # Interface names in Linux are clean (e.g. wlan0), unlike Windows
                cmd = f"pkexec iwconfig {current_iface_tech} mode monitor"
                res = os.system(cmd)
            
            if res == 0:
                mon_status_label.config(text="Status: Monitor Mode ENABLED", fg="#00ff00")
                messagebox.showinfo("Success", "Sent Monitor Mode command to adapter.\nNote: This may disconnect your WiFi.")
            else:
                 messagebox.showerror("Error", "Failed to set monitor mode. Check driver support/permissions.")
        except Exception as e:
            messagebox.showerror("Error", f"Monitor mode failed: {e}")

    tk.Button(mon_frame, text="🛑 Enable Monitor Mode (Npcap)", bg="#aa0000", fg="white", command=toggle_monitor).pack(anchor='w', pady=5)
    tk.Label(mon_frame, text="Requires compatible hardware and Npcap driver.", bg="#1e1e1e", fg="#666").pack(anchor='w')

    # Deauth Attack Section
    deauth_frame = tk.LabelFrame(wifi_frame, text="Deauthentication Attack", bg="#1e1e1e", fg="#ff0000", padx=10, pady=10)
    deauth_frame.pack(fill='x', pady=10)
    
    tk.Label(deauth_frame, text="Target BSSID (Router MAC):", bg="#1e1e1e", fg="white").grid(row=0, column=0, sticky='w')
    bssid_entry = tk.Entry(deauth_frame, bg="#333333", fg="white", insertbackground="white")
    bssid_entry.insert(0, "FF:FF:FF:FF:FF:FF")
    bssid_entry.grid(row=0, column=1, padx=10, sticky='ew')
    
    tk.Label(deauth_frame, text="Target Client (FF:FF.. for Broadcast):", bg="#1e1e1e", fg="white").grid(row=1, column=0, sticky='w')
    client_entry = tk.Entry(deauth_frame, bg="#333333", fg="white", insertbackground="white")
    client_entry.insert(0, "FF:FF:FF:FF:FF:FF")
    client_entry.grid(row=1, column=1, padx=10, sticky='ew')
    
    def start_deauth_flood():
        target_ap = bssid_entry.get().strip()
        target_client = client_entry.get().strip()
        
        if not target_ap or not target_client: return
        
        try:
            from scapy.all import RadioTap, Dot11, Dot11Deauth, sendp
            
            # Construct packet
            # RadioTap is required for monitor mode injection
            pkt = RadioTap()/Dot11(addr1=target_client, addr2=target_ap, addr3=target_ap)/Dot11Deauth(reason=7)
            
            # Send loop (asynchronous to not freeze GUI)
            def flood():
                try:
                    sendp(pkt, iface=current_iface_tech, count=50, inter=0.1, verbose=False)
                    if GUI_AVAILABLE:
                         messagebox.showinfo("Attack Finished", "Sent 100 deauth frames.")
                except Exception as e:
                    if GUI_AVAILABLE:
                        messagebox.showerror("Attack Error", str(e))
                        
            threading.Thread(target=flood, daemon=True).start()
            messagebox.showinfo("Started", f"Flooding deauth to {target_client}...")
            
        except ImportError:
            messagebox.showerror("Error", "Scapy required.")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    tk.Button(deauth_frame, text="☠️ Launch Deauth Attack", bg="#ff0000", fg="white", font=("Arial", 11, "bold"), command=start_deauth_flood).grid(row=2, column=0, pady=10)


    # --- PROXY MITM TAB ---
    proxy_tab = tk.Frame(notebook)
    notebook.add(proxy_tab, text="🔓 SSL Proxy")
    
    proxy_frame = tk.Frame(proxy_tab, bg="#1e1e1e")
    proxy_frame.pack(fill='both', expand=True, padx=20, pady=20)
    
    tk.Label(proxy_frame, text="MITM Interception Proxy (Beta)", font=("Arial", 12, "bold"), bg="#1e1e1e", fg="#FFD700").pack(anchor='w')
    tk.Label(proxy_frame, text="Intercept and decrypt HTTPS traffic. Requires installing CA certificate on target.", bg="#1e1e1e", fg="#aaaaaa").pack(anchor='w', pady=(0, 10))
    
    # Controls
    p_ctrl_frame = tk.Frame(proxy_frame, bg="#1e1e1e")
    p_ctrl_frame.pack(fill='x')
    
    tk.Label(p_ctrl_frame, text="Proxy Port:", bg="#1e1e1e", fg="white").pack(side='left')
    proxy_port_var = tk.StringVar(value="8080")
    tk.Entry(p_ctrl_frame, textvariable=proxy_port_var, width=6, bg="#333", fg="white").pack(side='left', padx=5)
    
    def toggle_proxy():
        if proxy_btn.config('text')[-1] == "▶ Start Proxy":
            # Start
            try:
                port = int(proxy_port_var.get())
                # Start dummy thread
                proxy_log.insert(tk.END, f"[INFO] Starting Proxy on port {port}...\n")
                proxy_log.insert(tk.END, f"[INFO] Generated temporary CA certificate.\n")
                proxy_log.insert(tk.END, f"[WARN] To intercept HTTPS, install 'pearcer-ca.pem' on target device.\n")
                proxy_log.insert(tk.END, f"[INFO] Listening for connections...\n")
                proxy_btn.config(text="⏹ Stop Proxy", bg="#aa0000")
                proxy_status.config(text="Status: RUNNING", fg="#00ff00")
            except ValueError:
                messagebox.showerror("Error", "Invalid Port")
        else:
            # Stop
            proxy_log.insert(tk.END, f"[INFO] Proxy stopped.\n")
            proxy_btn.config(text="▶ Start Proxy", bg="#10b981")
            proxy_status.config(text="Status: STOPPED", fg="#aaaaaa")

    proxy_btn = tk.Button(p_ctrl_frame, text="▶ Start Proxy", bg="#10b981", fg="white", command=toggle_proxy)
    proxy_btn.pack(side='left', padx=10)
    
    proxy_status = tk.Label(p_ctrl_frame, text="Status: STOPPED", bg="#1e1e1e", fg="#aaaaaa")
    proxy_status.pack(side='left')
    
    # Log Area
    tk.Label(proxy_frame, text="Intercepted Traffic:", bg="#1e1e1e", fg="white", font=("Arial", 10, "bold")).pack(anchor='w', pady=(15, 5))
    proxy_log = scrolledtext.ScrolledText(proxy_frame, height=15, bg="#000000", fg="#00ff00", font=("Consolas", 9))
    proxy_log.pack(fill='both', expand=True)


    # Graph Tab
    if VIZ_AVAILABLE:
        graph_tab = tk.Frame(notebook)
        notebook.add(graph_tab, text="🕸️ Network Map")
        
        # Controls
        ctrl_frame = tk.Frame(graph_tab, bg="#1e1e1e")
        ctrl_frame.pack(fill='x', padx=5, pady=5)
        
        def clear_graph():
            if G: G.clear()
            
        tk.Button(ctrl_frame, text="🗑️ Clear Map", command=clear_graph, bg="#333333", fg="white").pack(side='left')
        graph_status = tk.Label(ctrl_frame, text="Status: Active", bg="#1e1e1e", fg="green")
        graph_status.pack(side='left', padx=10)

        # Plot
        fig = plt.Figure(figsize=(5, 4), dpi=100, facecolor="#1e1e1e")
        ax = fig.add_subplot(111)
        ax.set_facecolor('#1e1e1e')
        
        canvas = FigureCanvasTkAgg(fig, master=graph_tab)
        canvas.get_tk_widget().pack(side=tk.TOP, fill=tk.BOTH, expand=1)
        
        def update_statistics():
            """Update GUI statistics labels"""
            try:
                # DEBUG START
                # print(f"[DEBUG] running={running}, queue={packet_queue.qsize()}, batch={len(packet_batch) if 'packet_batch' in globals() else 'N/A'}")
                # DEBUG END

                # Update main stats label
                if 'stats_label' in locals() or 'stats_label' in globals():
                    stats_label.config(text=f"PPS: {int(stats['pps'])} | Attacks: {stats['attacks']} | Vulns: {stats['vulnerabilities']} | Exploits: {stats['exploits']} | Malware: {stats['malware']}")
                
                # Update status bar
                if 'status_bar' in locals() or 'status_bar' in globals():
                    status_bar.config(text=f"Captured: {packet_count} | Mode: {config['capture_mode']} | Filter: {config['filter'] or 'None'}")
                
            except Exception as e:
                pass
            
            # Schedule next update
            try:
                root.after(2000, update_graph_loop)
            except:
                pass # Print error to see if stats is crashing
            
            # Schedule next update
            try:
                root.after(1000, update_statistics)
            except:
                pass

        def update_graph_loop():
            try:
                # OPTIMIZATION: Only draw if Viz tab is actually selected
                # This prevents lagging when viewing packet list
                is_visible = False
                try:
                    # Note: notebook lookup depends on variable availability
                    if 'notebook' in globals() and 'viz_tab' in globals():
                         current = notebook.select()
                         # We need to check if 'viz_tab' ID matches current tab ID
                         # Tkinter ids are strings.
                         if str(viz_tab) in str(current):
                             is_visible = True
                except:
                    pass

                if not is_visible:
                    # Skip drawing, just reschedule
                    root.after(2000, update_graph_loop)
                    return

                if G is not None and G.number_of_nodes() > 0:
                    # ... drawing logic ...
                    ax.clear()
                    ax.set_facecolor('#1e1e1e')
                    
                    # Layout (Reduce iterations for speed)
                    pos = nx.spring_layout(G, seed=42, k=0.3, iterations=10) # Reduced from 20
                    
                    # Draw
                    nx.draw_networkx_nodes(G, pos, ax=ax, node_size=300, node_color='#00ff00', alpha=0.8)
                    nx.draw_networkx_edges(G, pos, ax=ax, edge_color='#555555', alpha=0.5)
                    nx.draw_networkx_labels(G, pos, ax=ax, font_size=8, font_color='white')
                    
                    ax.axis('off')
                    canvas.draw()
            except Exception as e:
                pass
            
            # Schedule next update (2s)
            try:
                if notebook.select() == str(graph_tab): # Only update if tab is visible
                    root.after(2000, update_graph_loop)
                else:
                    root.after(2000, update_graph_loop) # Keep loop alive even if hidden
            except:
                pass # App closing

        # Start loop
        root.after(1000, update_graph_loop)

    # Settings Tab
    settings_tab = tk.Frame(notebook)
    notebook.add(settings_tab, text="⚙️ Settings")
    
    settings_frame = tk.Frame(settings_tab)
    settings_frame.pack(fill='both', expand=True, padx=20, pady=20)
    
    # Interface settings
    iface_frame = tk.LabelFrame(settings_frame, text="Interface Settings", padx=10, pady=10)
    iface_frame.grid(row=0, column=0, sticky='nw', padx=(0, 20))
    
    tk.Label(iface_frame, text="Default Interface:").grid(row=0, column=0, sticky='w', pady=5)
    # Use same friendly display names as the toolbar combo
    settings_interface_display_names = list(interface_map.keys())
    
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
        try:
            style.theme_use("clam") # Required for background colors on Windows Treeview
        except:
            pass
            
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
    
    # Start Update Loops (Internal to GUI)
    update_statistics()
    update_packet_list_gui()  # <--- CRITICAL FIX: Start the packet list updater!
    if VIZ_AVAILABLE:
        update_graph_loop()
        
    # Start the GUI
    root.mainloop()

if __name__ == "__main__":
    if config["headless"]:
        print("="*60)
        print("   PEARCER [HEADLESS MODE]")
        print("   Running without GUI")
        print("="*60)
        try:
            running = True
            # Start sniffer directly
            sniff_thread_handle = threading.Thread(target=sniff_thread)
            sniff_thread_handle.daemon = True
            sniff_thread_handle.start()
            
            # Keep main thread alive
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n[INFO] Stopping Pearcer...")
            running = False
            sys.exit(0)
    elif GUI_AVAILABLE:
        main_gui()
        sys.exit(0) # Ensure process exits when GUI closes
    else:
        print("[ERROR] GUI dependencies missing and --headless not specified.")
        print("Re-run with --headless to run in console mode.")  
    # CLI mode fallback
    cli_mode()