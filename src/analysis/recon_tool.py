"""Reconnaissance tool module for pearcer.

This module provides comprehensive reconnaissance capabilities including
subdomain enumeration, port scanning, service detection, and more.
"""

import threading
import time
import socket
import subprocess
import re
from typing import Dict, List, Optional, Set
from collections import defaultdict
from datetime import datetime

# Try to import nmap
NMAP_AVAILABLE = False
try:
    import nmap
    NMAP_AVAILABLE = True
except ImportError:
    pass

# Try to import requests for web requests
REQUESTS_AVAILABLE = False
try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    pass

# Try to import dns for DNS enumeration
DNS_AVAILABLE = False
try:
    import dns.resolver
    import dns.reversename
    DNS_AVAILABLE = True
except ImportError:
    pass


class ReconResult:
    """Represents a reconnaissance result."""
    
    def __init__(self, target: str, result_type: str, data: Dict, timestamp: Optional[str] = None):
        self.target = target
        self.result_type = result_type  # 'subdomain', 'port', 'service', 'dns', etc.
        self.data = data
        self.timestamp = timestamp or datetime.now().isoformat()
    
    def to_dict(self) -> Dict:
        """Convert result to dictionary."""
        return {
            'target': self.target,
            'type': self.result_type,
            'data': self.data,
            'timestamp': self.timestamp
        }


class ReconTool:
    """Main reconnaissance tool class."""
    
    def __init__(self):
        self.results: List[ReconResult] = []
        self.scanning = False
        self.scan_progress = 0.0
        self.scan_status = "Idle"
        self.lock = threading.Lock()
        
        # Common subdomain wordlist
        self.subdomain_wordlist = [
            'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk',
            'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'm', 'imap', 'test',
            'ns', 'www2', 'admin', 'forum', 'blog', 'dev', 'www1', 'ftp2', 'admin2',
            'mysql', 'mail2', 'ns3', 'web', 'server', 'dns', 'dns2', 'api', 'cdn',
            'static', 'media', 'images', 'img', 'js', 'css', 'assets', 'assets2',
            'assets3', 'assets4', 'assets5', 'staging', 'stage', 'test2', 'test3',
            'demo', 'm', 'mobile', 'wap', 'beta', 'alpha', 'dev2', 'dev3', 'secure',
            'vpn', 'ns4', 'mail3', 'sip', 'sip2', 'xmpp', 'chat', 'im', 'im2',
            'web2', 'www3', 'ns5', 'dns3', 'dns4', 'www4', 'secure2', 'secure3',
            'secure4', 'secure5', 'panel', 'cpanel2', 'whm2', 'webmin', 'webmin2',
            'control', 'control2', 'my', 'cp', 'direct', 'direct2', 'direct3',
            'origin', 'origin2', 'edge', 'edge2', 'cache', 'cache2', 'cdn2',
            'cdn3', 'cdn4', 'cdn5', 'lb', 'lb2', 'load', 'load2', 'srv', 'srv2',
            'service', 'service2', 'svc', 'svc2', 'app', 'app2', 'apps', 'apps2',
            'application', 'application2', 'gateway', 'gateway2', 'router', 'router2'
        ]
    
    def subdomain_enumeration(self, domain: str, use_wordlist: bool = True, 
                             use_crt: bool = True, use_dns: bool = True) -> List[str]:
        """Enumerate subdomains for a given domain.
        
        Args:
            domain: Target domain (e.g., 'example.com')
            use_wordlist: Use wordlist brute force
            use_crt: Use Certificate Transparency logs (crt.sh)
            use_dns: Use DNS enumeration
        
        Returns:
            List of discovered subdomains
        """
        self.scanning = True
        self.scan_status = f"Enumerating subdomains for {domain}..."
        discovered = set()
        
        try:
            # Method 1: Certificate Transparency logs
            if use_crt and REQUESTS_AVAILABLE:
                self.scan_status = f"Checking Certificate Transparency logs for {domain}..."
                try:
                    url = f"https://crt.sh/?q=%.{domain}&output=json"
                    response = requests.get(url, timeout=10)
                    if response.status_code == 200:
                        data = response.json()
                        for entry in data:
                            name = entry.get('name_value', '')
                            if domain in name:
                                # Extract subdomain
                                subdomain = name.split('.')[0] if '.' in name else name
                                if subdomain and subdomain != domain:
                                    discovered.add(name.strip())
                except Exception as e:
                    print(f"[CRT ERROR] {e}")
            
            # Method 2: DNS enumeration with wordlist
            if use_wordlist and DNS_AVAILABLE:
                self.scan_status = f"Brute forcing subdomains for {domain}..."
                total = len(self.subdomain_wordlist)
                for i, sub in enumerate(self.subdomain_wordlist):
                    self.scan_progress = (i / total) * 0.5 + 0.5
                    try:
                        full_domain = f"{sub}.{domain}"
                        answers = dns.resolver.resolve(full_domain, 'A')
                        if answers:
                            discovered.add(full_domain)
                            self.scan_status = f"Found: {full_domain}"
                    except:
                        pass
            
            # Method 3: DNS zone transfer attempt
            if use_dns and DNS_AVAILABLE:
                self.scan_status = f"Attempting DNS zone transfer for {domain}..."
                try:
                    # Get nameservers
                    ns_answers = dns.resolver.resolve(domain, 'NS')
                    for ns in ns_answers:
                        ns_str = str(ns.target).rstrip('.')
                        try:
                            # Try zone transfer (requires AXFR permission, usually fails)
                            import dns.query
                            import dns.zone
                            zone = dns.zone.from_xfr(dns.query.xfr(ns_str, domain))
                            for name, node in zone.nodes.items():
                                if name != '@':
                                    discovered.add(f"{name}.{domain}")
                        except:
                            pass
                except:
                    pass
            
            # Method 4: Common DNS records
            if DNS_AVAILABLE:
                common_records = ['A', 'AAAA', 'MX', 'TXT', 'CNAME', 'NS']
                for record_type in common_records:
                    try:
                        answers = dns.resolver.resolve(domain, record_type)
                        for answer in answers:
                            if hasattr(answer, 'target'):
                                target = str(answer.target).rstrip('.')
                                if domain in target and target != domain:
                                    discovered.add(target)
                    except:
                        pass
        
        except Exception as e:
            self.scan_status = f"Subdomain enumeration error: {str(e)}"
            print(f"[RECON ERROR] {e}")
        finally:
            self.scanning = False
            self.scan_progress = 1.0
        
        discovered_list = sorted(list(discovered))
        
        with self.lock:
            for subdomain in discovered_list:
                self.results.append(ReconResult(
                    target=domain,
                    result_type='subdomain',
                    data={'subdomain': subdomain}
                ))
        
        return discovered_list
    
    def port_scan(self, target: str, ports: str = "1-1000", 
                  scan_type: str = "syn") -> Dict[int, Dict]:
        """Perform port scan on target.
        
        Args:
            target: IP address or hostname
            ports: Port range (e.g., "1-1000" or "80,443,22")
            scan_type: Scan type ("syn", "connect", "udp")
        
        Returns:
            Dictionary mapping port numbers to port information
        """
        self.scanning = True
        self.scan_status = f"Scanning ports on {target}..."
        open_ports = {}
        
        if not NMAP_AVAILABLE:
            # Fallback to basic socket scanning
            port_list = self._parse_ports(ports)
            total = len(port_list)
            for i, port in enumerate(port_list):
                self.scan_progress = i / total
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(0.5)
                    result = sock.connect_ex((target, port))
                    if result == 0:
                        open_ports[port] = {'state': 'open', 'service': 'unknown'}
                    sock.close()
                except:
                    pass
        else:
            try:
                nm = nmap.PortScanner()
                scan_args = f"-s{scan_type[0].upper()}"
                if scan_type == "syn":
                    scan_args += " -sV"  # Version detection
                
                nm.scan(target, ports, arguments=scan_args)
                
                if target in nm.all_hosts():
                    host_info = nm[target]
                    for proto in host_info.all_protocols():
                        ports_info = host_info[proto]
                        for port, port_info in ports_info.items():
                            if port_info['state'] == 'open':
                                open_ports[port] = {
                                    'state': 'open',
                                    'service': port_info.get('name', 'unknown'),
                                    'product': port_info.get('product', ''),
                                    'version': port_info.get('version', ''),
                                    'extrainfo': port_info.get('extrainfo', '')
                                }
                
                with self.lock:
                    for port, info in open_ports.items():
                        self.results.append(ReconResult(
                            target=target,
                            result_type='port',
                            data={'port': port, **info}
                        ))
            
            except Exception as e:
                self.scan_status = f"Port scan error: {str(e)}"
                print(f"[RECON ERROR] {e}")
        
        self.scanning = False
        self.scan_progress = 1.0
        return open_ports
    
    def _parse_ports(self, ports: str) -> List[int]:
        """Parse port string into list of port numbers."""
        port_list = []
        for part in ports.split(','):
            part = part.strip()
            if '-' in part:
                start, end = part.split('-')
                port_list.extend(range(int(start), int(end) + 1))
            else:
                port_list.append(int(part))
        return sorted(set(port_list))
    
    def reverse_dns_lookup(self, ip: str) -> Optional[str]:
        """Perform reverse DNS lookup."""
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return hostname
        except:
            return None
    
    def dns_lookup(self, hostname: str, record_type: str = 'A') -> List[str]:
        """Perform DNS lookup."""
        results = []
        try:
            if DNS_AVAILABLE:
                answers = dns.resolver.resolve(hostname, record_type)
                for answer in answers:
                    if record_type == 'A' or record_type == 'AAAA':
                        results.append(str(answer))
                    else:
                        results.append(str(answer.target).rstrip('.'))
            else:
                # Fallback to socket
                if record_type == 'A':
                    ip = socket.gethostbyname(hostname)
                    results.append(ip)
        except:
            pass
        return results
    
    def service_scan(self, target: str, port: int) -> Dict:
        """Scan service on specific port."""
        service_info = {
            'port': port,
            'service': 'unknown',
            'banner': '',
            'version': ''
        }
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            sock.connect((target, port))
            
            # Try to grab banner
            try:
                banner = sock.recv(1024).decode('utf-8', errors='ignore')
                service_info['banner'] = banner[:200]  # Limit banner length
            except:
                pass
            
            sock.close()
        except:
            pass
        
        return service_info
    
    def full_recon(self, target: str, ports: str = "1-1000") -> Dict:
        """Perform full reconnaissance on target.
        
        Args:
            target: Domain or IP address
            ports: Port range to scan
        
        Returns:
            Dictionary with all reconnaissance results
        """
        self.scanning = True
        self.scan_status = f"Starting full reconnaissance on {target}..."
        results = {
            'target': target,
            'subdomains': [],
            'ports': {},
            'services': {},
            'dns': {},
            'timestamp': datetime.now().isoformat()
        }
        
        try:
            # Determine if target is IP or domain
            is_ip = self._is_ip(target)
            
            if is_ip:
                # IP target - reverse DNS and port scan
                self.scan_status = f"Performing reverse DNS lookup for {target}..."
                hostname = self.reverse_dns_lookup(target)
                if hostname:
                    results['dns']['reverse'] = hostname
                
                self.scan_status = f"Scanning ports on {target}..."
                results['ports'] = self.port_scan(target, ports)
            else:
                # Domain target - subdomain enumeration and port scan
                self.scan_status = f"Enumerating subdomains for {target}..."
                results['subdomains'] = self.subdomain_enumeration(target)
                
                # Get main domain IP
                self.scan_status = f"Resolving {target}..."
                ips = self.dns_lookup(target)
                if ips:
                    results['dns']['A'] = ips
                    main_ip = ips[0]
                    
                    # Port scan main IP
                    self.scan_status = f"Scanning ports on {main_ip}..."
                    results['ports'] = self.port_scan(main_ip, ports)
                    
                    # Scan discovered subdomains
                    for subdomain in results['subdomains'][:10]:  # Limit to first 10
                        try:
                            sub_ips = self.dns_lookup(subdomain)
                            if sub_ips:
                                sub_ports = self.port_scan(sub_ips[0], "80,443,22,21,25")
                                if sub_ports:
                                    results['ports'][f"{subdomain}"] = sub_ports
                        except:
                            pass
            
            self.scan_status = "Reconnaissance complete"
        
        except Exception as e:
            self.scan_status = f"Reconnaissance error: {str(e)}"
            print(f"[RECON ERROR] {e}")
        finally:
            self.scanning = False
            self.scan_progress = 1.0
        
        return results
    
    def _is_ip(self, target: str) -> bool:
        """Check if target is an IP address."""
        try:
            socket.inet_aton(target)
            return True
        except:
            return False
    
    def get_results(self) -> List[ReconResult]:
        """Get all reconnaissance results."""
        with self.lock:
            return self.results.copy()
    
    def clear_results(self):
        """Clear all results."""
        with self.lock:
            self.results.clear()
    
    def export_results(self, filename: str):
        """Export results to JSON file."""
        import json
        with self.lock:
            results = [r.to_dict() for r in self.results]
        
        with open(filename, 'w') as f:
            json.dump(results, f, indent=2)

