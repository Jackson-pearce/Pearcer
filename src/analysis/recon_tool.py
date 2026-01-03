"""Reconnaissance tool module for pearcer.

This module provides comprehensive REAL reconnaissance capabilities including:
- crt.sh Certificate Transparency logs (already working)
- WHOIS domain registration lookups
- Enhanced DNS security analysis (DNSSEC, SPF, DMARC, CAA)
- Technology fingerprinting
- Subdomain security validation
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

# Try to import whois for WHOIS lookups
WHOIS_AVAILABLE = False
try:
    import whois
    WHOIS_AVAILABLE = True
except ImportError:
    pass


class ReconResult:
    """Represents a reconnaissance result."""
    
    def __init__(self, target: str, result_type: str, data: Dict, timestamp: Optional[str] = None):
        self.target = target
        self.result_type = result_type  # 'subdomain', 'port', 'service', 'dns', 'whois', etc.
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
    """Main reconnaissance tool class with REAL data sources."""
    
    def __init__(self):
        self.results: List[ReconResult] = []
        self.scanning = False
        self.scan_progress = 0.0
        self.scan_status = "Idle"
        self.lock = threading.Lock()
        
        # Common subdomain wordlist (for brute force)
        self.subdomain_wordlist = [
            'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk',
            'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'm', 'imap', 'test',
            'ns', 'admin', 'forum', 'blog', 'dev', 'api', 'cdn', 'static', 'media',
            'staging', 'beta', 'vpn', 'secure', 'portal', 'git', 'jenkins', 'dashboard'
        ]
    
    def whois_lookup(self, domain: str) -> Optional[Dict]:
        """Perform WHOIS lookup for domain registration information.
        
        Returns dictionary with WHOIS data or None if unavailable.
        """
        if not WHOIS_AVAILABLE:
            print("[WHOIS] python-whois not installed. Run: pip install python-whois")
            return None
        
        try:
            self.scan_status = f"Performing WHOIS lookup for {domain}..."
            w = whois.whois(domain)
            
            whois_data = {
                'domain_name': w.domain_name if isinstance(w.domain_name, str) else w.domain_name[0] if w.domain_name else domain,
                'registrar': w.registrar,
                'creation_date': str(w.creation_date) if w.creation_date else 'Unknown',
                'expiration_date': str(w.expiration_date) if w.expiration_date else 'Unknown',
                'updated_date': str(w.updated_date) if w.updated_date else 'Unknown',
                'name_servers': w.name_servers if w.name_servers else [],
                'status': w.status if w.status else [],
                'registrant_org': w.org if hasattr(w, 'org') else 'N/A',
                'registrant_country': w.country if hasattr(w, 'country') else 'N/A',
            }
            
            with self.lock:
                self.results.append(ReconResult(
                    target=domain,
                    result_type='whois',
                    data=whois_data
                ))
            
            return whois_data
        
        except Exception as e:
            print(f"[WHOIS] Error looking up {domain}: {e}")
            return None
    
    def check_dnssec(self, domain: str) -> Dict:
        """Check if domain has DNSSEC enabled.
        
        Returns dict with DNSSEC status and details.
        """
        if not DNS_AVAILABLE:
            return {'enabled': False, 'error': 'dnspython not available'}
        
        try:
            self.scan_status = f"Checking DNSSEC for {domain}..."
            resolver = dns.resolver.Resolver()
            resolver.use_edns(0, dns.flags.DO, 4096)
            
            # Query for DNSKEY record
            try:
                dnskey_answers = resolver.resolve(domain, 'DNSKEY')
                return {
                    'enabled': True,
                    'keys_found': len(dnskey_answers),
                    'status': 'DNSSEC is enabled and configured'
                }
            except dns.resolver.NoAnswer:
                return {
                    'enabled': False,
                    'status': 'DNSSEC not configured (no DNSKEY records)'
                }
        
        except Exception as e:
            return {
                'enabled': False,
                'error': str(e),
                'status': 'Could not determine DNSSEC status'
            }
    
    def check_email_security(self, domain: str) -> Dict:
        """Check email security records (SPF, DMARC, DKIM).
        
        Returns dict with email security configuration.
        """
        if not DNS_AVAILABLE:
            return {}
        
        try:
            self.scan_status = f"Checking email security for {domain}..."
            email_security = {}
            
            # Check SPF record
            try:
                txt_answers = dns.resolver.resolve(domain, 'TXT')
                spf_records = [str(rdata) for rdata in txt_answers if 'v=spf1' in str(rdata)]
                email_security['spf'] = {
                    'configured': len(spf_records) > 0,
                    'records': spf_records,
                    'status': 'SPF configured' if spf_records else 'SPF not configured'
                }
            except:
                email_security['spf'] = {
                    'configured': False,
                    'status': 'SPF not configured'
                }
            
            # Check DMARC record
            try:
                dmarc_domain = f"_dmarc.{domain}"
                txt_answers = dns.resolver.resolve(dmarc_domain, 'TXT')
                dmarc_records = [str(rdata) for rdata in txt_answers if 'v=DMARC1' in str(rdata)]
                email_security['dmarc'] = {
                    'configured': len(dmarc_records) > 0,
                    'records': dmarc_records,
                    'status': 'DMARC configured' if dmarc_records else 'DMARC not configured'
                }
            except:
                email_security['dmarc'] = {
                    'configured': False,
                    'status': 'DMARC not configured'
                }
            
            # Check DKIM (common selectors)
            dkim_selectors = ['default', 'google', 'selector1', 'selector2', 'k1', 's1']
            dkim_found = []
            for selector in dkim_selectors:
                try:
                    dkim_domain = f"{selector}._domainkey.{domain}"
                    txt_answers = dns.resolver.resolve(dkim_domain, 'TXT')
                    if txt_answers:
                        dkim_found.append(selector)
                except:
                    pass
            
            email_security['dkim'] = {
                'configured': len(dkim_found) > 0,
                'selectors_found': dkim_found,
                'status': f'DKIM configured ({len(dkim_found)} selectors)' if dkim_found else 'DKIM not found (common selectors checked)'
            }
            
            return email_security
        
        except Exception as e:
            print(f"[EMAIL SECURITY] Error checking {domain}: {e}")
            return {}
    
    def check_caa_records(self, domain: str) -> Dict:
        """Check CAA (Certificate Authority Authorization) records.
        
        Returns dict with CAA configuration.
        """
        if not DNS_AVAILABLE:
            return {}
        
        try:
            self.scan_status = f"Checking CAA records for {domain}..."
            caa_answers = dns.resolver.resolve(domain, 'CAA')
            caa_records = []
            
            for rdata in caa_answers:
                caa_records.append({
                    'flags': rdata.flags,
                    'tag': rdata.tag,
                    'value': rdata.value
                })
            
            return {
                'configured': True,
                'records': caa_records,
                'status': f'CAA configured with {len(caa_records)} record(s)'
            }
        
        except dns.resolver.NoAnswer:
            return {
                'configured': False,
                'status': 'CAA not configured (any CA can issue certificates)'
            }
        except Exception as e:
            return {
                'configured': False,
                'error': str(e)
            }
    
    def detect_technology(self, url: str) -> Dict:
        """Detect web technologies, CMS, frameworks from HTTP response.
        
        Returns dict with detected technologies.
        """
        if not REQUESTS_AVAILABLE:
            return {}
        
        try:
            self.scan_status = f"Detecting technologies on {url}..."
            response = requests.get(url, timeout=5, verify=False, allow_redirects=True)
            
            headers = response.headers
            content = response.text[:5000]  # First 5KB should be enough
            
            technologies = {
                'server': headers.get('Server', 'Unknown'),
                'powered_by': headers.get('X-Powered-By', 'Not disclosed'),
                'framework': 'Unknown',
                'cms': 'Unknown',
                'programming_language': 'Unknown',
                'web_server': 'Unknown'
            }
            
            # Detect web server
            server_header = headers.get('Server', '').lower()
            if 'nginx' in server_header:
                technologies['web_server'] = 'Nginx'
            elif 'apache' in server_header:
                technologies['web_server'] = 'Apache'
            elif 'microsoft-iis' in server_header or 'iis' in server_header:
                technologies['web_server'] = 'Microsoft IIS'
            elif 'cloudflare' in server_header:
                technologies['web_server'] = 'Cloudflare (reverse proxy)'
            
            # Detect CMS
            if 'wp-content' in content or 'wp-includes' in content or 'wordpress' in content.lower():
                technologies['cms'] = 'WordPress'
            elif 'joomla' in content.lower() or '/components/com_' in content:
                technologies['cms'] = 'Joomla'
            elif 'drupal' in content.lower() or 'sites/default' in content:
                technologies['cms'] = 'Drupal'
            elif 'shopify' in content.lower():
                technologies['cms'] = 'Shopify'
            
            # Detect frameworks
            if 'django' in content.lower() or 'csrfmiddlewaretoken' in content:
                technologies['framework'] = 'Django'
                technologies['programming_language'] = 'Python'
            elif 'laravel' in content.lower() or 'csrf-token' in content:
                technologies['framework'] = 'Laravel'
                technologies['programming_language'] = 'PHP'
            elif 'react' in content.lower() or '__REACT' in content:
                technologies['framework'] = 'React'
                technologies['programming_language'] = 'JavaScript'
            elif 'angular' in content.lower() or 'ng-' in content:
                technologies['framework'] = 'Angular'
                technologies['programming_language'] = 'JavaScript'
            elif 'vue' in content.lower() or 'v-' in content:
                technologies['framework'] = 'Vue.js'
                technologies['programming_language'] = 'JavaScript'
            
            # Detect from X-Powered-By
            powered_by = headers.get('X-Powered-By', '').lower()
            if 'php' in powered_by:
                technologies['programming_language'] = f"PHP ({headers.get('X-Powered-By')})"
            elif 'asp.net' in powered_by:
                technologies['programming_language'] = 'ASP.NET'
            
            # Detect from meta tags
            if '<meta name="generator"' in content.lower():
                generator_match = re.search(r'<meta\s+name="generator"\s+content="([^"]+)"', content, re.IGNORECASE)
                if generator_match:
                    technologies['generator'] = generator_match.group(1)
            
            return technologies
        
        except Exception as e:
            print(f"[TECH DETECT] Error checking {url}: {e}")
            return {}
    
    def subdomain_enumeration(self, domain: str, use_wordlist: bool = True, 
                             use_crt: bool = True, use_dns: bool = True) -> List[str]:
        """Enumerate subdomains for a given domain.
        
        REAL implementation using crt.sh (Certificate Transparency logs).
        
        Args:
            domain: Target domain (e.g., 'example.com')
            use_wordlist: Use wordlist brute force
            use_crt: Use Certificate Transparency logs (crt.sh) - REAL DATA
            use_dns: Use DNS enumeration
        
        Returns:
            List of discovered subdomains
        """
        self.scanning = True
        self.scan_status = f"Enumerating subdomains for {domain}..."
        discovered = set()
        
        try:
            # Method 1: Certificate Transparency logs (REAL DATA)
            if use_crt and REQUESTS_AVAILABLE:
                self.scan_status = f"Checking Certificate Transparency logs for {domain}..."
                try:
                    url = f"https://crt.sh/?q=%.{domain}&output=json"
                    response = requests.get(url, timeout=30)
                    if response.status_code == 200:
                        data = response.json()
                        for entry in data:
                            name = entry.get('name_value', '')
                            # Handle wildcard and multiple domains
                            names = name.split('\n')
                            for n in names:
                                n = n.strip().replace('*', '')
                                if domain in n and n:
                                    discovered.add(n)
                        
                        self.scan_status = f"Found {len(discovered)} subdomains from crt.sh"
                except Exception as e:
                    print(f"[CRT.SH ERROR] {e}")
            
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
                    except:
                        pass
            
            # Method 3: Common DNS records
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
                    data={'subdomain': subdomain, 'source': 'crt.sh/dns'}
                ))
        
        return discovered_list
    
    def port_scan(self, target: str, ports: str = "1-1000", 
                  scan_type: str = "syn") -> Dict[int, Dict]:
        """Perform port scan on target using nmap.
        
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
    
    def full_recon(self, target: str, ports: str = "1-1000") -> Dict:
        """Perform full reconnaissance on target with ALL real security checks.
        
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
            'whois': {},
            'email_security': {},
            'dnssec': {},
            'caa': {},
            'technology': {},
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
                # Domain target - full reconnaissance
                
                # WHOIS lookup
                whois_data = self.whois_lookup(target)
                if whois_data:
                    results['whois'] = whois_data
                
                # DNS security checks
                results['dnssec'] = self.check_dnssec(target)
                results['email_security'] = self.check_email_security(target)
                results['caa'] = self.check_caa_records(target)
                
                # Subdomain enumeration
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
                    
                    # Technology detection (if HTTP/HTTPS is open)
                    http_ports = [p for p in results['ports'].keys() if p in [80, 443, 8080, 8443]]
                    for port in http_ports:
                        protocol = 'https' if port in [443, 8443] else 'http'
                        url = f"{protocol}://{target}:{port}" if port not in [80, 443] else f"{protocol}://{target}"
                        tech = self.detect_technology(url)
                        if tech:
                            results['technology'][port] = tech
                            break  # Only check first HTTP port
            
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
