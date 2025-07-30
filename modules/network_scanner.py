#!/usr/bin/env python3
"""
Network scanner module for port scanning and service detection.
"""

import logging
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse
import requests
import subprocess
import platform

logger = logging.getLogger("vanguard.network_scanner")

class NetworkScanner:
    """Advanced network scanner for service discovery and enumeration."""
    
    def __init__(self, timeout=3, max_workers=50, rate_limit=10):
        """
        Initialize the network scanner.
        
        Args:
            timeout: Socket timeout in seconds
            max_workers: Maximum concurrent threads
            rate_limit: Requests per second limit
        """
        self.timeout = timeout
        self.max_workers = max_workers
        self.rate_limit = rate_limit
        self.last_request_time = 0
        self.lock = threading.Lock()
        
        # Common ports for scanning
        self.common_ports = [
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 993, 995,
            1723, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200, 27017
        ]
        
        # Service signatures
        self.service_signatures = {
            21: "FTP",
            22: "SSH", 
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            110: "POP3",
            135: "RPC",
            139: "NetBIOS",
            143: "IMAP",
            443: "HTTPS",
            993: "IMAPS",
            995: "POP3S",
            1433: "MSSQL",
            1723: "PPTP",
            3306: "MySQL",
            3389: "RDP",
            5432: "PostgreSQL",
            5900: "VNC",
            6379: "Redis",
            8080: "HTTP-Alt",
            8443: "HTTPS-Alt",
            9200: "Elasticsearch",
            27017: "MongoDB"
        }

    def scan_target(self, target, ports=None):
        """
        Comprehensive scan of a target.
        
        Args:
            target: Target hostname/IP or URL
            ports: List of ports to scan (default: common ports)
            
        Returns:
            Dictionary containing scan results
        """
        logger.info(f"Starting comprehensive scan of {target}")
        
        # Parse target
        if target.startswith(('http://', 'https://')):
            parsed = urlparse(target)
            hostname = parsed.hostname
            default_port = 443 if parsed.scheme == 'https' else 80
        else:
            hostname = target
            default_port = None
            
        # Resolve hostname
        try:
            ip_address = socket.gethostbyname(hostname)
        except socket.gaierror:
            logger.error(f"Could not resolve hostname: {hostname}")
            return None
            
        scan_results = {
            'target': target,
            'hostname': hostname,
            'ip_address': ip_address,
            'timestamp': time.time(),
            'open_ports': [],
            'services': {},
            'web_servers': [],
            'vulnerabilities': []
        }
        
        # Port scan
        ports_to_scan = ports or self.common_ports
        if default_port and default_port not in ports_to_scan:
            ports_to_scan.append(default_port)
            
        open_ports = self._port_scan(ip_address, ports_to_scan)
        scan_results['open_ports'] = open_ports
        
        # Service detection
        for port in open_ports:
            service_info = self._detect_service(ip_address, port)
            if service_info:
                scan_results['services'][port] = service_info
                
        # Web server detection
        web_ports = [p for p in open_ports if p in [80, 443, 8080, 8443]]
        for port in web_ports:
            web_info = self._detect_web_server(hostname, port)
            if web_info:
                scan_results['web_servers'].append(web_info)
                
        logger.info(f"Scan completed for {target}: {len(open_ports)} open ports found")
        return scan_results

    def _rate_limit_wait(self):
        """Implement rate limiting."""
        with self.lock:
            current_time = time.time()
            time_since_last = current_time - self.last_request_time
            min_interval = 1.0 / self.rate_limit
            
            if time_since_last < min_interval:
                sleep_time = min_interval - time_since_last
                time.sleep(sleep_time)
                
            self.last_request_time = time.time()

    def _port_scan(self, ip_address, ports):
        """
        Perform multi-threaded port scan.
        
        Args:
            ip_address: Target IP address
            ports: List of ports to scan
            
        Returns:
            List of open ports
        """
        open_ports = []
        
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Submit port scan tasks
            future_to_port = {
                executor.submit(self._scan_port, ip_address, port): port 
                for port in ports
            }
            
            # Collect results
            for future in as_completed(future_to_port):
                port = future_to_port[future]
                try:
                    if future.result():
                        open_ports.append(port)
                except Exception as e:
                    logger.debug(f"Error scanning port {port}: {str(e)}")
                    
        return sorted(open_ports)

    def _scan_port(self, ip_address, port):
        """
        Scan a single port.
        
        Args:
            ip_address: Target IP address
            port: Port number to scan
            
        Returns:
            Boolean indicating if port is open
        """
        self._rate_limit_wait()
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((ip_address, port))
            sock.close()
            return result == 0
        except Exception:
            return False

    def _detect_service(self, ip_address, port):
        """
        Detect service running on a port.
        
        Args:
            ip_address: Target IP address
            port: Port number
            
        Returns:
            Dictionary with service information
        """
        service_info = {
            'port': port,
            'service': self.service_signatures.get(port, 'Unknown'),
            'banner': None,
            'version': None
        }
        
        # Try to grab banner
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((ip_address, port))
            
            # Send appropriate probe
            if port == 80:
                sock.send(b"GET / HTTP/1.1\r\nHost: " + ip_address.encode() + b"\r\n\r\n")
            elif port == 21:
                pass  # FTP sends banner automatically
            elif port == 22:
                pass  # SSH sends banner automatically
            elif port == 25:
                sock.send(b"EHLO test\r\n")
            
            # Receive banner
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            if banner:
                service_info['banner'] = banner
                service_info['version'] = self._extract_version(banner)
                
            sock.close()
            
        except Exception as e:
            logger.debug(f"Banner grab failed for {ip_address}:{port}: {str(e)}")
            
        return service_info

    def _detect_web_server(self, hostname, port):
        """
        Detect web server details.
        
        Args:
            hostname: Target hostname
            port: Port number
            
        Returns:
            Dictionary with web server information
        """
        protocol = 'https' if port in [443, 8443] else 'http'
        url = f"{protocol}://{hostname}:{port}"
        
        try:
            response = requests.get(url, timeout=self.timeout, verify=False,
                                  allow_redirects=False)
            
            web_info = {
                'url': url,
                'status_code': response.status_code,
                'server': response.headers.get('Server', 'Unknown'),
                'powered_by': response.headers.get('X-Powered-By', ''),
                'technologies': self._detect_technologies(response),
                'security_headers': self._check_security_headers(response.headers)
            }
            
            return web_info
            
        except Exception as e:
            logger.debug(f"Web server detection failed for {url}: {str(e)}")
            return None

    def _extract_version(self, banner):
        """Extract version information from service banner."""
        import re
        
        # Common version patterns
        patterns = [
            r'(\d+\.\d+\.\d+)',
            r'(\d+\.\d+)',
            r'version\s+(\d+\.\d+\.\d+)',
            r'v(\d+\.\d+)'
        ]
        
        for pattern in patterns:
            match = re.search(pattern, banner, re.IGNORECASE)
            if match:
                return match.group(1)
                
        return None

    def _detect_technologies(self, response):
        """Detect web technologies from response."""
        technologies = []
        
        # Check headers
        server = response.headers.get('Server', '').lower()
        powered_by = response.headers.get('X-Powered-By', '').lower()
        
        # Common technology indicators
        tech_indicators = {
            'apache': 'Apache',
            'nginx': 'Nginx',
            'iis': 'IIS',
            'php': 'PHP',
            'asp.net': 'ASP.NET',
            'python': 'Python',
            'node.js': 'Node.js',
            'express': 'Express.js'
        }
        
        content = response.text.lower()
        
        for indicator, tech in tech_indicators.items():
            if indicator in server or indicator in powered_by or indicator in content:
                if tech not in technologies:
                    technologies.append(tech)
                    
        return technologies

    def _check_security_headers(self, headers):
        """Check for security headers."""
        security_headers = {
            'X-Frame-Options': headers.get('X-Frame-Options'),
            'X-Content-Type-Options': headers.get('X-Content-Type-Options'),
            'X-XSS-Protection': headers.get('X-XSS-Protection'),
            'Strict-Transport-Security': headers.get('Strict-Transport-Security'),
            'Content-Security-Policy': headers.get('Content-Security-Policy')
        }
        
        return {k: v for k, v in security_headers.items() if v is not None}

    def discover_subdomains(self, domain, wordlist=None):
        """
        Discover subdomains using DNS enumeration.
        
        Args:
            domain: Target domain
            wordlist: List of subdomain names to try
            
        Returns:
            List of discovered subdomains
        """
        if not wordlist:
            wordlist = [
                'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk',
                'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'whcms', 'owa',
                'crm', 'cms', 'wiki', 'blog', 'dev', 'test', 'staging', 'admin', 'api'
            ]
            
        discovered = []
        
        with ThreadPoolExecutor(max_workers=20) as executor:
            future_to_subdomain = {
                executor.submit(self._check_subdomain, subdomain, domain): subdomain
                for subdomain in wordlist
            }
            
            for future in as_completed(future_to_subdomain):
                subdomain = future_to_subdomain[future]
                try:
                    if future.result():
                        full_domain = f"{subdomain}.{domain}"
                        discovered.append(full_domain)
                        logger.info(f"Discovered subdomain: {full_domain}")
                except Exception as e:
                    logger.debug(f"Error checking subdomain {subdomain}: {str(e)}")
                    
        return discovered

    def _check_subdomain(self, subdomain, domain):
        """Check if a subdomain exists."""
        full_domain = f"{subdomain}.{domain}"
        try:
            socket.gethostbyname(full_domain)
            return True
        except socket.gaierror:
            return False

    def ping_sweep(self, network):
        """
        Perform ping sweep on a network range.
        
        Args:
            network: Network range (e.g., "192.168.1.0/24")
            
        Returns:
            List of active hosts
        """
        try:
            import ipaddress
        except ImportError:
            logger.error("ipaddress module required for ping sweep")
            return []
            
        active_hosts = []
        
        try:
            net = ipaddress.IPv4Network(network, strict=False)
            hosts = list(net.hosts())
            
            with ThreadPoolExecutor(max_workers=50) as executor:
                future_to_host = {
                    executor.submit(self._ping_host, str(host)): host
                    for host in hosts
                }
                
                for future in as_completed(future_to_host):
                    host = future_to_host[future]
                    try:
                        if future.result():
                            active_hosts.append(str(host))
                    except Exception as e:
                        logger.debug(f"Error pinging {host}: {str(e)}")
                        
        except Exception as e:
            logger.error(f"Error in ping sweep: {str(e)}")
            
        return active_hosts

    def _ping_host(self, host):
        """Ping a single host."""
        try:
            # Use system ping command
            if platform.system().lower() == "windows":
                cmd = ["ping", "-n", "1", "-w", "1000", host]
            else:
                cmd = ["ping", "-c", "1", "-W", "1", host]
                
            result = subprocess.run(cmd, capture_output=True, timeout=3)
            return result.returncode == 0
            
        except Exception:
            return False
