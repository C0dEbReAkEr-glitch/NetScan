#!/usr/bin/env python3
"""
NetScan v0.2
Enhanced Network Scanner with Threat Detection, OS Fingerprinting and Service Version Detection
This script provides comprehensive network scanning capabilities including:
- Network auto-detection and host discovery
- OS detection and fingerprinting
- Port scanning with service and version identification
- Extended port range scanning
- Vulnerability assessment
- Behavior-based threat detection
- Formatted output reporting
"""

import socket
import ipaddress
import argparse
import concurrent.futures
import subprocess
import json
import os
import time
import logging
import re
import platform
from datetime import datetime
import pandas as pd
import numpy as np
from scapy.all import ARP, Ether, srp, ICMP, IP, TCP, sr1
import warnings

warnings.filterwarnings('ignore')

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('network.log')
    ]
)
logger = logging.getLogger(__name__)

# Cool ASCII banner
def display_banner():
    banner = r"""
    ███╗   ██╗███████╗████████╗███████╗ ██████╗ █████╗ ███╗   ██╗
    ████╗  ██║██╔════╝╚══██╔══╝██╔════╝██╔════╝██╔══██╗████╗  ██║
    ██╔██╗ ██║█████╗     ██║   ███████╗██║     ███████║██╔██╗ ██║
    ██║╚██╗██║██╔══╝     ██║   ╚════██║██║     ██╔══██║██║╚██╗██║
    ██║ ╚████║███████╗   ██║   ███████║╚██████╗██║  ██║██║ ╚████║
    ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
    
    ⚡ NetScan v0.2 ⚡ | Network Scanner with Threat Detection
    
    [*] Discover hosts      [*] Detect OS      [*] Scan ports      
    [*] Identify versions   [*] Detect vulnerabilities
    [*] Analyze behavior    [*] Multiple output formats
    """
    print(banner)
    print("=" * 80)

class NetworkScanner:
    """Main network scanner class combining all scanning functionality"""
    
    def __init__(self, target=None, ports=None, timeout=1, threads=100, output_format='text'):
        self.target = target
        self.ports = ports or self._get_default_port_list()  # Enhanced to include more ports
        self.timeout = timeout
        self.threads = threads
        self.output_format = output_format
        self.results = []
        self.scan_start_time = None
        self.scan_end_time = None
        
        # Banner response database for service prediction
        self.service_signatures = {
            b'SSH': 'SSH',
            b'SSH-': 'SSH',
            b'OpenSSH': 'OpenSSH',
            b'HTTP': 'HTTP',
            b'SMTP': 'SMTP',
            b'FTP': 'FTP',
            b'IMAP': 'IMAP',
            b'POP3': 'POP3',
            b'MYSQL': 'MySQL',
            b'+OK': 'POP3',
            b'220': 'SMTP/FTP',
            b'230': 'FTP',
            b'HTTP/1.': 'HTTP',
            b'<html>': 'HTTP',
            b'<!DOCTYPE': 'HTTP',
            b'RFB': 'VNC',
            b'* OK': 'IMAP',
            b'220-': 'SMTP',
            b'Redis': 'Redis',
            b'MONGODB': 'MongoDB',
            b'5.5': 'MySQL',
            b'5.6': 'MySQL',
            b'5.7': 'MySQL',
            b'8.0': 'MySQL',
            b'Server: Apache': 'Apache',
            b'Server: nginx': 'Nginx',
            b'Server: Microsoft-IIS': 'IIS',
            b'HTTPS': 'HTTPS',
            b'SSL': 'SSL/TLS',
            b'SSH-2.0': 'SSH-2',
            b'SSH-1.99': 'SSH-2',
            b'SSH-1.5': 'SSH-1',
            b'220 ProFTPD': 'ProFTPD',
            b'220 Pure-FTPd': 'Pure-FTPd',
            b'220 FileZilla': 'FileZilla FTP',
            b'220 vsftpd': 'vsftpd',
            b'Telnet': 'Telnet'
        }
        
        # OS fingerprinting database
        self.os_signatures = {
            # TTL-based OS detection (simplified)
            64: 'Linux/Unix',
            128: 'Windows',
            254: 'Cisco/Network',
            255: 'Unix/BSD',
            
            # TCP window sizes (simplified)
            5840: 'Linux',
            8192: 'Windows',
            16384: 'BSD/macOS',
            65535: 'Windows 7/10',
            
            # Common port combinations
            'ports_22_80_443': 'Linux web server',
            'ports_135_139_445': 'Windows',
            'ports_22_25_53_80': 'Linux mail server',
            'ports_21_22_80_443': 'Web/FTP server',
        }
        
        # Common vulnerabilities database (expanded)
        self.vulnerability_db = {
            'SSH': {
                'default_ports': [22], 
                'weak_versions': ['1.0', '1.2', '1.3', '1.5', '2.0'],
                'version_vulns': {
                    'OpenSSH 4': 'Vulnerable to multiple CVEs including authentication bypass',
                    'OpenSSH 5': 'Multiple memory corruption vulnerabilities',
                    'OpenSSH 6.6': 'Potential information disclosure (CVE-2014-1692)',
                    'OpenSSH 7.2': 'Vulnerable to user enumeration (CVE-2016-6210)'
                }
            },
            'HTTP': {
                'default_ports': [80, 8080], 
                'weak_services': ['Apache/1.', 'Apache/2.0', 'Apache/2.2', 'IIS/5.0', 'IIS/6.0', 'IIS/7.0'],
                'version_vulns': {
                    'Apache/1': 'Multiple critical vulnerabilities, end-of-life',
                    'Apache/2.0': 'Multiple vulnerabilities, no longer supported',
                    'Apache/2.2': 'Multiple vulnerabilities including memory leaks',
                    'nginx/1.0': 'Multiple security issues, outdated',
                    'IIS/5.0': 'Multiple critical vulnerabilities, end-of-life',
                    'IIS/6.0': 'Multiple critical vulnerabilities including RCE',
                    'IIS/7.0': 'Multiple vulnerabilities including path traversal'
                }
            },
            'FTP': {
                'default_ports': [21], 
                'weak_auth': ['anonymous'],
                'version_vulns': {
                    'vsftpd 2.3.4': 'Backdoor vulnerability',
                    'ProFTPD 1.3.3': 'Multiple vulnerabilities including RCE',
                    'wu-ftpd 2': 'Multiple buffer overflows and RCE vulnerabilities',
                    'FileZilla Server 0': 'Multiple vulnerabilities, outdated'
                }
            },
            'Telnet': {
                'default_ports': [23], 
                'security': 'inherently_insecure',
                'version_vulns': {
                    'all': 'Transmits data in cleartext including credentials'
                }
            },
            'SMB': {
                'default_ports': [445], 
                'weak_versions': ['1.0', '2.0', '2.1'],
                'version_vulns': {
                    'SMB 1.0': 'Multiple critical vulnerabilities (EternalBlue, WannaCry)',
                    'SMB 2.0': 'Multiple vulnerabilities including remote code execution',
                    'Samba 3': 'Multiple critical vulnerabilities',
                    'Samba 4.3': 'Multiple vulnerabilities including badlock'
                }
            },
            'MySQL': {
                'default_ports': [3306], 
                'weak_auth': ['root:""', 'root:root', 'root:password', 'admin:admin'],
                'version_vulns': {
                    'MySQL 5.0': 'Multiple vulnerabilities, end-of-life',
                    'MySQL 5.1': 'Multiple vulnerabilities, end-of-life',
                    'MySQL 5.5': 'Multiple vulnerabilities, approaching end-of-life',
                    'MySQL 5.6': 'Some security vulnerabilities'
                }
            },
            'PostgreSQL': {
                'default_ports': [5432],
                'weak_auth': ['postgres:postgres', 'postgres:password'],
                'version_vulns': {
                    'PostgreSQL 9.3': 'End-of-life, multiple vulnerabilities',
                    'PostgreSQL 9.4': 'End-of-life, multiple vulnerabilities',
                    'PostgreSQL 9.5': 'Approaching end-of-life'
                }
            },
            'MSSQL': {
                'default_ports': [1433],
                'weak_auth': ['sa:sa', 'sa:password', 'sa:""'],
                'version_vulns': {
                    'SQL Server 2000': 'Multiple critical vulnerabilities, end-of-life',
                    'SQL Server 2005': 'Multiple vulnerabilities, end-of-life',
                    'SQL Server 2008': 'Multiple vulnerabilities, end-of-life',
                    'SQL Server 2012': 'Approaching end-of-life'
                }
            },
            'Redis': {
                'default_ports': [6379],
                'weak_auth': ['no_auth'],
                'version_vulns': {
                    'Redis 2': 'Multiple vulnerabilities, end-of-life',
                    'Redis 3': 'Some security vulnerabilities',
                    'Redis 4': 'Lua sandbox escape vulnerabilities'
                }
            },
            'MongoDB': {
                'default_ports': [27017],
                'weak_auth': ['no_auth'],
                'version_vulns': {
                    'MongoDB 2.4': 'Multiple vulnerabilities, end-of-life',
                    'MongoDB 2.6': 'Multiple vulnerabilities, end-of-life',
                    'MongoDB 3.0': 'Multiple vulnerabilities, end-of-life',
                    'MongoDB 3.2': 'Multiple vulnerabilities'
                }
            },
            'RDP': {
                'default_ports': [3389],
                'weak_auth': ['admin:admin', 'administrator:administrator', 'administrator:password'],
                'version_vulns': {
                    'Windows XP': 'BlueKeep vulnerability (CVE-2019-0708)',
                    'Windows 7': 'Multiple vulnerabilities including BlueKeep',
                    'Windows Server 2008': 'Multiple RDP vulnerabilities',
                    'Windows Server 2012': 'Various RDP security issues'
                }
            },
            'HTTPS': {
                'default_ports': [443, 8443],
                'weak_versions': ['SSLv2', 'SSLv3', 'TLSv1.0', 'TLSv1.1'],
                'version_vulns': {
                    'SSLv2': 'Completely broken, many vulnerabilities',
                    'SSLv3': 'Vulnerable to POODLE attack',
                    'TLSv1.0': 'Vulnerable to BEAST attack',
                    'TLSv1.1': 'Contains cryptographic weaknesses'
                }
            }
        }
        
        # Threat patterns database for behavior analysis
        self.threat_patterns = {
            'port_scan_profile': {
                'description': 'Port scanning activity',
                'criteria': {
                    'high_port_count': 10,  # Number of consecutive ports
                    'common_scan_ports': [21, 22, 23, 25, 80, 443, 445, 3389]  # Commonly scanned ports
                }
            },
            'backdoor_profile': {
                'description': 'Potential backdoor/remote access',
                'criteria': {
                    'unusual_ports': [1337, 4444, 5554, 6666, 6667, 8080, 9999],
                    'non_standard_services': ['Unknown']
                }
            },
            'sensitive_service_exposure': {
                'description': 'Sensitive services exposed',
                'criteria': {
                    'admin_ports': [10000, 8080, 8443, 2222, 2082, 2083, 2087, 2096, 2095],
                    'database_ports': [3306, 5432, 1433, 1521, 27017, 6379, 11211],
                    'service_types': ['MySQL', 'PostgreSQL', 'MongoDB', 'Redis', 'MSSQL', 'Oracle']
                }
            },
            'insecure_protocol': {
                'description': 'Insecure protocols detected',
                'criteria': {
                    'insecure_services': ['Telnet', 'FTP', 'SMTP', 'HTTP'],
                    'secure_alternatives': {'FTP': 'SFTP/FTPS', 'HTTP': 'HTTPS', 'Telnet': 'SSH'}
                }
            },
            'legacy_os': {
                'description': 'Legacy or outdated operating system detected',
                'criteria': {
                    'vulnerable_os': ['Windows XP', 'Windows Server 2003', 'Windows Server 2008', 'Windows 7'],
                    'eol_os': ['Windows XP', 'Windows Server 2003', 'Windows 7', 'Debian 8', 'Ubuntu 16.04', 'CentOS 6']
                }
            },
            'unpatched_services': {
                'description': 'Potentially unpatched services with known vulnerabilities',
                'criteria': {
                    'eol_versions': ['Apache/1', 'Apache/2.0', 'Apache/2.2', 'nginx/1.0', 'IIS/5.0', 'IIS/6.0']
                }
            }
        }
    
    def _get_default_port_list(self):
        """Get a focused list of important ports to scan"""
        # Common and critical services
        common_ports = [20, 21, 22, 23, 25, 53, 80, 110, 111, 123, 135, 137, 138, 139, 143, 161, 389, 443, 445, 465, 587, 993, 995]
        
        # Database services (high-value targets)
        db_ports = [1433, 1521, 3306, 5432, 6379, 27017, 11211, 5984, 9042]
        
        # Web services (commonly exposed)
        web_ports = [80, 443, 8080, 8443, 3000, 8000, 8008, 8800, 8888, 9000, 9090, 9200]
        
        # Remote access (critical security concern)
        remote_ports = [22, 23, 3389, 5900, 5800, 5938]
        
        # Commonly exploited services
        exploit_ports = [135, 139, 445, 1433, 1434, 3306, 4444, 4899, 5000, 5432, 5900]
        
        # IoT and embedded device common ports
        iot_ports = [1883, 5683, 5684, 8883, 8884, 9001]
        
        # VPN and secure communication
        vpn_ports = [500, 1701, 1723, 4500, 1194]
        
        # Mail services
        mail_ports = [25, 110, 143, 465, 587, 993, 995]
        
        # Active Directory/LDAP
        ad_ports = [88, 389, 636, 3268, 3269]
        
        # Services commonly exposed with vulnerabilities
        vuln_ports = [21, 23, 53, 111, 135, 139, 445, 512, 513, 514, 1099, 1433, 1521, 2049, 3306, 3389, 4786, 5432, 6379, 8080, 27017]
        
        # Commonly backdoored ports
        backdoor_ports = [31337, 4444, 5554, 6666, 6667, 6697, 9999]
        
        # Critical infrastructure ports
        critical_ports = [102, 502, 1883, 1911, 4000, 4840, 9600, 20000, 44818, 47808]
        
        # Top 50 most important ports (based on frequency and criticality)
        top_important = [21, 22, 23, 25, 53, 80, 88, 110, 111, 135, 137, 139, 143, 389, 443, 445, 465, 500, 587, 636,
                          993, 995, 1025, 1433, 1434, 1521, 1723, 2049, 3306, 3389, 5060, 5432, 5900, 6379, 8080, 
                          8443, 8888, 10000, 27017, 31337]
        
        # Combining all ports and removing duplicates
        all_ports = list(set(common_ports + db_ports + web_ports + remote_ports + exploit_ports + 
                            iot_ports + vpn_ports + mail_ports + ad_ports + vuln_ports + 
                            backdoor_ports + critical_ports + top_important))
        
        return sorted(all_ports)

# Continuing from where the shared code left off

    def discover_network(self):
        """Auto-detect network and discover active hosts"""
        if self.target:
            return
            
        try:
            logger.info("Auto-detecting network...")
            
            # Get default gateway
            if platform.system() == "Windows":
                command = "ipconfig"
                result = subprocess.check_output(command, shell=True).decode('utf-8')
                for line in result.splitlines():
                    if "Default Gateway" in line:
                        gateway = line.split(":")[-1].strip()
                        if gateway and gateway != "":
                            break
            else:  # Linux, macOS, etc.
                command = "ip route | grep default"
                result = subprocess.check_output(command, shell=True).decode('utf-8')
                gateway = result.split()[2] if result else None
                
            if not gateway:
                logger.error("Could not determine default gateway. Please specify a target.")
                return
                
            # Determine local network CIDR
            if platform.system() == "Windows":
                command = "ipconfig"
                result = subprocess.check_output(command, shell=True).decode('utf-8')
                for line in result.splitlines():
                    if "IPv4 Address" in line or "IP Address" in line:
                        ip = line.split(":")[-1].strip()
                    if "Subnet Mask" in line:
                        mask = line.split(":")[-1].strip()
                        if ip and mask:
                            break
            else:
                command = "hostname -I | awk '{print $1}'"
                ip = subprocess.check_output(command, shell=True).decode('utf-8').strip()
                command = "ip addr show | grep 'inet ' | grep -v 127.0.0.1 | awk '{print $2}' | head -n 1"
                cidr = subprocess.check_output(command, shell=True).decode('utf-8').strip()
                ip = cidr.split('/')[0] if cidr else ip
                
                # Get subnet mask
                if cidr and '/' in cidr:
                    prefix = int(cidr.split('/')[1])
                    mask_bits = '1' * prefix + '0' * (32 - prefix)
                    mask = '.'.join([str(int(mask_bits[i:i+8], 2)) for i in range(0, 32, 8)])
                else:
                    mask = "255.255.255.0"  # Default to class C if we can't detect
            
            # Calculate network address
            ip_parts = [int(part) for part in ip.split('.')]
            mask_parts = [int(part) for part in mask.split('.')]
            network_parts = [ip_parts[i] & mask_parts[i] for i in range(4)]
            network = '.'.join([str(part) for part in network_parts])
            
            # Calculate CIDR prefix
            prefix = sum([bin(int(part)).count('1') for part in mask.split('.')])
            
            network_cidr = f"{network}/{prefix}"
            logger.info(f"Detected network: {network_cidr}")
            
            self.target = network_cidr
            
        except Exception as e:
            logger.error(f"Error during network auto-detection: {e}")
            logger.error("Please specify a target IP or network manually.")
            return

    def discover_hosts(self):
        """Discover active hosts in the target network"""
        logger.info(f"Starting host discovery on {self.target}")
        
        active_hosts = []
        
        try:
            # Parse target (could be IP, range, or CIDR)
            if '/' in self.target:  # CIDR notation
                network = ipaddress.IPv4Network(self.target, strict=False)
                hosts = [str(ip) for ip in network.hosts()]
            elif '-' in self.target:  # Range notation (e.g., 192.168.1.1-20)
                base, range_end = self.target.rsplit('.', 1)[0], self.target.rsplit('.', 1)[1]
                if '-' in range_end:
                    start, end = range_end.split('-')
                    hosts = [f"{base}.{i}" for i in range(int(start), int(end) + 1)]
                else:
                    hosts = [self.target]
            else:  # Single IP
                hosts = [self.target]
            
            logger.info(f"Scanning {len(hosts)} potential hosts...")
            
            # Use ARP ping for local networks (faster and more reliable)
            if len(hosts) < 256:  # Small network, use ARP for efficiency
                try:
                    arp_results = self._arp_scan(hosts[0].rsplit('.', 1)[0] + '.0/24')
                    active_hosts.extend(arp_results)
                except Exception as e:
                    logger.error(f"ARP scan failed: {e}, falling back to ICMP")
                    active_hosts = self._icmp_scan(hosts)
            else:
                # For larger networks, scan in parallel using ICMP
                active_hosts = self._icmp_scan(hosts)
            
            logger.info(f"Found {len(active_hosts)} active hosts")
            return active_hosts
            
        except Exception as e:
            logger.error(f"Error during host discovery: {e}")
            return []

    def _arp_scan(self, cidr):
        """Perform ARP scan to discover hosts"""
        logger.info("Starting ARP scan for host discovery")
        
        try:
            # Create ARP request packet
            arp = ARP(pdst=cidr)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether/arp
            
            # Send packet and capture responses
            start_time = time.time()
            result = srp(packet, timeout=3, verbose=0)[0]
            end_time = time.time()
            
            # Process responses
            hosts = []
            for sent, received in result:
                hosts.append(received.psrc)
            
            logger.info(f"ARP scan completed in {end_time - start_time:.2f} seconds")
            return hosts
            
        except Exception as e:
            logger.error(f"ARP scan error: {e}")
            return []

    def _icmp_scan(self, hosts):
        """Perform ICMP ping scan to discover hosts"""
        logger.info("Starting ICMP ping scan for host discovery")
        
        active_hosts = []
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_ip = {executor.submit(self._ping_host, ip): ip for ip in hosts}
            for future in concurrent.futures.as_completed(future_to_ip):
                ip = future_to_ip[future]
                try:
                    is_active = future.result()
                    if is_active:
                        active_hosts.append(ip)
                        if len(active_hosts) % 10 == 0:
                            logger.info(f"Found {len(active_hosts)} active hosts so far...")
                except Exception as e:
                    logger.error(f"Error pinging {ip}: {e}")
        
        return active_hosts

    def _ping_host(self, ip):
        """Ping a host to check if it's online"""
        try:
            # Create an ICMP echo request
            icmp = IP(dst=ip)/ICMP()
            
            # Send packet and wait for response
            resp = sr1(icmp, timeout=self.timeout, verbose=0)
            
            return resp is not None
            
        except Exception:
            return False

    def scan_port(self, ip, port):
        """Scan a single port on a host"""
        try:
            # Create a socket object
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.timeout)
            
            # Attempt to connect to the port
            result = s.connect_ex((ip, port))
            
            if result == 0:  # Port is open
                # Try to get banner for service identification
                banner = self._grab_banner(s)
                service_info = self._identify_service(port, banner)
                
                version_info = None
                if banner:
                    version_info = self._extract_version_info(banner, service_info)
                
                vuln_info = self._check_vulnerabilities(service_info, version_info)
                
                s.close()
                return {
                    'port': port,
                    'state': 'open',
                    'service': service_info,
                    'banner': banner.decode('utf-8', errors='ignore') if banner else None,
                    'version': version_info,
                    'vulnerabilities': vuln_info
                }
            
            s.close()
            return None
            
        except Exception as e:
            logger.debug(f"Error scanning {ip}:{port} - {e}")
            return None

    def _grab_banner(self, sock):
        """Attempt to grab the service banner"""
        try:
            # Some services need a prompt
            service_prompts = {
                21: b"USER anonymous\r\n",
                25: b"EHLO netscan.local\r\n",
                23: b"\r\n",
                110: b"USER netscan\r\n",
                143: b"A1 CAPABILITY\r\n"
            }
            
            port = sock.getpeername()[1]
            if port in service_prompts:
                sock.send(service_prompts[port])
            
            sock.settimeout(1)  # Short timeout for banner grabbing
            banner = sock.recv(1024)
            return banner
            
        except Exception:
            return None

    def _identify_service(self, port, banner):
        """Identify service based on port and banner"""
        # Common port to service mapping
        common_ports = {
            20: 'FTP-DATA', 21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
            53: 'DNS', 80: 'HTTP', 110: 'POP3', 111: 'RPC', 123: 'NTP',
            135: 'RPC', 139: 'NetBIOS', 143: 'IMAP', 161: 'SNMP', 
            389: 'LDAP', 443: 'HTTPS', 445: 'SMB', 465: 'SMTPS',
            514: 'Syslog', 587: 'SMTP', 636: 'LDAPS', 993: 'IMAPS',
            995: 'POP3S', 1433: 'MSSQL', 1521: 'Oracle', 3306: 'MySQL',
            3389: 'RDP', 5432: 'PostgreSQL', 5900: 'VNC', 6379: 'Redis',
            8080: 'HTTP-Proxy', 8443: 'HTTPS-Alt', 27017: 'MongoDB'
        }
        
        # First check the banner for service identification
        if banner:
            for signature, service in self.service_signatures.items():
                if signature in banner:
                    return service
        
        # If banner analysis doesn't work, use port number
        return common_ports.get(port, 'Unknown')

    def _extract_version_info(self, banner, service):
        """Extract version information from banner"""
        banner_str = banner.decode('utf-8', errors='ignore')
        
        # Extract version based on service
        if service == "SSH":
            ssh_match = re.search(r'SSH-\d\.\d-([^\s]+)', banner_str)
            if ssh_match:
                return ssh_match.group(1)
        
        elif service == "HTTP" or service == "HTTPS":
            server_match = re.search(r'Server: ([^\r\n]+)', banner_str)
            if server_match:
                return server_match.group(1)
        
        elif service == "FTP":
            ftp_match = re.search(r'^220[- ]([^\r\n]+)', banner_str)
            if ftp_match:
                return ftp_match.group(1)
        
        elif service == "SMTP":
            smtp_match = re.search(r'^220[- ]([^\r\n]+)', banner_str)
            if smtp_match:
                return smtp_match.group(1)
        
        elif service == "MySQL":
            mysql_match = re.search(r'([0-9]+\.[0-9]+\.[0-9]+)', banner_str)
            if mysql_match:
                return mysql_match.group(1)
        
        # Generic version pattern matching as fallback
        version_patterns = [
            r'([0-9]+\.[0-9]+\.[0-9]+)',  # Matches version like 1.2.3
            r'([0-9]+\.[0-9]+)',           # Matches version like 1.2
            r'v([0-9]+\.[0-9]+)',          # Matches version like v1.2
            r'version ([0-9]+\.[0-9]+)'    # Matches "version 1.2"
        ]
        
        for pattern in version_patterns:
            match = re.search(pattern, banner_str, re.IGNORECASE)
            if match:
                return match.group(1)
        
        return None

    def _check_vulnerabilities(self, service, version):
        """Check for known vulnerabilities based on service and version"""
        vulns = []
        
        if service in self.vulnerability_db:
            vuln_info = self.vulnerability_db[service]
            
            # Check for inherently insecure services
            if 'security' in vuln_info and vuln_info['security'] == 'inherently_insecure':
                vulns.append({
                    'type': 'insecure_protocol',
                    'severity': 'HIGH',
                    'description': f'{service} is inherently insecure as it transmits data in cleartext'
                })
            
            # Check version-specific vulnerabilities
            if version and 'version_vulns' in vuln_info:
                for vuln_ver, desc in vuln_info['version_vulns'].items():
                    if vuln_ver == 'all' or vuln_ver in version:
                        vulns.append({
                            'type': 'version_vulnerability',
                            'severity': 'HIGH',
                            'description': desc
                        })
            
            # Check for weak versions
            if version and 'weak_versions' in vuln_info:
                for weak_ver in vuln_info['weak_versions']:
                    if weak_ver in version:
                        vulns.append({
                            'type': 'weak_version',
                            'severity': 'MEDIUM',
                            'description': f'Running potentially vulnerable version {version}'
                        })
            
        return vulns if vulns else None

    def scan_host(self, ip):
        """Scan a single host for open ports and services"""
        logger.info(f"Scanning host {ip}")
        
        host_results = {
            'ip': ip,
            'hostname': self._get_hostname(ip),
            'os': self._detect_os(ip),
            'ports': [],
            'threats': []
        }
        
        # Scan ports in parallel
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_port = {executor.submit(self.scan_port, ip, port): port for port in self.ports}
            for future in concurrent.futures.as_completed(future_to_port):
                port = future_to_port[future]
                try:
                    result = future.result()
                    if result:
                        host_results['ports'].append(result)
                except Exception as e:
                    logger.error(f"Error scanning port {port} on {ip}: {e}")
        
        # Analyze results for potential threats
        if host_results['ports']:
            host_results['threats'] = self._analyze_threats(host_results)
            
        return host_results

    def _get_hostname(self, ip):
        """Get hostname for an IP address"""
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return hostname
        except socket.herror:
            return None

    def _detect_os(self, ip):
        """Detect operating system of a host"""
        os_results = []
        
        try:
            # Send TCP probe to well-known port
            ttl_probe = IP(dst=ip)/ICMP()
            response = sr1(ttl_probe, timeout=1, verbose=0)
            
            if response:
                # TTL-based OS detection
                ttl = response.ttl
                if ttl <= 64:
                    os_results.append("Linux/Unix (TTL: {})".format(ttl))
                elif ttl <= 128:
                    os_results.append("Windows (TTL: {})".format(ttl))
                elif ttl <= 255:
                    os_results.append("Cisco/Network Device (TTL: {})".format(ttl))
            
            # Port-based OS fingerprinting
            open_ports = []
            for port in [21, 22, 23, 25, 80, 135, 139, 443, 445, 3389]:
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(0.5)
                    result = s.connect_ex((ip, port))
                    if result == 0:
                        open_ports.append(port)
                    s.close()
                except:
                    pass
            
            # Analyze port combinations for OS fingerprinting
            if 135 in open_ports and 139 in open_ports and 445 in open_ports:
                os_results.append("Windows (Port signature)")
            elif 22 in open_ports and 80 in open_ports:
                os_results.append("Linux/Unix (Port signature)")
            
        except Exception as e:
            logger.debug(f"OS detection error for {ip}: {e}")
        
        return os_results[0] if os_results else "Unknown"

    def _analyze_threats(self, host_data):
        """Analyze scan results for potential threats"""
        threats = []
        
        # Check for exposed sensitive services
        db_services = ['MySQL', 'PostgreSQL', 'MSSQL', 'MongoDB', 'Redis', 'Oracle']
        exposed_dbs = [p for p in host_data['ports'] if p['service'] in db_services]
        
        if exposed_dbs:
            threats.append({
                'type': 'sensitive_service_exposure',
                'severity': 'MEDIUM',
                'description': f'Exposed database services: {", ".join([p["service"] for p in exposed_dbs])}',
                'affected_ports': [p['port'] for p in exposed_dbs]
            })
        
        # Check for insecure protocols
        insecure_services = ['Telnet', 'FTP', 'HTTP']
        exposed_insecure = [p for p in host_data['ports'] if p['service'] in insecure_services]
        
        if exposed_insecure:
            threats.append({
                'type': 'insecure_protocol',
                'severity': 'MEDIUM',
                'description': f'Insecure protocols in use: {", ".join([p["service"] for p in exposed_insecure])}',
                'affected_ports': [p['port'] for p in exposed_insecure]
            })
        
        # Check for potentially backdoored ports
        backdoor_ports = [1337, 4444, 5554, 6666, 6667, 8080, 9999]
        potential_backdoors = [p for p in host_data['ports'] if p['port'] in backdoor_ports]
        
        if potential_backdoors:
            threats.append({
                'type': 'potential_backdoor',
                'severity': 'HIGH',
                'description': f'Potential backdoor ports open: {", ".join([str(p["port"]) for p in potential_backdoors])}',
                'affected_ports': [p['port'] for p in potential_backdoors]
            })
        
        # Check for exploitable vulnerabilities
        exploitable_ports = [p for p in host_data['ports'] if p.get('vulnerabilities')]
        
        if exploitable_ports:
            vuln_count = sum(len(p['vulnerabilities']) for p in exploitable_ports if p['vulnerabilities'])
            threats.append({
                'type': 'vulnerable_services',
                'severity': 'HIGH',
                'description': f'Found {vuln_count} potential vulnerabilities in {len(exploitable_ports)} services',
                'affected_ports': [p['port'] for p in exploitable_ports]
            })
        
        # Check for legacy OS
        if host_data['os'] and any(legacy in host_data['os'] for legacy in ['Windows XP', 'Windows Server 2003', 'Windows 7']):
            threats.append({
                'type': 'legacy_os',
                'severity': 'HIGH',
                'description': f'Legacy operating system detected: {host_data["os"]}',
                'remediation': 'Update to a supported operating system with security patches'
            })
        
        return threats

    def run_scan(self):
        """Run the full network scan"""
        self.scan_start_time = datetime.now()
        logger.info(f"Starting network scan at {self.scan_start_time}")
        
        # Step 1: Auto-detect network if no target specified
        if not self.target:
            self.discover_network()
            if not self.target:
                logger.error("No target specified and auto-detection failed. Exiting.")
                return None
        
        # Step 2: Discover active hosts
        active_hosts = self.discover_hosts()
        if not active_hosts:
            logger.error("No active hosts found. Exiting.")
            return None
        
        # Step 3: Scan each host
        scan_results = []
        for host in active_hosts:
            scan_results.append(self.scan_host(host))
            
        self.scan_end_time = datetime.now()
        scan_duration = (self.scan_end_time - self.scan_start_time).total_seconds()
        
        logger.info(f"Scan completed in {scan_duration:.2f} seconds")
        logger.info(f"Scanned {len(active_hosts)} hosts")
        
        # Save results
        self.results = {
            'scan_info': {
                'target': self.target,
                'start_time': self.scan_start_time.strftime('%Y-%m-%d %H:%M:%S'),
                'end_time': self.scan_end_time.strftime('%Y-%m-%d %H:%M:%S'),
                'duration': scan_duration,
                'hosts_scanned': len(active_hosts)
            },
            'hosts': scan_results
        }
        
        return self.results

    def generate_report(self):
        """Generate a formatted report of scan results"""
        if not self.results:
            logger.error("No scan results available. Run scan first.")
            return None
            
        if self.output_format == 'json':
            return self._generate_json_report()
        elif self.output_format == 'csv':
            return self._generate_csv_report()
        else:  # text format
            return self._generate_text_report()

    def _generate_text_report(self):
        """Generate a text-based report"""
        report = []
        
        # Header
        report.append("=" * 80)
        report.append("NETWORK SCAN REPORT")
        report.append("=" * 80)
        
        # Scan info
        scan_info = self.results['scan_info']
        report.append(f"Target: {scan_info['target']}")
        report.append(f"Scan duration: {scan_info['duration']:.2f} seconds")
        report.append(f"Start time: {scan_info['start_time']}")
        report.append(f"End time: {scan_info['end_time']}")
        report.append(f"Hosts scanned: {scan_info['hosts_scanned']}")
        report.append("-" * 80)
        
        # Host details
        for host in self.results['hosts']:
            report.append(f"HOST: {host['ip']}")
            if host['hostname']:
                report.append(f"Hostname: {host['hostname']}")
            
            report.append(f"Operating System: {host['os']}")
            
            # Open ports
            report.append(f"\nOpen ports: {len(host['ports'])}")
            if host['ports']:
                report.append("{:<10} {:<15} {:<20} {:<}".format("PORT", "STATE", "SERVICE", "VERSION"))
                report.append("-" * 70)
                for port in sorted(host['ports'], key=lambda x: x['port']):
                    version = port.get('version', '')
                    report.append("{:<10} {:<15} {:<20} {:<}".format(
                        port['port'], 
                        port['state'], 
                        port['service'], 
                        version if version else ''
                    ))
            
            # Vulnerabilities
            vulns = []
            for port in host['ports']:
                if port.get('vulnerabilities'):
                    for vuln in port['vulnerabilities']:
                        vuln_info = {
                            'port': port['port'],
                            'service': port['service'],
                            'type': vuln['type'],
                            'severity': vuln['severity'],
                            'description': vuln['description']
                        }
                        vulns.append(vuln_info)
            
            if vulns:
                report.append("\nVulnerabilities:")
                report.append("{:<10} {:<15} {:<10} {:<}".format("PORT", "SERVICE", "SEVERITY", "DESCRIPTION"))
                report.append("-" * 80)
                for vuln in vulns:
                    report.append("{:<10} {:<15} {:<10} {:<}".format(
                        vuln['port'],
                        vuln['service'],
                        vuln['severity'],
                        vuln['description']
                    ))
            
            # Threats
            if host['threats']:
                report.append("\nPotential threats:")
                for threat in host['threats']:
                    report.append(f"- [{threat['severity']}] {threat['type']}: {threat['description']}")
            
            report.append("=" * 80)
        
        # Security summary
        total_vulns = sum(len([v for p in h['ports'] if p.get('vulnerabilities') for v in p['vulnerabilities']]) for h in self.results['hosts'])
        total_threats = sum(len(h['threats']) for h in self.results['hosts'])
        
        report.append("\nSECURITY SUMMARY")
        report.append("-" * 80)
        report.append(f"Total vulnerabilities found: {total_vulns}")
        report.append(f"Total potential threats detected: {total_threats}")
        
        if total_vulns > 10 or total_threats > 5:
            report.append("\n[!] HIGH RISK: Multiple security issues detected")
        elif total_vulns > 5 or total_threats > 2:
            report.append("\n[!] MEDIUM RISK: Several security issues detected")
        elif total_vulns > 0 or total_threats > 0:
            report.append("\n[!] LOW RISK: Minor security issues detected")
        else:
            report.append("\n[✓] No significant security issues detected")
        
        return "\n".join(report)

    def _generate_json_report(self):
        """Generate a JSON report"""
        return json.dumps(self.results, indent=4)

    def _generate_csv_report(self):
        """Generate a CSV report"""
        # Create dataframes for different report sections
        hosts_data = []
        ports_data = []
        vulns_data = []
        threats_data = []
        
        for host in self.results['hosts']:
            # Host info
            host_info = {
                'ip': host['ip'],
                'hostname': host['hostname'] or '',
                'os': host['os'],
                'open_ports': len(host['ports']),
                'threats': len(host['threats'])
            }
            hosts_data.append(host_info)
            
            # Ports info
            for port in host['ports']:
                port_info = {
                    'ip': host['ip'],
                    'port': port['port'],
                    'state': port['state'],
                    'service': port['service'],
                    'version': port.get('version', '')
                }
                ports_data.append(port_info)
                
                # Vulnerabilities info
                if port.get('vulnerabilities'):
                    for vuln in port['vulnerabilities']:
                        vuln_info = {
                            'ip': host['ip'],
                            'port': port['port'],
                            'service': port['service'],
                            'type': vuln['type'],
                            'severity': vuln['severity'],
                            'description': vuln['description']
                        }
                        vulns_data.append(vuln_info)
            
            # Threats info
            for threat in host['threats']:
                threat_info = {
                    'ip': host['ip'],
                    'type': threat['type'],
                    'severity': threat['severity'],
                    'description': threat['description'],
                    'affected_ports': ','.join(map(str, threat.get('affected_ports', [])))
                }
                threats_data.append(threat_info)
        
        # Convert to dataframes
        hosts_df = pd.DataFrame(hosts_data)
        ports_df = pd.DataFrame(ports_data)
        vulns_df = pd.DataFrame(vulns_data) if vulns_data else pd.DataFrame()
        threats_df = pd.DataFrame(threats_data) if threats_data else pd.DataFrame()
        
        # Generate CSV
        hosts_csv = hosts_df.to_csv(index=False)
        ports_csv = ports_df.to_csv(index=False)
        vulns_csv = vulns_df.to_csv(index=False) if not vulns_df.empty else "No vulnerabilities found"
        threats_csv = threats_df.to_csv(index=False) if not threats_df.empty else "No threats found"
        
        # Combine reports
        result = f"""
HOSTS
{hosts_csv}

PORTS
{ports_csv}

VULNERABILITIES
{vulns_csv}

THREATS
{threats_csv}
"""
        return result

    def save_results(self, filename=None):
        """Save scan results to a file"""
        if not self.results:
            logger.error("No scan results available to save")
            return False
            
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"results_{timestamp}.{self.output_format}"
            
        try:
            report = self.generate_report()
            with open(filename, 'w') as f:
                f.write(report)
            logger.info(f"Results saved to {filename}")
            return True
        except Exception as e:
            logger.error(f"Error saving results: {e}")
            return False
            
            """
Command line interface for NetScan
"""

def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description='NetScan - Enhanced Network Scanner with Threat Detection',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
examples:
    # Scan a single host with default settings
    python netscan.py -t 192.168.1.10
    
    # Scan a subnet with custom port range
    python netscan.py -t 192.168.1.0/24 -p 22,80,443,3389
    
    # Auto-detect and scan local network with extended options
    python netscan.py --auto-detect --extended-scan
    
    # Save results in JSON format
    python netscan.py -t 10.0.0.0/24 -o json -f scan_results.json
        '''
    )
    
    # Target options
    target_group = parser.add_argument_group('Target Selection')
    target_group.add_argument('-t', '--target', help='Target IP, range (e.g., 192.168.1.1-20), or CIDR (e.g., 192.168.1.0/24)')
    target_group.add_argument('--auto-detect', action='store_true', help='Auto-detect network and scan all hosts')
    
    # Scan options
    scan_group = parser.add_argument_group('Scan Options')
    scan_group.add_argument('-p', '--ports', help='Port(s) to scan (e.g., 80,443,8080 or 1-1000)')
    scan_group.add_argument('--timeout', type=float, default=1, help='Timeout for network operations (seconds)')
    scan_group.add_argument('--threads', type=int, default=100, help='Number of concurrent threads')
    scan_group.add_argument('--extended-scan', action='store_true', help='Enable extended port range and additional checks')
    
    # Output options
    output_group = parser.add_argument_group('Output Options')
    output_group.add_argument('-o', '--output', choices=['text', 'json', 'csv'], default='text', help='Output format')
    output_group.add_argument('-f', '--file', help='Output file')
    output_group.add_argument('-q', '--quiet', action='store_true', help='Suppress terminal output except for errors')
    output_group.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    
    return parser.parse_args()

def process_port_range(port_arg):
    """Process port range argument"""
    ports = []
    if not port_arg:
        return None
    
    for item in port_arg.split(','):
        if '-' in item:
            start, end = map(int, item.split('-'))
            ports.extend(range(start, end + 1))
        else:
            ports.append(int(item))
    
    return sorted(list(set(ports)))

def main():
    """Main function"""
    # Parse command line arguments
    args = parse_arguments()
    
    # Display banner
    display_banner()
    
    # Set log level
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    elif args.quiet:
        logger.setLevel(logging.ERROR)
    
    # Process target
    target = args.target
    if args.auto_detect:
        target = None  # Let the scanner auto-detect the network
    
    # Process ports
    ports = process_port_range(args.ports)
    
    # Create scanner instance
    scanner = NetworkScanner(
        target=target,
        ports=ports,
        timeout=args.timeout,
        threads=args.threads,
        output_format=args.output
    )
    
    # Run scan
    results = scanner.run_scan()
    
    if results:
        # Generate report
        report = scanner.generate_report()
        
        # Print report
        if not args.quiet:
            print(report)
        
        # Save results to file if specified
        if args.file:
            scanner.save_results(args.file)
        else:
            # Save with default filename
            scanner.save_results()
    else:
        logger.error("Scan failed to complete")
        return 1
    
    return 0

if __name__ == "__main__":
    try:
        exit_code = main()
        exit(exit_code)
    except KeyboardInterrupt:
        logger.error("\nScan interrupted by user")
        exit(1)
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        exit(1)
