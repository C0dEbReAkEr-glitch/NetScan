# ⚡ NetScan ⚡

A comprehensive Python-based network scanner with advanced threat detection capabilities.

[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/downloads/)

## 📋 Overview

NetScan is a powerful network reconnaissance and security assessment tool designed to provide comprehensive visibility into your network infrastructure. It combines multiple scanning techniques with threat intelligence to detect potential vulnerabilities and security risks.

## ✨ Features

- **Host Discovery:** Identify all active hosts on target networks using ICMP, ARP, and TCP methods
- **OS Detection:** Determine operating systems running on target hosts using TCP/IP fingerprinting
- **Port Scanning:** Perform comprehensive port scanning with multiple techniques (SYN, TCP, UDP)
- **Version Identification:** Detect service versions for precise vulnerability correlation
- **Vulnerability Detection:** Match discovered services against known vulnerability databases
- **Behavior Analysis:** Monitor and analyze network traffic patterns to identify anomalies
- **Multiple Output Formats:** Export results as JSON, CSV, XML, or formatted reports

## 🚀 Installation

```bash
# Clone the repository
https://github.com/C0dEbReAkEr-glitch/NetScan.git
cd netscan

# No additional dependencies required for installation!
# The tool is ready to use right after cloning
```

## 📊 Usage

### Command Line Arguments
```
NetScan - Enhanced Network Scanner with Threat Detection

usage: netscan2.py [-h] [-t TARGET] [--auto-detect] [-p PORTS]
                   [--timeout TIMEOUT] [--threads THREADS] [--extended-scan]
                   [-o {text,json,csv}] [-f FILE] [-q] [-v]

options:
  -h, --help            show this help message and exit

Target Selection:
  -t, --target TARGET   Target IP, range (e.g., 192.168.1.1-20), or CIDR
                        (e.g., 192.168.1.0/24)
  --auto-detect         Auto-detect network and scan all hosts

Scan Options:
  -p, --ports PORTS     Port(s) to scan (e.g., 80,443,8080 or 1-1000)
  --timeout TIMEOUT     Timeout for network operations (seconds)
  --threads THREADS     Number of concurrent threads
  --extended-scan       Enable extended port range and additional checks

Output Options:
  -o, --output {text,json,csv}
                        Output format
  -f, --file FILE       Output file
  -q, --quiet           Suppress terminal output except for errors
  -v, --verbose         Enable verbose output
```

### Examples
```bash
# Scan a single host with default settings
python netscan.py -t 192.168.1.10

# Scan a subnet with custom port range
python netscan.py -t 192.168.1.0/24 -p 22,80,443,3389

# Auto-detect and scan local network with extended options
python netscan.py --auto-detect --extended-scan

# Save results in JSON format
python netscan.py -t 10.0.0.0/24 -o json -f scan_results.json
```

## 📋 Requirements

- Python 3.8+
- No additional dependencies required! NetScan works with Python standard libraries

## 📊 Sample Output

```
================================================================================
NETWORK SCAN REPORT
================================================================================
Target: xxx.xxx.x.xxx
Scan duration: 8.75 seconds
Start time: 2025-05-08 13:35:47
End time: 2025-05-08 13:35:56
Hosts scanned: 2
--------------------------------------------------------------------------------
HOST: xxx.xxx.x.x
Hostname: _gateway
Operating System: Linux/Unix (TTL: 64)
Open ports: 4
PORT       STATE           SERVICE              VERSION
----------------------------------------------------------------------
80         open            HTTP                 
443        open            HTTPS                
8080       open            HTTP-Proxy           
8443       open            HTTPS-Alt            
Potential threats:
- [MEDIUM] insecure_protocol: Insecure protocols in use: HTTP
- [HIGH] potential_backdoor: Potential backdoor ports open: 8080
================================================================================
HOST: 192.168.1.100
Operating System: Linux/Unix (TTL: 64)
Open ports: 19
PORT       STATE           SERVICE              VERSION
----------------------------------------------------------------------
21         open            FTP                  (xxXXXx x.x.x)
22         open            SSH                  XXXXXXX_x.xxx
23         open            Telnet               
25         open            SMTP                 xxxxxxxxxxxxxxxxxxxx
53         open            DNS                  
80         open            HTTP                 
111        open            RPC                  
139        open            NetBIOS              
445        open            SMB                  
512        open            Unknown              
513        open            Unknown              
514        open            Syslog               
1099       open            Unknown              
2049       open            Unknown              
3306       open            MySQL                x.x.xx
5432       open            PostgreSQL           
5900       open            VNC                  xxx.xxx
6667       open            Unknown              
6697       open            Unknown              
Vulnerabilities:
PORT       SERVICE         SEVERITY   DESCRIPTION
--------------------------------------------------------------------------------
23         Telnet          HIGH       Telnet is inherently insecure as it transmits data in cleartext
Potential threats:
- [MEDIUM] sensitive_service_exposure: Exposed database services: MySQL, PostgreSQL
- [MEDIUM] insecure_protocol: Insecure protocols in use: FTP, Telnet, HTTP
- [HIGH] potential_backdoor: Potential backdoor ports open: 6667
- [HIGH] vulnerable_services: Found 1 potential vulnerabilities in 1 services
================================================================================
SECURITY SUMMARY
--------------------------------------------------------------------------------
Total vulnerabilities found: 1
Total potential threats detected: 6
[!] HIGH RISK: Multiple security issues detected
```

## 🛡️ Security Considerations

This tool is intended for legitimate security testing with proper authorization. Unauthorized scanning may violate laws or regulations. Always ensure you have permission before scanning any networks or systems you don't own.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

⚠️ **Disclaimer:** This tool is for educational and ethical testing purposes only. The author is not responsible for any misuse or damage caused by this program. Use responsibly.
