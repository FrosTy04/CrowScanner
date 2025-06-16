# CrowScanner
CrowScanner is a Python-based network scanning tool inspired by Nmap, designed for efficient network exploration, port scanning, service and OS detection, and more. This tool provides flexibility in targeting options and scan types, making it ideal for network administrators, cybersecurity enthusiasts, and developers.




**Version**: Vrs 0.5  
**Author**: FrosTy

---

## Table of Contents
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
  - [Basic Scanning](#basic-scanning)
  - [Port Scanning](#port-scanning)
  - [Service and OS Detection](#service-and-os-detection)
  - [Additional Options](#additional-options)
  - [Timing and Performance](#timing-and-performance)
- [Examples](#examples)
- [License](#license)
- [Disclaimer](#disclaimer)

---

## Features

- **Basic Scanning**: Scan single IPs, IP ranges, subnets, and domains.
- **Port Scanning**: Scan specific ports, all ports (1-65535), or common ports.
- **Service and OS Detection**: Identify service versions and detect operating systems.
- **Additional Options**: Supports verbose output, ping bypass, file output, and UDP scanning.
- **Timing Templates**: Adjust scan speed from stealth to aggressive for performance tuning.

---

## Installation

1. **Clone the Repository**
   ```bash
   git clone https://github.com/frostyceo/CrowScanner.git
   cd CrowScanner


Install Dependencies CrowScanner relies on a few Python packages. You can install them using:
pip install -r requirements.txt
asyncio
argparse
colorama
socket
ipaddress
aiohttp



Usage
CrowScanner provides multiple scanning options. Below is a summary of each major feature and example usage.

Basic Scanning
Single IP: scanner example.com
IP Range: scanner 
Subnet: scanner 
Multiple IPs: scanner example example.2
Domain Name: scanner example.com
Port Scanning
Specific Ports: scanner -p 22,80,443 example
All Ports: scanner -p- example
Common Ports: scanner --top-ports 20 example
Service and OS Detection
Service Version Detection: scanner -sV example
OS Detection: scanner -O example
Aggressive Scan: scanner -A example
Additional Options
Verbose Output: scanner -v example
No Ping: scanner -Pn example
Save Output to File: scanner -oN output.txt example
UDP Scanning: scanner -sU example
Timing and Performance
Timing Template: scanner -T4 example (0-5, where 5 is the fastest)
