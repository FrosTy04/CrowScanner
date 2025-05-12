import argparse
import asyncio
import socket
import ipaddress
from colorama import Fore, Style, init

# Initialize colorama for colored output
init(autoreset=True)

def print_banner():
    banner = r"""
 _____                   _____                                 
/  __ \                 /  ___|                                
| /  \/_ __ _____      _\ `--.  ___ __ _ _ __  _ __   ___ _ __ 
| |   | '__/ _ \ \ /\ / /`--. \/ __/ _` | '_ \| '_ \ / _ \ '__|
| \__/\ | | (_) \ V  V //\__/ / (_| (_| | | | | | | |  __/ |   
 \____/_|  \___/ \_/\_/ \____/ \___\__,_|_| |_|_| |_|\___|_|   
                                                               
    """
    print(Fore.CYAN + banner + Style.RESET_ALL)
    print("By FrosTy, Vrs 0.5")

class PortScanner:
    def __init__(self, target, ports, top_ports, show_ip, scan_os, scan_service, udp_scan, verbose, output_file, aggressive, timing):
        self.target = target
        self.ports = ports
        self.top_ports = top_ports
        self.open_ports = {}
        self.show_ip = show_ip
        self.scan_os = scan_os
        self.scan_service = scan_service
        self.udp_scan = udp_scan
        self.verbose = verbose
        self.output_file = output_file
        self.aggressive = aggressive
        self.timing = timing

    async def scan_port(self, ip, port):
        """Asynchronously scans a single port."""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout=1.5
            )
            service, version = await self.identify_service(reader, writer)
            return port, 'Open', service, version
        except (ConnectionRefusedError, asyncio.TimeoutError):
            return None

    async def identify_service(self, reader, writer):
        """Attempts to identify the service and version running on the port."""
        try:
            writer.write(b"\n")
            await writer.drain()
            banner = await asyncio.wait_for(reader.read(100), timeout=1)
            service_info = banner.decode().strip()
            service = service_info.split('/')[0] if '/' in service_info else service_info
            version = service_info.split('/')[1] if '/' in service_info else 'Unknown Version'
            return service, version
        except Exception:
            return "Unknown Service", "Unknown Version"
        finally:
            writer.close()
            await writer.wait_closed()

    async def scan_ports(self):
        """Asynchronously scans the specified ports on the target IP."""
        ips = self.resolve_target()
        if not ips:
            return

        for ip in ips:
            if self.show_ip:
                print(f"Resolved IP address for {self.target}: {ip}")

            tasks = [self.scan_port(ip, port) for port in self.ports]
            for task in asyncio.as_completed(tasks):
                result = await task
                if result:
                    port, state, service, version = result
                    self.open_ports[port] = {
                        'state': state,
                        'service': service,
                        'version': version
                    }

    def resolve_target(self):
        """Resolves the target (IP or URL) to an IP address or range of addresses."""
        try:
            ip_list = []
            # Check if the target is a subnet
            if '/' in self.target:
                network = ipaddress.ip_network(self.target, strict=False)
                ip_list = [str(ip) for ip in network.hosts()]
            elif '-' in self.target:
                start_ip, end_ip = self.target.split('-')
                ip_list = [str(ip) for ip in ipaddress.summarize_address_range(ipaddress.ip_address(start_ip), ipaddress.ip_address(end_ip))]
            else:
                ip = socket.gethostbyname(self.target)
                ip_list.append(ip)
                print(f"Scanning target: {self.target} (IP: {ip})...")

            return ip_list
        except Exception as e:
            print(f"Error: Unable to resolve {self.target} - {str(e)}")
            return None

    def print_results(self):
        """Prints the results of the scan."""
        print("\nScan complete!")
        if self.open_ports:
            print(f"{'Port':<10} {'State':<10} {'Service':<30} {'Version'}")
            print("=" * 70)
            for port, info in self.open_ports.items():
                print(f"{port:<10} {info['state']:<10} {info['service']:<30} {info['version']}")
        else:
            print(f"No open ports found on {self.target}.")

        if self.output_file:
            with open(self.output_file, 'w') as f:
                for port, info in self.open_ports.items():
                    f.write(f"{port} {info['state']} {info['service']} {info['version']}\n")
            print(f"Results saved to {self.output_file}")

async def main():
    print_banner()  # Print the banner at the start of the scan
    parser = argparse.ArgumentParser(description="Nmap-like Simple Port Scanner", formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("target", help="Target IP address or URL to scan")
    parser.add_argument("-p", "--ports", type=str, help="Comma-separated list of ports or ranges (e.g., 22,80,443 or 1-65535)")
    parser.add_argument("--top-ports", type=int, help="Scan the specified number of most common ports")
    parser.add_argument("-ip", "--show-ip", action='store_true', help="Show the resolved IP address of the target")
    parser.add_argument("-O", "--scan-os", action='store_true', help="Enable OS detection")
    parser.add_argument("-sV", "--scan-service", action='store_true', help="Enable service version detection")
    parser.add_argument("-v", "--verbose", action='store_true', help="Enable verbose output")
    parser.add_argument("-Pn", "--ping-skip", action='store_true', help="Scan without pinging")
    parser.add_argument("-oN", "--output-file", type=str, help="Save output to a file")
    parser.add_argument("-sU", "--udp-scan", action='store_true', help="Scan for UDP ports")
    parser.add_argument("-A", "--aggressive", action='store_true', help="Enable aggressive scan (service and OS detection)")
    parser.add_argument("-T", "--timing", type=int, choices=range(0, 6), help="Set timing template (0-5)")

    args = parser.parse_args()

    # Parse ports input
    port_list = []
    if args.ports:
        if args.ports == '-':
            port_list = range(1, 65536)  # Scan all ports
        else:
            for part in args.ports.split(','):
                if '-' in part:
                    start, end = map(int, part.split('-'))
                    port_list.extend(range(start, end + 1))
                else:
                    port_list.append(int(part))
    elif args.top_ports:
        port_list = range(1, args.top_ports + 1)  # Scan specified number of top ports
    else:
        port_list = range(1, 1025)  # Default to scanning ports 1-1024

    scanner = PortScanner(
        target=args.target, ports=port_list, top_ports=args.top_ports, show_ip=args.show_ip,
        scan_os=args.scan_os, scan_service=args.scan_service, udp_scan=args.udp_scan,
        verbose=args.verbose, output_file=args.output_file, aggressive=args.aggressive, timing=args.timing
    )
    await scanner.scan_ports()
    scanner.print_results()

if __name__ == "__main__":
    asyncio.run(main())
