import argparse
import asyncio
import socket
import ipaddress
from colorama import Fore, Style, init
import time
from concurrent.futures import ThreadPoolExecutor
from typing import List, Dict, Tuple, Optional
import sys

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
    print(f"{Fore.GREEN}The Modern Port Scanner - Inspired by RustScan{Style.RESET_ALL}")
    print("By FrosTy, Vrs 0.6\n")

class PortScanner:
    def __init__(self, target: str, ports: List[int], batch_size: int = 5000, timeout: float = 0.1, **kwargs):
        self.target = target
        self.ports = ports
        self.batch_size = batch_size
        self.timeout = timeout
        self.open_ports: Dict[int, Dict] = {}
        self.start_time = time.time()
        self.kwargs = kwargs
        self.total_ports = len(ports)
        self.scanned_ports = 0

    def update_progress(self):
        """Updates the progress bar."""
        percentage = (self.scanned_ports / self.total_ports) * 100
        bar_length = 40
        filled_length = int(bar_length * self.scanned_ports // self.total_ports)
        bar = '=' * filled_length + '-' * (bar_length - filled_length)
        
        sys.stdout.write(f'\r[{bar}] {percentage:.1f}% ({self.scanned_ports}/{self.total_ports} ports)')
        sys.stdout.flush()

    async def scan_port(self, ip: str, port: int) -> Optional[Tuple[int, str, str, str]]:
        """Asynchronously scans a single port with minimal timeout."""
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=self.timeout
            )
            writer.close()
            await writer.wait_closed()
            return port, 'Open', 'Unknown', 'Unknown'
        except (ConnectionRefusedError, asyncio.TimeoutError):
            return None
        except Exception as e:
            if self.kwargs.get('verbose'):
                print(f"\nError scanning port {port}: {str(e)}")
            return None
        finally:
            self.scanned_ports += 1
            if not self.kwargs.get('quiet'):
                self.update_progress()

    async def scan_batch(self, ip: str, batch: List[int]):
        """Scans a batch of ports concurrently."""
        tasks = [self.scan_port(ip, port) for port in batch]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        return [r for r in results if r is not None]

    async def scan_ports(self):
        """Scans ports in batches for improved performance."""
        ips = self.resolve_target()
        if not ips:
            return

        print(f"{Fore.YELLOW}Starting Fast Scan at {time.strftime('%Y-%m-%d %H:%M:%S')}{Style.RESET_ALL}")
        print(f"Scanning {self.total_ports} ports on {self.target} with {self.batch_size} ports per batch")
        
        for ip in ips:
            if self.kwargs.get('show_ip'):
                print(f"\nScanning IP: {ip}")

            # Split ports into batches
            for i in range(0, len(self.ports), self.batch_size):
                batch = self.ports[i:i + self.batch_size]
                results = await self.scan_batch(ip, batch)
                
                for result in results:
                    if result:
                        port, state, service, version = result
                        if port not in self.open_ports:  # Avoid duplicates
                            self.open_ports[port] = {
                                'state': state,
                                'service': service,
                                'version': version
                            }
                            if self.kwargs.get('verbose'):
                                print(f"\nPort {port} is open!")

    def resolve_target(self) -> Optional[List[str]]:
        """Resolves the target to IP addresses."""
        try:
            ip_list = []
            if '/' in self.target:
                network = ipaddress.ip_network(self.target, strict=False)
                ip_list = [str(ip) for ip in network.hosts()]
            elif '-' in self.target:
                start_ip, end_ip = self.target.split('-')
                ip_list = [str(ip) for ip in ipaddress.summarize_address_range(
                    ipaddress.ip_address(start_ip.strip()),
                    ipaddress.ip_address(end_ip.strip())
                )]
            else:
                ip = socket.gethostbyname(self.target)
                ip_list.append(ip)
                print(f"{Fore.GREEN}Target: {self.target} ({ip}){Style.RESET_ALL}")

            return ip_list
        except Exception as e:
            print(f"{Fore.RED}Error: Unable to resolve {self.target} - {str(e)}{Style.RESET_ALL}")
            return None

    def print_results(self):
        """Prints scan results in RustScan format."""
        duration = time.time() - self.start_time
        print(f"\n\n{Fore.GREEN}Scan completed in {duration:.2f} seconds{Style.RESET_ALL}")
        
        if self.open_ports:
            print(f"\n{Fore.CYAN}Open ports:{Style.RESET_ALL}")
            ports_list = sorted(self.open_ports.keys())
            print(f"PORT     STATE  SERVICE")
            print("==========================================")
            for port in ports_list:
                info = self.open_ports[port]
                print(f"{port:<8} {info['state']:<6} {info['service']}")
        else:
            print(f"\n{Fore.YELLOW}No open ports found{Style.RESET_ALL}")

        if self.kwargs.get('output_file'):
            with open(self.kwargs['output_file'], 'w') as f:
                f.write(f"Scan Results for {self.target}\n")
                f.write(f"Scan Duration: {duration:.2f} seconds\n\n")
                for port, info in sorted(self.open_ports.items()):
                    f.write(f"{port} {info['state']} {info['service']}\n")
            print(f"\nResults saved to {self.kwargs['output_file']}")

async def main():
    print_banner()
    parser = argparse.ArgumentParser(description="Fast Port Scanner (RustScan-inspired)", 
                                   formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("target", help="Target IP address or URL to scan")
    parser.add_argument("-p", "--ports", type=str, help="Port range (e.g., 80,443 or 1-65535)")
    parser.add_argument("-b", "--batch-size", type=int, default=5000, help="Number of ports to scan simultaneously")
    parser.add_argument("-t", "--timeout", type=float, default=0.1, help="Timeout for port scanning")
    parser.add_argument("-v", "--verbose", action='store_true', help="Show detailed output")
    parser.add_argument("-q", "--quiet", action='store_true', help="Hide progress bar")
    parser.add_argument("-oN", "--output-file", type=str, help="Save results to file")
    parser.add_argument("--show-ip", action='store_true', help="Show resolved IP addresses")

    args = parser.parse_args()

    # Parse ports
    if args.ports:
        port_list = []
        if args.ports == '-' or args.ports == '1-65535':
            port_list = list(range(1, 65536))
        else:
            for part in args.ports.split(','):
                if '-' in part:
                    start, end = map(int, part.split('-'))
                    port_list.extend(range(start, end + 1))
                else:
                    port_list.append(int(part))
    else:
        port_list = list(range(1, 1025))

    scanner = PortScanner(
        target=args.target,
        ports=port_list,
        batch_size=args.batch_size,
        timeout=args.timeout,
        verbose=args.verbose,
        quiet=args.quiet,
        output_file=args.output_file,
        show_ip=args.show_ip
    )

    await scanner.scan_ports()
    scanner.print_results()

if __name__ == "__main__":
    asyncio.run(main())