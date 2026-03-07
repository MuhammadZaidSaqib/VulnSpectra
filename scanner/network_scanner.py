"""
Network Scanner - Handles network discovery and host detection
"""
import socket
import ipaddress
import logging
from typing import List, Dict
from concurrent.futures import ThreadPoolExecutor, as_completed
import time

logger = logging.getLogger(__name__)


class NetworkScanner:
    """
    Network scanner for host discovery and reachability checks
    """

    def __init__(self, timeout: int = 2, max_workers: int = 50):
        """
        Initialize network scanner

        Args:
            timeout: Connection timeout in seconds
            max_workers: Maximum concurrent threads
        """
        self.timeout = timeout
        self.max_workers = max_workers
        logger.info(f"NetworkScanner initialized with timeout={timeout}s, workers={max_workers}")

    def resolve_target(self, target: str) -> str:
        """
        Resolve domain name/URL to IP address, or validate IP

        Args:
            target: IP address, domain name, or URL

        Returns:
            IP address as string
        """
        # Remove protocol if present
        target = target.replace('http://', '').replace('https://', '').strip()

        # Remove path if present
        target = target.split('/')[0]

        # Remove port if present
        target = target.split(':')[0]

        # Check if already an IP address or CIDR
        try:
            # Try to parse as IP or CIDR
            if '/' in target:
                # CIDR notation - validate and return
                ipaddress.ip_network(target, strict=False)
                return target
            else:
                # Try to parse as IP
                ipaddress.ip_address(target)
                return target
        except ValueError:
            # Not an IP, try to resolve as domain name
            try:
                logger.info(f"Resolving domain name: {target}")
                ip = socket.gethostbyname(target)
                logger.info(f"Resolved {target} to {ip}")
                return ip
            except socket.gaierror as e:
                logger.error(f"Failed to resolve domain {target}: {str(e)}")
                raise ValueError(f"Cannot resolve domain name: {target}")

    def scan_host(self, ip: str) -> Dict:
        """
        Check if a single host is alive

        Args:
            ip: Target IP address

        Returns:
            Dictionary with host status
        """
        try:
            # Try to resolve hostname
            try:
                hostname = socket.gethostbyaddr(ip)[0]
            except (socket.herror, socket.gaierror):
                hostname = "Unknown"

            # Check if host is reachable (try common ports)
            is_alive = self._check_host_alive(ip)

            if is_alive:
                logger.info(f"Host {ip} is alive (hostname: {hostname})")
                return {
                    'ip': ip,
                    'hostname': hostname,
                    'status': 'up',
                    'timestamp': time.time()
                }
            else:
                return {
                    'ip': ip,
                    'hostname': hostname,
                    'status': 'down',
                    'timestamp': time.time()
                }

        except Exception as e:
            logger.error(f"Error scanning host {ip}: {str(e)}")
            return {
                'ip': ip,
                'hostname': 'Unknown',
                'status': 'error',
                'error': str(e),
                'timestamp': time.time()
            }

    def _check_host_alive(self, ip: str) -> bool:
        """
        Check if host is alive by attempting connections to common ports

        Args:
            ip: Target IP address

        Returns:
            True if host responds, False otherwise
        """
        # Common ports to check
        common_ports = [80, 443, 22, 21, 25, 3389, 8080]

        for port in common_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                result = sock.connect_ex((ip, port))
                sock.close()

                # If any port is reachable, host is alive
                if result == 0:
                    return True
            except:
                continue

        return False

    def scan_range(self, ip_range: str) -> List[Dict]:
        """
        Scan a range of IP addresses or single domain/IP

        Args:
            ip_range: IP range in CIDR notation, single IP, or domain name

        Returns:
            List of dictionaries with host information
        """
        logger.info(f"Starting network scan for target: {ip_range}")

        try:
            # Resolve target (handles IPs, domains, and CIDR)
            resolved_target = self.resolve_target(ip_range)

            # Parse IP range
            network = ipaddress.ip_network(resolved_target, strict=False)
            hosts = list(network.hosts())

            # If single IP
            if network.num_addresses == 1:
                hosts = [network.network_address]

            logger.info(f"Scanning {len(hosts)} hosts...")

            results = []

            # Parallel scanning
            with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                future_to_ip = {executor.submit(self.scan_host, str(ip)): ip for ip in hosts}

                for future in as_completed(future_to_ip):
                    try:
                        result = future.result()
                        results.append(result)
                    except Exception as e:
                        logger.error(f"Error in scan task: {str(e)}")

            # Filter only alive hosts
            alive_hosts = [host for host in results if host['status'] == 'up']
            logger.info(f"Scan complete. Found {len(alive_hosts)} alive hosts out of {len(hosts)}")

            return results

        except ValueError as e:
            logger.error(f"Invalid IP range: {ip_range}")
            raise ValueError(f"Invalid IP range format: {ip_range}")
        except Exception as e:
            logger.error(f"Error during network scan: {str(e)}")
            raise

    def scan_single(self, target: str) -> Dict:
        """
        Scan a single host

        Args:
            target: IP address or hostname

        Returns:
            Dictionary with host information
        """
        logger.info(f"Scanning single target: {target}")

        try:
            # Resolve hostname to IP if needed
            ip = socket.gethostbyname(target)
            return self.scan_host(ip)
        except socket.gaierror:
            logger.error(f"Could not resolve hostname: {target}")
            return {
                'target': target,
                'status': 'error',
                'error': 'Could not resolve hostname',
                'timestamp': time.time()
            }

