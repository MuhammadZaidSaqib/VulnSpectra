"""
Port Scanner - Advanced port scanning with service detection
"""
import socket
import logging
from typing import List, Dict, Tuple
from concurrent.futures import ThreadPoolExecutor, as_completed
import time

logger = logging.getLogger(__name__)


class PortScanner:
    """
    Advanced port scanner with multi-threading support
    """

    # Common ports and their typical services
    COMMON_PORTS = {
        20: 'FTP-DATA',
        21: 'FTP',
        22: 'SSH',
        23: 'Telnet',
        25: 'SMTP',
        53: 'DNS',
        80: 'HTTP',
        110: 'POP3',
        143: 'IMAP',
        443: 'HTTPS',
        445: 'SMB',
        3306: 'MySQL',
        3389: 'RDP',
        5432: 'PostgreSQL',
        5900: 'VNC',
        6379: 'Redis',
        8080: 'HTTP-Proxy',
        8443: 'HTTPS-Alt',
        27017: 'MongoDB',
    }

    def __init__(self, timeout: int = 2, max_workers: int = 100):
        """
        Initialize port scanner

        Args:
            timeout: Connection timeout in seconds
            max_workers: Maximum concurrent threads
        """
        self.timeout = timeout
        self.max_workers = max_workers
        logger.info(f"PortScanner initialized with timeout={timeout}s, workers={max_workers}")

    def scan_port(self, ip: str, port: int) -> Dict:
        """
        Scan a single port on a host

        Args:
            ip: Target IP address
            port: Port number to scan

        Returns:
            Dictionary with port information
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)

            result = sock.connect_ex((ip, port))

            if result == 0:
                # Port is open
                service = self.COMMON_PORTS.get(port, 'Unknown')

                # Try to grab banner
                banner = self._grab_banner(ip, port)

                logger.debug(f"Port {port} is open on {ip} - Service: {service}")

                sock.close()
                return {
                    'port': port,
                    'state': 'open',
                    'service': service,
                    'banner': banner
                }
            else:
                sock.close()
                return {
                    'port': port,
                    'state': 'closed',
                    'service': None,
                    'banner': None
                }

        except socket.timeout:
            return {
                'port': port,
                'state': 'filtered',
                'service': None,
                'banner': None
            }
        except Exception as e:
            logger.error(f"Error scanning port {port} on {ip}: {str(e)}")
            return {
                'port': port,
                'state': 'error',
                'service': None,
                'banner': None,
                'error': str(e)
            }

    def _grab_banner(self, ip: str, port: int) -> str:
        """
        Attempt to grab banner from service

        Args:
            ip: Target IP address
            port: Port number

        Returns:
            Banner string or None
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((ip, port))

            # Send generic probe
            try:
                sock.send(b'HEAD / HTTP/1.0\r\n\r\n')
            except:
                pass

            # Receive banner
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()

            return banner if banner else None

        except:
            return None

    def scan_host(self, ip: str, ports: List[int]) -> Dict:
        """
        Scan multiple ports on a single host

        Args:
            ip: Target IP address
            ports: List of ports to scan

        Returns:
            Dictionary with scan results
        """
        logger.info(f"Scanning {len(ports)} ports on {ip}")

        start_time = time.time()
        open_ports = []

        # Parallel port scanning
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_port = {executor.submit(self.scan_port, ip, port): port for port in ports}

            for future in as_completed(future_to_port):
                try:
                    result = future.result()
                    if result['state'] == 'open':
                        open_ports.append(result)
                except Exception as e:
                    logger.error(f"Error in port scan task: {str(e)}")

        scan_duration = time.time() - start_time

        logger.info(f"Found {len(open_ports)} open ports on {ip} in {scan_duration:.2f}s")

        return {
            'ip': ip,
            'total_ports_scanned': len(ports),
            'open_ports': open_ports,
            'open_count': len(open_ports),
            'scan_duration': scan_duration,
            'timestamp': time.time()
        }

    def parse_port_range(self, port_spec: str) -> List[int]:
        """
        Parse port specification string

        Args:
            port_spec: Port specification (e.g., '1-1000', '80,443,8080', '1-100,443,8000-9000')

        Returns:
            List of port numbers
        """
        ports = set()

        try:
            # Split by comma
            parts = port_spec.split(',')

            for part in parts:
                part = part.strip()

                # Check if range
                if '-' in part:
                    start, end = map(int, part.split('-'))
                    if start > end or start < 1 or end > 65535:
                        raise ValueError(f"Invalid port range: {part}")
                    ports.update(range(start, end + 1))
                else:
                    # Single port
                    port = int(part)
                    if port < 1 or port > 65535:
                        raise ValueError(f"Invalid port number: {port}")
                    ports.add(port)

            return sorted(list(ports))

        except ValueError as e:
            logger.error(f"Error parsing port specification: {port_spec}")
            raise ValueError(f"Invalid port specification: {port_spec}")

    def get_common_ports(self) -> List[int]:
        """
        Get list of commonly used ports

        Returns:
            List of common port numbers
        """
        return sorted(list(self.COMMON_PORTS.keys()))

