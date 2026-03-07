"""
Service Detector - Service fingerprinting and version detection
"""
import re
import socket
import logging
from typing import Dict, Optional, List
import time

logger = logging.getLogger(__name__)


class ServiceDetector:
    """
    Service detection and version fingerprinting
    """

    # Service fingerprinting patterns
    SERVICE_PATTERNS = {
        'http': [
            (r'Apache[\/\s]([\d.]+)', 'Apache'),
            (r'nginx[\/\s]([\d.]+)', 'nginx'),
            (r'Microsoft-IIS[\/\s]([\d.]+)', 'IIS'),
            (r'lighttpd[\/\s]([\d.]+)', 'lighttpd'),
        ],
        'ssh': [
            (r'OpenSSH[_\s]([\d.]+\w*)', 'OpenSSH'),
            (r'SSH-[\d.]+-OpenSSH_([\d.]+\w*)', 'OpenSSH'),
            (r'Cisco-[\d.]', 'Cisco SSH'),
        ],
        'ftp': [
            (r'ProFTPD ([\d.]+)', 'ProFTPD'),
            (r'vsftpd ([\d.]+)', 'vsftpd'),
            (r'FileZilla Server ([\d.]+)', 'FileZilla'),
            (r'Microsoft FTP Service', 'Microsoft FTP'),
        ],
        'smtp': [
            (r'Postfix', 'Postfix'),
            (r'Exim ([\d.]+)', 'Exim'),
            (r'Sendmail ([\d.]+)', 'Sendmail'),
            (r'Microsoft ESMTP', 'Microsoft Exchange'),
        ],
        'mysql': [
            (r'([\d.]+)-MariaDB', 'MariaDB'),
            (r'MySQL ([\d.]+)', 'MySQL'),
        ],
        'postgresql': [
            (r'PostgreSQL ([\d.]+)', 'PostgreSQL'),
        ],
        'redis': [
            (r'Redis.*version=([\d.]+)', 'Redis'),
        ],
    }

    def __init__(self, timeout: int = 3):
        """
        Initialize service detector

        Args:
            timeout: Connection timeout in seconds
        """
        self.timeout = timeout
        logger.info(f"ServiceDetector initialized with timeout={timeout}s")

    def detect_service(self, ip: str, port: int, banner: Optional[str] = None) -> Dict:
        """
        Detect service and version from port and banner

        Args:
            ip: Target IP address
            port: Port number
            banner: Banner string (if already captured)

        Returns:
            Dictionary with service information
        """
        logger.debug(f"Detecting service on {ip}:{port}")

        # If no banner provided, try to grab it
        if banner is None:
            banner = self._grab_enhanced_banner(ip, port)

        # Determine service type based on port and banner
        service_info = {
            'ip': ip,
            'port': port,
            'service': 'Unknown',
            'product': 'Unknown',
            'version': 'Unknown',
            'banner': banner,
            'timestamp': time.time()
        }

        if banner:
            # Try to match against fingerprint patterns
            service_info.update(self._fingerprint_service(port, banner))
        else:
            # Use port-based guessing
            service_info['service'] = self._guess_service_by_port(port)

        logger.info(f"Detected {service_info['service']} {service_info['version']} on {ip}:{port}")

        return service_info

    def _grab_enhanced_banner(self, ip: str, port: int) -> Optional[str]:
        """
        Grab banner with service-specific probes

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

            banner = None

            # Try different probes based on port
            if port in [80, 8080, 8081, 8082, 8443]:
                # HTTP probe
                sock.send(b'HEAD / HTTP/1.1\r\nHost: ' + ip.encode() + b'\r\n\r\n')
                banner = sock.recv(2048).decode('utf-8', errors='ignore')
            elif port == 443:
                # HTTPS - just try to read
                banner = sock.recv(1024).decode('utf-8', errors='ignore')
            elif port in [22, 2222]:
                # SSH - server sends banner first
                banner = sock.recv(1024).decode('utf-8', errors='ignore')
            elif port in [21, 2121]:
                # FTP - server sends banner first
                banner = sock.recv(1024).decode('utf-8', errors='ignore')
            elif port in [25, 2525]:
                # SMTP - server sends banner first
                banner = sock.recv(1024).decode('utf-8', errors='ignore')
            elif port == 6379:
                # Redis - send INFO command
                sock.send(b'INFO\r\n')
                banner = sock.recv(2048).decode('utf-8', errors='ignore')
            else:
                # Generic probe
                try:
                    sock.send(b'\r\n')
                except:
                    pass
                banner = sock.recv(1024).decode('utf-8', errors='ignore')

            sock.close()
            return banner.strip() if banner else None

        except Exception as e:
            logger.debug(f"Could not grab banner from {ip}:{port}: {str(e)}")
            return None

    def _fingerprint_service(self, port: int, banner: str) -> Dict:
        """
        Fingerprint service based on banner

        Args:
            port: Port number
            banner: Banner string

        Returns:
            Dictionary with service, product, and version
        """
        result = {
            'service': 'Unknown',
            'product': 'Unknown',
            'version': 'Unknown'
        }

        # Determine service category
        service_type = self._guess_service_by_port(port)
        result['service'] = service_type

        # Try to match patterns
        if service_type.lower() in self.SERVICE_PATTERNS:
            patterns = self.SERVICE_PATTERNS[service_type.lower()]

            for pattern, product in patterns:
                match = re.search(pattern, banner, re.IGNORECASE)
                if match:
                    result['product'] = product
                    if match.groups():
                        result['version'] = match.group(1)
                    break

        # Additional generic patterns
        if result['product'] == 'Unknown':
            # Try to extract any version number
            version_match = re.search(r'(\d+\.\d+(?:\.\d+)?)', banner)
            if version_match:
                result['version'] = version_match.group(1)

        return result

    def _guess_service_by_port(self, port: int) -> str:
        """
        Guess service type based on port number

        Args:
            port: Port number

        Returns:
            Service name
        """
        port_map = {
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
            8080: 'HTTP',
            8081: 'HTTP',
            8082: 'HTTP',
            8443: 'HTTPS',
            2121: 'FTP',
            2222: 'SSH',
            2525: 'SMTP',
            27017: 'MongoDB',
        }

        return port_map.get(port, 'Unknown')

    def detect_services_bulk(self, scan_results: List[Dict]) -> List[Dict]:
        """
        Detect services for multiple scan results

        Args:
            scan_results: List of scan results with open ports

        Returns:
            List of service detection results
        """
        logger.info(f"Performing service detection on {len(scan_results)} results")

        detected_services = []

        for result in scan_results:
            ip = result.get('ip')
            open_ports = result.get('open_ports', [])

            for port_info in open_ports:
                port = port_info['port']
                banner = port_info.get('banner')

                service_info = self.detect_service(ip, port, banner)
                detected_services.append(service_info)

        logger.info(f"Service detection complete. Detected {len(detected_services)} services")

        return detected_services

