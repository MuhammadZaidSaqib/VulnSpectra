"""
Vulnerable Services Lab - Intentionally Insecure Services for Testing
WARNING: These services are INTENTIONALLY VULNERABLE. Only run in isolated test environments!
"""

import socket
import threading
import time
import logging

logger = logging.getLogger(__name__)


class VulnerableServicesLab:
    """
    Manages multiple intentionally vulnerable services for testing VulnSpectra
    """

    def __init__(self):
        """Initialize the vulnerable services lab"""
        self.services = []
        self.running = False
        logger.info("VulnerableServicesLab initialized")

    def start_all(self):
        """Start all vulnerable services"""
        logger.info("=" * 70)
        logger.info("🧪 STARTING VULNERABLE SERVICES LAB")
        logger.info("=" * 70)
        logger.warning("⚠️  WARNING: These services are INTENTIONALLY VULNERABLE!")
        logger.warning("⚠️  Only run in isolated test/development environments!")
        logger.info("=" * 70)

        self.running = True

        # Start each service in a separate thread
        services_config = [
            ("HTTP Web Server (Apache/2.4.49)", self._start_http_service, 8080),
            ("FTP Server (Anonymous)", self._start_ftp_service, 2121),
            ("SSH Server (OpenSSH 5.3)", self._start_ssh_service, 2222),
            ("SMTP Server (Vulnerable)", self._start_smtp_service, 2525),
            ("Redis Server (3.2.1)", self._start_redis_service, 6379)
        ]

        for name, func, port in services_config:
            thread = threading.Thread(target=func, daemon=True, name=name)
            thread.start()
            self.services.append((name, thread, port))
            time.sleep(0.2)  # Small delay to avoid port binding issues

        # Wait a moment for all services to start
        time.sleep(1)

        # Ensure expected ports are reachable; recover missing FTP if needed.
        self._verify_and_recover_services()

        # Display running services
        logger.info("\n✓ All services started successfully!\n")
        logger.info("Services running on 127.0.0.1:")
        logger.info("-" * 70)
        for name, _, port in self.services:
            logger.info(f"  • Port {port:5d} - {name}")
        logger.info("-" * 70)
        logger.info("\n📊 Scan these services with:")
        logger.info("   python main.py --target 127.0.0.1 --ports 8080,2121,2222,2525,6379\n")
        logger.info("Press Ctrl+C to stop all services\n")

    def _start_http_service(self):
        """Start lightweight vulnerable HTTP server (no external deps)."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("0.0.0.0", 8080))
            sock.listen(20)
            sock.settimeout(1.0)
            logger.info("✓ HTTP Web Server starting on port 8080...")

            body = (
                "<html><head><title>VulnSpectra Test Server</title></head>"
                "<body><h1>VulnSpectra Testing Lab</h1>"
                "<p><strong>Server:</strong> Apache/2.4.49 (Vulnerable)</p>"
                "<p>Intentionally insecure test endpoint.</p></body></html>"
            )
            response = (
                "HTTP/1.1 200 OK\r\n"
                "Server: Apache/2.4.49\r\n"
                "Content-Type: text/html; charset=utf-8\r\n"
                f"Content-Length: {len(body.encode('utf-8'))}\r\n"
                "Connection: close\r\n\r\n"
                f"{body}"
            ).encode("utf-8")

            while self.running:
                try:
                    conn, _ = sock.accept()
                    conn.settimeout(1.0)
                    try:
                        _ = conn.recv(2048)
                        conn.sendall(response)
                    except Exception:
                        pass
                    finally:
                        conn.close()
                except socket.timeout:
                    continue

            sock.close()
        except Exception as e:
            logger.error(f"✗ HTTP Web Server failed: {e}")

    def _start_ftp_service(self):
        """Start lightweight vulnerable FTP server with anonymous login banner."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("0.0.0.0", 2121))
            sock.listen(20)
            sock.settimeout(1.0)
            logger.info("✓ FTP Server starting on port 2121...")

            while self.running:
                try:
                    conn, _ = sock.accept()
                    conn.settimeout(1.0)
                    try:
                        conn.sendall(b"220 VulnSpectra FTP Test Server (pyftpdlib)\r\n")
                        data = conn.recv(1024).upper()
                        if b"USER" in data:
                            conn.sendall(b"331 Anonymous login ok, send password.\r\n")
                            data2 = conn.recv(1024).upper()
                            if b"PASS" in data2:
                                conn.sendall(b"230 Login successful.\r\n")
                        conn.sendall(b"221 Goodbye.\r\n")
                    except Exception:
                        pass
                    finally:
                        conn.close()
                except socket.timeout:
                    continue

            sock.close()
        except Exception as e:
            logger.error(f"✗ FTP Server failed: {e}")

    def _start_ftp_fallback_service(self):
        """Fallback FTP banner service to guarantee port 2121 availability."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("0.0.0.0", 2121))
            sock.listen(20)
            sock.settimeout(1.0)
            logger.info("✓ FTP fallback service started on port 2121")

            while self.running:
                try:
                    conn, _ = sock.accept()
                    conn.settimeout(1.0)
                    try:
                        conn.sendall(b"220 Anonymous FTP ready\r\n")
                    except Exception:
                        pass
                    finally:
                        conn.close()
                except socket.timeout:
                    continue

            sock.close()
        except Exception as e:
            logger.error(f"✗ FTP fallback service failed: {e}")

    def _start_ssh_service(self):
        """Start fake SSH service with vulnerable banner"""
        try:
            # Create socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("0.0.0.0", 2222))
            sock.listen(5)

            logger.info("✓ SSH Server starting on port 2222...")

            while self.running:
                try:
                    # Accept connection
                    conn, addr = sock.accept()

                    # Send vulnerable SSH banner
                    banner = b"SSH-2.0-OpenSSH_5.3\r\n"
                    conn.send(banner)

                    # Send some fake SSH protocol data
                    time.sleep(0.1)
                    fake_data = b"\x00\x00\x00\x0c\x08\x0a\x00\x00\x00\x00\x00\x00\x00\x00\x00"
                    conn.send(fake_data)

                    # Close connection after a short delay
                    time.sleep(0.2)
                    conn.close()

                except socket.timeout:
                    continue
                except Exception as e:
                    if self.running:
                        logger.debug(f"SSH connection error: {e}")

        except Exception as e:
            logger.error(f"✗ SSH Server failed: {e}")

    def _start_smtp_service(self):
        """Start fake SMTP service"""
        try:
            # Create socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("0.0.0.0", 2525))
            sock.listen(5)

            logger.info("✓ SMTP Server starting on port 2525...")

            while self.running:
                try:
                    # Accept connection
                    conn, addr = sock.accept()

                    # Send SMTP banner
                    banner = b"220 vulnerable-smtp.test ESMTP Vulnerable SMTP Server\r\n"
                    conn.send(banner)

                    # Handle basic SMTP commands
                    try:
                        data = conn.recv(1024)
                        if b"EHLO" in data or b"HELO" in data:
                            conn.send(b"250 vulnerable-smtp.test\r\n")
                    except:
                        pass

                    # Close connection
                    time.sleep(0.2)
                    conn.close()

                except socket.timeout:
                    continue
                except Exception as e:
                    if self.running:
                        logger.debug(f"SMTP connection error: {e}")

        except Exception as e:
            logger.error(f"✗ SMTP Server failed: {e}")

    def _start_redis_service(self):
        """Start fake Redis service"""
        try:
            # Create socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(("0.0.0.0", 6379))
            sock.listen(5)

            logger.info("✓ Redis Server starting on port 6379...")

            while self.running:
                try:
                    # Accept connection
                    conn, addr = sock.accept()

                    # Handle Redis PING command
                    try:
                        data = conn.recv(1024)
                        if b"PING" in data:
                            conn.send(b"+PONG\r\n")
                        elif b"INFO" in data:
                            # Send Redis INFO response with version
                            info_response = (
                                b"$1234\r\n"
                                b"# Server\r\n"
                                b"redis_version:3.2.1\r\n"
                                b"redis_mode:standalone\r\n"
                                b"os:Linux 4.4.0 x86_64\r\n"
                                b"# Clients\r\n"
                                b"connected_clients:1\r\n"
                            )
                            conn.send(info_response)
                        else:
                            # Generic response
                            conn.send(b"+OK\r\n")
                    except:
                        pass

                    # Close connection
                    time.sleep(0.2)
                    conn.close()

                except socket.timeout:
                    continue
                except Exception as e:
                    if self.running:
                        logger.debug(f"Redis connection error: {e}")

        except Exception as e:
            logger.error(f"✗ Redis Server failed: {e}")

    def _verify_and_recover_services(self):
        """Verify required ports and start fallback handlers when needed."""
        required_ports = [8080, 2121, 2222, 2525, 6379]
        missing = [p for p in required_ports if not self._is_port_open(p)]

        if 2121 in missing:
            logger.warning("Port 2121 was not reachable; starting FTP fallback handler")
            fallback = threading.Thread(
                target=self._start_ftp_fallback_service,
                daemon=True,
                name="FTP Fallback Server",
            )
            fallback.start()
            self.services.append(("FTP Fallback Server", fallback, 2121))
            time.sleep(0.5)
            missing = [p for p in required_ports if not self._is_port_open(p)]

        if missing:
            logger.warning("Some lab ports are still not reachable: %s", ", ".join(map(str, missing)))
        else:
            logger.info("✓ Verified all expected vulnerable ports are reachable")

    def _is_port_open(self, port: int) -> bool:
        """Check if a TCP port is accepting local connections."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.6)
        try:
            return sock.connect_ex(("127.0.0.1", port)) == 0
        finally:
            sock.close()

    def stop_all(self):
        """Stop all services"""
        logger.info("\n🛑 Stopping all vulnerable services...")
        self.running = False

        # Give threads time to clean up
        time.sleep(1)

        logger.info("✓ All services stopped")

    def wait(self):
        """Keep the lab running until interrupted"""
        try:
            while self.running:
                time.sleep(1)
        except KeyboardInterrupt:
            logger.info("\n\nReceived interrupt signal...")
            self.stop_all()


def main():
    """Standalone execution of the vulnerable services lab"""
    import sys
    import colorlog

    # Setup colored logging
    handler = colorlog.StreamHandler()
    handler.setFormatter(colorlog.ColoredFormatter(
        '%(log_color)s%(levelname)-8s%(reset)s %(message)s',
        log_colors={
            'DEBUG': 'cyan',
            'INFO': 'green',
            'WARNING': 'yellow',
            'ERROR': 'red',
            'CRITICAL': 'red,bg_white',
        }
    ))

    logger = logging.getLogger()
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)

    # Start the lab
    lab = VulnerableServicesLab()

    try:
        lab.start_all()
        lab.wait()
    except KeyboardInterrupt:
        logger.info("\n\nShutting down...")
        lab.stop_all()
        sys.exit(0)


if __name__ == "__main__":
    main()

