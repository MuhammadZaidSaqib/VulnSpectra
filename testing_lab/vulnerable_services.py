"""
Vulnerable Services Lab - Intentionally Insecure Services for Testing
WARNING: These services are INTENTIONALLY VULNERABLE. Only run in isolated test environments!
"""

import socket
import threading
import time
import logging
from flask import Flask, request
from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer

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
        """Start vulnerable HTTP web server"""
        try:
            app = Flask(__name__)

            @app.route('/')
            def home():
                return """
                <html>
                <head><title>VulnSpectra Test Server</title></head>
                <body>
                    <h1>🧪 VulnSpectra Testing Lab</h1>
                    <p><strong>Server:</strong> Apache/2.4.49 (Vulnerable)</p>
                    <p>This is an intentionally vulnerable test server.</p>
                    <p><a href="/search?q=test">Try the search feature</a></p>
                    <hr>
                    <small>⚠️ For testing purposes only</small>
                </body>
                </html>
                """

            @app.route('/search')
            def search():
                """Intentionally vulnerable search endpoint (XSS)"""
                query = request.args.get('q', '')
                # Intentional XSS vulnerability for testing
                return f"""
                <html>
                <head><title>Search Results</title></head>
                <body>
                    <h2>Search Results</h2>
                    <p>You searched for: <strong>{query}</strong></p>
                    <p><a href="/">Back</a></p>
                </body>
                </html>
                """

            # Override server version in response headers
            @app.after_request
            def set_server_header(response):
                response.headers['Server'] = 'Apache/2.4.49'
                return response

            logger.info("✓ HTTP Web Server starting on port 8080...")
            app.run(host='0.0.0.0', port=8080, debug=False, use_reloader=False)

        except Exception as e:
            logger.error(f"✗ HTTP Web Server failed: {e}")

    def _start_ftp_service(self):
        """Start vulnerable FTP server with anonymous access"""
        try:
            # Create FTP authorizer with anonymous access
            authorizer = DummyAuthorizer()
            authorizer.add_anonymous(".", perm="elradfmw")  # Full permissions

            # Create FTP handler
            handler = FTPHandler
            handler.authorizer = authorizer
            handler.banner = "VulnSpectra FTP Test Server (pyftpdlib)"

            # Create and start FTP server
            server = FTPServer(("0.0.0.0", 2121), handler)
            logger.info("✓ FTP Server starting on port 2121...")
            server.serve_forever()

        except Exception as e:
            logger.error(f"✗ FTP Server failed: {e}")

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

