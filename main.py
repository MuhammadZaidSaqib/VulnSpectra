"""
VulnSpectra - Intelligent Network Vulnerability & CVE Analysis Platform
Main Entry Point
"""
import argparse
import sys
import logging
from datetime import datetime
import time

from scanner import NetworkScanner, PortScanner, ServiceDetector
from intelligence import CVEFetcher, VulnerabilityMatcher
from reporting import JSONReporter, HTMLReporter, ConsoleReporter
from utils.logger import setup_logger
from utils.validators import validate_target, validate_port_range
from api.app import run_api


def main():
    """Main entry point for VulnSpectra"""
    parser = argparse.ArgumentParser(
        description='VulnSpectra - Intelligent Network Vulnerability & CVE Analysis Platform',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py --target 192.168.1.10
  python main.py --target example.com --ports 80,443
  python main.py --range 192.168.1.0/24
  python main.py --target 192.168.1.10 --ports 1-1000
  python main.py --start-test-lab
  python main.py --dashboard
  python main.py --api
        """
    )

    # Scan options
    parser.add_argument('--target', type=str, help='Target IP address')
    parser.add_argument('--range', type=str, help='Target IP range (CIDR notation)')
    parser.add_argument('--ports', type=str, default='1-1000', help='Port range to scan (default: 1-1000)')
    parser.add_argument('--timeout', type=int, default=2, help='Connection timeout in seconds (default: 2)')

    # Service options
    parser.add_argument('--dashboard', action='store_true', help='Start web dashboard')
    parser.add_argument('--api', action='store_true', help='Start API server')
    parser.add_argument('--start-test-lab', action='store_true', help='Start vulnerable services for testing')

    # Output options
    parser.add_argument('--output', type=str, help='Output directory for reports')
    parser.add_argument('--json', action='store_true', help='Generate JSON report')
    parser.add_argument('--html', action='store_true', help='Generate HTML report')
    parser.add_argument('--no-console', action='store_true', help='Disable console output')

    # Misc options
    parser.add_argument('--verbose', '-v', action='store_true', help='Enable verbose logging')
    parser.add_argument('--api-key', type=str, help='NVD API key for CVE lookups')

    args = parser.parse_args()

    # Setup logging
    log_level = logging.DEBUG if args.verbose else logging.INFO
    setup_logger(log_level=log_level)
    logger = logging.getLogger(__name__)

    # Print banner
    if not args.no_console:
        console_reporter = ConsoleReporter()
        console_reporter.print_banner()

    # Test Lab mode
    if args.start_test_lab:
        logger.info("Starting Vulnerable Services Testing Lab...")
        from testing_lab import VulnerableServicesLab

        lab = VulnerableServicesLab()

        try:
            lab.start_all()
            lab.wait()
        except KeyboardInterrupt:
            logger.info("\n\nShutting down...")
            lab.stop_all()
            sys.exit(0)

        return

    # Dashboard mode
    if args.dashboard:
        logger.info("Starting dashboard mode...")
        import subprocess
        import webbrowser
        import os

        # Start API server in background
        logger.info("Starting API server...")
        api_process = subprocess.Popen(
            [sys.executable, '-m', 'api.app'],
            cwd=os.getcwd()
        )

        # Wait for API to start
        time.sleep(2)

        # Open dashboard in browser
        dashboard_path = os.path.join(os.getcwd(), 'dashboard', 'index.html')
        webbrowser.open(f'file:///{dashboard_path}')

        logger.info("Dashboard opened in browser. Press Ctrl+C to stop.")

        try:
            api_process.wait()
        except KeyboardInterrupt:
            logger.info("Shutting down...")
            api_process.terminate()

        return

    # API mode
    if args.api:
        logger.info("Starting API server...")
        run_api()
        return

    # Validate required arguments
    if not args.target and not args.range:
        parser.error("Either --target or --range must be specified")

    # Validate target
    target = args.target or args.range
    if not validate_target(target):
        logger.error(f"Invalid target: {target}")
        sys.exit(1)

    # Validate port range
    if not validate_port_range(args.ports):
        logger.error(f"Invalid port range: {args.ports}")
        sys.exit(1)

    # Run scan
    try:
        scan_results = run_vulnerability_scan(
            target=target,
            ports=args.ports,
            timeout=args.timeout,
            api_key=args.api_key,
            verbose=args.verbose
        )

        # Generate reports
        output_dir = args.output or 'reports'

        # Console report
        if not args.no_console:
            console_reporter = ConsoleReporter()
            console_reporter.print_report(scan_results)

        # JSON report
        if args.json:
            json_reporter = JSONReporter(output_dir=output_dir)
            json_path = json_reporter.generate_report(scan_results)
            logger.info(f"JSON report saved to: {json_path}")

        # HTML report
        if args.html:
            html_reporter = HTMLReporter(output_dir=output_dir)
            html_path = html_reporter.generate_report(scan_results)
            logger.info(f"HTML report saved to: {html_path}")

        logger.info("Scan completed successfully!")

    except KeyboardInterrupt:
        logger.info("\nScan interrupted by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Scan failed: {str(e)}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


def run_vulnerability_scan(target, ports, timeout, api_key=None, verbose=False):
    """
    Execute complete vulnerability scan

    Args:
        target: Target IP or range
        ports: Port specification
        timeout: Connection timeout
        api_key: NVD API key
        verbose: Verbose output

    Returns:
        Dictionary with complete scan results
    """
    logger = logging.getLogger(__name__)
    start_time = time.time()

    logger.info(f"Starting vulnerability scan for target: {target}")

    # Initialize scanners
    logger.info("Initializing scanners...")
    net_scanner = NetworkScanner(timeout=timeout)
    port_scanner = PortScanner(timeout=timeout)
    service_detector = ServiceDetector(timeout=timeout)
    cve_fetcher = CVEFetcher(api_key=api_key)
    vuln_matcher = VulnerabilityMatcher()

    # Step 1: Network scan
    logger.info("Step 1/5: Network discovery")
    if '/' in target:
        hosts = net_scanner.scan_range(target)
    else:
        hosts = [net_scanner.scan_single(target)]

    alive_hosts = [h for h in hosts if h.get('status') == 'up']
    logger.info(f"Found {len(alive_hosts)} alive hosts")

    if len(alive_hosts) == 0:
        logger.warning("No alive hosts found!")
        return {
            'target': target,
            'summary': {
                'total_hosts_scanned': len(hosts),
                'alive_hosts': 0,
                'total_services': 0,
                'total_vulnerabilities': 0
            },
            'hosts': hosts,
            'services': [],
            'vulnerabilities': [],
            'risk_analysis': {},
            'scan_duration': time.time() - start_time
        }

    # Step 2: Port scan
    logger.info("Step 2/5: Port scanning")
    port_list = port_scanner.parse_port_range(ports)

    all_port_results = []
    for host in alive_hosts:
        ip = host['ip']
        logger.info(f"Scanning ports on {ip}...")
        port_results = port_scanner.scan_host(ip, port_list)
        all_port_results.append(port_results)

    # Step 3: Service detection
    logger.info("Step 3/5: Service detection and fingerprinting")
    all_services = []
    for port_result in all_port_results:
        if port_result['open_ports']:
            services = service_detector.detect_services_bulk([port_result])
            all_services.extend(services)

    logger.info(f"Detected {len(all_services)} services")

    # Step 4: CVE lookup
    logger.info("Step 4/5: Querying CVE database")
    all_cves = []

    # Get unique products
    products = set()
    for service in all_services:
        product = service.get('product', '').lower()
        if product and product != 'unknown':
            products.add(product)

    logger.info(f"Querying CVEs for {len(products)} unique products...")
    for product in products:
        logger.debug(f"Fetching CVEs for {product}")
        cves = cve_fetcher.search_cve_by_product(product)
        all_cves.extend(cves)

    logger.info(f"Found {len(all_cves)} CVEs")

    # Step 5: Vulnerability matching
    logger.info("Step 5/5: Matching vulnerabilities")
    vulnerabilities = vuln_matcher.match_vulnerabilities(all_services, all_cves)

    logger.info(f"Identified {len(vulnerabilities)} vulnerability matches")

    # Calculate risk metrics
    risk_analysis = vuln_matcher.calculate_risk_metrics(vulnerabilities)
    severity_breakdown = vuln_matcher.categorize_by_severity(vulnerabilities)

    # Prepare results
    scan_duration = time.time() - start_time

    results = {
        'target': target,
        'summary': {
            'total_hosts_scanned': len(hosts),
            'alive_hosts': len(alive_hosts),
            'total_services': len(all_services),
            'total_vulnerabilities': len(vulnerabilities),
            'severity_breakdown': severity_breakdown,
            'scan_duration': scan_duration
        },
        'hosts': hosts,
        'services': all_services,
        'vulnerabilities': vulnerabilities,
        'risk_analysis': risk_analysis,
        'scan_duration': scan_duration,
        'timestamp': datetime.now().isoformat()
    }

    logger.info(f"Scan completed in {scan_duration:.2f} seconds")

    return results


if __name__ == '__main__':
    main()

