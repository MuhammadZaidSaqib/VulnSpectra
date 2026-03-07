"""
Console Reporter - Display reports in the console
"""
import logging
from typing import Dict
from tabulate import tabulate
from colorama import init, Fore, Style

# Initialize colorama for Windows support
init(autoreset=True)

logger = logging.getLogger(__name__)


class ConsoleReporter:
    """
    Display reports in the console with colors
    """

    def __init__(self):
        """Initialize console reporter"""
        logger.info("ConsoleReporter initialized")

    def print_report(self, scan_data: Dict):
        """
        Print comprehensive report to console

        Args:
            scan_data: Complete scan data
        """
        print("\n" + "=" * 80)
        print(f"{Fore.CYAN}{Style.BRIGHT}{'VulnSpectra Security Report':^80}{Style.RESET_ALL}")
        print("=" * 80 + "\n")

        # Print summary
        self.print_summary(scan_data.get('summary', {}))

        # Print services
        self.print_services(scan_data.get('services', []))

        # Print vulnerabilities
        self.print_vulnerabilities(scan_data.get('vulnerabilities', []))

        # Print risk analysis
        self.print_risk_analysis(scan_data.get('risk_analysis', {}))

        print("\n" + "=" * 80 + "\n")

    def print_summary(self, summary: Dict):
        """
        Print summary section

        Args:
            summary: Summary data
        """
        print(f"\n{Fore.YELLOW}{Style.BRIGHT}📊 SCAN SUMMARY{Style.RESET_ALL}")
        print("-" * 80)

        summary_data = [
            ["Total Hosts Scanned", summary.get('total_hosts_scanned', 0)],
            ["Alive Hosts", summary.get('alive_hosts', 0)],
            ["Total Services", summary.get('total_services', 0)],
            ["Total Vulnerabilities", summary.get('total_vulnerabilities', 0)],
            ["Scan Duration", f"{summary.get('scan_duration', 0):.2f}s"]
        ]

        print(tabulate(summary_data, tablefmt="grid"))

        # Severity breakdown
        severity = summary.get('severity_breakdown', {})
        if severity:
            print(f"\n{Fore.YELLOW}Severity Breakdown:{Style.RESET_ALL}")
            severity_data = [
                [f"{Fore.RED}CRITICAL{Style.RESET_ALL}", severity.get('critical', 0)],
                [f"{Fore.LIGHTRED_EX}HIGH{Style.RESET_ALL}", severity.get('high', 0)],
                [f"{Fore.LIGHTYELLOW_EX}MEDIUM{Style.RESET_ALL}", severity.get('medium', 0)],
                [f"{Fore.GREEN}LOW{Style.RESET_ALL}", severity.get('low', 0)]
            ]
            print(tabulate(severity_data, headers=["Severity", "Count"], tablefmt="grid"))

    def print_services(self, services: list):
        """
        Print detected services

        Args:
            services: List of detected services
        """
        if not services:
            return

        print(f"\n{Fore.CYAN}{Style.BRIGHT}🔍 DETECTED SERVICES{Style.RESET_ALL}")
        print("-" * 80)

        # Limit to first 20 services for console display
        display_services = services[:20]

        service_data = []
        for service in display_services:
            service_data.append([
                service.get('ip', 'N/A'),
                service.get('port', 'N/A'),
                service.get('service', 'N/A'),
                service.get('product', 'N/A'),
                service.get('version', 'N/A')
            ])

        headers = ["IP Address", "Port", "Service", "Product", "Version"]
        print(tabulate(service_data, headers=headers, tablefmt="grid"))

        if len(services) > 20:
            print(f"\n{Fore.YELLOW}... and {len(services) - 20} more services{Style.RESET_ALL}")

    def print_vulnerabilities(self, vulnerabilities: list):
        """
        Print vulnerabilities

        Args:
            vulnerabilities: List of vulnerabilities
        """
        if not vulnerabilities:
            print(f"\n{Fore.GREEN}{Style.BRIGHT}✅ No vulnerabilities found!{Style.RESET_ALL}")
            return

        print(f"\n{Fore.RED}{Style.BRIGHT}⚠️  VULNERABILITIES FOUND{Style.RESET_ALL}")
        print("-" * 80)

        # Group by severity
        critical = [v for v in vulnerabilities if v.get('severity') == 'CRITICAL']
        high = [v for v in vulnerabilities if v.get('severity') == 'HIGH']
        medium = [v for v in vulnerabilities if v.get('severity') == 'MEDIUM']
        low = [v for v in vulnerabilities if v.get('severity') == 'LOW']

        # Display critical vulnerabilities
        if critical:
            print(f"\n{Fore.RED}{Style.BRIGHT}🔴 CRITICAL VULNERABILITIES ({len(critical)}){Style.RESET_ALL}")
            self._print_vuln_table(critical[:10])

        # Display high vulnerabilities
        if high:
            print(f"\n{Fore.LIGHTRED_EX}{Style.BRIGHT}🟠 HIGH VULNERABILITIES ({len(high)}){Style.RESET_ALL}")
            self._print_vuln_table(high[:10])

        # Display medium vulnerabilities
        if medium:
            print(f"\n{Fore.LIGHTYELLOW_EX}{Style.BRIGHT}🟡 MEDIUM VULNERABILITIES ({len(medium)}){Style.RESET_ALL}")
            self._print_vuln_table(medium[:5])

        # Display low vulnerabilities count only
        if low:
            print(f"\n{Fore.GREEN}🟢 LOW VULNERABILITIES: {len(low)}{Style.RESET_ALL}")

    def _print_vuln_table(self, vulnerabilities: list):
        """
        Print vulnerability table

        Args:
            vulnerabilities: List of vulnerabilities to display
        """
        vuln_data = []
        for vuln in vulnerabilities:
            description = vuln.get('description', 'N/A')
            if len(description) > 60:
                description = description[:60] + '...'

            vuln_data.append([
                vuln.get('cve_id', 'N/A'),
                f"{vuln.get('ip', 'N/A')}:{vuln.get('port', 'N/A')}",
                f"{vuln.get('product', 'N/A')} {vuln.get('version', '')}",
                vuln.get('cvss_score', 'N/A'),
                description
            ])

        headers = ["CVE ID", "Target", "Service", "CVSS", "Description"]
        print(tabulate(vuln_data, headers=headers, tablefmt="grid"))

    def print_risk_analysis(self, risk_analysis: Dict):
        """
        Print risk analysis

        Args:
            risk_analysis: Risk analysis data
        """
        if not risk_analysis:
            return

        print(f"\n{Fore.MAGENTA}{Style.BRIGHT}📈 RISK ANALYSIS{Style.RESET_ALL}")
        print("-" * 80)

        risk_score = risk_analysis.get('risk_score', 0)

        # Color code based on risk score
        if risk_score >= 80:
            color = Fore.RED
            risk_level = "CRITICAL"
        elif risk_score >= 60:
            color = Fore.LIGHTRED_EX
            risk_level = "HIGH"
        elif risk_score >= 40:
            color = Fore.LIGHTYELLOW_EX
            risk_level = "MEDIUM"
        else:
            color = Fore.GREEN
            risk_level = "LOW"

        print(f"\n{color}{Style.BRIGHT}Overall Risk Score: {risk_score}/100 ({risk_level}){Style.RESET_ALL}\n")

        risk_data = [
            ["Total Vulnerabilities", risk_analysis.get('total_vulnerabilities', 0)],
            ["Average CVSS Score", f"{risk_analysis.get('average_cvss', 0):.2f}"],
            ["Maximum CVSS Score", f"{risk_analysis.get('max_cvss', 0):.2f}"]
        ]

        print(tabulate(risk_data, tablefmt="grid"))

    def print_banner(self):
        """Print VulnSpectra banner"""
        banner = f"""
{Fore.CYAN}{Style.BRIGHT}
=============================================================================
    VulnSpectra - Network Vulnerability & CVE Analysis Platform
=============================================================================
{Style.RESET_ALL}
{Fore.YELLOW}Intelligent Network Vulnerability & CVE Analysis Platform{Style.RESET_ALL}
{Fore.GREEN}Version 1.0.0{Style.RESET_ALL}
"""
        print(banner)

