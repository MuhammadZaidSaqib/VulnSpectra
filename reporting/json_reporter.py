"""
JSON Reporter - Generate JSON format reports
"""
import json
import logging
from typing import Dict
from datetime import datetime
import os

logger = logging.getLogger(__name__)


class JSONReporter:
    """
    Generate JSON format security reports
    """

    def __init__(self, output_dir: str = 'reports'):
        """
        Initialize JSON reporter

        Args:
            output_dir: Directory to save reports
        """
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
        logger.info(f"JSONReporter initialized with output_dir={output_dir}")

    def generate_report(self, scan_data: Dict, filename: str = None) -> str:
        """
        Generate JSON report

        Args:
            scan_data: Complete scan data
            filename: Output filename (auto-generated if None)

        Returns:
            Path to generated report
        """
        if filename is None:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f'vulnspectra_report_{timestamp}.json'

        filepath = os.path.join(self.output_dir, filename)

        # Prepare report structure
        report = {
            'metadata': {
                'scan_timestamp': datetime.now().isoformat(),
                'scan_target': scan_data.get('target', 'Unknown'),
                'scanner_version': '1.0.0',
                'report_type': 'vulnerability_scan'
            },
            'summary': scan_data.get('summary', {}),
            'hosts': scan_data.get('hosts', []),
            'services': scan_data.get('services', []),
            'vulnerabilities': scan_data.get('vulnerabilities', []),
            'risk_analysis': scan_data.get('risk_analysis', {})
        }

        # Write to file
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2, ensure_ascii=False)

            logger.info(f"JSON report generated: {filepath}")
            return filepath

        except Exception as e:
            logger.error(f"Error generating JSON report: {str(e)}")
            raise

    def generate_summary(self, scan_data: Dict) -> Dict:
        """
        Generate summary statistics

        Args:
            scan_data: Complete scan data

        Returns:
            Summary dictionary
        """
        hosts = scan_data.get('hosts', [])
        services = scan_data.get('services', [])
        vulnerabilities = scan_data.get('vulnerabilities', [])

        alive_hosts = [h for h in hosts if h.get('status') == 'up']

        # Count severity levels
        severity_counts = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'unknown': 0
        }

        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'UNKNOWN').lower()
            if severity in severity_counts:
                severity_counts[severity] += 1
            else:
                severity_counts['unknown'] += 1

        summary = {
            'total_hosts_scanned': len(hosts),
            'alive_hosts': len(alive_hosts),
            'total_services': len(services),
            'total_vulnerabilities': len(vulnerabilities),
            'severity_breakdown': severity_counts,
            'scan_duration': scan_data.get('scan_duration', 0)
        }

        return summary

