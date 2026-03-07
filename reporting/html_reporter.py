"""
HTML Reporter - Generate HTML security reports
"""
import logging
from typing import Dict
from datetime import datetime
import os

logger = logging.getLogger(__name__)


class HTMLReporter:
    """
    Generate HTML format security reports
    """

    def __init__(self, output_dir: str = 'reports'):
        """
        Initialize HTML reporter

        Args:
            output_dir: Directory to save reports
        """
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)
        logger.info(f"HTMLReporter initialized with output_dir={output_dir}")

    def generate_report(self, scan_data: Dict, filename: str = None) -> str:
        """
        Generate HTML report

        Args:
            scan_data: Complete scan data
            filename: Output filename (auto-generated if None)

        Returns:
            Path to generated report
        """
        if filename is None:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f'vulnspectra_report_{timestamp}.html'

        filepath = os.path.join(self.output_dir, filename)

        # Generate HTML content
        html_content = self._generate_html(scan_data)

        # Write to file
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(html_content)

            logger.info(f"HTML report generated: {filepath}")
            return filepath

        except Exception as e:
            logger.error(f"Error generating HTML report: {str(e)}")
            raise

    def _generate_html(self, scan_data: Dict) -> str:
        """
        Generate HTML content

        Args:
            scan_data: Complete scan data

        Returns:
            HTML string
        """
        summary = scan_data.get('summary', {})
        vulnerabilities = scan_data.get('vulnerabilities', [])
        services = scan_data.get('services', [])
        risk_analysis = scan_data.get('risk_analysis', {})

        # Categorize vulnerabilities
        critical_vulns = [v for v in vulnerabilities if v.get('severity') == 'CRITICAL']
        high_vulns = [v for v in vulnerabilities if v.get('severity') == 'HIGH']
        medium_vulns = [v for v in vulnerabilities if v.get('severity') == 'MEDIUM']
        low_vulns = [v for v in vulnerabilities if v.get('severity') == 'LOW']

        html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VulnSpectra Security Report</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            color: #e0e0e0;
            padding: 20px;
        }}
        
        .container {{
            max-width: 1400px;
            margin: 0 auto;
        }}
        
        .header {{
            background: linear-gradient(135deg, #0f3460 0%, #16213e 100%);
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.3);
        }}
        
        .header h1 {{
            color: #00d9ff;
            font-size: 2.5em;
            margin-bottom: 10px;
        }}
        
        .header p {{
            color: #b0b0b0;
            font-size: 1.1em;
        }}
        
        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        
        .summary-card {{
            background: linear-gradient(135deg, #1e3a5f 0%, #2a4a6f 100%);
            padding: 25px;
            border-radius: 10px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.3);
            border-left: 4px solid #00d9ff;
        }}
        
        .summary-card h3 {{
            color: #00d9ff;
            margin-bottom: 10px;
            font-size: 0.9em;
            text-transform: uppercase;
        }}
        
        .summary-card .value {{
            font-size: 2.5em;
            font-weight: bold;
            color: #ffffff;
        }}
        
        .severity-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-bottom: 30px;
        }}
        
        .severity-card {{
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.3);
            text-align: center;
        }}
        
        .severity-critical {{
            background: linear-gradient(135deg, #8b0000 0%, #a00000 100%);
            border-left: 4px solid #ff0000;
        }}
        
        .severity-high {{
            background: linear-gradient(135deg, #d35400 0%, #e67e22 100%);
            border-left: 4px solid #ff6b00;
        }}
        
        .severity-medium {{
            background: linear-gradient(135deg, #d68910 0%, #f39c12 100%);
            border-left: 4px solid #ffaa00;
        }}
        
        .severity-low {{
            background: linear-gradient(135deg, #1e8449 0%, #27ae60 100%);
            border-left: 4px solid #00ff00;
        }}
        
        .section {{
            background: linear-gradient(135deg, #1e3a5f 0%, #2a4a6f 100%);
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
            box-shadow: 0 4px 6px rgba(0, 0, 0, 0.3);
        }}
        
        .section h2 {{
            color: #00d9ff;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 2px solid #00d9ff;
        }}
        
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;
        }}
        
        th {{
            background: #0f3460;
            color: #00d9ff;
            padding: 12px;
            text-align: left;
            font-weight: 600;
        }}
        
        td {{
            padding: 12px;
            border-bottom: 1px solid #3a5a7f;
        }}
        
        tr:hover {{
            background: rgba(0, 217, 255, 0.1);
        }}
        
        .badge {{
            display: inline-block;
            padding: 5px 12px;
            border-radius: 15px;
            font-size: 0.85em;
            font-weight: bold;
        }}
        
        .badge-critical {{
            background: #ff0000;
            color: white;
        }}
        
        .badge-high {{
            background: #ff6b00;
            color: white;
        }}
        
        .badge-medium {{
            background: #ffaa00;
            color: white;
        }}
        
        .badge-low {{
            background: #00ff00;
            color: black;
        }}
        
        .risk-score {{
            text-align: center;
            margin: 20px 0;
        }}
        
        .risk-score-value {{
            font-size: 4em;
            font-weight: bold;
            color: #ff6b00;
        }}
        
        .footer {{
            text-align: center;
            color: #808080;
            margin-top: 30px;
            padding: 20px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ VulnSpectra Security Report</h1>
            <p>Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p>Target: {scan_data.get('target', 'Unknown')}</p>
        </div>
        
        <div class="summary-grid">
            <div class="summary-card">
                <h3>Hosts Scanned</h3>
                <div class="value">{summary.get('total_hosts_scanned', 0)}</div>
            </div>
            <div class="summary-card">
                <h3>Services Detected</h3>
                <div class="value">{summary.get('total_services', 0)}</div>
            </div>
            <div class="summary-card">
                <h3>Vulnerabilities Found</h3>
                <div class="value">{summary.get('total_vulnerabilities', 0)}</div>
            </div>
            <div class="summary-card">
                <h3>Scan Duration</h3>
                <div class="value">{summary.get('scan_duration', 0):.1f}s</div>
            </div>
        </div>
        
        <div class="section">
            <h2>Vulnerability Severity Distribution</h2>
            <div class="severity-grid">
                <div class="severity-card severity-critical">
                    <h3>CRITICAL</h3>
                    <div class="value">{len(critical_vulns)}</div>
                </div>
                <div class="severity-card severity-high">
                    <h3>HIGH</h3>
                    <div class="value">{len(high_vulns)}</div>
                </div>
                <div class="severity-card severity-medium">
                    <h3>MEDIUM</h3>
                    <div class="value">{len(medium_vulns)}</div>
                </div>
                <div class="severity-card severity-low">
                    <h3>LOW</h3>
                    <div class="value">{len(low_vulns)}</div>
                </div>
            </div>
        </div>
        
        <div class="section">
            <h2>Risk Analysis</h2>
            <div class="risk-score">
                <div class="risk-score-value">{risk_analysis.get('risk_score', 0)}/100</div>
                <p>Overall Risk Score</p>
            </div>
        </div>
        
        <div class="section">
            <h2>Detected Services</h2>
            <table>
                <thead>
                    <tr>
                        <th>IP Address</th>
                        <th>Port</th>
                        <th>Service</th>
                        <th>Product</th>
                        <th>Version</th>
                    </tr>
                </thead>
                <tbody>
                    {self._generate_services_rows(services)}
                </tbody>
            </table>
        </div>
        
        <div class="section">
            <h2>Vulnerabilities</h2>
            <table>
                <thead>
                    <tr>
                        <th>CVE ID</th>
                        <th>IP:Port</th>
                        <th>Service</th>
                        <th>Severity</th>
                        <th>CVSS</th>
                        <th>Description</th>
                    </tr>
                </thead>
                <tbody>
                    {self._generate_vulnerabilities_rows(vulnerabilities)}
                </tbody>
            </table>
        </div>
        
        <div class="footer">
            <p>Generated by VulnSpectra v1.0.0 - Intelligent Network Vulnerability & CVE Analysis Platform</p>
        </div>
    </div>
</body>
</html>
"""
        return html

    def _generate_services_rows(self, services: list) -> str:
        """Generate HTML table rows for services"""
        if not services:
            return '<tr><td colspan="5" style="text-align: center;">No services detected</td></tr>'

        rows = []
        for service in services[:50]:  # Limit to 50 for readability
            rows.append(f"""
                <tr>
                    <td>{service.get('ip', 'N/A')}</td>
                    <td>{service.get('port', 'N/A')}</td>
                    <td>{service.get('service', 'N/A')}</td>
                    <td>{service.get('product', 'N/A')}</td>
                    <td>{service.get('version', 'N/A')}</td>
                </tr>
            """)

        return ''.join(rows)

    def _generate_vulnerabilities_rows(self, vulnerabilities: list) -> str:
        """Generate HTML table rows for vulnerabilities"""
        if not vulnerabilities:
            return '<tr><td colspan="6" style="text-align: center;">No vulnerabilities found</td></tr>'

        rows = []
        for vuln in vulnerabilities[:100]:  # Limit to 100 for readability
            severity = vuln.get('severity', 'UNKNOWN')
            badge_class = f"badge-{severity.lower()}"

            # Truncate description
            description = vuln.get('description', 'N/A')
            if len(description) > 100:
                description = description[:100] + '...'

            rows.append(f"""
                <tr>
                    <td><strong>{vuln.get('cve_id', 'N/A')}</strong></td>
                    <td>{vuln.get('ip', 'N/A')}:{vuln.get('port', 'N/A')}</td>
                    <td>{vuln.get('product', 'N/A')} {vuln.get('version', '')}</td>
                    <td><span class="badge {badge_class}">{severity}</span></td>
                    <td>{vuln.get('cvss_score', 0)}</td>
                    <td>{description}</td>
                </tr>
            """)

        return ''.join(rows)

