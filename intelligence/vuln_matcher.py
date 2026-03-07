"""
Vulnerability Matcher - Match detected services with CVEs
"""
import re
import logging
from typing import List, Dict, Tuple

logger = logging.getLogger(__name__)


class VulnerabilityMatcher:
    """
    Match detected services with known vulnerabilities
    """

    # Severity ranking
    SEVERITY_RANK = {
        'CRITICAL': 4,
        'HIGH': 3,
        'MEDIUM': 2,
        'LOW': 1,
        'UNKNOWN': 0
    }

    def __init__(self):
        """Initialize vulnerability matcher"""
        logger.info("VulnerabilityMatcher initialized")

    def match_vulnerabilities(self, services: List[Dict], cves: List[Dict]) -> List[Dict]:
        """
        Match detected services with CVEs

        Args:
            services: List of detected services
            cves: List of CVE data

        Returns:
            List of matched vulnerabilities
        """
        logger.info(f"Matching {len(services)} services against {len(cves)} CVEs")

        matches = []

        for service in services:
            product = service.get('product', '').lower()
            version = service.get('version', '').lower()

            if product == 'unknown' or not product:
                continue

            # Find relevant CVEs
            for cve in cves:
                if self._is_relevant_cve(service, cve):
                    match = {
                        'ip': service.get('ip'),
                        'port': service.get('port'),
                        'service': service.get('service'),
                        'product': service.get('product'),
                        'version': service.get('version'),
                        'cve_id': cve.get('cve_id'),
                        'description': cve.get('description'),
                        'cvss_score': cve.get('cvss_score'),
                        'severity': cve.get('severity'),
                        'published_date': cve.get('published_date'),
                        'references': cve.get('references', [])
                    }
                    matches.append(match)

        # Sort by severity and CVSS score
        matches.sort(key=lambda x: (
            -self.SEVERITY_RANK.get(x.get('severity', 'UNKNOWN'), 0),
            -x.get('cvss_score', 0)
        ))

        logger.info(f"Found {len(matches)} vulnerability matches")

        return matches

    def _is_relevant_cve(self, service: Dict, cve: Dict) -> bool:
        """
        Check if CVE is relevant to the service

        Args:
            service: Service information
            cve: CVE information

        Returns:
            True if CVE is relevant
        """
        product = service.get('product', '').lower()
        version = service.get('version', '').lower()

        cve_description = cve.get('description', '').lower()

        # Check if product name appears in CVE description
        if product not in cve_description:
            return False

        # If version is unknown, assume it might be vulnerable
        if version == 'unknown' or not version:
            return True

        # Try to determine if version is affected
        # This is a simplified check - production systems should use CPE matching
        return True

    def categorize_by_severity(self, vulnerabilities: List[Dict]) -> Dict:
        """
        Categorize vulnerabilities by severity

        Args:
            vulnerabilities: List of vulnerabilities

        Returns:
            Dictionary with categorized vulnerabilities
        """
        categories = {
            'CRITICAL': [],
            'HIGH': [],
            'MEDIUM': [],
            'LOW': [],
            'UNKNOWN': []
        }

        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'UNKNOWN')
            categories[severity].append(vuln)

        summary = {
            'total': len(vulnerabilities),
            'critical_count': len(categories['CRITICAL']),
            'high_count': len(categories['HIGH']),
            'medium_count': len(categories['MEDIUM']),
            'low_count': len(categories['LOW']),
            'unknown_count': len(categories['UNKNOWN']),
            'categories': categories
        }

        logger.info(f"Categorized vulnerabilities - Critical: {summary['critical_count']}, "
                   f"High: {summary['high_count']}, Medium: {summary['medium_count']}, "
                   f"Low: {summary['low_count']}")

        return summary

    def group_by_host(self, vulnerabilities: List[Dict]) -> Dict:
        """
        Group vulnerabilities by host

        Args:
            vulnerabilities: List of vulnerabilities

        Returns:
            Dictionary with vulnerabilities grouped by host
        """
        hosts = {}

        for vuln in vulnerabilities:
            ip = vuln.get('ip')
            if ip not in hosts:
                hosts[ip] = []
            hosts[ip].append(vuln)

        return hosts

    def calculate_risk_metrics(self, vulnerabilities: List[Dict]) -> Dict:
        """
        Calculate risk metrics from vulnerabilities

        Args:
            vulnerabilities: List of vulnerabilities

        Returns:
            Dictionary with risk metrics
        """
        if not vulnerabilities:
            return {
                'total_vulnerabilities': 0,
                'average_cvss': 0.0,
                'max_cvss': 0.0,
                'risk_score': 0.0
            }

        cvss_scores = [v.get('cvss_score', 0) for v in vulnerabilities]

        # Calculate risk score based on severity distribution and CVSS
        severity_weights = {
            'CRITICAL': 10,
            'HIGH': 7,
            'MEDIUM': 4,
            'LOW': 1,
            'UNKNOWN': 0
        }

        weighted_score = sum(
            severity_weights.get(v.get('severity', 'UNKNOWN'), 0)
            for v in vulnerabilities
        )

        categorized = self.categorize_by_severity(vulnerabilities)

        # Risk score (0-100)
        risk_score = min(100, weighted_score / max(1, len(vulnerabilities)) * 10)

        return {
            'total_vulnerabilities': len(vulnerabilities),
            'average_cvss': sum(cvss_scores) / len(cvss_scores),
            'max_cvss': max(cvss_scores),
            'risk_score': round(risk_score, 2),
            'severity_distribution': {
                'critical': categorized['critical_count'],
                'high': categorized['high_count'],
                'medium': categorized['medium_count'],
                'low': categorized['low_count']
            }
        }

    def filter_by_cvss(self, vulnerabilities: List[Dict], min_score: float) -> List[Dict]:
        """
        Filter vulnerabilities by minimum CVSS score

        Args:
            vulnerabilities: List of vulnerabilities
            min_score: Minimum CVSS score

        Returns:
            Filtered list of vulnerabilities
        """
        filtered = [v for v in vulnerabilities if v.get('cvss_score', 0) >= min_score]
        logger.info(f"Filtered {len(filtered)} vulnerabilities with CVSS >= {min_score}")
        return filtered

    def get_top_vulnerabilities(self, vulnerabilities: List[Dict], limit: int = 10) -> List[Dict]:
        """
        Get top N most critical vulnerabilities

        Args:
            vulnerabilities: List of vulnerabilities
            limit: Number of vulnerabilities to return

        Returns:
            List of top vulnerabilities
        """
        # Already sorted by severity and CVSS in match_vulnerabilities
        return vulnerabilities[:limit]

