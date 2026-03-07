"""
CVE Fetcher - Query CVE data from NVD API
"""
import requests
import logging
import time
from typing import Dict, List, Optional
import json
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)


class CVEFetcher:
    """
    Fetch CVE data from National Vulnerability Database (NVD) API
    """

    NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def __init__(self, api_key: Optional[str] = None, rate_limit: float = 0.6):
        """
        Initialize CVE fetcher

        Args:
            api_key: NVD API key (optional, but recommended for higher rate limits)
            rate_limit: Minimum seconds between API calls
        """
        self.api_key = api_key
        self.rate_limit = rate_limit
        self.last_request_time = 0
        self.cache = {}
        logger.info("CVEFetcher initialized")

    def _wait_for_rate_limit(self):
        """Wait to respect rate limiting"""
        elapsed = time.time() - self.last_request_time
        if elapsed < self.rate_limit:
            time.sleep(self.rate_limit - elapsed)
        self.last_request_time = time.time()

    def search_cve_by_product(self, product: str, version: Optional[str] = None) -> List[Dict]:
        """
        Search for CVEs related to a product

        Args:
            product: Product name (e.g., 'apache', 'nginx')
            version: Specific version (optional)

        Returns:
            List of CVE dictionaries
        """
        logger.info(f"Searching CVEs for product: {product} {version or ''}")

        # Check cache
        cache_key = f"{product}:{version or 'all'}"
        if cache_key in self.cache:
            logger.debug(f"Returning cached results for {cache_key}")
            return self.cache[cache_key]

        try:
            self._wait_for_rate_limit()

            # Build query parameters
            params = {
                'keywordSearch': product,
                'resultsPerPage': 50
            }

            headers = {}
            if self.api_key:
                headers['apiKey'] = self.api_key

            response = requests.get(
                self.NVD_API_BASE,
                params=params,
                headers=headers,
                timeout=30
            )

            if response.status_code == 200:
                data = response.json()
                cves = self._parse_nvd_response(data)

                # Filter by version if provided
                if version:
                    cves = self._filter_by_version(cves, version)

                # Cache results
                self.cache[cache_key] = cves

                logger.info(f"Found {len(cves)} CVEs for {product}")
                return cves
            else:
                logger.error(f"NVD API error: {response.status_code}")
                return []

        except requests.exceptions.RequestException as e:
            logger.error(f"Network error fetching CVEs: {str(e)}")
            return []
        except Exception as e:
            logger.error(f"Error fetching CVEs: {str(e)}")
            return []

    def get_cve_details(self, cve_id: str) -> Optional[Dict]:
        """
        Get detailed information for a specific CVE

        Args:
            cve_id: CVE identifier (e.g., 'CVE-2023-12345')

        Returns:
            Dictionary with CVE details or None
        """
        logger.info(f"Fetching details for {cve_id}")

        # Check cache
        if cve_id in self.cache:
            return self.cache[cve_id]

        try:
            self._wait_for_rate_limit()

            params = {'cveId': cve_id}
            headers = {}
            if self.api_key:
                headers['apiKey'] = self.api_key

            response = requests.get(
                self.NVD_API_BASE,
                params=params,
                headers=headers,
                timeout=30
            )

            if response.status_code == 200:
                data = response.json()
                cves = self._parse_nvd_response(data)

                if cves:
                    cve = cves[0]
                    self.cache[cve_id] = cve
                    return cve

                return None
            else:
                logger.error(f"NVD API error: {response.status_code}")
                return None

        except Exception as e:
            logger.error(f"Error fetching CVE details: {str(e)}")
            return None

    def _parse_nvd_response(self, data: Dict) -> List[Dict]:
        """
        Parse NVD API response

        Args:
            data: Raw API response

        Returns:
            List of parsed CVE dictionaries
        """
        cves = []

        try:
            vulnerabilities = data.get('vulnerabilities', [])

            for vuln in vulnerabilities:
                cve_data = vuln.get('cve', {})

                # Extract CVE ID
                cve_id = cve_data.get('id', 'Unknown')

                # Extract description
                descriptions = cve_data.get('descriptions', [])
                description = next((d['value'] for d in descriptions if d.get('lang') == 'en'), 'No description')

                # Extract CVSS metrics
                metrics = cve_data.get('metrics', {})
                cvss_data = self._extract_cvss(metrics)

                # Extract published and modified dates
                published = cve_data.get('published', '')
                modified = cve_data.get('lastModified', '')

                # Extract references
                references = [ref.get('url', '') for ref in cve_data.get('references', [])]

                cve_info = {
                    'cve_id': cve_id,
                    'description': description,
                    'cvss_score': cvss_data['score'],
                    'cvss_vector': cvss_data['vector'],
                    'severity': cvss_data['severity'],
                    'published_date': published,
                    'modified_date': modified,
                    'references': references
                }

                cves.append(cve_info)

        except Exception as e:
            logger.error(f"Error parsing NVD response: {str(e)}")

        return cves

    def _extract_cvss(self, metrics: Dict) -> Dict:
        """
        Extract CVSS score information

        Args:
            metrics: Metrics from CVE data

        Returns:
            Dictionary with CVSS information
        """
        # Try CVSS v3.1 first, then v3.0, then v2.0
        for version in ['cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2']:
            if version in metrics and metrics[version]:
                cvss = metrics[version][0].get('cvssData', {})

                return {
                    'score': cvss.get('baseScore', 0.0),
                    'vector': cvss.get('vectorString', ''),
                    'severity': cvss.get('baseSeverity', 'UNKNOWN').upper()
                }

        # Default if no CVSS data
        return {
            'score': 0.0,
            'vector': '',
            'severity': 'UNKNOWN'
        }

    def _filter_by_version(self, cves: List[Dict], version: str) -> List[Dict]:
        """
        Filter CVEs relevant to a specific version

        Args:
            cves: List of CVEs
            version: Version string

        Returns:
            Filtered list of CVEs
        """
        # Basic filtering - check if version appears in description
        # In production, this should use CPE matching
        filtered = []

        for cve in cves:
            description = cve.get('description', '').lower()
            if version.lower() in description or 'all versions' in description:
                filtered.append(cve)

        return filtered if filtered else cves

    def get_recent_cves(self, days: int = 7) -> List[Dict]:
        """
        Get recently published CVEs

        Args:
            days: Number of days to look back

        Returns:
            List of recent CVEs
        """
        logger.info(f"Fetching CVEs from the last {days} days")

        try:
            self._wait_for_rate_limit()

            # Calculate date range
            end_date = datetime.now()
            start_date = end_date - timedelta(days=days)

            params = {
                'pubStartDate': start_date.strftime('%Y-%m-%dT%H:%M:%S.000'),
                'pubEndDate': end_date.strftime('%Y-%m-%dT%H:%M:%S.000'),
                'resultsPerPage': 100
            }

            headers = {}
            if self.api_key:
                headers['apiKey'] = self.api_key

            response = requests.get(
                self.NVD_API_BASE,
                params=params,
                headers=headers,
                timeout=30
            )

            if response.status_code == 200:
                data = response.json()
                cves = self._parse_nvd_response(data)
                logger.info(f"Found {len(cves)} recent CVEs")
                return cves
            else:
                logger.error(f"NVD API error: {response.status_code}")
                return []

        except Exception as e:
            logger.error(f"Error fetching recent CVEs: {str(e)}")
            return []

