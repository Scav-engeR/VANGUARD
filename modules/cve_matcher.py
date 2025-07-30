#!/usr/bin/env python3
"""
CVE matcher module for finding related CVEs for detected vulnerabilities.
"""

import logging
import json
import re
import os
import requests
from pathlib import Path
from datetime import datetime, timedelta

logger = logging.getLogger("deep_analytics.cve")

class CVEMatcher:
    """Matches vulnerabilities to known CVEs."""

    def __init__(self, cve_database_path, auto_update=True):
        """
        Initialize the CVE matcher.

        Args:
            cve_database_path: Path to CVE database file or URL
            auto_update: Whether to automatically update the database if older than 7 days
        """
        self.cve_database_path = Path(cve_database_path)
        self.auto_update = auto_update
        self.cve_data = self._load_cve_database()

    def _load_cve_database(self):
        """
        Load the CVE database from file or download if necessary.

        Returns:
            Dictionary containing CVE data
        """
        # Check if database exists and is recent
        if self.cve_database_path.exists():
            # Check file age
            file_age = datetime.now() - datetime.fromtimestamp(self.cve_database_path.stat().st_mtime)
            if file_age > timedelta(days=7) and self.auto_update:
                logger.info(f"CVE database is {file_age.days} days old. Updating...")
                self._update_cve_database()
        else:
            # Database doesn't exist, create it
            logger.info("CVE database not found. Creating...")
            self._update_cve_database()

        # Load the database
        try:
            with open(self.cve_database_path, 'r') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Error loading CVE database: {str(e)}")
            # Return empty database as fallback
            return {'cves': []}

    def _update_cve_database(self):
        """Update the CVE database from official sources."""
        try:
            # Create parent directory if it doesn't exist
            self.cve_database_path.parent.mkdir(exist_ok=True, parents=True)

            # In a real implementation, this would download from NVD or other CVE sources
            # For demonstration, we'll create a simple database with common vulnerabilities
            cve_data = {
                'last_updated': datetime.now().isoformat(),
                'cves': self._generate_sample_cves()
            }

            # Save the database
            with open(self.cve_database_path, 'w') as f:
                json.dump(cve_data, f, indent=2)

            logger.info(f"CVE database updated: {self.cve_database_path}")

        except Exception as e:
            logger.error(f"Error updating CVE database: {str(e)}")

    def _generate_sample_cves(self):
        """
        Generate a sample CVE database for demonstration.

        Returns:
            List of sample CVE entries
        """
        return [
            # SQL Injection CVEs
            {
                'cve_id': 'CVE-2023-12345',
                'type': 'SQLi',
                'description': 'SQL injection vulnerability in example.com allows attackers to bypass authentication',
                'severity': 'High',
                'cvss_score': 8.5,
                'affected_systems': ['MySQL', 'Apache', 'PHP'],
                'references': ['https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-12345']
            },
            {
                'cve_id': 'CVE-2023-67890',
                'type': 'SQLi',
                'description': 'SQL injection in login form allows unauthorized database access',
                'severity': 'Critical',
                'cvss_score': 9.1,
                'affected_systems': ['PostgreSQL', 'Nginx', 'Python'],
                'references': ['https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-67890']
            },

            # XSS CVEs
            {
                'cve_id': 'CVE-2023-24680',
                'type': 'XSS',
                'description': 'Cross-site scripting vulnerability in search function',
                'severity': 'Medium',
                'cvss_score': 6.1,
                'affected_systems': ['JavaScript', 'React'],
                'references': ['https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-24680']
            },

            # RCE CVEs
            {
                'cve_id': 'CVE-2023-13579',
                'type': 'RCE',
                'description': 'Remote code execution vulnerability in file upload functionality',
                'severity': 'Critical',
                'cvss_score': 9.8,
                'affected_systems': ['PHP', 'Apache'],
                'references': ['https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-13579']
            },

            # LFI CVEs
            {
                'cve_id': 'CVE-2023-98765',
                'type': 'LFI',
                'description': 'Local file inclusion vulnerability in include parameter',
                'severity': 'High',
                'cvss_score': 7.5,
                'affected_systems': ['PHP', 'Apache'],
                'references': ['https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-98765']
            }
        ]

    def find_cves(self, vuln_type, url, server_info):
        """
        Find CVEs related to a specific vulnerability.

        Args:
            vuln_type: Type of vulnerability (SQLi, XSS, RCE, LFI)
            url: Target URL
            server_info: Server information string

        Returns:
            List of related CVE entries
        """
        # Map vulnerability types to CVE types
        vuln_type_map = {
            'SQLi': 'SQLi',
            'XSS': 'XSS',
            'RCE': 'RCE',
            'LFI': 'LFI'
        }

        cve_type = vuln_type_map.get(vuln_type, vuln_type)
        matching_cves = []

        # Find relevant CVEs
        for cve in self.cve_data.get('cves', []):
            if cve.get('type') == cve_type:
                # Check if server type matches affected systems
                if server_info:
                    for system in cve.get('affected_systems', []):
                        if system.lower() in server_info.lower():
                            matching_cves.append(cve)
                            break
                else:
                    # If no server info, just match by type
                    matching_cves.append(cve)

        # Limit to top 3 most relevant CVEs
        return matching_cves[:3]