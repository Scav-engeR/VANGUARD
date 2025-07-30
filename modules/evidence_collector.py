#!/usr/bin/env python3
"""
Evidence collector module for gathering proof of vulnerabilities.
"""

import logging
import requests
import os
import datetime
import json
import base64
from pathlib import Path
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

logger = logging.getLogger("deep_analytics.evidence")

class EvidenceCollector:
    """Collects evidence of security vulnerabilities."""

    def __init__(self, output_dir="./evidence", capture_screenshots=False, save_http=True):
        """
        Initialize the evidence collector.

        Args:
            output_dir: Directory to save evidence files
            capture_screenshots: Whether to capture screenshots of vulnerable pages
            save_http: Whether to save HTTP request/response data
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True, parents=True)
        self.capture_screenshots = capture_screenshots
        self.save_http = save_http

        # Initialize screenshot capability if requested
        if self.capture_screenshots:
            try:
                # Only import if needed
                from selenium import webdriver
                from selenium.webdriver.chrome.options import Options

                # Set up headless browser
                chrome_options = Options()
                chrome_options.add_argument("--headless")
                chrome_options.add_argument("--no-sandbox")
                chrome_options.add_argument("--disable-dev-shm-usage")
                chrome_options.add_argument("--disable-gpu")

                self.browser = webdriver.Chrome(options=chrome_options)
                logger.info("Screenshot capability initialized")
            except ImportError:
                logger.warning("Selenium not installed. Screenshots will not be captured.")
                self.capture_screenshots = False
            except Exception as e:
                logger.warning(f"Error initializing browser for screenshots: {str(e)}")
                self.capture_screenshots = False

    def collect_evidence(self, url, vulnerabilities):
        """
        Collect evidence for vulnerabilities.

        Args:
            url: Target URL
            vulnerabilities: List of vulnerability dictionaries

        Returns:
            List of evidence dictionaries
        """
        evidence = []

        # Create a directory for this target
        target_dir = self._create_target_dir(url)

        # For each vulnerability, collect specific evidence
        for vuln in vulnerabilities:
            vuln_type = vuln['type']

            # Generate evidence based on vulnerability type
            if 'SQL Injection' in vuln_type:
                evidence.append(self._collect_sqli_evidence(url, vuln, target_dir))
            elif 'Cross-Site Scripting' in vuln_type:
                evidence.append(self._collect_xss_evidence(url, vuln, target_dir))
            elif 'Remote Code Execution' in vuln_type:
                evidence.append(self._collect_rce_evidence(url, vuln, target_dir))
            elif 'Local File Inclusion' in vuln_type:
                evidence.append(self._collect_lfi_evidence(url, vuln, target_dir))
            else:
                # Generic evidence collection
                evidence.append(self._collect_generic_evidence(url, vuln, target_dir))

        return evidence

    def _create_target_dir(self, url):
        """Create a directory for the target's evidence."""
        # Sanitize URL for filesystem
        parsed_url = urlparse(url)
        hostname = parsed_url.netloc.replace(':', '_')
        path = parsed_url.path.replace('/', '_')
        if not path:
            path = '_root_'

        # Create target directory
        target_dir = self.output_dir / f"{hostname}{path}"
        target_dir.mkdir(exist_ok=True, parents=True)

        return target_dir

    def _collect_sqli_evidence(self, url, vulnerability, target_dir):
        """Collect evidence for SQL Injection vulnerability."""
        # Extract PoC from vulnerability
        poc_lines = vulnerability['proof_of_concept'].strip().split('\n')
        payload = None
        for line in poc_lines:
            if 'payload =' in line:
                payload = line.split('=', 1)[1].strip().strip('"\'')
                break

        if not payload:
            payload = "id=1' OR '1'='1"

        # Craft test URL with payload
        test_url = self._create_test_url(url, payload)

        # Collect HTTP evidence
        http_evidence = self._capture_http_interaction(test_url)

        # Capture screenshot if enabled
        screenshot_path = None
        if self.capture_screenshots:
            screenshot_path = self._capture_screenshot(test_url, target_dir, 'sqli')

        # Save evidence to file
        evidence_file = target_dir / "sqli_evidence.json"
        evidence_data = {
            'timestamp': datetime.datetime.now().isoformat(),
            'vulnerability_type': 'SQL Injection',
            'target_url': url,
            'test_url': test_url,
            'payload': payload,
            'http_request': http_evidence['request'],
            'http_response': http_evidence['response'],
            'screenshot_path': str(screenshot_path) if screenshot_path else None,
            'notes': "Evidence of SQL injection vulnerability. Look for database error messages or unexpected data in the response."
        }

        with open(evidence_file, 'w') as f:
            json.dump(evidence_data, f, indent=2)

        return evidence_data

    def _collect_xss_evidence(self, url, vulnerability, target_dir):
        """Collect evidence for XSS vulnerability."""
        # Implementation similar to _collect_sqli_evidence
        poc_lines = vulnerability['proof_of_concept'].strip().split('\n')
        payload = None
        for line in poc_lines:
            if 'payload =' in line:
                payload = line.split('=', 1)[1].strip().strip('"\'')
                break

        if not payload:
            payload = "name=<script>alert('XSS')</script>"

        test_url = self._create_test_url(url, payload)
        http_evidence = self._capture_http_interaction(test_url)

        screenshot_path = None
        if self.capture_screenshots:
            screenshot_path = self._capture_screenshot(test_url, target_dir, 'xss')

        evidence_file = target_dir / "xss_evidence.json"
        evidence_data = {
            'timestamp': datetime.datetime.now().isoformat(),
            'vulnerability_type': 'Cross-Site Scripting (XSS)',
            'target_url': url,
            'test_url': test_url,
            'payload': payload,
            'http_request': http_evidence['request'],
            'http_response': http_evidence['response'],
            'screenshot_path': str(screenshot_path) if screenshot_path else None,
            'notes': "Evidence of XSS vulnerability. Look for unescaped script tags or event handlers in the response."
        }

        with open(evidence_file, 'w') as f:
            json.dump(evidence_data, f, indent=2)

        return evidence_data

    def _collect_rce_evidence(self, url, vulnerability, target_dir):
        """Collect evidence for RCE vulnerability."""
        # Implementation similar to _collect_sqli_evidence
        poc_lines = vulnerability['proof_of_concept'].strip().split('\n')
        payload = None
        for line in poc_lines:
            if 'payload =' in line:
                payload = line.split('=', 1)[1].strip().strip('"\'')
                break

        if not payload:
            payload = "cmd=cat+/etc/passwd"

        test_url = self._create_test_url(url, payload)
        http_evidence = self._capture_http_interaction(test_url)

        screenshot_path = None
        if self.capture_screenshots:
            screenshot_path = self._capture_screenshot(test_url, target_dir, 'rce')

        evidence_file = target_dir / "rce_evidence.json"
        evidence_data = {
            'timestamp': datetime.datetime.now().isoformat(),
            'vulnerability_type': 'Remote Code Execution (RCE)',
            'target_url': url,
            'test_url': test_url,
            'payload': payload,
            'http_request': http_evidence['request'],
            'http_response': http_evidence['response'],
            'screenshot_path': str(screenshot_path) if screenshot_path else None,
            'notes': "Evidence of RCE vulnerability. Look for command output or system information in the response."
        }

        with open(evidence_file, 'w') as f:
            json.dump(evidence_data, f, indent=2)

        return evidence_data

    def _collect_lfi_evidence(self, url, vulnerability, target_dir):
        """Collect evidence for LFI vulnerability."""
        # Implementation similar to _collect_sqli_evidence
        poc_lines = vulnerability['proof_of_concept'].strip().split('\n')
        payload = None
        for line in poc_lines:
            if 'payload =' in line:
                payload = line.split('=', 1)[1].strip().strip('"\'')
                break

        if not payload:
            payload = "file=../../../etc/passwd"

        test_url = self._create_test_url(url, payload)
        http_evidence = self._capture_http_interaction(test_url)

        screenshot_path = None
        if self.capture_screenshots:
            screenshot_path = self._capture_screenshot(test_url, target_dir, 'lfi')

        evidence_file = target_dir / "lfi_evidence.json"
        evidence_data = {
            'timestamp': datetime.datetime.now().isoformat(),
            'vulnerability_type': 'Local File Inclusion (LFI)',
            'target_url': url,
            'test_url': test_url,
            'payload': payload,
            'http_request': http_evidence['request'],
            'http_response': http_evidence['response'],
            'screenshot_path': str(screenshot_path) if screenshot_path else None,
            'notes': "Evidence of LFI vulnerability. Look for file contents in the response."
        }

        with open(evidence_file, 'w') as f:
            json.dump(evidence_data, f, indent=2)

        return evidence_data

    def _collect_generic_evidence(self, url, vulnerability, target_dir):
        """Collect generic evidence for any vulnerability type."""
        # Extract information from vulnerability
        vuln_type = vulnerability['type']

        # Use a generic payload
        payload = "param=test"

        # Collect HTTP evidence
        http_evidence = self._capture_http_interaction(url)

        # Capture screenshot if enabled
        screenshot_path = None
        if self.capture_screenshots:
            screenshot_path = self._capture_screenshot(url, target_dir, 'generic')

        # Save evidence to file
        evidence_file = target_dir / "generic_evidence.json"
        evidence_data = {
            'timestamp': datetime.datetime.now().isoformat(),
            'vulnerability_type': vuln_type,
            'target_url': url,
            'http_request': http_evidence['request'],
            'http_response': http_evidence['response'],
            'screenshot_path': str(screenshot_path) if screenshot_path else None,
            'notes': f"Evidence of {vuln_type} vulnerability."
        }

        with open(evidence_file, 'w') as f:
            json.dump(evidence_data, f, indent=2)

        return evidence_data

    def _create_test_url(self, url, payload):
        """
        Create a test URL with the payload.

        Args:
            url: Original URL
            payload: Payload to add

        Returns:
            URL with payload added
        """
        # Parse the URL
        parsed_url = urlparse(url)

        # Extract payload parameter and value
        payload_parts = payload.split('=', 1)
        if len(payload_parts) == 2:
            param_name = payload_parts[0]
            param_value = payload_parts[1]
        else:
            # Default to 'id' parameter if no parameter name in payload
            param_name = 'id'
            param_value = payload

        # Get existing parameters
        params = parse_qs(parsed_url.query)

        # Add or replace parameter
        params[param_name] = [param_value]

        # Create new query string
        query = urlencode(params, doseq=True)

        # Construct and return the test URL
        return urlunparse((
            parsed_url.scheme, parsed_url.netloc, parsed_url.path,
            parsed_url.params, query, parsed_url.fragment
        ))

    def _capture_http_interaction(self, url):
        """
        Capture HTTP request and response for a URL.

        Args:
            url: URL to request

        Returns:
            Dictionary with request and response details
        """
        if not self.save_http:
            return {
                'request': 'HTTP capture disabled',
                'response': 'HTTP capture disabled'
            }

        try:
            # Parse URL for request details
            parsed_url = urlparse(url)

            # Prepare the request (but don't send it yet)
            session = requests.Session()
            request = requests.Request('GET', url)
            prepared_request = request.prepare()

            # Capture request details
            request_details = f"GET {parsed_url.path}?{parsed_url.query} HTTP/1.1\n"
            request_details += f"Host: {parsed_url.netloc}\n"
            request_details += "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/91.0.4472.124 Safari/537.36\n"
            request_details += "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\n"
            request_details += "Accept-Language: en-US,en;q=0.5\n"
            request_details += "Connection: keep-alive\n"

            # Send the request and capture response
            response = session.send(prepared_request, timeout=10)

            # Capture response details
            response_details = f"HTTP/1.1 {response.status_code} {response.reason}\n"
            for key, value in response.headers.items():
                response_details += f"{key}: {value}\n"
            response_details += "\n"

            # Add response body (limit to 5000 characters to avoid excessive size)
            max_body_length = 5000
            response_body = response.text[:max_body_length]
            if len(response.text) > max_body_length:
                response_body += f"\n... (truncated, total length: {len(response.text)} characters)"
            response_details += response_body

            return {
                'request': request_details,
                'response': response_details
            }

        except Exception as e:
            logger.error(f"Error capturing HTTP interaction for {url}: {str(e)}")
            return {
                'request': f"Error: {str(e)}",
                'response': f"Error: {str(e)}"
            }

    def _capture_screenshot(self, url, target_dir, prefix):
        """
        Capture a screenshot of a URL using Selenium.

        Args:
            url: URL to capture
            target_dir: Directory to save the screenshot
            prefix: Prefix for the screenshot filename

        Returns:
            Path to the saved screenshot, or None if failed
        """
        if not self.capture_screenshots:
            return None

        try:
            # Generate filename
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"{prefix}_{timestamp}.png"
            filepath = target_dir / filename

            # Navigate to URL and capture screenshot
            self.browser.get(url)
            self.browser.save_screenshot(str(filepath))

            logger.info(f"Screenshot saved: {filepath}")
            return filepath

        except Exception as e:
            logger.error(f"Error capturing screenshot for {url}: {str(e)}")
            return None

    def close(self):
        """Close any open resources."""
        if self.capture_screenshots and hasattr(self, 'browser'):
            try:
                self.browser.quit()
            except Exception:
                pass