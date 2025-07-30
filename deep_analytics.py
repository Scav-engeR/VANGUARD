#!/usr/bin/env python3
"""
deep_analytics.py - Automated Vulnerability Analysis Tool for Bug Bounty Submissions

This tool analyzes security scan results to generate detailed vulnerability reports
for bug bounty submissions, with evidence collection and remediation recommendations.
"""

import argparse
import json
import os
import sys
import datetime
import logging
from pathlib import Path

# Internal modules
from modules.data_parser import ScanDataParser
from modules.vulnerability_analyzer import VulnerabilityAnalyzer
from modules.evidence_collector import EvidenceCollector
from modules.report_generator import ReportGenerator
from modules.cve_matcher import CVEMatcher

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("deep_analytics.log"),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger("deep_analytics")

class DeepAnalytics:
    """Main class for the vulnerability analysis tool."""

    def __init__(self, args):
        """Initialize the analysis tool with command line arguments."""
        self.args = args
        self.output_dir = Path(args.output_dir)
        self.output_dir.mkdir(exist_ok=True, parents=True)

        # Initialize components
        self.parser = ScanDataParser()
        self.cve_matcher = CVEMatcher(args.cve_database)
        self.evidence_collector = EvidenceCollector(
            output_dir=self.output_dir / "evidence",
            capture_screenshots=args.capture_screenshots,
            save_http=args.save_http
        )
        self.analyzer = VulnerabilityAnalyzer(
            self.cve_matcher,
            self.evidence_collector,
            verify_vulnerabilities=not args.no_verification
        )
        self.report_generator = ReportGenerator(
            output_format=args.format,
            template_dir=args.template_dir,
            output_dir=self.output_dir
        )

    def run(self):
        """Run the full analysis process."""
        logger.info(f"Starting analysis of {self.args.scan_file}")

        # Parse the scan data
        try:
            scan_data = self.parser.parse_file(self.args.scan_file)
            logger.info(f"Successfully parsed {len(scan_data)} scan entries")
        except Exception as e:
            logger.error(f"Failed to parse scan file: {str(e)}")
            return 1

        # Analyze vulnerabilities
        findings = self.analyzer.analyze(scan_data)
        logger.info(f"Found {len(findings)} potential vulnerabilities")

        # Generate and save the report
        if findings:
            report_path = self.report_generator.generate(
                findings,
                title=self.args.title or "Vulnerability Analysis Report",
                author=self.args.author or "Security Researcher"
            )
            logger.info(f"Report generated: {report_path}")

            # Generate executive summary if requested
            if self.args.executive_summary:
                summary_path = self.report_generator.generate_executive_summary(findings)
                logger.info(f"Executive summary generated: {summary_path}")

            # Generate individual vulnerability reports if requested
            if self.args.individual_reports:
                for i, finding in enumerate(findings, 1):
                    vuln_report_path = self.report_generator.generate_single_vulnerability_report(
                        finding,
                        f"vulnerability_{i}"
                    )
                    logger.info(f"Individual vulnerability report generated: {vuln_report_path}")
        else:
            logger.info("No vulnerabilities found to report")

        return 0

def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="Deep Analytics - Automated Vulnerability Analysis for Bug Bounty Submissions",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )

    # Required arguments
    parser.add_argument("scan_file", help="Path to scan results file (TXT, CSV, JSON)")

    # Output options
    parser.add_argument("--format", choices=["html", "markdown", "json", "pdf"],
                        default="html", help="Output format for the report")
    parser.add_argument("--output-dir", default="./output",
                        help="Directory to save all output files")
    parser.add_argument("--title", help="Report title")
    parser.add_argument("--author", help="Report author name")

    # Report generation options
    parser.add_argument("--template-dir", default="./templates",
                        help="Directory containing report templates")
    parser.add_argument("--executive-summary", action="store_true",
                        help="Generate an executive summary")
    parser.add_argument("--individual-reports", action="store_true",
                        help="Generate individual reports for each vulnerability")

    # Evidence collection options
    parser.add_argument("--capture-screenshots", action="store_true",
                        help="Capture screenshots of vulnerable pages")
    parser.add_argument("--save-http", action="store_true",
                        help="Save HTTP request/response data")

    # CVE database options
    parser.add_argument("--cve-database", default="./data/cve_database.json",
                        help="Path to CVE database file or URL")

    # Analysis options
    parser.add_argument("--no-verification", action="store_true",
                        help="Skip vulnerability verification (faster but less accurate)")

    return parser.parse_args()

def main():
    """Main entry point for the script."""
    args = parse_arguments()
    analyzer = DeepAnalytics(args)
    return analyzer.run()

if __name__ == "__main__":
    sys.exit(main())