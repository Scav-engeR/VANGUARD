#!/usr/bin/env python3
"""
VANGUARD - Vulnerability Analytics Framework
Advanced Automated Vulnerability Analysis Tool for Security Research

This tool provides comprehensive security analysis including:
- Network scanning and service discovery
- Vulnerability analysis and classification
- Payload generation and testing
- Evidence collection and reporting
- CVE matching and correlation
"""

import argparse
import json
import os
import sys
import datetime
import logging
import time
from pathlib import Path

# Visual enhancements
try:
    from colorama import init, Fore, Back, Style
    from tqdm import tqdm
    from tabulate import tabulate
    init(autoreset=True)
    COLORS_AVAILABLE = True
except ImportError:
    COLORS_AVAILABLE = False
    print("Install colorama, tqdm, and tabulate for enhanced visuals: pip install colorama tqdm tabulate")

# Internal modules
try:
    from modules.data_parser import ScanDataParser
    from modules.vulnerability_analyzer import VulnerabilityAnalyzer
    from modules.evidence_collector import EvidenceCollector
    from modules.report_generator import ReportGenerator
    from modules.cve_matcher import CVEMatcher
    from modules.network_scanner import NetworkScanner
    from modules.payload_generator import PayloadGenerator
except ImportError as e:
    print(f"Error importing modules: {e}")
    print("Make sure all modules are in the 'modules/' directory with __init__.py")
    sys.exit(1)

# Version information
__version__ = "1.0.0"
__author__ = "VANGUARD Security Team"

def print_banner():
    """Display the VANGUARD banner."""
    if COLORS_AVAILABLE:
        banner = f"""
{Fore.MAGENTA}████████████████████████████████████████████████████████████████████████████████████████████████████████{Style.RESET_ALL}
{Fore.MAGENTA}█                                                                                                   ░  █{Style.RESET_ALL}
{Fore.MAGENTA}█  ██╗   ██╗ █████╗ ███╗   ██╗ ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗                     ░░    ░  ░  █{Style.RESET_ALL}
{Fore.MAGENTA}█  ██╗   ██╗ █████╗ ███╗   ██╗ ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗                             ░ █{Style.RESET_ALL}
{Fore.MAGENTA}█  ██║   ██║██╔══██╗████╗  ██║██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗                 ░    ░░ ░░  ░ ░█{Style.RESET_ALL}
{Fore.MAGENTA}█  ██║   ██║███████║██╔██╗ ██║██║  ███╗██║   ██║███████║██████╔╝██║  ██║                      ░        █{Style.RESET_ALL}
{Fore.MAGENTA}█  ╚██╗ ██╔╝██╔══██║██║╚██╗██║██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║                 ░   ░ ░ ░     ░█{Style.RESET_ALL}
{Fore.MAGENTA}█   ╚████╔╝ ██║  ██║██║ ╚████║╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝                      ░       ░ █{Style.RESET_ALL}
{Fore.MAGENTA}█    ╚═══╝  ╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝                           ░ ░ ░ █{Style.RESET_ALL}
{Fore.MAGENTA}█    ╚═══╝  ╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝                        ░ ░░  ░░ █{Style.RESET_ALL}
{Fore.MAGENTA}█                                                                                                  ░░  █{Style.RESET_ALL}
{Fore.CYAN}   ████████████████████████████████████████████████████████████████████████████████████████████████████████{Style.RESET_ALL}
{Fore.YELLOW} █▓▒░ ▀▄   ▄▀ █ █ █   █▄  █ █▀▀ █▀▀█ █▀▀█ █▀▀▄ ░ █   ▀█▀ ▀▀█▀▀ █  █   █▀▀ █▀▀█ █▀▀█ █▀▄▀█ █▀▀ ░▒▓█{Style.RESET_ALL}
{Fore.YELLOW} █▓▒░  █▄█  █ █ █ █   █ █ █ █▀▀ █▄▄▀ █▄▄█ █▀▀▄ ░ █    █    █   █▄▄█   █▀▀ █▄▄▀ █▄▄█ █ ▀ █ █▀▀ ░▒▓█{Style.RESET_ALL}
{Fore.WHITE}  █▓▒░   █   ▀▄▀▄▀ ▀▄▄ ▀  ▀▀ ▀▀▀ ▀ ▀▀ ▀  ▀ ▀▀▀  ░ ▀▄▄ ▄▀▄   ▀    ▄▄▄█   ▀   ▀ ▀▀ ▀  ▀ ▀   ▀ ▀▀▀ ░▒▓█{Style.RESET_ALL}
{Fore.YELLOW} ████████████████████████████████████████████████████████████████████████████████████████████████████████{Style.RESET_ALL}
{Fore.WHITE}════════════════════════════════════════════════
{Fore.CYAN}      Vulnerability Analytics Framework{Style.RESET_ALL}
{Fore.WHITE}════════════════════════════════════════════════
{Fore.YELLOW}Version: {__version__} | Author: {__author__}{Style.RESET_ALL}
{Fore.MAGENTA}🔍 Advanced Security Research & Analysis Tool 🔍{Style.RESET_ALL}
{Fore.GREEN}🛡️  Comprehensive Vulnerability Assessment  🛡️{Style.RESET_ALL}
{Fore.WHITE}════════════════════════════════════════════════{Style.RESET_ALL}
"""
    else:
        banner = """
████████████████████████████████████████████████████████████████████████████████████████████████████████
█                                                                                             ▓▒░   ▓▒░█
█  ██╗   ██╗ █████╗ ███╗   ██╗ ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗                    ░       ▓▒░ █
█▓ ██║   ██║██╔══██╗████╗  ██║██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗                 ▒░▒░▒░ ▓▒░▒░  █
█▓▒██║   ██║███████║██╔██╗ ██║██║  ███╗██║   ██║███████║██████╔╝██║  ██║              ▒░  ▒░     ░ ░ ░ █
█▓▒██║   ██║███████║██╔██╗ ██║██║  ███╗██║   ██║███████║██████╔╝██║  ██║                 ▒░   ▒░▒░▒░▒▒ █
█▓ ╚██╗ ██╔╝██╔══██║██║╚██╗██║██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║              ▒  ░ ▒▒░▒░▒░░  ▒ █           
█▓▒ ╚████╔╝ ██║  ██║██║ ╚████║╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝                 ▒░▒░▒▒░▒▒░▒░▒░█
█▓▒  ╚═══╝  ╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝                ░ ░ ░  ░    ▒░ ██
█░░▓▒░                                                                                            ▒░  ██ 
████████████████████████████████████████████████████████████████████████████████████████████████████████
█▓▒░ ▀▄   ▄▀ █ █ █   █▄  █ █▀▀ █▀▀█ █▀▀█ █▀▀▄ ░ █   ▀█▀ ▀▀█▀▀ █  █   █▀▀ █▀▀█ █▀▀█ █▀▄▀█ █▀▀ ░▒▓█
█▓▒░  █▄█  █ █ █ █   █ █ █ █▀▀ █▄▄▀ █▄▄█ █▀▀▄ ░ █    █    █   █▄▄█   █▀▀ █▄▄▀ █▄▄█ █ ▀ █ █▀▀ ░▒▓█
█▓▒░   █   ▀▄▀▄▀ ▀▄▄ ▀  ▀▀ ▀▀▀ ▀ ▀▀ ▀  ▀ ▀▀▀  ░ ▀▄▄ ▄▀▄   ▀    ▄▄▄█   ▀   ▀ ▀▀ ▀  ▀ ▀   ▀ ▀▀▀ ░▒▓█
████████████████████████████████████████████████████████████████████████████████████████████████████████
════════════════════════════════════════════════
      Vulnerability Analytics Framework
════════════════════════════════════════════════
Version: 1.0.0 | Author: VANGUARD Security Team
🔍 Advanced Security Research & Analysis Tool 🔍
🛡️  Comprehensive Vulnerability Assessment  🛡️
════════════════════════════════════════════════

"""
    print(banner)

def print_status(message, status="INFO"):
    """Print colored status messages."""
    if not COLORS_AVAILABLE:
        print(f"[{status}] {message}")
        return
        
    colors = {
        "INFO": Fore.BLUE,
        "SUCCESS": Fore.GREEN,
        "WARNING": Fore.YELLOW,
        "ERROR": Fore.RED,
        "CRITICAL": Fore.MAGENTA,
        "SCANNING": Fore.CYAN,
        "ANALYZING": Fore.YELLOW,
        "REPORTING": Fore.GREEN
    }
    
    color = colors.get(status, Fore.WHITE)
    timestamp = datetime.datetime.now().strftime("%H:%M:%S")
    icons = {
        "INFO": "ℹ️",
        "SUCCESS": "✅",
        "WARNING": "⚠️",
        "ERROR": "❌",
        "CRITICAL": "🚨",
        "SCANNING": "🔍",
        "ANALYZING": "🔬",
        "REPORTING": "📊"
    }
    icon = icons.get(status, "•")
    print(f"{Fore.WHITE}[{timestamp}] {color}{icon} [{status}]{Style.RESET_ALL} {message}")

# Set up logging with enhanced formatting
class ColoredFormatter(logging.Formatter):
    """Custom colored log formatter."""
    
    def __init__(self):
        super().__init__()
        self.colors = {
            'DEBUG': Fore.CYAN,
            'INFO': Fore.BLUE,
            'WARNING': Fore.YELLOW,
            'ERROR': Fore.RED,
            'CRITICAL': Fore.MAGENTA
        } if COLORS_AVAILABLE else {}
    
    def format(self, record):
        if COLORS_AVAILABLE and record.levelname in self.colors:
            record.levelname = f"{self.colors[record.levelname]}{record.levelname}{Style.RESET_ALL}"
        return super().format(record)

def setup_logging(log_level=logging.INFO):
    """Set up logging configuration."""
    log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    
    # Create logs directory
    Path("logs").mkdir(exist_ok=True)
    
    # File handler with rotation
    from logging.handlers import RotatingFileHandler
    file_handler = RotatingFileHandler(
        "logs/vanguard.log", maxBytes=10*1024*1024, backupCount=5
    )
    file_handler.setFormatter(logging.Formatter(log_format))
    
    # Console handler with colors
    console_handler = logging.StreamHandler(sys.stdout)
    if COLORS_AVAILABLE:
        console_handler.setFormatter(ColoredFormatter())
    else:
        console_handler.setFormatter(logging.Formatter(log_format))
    
    # Root logger configuration
    logging.basicConfig(
        level=log_level,
        handlers=[file_handler, console_handler],
        format=log_format
    )

logger = logging.getLogger("vanguard")

class VANGUARD:
    """Main class for the VANGUARD vulnerability analysis framework."""

    def __init__(self, args):
        """Initialize the VANGUARD framework with command line arguments."""
        self.args = args
        self.output_dir = Path(args.output_dir)
        self.output_dir.mkdir(exist_ok=True, parents=True)
        
        print_status("Initializing VANGUARD framework...", "INFO")
        
        # Initialize progress tracking
        self.progress_bar = None
        self.stats = {
            'targets_scanned': 0,
            'vulnerabilities_found': 0,
            'reports_generated': 0,
            'payloads_generated': 0
        }
        
        # Initialize core components
        self._initialize_components()
        
        print_status("VANGUARD framework initialized successfully!", "SUCCESS")

    def _initialize_components(self):
        """Initialize all framework components."""
        components = [
            ("Data Parser", lambda: ScanDataParser()),
            ("CVE Matcher", lambda: CVEMatcher(self.args.cve_database)),
            ("Evidence Collector", lambda: EvidenceCollector(
                output_dir=self.output_dir / "evidence",
                capture_screenshots=self.args.capture_screenshots,
                save_http=self.args.save_http
            )),
            ("Network Scanner", lambda: NetworkScanner(
                timeout=self.args.scan_timeout,
                max_workers=self.args.max_workers,
                rate_limit=self.args.rate_limit
            )),
            ("Payload Generator", lambda: PayloadGenerator()),
            ("Vulnerability Analyzer", lambda: VulnerabilityAnalyzer(
                self.cve_matcher,
                self.evidence_collector,
                verify_vulnerabilities=not self.args.no_verification
            )),
            ("Report Generator", lambda: ReportGenerator(
                output_format=self.args.format,
                template_dir=self.args.template_dir,
                output_dir=self.output_dir
            ))
        ]
        
        if COLORS_AVAILABLE:
            pbar = tqdm(
                components, 
                desc=f"{Fore.CYAN}🔧 Loading components{Style.RESET_ALL}", 
                bar_format="{desc}: {percentage:3.0f}%|{bar:30}| {n_fmt}/{total_fmt} [{elapsed}]",
                colour="cyan"
            )
        else:
            pbar = components
            
        for name, initializer in pbar:
            try:
                if name == "Data Parser":
                    self.parser = initializer()
                elif name == "CVE Matcher":
                    self.cve_matcher = initializer()
                elif name == "Evidence Collector":
                    self.evidence_collector = initializer()
                elif name == "Network Scanner":
                    self.network_scanner = initializer()
                elif name == "Payload Generator":
                    self.payload_generator = initializer()
                elif name == "Vulnerability Analyzer":
                    self.analyzer = initializer()
                elif name == "Report Generator":
                    self.report_generator = initializer()
                    
                if not COLORS_AVAILABLE:
                    print_status(f"{name} initialized", "SUCCESS")
                    
            except Exception as e:
                print_status(f"Failed to initialize {name}: {str(e)}", "ERROR")
                raise

    def run(self):
        """Run the complete VANGUARD analysis process."""
        start_time = time.time()
        print_status(f"Starting VANGUARD analysis of {self.args.scan_file}", "SCANNING")
        
        try:
            # Step 1: Parse scan data
            scan_data = self._parse_scan_data()
            if not scan_data:
                return 1
            
            # Step 2: Enhanced network scanning (if enabled)
            if self.args.network_scan:
                scan_data = self._enhance_with_network_scan(scan_data)
            
            # Step 3: Generate payloads (if enabled)
            if self.args.generate_payloads:
                self._generate_test_payloads()
            
            # Step 4: Analyze vulnerabilities
            findings = self._analyze_vulnerabilities(scan_data)
            
            # Step 5: Generate reports
            if findings:
                self._generate_reports(findings)
                self._display_summary(findings)
            else:
                print_status("No vulnerabilities found to report", "WARNING")
            
            # Execution summary
            execution_time = time.time() - start_time
            self._display_execution_summary(execution_time)
            
            return 0
            
        except KeyboardInterrupt:
            print_status("Analysis interrupted by user", "WARNING")
            return 1
        except Exception as e:
            print_status(f"Analysis failed: {str(e)}", "ERROR")
            logger.exception("Detailed error information:")
            return 1

    def _parse_scan_data(self):
        """Parse the input scan data file."""
        print_status("Parsing scan data...", "ANALYZING")
        
        try:
            scan_data = self.parser.parse_file(self.args.scan_file)
            self.stats['targets_scanned'] = len(scan_data)
            print_status(f"Successfully parsed {len(scan_data)} scan entries", "SUCCESS")
            return scan_data
        except Exception as e:
            print_status(f"Failed to parse scan file: {str(e)}", "ERROR")
            return None

    def _enhance_with_network_scan(self, scan_data):
        """Enhance scan data with additional network scanning."""
        print_status("Performing enhanced network scanning...", "SCANNING")
        
        enhanced_data = []
        targets = [entry.get('URL', entry.get('target', '')) for entry in scan_data]
        
        if COLORS_AVAILABLE:
            pbar = tqdm(
                targets, 
                desc=f"{Fore.CYAN}🌐 Network scanning{Style.RESET_ALL}", 
                bar_format="{desc}: {percentage:3.0f}%|{bar:30}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}]",
                colour="cyan"
            )
        else:
            pbar = targets
            
        for target in pbar:
            if target:
                try:
                    network_info = self.network_scanner.scan_target(target)
                    if network_info:
                        # Merge network scan results with existing data
                        for entry in scan_data:
                            if entry.get('URL') == target or entry.get('target') == target:
                                entry.update({
                                    'network_info': network_info,
                                    'open_ports': network_info.get('open_ports', []),
                                    'services': network_info.get('services', {}),
                                    'web_servers': network_info.get('web_servers', [])
                                })
                                enhanced_data.append(entry)
                                break
                except Exception as e:
                    logger.debug(f"Network scan failed for {target}: {str(e)}")
                    
        print_status(f"Enhanced {len(enhanced_data)} targets with network data", "SUCCESS")
        return enhanced_data if enhanced_data else scan_data

    def _generate_test_payloads(self):
        """Generate test payloads for manual testing."""
        print_status("Generating test payloads...", "ANALYZING")
        
        payload_dir = self.output_dir / "payloads"
        payload_dir.mkdir(exist_ok=True)
        
        vuln_types = ['sqli', 'xss', 'rce', 'lfi', 'xxe', 'ssti']
        total_payloads = 0
        
        if COLORS_AVAILABLE:
            pbar = tqdm(
                vuln_types, 
                desc=f"{Fore.YELLOW}⚡ Generating payloads{Style.RESET_ALL}",
                bar_format="{desc}: {percentage:3.0f}%|{bar:30}| {n_fmt}/{total_fmt}",
                colour="yellow"
            )
        else:
            pbar = vuln_types
        
        for vuln_type in pbar:
            payloads = self.payload_generator.generate_payloads(
                vuln_type, count=25, context='web'
            )
            
            payload_file = payload_dir / f"{vuln_type}_payloads.txt"
            with open(payload_file, 'w') as f:
                f.write(f"# {vuln_type.upper()} Test Payloads\n")
                f.write(f"# Generated by VANGUARD v{__version__}\n")
                f.write(f"# Generated on: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                for i, payload in enumerate(payloads, 1):
                    f.write(f"{i:2d}. {payload}\n")
            
            total_payloads += len(payloads)
                    
        self.stats['payloads_generated'] = total_payloads
        print_status(f"Generated {total_payloads} payloads saved to {payload_dir}", "SUCCESS")

    def _analyze_vulnerabilities(self, scan_data):
        """Analyze scan data for vulnerabilities."""
        print_status("Analyzing vulnerabilities...", "ANALYZING")
        
        findings = self.analyzer.analyze(scan_data)
        
        # Count total vulnerabilities
        total_vulns = sum(len(finding.get('vulnerabilities', [])) for finding in findings)
        self.stats['vulnerabilities_found'] = total_vulns
        
        print_status(f"Found {len(findings)} targets with {total_vulns} vulnerabilities", "SUCCESS")
        
        return findings

    def _generate_reports(self, findings):
        """Generate comprehensive reports."""
        print_status("Generating reports...", "REPORTING")
        
        reports_generated = []
        
        # Main report
        report_path = self.report_generator.generate(
            findings,
            title=self.args.title or "VANGUARD Security Analysis Report",
            author=self.args.author or "VANGUARD Security Team"
        )
        if report_path:
            reports_generated.append(("Main Report", report_path))
        
        # Executive summary
        if self.args.executive_summary:
            summary_path = self.report_generator.generate_executive_summary(findings)
            if summary_path:
                reports_generated.append(("Executive Summary", summary_path))
        
        # Individual reports
        if self.args.individual_reports:
            if COLORS_AVAILABLE:
                pbar = tqdm(
                    enumerate(findings, 1), 
                    total=len(findings),
                    desc=f"{Fore.GREEN}📄 Individual reports{Style.RESET_ALL}",
                    bar_format="{desc}: {percentage:3.0f}%|{bar:20}| {n_fmt}/{total_fmt}",
                    colour="green"
                )
            else:
                pbar = enumerate(findings, 1)
                
            for i, finding in pbar:
                vuln_report_path = self.report_generator.generate_single_vulnerability_report(
                    finding, f"vulnerability_{i}"
                )
                if vuln_report_path:
                    reports_generated.append((f"Vulnerability {i}", vuln_report_path))
        
        self.stats['reports_generated'] = len(reports_generated)
        
        # Display report summary
        if reports_generated and COLORS_AVAILABLE:
            print_status("Reports generated successfully!", "SUCCESS")
            headers = [f"{Fore.CYAN}Report Type{Style.RESET_ALL}", f"{Fore.CYAN}File Path{Style.RESET_ALL}"]
            table_data = [[name, str(path)] for name, path in reports_generated]
            print(tabulate(table_data, headers=headers, tablefmt="fancy_grid"))
        elif reports_generated:
            print_status("Reports generated:", "SUCCESS")
            for name, path in reports_generated:
                print(f"  • {name}: {path}")

    def _display_summary(self, findings):
        """Display comprehensive analysis summary."""
        if not findings:
            return
            
        # Count vulnerabilities by severity
        severity_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
        vuln_types = {}
        affected_urls = set()
        
        for finding in findings:
            affected_urls.add(finding.get('url', 'Unknown'))
            for vuln in finding.get('vulnerabilities', []):
                severity = vuln.get('severity', {}).get('rating', 'Medium')
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
                
                vuln_type = vuln.get('type', 'Unknown')
                vuln_types[vuln_type] = vuln_types.get(vuln_type, 0) + 1
        
        if COLORS_AVAILABLE:
            print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
            print(f"{Fore.CYAN}📊 VULNERABILITY ANALYSIS SUMMARY 📊{Style.RESET_ALL}")
            print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
            
            # Main summary table
            summary_data = [
                [f"{Fore.BLUE}Total Targets{Style.RESET_ALL}", len(findings)],
                [f"{Fore.BLUE}Affected URLs{Style.RESET_ALL}", len(affected_urls)],
                [f"{Fore.RED}🚨 Critical{Style.RESET_ALL}", severity_counts['Critical']],
                [f"{Fore.YELLOW}⚠️  High{Style.RESET_ALL}", severity_counts['High']],
                [f"{Fore.GREEN}📊 Medium{Style.RESET_ALL}", severity_counts['Medium']],
                [f"{Fore.CYAN}ℹ️  Low{Style.RESET_ALL}", severity_counts['Low']]
            ]
            
            print(tabulate(summary_data, headers=[f"{Fore.MAGENTA}Metric{Style.RESET_ALL}", f"{Fore.MAGENTA}Count{Style.RESET_ALL}"], tablefmt="fancy_grid"))
            
            # Vulnerability types
            if vuln_types:
                vuln_data = [[f"{Fore.YELLOW}{vtype}{Style.RESET_ALL}", count] for vtype, count in sorted(vuln_types.items(), key=lambda x: x[1], reverse=True)]
                print(f"\n{Fore.CYAN}🔍 VULNERABILITY TYPES BREAKDOWN{Style.RESET_ALL}")
                print(tabulate(vuln_data, headers=[f"{Fore.MAGENTA}Vulnerability Type{Style.RESET_ALL}", f"{Fore.MAGENTA}Count{Style.RESET_ALL}"], tablefmt="fancy_grid"))
                
            # Risk assessment
            total_vulns = sum(severity_counts.values())
            risk_score = (severity_counts['Critical'] * 4 + severity_counts['High'] * 3 + 
                         severity_counts['Medium'] * 2 + severity_counts['Low'] * 1)
            
            if risk_score >= total_vulns * 3:
                risk_level = f"{Fore.RED}🚨 CRITICAL{Style.RESET_ALL}"
            elif risk_score >= total_vulns * 2:
                risk_level = f"{Fore.YELLOW}⚠️  HIGH{Style.RESET_ALL}"
            elif risk_score >= total_vulns * 1:
                risk_level = f"{Fore.GREEN}📊 MEDIUM{Style.RESET_ALL}"
            else:
                risk_level = f"{Fore.CYAN}ℹ️  LOW{Style.RESET_ALL}"
                
            print(f"\n{Fore.CYAN}🎯 OVERALL RISK ASSESSMENT: {risk_level}{Style.RESET_ALL}")
            print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        else:
            print("\n" + "="*60)
            print("📊 VULNERABILITY ANALYSIS SUMMARY")
            print("="*60)
            print(f"Total Targets: {len(findings)}")
            print(f"Affected URLs: {len(affected_urls)}")
            print(f"Critical: {severity_counts['Critical']}")
            print(f"High: {severity_counts['High']}")
            print(f"Medium: {severity_counts['Medium']}")
            print(f"Low: {severity_counts['Low']}")
            
            if vuln_types:
                print("\nVulnerability Types:")
                for vtype, count in sorted(vuln_types.items(), key=lambda x: x[1], reverse=True):
                    print(f"  {vtype}: {count}")

    def _display_execution_summary(self, execution_time):
        """Display execution summary with statistics."""
        if COLORS_AVAILABLE:
            print(f"\n{Fore.GREEN}{'='*60}{Style.RESET_ALL}")
            print(f"{Fore.GREEN}🎉 VANGUARD EXECUTION SUMMARY 🎉{Style.RESET_ALL}")
            print(f"{Fore.GREEN}{'='*60}{Style.RESET_ALL}")
            
            stats_data = [
                [f"{Fore.BLUE}⏱️  Execution Time{Style.RESET_ALL}", f"{execution_time:.2f} seconds"],
                [f"{Fore.BLUE}🎯 Targets Scanned{Style.RESET_ALL}", self.stats['targets_scanned']],
                [f"{Fore.BLUE}🔍 Vulnerabilities Found{Style.RESET_ALL}", self.stats['vulnerabilities_found']],
                [f"{Fore.BLUE}📊 Reports Generated{Style.RESET_ALL}", self.stats['reports_generated']],
                [f"{Fore.BLUE}⚡ Payloads Generated{Style.RESET_ALL}", self.stats['payloads_generated']]
            ]
            
            print(tabulate(stats_data, headers=[f"{Fore.MAGENTA}Statistic{Style.RESET_ALL}", f"{Fore.MAGENTA}Value{Style.RESET_ALL}"], tablefmt="fancy_grid"))
            print(f"{Fore.GREEN}✅ Analysis completed successfully!{Style.RESET_ALL}")
            print(f"{Fore.GREEN}{'='*60}{Style.RESET_ALL}")
        else:
            print("\n" + "="*60)
            print("🎉 VANGUARD EXECUTION SUMMARY")
            print("="*60)
            print(f"Execution Time: {execution_time:.2f} seconds")
            print(f"Targets Scanned: {self.stats['targets_scanned']}")
            print(f"Vulnerabilities Found: {self.stats['vulnerabilities_found']}")
            print(f"Reports Generated: {self.stats['reports_generated']}")
            print(f"Payloads Generated: {self.stats['payloads_generated']}")
            print("✅ Analysis completed successfully!")
            print("="*60)

def parse_arguments():
    """Parse command line arguments with enhanced options."""
    parser = argparse.ArgumentParser(
        description="VANGUARD - Vulnerability Analytics Framework",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        epilog=f"VANGUARD v{__version__} - Advanced Security Research Tool"
    )

    # Required arguments
    parser.add_argument("scan_file", 
                       help="Path to scan results file (TXT, CSV, JSON)")

    # Output options
    parser.add_argument("--format", 
                       choices=["html", "markdown", "json", "pdf"],
                       default="html", 
                       help="Output format for reports")
    parser.add_argument("--output-dir", 
                       default="./output",
                       help="Directory to save all output files")
    parser.add_argument("--title", 
                       help="Custom report title")
    parser.add_argument("--author", 
                       help="Report author name")

    # Report generation options
    parser.add_argument("--template-dir", 
                       default="./templates",
                       help="Directory containing report templates")
    parser.add_argument("--executive-summary", 
                       action="store_true",
                       help="Generate executive summary")
    parser.add_argument("--individual-reports", 
                       action="store_true",
                       help="Generate individual vulnerability reports")

    # Enhanced analysis options
    parser.add_argument("--network-scan", 
                       action="store_true",
                       help="Perform enhanced network scanning")
    parser.add_argument("--generate-payloads", 
                       action="store_true",
                       help="Generate test payloads for manual testing")

    # Network scanning options
    parser.add_argument("--scan-timeout", 
                       type=int, 
                       default=3,
                       help="Network scan timeout in seconds")
    parser.add_argument("--max-workers", 
                       type=int, 
                       default=50,
                       help="Maximum concurrent threads for scanning")
    parser.add_argument("--rate-limit", 
                       type=int, 
                       default=10,
                       help="Requests per second limit")

    # Evidence collection options
    parser.add_argument("--capture-screenshots", 
                       action="store_true",
                       help="Capture screenshots of vulnerable pages")
    parser.add_argument("--save-http", 
                       action="store_true", 
                       default=True,
                       help="Save HTTP request/response data")

    # CVE database options
    parser.add_argument("--cve-database", 
                       default="./data/cve_database.json",
                       help="Path to CVE database file")

    # Analysis options
    parser.add_argument("--no-verification", 
                       action="store_true",
                       help="Skip vulnerability verification")

    # Logging options
    parser.add_argument("--verbose", "-v", 
                       action="store_true",
                       help="Enable verbose logging")
    parser.add_argument("--debug", 
                       action="store_true",
                       help="Enable debug logging")

    return parser.parse_args()

def main():
    """Main entry point for VANGUARD."""
    # Parse arguments
    args = parse_arguments()
    
    # Set up logging level
    log_level = logging.DEBUG if args.debug else (logging.INFO if args.verbose else logging.WARNING)
    setup_logging(log_level)
    
    # Display banner
    print_banner()
    
    # Initialize and run VANGUARD
    try:
        vanguard = VANGUARD(args)
        return vanguard.run()
    except KeyboardInterrupt:
        print_status("VANGUARD interrupted by user", "WARNING")
        return 1
    except Exception as e:
        print_status(f"VANGUARD failed to initialize: {str(e)}", "ERROR")
        return 1
    finally:
        print_status("VANGUARD execution completed", "INFO")

if __name__ == "__main__":
    sys.exit(main())
