#!/usr/bin/env python3
"""
Report generator module for creating vulnerability assessment reports.
"""

import logging
import json
import os
import datetime
from pathlib import Path
import shutil
from urllib.parse import urlparse
from jinja2 import Environment, FileSystemLoader, select_autoescape

logger = logging.getLogger("deep_analytics.report")

class ReportGenerator:
    """Generates vulnerability assessment reports in various formats."""
    
    def __init__(self, output_format="html", template_dir="./templates", output_dir="./output"):
        """
        Initialize the report generator.
        
        Args:
            output_format: Format of the generated report (html, markdown, json, pdf)
            template_dir: Directory containing report templates
            output_dir: Directory to save the generated reports
        """
        self.output_format = output_format
        self.template_dir = Path(template_dir)
        self.output_dir = Path(output_dir)
        
        # Create output directory if it doesn't exist
        self.output_dir.mkdir(exist_ok=True, parents=True)
        
        # Set up Jinja2 environment
        self._setup_jinja_environment()
        
        # Ensure templates directory exists
        self._ensure_templates()
    
    def _setup_jinja_environment(self):
        """Set up Jinja2 environment for templates."""
        # Create template directory if it doesn't exist
        self.template_dir.mkdir(exist_ok=True, parents=True)
        
        # Set up Jinja2 environment
        self.jinja_env = Environment(
            loader=FileSystemLoader(self.template_dir),
            autoescape=select_autoescape(['html', 'xml']),
            trim_blocks=True,
            lstrip_blocks=True
        )
        
        # Add custom filters
        self.jinja_env.filters['to_json'] = lambda obj: json.dumps(obj, indent=2)
        self.jinja_env.filters['datetime_format'] = lambda dt: dt.strftime('%Y-%m-%d %H:%M:%S')
    
    def _ensure_templates(self):
        """Ensure that template files exist, create if not."""
        # Check for HTML template
        html_template_path = self.template_dir / "report_template.html"
        if not html_template_path.exists():
            self._create_default_html_template(html_template_path)
        
        # Check for Markdown template
        md_template_path = self.template_dir / "report_template.md"
        if not md_template_path.exists():
            self._create_default_md_template(md_template_path)
        
        # Check for executive summary template
        exec_template_path = self.template_dir / "executive_summary_template.html"
        if not exec_template_path.exists():
            self._create_default_exec_summary_template(exec_template_path)
    
    def _create_default_html_template(self, template_path):
        """Create a default HTML report template."""
        template_content = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ title }}</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        h1, h2, h3, h4 {
            color: #2c3e50;
        }
        .header {
            border-bottom: 2px solid #3498db;
            padding-bottom: 10px;
            margin-bottom: 20px;
        }
        .meta-info {
            background-color: #f8f9fa;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
        }
        .finding {
            border: 1px solid #ddd;
            border-radius: 5px;
            padding: 15px;
            margin-bottom: 20px;
            background-color: #fff;
        }
        .severity-critical {
            border-left: 5px solid #e74c3c;
        }
        .severity-high {
            border-left: 5px solid #e67e22;
        }
        .severity-medium {
            border-left: 5px solid #f1c40f;
        }
        .severity-low {
            border-left: 5px solid #2ecc71;
        }
        .vulnerability {
            margin-top: 15px;
            padding: 15px;
            background-color: #f8f9fa;
            border-radius: 5px;
        }
        .technical-details {
            font-family: monospace;
            white-space: pre-wrap;
            background-color: #f1f1f1;
            padding: 10px;
            border-radius: 5px;
            overflow-x: auto;
        }
        .evidence {
            margin-top: 15px;
            border-top: 1px dashed #ddd;
            padding-top: 15px;
        }
        .request-response {
            font-family: monospace;
            white-space: pre-wrap;
            background-color: #2c3e50;
            color: #ecf0f1;
            padding: 10px;
            border-radius: 5px;
            overflow-x: auto;
            font-size: 0.9em;
        }
        .cve {
            background-color: #f1f1f1;
            padding: 10px;
            border-radius: 5px;
            margin-top: 10px;
        }
        .remediation {
            background-color: #e8f4f8;
            padding: 15px;
            border-radius: 5px;
            margin-top: 20px;
        }
        .remediation ul {
            margin-top: 5px;
            padding-left: 20px;
        }
        .footer {
            text-align: center;
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #ddd;
            font-size: 0.9em;
            color: #7f8c8d;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>{{ title }}</h1>
        <p>Generated on: {{ generation_date }}</p>
    </div>
    
    <div class="meta-info">
        <h2>Report Information</h2>
        <p><strong>Author:</strong> {{ author }}</p>
        <p><strong>Generation Date:</strong> {{ generation_date }}</p>
        <p><strong>Total Findings:</strong> {{ findings|length }}</p>
    </div>
    
    <h2>Executive Summary</h2>
    <p>This report details {{ findings|length }} security vulnerabilities discovered during security testing.</p>
    
    <h2>Findings</h2>
    {% for finding in findings %}
    <div class="finding severity-{{ finding.vulnerabilities[0].severity.rating|lower }}">
        <h3>Target: {{ finding.url }}</h3>
        <div class="target-info">
            <p><strong>Status Code:</strong> {{ finding.status_code }}</p>
            <p><strong>Server:</strong> {{ finding.server }}</p>
        </div>
        
        {% for vuln in finding.vulnerabilities %}
        <div class="vulnerability">
            <h4>{{ vuln.type }} - {{ vuln.severity.rating }} (CVSS: {{ vuln.severity.cvss_score }})</h4>
            <p>{{ vuln.description }}</p>
            
            <h5>Technical Details</h5>
            <div class="technical-details">{{ vuln.technical_details|to_json }}</div>
            
            <h5>Proof of Concept</h5>
            <div class="technical-details">{{ vuln.proof_of_concept }}</div>
            
            {% if vuln.potential_cves %}
            <h5>Related CVEs</h5>
            <div class="cves">
                {% for cve in vuln.potential_cves %}
                <div class="cve">
                    <p><strong>{{ cve.cve_id }}</strong> - {{ cve.description }}</p>
                    <p><strong>Severity:</strong> {{ cve.severity }} (CVSS: {{ cve.cvss_score }})</p>
                    <p><strong>References:</strong> 
                        {% for ref in cve.references %}
                        <a href="{{ ref }}" target="_blank">{{ ref }}</a>{% if not loop.last %}, {% endif %}
                        {% endfor %}
                    </p>
                </div>
                {% endfor %}
            </div>
            {% endif %}
            
            <div class="remediation">
                <h5>Remediation Recommendations</h5>
                <ul>
                    {% for step in vuln.remediation %}
                    <li>{{ step }}</li>
                    {% endfor %}
                </ul>
            </div>
        </div>
        {% endfor %}
        
        {% if finding.evidence %}
        <h5>Evidence</h5>
        {% for evidence_item in finding.evidence %}
        <div class="evidence">
            <p><strong>Timestamp:</strong> {{ evidence_item.timestamp }}</p>
            
            {% if evidence_item.screenshot_path %}
            <p><strong>Screenshot:</strong> <a href="{{ evidence_item.screenshot_path }}" target="_blank">View Screenshot</a></p>
            {% endif %}
            
            <h6>HTTP Request</h6>
            <div class="request-response">{{ evidence_item.http_request }}</div>
            
            <h6>HTTP Response</h6>
            <div class="request-response">{{ evidence_item.http_response }}</div>
            
            <p><strong>Notes:</strong> {{ evidence_item.notes }}</p>
        </div>
        {% endfor %}
        {% endif %}
    </div>
    {% endfor %}
    
    <div class="footer">
        <p>Report generated using Deep Analytics - Automated Vulnerability Analysis Tool</p>
        <p>© {{ current_year }} Security Research Team</p>
    </div>
</body>
</html>
"""
        
        # Write template to file
        with open(template_path, 'w') as f:
            f.write(template_content)
            
        logger.info(f"Created default HTML template: {template_path}")
    
    def _create_default_md_template(self, template_path):
        """Create a default Markdown report template."""
        template_content = """# {{ title }}

*Generated on: {{ generation_date }}*

## Report Information
**Author:** {{ author }}
**Generation Date:** {{ generation_date }}
**Total Findings:** {{ findings|length }}

## Executive Summary
This report details {{ findings|length }} security vulnerabilities discovered during security testing.

## Findings

{% for finding in findings %}
### Target: {{ finding.url }}
**Status Code:** {{ finding.status_code }}
**Server:** {{ finding.server }}

{% for vuln in finding.vulnerabilities %}
#### {{ vuln.type }} - {{ vuln.severity.rating }} (CVSS: {{ vuln.severity.cvss_score }})
{{ vuln.description }}

##### Technical Details
```json
{{ vuln.technical_details|to_json }}
```

##### Proof of Concept
```
{{ vuln.proof_of_concept }}
```

{% if vuln.potential_cves %}
##### Related CVEs
{% for cve in vuln.potential_cves %}
**{{ cve.cve_id }}** - {{ cve.description }}
**Severity:** {{ cve.severity }} (CVSS: {{ cve.cvss_score }})
**References:** {% for ref in cve.references %}[{{ ref }}]({{ ref }}){% if not loop.last %}, {% endif %}{% endfor %}

{% endfor %}
{% endif %}

##### Remediation Recommendations
{% for step in vuln.remediation %}
- {{ step }}
{% endfor %}

{% endfor %}

{% if finding.evidence %}
##### Evidence
{% for evidence_item in finding.evidence %}
**Timestamp:** {{ evidence_item.timestamp }}
{% if evidence_item.screenshot_path %}
**Screenshot:** [View Screenshot]({{ evidence_item.screenshot_path }})
{% endif %}

**HTTP Request:**
```
{{ evidence_item.http_request }}
```

**HTTP Response:**
```
{{ evidence_item.http_response }}
```

**Notes:** {{ evidence_item.notes }}

{% endfor %}
{% endif %}

{% endfor %}

---

Report generated using Deep Analytics - Automated Vulnerability Analysis Tool
© {{ current_year }} Security Research Team
"""
        
        # Write template to file
        with open(template_path, 'w') as f:
            f.write(template_content)
            
        logger.info(f"Created default Markdown template: {template_path}")

    def _create_default_exec_summary_template(self, template_path):
        """Create a default executive summary template."""
        template_content = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Executive Summary - {{ title }}</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        h1, h2, h3 {
            color: #2c3e50;
        }
        .header {
            border-bottom: 2px solid #3498db;
            padding-bottom: 10px;
            margin-bottom: 20px;
        }
        .summary-box {
            background-color: #f8f9fa;
            padding: 20px;
            border-radius: 5px;
            margin-bottom: 20px;
        }
        .vulnerability-summary {
            margin-top: 30px;
        }
        .severity-chart {
            width: 100%;
            height: 30px;
            background-color: #ecf0f1;
            border-radius: 5px;
            margin: 20px 0;
            overflow: hidden;
            display: flex;
        }
        .severity-critical {
            background-color: #e74c3c;
        }
        .severity-high {
            background-color: #e67e22;
        }
        .severity-medium {
            background-color: #f1c40f;
        }
        .severity-low {
            background-color: #2ecc71;
        }
        .chart-legend {
            display: flex;
            justify-content: space-between;
            margin-bottom: 30px;
        }
        .legend-item {
            display: flex;
            align-items: center;
        }
        .legend-color {
            width: 20px;
            height: 20px;
            margin-right: 5px;
            border-radius: 3px;
        }
        .recommendations {
            background-color: #e8f4f8;
            padding: 20px;
            border-radius: 5px;
            margin-top: 30px;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }
        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        th {
            background-color: #f2f2f2;
        }
        .footer {
            text-align: center;
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #ddd;
            font-size: 0.9em;
            color: #7f8c8d;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>Executive Summary - {{ title }}</h1>
        <p>Generated on: {{ generation_date }}</p>
    </div>

    <div class="summary-box">
        <h2>Overview</h2>
        <p>This security assessment identified <strong>{{ findings|length }}</strong> vulnerable targets with security issues that require attention.</p>
        
        <h3>Key Statistics:</h3>
        <ul>
            <li><strong>Total Vulnerabilities:</strong> {{ total_vulnerabilities }}</li>
            <li><strong>Critical Severity:</strong> {{ severity_counts.Critical|default(0) }}</li>
            <li><strong>High Severity:</strong> {{ severity_counts.High|default(0) }}</li>
            <li><strong>Medium Severity:</strong> {{ severity_counts.Medium|default(0) }}</li>
            <li><strong>Low Severity:</strong> {{ severity_counts.Low|default(0) }}</li>
        </ul>
        
        <div class="severity-chart">
            {% if severity_counts.Critical|default(0) > 0 %}
            <div class="severity-critical" style="width: {{ (severity_counts.Critical / total_vulnerabilities * 100)|round }}%;"></div>
            {% endif %}
            
            {% if severity_counts.High|default(0) > 0 %}
            <div class="severity-high" style="width: {{ (severity_counts.High / total_vulnerabilities * 100)|round }}%;"></div>
            {% endif %}
            
            {% if severity_counts.Medium|default(0) > 0 %}
            <div class="severity-medium" style="width: {{ (severity_counts.Medium / total_vulnerabilities * 100)|round }}%;"></div>
            {% endif %}
            
            {% if severity_counts.Low|default(0) > 0 %}
            <div class="severity-low" style="width: {{ (severity_counts.Low / total_vulnerabilities * 100)|round }}%;"></div>
            {% endif %}
        </div>
        
        <div class="chart-legend">
            {% if severity_counts.Critical|default(0) > 0 %}
            <div class="legend-item">
                <div class="legend-color severity-critical"></div>
                <div>Critical ({{ severity_counts.Critical }})</div>
            </div>
            {% endif %}
            
            {% if severity_counts.High|default(0) > 0 %}
            <div class="legend-item">
                <div class="legend-color severity-high"></div>
                <div>High ({{ severity_counts.High }})</div>
            </div>
            {% endif %}
            
            {% if severity_counts.Medium|default(0) > 0 %}
            <div class="legend-item">
                <div class="legend-color severity-medium"></div>
                <div>Medium ({{ severity_counts.Medium }})</div>
            </div>
            {% endif %}
            
            {% if severity_counts.Low|default(0) > 0 %}
            <div class="legend-item">
                <div class="legend-color severity-low"></div>
                <div>Low ({{ severity_counts.Low }})</div>
            </div>
            {% endif %}
        </div>
    </div>

    <div class="vulnerability-summary">
        <h2>Vulnerability Summary</h2>
        <table>
            <tr>
                <th>Vulnerability Type</th>
                <th>Count</th>
                <th>Severity</th>
                <th>Affected URLs</th>
            </tr>
            {% for vuln_type, details in vuln_type_summary.items() %}
            <tr>
                <td>{{ vuln_type }}</td>
                <td>{{ details.count }}</td>
                <td>{{ details.severity }}</td>
                <td>{{ details.urls|join(', ') }}</td>
            </tr>
            {% endfor %}
        </table>
    </div>

    <div class="recommendations">
        <h2>Key Recommendations</h2>
        <ol>
            {% for rec in top_recommendations %}
            <li>{{ rec }}</li>
            {% endfor %}
        </ol>
    </div>

    <div class="footer">
        <p>This is an executive summary. For detailed findings, please refer to the full vulnerability report.</p>
        <p>© {{ current_year }} Security Research Team</p>
    </div>
</body>
</html>
"""
        
        # Write template to file
        with open(template_path, 'w') as f:
            f.write(template_content)
            
        logger.info(f"Created default executive summary template: {template_path}")

    def generate(self, findings, title="Vulnerability Analysis Report", author="Security Researcher"):
        """
        Generate a full vulnerability report.
        
        Args:
            findings: List of finding dictionaries
            title: Report title
            author: Report author
            
        Returns:
            Path to the generated report
        """
        if not findings:
            logger.warning("No findings to include in the report")
            return None
        
        # Select appropriate generator based on format
        if self.output_format == "html":
            return self._generate_html_report(findings, title, author)
        elif self.output_format == "markdown":
            return self._generate_markdown_report(findings, title, author)
        elif self.output_format == "json":
            return self._generate_json_report(findings, title, author)
        elif self.output_format == "pdf":
            return self._generate_pdf_report(findings, title, author)
        else:
            logger.error(f"Unsupported output format: {self.output_format}")
            # Default to HTML
            return self._generate_html_report(findings, title, author)

    def _generate_html_report(self, findings, title, author):
        """Generate an HTML report."""
        try:
            # Load the template
            template = self.jinja_env.get_template("report_template.html")
            
            # Prepare template variables
            template_vars = {
                'title': title,
                'author': author,
                'findings': findings,
                'generation_date': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'current_year': datetime.datetime.now().year
            }
            
            # Render the template
            report_html = template.render(template_vars)
            
            # Save the report
            report_path = self.output_dir / f"{self._sanitize_filename(title)}.html"
            with open(report_path, 'w') as f:
                f.write(report_html)
            
            logger.info(f"HTML report generated: {report_path}")
            return report_path
            
        except Exception as e:
            logger.error(f"Error generating HTML report: {str(e)}")
            return None

    def _generate_markdown_report(self, findings, title, author):
        """Generate a Markdown report."""
        try:
            # Load the template
            template = self.jinja_env.get_template("report_template.md")
            
            # Prepare template variables
            template_vars = {
                'title': title,
                'author': author,
                'findings': findings,
                'generation_date': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'current_year': datetime.datetime.now().year
            }
            
            # Render the template
            report_md = template.render(template_vars)
            
            # Save the report
            report_path = self.output_dir / f"{self._sanitize_filename(title)}.md"
            with open(report_path, 'w') as f:
                f.write(report_md)
            
            logger.info(f"Markdown report generated: {report_path}")
            return report_path
            
        except Exception as e:
            logger.error(f"Error generating Markdown report: {str(e)}")
            return None

    def _generate_json_report(self, findings, title, author):
        """Generate a JSON report."""
        try:
            # Prepare report data
            report_data = {
                'title': title,
                'author': author,
                'generation_date': datetime.datetime.now().isoformat(),
                'findings': findings
            }
            
            # Save the report
            report_path = self.output_dir / f"{self._sanitize_filename(title)}.json"
            with open(report_path, 'w') as f:
                json.dump(report_data, f, indent=2)
            
            logger.info(f"JSON report generated: {report_path}")
            return report_path
            
        except Exception as e:
            logger.error(f"Error generating JSON report: {str(e)}")
            return None

    def _generate_pdf_report(self, findings, title, author):
        """Generate a PDF report (via HTML conversion)."""
        try:
            # First generate HTML report
            html_path = self._generate_html_report(findings, title, author)
            if not html_path:
                return None
            
            # Attempt to convert to PDF
            try:
                # Try to import required libraries
                import pdfkit
                
                # Define PDF output path
                pdf_path = self.output_dir / f"{self._sanitize_filename(title)}.pdf"
                
                # Convert HTML to PDF
                pdfkit.from_file(str(html_path), str(pdf_path))
                
                logger.info(f"PDF report generated: {pdf_path}")
                return pdf_path
                
            except ImportError:
                logger.warning("pdfkit not installed. Falling back to HTML report.")
                return html_path
                
        except Exception as e:
            logger.error(f"Error generating PDF report: {str(e)}")
            return None

    def generate_executive_summary(self, findings):
        """
        Generate an executive summary of the findings.
        
        Args:
            findings: List of finding dictionaries
            
        Returns:
            Path to the generated summary
        """
        try:
            # Count vulnerabilities by type and severity
            total_vulnerabilities = 0
            severity_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
            vuln_type_summary = {}
            
            for finding in findings:
                for vuln in finding.get('vulnerabilities', []):
                    total_vulnerabilities += 1
                    severity = vuln.get('severity', {}).get('rating', 'Medium')
                    severity_counts[severity] = severity_counts.get(severity, 0) + 1
                    
                    vuln_type = vuln.get('type', 'Unknown')
                    if vuln_type not in vuln_type_summary:
                        vuln_type_summary[vuln_type] = {
                            'count': 0,
                            'severity': severity,
                            'urls': []
                        }
                    
                    vuln_type_summary[vuln_type]['count'] += 1
                    vuln_type_summary[vuln_type]['urls'].append(finding.get('url', ''))
            
            # Collect top recommendations
            top_recommendations = set()
            for finding in findings:
                for vuln in finding.get('vulnerabilities', []):
                    if vuln.get('severity', {}).get('rating') in ['Critical', 'High']:
                        for rec in vuln.get('remediation', [])[:2]:  # Get top 2 recommendations
                            top_recommendations.add(rec)
            
            # Load the template
            template = self.jinja_env.get_template("executive_summary_template.html")
            
            # Prepare template variables
            template_vars = {
                'title': "Vulnerability Assessment",
                'findings': findings,
                'total_vulnerabilities': total_vulnerabilities,
                'severity_counts': severity_counts,
                'vuln_type_summary': vuln_type_summary,
                'top_recommendations': list(top_recommendations)[:5],  # Top 5 recommendations
                'generation_date': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'current_year': datetime.datetime.now().year
            }
            
            # Render the template
            summary_html = template.render(template_vars)
            
            # Save the summary
            summary_path = self.output_dir / "executive_summary.html"
            with open(summary_path, 'w') as f:
                f.write(summary_html)
            
            logger.info(f"Executive summary generated: {summary_path}")
            return summary_path
            
        except Exception as e:
            logger.error(f"Error generating executive summary: {str(e)}")
            return None

    def generate_single_vulnerability_report(self, finding, filename_prefix):
        """
        Generate a report for a single vulnerability finding.
        
        Args:
            finding: Dictionary containing finding information
            filename_prefix: Prefix for the output filename
            
        Returns:
            Path to the generated report
        """
        try:
            # Wrap the finding in a list for the template
            findings = [finding]
            
            # Get vulnerability type for the title
            vuln_type = "Vulnerability"
            if finding.get('vulnerabilities') and finding['vulnerabilities'][0].get('type'):
                vuln_type = finding['vulnerabilities'][0]['type']
            
            title = f"{vuln_type} in {urlparse(finding.get('url', '')).netloc}"
            
            # Generate the report
            if self.output_format == "html":
                return self._generate_html_report(findings, title, "Security Researcher")
            elif self.output_format == "markdown":
                return self._generate_markdown_report(findings, title, "Security Researcher")
            elif self.output_format == "json":
                return self._generate_json_report(findings, title, "Security Researcher")
            elif self.output_format == "pdf":
                return self._generate_pdf_report(findings, title, "Security Researcher")
            
        except Exception as e:
            logger.error(f"Error generating single vulnerability report: {str(e)}")
            return None

    def _sanitize_filename(self, filename):
        """Sanitize a string for use as a filename."""
        # Replace invalid characters
        invalid_chars = '<>:"/\\|?*'
        for char in invalid_chars:
            filename = filename.replace(char, '_')
        
        # Limit length
        max_length = 50
        if len(filename) > max_length:
            filename = filename[:max_length]
        
        return filename