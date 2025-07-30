#!/usr/bin/env python3
"""
Data parser module for converting various scan result formats into a standardized structure.
"""

import pandas as pd
import json
import csv
import logging
import re
from pathlib import Path

logger = logging.getLogger("deep_analytics.parser")

class ScanDataParser:
    """Parser for various security scan result formats."""

    def parse_file(self, file_path):
        """
        Parse a scan results file based on its extension.

        Args:
            file_path: Path to the scan results file

        Returns:
            List of dictionaries containing scan data
        """
        file_path = Path(file_path)

        if not file_path.exists():
            raise FileNotFoundError(f"Scan file not found: {file_path}")

        # Determine parsing method based on file extension
        if file_path.suffix.lower() == '.csv':
            return self.parse_csv(file_path)
        elif file_path.suffix.lower() == '.json':
            return self.parse_json(file_path)
        elif file_path.suffix.lower() == '.txt':
            return self.parse_txt(file_path)
        else:
            raise ValueError(f"Unsupported file format: {file_path.suffix}")

    def parse_csv(self, file_path):
        """Parse a CSV scan results file."""
        try:
            df = pd.read_csv(file_path)
            # Convert DataFrame to list of dictionaries
            return df.to_dict('records')
        except Exception as e:
            logger.error(f"Error parsing CSV file: {str(e)}")
            raise

    def parse_json(self, file_path):
        """Parse a JSON scan results file."""
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)

            # Handle different JSON structures
            if isinstance(data, list):
                return data
            elif isinstance(data, dict) and 'results' in data:
                return data['results']
            else:
                return [data]
        except Exception as e:
            logger.error(f"Error parsing JSON file: {str(e)}")
            raise

    def parse_txt(self, file_path):
        """
        Parse a text-based scan results file.
        Handles tab-delimited, space-delimited, and custom formats.
        """
        try:
            with open(file_path, 'r') as f:
                content = f.read()

            # Try to detect format
            if '\t' in content.split('\n')[0]:
                return self._parse_tab_delimited(file_path)
            elif re.search(r'URL\s+Status\s+Response', content):
                return self._parse_space_delimited(file_path)
            else:
                # Try general parsing approach
                return self._parse_generic_txt(file_path)
        except Exception as e:
            logger.error(f"Error parsing TXT file: {str(e)}")
            raise

    def _parse_tab_delimited(self, file_path):
        """Parse a tab-delimited text file."""
        results = []
        with open(file_path, 'r') as f:
            # Read header line
            header = next(f).strip().split('\t')

            # Process each line
            for line in f:
                if not line.strip():
                    continue

                values = line.strip().split('\t')
                if len(values) < len(header):
                    # Pad with empty values if needed
                    values.extend([''] * (len(header) - len(values)))
                elif len(values) > len(header):
                    # Truncate if too many values
                    values = values[:len(header)]

                # Create dictionary from header and values
                entry = {}
                for i, field in enumerate(header):
                    # Handle boolean fields
                    if values[i].lower() in ('true', 'false'):
                        entry[field] = values[i].lower() == 'true'
                    else:
                        entry[field] = values[i]

                results.append(entry)

        return results

    def _parse_space_delimited(self, file_path):
        """Parse a space-delimited text file with fixed width columns."""
        results = []
        with open(file_path, 'r') as f:
            content = f.readlines()

            # Extract header and determine column positions
            header_line = content[0]
            column_positions = []
            header_fields = []

            # Find the starting positions of each column
            for match in re.finditer(r'\S+\s+', header_line):
                column_positions.append(match.start())
                header_fields.append(match.group().strip())

            # Add the last column
            last_match = re.search(r'\S+$', header_line)
            if last_match:
                column_positions.append(last_match.start())
                header_fields.append(last_match.group())

            # Process each data line
            for line in content[1:]:
                if not line.strip():
                    continue

                # Extract values based on column positions
                entry = {}
                for i in range(len(column_positions)):
                    start = column_positions[i]
                    end = column_positions[i+1] if i+1 < len(column_positions) else None
                    value = line[start:end].strip() if end else line[start:].strip()

                    # Handle boolean fields
                    if value.lower() in ('true', 'false'):
                        entry[header_fields[i]] = value.lower() == 'true'
                    else:
                        entry[header_fields[i]] = value

                results.append(entry)

        return results

    def _parse_generic_txt(self, file_path):
        """
        Parse a generic text file format.
        Tries to detect the format and extract relevant information.
        """
        results = []
        url_pattern = r'https?://\S+'

        with open(file_path, 'r') as f:
            lines = f.readlines()

            # Skip empty lines
            lines = [line.strip() for line in lines if line.strip()]

            # Detect header line
            header_line = lines[0] if lines else ""
            header_fields = []

            # Try to extract header fields
            if re.search(r'URL|Status|Server|SQLi|XSS|RCE', header_line, re.IGNORECASE):
                header_fields = re.findall(r'\b(\w+)\b', header_line)
                lines = lines[1:]  # Skip header line

            # Process each line
            for line in lines:
                # Extract URL
                url_match = re.search(url_pattern, line)
                if not url_match:
                    continue

                url = url_match.group(0)

                # Extract other fields
                entry = {'URL': url}

                # Status code
                status_match = re.search(r'\b(\d{3})\b', line[url_match.end():])
                if status_match:
                    entry['Status'] = status_match.group(1)

                # Server type
                server_match = re.search(r'Server:\s*(\S+)', line)
                if server_match:
                    entry['Server'] = server_match.group(1)

                # Boolean flags
                for flag in ['SQLi', 'XSS', 'RCE', 'LFI']:
                    if re.search(fr'\b{flag}\b.*?(True|False)', line, re.IGNORECASE):
                        value_match = re.search(fr'\b{flag}\b.*?(True|False)', line, re.IGNORECASE)
                        entry[flag] = value_match.group(1).lower() == 'true'
                    else:
                        # Default to False if not found
                        entry[flag] = False

                results.append(entry)

        return results