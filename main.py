#!/usr/bin/env python3
"""
Cross-Site Scripting (XSS) Payload Sanitizer
Advanced structural tokenization filters with context-aware validation
"""

import re
import html
import base64
import urllib.parse
from typing import Dict, List, Tuple, Optional, Set
from dataclasses import dataclass, field
import json
from datetime import datetime
import hashlib

@dataclass
class XSSDetectionResult:
    """Represents XSS detection and sanitization results"""
    original_payload: str
    sanitized_payload: str
    is_malicious: bool
    threat_level: str  # LOW, MEDIUM, HIGH, CRITICAL
    detected_patterns: List[str]
    sanitization_applied: List[str]
    context: str
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())

class AdvancedXSSSanitizer:
    """
    Enterprise-grade XSS sanitizer with:
    - Multi-layer validation
    - Context-aware filtering
    - Pattern-based detection
    - Obfuscation handling
    - Unicode normalization
    - Custom rule engine
    - Machine learning integration (optional)
    """
    
    def __init__(self, enable_ml: bool = False):
        self.enable_ml = enable_ml
        self.statistics = {
            'total_processed': 0,
            'malicious_detected': 0,
            'patterns_used': {},
            'sanitized_count': 0
        }
        
        # Initialize detection patterns
        self.patterns = self._initialize_patterns()
        
        # Initialize context handlers
        self.context_handlers = {
            'html': self._sanitize_html,
            'attribute': self._sanitize_attribute,
            'javascript': self._sanitize_javascript,
            'url': self._sanitize_url,
            'css': self._sanitize_css,
            'json': self._sanitize_json,
            'xml': self._sanitize_xml,
            'ldap': self._sanitize_ldap
        }
        
        # Dangerous patterns database
        self.xss_payloads = self._load_xss_payloads()
        
        # ML model (if enabled)
        if enable_ml:
            self._initialize_ml_model()
    
    def _initialize_patterns(self) -> Dict[str, re.Pattern]:
        """Initialize comprehensive XSS pattern database"""
        return {
            # HTML tags
            'script_tag': re.compile(r'<script[^>]*>.*?</script>', re.IGNORECASE | re.DOTALL),
            'iframe_tag': re.compile(r'<iframe[^>]*>.*?</iframe>', re.IGNORECASE | re.DOTALL),
            'object_tag': re.compile(r'<object[^>]*>.*?</object>', re.IGNORECASE | re.DOTALL),
            'embed_tag': re.compile(r'<embed[^>]*>', re.IGNORECASE),
            'applet_tag': re.compile(r'<applet[^>]*>.*?</applet>', re.IGNORECASE | re.DOTALL),
            'meta_tag': re.compile(r'<meta[^>]*>', re.IGNORECASE),
            'link_tag': re.compile(r'<link[^>]*>', re.IGNORECASE),
            'style_tag': re.compile(r'<style[^>]*>.*?</style>', re.IGNORECASE | re.DOTALL),
            'form_tag': re.compile(r'<form[^>]*>', re.IGNORECASE),
            'input_tag': re.compile(r'<input[^>]*>', re.IGNORECASE),
            'textarea_tag': re.compile(r'<textarea[^>]*>.*?</textarea>', re.IGNORECASE | re.DOTALL),
            'button_tag': re.compile(r'<button[^>]*>.*?</button>', re.IGNORECASE | re.DOTALL),
            
            # Event handlers
            'onload': re.compile(r'onload\s*=', re.IGNORECASE),
            'onerror': re.compile(r'onerror\s*=', re.IGNORECASE),
            'onclick': re.compile(r'onclick\s*=', re.IGNORECASE),
            'onmouseover': re.compile(r'onmouseover\s*=', re.IGNORECASE),
            'onkeypress': re.compile(r'onkeypress\s*=', re.IGNORECASE),
            'onsubmit': re.compile(r'onsubmit\s*=', re.IGNORECASE),
            'onfocus': re.compile(r'onfocus\s*=', re.IGNORECASE),
            'onblur': re.compile(r'onblur\s*=', re.IGNORECASE),
            'onchange': re.compile(r'onchange\s*=', re.IGNORECASE),
            'oninput': re.compile(r'oninput\s*=', re.IGNORECASE),
            'onsearch': re.compile(r'onsearch\s*=', re.IGNORECASE),
            'ondrag': re.compile(r'ondrag\s*=', re.IGNORECASE),
            'ondrop': re.compile(r'ondrop\s*=', re.IGNORECASE),
            'onresize': re.compile(r'onresize\s*=', re.IGNORECASE),
            'onscroll': re.compile(r'onscroll\s*=', re.IGNORECASE),
            'ontouch': re.compile(r'ontouch\w*\s*=', re.IGNORECASE),
            'onanimation': re.compile(r'onanimation\w*\s*=', re.IGNORECASE),
            'ontransition': re.compile(r'ontransition\w*\s*=', re.IGNORECASE),
            
            # URI schemes
            'javascript_uri': re.compile(r'javascript\s*:', re.IGNORECASE),
            'vbscript_uri': re.compile(r'vbscript\s*:', re.IGNORECASE),
            'livescript_uri': re.compile(r'livescript\s*:', re.IGNORECASE),
            'data_uri': re.compile(r'data\s*:', re.IGNORECASE),
            'file_uri': re.compile(r'file\s*:', re.IGNORECASE),
            
            # Function calls
            'eval_call': re.compile(r'eval\s*\(', re.IGNORECASE),
            'settimeout_call': re.compile(r'setTimeout\s*\(', re.IGNORECASE),
            'setinterval_call': re.compile(r'setInterval\s*\(', re.IGNORECASE),
            'function_constructor': re.compile(r'Function\s*\(', re.IGNORECASE),
            
            # CSS expressions
            'css_expression': re.compile(r'expression\s*\(', re.IGNORECASE),
            'css_url': re.compile(r'url\s*\(', re.IGNORECASE),
            
            # Obfuscation patterns
            'obfuscated_js': re.compile(r'&\s*[#\w]+;', re.IGNORECASE),
            'hex_encoding': re.compile(r'&#x[0-9a-f]{2,4};', re.IGNORECASE),
            'decimal_encoding': re.compile(r'&#[0-9]{2,4};', re.IGNORECASE),
            'unicode_encoding': re.compile(r'\\u[0-9a-f]{4}', re.IGNORECASE),
            
            # Special characters
            'null_byte': re.compile(r'\x00', re.IGNORECASE),
            'newline': re.compile(r'\n', re.IGNORECASE),
            'carriage_return': re.compile(r'\r', re.IGNORECASE),
            
            # SVG patterns
            'svg_tags': re.compile(r'<svg[^>]*>', re.IGNORECASE),
            'svg_onload': re.compile(r'onload\s*=.*?svg', re.IGNORECASE),
            
            # HTML5 new events
            'onmessage': re.compile(r'onmessage\s*=', re.IGNORECASE),
            'onstorage': re.compile(r'onstorage\s*=', re.IGNORECASE),
            'onpopstate': re.compile(r'onpopstate\s*=', re.IGNORECASE),
            'onhashchange': re.compile(r'onhashchange\s*=', re.IGNORECASE),
            'onpageshow': re.compile(r'onpageshow\s*=', re.IGNORECASE),
            'onpagehide': re.compile(r'onpagehide\s*=', re.IGNORECASE)
        }
    
    def _load_xss_payloads(self) -> List[str]:
        """Load common XSS payloads for detection"""
        return [
            # Classic script injection
            '<script>alert(1)</script>',
            '<script>alert("XSS")</script>',
            "<script>alert('XSS')</script>",
            
            # Event-based
            '<img src=x onerror=alert(1)>',
            '<img src="javascript:alert(1)">',
            '<body onload=alert(1)>',
            '<div onclick=alert(1)>',
            '<a href="javascript:alert(1)">',
            
            # Encoded variants
            '%3Cscript%3Ealert%281%29%3C%2Fscript%3E',
            '&#60;script&#62;alert&#40;1&#41;&#60;/script&#62;',
            
            # Obfuscated
            '<scr<script>ipt>alert(1)</scr</script>ipt>',
            '<IMG SRC=&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;&#97;&#108;&#101;&#114;&#116;&#40;&#39;&#88;&#83;&#83;&#39;&#41;>',
            
            # DOM-based
            'javascript:alert(document.cookie)',
            'javascript:eval("alert(1)")',
            
            # Data URI
            'data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==',
            
            # SVG attacks
            '<svg onload=alert(1)>',
            '<svg/onload=alert(1)>',
            
            # Form-based
            '<input value=""><script>alert(1)</script>',
            
            # CSS-based
            '<div style="background:url(javascript:alert(1))">',
            '<div style="expression(alert(1))">',
            
            # Flash-based
            '<object data="data:application/x-shockwave-flash;base64,...">'
        ]
    
    def _initialize_ml_model(self):
        """Initialize ML model for XSS detection"""
        # Placeholder for ML implementation
        from sklearn.feature_extraction.text import TfidfVectorizer
        from sklearn.ensemble import RandomForestClassifier
        
        self.vectorizer = TfidfVectorizer(max_features=1000)
        self.ml_model = RandomForestClassifier(n_estimators=100, random_state=42)
    
    def sanitize(self, 
                 input_text: str, 
                 context: str = 'html',
                 custom_rules: Optional[List[str]] = None) -> XSSDetectionResult:
        """
        Main sanitization entry point with context awareness
        
        Args:
            input_text: The input string to sanitize
            context: Context type (html, attribute, javascript, url, css, json, xml, ldap)
            custom_rules: Optional list of custom regex patterns
        
        Returns:
            XSSDetectionResult with sanitization details
        """
        self.statistics['total_processed'] += 1
        
        if not input_text:
            return XSSDetectionResult(
                original_payload='',
                sanitized_payload='',
                is_malicious=False,
                threat_level='LOW',
                detected_patterns=[],
                sanitization_applied=['No input provided'],
                context=context
            )
        
        # Step 1: Normalize input
        normalized = self._normalize_input(input_text)
        
        # Step 2: Detect XSS patterns
        detected_patterns = self._detect_xss_patterns(normalized)
        
        # Step 3: Determine threat level
        threat_level = self._calculate_threat_level(detected_patterns)
        
        # Step 4: Apply context-specific sanitization
        if context in self.context_handlers:
            sanitized = self.context_handlers[context](normalized)
        else:
            sanitized = self._sanitize_html(normalized)
        
        # Step 5: Apply custom rules if provided
        if custom_rules:
            sanitized = self._apply_custom_rules(sanitized, custom_rules)
        
        # Step 6: Final validation
        is_malicious = bool(detected_patterns)
        if is_malicious:
            self.statistics['malicious_detected'] += 1
            
        # Step 7: ML-based detection (if enabled)
        if self.enable_ml and is_malicious:
            ml_result = self._ml_detect(normalized)
            if ml_result:
                self.statistics['malicious_detected'] += 1
        
        # Update statistics
        for pattern in detected_patterns:
            self.statistics['patterns_used'][pattern] = self.statistics['patterns_used'].get(pattern, 0) + 1
        
        if sanitized != input_text:
            self.statistics['sanitized_count'] += 1
        
        return XSSDetectionResult(
            original_payload=input_text,
            sanitized_payload=sanitized,
            is_malicious=is_malicious,
            threat_level=threat_level,
            detected_patterns=detected_patterns,
            sanitization_applied=self._get_sanitization_applied(input_text, sanitized),
            context=context
        )
    
    def _normalize_input(self, text: str) -> str:
        """Normalize input to handle obfuscation techniques"""
        # Unicode normalization
        import unicodedata
        text = unicodedata.normalize('NFKC', text)
        
        # Decode HTML entities
        text = html.unescape(text)
        
        # Decode URL encoding
        try:
            text = urllib.parse.unquote(text)
        except:
            pass
        
        # Decode base64 (check if it looks like base64)
        if re.match(r'^[A-Za-z0-9+/=]+$', text) and len(text) > 10:
            try:
                decoded = base64.b64decode(text).decode('utf-8', errors='ignore')
                if decoded and any(pattern in decoded.lower() for pattern in ['<script', 'javascript', 'alert']):
                    text = decoded
            except:
                pass
        
        # Remove null bytes
        text = text.replace('\x00', '')
        
        # Normalize whitespace
        text = ' '.join(text.split())
        
        return text
    
    def _detect_xss_patterns(self, text: str) -> List[str]:
        """Detect XSS patterns in input text"""
        detected = []
        
        for pattern_name, pattern in self.patterns.items():
            if pattern.search(text):
                detected.append(pattern_name)
        
        # Additional heuristic detection
        # Check for HTML tag structures
        if '<' in text and '>' in text:
            tag_content = re.sub(r'<[^>]+>', '', text)
            if tag_content and any(keyword in tag_content.lower() for keyword in ['script', 'alert', 'window', 'document']):
                if 'html_tag' not in detected:
                    detected.append('html_tag_detected')
        
        # Check for inline event handlers
        if 'on' in text and '=' in text and ('(' in text or '"' in text or "'" in text):
            if 'inline_event' not in detected:
                detected.append('inline_event_suspected')
        
        return detected
    
    def _calculate_threat_level(self, detected_patterns: List[str]) -> str:
        """Calculate threat level based on detected patterns"""
        if not detected_patterns:
            return 'LOW'
        
        # Critical patterns
        critical_patterns = ['script_tag', 'iframe_tag', 'object_tag', 'embed_tag', 
                           'eval_call', 'function_constructor', 'javascript_uri']
        
        high_patterns = ['onload', 'onerror', 'onclick', 'svg_tags', 'css_expression',
                        'data_uri', 'base64_encoding']
        
        critical_count = sum(1 for p in detected_patterns if p in critical_patterns)
        high_count = sum(1 for p in detected_patterns if p in high_patterns)
        
        if critical_count > 0:
            return 'CRITICAL'
        elif critical_count > 1 or high_count > 2:
            return 'HIGH'
        elif high_count > 0:
            return 'MEDIUM'
        else:
            return 'LOW'
    
    def _sanitize_html(self, text: str) -> str:
        """Sanitize HTML context"""
        # Remove dangerous tags and their content
        for pattern in ['script_tag', 'iframe_tag', 'object_tag', 'embed_tag', 
                       'applet_tag', 'meta_tag', 'style_tag']:
            text = self.patterns[pattern].sub('', text)
        
        # Remove dangerous attributes
        for pattern in ['onload', 'onerror', 'onclick', 'onmouseover', 'onkeypress',
                       'onsubmit', 'onfocus', 'onblur', 'onchange', 'oninput',
                       'onmessage', 'onstorage', 'onpopstate', 'onhashchange']:
            text = self.patterns[pattern].sub('', text)
        
        # Remove dangerous URI schemes
        for pattern in ['javascript_uri', 'vbscript_uri', 'livescript_uri', 
                       'data_uri', 'file_uri']:
            text = self.patterns[pattern].sub('', text)
        
        # Escape remaining HTML
        text = html.escape(text)
        
        # Remove SVG-specific patterns
        text = self.patterns['svg_tags'].sub('', text)
        text = self.patterns['svg_onload'].sub('', text)
        
        # Remove CSS expressions
        text = self.patterns['css_expression'].sub('', text)
        
        # Remove obfuscation
        text = self.patterns['obfuscated_js'].sub('', text)
        
        # Clean up extra whitespace
        text = ' '.join(text.split())
        
        return text
    
    def _sanitize_attribute(self, text: str) -> str:
        """Sanitize HTML attribute values"""
        # Remove dangerous URI schemes
        for pattern in ['javascript_uri', 'vbscript_uri', 'livescript_uri', 
                       'data_uri', 'file_uri']:
            text = self.patterns[pattern].sub('', text)
        
        # Remove event handlers
        for pattern in ['onload', 'onerror', 'onclick', 'onmouseover', 'onkeypress',
                       'onsubmit', 'onfocus', 'onblur', 'onchange', 'oninput']:
            text = self.patterns[pattern].sub('', text)
        
        # Escape quotes
        text = text.replace('"', '&quot;').replace("'", '&#x27;')
        
        return text
    
    def _sanitize_javascript(self, text: str) -> str:
        """Sanitize JavaScript context"""
        # Remove dangerous function calls
        for pattern in ['eval_call', 'function_constructor', 'settimeout_call', 
                       'setinterval_call']:
            text = self.patterns[pattern].sub('', text)
        
        # Remove dangerous properties
        dangerous_props = ['document', 'window', 'location', 'navigator', 
                          'localStorage', 'sessionStorage', 'cookie']
        for prop in dangerous_props:
            text = re.sub(rf'\b{prop}\b', f'blocked_{prop}', text, re.IGNORECASE)
        
        # Remove dangerous methods
        dangerous_methods = ['alert', 'confirm', 'prompt', 'eval', 'exec', 
                            'setTimeout', 'setInterval', 'constructor']
        for method in dangerous_methods:
            text = re.sub(rf'\b{method}\s*\(', f'blocked_{method}(', text, re.IGNORECASE)
        
        return text
    
    def _sanitize_url(self, text: str) -> str:
        """Sanitize URL context"""
        # Block dangerous URI schemes
        dangerous_schemes = ['javascript:', 'vbscript:', 'livescript:', 
                           'data:', 'file:', 'ftp:']
        for scheme in dangerous_schemes:
            if text.lower().startswith(scheme):
                return '#blocked'
        
        # Validate URL structure
        try:
            parsed = urllib.parse.urlparse(text)
            if parsed.scheme and parsed.scheme.lower() in ['javascript', 'vbscript', 'data']:
                return '#blocked'
        except:
            pass
        
        return text
    
    def _sanitize_css(self, text: str) -> str:
        """Sanitize CSS context"""
        # Remove expressions
        text = self.patterns['css_expression'].sub('', text)
        
        # Remove dangerous url() references
        text = re.sub(r'url\s*\([^)]*\)', '', text, re.IGNORECASE)
        
        # Remove dangerous properties
        dangerous_props = ['behavior', 'expression', 'filter', 'moz-binding']
        for prop in dangerous_props:
            text = re.sub(rf'{prop}\s*:', f'blocked_{prop}:', text, re.IGNORECASE)
        
        return text
    
    def _sanitize_json(self, text: str) -> str:
        """Sanitize JSON context"""
        try:
            # Parse and validate JSON
            data = json.loads(text)
            
            # Recursively sanitize string values
            def sanitize_json(obj):
                if isinstance(obj, str):
                    return self.sanitize(obj, context='html').sanitized_payload
                elif isinstance(obj, dict):
                    return {k: sanitize_json(v) for k, v in obj.items()}
                elif isinstance(obj, list):
                    return [sanitize_json(item) for item in obj]
                else:
                    return obj
            
            sanitized = sanitize_json(data)
            return json.dumps(sanitized)
        except:
            return self._sanitize_html(text)
    
    def _sanitize_xml(self, text: str) -> str:
        """Sanitize XML context"""
        # Remove CDATA sections with dangerous content
        text = re.sub(r'<\!\[CDATA\[.*?\]\]>', '', text, re.DOTALL)
        
        # Escape special characters
        text = html.escape(text)
        
        return text
    
    def _sanitize_ldap(self, text: str) -> str:
        """Sanitize LDAP context"""
        # Remove LDAP injection characters
        dangerous_chars = ['(', ')', '\\', '*', '&', '!', '|', '=', '<', '>', '~', '`']
        for char in dangerous_chars:
            text = text.replace(char, f'\\{char}')
        
        return text
    
    def _apply_custom_rules(self, text: str, custom_rules: List[str]) -> str:
        """Apply custom sanitization rules"""
        for rule in custom_rules:
            try:
                pattern = re.compile(rule, re.IGNORECASE)
                text = pattern.sub('', text)
            except:
                pass
        return text
    
    def _get_sanitization_applied(self, original: str, sanitized: str) -> List[str]:
        """Determine what sanitization was applied"""
        applied = []
        
        if original != sanitized:
            # Check what changed
            if len(original) > len(sanitized):
                applied.append('removed_characters')
            
            if original.lower() != sanitized.lower():
                applied.append('case_changed')
            
            if any(pattern in original.lower() for pattern in ['script', 'alert', 'onerror', 'javascript']):
                if not any(pattern in sanitized.lower() for pattern in ['script', 'alert', 'onerror', 'javascript']):
                    applied.append('removed_dangerous_patterns')
            
            if '<' in original and '>' in sanitized:
                if '<' not in sanitized or '>' not in sanitized:
                    applied.append('escaped_html_tags')
        
        return applied
    
    def _ml_detect(self, text: str) -> bool:
        """ML-based XSS detection"""
        # Placeholder for ML implementation
        # In production, train with labeled XSS dataset
        return False
    
    def batch_sanitize(self, inputs: List[str], context: str = 'html') -> List[XSSDetectionResult]:
        """Batch sanitize multiple inputs"""
        results = []
        for input_text in inputs:
            results.append(self.sanitize(input_text, context))
        return results
    
    def get_statistics(self) -> Dict:
        """Get sanitization statistics"""
        return {
            'total_processed': self.statistics['total_processed'],
            'malicious_detected': self.statistics['malicious_detected'],
            'sanitized_count': self.statistics['sanitized_count'],
            'detection_rate': self.statistics['malicious_detected'] / max(1, self.statistics['total_processed']) * 100,
            'patterns_used': self.statistics['patterns_used'],
            'timestamp': datetime.utcnow().isoformat()
        }
    
    def test_payloads(self, context: str = 'html') -> Dict:
        """Test sanitizer against known XSS payloads"""
        results = {}
        
        for payload in self.xss_payloads:
            result = self.sanitize(payload, context)
            results[payload[:50] + '...' if len(payload) > 50 else payload] = {
                'sanitized': result.sanitized_payload,
                'detected': result.is_malicious,
                'threat_level': result.threat_level,
                'patterns': result.detected_patterns
            }
        
        return results
    
    def generate_report(self) -> str:
        """Generate comprehensive sanitization report"""
        stats = self.get_statistics()
        report = {
            'timestamp': datetime.utcnow().isoformat(),
            'statistics': stats,
            'recommendations': [],
            'summary': ''
        }
        
        if stats['detection_rate'] > 10:
            report['recommendations'].append({
                'severity': 'HIGH',
                'message': 'High XSS detection rate detected',
                'action': 'Review input sources and implement additional validation'
            })
        
        if stats['sanitized_count'] < stats['malicious_detected']:
            report['recommendations'].append({
                'severity': 'MEDIUM',
                'message': 'Some malicious inputs were not sanitized',
                'action': 'Review sanitization rules and patterns'
            })
        
        report['summary'] = f"""
        XSS Sanitizer Report
        =====================
        Total Processed: {stats['total_processed']}
        Malicious Detected: {stats['malicious_detected']}
        Sanitized: {stats['sanitized_count']}
        Detection Rate: {stats['detection_rate']:.2f}%
        Top Patterns: {', '.join(list(stats['patterns_used'].keys())[:5])}
        """
        
        return json.dumps(report, indent=2)


# ============================================================================
# ADVANCED USAGE EXAMPLE
# ============================================================================

def main():
    """Main execution with comprehensive testing"""
    sanitizer = AdvancedXSSSanitizer()
    
    print("=" * 70)
    print("ADVANCED XSS PAYLOAD SANITIZER")
    print("=" * 70 + "\n")
    
    # Test payloads
    test_payloads = [
        # Basic XSS
        '<script>alert(1)</script>',
        '<img src="x" onerror="alert(1)">',
        '<body onload="alert(1)">',
        '<a href="javascript:alert(1)">Click me</a>',
        
        # Encoded attacks
        '%3Cscript%3Ealert%281%29%3C%2Fscript%3E',
        '&#60;script&#62;alert&#40;1&#41;&#60;/script&#62;',
        
        # Obfuscated attacks
        '<scr<script>ipt>alert(1)</scr</script>ipt>',
        '<IMG SRC=&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;&#97;&#108;&#101;&#114;&#116;&#40;&#39;&#88;&#83;&#83;&#39;&#41;>',
        
        # DOM-based XSS
        'javascript:alert(document.cookie)',
        'javascript:eval("alert(1)")',
        
        # Data URI XSS
        'data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==',
        
        # SVG attacks
        '<svg onload=alert(1)>',
        '<svg/onload=alert(1)>',
        
        # CSS-based
        '<div style="background:url(javascript:alert(1))">',
        '<div style="expression(alert(1))">',
        
        # Benign input (should not trigger)
        'This is a normal text input without XSS',
        '<strong>Hello World</strong>',
        'My email is test@example.com'
    ]
    
    print("[*] Testing payload sanitization with different contexts...\n")
    
    # Test with different contexts
    contexts = ['html', 'attribute', 'javascript', 'url', 'css']
    
    for context in contexts:
        print(f"\n[+] Context: {context.upper()}")
        print("-" * 50)
        
        for payload in test_payloads[:5]:  # Test first 5 payloads
            result = sanitizer.sanitize(payload, context)
            
            status = "⚠️  MALICIOUS" if result.is_malicious else "✅  SAFE"
            print(f"  {status}")
            print(f"    Original: {payload[:60]}{'...' if len(payload) > 60 else ''}")
            print(f"    Sanitized: {result.sanitized_payload[:60]}{'...' if len(result.sanitized_payload) > 60 else ''}")
            print(f"    Threat Level: {result.threat_level}")
            if result.detected_patterns:
                print(f"    Patterns: {', '.join(result.detected_patterns[:3])}")
            print()
    
    # Run comprehensive testing
    print("\n[+] Running comprehensive test against known XSS payloads...")
    test_results = sanitizer.test_payloads()
    
    # Display results
    total_payloads = len(test_results)
    detected_count = sum(1 for r in test_results.values() if r['detected'])
    
    print(f"    Total payloads tested: {total_payloads}")
    print(f"    Detected: {detected_count}")
    print(f"    Detection rate: {(detected_count / total_payloads) * 100:.2f}%")
    
    # Show statistics
    stats = sanitizer.get_statistics()
    print("\n[+] Statistics:")
    print(f"    Total processed: {stats['total_processed']}")
    print(f"    Malicious detected: {stats['malicious_detected']}")
    print(f"    Sanitized count: {stats['sanitized_count']}")
    print(f"    Detection rate: {stats['detection_rate']:.2f}%")
    
    # Generate report
    report = sanitizer.generate_report()
    print("\n[+] Report:")
    print(report)
    
    # Save report to file
    with open('xss_sanitizer_report.json', 'w') as f:
        f.write(report)
    print("\n[+] Report saved to 'xss_sanitizer_report.json'")
    
    # Example of custom rule application
    print("\n[+] Custom Rule Example:")
    custom_rules = [r'custom_pattern', r'block_this_pattern']
    result = sanitizer.sanitize(
        '<script>alert("XSS")</script>', 
        context='html',
        custom_rules=custom_rules
    )
    print(f"    Input: <script>alert('XSS')</script>")
    print(f"    With custom rules: {result.sanitized_payload}")


if __name__ == "__main__":
    main()