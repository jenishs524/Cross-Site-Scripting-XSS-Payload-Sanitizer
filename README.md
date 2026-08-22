# 🛡️ Context-Aware Cross-Site Scripting (XSS) Payload Sanitizer

An advanced, context-aware input sanitizer and XSS detection engine written in Python. Performs structural tokenization, recursive obfuscation decoding (URL, Base64, HTML entities), and context-sensitive sanitization to neutralize stored, reflected, and DOM-based XSS attacks.

---

## 📌 Overview

Simple regex filters and basic HTML entity encoding are frequently bypassed using multi-layer encoding, attribute contexts, or event handlers.

This sanitizer implements context-aware sanitization based on where user input is placed:
1. **HTML Body Context**: Encodes HTML special characters (`<`, `>`, `&`, `"`, `'`).
2. **HTML Attribute Context**: Sanitizes quote breakouts, `javascript:` schemes, and inline event handlers (`onload`, `onerror`).
3. **JavaScript Context**: Escapes string literal delimiters and unicode escapes.
4. **URI/URL Context**: Filters dangerous schemes (`javascript:`, `data:`, `vbscript:`).

---

## ✨ Key Features

- 🔄 **Recursive Obfuscation Decoding**: Unpacks nested URL-encoding, Base64 encodings, and HTML entity representations to catch evasive payloads.
- 🎯 **Context-Aware Sanitization Rules**: Dynamic sanitization tailored to HTML, Attribute, JavaScript, and URI execution contexts.
- 🔍 **Structural Tokenization Engine**: Parses input streams into HTML/JS structural tokens to identify executable code injections.
- 📑 **Comprehensive Detection Metadata**: Returns detailed diagnostic results including risk scores, detected payload patterns, and sanitized strings.

---

## 🏗️ Processing Pipeline

```
[ Raw User Input ] ──► [ Recursive Decoder ] (Unpacks Base64/URL/HTML Entities)
                             │
                             ▼
                     [ Structural Tokenizer ]
                             │
                             ▼
                     [ Context Classifier ]
           ┌─────────────────┼─────────────────┐
           ▼                 ▼                 ▼
     [ HTML Body ]    [ Attribute ]     [ JavaScript ]
           │                 │                 │
           ▼                 ▼                 ▼
   Entity Escaping     Scheme & Event    Literal & Quote
                      Handler Stripping     Escaping
           └─────────────────┬─────────────────┘
                             │
                             ▼
                     [ Sanitized Output & XSS Detection Report ]
```

---

## 📋 Prerequisites & Dependencies

- **Python 3.8+** (Standard library only; no external dependencies needed).

---

## 🚀 How to Use

### 1. Run Interactive & Automated Tests
```bash
python3 main.py
```

### 2. Programmatic Python Integration
```python
from main import AdvancedXSSSanitizer

sanitizer = AdvancedXSSSanitizer()

# Sample malicious input payload
untrusted_input = "<script>alert('XSS')</script>"

# 1. Inspect for XSS payload signatures
result = sanitizer.detect_xss(untrusted_input)
print(f"XSS Detected: {result.is_xss}")
print(f"Risk Score: {result.risk_score}")

# 2. Context-aware sanitization
clean_html = sanitizer.sanitize_html_body(untrusted_input)
clean_attr = sanitizer.sanitize_attribute_context("javascript:alert(1)")

print(f"Clean HTML: {clean_html}")
# Output: &lt;script&gt;alert(&#x27;XSS&#x27;)&lt;/script&gt;
```

---

## 📊 Sample Detection Output

```text
======================================================================
CROSS-SITE SCRIPTING (XSS) PAYLOAD SANITIZER
======================================================================

[*] Testing Obfuscated & Recursive Payloads...
    Payload: %3Cscript%3Ealert(1)%3C/script%3E
    Decoded: <script>alert(1)</script>
    Result: XSS Detected (Score: 10/10)
    Sanitized: &lt;script&gt;alert(1)&lt;/script&gt;
```

---

## 🛡️ Defensive Value

- **Defense-in-Depth**: Secures web apps against bypasses caused by browser rendering quirks and multi-encoding obfuscation.
- **OWASP Recommended Practice**: Aligns with OWASP XSS Prevention Cheat Sheet rules.
