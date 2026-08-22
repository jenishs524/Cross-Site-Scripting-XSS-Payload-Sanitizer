# 🛡️ Context-Aware Cross-Site Scripting (XSS) Payload Sanitizer

[![Python 3.8+](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/downloads/)
[![Security Level](https://img.shields.io/badge/security-Application--Level-red.svg)](#)
[![OWASP Top 10](https://img.shields.io/badge/OWASP-A03%3A2021--Injection%20(XSS)-green.svg)](https://owasp.org/)

An advanced, context-aware input sanitizer and XSS detection engine written in Python. Performs structural tokenization, recursive obfuscation decoding (URL, Base64, HTML entities), and context-sensitive sanitization to neutralize stored, reflected, and DOM-based XSS attacks.

---

## 📌 Executive Overview

Basic regex filters and simple HTML entity encoding are easily bypassed using multi-layer encoding, attribute contexts, or inline event handlers.

This sanitizer implements context-aware sanitization based on where user input is placed:
1. **HTML Body Context**: Encodes HTML special characters (`<`, `>`, `&`, `"`, `'`).
2. **HTML Attribute Context**: Sanitizes quote breakouts, `javascript:` schemes, and inline event handlers (`onload`, `onerror`).
3. **JavaScript Context**: Escapes string literal delimiters and unicode escapes.
4. **URI/URL Context**: Filters dangerous schemes (`javascript:`, `data:`, `vbscript:`).

---

## ✨ Advanced Features

- 🔄 **Recursive Obfuscation Decoding**: Unpacks nested URL-encoding, Base64 encodings, and HTML entity representations to catch evasive payloads.
- 🎯 **Context-Aware Sanitization Rules**: Dynamic sanitization tailored to HTML, Attribute, JavaScript, and URI execution contexts.
- 🔍 **Structural Tokenization Engine**: Parses input streams into HTML/JS structural tokens to identify executable code injections.
- 📑 **Comprehensive Detection Metadata**: Returns detailed diagnostic results including risk scores, detected payload patterns, and sanitized strings.

---

## 🏗️ Sanitization Processing Pipeline

```
 [ Raw User Input ] ──► [ Recursive Decoder ] (Unpacks Base64/URL/HTML Entities)
                              │
                              ▼
                      [ Structural Tokenizer ]
                              │
                              ▼
                      [ Context Classifier ]
           ┌──────────────────┼──────────────────┐
           ▼                  ▼                  ▼
     [ HTML Body ]     [ Attribute ]      [ JavaScript ]
           │                  │                  │
           ▼                  ▼                  ▼
   Entity Escaping      Scheme & Event     Literal & Quote
                       Handler Stripping      Escaping
           └──────────────────┬──────────────────┘
                              │
                              ▼
                      [ Sanitized Output & XSS Detection Report ]
```

---

## 📋 Prerequisites & Setup

- **Python 3.8+** (Standard library only; zero external third-party dependencies required).

---

## 🚀 Usage & Integration Guide

### 1. Direct Execution
```bash
python3 main.py
```

### 2. Programmatic Python Integration
```python
from main import AdvancedXSSSanitizer

sanitizer = AdvancedXSSSanitizer()

# Malicious payload
payload = "<script>alert('XSS')</script>"

# 1. Detect XSS signature
result = sanitizer.detect_xss(payload)
print(f"XSS Detected: {result.is_xss} | Risk Score: {result.risk_score}")

# 2. Context-aware sanitization
clean_body = sanitizer.sanitize_html_body(payload)
clean_attr = sanitizer.sanitize_attribute_context("javascript:alert(1)")

print(f"Clean Body: {clean_body}")
# Output: &lt;script&gt;alert(&#x27;XSS&#x27;)&lt;/script&gt;
```

---

## 📊 Sample Output & Detection Summary

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

## 🛡️ OWASP Alignment & Threat Mitigation Matrix

| Threat Vector | Attack Description | Engine Countermeasure |
|---|---|---|
| **Reflected XSS** | Scripts injected via URL parameters reflected into HTML. | Context-aware HTML entity encoding. |
| **Stored XSS** | Malicious scripts stored in databases rendered to users. | Input tokenization and scheme sanitization before storage. |
| **DOM-based XSS** | Client-side JS manipulates DOM using untrusted sources. | JS literal escaping and URI scheme filtering (`javascript:`). |
