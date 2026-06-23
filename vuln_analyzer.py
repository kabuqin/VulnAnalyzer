#!/usr/bin/env python3
"""
Static web security signal analyzer — enhanced edition.

Input : raw HTTP request/response, HTML, or server-side source snippets
        (one or many files, or stdin).
Output: structured JSON / Markdown / plain-text / SARIF report with
        potential vulnerability findings.

This tool is intentionally non-exploitative: it reports indicators and
defensive verification steps but never generates attack payloads.

Detected vulnerability classes
───────────────────────────────
  XSS                  Cross-Site Scripting
  SQLi                 SQL Injection
  File Upload          Unrestricted File Upload
  SSRF                 Server-Side Request Forgery
  AuthZ Bypass         Broken Object / Function Level Authorization
  Open Redirect        Unvalidated Redirect & Forward
  Path Traversal       Directory Traversal / LFI
  Cmd Injection        OS Command Injection
  XXE                  XML External Entity Injection
  Sensitive Exposure   Secrets / PII / Debug info in responses
  CORS Misconfiguration Overly-permissive cross-origin policy
  Security Hardening   Missing HTTP security response headers
  SSTI                 Server-Side Template Injection (Jinja2 / Twig / Freemarker / Velocity / Pug / etc.)

Java-specific (auto-detected)
───────────────────────────────
  SQL Injection        JDBC / JPA / Hibernate / MyBatis / Spring Data
  Cmd Injection        Runtime.exec / ProcessBuilder
  Path Traversal       File / Paths / Files APIs
  XXE                  DocumentBuilder / SAX / StAX / XStream / JAXB
  Insecure Deserializ. ObjectInputStream / XStream / Jackson / Kryo / SnakeYAML
  SSRF                 URL / HttpURLConnection / RestTemplate / WebClient / OkHttp
  Open Redirect        HttpServletResponse.sendRedirect / Spring MVC redirect
  Cryptography         Weak ciphers, ECB, hardcoded keys/IV, MD5/SHA1, weak TLS
  Sensitive Exposure   Hardcoded credentials, secrets, Basic auth in source
  Log Injection        SLF4J / Log4j with user-controlled input
  AuthZ Bypass         Spring Security misconfigurations, CSRF disabled
  EL Injection         SpEL parseExpression with user input
  Unsafe Reflection    Class.forName / ClassLoader with user-controlled names
""" 

from __future__ import annotations

import argparse
import json
import re
import sys
import time
from dataclasses import dataclass, field
from html.parser import HTMLParser
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

# ──────────────────────────────────────────────────────────────────────────────
# Constants
# ──────────────────────────────────────────────────────────────────────────────

RISK_ORDER: dict[str, int] = {
    "info": 0,
    "low": 1,
    "medium": 2,
    "high": 3,
    "critical": 4,
}

# ── Location helpers ────────────────────────────────────────────────────

def _offset_to_line_col(text: str, offset: int) -> tuple[int, int]:
    """Convert character offset to (line_number, column_number), 1-based."""
    if offset < 0 or offset > len(text):
        return (0, 0)
    line_start = text.rfind("\n", 0, offset) + 1
    line_num = text[:offset].count("\n") + 1
    col = offset - line_start + 1
    return (line_num, col)


def _get_source_line(text: str, offset: int) -> str:
    """Extract the source line containing the given offset."""
    if offset < 0 or offset > len(text):
        return ""
    line_start = text.rfind("\n", 0, offset) + 1
    line_end = text.find("\n", offset)
    if line_end == -1:
        line_end = len(text)
    return text[line_start:line_end].strip()


def _format_location(text: str, offset: int) -> str:
    """Format a human-readable location string from an offset."""
    line, col = _offset_to_line_col(text, offset)
    if line == 0:
        return "unknown"
    return f"第{line}行 第{col}列"

RISK_EMOJI: dict[str, str] = {
    "info": "ℹ️ ",
    "low": "🟡",
    "medium": "🟠",
    "high": "🔴",
    "critical": "🚨",
}

SENSITIVE_PARAM_NAMES: set[str] = {
    "url", "uri", "target", "redirect", "next", "return", "returnurl",
    "callback", "domain", "host", "path", "file", "filename", "template",
    "page", "role", "admin", "user_id", "userid", "account", "tenant", "org",
    "dest", "destination", "redir", "goto", "link", "forward",
}

SQL_PARAM_NAMES: set[str] = {
    "id", "uid", "user", "userid", "account", "order", "sort", "search",
    "q", "query", "where", "filter", "category", "product", "pid", "cid",
    "item", "num", "start", "offset", "limit", "page",
}

UPLOAD_FIELD_NAMES: set[str] = {
    "file", "upload", "avatar", "image", "document", "attachment", "media",
    "photo", "picture", "resume", "cv", "import", "data",
}

SECURITY_HEADERS: dict[str, str] = {
    "content-security-policy":   "Content-Security-Policy",
    "x-frame-options":           "X-Frame-Options",
    "x-content-type-options":    "X-Content-Type-Options",
    "strict-transport-security": "Strict-Transport-Security",
    "referrer-policy":           "Referrer-Policy",
    "permissions-policy":        "Permissions-Policy",
}

# Secret / sensitive data patterns for exposure detection
SECRET_PATTERNS: list[tuple[str, str, str]] = [
    (r"(?i)(?:api[_-]?key|apikey)\s*[:=]\s*['\"]?([A-Za-z0-9\-_]{16,})", "API key pattern", "high"),
    (r"(?i)(?:secret|token|passwd|password)\s*[:=]\s*['\"]?([^\s'\"]{8,})", "Secret/token pattern", "high"),
    (r"(?i)aws[_-]?(?:access[_-]?key|secret)[_-]?(?:id)?\s*[:=]\s*['\"]?([A-Z0-9]{16,})", "AWS credential pattern", "critical"),
    (r"(?i)(?:private[_-]?key|rsa[_-]?key)\s*[:=]", "Private key reference", "critical"),
    (r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----", "PEM private key block", "critical"),
    (r"(?i)(?:Authorization|Bearer)\s*:\s*[A-Za-z0-9\-_\.]{20,}", "Auth token in header/body", "high"),
    (r"\b(?:\d{4}[- ]?){3}\d{4}\b", "Credit card number pattern", "high"),
    (r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b", "Email address (PII)", "info"),
    (r"(?i)(?:ssn|social.?security)\s*[:=]?\s*\d{3}-?\d{2}-?\d{4}", "SSN pattern", "critical"),
    (r"(?i)stack.?trace|traceback|at\s+\w+\.\w+\([\w\.]+:\d+\)", "Stack trace disclosure", "medium"),
    (r"(?i)(?:debug|verbose)\s*[:=]\s*(?:true|1|on|yes)", "Debug mode enabled", "medium"),
    (r"(?i)internal server error|application error|unhandled exception", "Generic error disclosure", "low"),
    (r"(?i)(?:jdbc|mysql|postgresql|mongodb|redis):\/\/[^\s\"'<>]{5,}", "Database connection string", "critical"),
]

# ──────────────────────────────────────────────────────────────────────────────
# PoC / Payload Library
# ──────────────────────────────────────────────────────────────────────────────

class PayloadLib:
    """Common test payloads for various vulnerability types."""

    # XSS
    XSS_BASIC = '<img src=x onerror=alert(1)>'
    XSS_ATTR = '" onmouseover="alert(1)" x="'
    XSS_SCRIPT = '<script>alert(1)</script>'
    
    # SQL Injection
    SQLI_QUOTE = "' OR '1'='1"
    SQLI_UNION = "' UNION SELECT 1,2,3,4-- -"
    SQLI_TIME = "' AND SLEEP(5)-- -"
    SQLI_BLIND = "' AND 1=1-- -"
    
    # Command Injection
    CMD_BASIC = "; id; "
    CMD_PING = "| ping -c 1 127.0.0.1"
    CMD_SLEEP = "&& sleep 5"
    
    # Path Traversal
    PATH_TRAV = "../../../etc/passwd"
    PATH_TRAV_ENCODED = "..%2F..%2F..%2Fetc%2Fpasswd"
    PATH_TRAV_BACKSLASH = "..\\..\\..\\windows\\win.ini"
    
    # SSRF
    SSRF_LOCALHOST = "http://127.0.0.1:8080"
    SSRF_METADATA = "http://169.254.169.254/latest/meta-data/"
    SSRF_INTERNAL = "http://192.168.1.1/"
    
    # Open Redirect
    OPEN_REDIR_JS = "javascript:alert(1)"
    OPEN_REDIR_PROTO = "//attacker.com"
    OPEN_REDIR_DATA = "data:text/html,<script>alert(1)</script>"
    
    # File Upload
    FILE_UPLOAD = "shell.php"
    FILE_UPLOAD_DOUBLE = "shell.php.jpg"
    FILE_UPLOAD_NULL = "shell.php%00.jpg"
    
    @classmethod
    def get_payload(cls, vuln_type: str, param_name: str = "", value: str = "") -> str:
        """Get appropriate payload for vulnerability type."""
        payload_map = {
            "XSS": cls.XSS_BASIC,
            "SQL Injection": cls.SQLI_QUOTE,
            "Cmd Injection": cls.CMD_BASIC,
            "Path Traversal": cls.PATH_TRAV,
            "SSRF": cls.SSRF_LOCALHOST,
            "Open Redirect": cls.OPEN_REDIR_PROTO,
        }
        return payload_map.get(vuln_type, "test")

# ──────────────────────────────────────────────────────────────────────────────
# Data model
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class Finding:
    type: str
    location: str
    risk: str
    evidence: str
    verification: str
    confidence: str = "medium"
    tags: list[str] = field(default_factory=list)
    cwe: str = ""        # CWE identifier e.g. "CWE-79"
    owasp: str = ""      # OWASP Top-10 ref e.g. "A03:2021"
    poc: str = ""        # Proof-of-concept payload or test case
    line: int = 0        # 1-based line number in source
    col: int = 0         # 1-based column number in source
    source_line: str = ""  # The actual source code line

    def key(self) -> tuple[str, str, str]:
        return (self.type, self.location, self.evidence)

    def to_json(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "type": self.type,
            "location": self.location,
            "risk": self.risk,
            "confidence": self.confidence,
            "evidence": self.evidence,
            "verification": self.verification,
            "tags": self.tags,
        }
        if self.cwe:
            result["cwe"] = self.cwe
        if self.owasp:
            result["owasp"] = self.owasp
        if self.poc:
            result["poc"] = self.poc
        if self.line:
            result["line"] = self.line
            result["col"] = self.col
        if self.source_line:
            result["source_line"] = self.source_line
        return result

    def to_text_line(self) -> str:
        parts = [
            f"[{self.risk.upper():8s}]",
            f"[{self.confidence:6s}]",
            f"{self.type:<22s}",
            self.location,
        ]
        return "  ".join(parts)

    def to_markdown_row(self) -> str:
        emoji = RISK_EMOJI.get(self.risk, "")
        cwe_str = f"`{self.cwe}`" if self.cwe else "—"
        tags_str = ", ".join(f"`{t}`" for t in self.tags) if self.tags else "—"
        return (
            f"| {emoji} **{self.risk.upper()}** | {self.type} | {self.location} | "
            f"{self.evidence} | {self.confidence} | {cwe_str} | {tags_str} |"
        )


# ──────────────────────────────────────────────────────────────────────────────
# HTML parser
# ──────────────────────────────────────────────────────────────────────────────

class FormParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.forms: list[dict[str, Any]] = []
        self.scripts: list[dict[str, str]] = []
        self.links: list[dict[str, str]] = []
        self.comments: list[str] = []
        self.current_form: dict[str, Any] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr = {name.lower(): value or "" for name, value in attrs}
        tag = tag.lower()

        if tag == "form":
            self.current_form = {
                "method": attr.get("method", "get").lower(),
                "action": attr.get("action", ""),
                "enctype": attr.get("enctype", "").lower(),
                "inputs": [],
                "autocomplete": attr.get("autocomplete", ""),
            }
            self.forms.append(self.current_form)
            return

        if tag in {"input", "textarea", "select"} and self.current_form is not None:
            self.current_form["inputs"].append({
                "tag": tag,
                "name": attr.get("name", ""),
                "type": attr.get("type", "text").lower(),
                "accept": attr.get("accept", ""),
                "autocomplete": attr.get("autocomplete", ""),
            })
            return

        if tag == "script":
            self.scripts.append({"src": attr.get("src", "")})
            return

        if tag in {"a", "iframe", "img", "script", "link"}:
            href = attr.get("href") or attr.get("src") or ""
            if href:
                self.links.append({"tag": tag, "url": href})

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "form":
            self.current_form = None

    def handle_comment(self, data: str) -> None:
        self.comments.append(data.strip())


# ──────────────────────────────────────────────────────────────────────────────
# HTTP message parser & parameter extraction
# ──────────────────────────────────────────────────────────────────────────────

def parse_http_message(text: str) -> dict[str, Any]:
    lines = text.replace("\r\n", "\n").split("\n")
    start_line = lines[0].strip() if lines else ""
    headers: dict[str, list[str]] = {}
    body_start = 0

    for index, line in enumerate(lines[1:], start=1):
        if not line.strip():
            body_start = index + 1
            break
        if ":" in line:
            name, value = line.split(":", 1)
            headers.setdefault(name.strip().lower(), []).append(value.strip())

    body = "\n".join(lines[body_start:]) if body_start else ""
    method = target = status_code = ""

    request_match = re.match(
        r"^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|TRACE|CONNECT)\s+(\S+)",
        start_line, re.I,
    )
    response_match = re.match(r"^HTTP/\d(?:\.\d)?\s+(\d{3})", start_line, re.I)
    if request_match:
        method = request_match.group(1).upper()
        target = request_match.group(2)
    elif response_match:
        status_code = response_match.group(1)

    return {
        "start_line": start_line,
        "headers": headers,
        "body": body,
        "method": method,
        "target": target,
        "status_code": status_code,
    }


def extract_params(message: dict[str, Any], text: str) -> list[dict[str, str]]:
    params: list[dict[str, str]] = []
    parsed_pairs: set[tuple[str, str]] = set()
    parsed_names: set[str] = set()

    target = message.get("target") or ""
    if target:
        parsed = urlparse(target)
        for name, values in parse_qs(parsed.query, keep_blank_values=True).items():
            for value in values:
                params.append({"location": f"query parameter '{name}'", "name": name, "value": value})
                parsed_pairs.add((name, value))
                parsed_names.add(name)

    content_type = ",".join(message.get("headers", {}).get("content-type", [])).lower()
    body = message.get("body") or ""
    if "application/x-www-form-urlencoded" in content_type:
        for name, values in parse_qs(body, keep_blank_values=True).items():
            for value in values:
                params.append({"location": f"body parameter '{name}'", "name": name, "value": value})
                parsed_pairs.add((name, value))
                parsed_names.add(name)

    for match in re.finditer(r"(?<![\w-])([A-Za-z_][\w-]{1,40})=([^&\s<>\"']{0,120})", text):
        name, value = match.group(1), match.group(2)
        if name in parsed_names or (name, value) in parsed_pairs:
            continue
        location = f"text parameter-like token '{name}'"
        if not any(item["location"] == location and item["value"] == value for item in params):
            params.append({"location": location, "name": name, "value": value})

    return params


# ──────────────────────────────────────────────────────────────────────────────
# Analyser functions
# ──────────────────────────────────────────────────────────────────────────────

def analyze_xss(
    text: str,
    html: FormParser,
    message: dict[str, Any],
    params: list[dict[str, str]],
) -> list[Finding]:
    findings: list[Finding] = []
    lowered = text.lower()

    dangerous_js = [
        (r"\.innerHTML\s*=",                       "DOM sink: innerHTML assignment"),
        (r"\.outerHTML\s*=",                       "DOM sink: outerHTML assignment"),
        (r"document\.write\s*\(",                  "DOM sink: document.write()"),
        (r"eval\s*\(",                             "DOM sink: eval()"),
        (r"setTimeout\s*\(\s*[^,\n]+[,)]",         "DOM sink: string-like setTimeout()"),
        (r"setInterval\s*\(\s*['\"]",              "DOM sink: string-like setInterval()"),
        (r"location\.hash",                        "DOM source: location.hash"),
        (r"location\.search",                      "DOM source: location.search"),
        (r"location\.href\s*=",                    "DOM sink: location.href assignment"),
        (r"insertAdjacentHTML\s*\(",               "DOM sink: insertAdjacentHTML()"),
        (r"\.setAttribute\s*\(\s*['\"]on\w+['\"]","DOM sink: setAttribute with event handler"),
        (r"new\s+Function\s*\(",                   "DOM sink: new Function()"),
        (r"URLSearchParams\s*\(",                  "DOM source: URLSearchParams — attacker-controlled GET params"),
        (r"new\s+URL\s*\(",                        "DOM source: new URL() — may expose user-controlled data"),
        (r"window\.location\.(search|hash|href)",  "DOM source: window.location (search/hash/href)"),
    ]
    for pattern, evidence in dangerous_js:
        for match in re.finditer(pattern, text, re.I):
            findings.append(Finding(
                type="XSS",
                location=f"source offset {match.start()}",
                risk="medium",
                confidence="medium",
                evidence=evidence,
                verification=(
                    "Check whether untrusted input reaches this sink and confirm "
                    "context-aware output encoding or sanitisation is applied."
                ),
                tags=["client-side", "dom-xss"],
                cwe="CWE-79",
                owasp="A03:2021",
            ))

    if "<script" in lowered and any(m in lowered for m in ("{{", "${", "<%=", "<?=", "#{", "@{")):
        findings.append(Finding(
            type="XSS",
            location="HTML template/script block",
            risk="medium",
            confidence="low",
            evidence="Template expression appears near script-capable HTML.",
            verification="Ensure template variables are context-encoded for HTML, attribute, URL, and JS contexts.",
            tags=["template", "output-encoding"],
            cwe="CWE-79",
            owasp="A03:2021",
        ))

    response_headers = message.get("headers", {})
    if message.get("status_code") and "content-security-policy" not in response_headers and "<script" in lowered:
        findings.append(Finding(
            type="XSS",
            location="HTTP response headers",
            risk="low",
            confidence="medium",
            evidence="Script-capable response has no Content-Security-Policy header.",
            verification="Apply a restrictive CSP via response header or middleware.",
            tags=["headers", "defense-in-depth"],
            cwe="CWE-79",
            owasp="A03:2021",
        ))

    for comment in html.comments:
        c = comment.lower()
        if any(k in c for k in ("todo", "fixme", "hack", "password", "secret", "key", "debug", "remove")):
            findings.append(Finding(
                type="XSS",
                location="HTML comment",
                risk="info",
                confidence="medium",
                evidence=f"Sensitive keyword in HTML comment: {comment[:80]}",
                verification="Remove comments containing internal notes, credentials, or TODOs before deployment.",
                tags=["information-disclosure"],
                cwe="CWE-615",
                owasp="A05:2021",
            ))

    for param in params:
        value = param["value"].lower()
        if any(t in value for t in ("<", ">", "script", "onerror", "onload", "javascript:", "vbscript:")):
            poc = f"Test injection in {param['name']}: {PayloadLib.XSS_BASIC}"
            findings.append(Finding(
                type="XSS",
                location=param["location"],
                risk="medium",
                confidence="medium",
                evidence="Parameter contains script-like or HTML-like characters.",
                verification="Safely test reflection in a controlled environment and confirm context-aware encoding.",
                tags=["input-reflection"],
                cwe="CWE-79",
                owasp="A03:2021",
                poc=poc,
            ))

    # ── Taint chain: detect DOM source→sink pairs in same JS context ──
    dom_sources = [
        r"URLSearchParams\s*\(",
        r"location\.search",
        r"location\.hash",
        r"location\.href",
        r"window\.location",
        r"params\.get\s*\(",
    ]
    dom_sinks = [
        r"\.innerHTML\s*=",
        r"\.outerHTML\s*=",
        r"document\.write\s*\(",
        r"eval\s*\(",
        r"insertAdjacentHTML\s*\(",
    ]
    source_matches = set()
    for pat in dom_sources:
        for m in re.finditer(pat, text, re.I):
            source_matches.add(m.start())
    sink_matches = set()
    for pat in dom_sinks:
        for m in re.finditer(pat, text, re.I):
            sink_matches.add(m.start())

    if source_matches and sink_matches:
        # Find the nearest source-to-sink pairs within reasonable distance
        for sink_pos in sorted(sink_matches):
            # Look for any source position before this sink
            preceding_sources = [s for s in source_matches if s < sink_pos]
            if preceding_sources:
                nearest_source = max(preceding_sources)
                # Only flag if source is within 1000 chars (same function scope)
                if sink_pos - nearest_source < 1000:
                    snippet = text[max(0, nearest_source - 20):sink_pos + 30]
                    findings.append(Finding(
                        type="XSS",
                        location=f"source offset {nearest_source} → sink offset {sink_pos}",
                        risk="high",
                        confidence="medium",
                        evidence=f"Taint chain: DOM source reaches DOM sink (potential XSS). Snippet: ...{snippet.strip()[:80]}...",
                        verification=(
                            "Trace the full data flow from the DOM source (URL param, hash, etc.) "
                            "to this DOM sink. Ensure untrusted data is never assigned to innerHTML, "
                            "outerHTML, or eval() without proper encoding/sanitisation."
                        ),
                        tags=["client-side", "dom-xss", "taint-chain"],
                        cwe="CWE-79",
                        owasp="A03:2021",
                    ))

    return findings


def analyze_sql_injection(text: str, params: list[dict[str, str]]) -> list[Finding]:
    findings: list[Finding] = []
    sql_error_markers = [
        "sql syntax", "mysql_fetch", "ora-", "postgresql error",
        "sqlite error", "unclosed quotation mark", "odbc driver",
        "jdbc", "syntax error in query", "you have an error in your sql",
        "pg_query()", "mssql_", "division by zero",
    ]
    lowered = text.lower()
    for marker in sql_error_markers:
        if marker in lowered:
            findings.append(Finding(
                type="SQL Injection",
                location="HTTP response/body",
                risk="high",
                confidence="high",
                evidence=f"Database error marker observed: '{marker}'",
                verification="Reproduce in a non-production environment; ensure parameterised statements and generic error handling.",
                tags=["error-disclosure", "database"],
                cwe="CWE-89",
                owasp="A03:2021",
            ))

    dynamic_sql_patterns = [
        (r"select\s+.+\s+from\s+.+\s*\+",                              "SQL string concatenation near SELECT"),
        (r"where\s+.+\s*\+\s*[\w'\"]+",                                 "String concatenation near WHERE clause"),
        (r"(execute|query)\s*\(\s*[\"'`].*(select|insert|update|delete)", "Inline SQL passed to query/execute"),
        (r"\$\{[^}]+\}.*\b(select|where|order by)\b",                   "Template interpolation near SQL keyword"),
        (r'(?:f"|f\').*\b(select|insert|update|delete|where)\b',        "f-string with SQL keyword (Python)"),
        (r"String\.format\s*\(.*(?:select|where)",                       "String.format with SQL keyword"),
        (r"sprintf\s*\(.*(?:select|where|from)",                         "sprintf with SQL keyword"),
    ]
    for pattern, evidence in dynamic_sql_patterns:
        for match in re.finditer(pattern, text, re.I | re.S):
            findings.append(Finding(
                type="SQL Injection",
                location=f"source offset {match.start()}",
                risk="high",
                confidence="medium",
                evidence=evidence,
                verification="Trace input into the query and verify prepared statements or safe query builders are used.",
                tags=["source-code", "database"],
                cwe="CWE-89",
                owasp="A03:2021",
            ))

    for param in params:
        name = param["name"].lower()
        value = param["value"].lower()
        if name in SQL_PARAM_NAMES or any(t in value for t in ("'", '"', " or ", " and ", " union ", "--", "#", "/*")):
            risk = "medium" if name in SQL_PARAM_NAMES else "high"
            findings.append(Finding(
                type="SQL Injection",
                location=param["location"],
                risk=risk,
                confidence="low",
                evidence="Parameter name or value suggests database-backed filtering.",
                verification="Confirm server uses typed parameters, allowlisted sort fields, and prepared statements.",
                tags=["input-validation", "database"],
                cwe="CWE-89",
                owasp="A03:2021",
            ))

    return findings


def analyze_uploads(html: FormParser, message: dict[str, Any], text: str) -> list[Finding]:
    findings: list[Finding] = []
    content_type = ",".join(message.get("headers", {}).get("content-type", [])).lower()
    has_multipart = "multipart/form-data" in content_type

    for index, form in enumerate(html.forms, start=1):
        file_inputs = [
            item for item in form["inputs"]
            if item["type"] == "file" or item["name"].lower() in UPLOAD_FIELD_NAMES
        ]
        if not file_inputs:
            continue
        accept_values = [item["accept"] for item in file_inputs if item.get("accept")]
        has_accept = bool(accept_values)
        risk = "high" if not has_accept else "medium"
        findings.append(Finding(
            type="File Upload",
            location=f"HTML form #{index} action='{form['action'] or '(current URL)'}'",
            risk=risk,
            confidence="medium",
            evidence="File upload control detected" + (
                f" with accept='{','.join(accept_values)}'" if has_accept
                else " without client-side accept filter"
            ),
            verification=(
                "Verify server-side extension allowlist, MIME sniffing, content inspection, "
                "size limits, randomised storage names, and non-executable storage location."
            ),
            tags=["upload", "form"],
            cwe="CWE-434",
            owasp="A04:2021",
        ))

    if has_multipart:
        findings.append(Finding(
            type="File Upload",
            location="HTTP request Content-Type",
            risk="medium",
            confidence="medium",
            evidence="multipart/form-data request detected.",
            verification="Confirm server-side validation is independent of client-supplied filename and Content-Type.",
            tags=["upload", "http-request"],
            cwe="CWE-434",
            owasp="A04:2021",
        ))

    upload_keywords = re.search(
        r"\b(move_uploaded_file|multer|formidable|busboy|FileField|MultipartFile|saveAs|"
        r"UploadedFile|request\.files|werkzeug\.FileStorage)\b",
        text, re.I,
    )
    if upload_keywords:
        findings.append(Finding(
            type="File Upload",
            location=f"source offset {upload_keywords.start()}",
            risk="medium",
            confidence="medium",
            evidence=f"Upload handling API observed: {upload_keywords.group(1)}",
            verification="Review storage path, allowed content types, antivirus scanning, and access controls for uploaded objects.",
            tags=["source-code", "upload"],
            cwe="CWE-434",
            owasp="A04:2021",
        ))

    return findings


def analyze_ssrf(text: str, params: list[dict[str, str]], html: FormParser) -> list[Finding]:
    findings: list[Finding] = []
    url_fetch_patterns = [
        (r"\b(requests|urllib|httpx|curl|wget|fetch|axios|guzzle|resttemplate)\b",
         "HTTP client/fetching API observed"),
        (r"\b(openUrl|openConnection|WebClient|HttpClient|URLConnection|HttpURLConnection)\b",
         "URL connection API observed"),
        (r"\b(file_get_contents|readfile|fopen)\b",
         "PHP file/URL read function observed"),
    ]

    # ── Chained SSRF: fetch result field used in another fetch (dataUrl pattern) ──
    # Pattern: a .dataUrl/.url property reference used inside a fetch() call
    fetch_chain = re.finditer(
        r"fetch\s*\([^)]*\w+\.(?:dataUrl|downloadUrl|fileUrl|url|location)\b",
        text, re.I,
    )
    for match in fetch_chain:
        findings.append(Finding(
            type="SSRF",
            location=f"source offset {match.start()}",
            risk="high",
            confidence="medium",
            evidence="Chained SSRF: fetch response field used as URL in subsequent fetch — possible SSRF amplification.",
            verification=(
                "Verify the first API response is strictly validated before its fields are "
                "used as URLs for further fetches. An attacker who controls the first API's "
                "response can force the client to fetch arbitrary internal/external URLs."
            ),
            tags=["client-side", "ssrf-chain", "source-code"],
            cwe="CWE-918",
            owasp="A10:2021",
        ))

    # ── Template literal injection in fetch URLs ──
    template_fetch = re.finditer(
        r"(?:fetch|axios|open|request)\s*\(\s*(?:['\"`][^'\"`]*['\"`]\s*\+\s*|`[^`]*\$\{)",
        text, re.I,
    )
    for match in template_fetch:
        findings.append(Finding(
            type="SSRF",
            location=f"source offset {match.start()}",
            risk="high",
            confidence="medium",
            evidence="Template literal or string concatenation in fetch URL — potential URL injection.",
            verification=(
                "Ensure user-controlled variables in fetch URLs are validated against an "
                "allowlist. URL concatenation with unsanitized input enables path traversal, "
                "SSRF, or redirect attacks."
            ),
            tags=["client-side", "url-injection", "source-code"],
            cwe="CWE-918",
            owasp="A10:2021",
        ))
    for pattern, evidence in url_fetch_patterns:
        for match in re.finditer(pattern, text, re.I):
            findings.append(Finding(
                type="SSRF",
                location=f"source offset {match.start()}",
                risk="medium",
                confidence="low",
                evidence=evidence,
                verification=(
                    "Trace whether user-controlled URLs reach this network call; "
                    "verify scheme, host, DNS, redirect, and private-network restrictions."
                ),
                tags=["source-code", "outbound-request"],
                cwe="CWE-918",
                owasp="A10:2021",
            ))

    private_ip_re = re.compile(
        r"https?://(?:127\.\d+\.\d+\.\d+|10\.\d+\.\d+\.\d+|"
        r"192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|"
        r"169\.254\.\d+\.\d+|::1|localhost|0\.0\.0\.0|metadata\.google\.internal"
        r"|169\.254\.169\.254)",
        re.I,
    )
    for match in private_ip_re.finditer(text):
        findings.append(Finding(
            type="SSRF",
            location=f"text offset {match.start()}",
            risk="high",
            confidence="medium",
            evidence=f"Private/internal host URL found: {match.group()[:60]}",
            verification="Confirm this is not reachable via user-supplied input; block private IP ranges server-side.",
            tags=["internal-reference", "cloud-metadata"],
            cwe="CWE-918",
            owasp="A10:2021",
        ))

    for param in params:
        name = param["name"].lower()
        value = param["value"].lower()
        if name in SENSITIVE_PARAM_NAMES and (
            "http://" in value or "https://" in value or
            name in {"url", "uri", "target", "callback"}
        ):
            findings.append(Finding(
                type="SSRF",
                location=param["location"],
                risk="high" if name in {"url", "uri", "target", "callback"} else "medium",
                confidence="medium",
                evidence="URL-like user-controlled parameter detected.",
                verification="Ensure the server never fetches arbitrary user-supplied URLs without strict allowlisting.",
                tags=["input-validation", "outbound-request"],
                cwe="CWE-918",
                owasp="A10:2021",
            ))

    for link in html.links:
        parsed = urlparse(link["url"])
        if parsed.scheme in {"http", "https"} and parsed.hostname in {
            "localhost", "127.0.0.1", "0.0.0.0", "::1",
        }:
            findings.append(Finding(
                type="SSRF",
                location=f"HTML {link['tag']} URL",
                risk="low",
                confidence="low",
                evidence="Internal host reference in page markup.",
                verification="Check whether this is a static client-side reference or consumed by a server-side fetch.",
                tags=["internal-reference"],
                cwe="CWE-918",
                owasp="A10:2021",
            ))

    return findings


def analyze_authz_bypass(
    text: str,
    message: dict[str, Any],
    params: list[dict[str, str]],
) -> list[Finding]:
    findings: list[Finding] = []
    target = message.get("target") or ""
    lowered_target = target.lower()
    headers = message.get("headers", {})

    sensitive_paths = [
        "/admin", "/manage", "/internal", "/debug", "/api/users", "/api/user",
        "/settings", "/dashboard", "/console", "/superuser", "/root", "/sys",
        "/api/admin", "/__debug__", "/actuator", "/metrics", "/health",
    ]
    if any(path in lowered_target for path in sensitive_paths):
        has_auth = any(name in headers for name in ("authorization", "cookie", "x-api-key", "x-auth-token"))
        findings.append(Finding(
            type="Authorization Bypass",
            location=f"HTTP target '{target}'",
            risk="high" if not has_auth else "medium",
            confidence="medium",
            evidence="Sensitive route observed" + (
                " without obvious auth header." if not has_auth
                else " with client-provided auth context."
            ),
            verification="Verify object-level and function-level authorisation on the server for every role and tenant.",
            tags=["access-control", "routing"],
            cwe="CWE-285",
            owasp="A01:2021",
        ))

    for param in params:
        name = param["name"].lower()
        if name in {"role", "admin", "is_admin", "user_id", "userid", "tenant", "org", "account", "group", "privilege"}:
            findings.append(Finding(
                type="Authorization Bypass",
                location=param["location"],
                risk="high" if name in {"role", "admin", "is_admin", "privilege"} else "medium",
                confidence="medium",
                evidence="Client-controlled authorisation or object identifier parameter detected.",
                verification="Derive permissions from trusted session state; enforce object ownership server-side.",
                tags=["idor", "access-control"],
                cwe="CWE-639",
                owasp="A01:2021",
            ))

    authz_patterns = [
        (r"if\s*\(\s*(isAdmin|admin|role|is_admin)\s*\)",                "Simple role/admin branch"),
        (r"req\.(query|body|params)\.(user_id|userid|role|admin|tenant)", "Auth-sensitive field read from request"),
        (r"@PreAuthorize|authorize\(|canAccess|hasPermission|hasRole",    "Authorisation check keyword"),
        (r"if\s*\(.*==\s*['\"]admin['\"]",                               "Hardcoded admin string comparison"),
    ]
    for pattern, evidence in authz_patterns:
        for match in re.finditer(pattern, text, re.I):
            findings.append(Finding(
                type="Authorization Bypass",
                location=f"source offset {match.start()}",
                risk="medium",
                confidence="low",
                evidence=evidence,
                verification="Review negative test cases for lower-privileged users and cross-object access.",
                tags=["source-code", "access-control"],
                cwe="CWE-285",
                owasp="A01:2021",
            ))

    return findings


def analyze_open_redirect(
    text: str,
    message: dict[str, Any],
    params: list[dict[str, str]],
) -> list[Finding]:
    findings: list[Finding] = []

    redirect_params = {
        "redirect", "redirect_url", "redirecturl", "return", "returnurl",
        "next", "goto", "dest", "destination", "url", "target", "redir",
        "forward", "link", "callback",
    }
    for param in params:
        name = param["name"].lower()
        value = param["value"].lower()
        if name in redirect_params:
            risk = "medium"
            if value.startswith("http") or value.startswith("//") or "%" in value:
                risk = "high"
            findings.append(Finding(
                type="Open Redirect",
                location=param["location"],
                risk=risk,
                confidence="medium" if risk == "high" else "low",
                evidence=f"Redirect-related parameter '{param['name']}' with value '{param['value'][:60]}'",
                verification=(
                    "Ensure redirects only go to allowlisted, same-origin, or relative paths. "
                    "Never reflect an arbitrary user-supplied URL."
                ),
                tags=["redirect", "input-validation"],
                cwe="CWE-601",
                owasp="A01:2021",
            ))

    redirect_code_patterns = [
        (r"header\s*\(\s*['\"]Location:\s*['\"]?\s*\.\s*\$", "PHP header Location with concatenated variable"),
        (r"res\.redirect\s*\(\s*req\.\w+",                   "Express res.redirect() using request data"),
        (r"HttpResponseRedirect\s*\(\s*request\.",            "Django HttpResponseRedirect with request data"),
        (r"return\s+redirect\s*\(\s*request\.",               "Flask/Django redirect() with request data"),
        (r"window\.location\s*=\s*(?:location|document|window|req)", "JS location assignment from input"),
    ]
    for pattern, evidence in redirect_code_patterns:
        for match in re.finditer(pattern, text, re.I):
            findings.append(Finding(
                type="Open Redirect",
                location=f"source offset {match.start()}",
                risk="high",
                confidence="medium",
                evidence=evidence,
                verification="Validate redirect destination against an allowlist; reject external or scheme-relative URLs.",
                tags=["source-code", "redirect"],
                cwe="CWE-601",
                owasp="A01:2021",
            ))

    # Detect 3xx responses with Location header
    if message.get("status_code", "").startswith("3"):
        loc = message.get("headers", {}).get("location", [])
        if loc and any(l.startswith("http") for l in loc):
            findings.append(Finding(
                type="Open Redirect",
                location="HTTP response Location header",
                risk="info",
                confidence="low",
                evidence=f"3xx redirect to external URL: {loc[0][:80]}",
                verification="Verify this redirect target is intentional and cannot be influenced by user input.",
                tags=["redirect", "response"],
                cwe="CWE-601",
                owasp="A01:2021",
            ))

    return findings


def analyze_path_traversal(
    text: str,
    params: list[dict[str, str]],
) -> list[Finding]:
    findings: list[Finding] = []

    traversal_values = re.compile(
        r"(?:\.\./|\.\.\\|%2e%2e[%/\\]|%252e%252e|\.\.%2f|\.\.%5c|%c0%ae)",
        re.I,
    )
    for param in params:
        if traversal_values.search(param["value"]):
            findings.append(Finding(
                type="Path Traversal",
                location=param["location"],
                risk="high",
                confidence="high",
                evidence=f"Directory traversal sequence in parameter value: '{param['value'][:80]}'",
                verification=(
                    "Canonicalise paths server-side, reject any path that escapes the intended base directory, "
                    "and never pass user input directly to file system APIs."
                ),
                tags=["input-validation", "lfi"],
                cwe="CWE-22",
                owasp="A01:2021",
            ))

    traversal_param_names = {"file", "filename", "path", "filepath", "page", "template", "doc", "include"}
    for param in params:
        if param["name"].lower() in traversal_param_names:
            findings.append(Finding(
                type="Path Traversal",
                location=param["location"],
                risk="medium",
                confidence="low",
                evidence=f"Parameter name '{param['name']}' commonly used in file path operations.",
                verification="Validate and sanitise the value; confirm it cannot reference files outside the intended directory.",
                tags=["input-validation", "lfi"],
                cwe="CWE-22",
                owasp="A01:2021",
            ))

    lfi_code_patterns = [
        (r"include\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)", "PHP include() with superglobal"),
        (r"require\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)", "PHP require() with superglobal"),
        (r"open\s*\(\s*(?:f?string|f['\"]|str\.format|%s)",            "open() with potential user data"),
        (r"fs\.readFile(?:Sync)?\s*\(\s*(?:req\.|path\.join|__dirname.*\+)", "Node.js fs.readFile with request data"),
        (r"Path\.of\s*\(\s*(?:request|param|query)",                   "Java Path.of() with request data"),
    ]
    for pattern, evidence in lfi_code_patterns:
        for match in re.finditer(pattern, text, re.I):
            findings.append(Finding(
                type="Path Traversal",
                location=f"source offset {match.start()}",
                risk="high",
                confidence="medium",
                evidence=evidence,
                verification="Never pass unvalidated user input to file path APIs; use allowlists and canonical path checks.",
                tags=["source-code", "lfi"],
                cwe="CWE-22",
                owasp="A01:2021",
            ))

    return findings


def analyze_command_injection(text: str, params: list[dict[str, str]]) -> list[Finding]:
    findings: list[Finding] = []

    cmd_exec_patterns = [
        (r"\b(os\.system|subprocess\.(run|call|Popen|check_output))\s*\(", "Python OS command execution API"),
        (r"\b(exec|shell_exec|passthru|popen|proc_open|system)\s*\(",     "PHP command execution function"),
        (r"\b(Runtime\.exec|ProcessBuilder)\b",                            "Java process execution API"),
        (r"\bchild_process\.(exec|spawn|execSync|spawnSync)\s*\(",         "Node.js child_process execution"),
        (r"(?i)\b(sh|bash|cmd|powershell)\s+-c\s+",                        "Shell invocation with -c flag"),
        (r"\bpopen\s*\(",                                                   "C popen() call"),
    ]
    for pattern, evidence in cmd_exec_patterns:
        for match in re.finditer(pattern, text, re.I):
            findings.append(Finding(
                type="Cmd Injection",
                location=f"source offset {match.start()}",
                risk="high",
                confidence="low",
                evidence=evidence,
                verification=(
                    "Trace whether user input reaches this call without sanitisation. "
                    "Use parameterised APIs (subprocess list form) and avoid shell=True."
                ),
                tags=["source-code", "rce"],
                cwe="CWE-78",
                owasp="A03:2021",
            ))

    shell_metachar_re = re.compile(r"[;|`$&\(\)]")
    for param in params:
        if shell_metachar_re.search(param["value"]):
            findings.append(Finding(
                type="Cmd Injection",
                location=param["location"],
                risk="high",
                confidence="medium",
                evidence=f"Shell metacharacter(s) detected in parameter value: '{param['value'][:80]}'",
                verification="Strip or reject shell metacharacters server-side; prefer parameterised command APIs.",
                tags=["input-validation", "rce"],
                cwe="CWE-78",
                owasp="A03:2021",
            ))

    return findings


def analyze_xxe(text: str, message: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    content_type = ",".join(message.get("headers", {}).get("content-type", [])).lower()
    body = (message.get("body") or "").lower()
    is_xml = "xml" in content_type or body.lstrip().startswith("<?xml") or "<xml" in body

    if is_xml:
        has_doctype = "<!doctype" in body or "<!entity" in body
        has_external = "system " in body or "public " in body or "http://" in body

        if has_doctype and has_external:
            findings.append(Finding(
                type="XXE",
                location="HTTP request body (XML)",
                risk="critical",
                confidence="high",
                evidence="XML with DOCTYPE and external entity reference detected.",
                verification=(
                    "Disable external entity processing in your XML parser. "
                    "Use SAX or DOM with feature flags: FEATURE_EXTERNAL_GENERAL_ENTITIES=false."
                ),
                tags=["xml", "external-entity"],
                cwe="CWE-611",
                owasp="A05:2021",
            ))
        elif has_doctype:
            findings.append(Finding(
                type="XXE",
                location="HTTP request body (XML)",
                risk="high",
                confidence="medium",
                evidence="XML DOCTYPE declaration detected.",
                verification="Ensure external entity resolution is disabled in the XML parser.",
                tags=["xml", "external-entity"],
                cwe="CWE-611",
                owasp="A05:2021",
            ))
        else:
            findings.append(Finding(
                type="XXE",
                location="HTTP request body (XML)",
                risk="low",
                confidence="low",
                evidence="XML content-type/body detected; parser configuration should be verified.",
                verification="Confirm that your XML parser has external entity and DTD processing disabled.",
                tags=["xml"],
                cwe="CWE-611",
                owasp="A05:2021",
            ))

    xxe_code_patterns = [
        (r"DocumentBuilderFactory",     "Java DocumentBuilderFactory (configure setFeature to disable XXE)"),
        (r"SAXParserFactory",           "Java SAXParserFactory (verify XXE features disabled)"),
        (r"XMLReader",                  "Java XMLReader (verify entity resolution disabled)"),
        (r"libxml_disable_entity_loader","PHP libxml entity loader — confirm it is disabled"),
        (r"etree\.parse|lxml\.etree",   "Python lxml/etree parser (check resolve_entities=False)"),
    ]
    for pattern, evidence in xxe_code_patterns:
        for match in re.finditer(pattern, text, re.I):
            findings.append(Finding(
                type="XXE",
                location=f"source offset {match.start()}",
                risk="medium",
                confidence="low",
                evidence=evidence,
                verification="Verify XXE and DTD processing are explicitly disabled in the parser configuration.",
                tags=["source-code", "xml"],
                cwe="CWE-611",
                owasp="A05:2021",
            ))

    return findings


def analyze_cors(message: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    if not message.get("status_code"):
        return findings

    headers = message.get("headers", {})
    acao = headers.get("access-control-allow-origin", [])
    acac = headers.get("access-control-allow-credentials", [])

    if acao:
        origin_value = acao[0].strip()
        cred_value = acac[0].strip().lower() if acac else ""

        if origin_value == "*":
            risk = "high" if cred_value == "true" else "medium"
            findings.append(Finding(
                type="CORS Misconfiguration",
                location="HTTP response CORS headers",
                risk=risk,
                confidence="high",
                evidence=(
                    f"Access-Control-Allow-Origin: * "
                    + ("with Allow-Credentials: true (credentials ignored by browsers but signals misconfiguration)."
                       if cred_value == "true" else "(wildcard origin).")
                ),
                verification=(
                    "Restrict ACAO to specific trusted origins. "
                    "Never combine wildcard origin with Allow-Credentials: true."
                ),
                tags=["cors", "headers"],
                cwe="CWE-942",
                owasp="A05:2021",
            ))
        elif origin_value and cred_value == "true":
            findings.append(Finding(
                type="CORS Misconfiguration",
                location="HTTP response CORS headers",
                risk="medium",
                confidence="medium",
                evidence=(
                    f"CORS with credentials enabled for origin '{origin_value}'. "
                    "Verify this origin is strictly validated server-side."
                ),
                verification="Ensure the origin allowlist is exact-match; reject null and unexpected origins.",
                tags=["cors", "headers"],
                cwe="CWE-942",
                owasp="A05:2021",
            ))

    vary = headers.get("vary", [])
    if acao and not any("origin" in v.lower() for v in vary):
        findings.append(Finding(
            type="CORS Misconfiguration",
            location="HTTP response headers",
            risk="low",
            confidence="medium",
            evidence="CORS headers present but 'Vary: Origin' is missing — may cause cache poisoning.",
            verification="Add 'Vary: Origin' whenever Access-Control-Allow-Origin is set dynamically.",
            tags=["cors", "cache"],
            cwe="CWE-942",
            owasp="A05:2021",
        ))

    return findings


def analyze_sensitive_exposure(
    text: str,
    message: dict[str, Any],
    html: FormParser,
) -> list[Finding]:
    findings: list[Finding] = []

    for pattern, label, risk in SECRET_PATTERNS:
        for match in re.finditer(pattern, text):
            snippet = match.group()[:80]
            findings.append(Finding(
                type="Sensitive Exposure",
                location=f"text offset {match.start()}",
                risk=risk,
                confidence="medium",
                evidence=f"{label}: '{snippet}'",
                verification=(
                    "Remove or redact sensitive values from responses, logs, and HTML. "
                    "Rotate any exposed credentials immediately."
                ),
                tags=["information-disclosure", "secrets"],
                cwe="CWE-200",
                owasp="A02:2021",
            ))

    # Password fields without autocomplete=off
    for index, form in enumerate(html.forms, start=1):
        for inp in form["inputs"]:
            if inp["type"] == "password" and inp.get("autocomplete", "").lower() not in {"off", "new-password", "current-password"}:
                findings.append(Finding(
                    type="Sensitive Exposure",
                    location=f"HTML form #{index} password field '{inp['name']}'",
                    risk="low",
                    confidence="medium",
                    evidence="Password field without explicit autocomplete restriction.",
                    verification="Set autocomplete='current-password' or 'new-password' (or 'off') on password inputs.",
                    tags=["form", "autocomplete"],
                    cwe="CWE-522",
                    owasp="A02:2021",
                ))

    return findings


def analyze_headers(message: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    if not message.get("status_code"):
        return findings

    headers = message.get("headers", {})
    for header_key, canonical_name in SECURITY_HEADERS.items():
        if header_key not in headers:
            findings.append(Finding(
                type="Security Hardening",
                location="HTTP response headers",
                risk="low",
                confidence="medium",
                evidence=f"Missing {canonical_name} header.",
                verification="Add the header or confirm an equivalent control exists at a proxy/CDN layer.",
                tags=["headers"],
                cwe="CWE-693",
                owasp="A05:2021",
            ))

    # Server version disclosure
    server = headers.get("server", [])
    if server and re.search(r"\d", server[0]):
        findings.append(Finding(
            type="Security Hardening",
            location="HTTP response headers",
            risk="info",
            confidence="high",
            evidence=f"Server header discloses version info: '{server[0]}'",
            verification="Configure the server to suppress or genericise the Server header.",
            tags=["headers", "information-disclosure"],
            cwe="CWE-200",
            owasp="A05:2021",
        ))

    # X-Powered-By disclosure
    xpb = headers.get("x-powered-by", [])
    if xpb:
        findings.append(Finding(
            type="Security Hardening",
            location="HTTP response headers",
            risk="info",
            confidence="high",
            evidence=f"X-Powered-By header discloses technology: '{xpb[0]}'",
            verification="Remove X-Powered-By via server configuration or middleware (e.g. helmet.js hidePoweredBy).",
            tags=["headers", "information-disclosure"],
            cwe="CWE-200",
            owasp="A05:2021",
        ))

    return findings


# ──────────────────────────────────────────────────────────────────────────────
# Java-specific analyser
# ──────────────────────────────────────────────────────────────────────────────

def is_java_source(text: str) -> bool:
    """Heuristic: does the text look like Java source code?"""
    java_signals = [
        r"\bpublic\s+(?:class|interface|enum|record|@interface)\b",
        r"\bimport\s+(?:java|javax|org\.springframework|org\.hibernate|com\.google)\.",
        r"\bprivate\s+(?:static\s+)?(?:final\s+)?[A-Z]",
        r"@(?:Override|Autowired|RequestMapping|GetMapping|PostMapping|Controller|Service|Repository|Entity|Column|Table)\b",
        r"\bSystem\.out\.print",
        r"\bnew\s+[A-Z]\w+\s*\(",
        r"\.class\b",
        r"\bthrows\s+\w+Exception",
    ]
    hits = sum(1 for p in java_signals if re.search(p, text))
    return hits >= 2


def analyze_error_handling(text: str) -> list[Finding]:
    """
    Detect missing or inadequate error handling in JavaScript/TypeScript code.
      - Async functions without try/catch
      - Promise chains without .catch()
      - fetch() calls without error handling
    """
    findings: list[Finding] = []

    # ── Async functions without try/catch or .catch() ──
    async_funcs = re.finditer(
        r"(?:async\s+function\s+\w+\s*\([^)]*\)\s*\{|"
        r"(?:const|let|var)\s+\w+\s*=\s*async\s*\([^)]*\)\s*=>\s*\{)",
        text, re.I,
    )
    for m in async_funcs:
        # Extract the function body to check for error handling
        func_start = m.start()
        # Find opening brace
        brace_start = text.find("{", func_start)
        if brace_start == -1:
            continue
        # Find matching closing brace
        depth = 0
        brace_end = -1
        for i in range(brace_start, len(text)):
            if text[i] == "{":
                depth += 1
            elif text[i] == "}":
                depth -= 1
                if depth == 0:
                    brace_end = i
                    break
        if brace_end == -1:
            continue
        body = text[brace_start:brace_end + 1]

        # Check for try/catch or .catch() inside the function body
        has_try = bool(re.search(r"\btry\s*\{", body))
        has_catch = bool(re.search(r"\.catch\s*\(", body))
        if not has_try and not has_catch:
            # Extract function name for the evidence
            func_name = m.group(0)[:40]
            findings.append(Finding(
                type="Missing Error Handling",
                location=f"source offset {func_start}",
                risk="medium",
                confidence="high",
                evidence=f"Async function without try/catch or .catch(): {func_name}...",
                verification=(
                    "Wrap the async function body in a try/catch block, or append .catch() "
                    "to promise chains, to prevent uncaught rejections from crashing the "
                    "application or leaking stack traces."
                ),
                tags=["client-side", "robustness", "error-handling"],
                owasp="A05:2021",
            ))

    # ── fetch() calls without .catch() ──
    fetch_calls = re.finditer(r"fetch\s*\([^)]+\)", text, re.I)
    for m in fetch_calls:
        start = m.start()
        end = m.end()
        # Look at the next 50 chars for .catch
        tail = text[end:end + 50]
        if ".catch" not in tail and "try" not in tail:
            # Check if this fetch is already inside a function with error handling
            # Simple heuristic: skip if the line already has 'await'
            line_start = text.rfind("\n", 0, start) + 1
            line_end = text.find("\n", end)
            line = text[line_start:line_end if line_end != -1 else len(text)].strip()
            if line.startswith("//") or line.startswith("/*"):
                continue
            confidence = "low" if "await" in tail else "medium"
            findings.append(Finding(
                type="Missing Error Handling",
                location=f"source offset {start}",
                risk="low",
                confidence=confidence,
                evidence=f"fetch() call without .catch() error handler.",
                verification=(
                    "Add .catch() to handle network errors gracefully, or wrap in try/catch "
                    "if using async/await."
                ),
                tags=["client-side", "robustness", "error-handling"],
                owasp="A05:2021",
            ))

    return findings


def analyze_ssti(text: str, params: list[dict[str, str]]) -> list[Finding]:
    """
    Detect Server-Side Template Injection (SSTI) signals.
      - Template engine API calls with user-controlled data
      - Template syntax expressions that may process user input
      - Template injection payloads in parameters
    """
    findings: list[Finding] = []

    # ── Template engine API calls ──
    template_apis = [
        (r"(?:render_template_string|renderTemplateString)\s*\(",           "Python Flask render_template_string()"),
        (r"(?:render|renderToString)\s*\([^)]*\b(request\.|getParameter|fetch|params\.get|req\.\w+)",
                                                                           "Template render() with request data"),
        (r"(?:env|environment|template)\.render\s*\([^)]*\{",              "Template engine .render() with object"),
        (r"\b(template|twig|jade|pug|handlebars|mustache|ejs|nunjucks)\.compile\s*\(",
                                                                           "Template compile() API called"),
        (r"\bTemplate\s*\.\s*process\s*\(",                                "Java Play Template.process()"),
        (r"(?:Velocity|Freemarker|FreeMarker)\.(evaluate|render)\s*\(",    "Java Velocity/Freemarker evaluate/render"),
        (r"new\s+Template\s*\([^)]*\)",                                    "Java Template object creation"),
        (r"\bThymeleaf\b.*\b(process|render|parse)\s*\(",                  "Thymeleaf template processing"),
        (r"\bsmarty\s*->\s*(fetch|display|render|eval)\s*\(",             "PHP Smarty template rendering"),
        (r"\bblade\s*->\s*render\s*\(",                                    "PHP Blade render()"),
        (r"\.render\([^)]*\.(html|twig|ftl|vm|jade|pug|ejs|hbs|mustache)", "Template file render with extension"),
    ]
    for pattern, evidence in template_apis:
        for match in re.finditer(pattern, text, re.I):
            findings.append(Finding(
                type="SSTI",
                location=f"source offset {match.start()}",
                risk="high",
                confidence="medium",
                evidence=evidence,
                verification=(
                    "Verify that user input is never concatenated into template strings. "
                    "Always pass user data as template context variables, never in the template source itself. "
                    "Use sandboxed template environments when possible."
                ),
                tags=["source-code", "ssti", "rce"],
                cwe="CWE-94",
                owasp="A03:2021",
            ))

    # ── Template syntax in code context (potential injection) ──
    template_syntax_patterns = [
        # Jinja2 / Twig / Nunjucks
        (r"\{\{.*?(?:request|params|query|user|input|data|name|id|search|q).*?\}\}", "Jinja2/Twig expression with potential user variable"),
        (r"\{%\s*(?:include|extends|import|from|set)\s+.*?(?:request|user|params|query|input|data)\b",
                                                                                     "Jinja2/Twig directive with dynamic input"),
        # Freemarker / Velocity
        (r"\$\{.*?(?:request|user|params|input|data|name|search|q|id)\}",            "Freemarker/Velocity expression with potential user variable"),
        # Thymeleaf
        (r"(?:th:text|th:utext|th:value|th:attr|data-th-text)\s*=\s*\"[^\"]*?(?:\+\s*|\$\{)[^\"]*?",
                                                                                     "Thymeleaf attribute with expression"),
        # Pebble / Spring EL in templates
        (r"#\{.*?(?:request|user|params|input|data|param)\}",                        "Pebble/Spring EL expression with user variable"),
    ]
    for pattern, evidence in template_syntax_patterns:
        for match in re.finditer(pattern, text, re.I):
            findings.append(Finding(
                type="SSTI",
                location=f"source offset {match.start()}",
                risk="high",
                confidence="low",
                evidence=evidence,
                verification=(
                    "Check whether template content is built from user-controllable strings. "
                    "Template expressions containing user variable names may indicate dynamic template generation, "
                    "which is a common SSTI vector."
                ),
                tags=["template-syntax", "ssti"],
                cwe="CWE-94",
                owasp="A03:2021",
            ))

    # ── SSTI payload patterns in parameters ──
    ssti_payload_re = re.compile(
        r"\{\{.*?(?:config|self|class|__class__|__globals__|popen|import|os|subprocess|eval|exec).*?\}\}|"
        r"\$\{.*?(?:class|Runtime|exec|java|process|cmd)\}|"
        r"#\{.*?(?:class|exec|runtime|java)}",
        re.I,
    )
    for param in params:
        if ssti_payload_re.search(param["value"]):
            findings.append(Finding(
                type="SSTI",
                location=param["location"],
                risk="critical",
                confidence="high",
                evidence=f"SSTI probe payload in parameter '{param['name']}': {param['value'][:80]}",
                verification=(
                    "This parameter appears to contain a template injection probing payload. "
                    "Confirm whether the value is reflected in a server-side template context. "
                    "If yes, it likely indicates confirmed SSTI."
                ),
                tags=["input-validation", "ssti", "exploit-probe"],
                cwe="CWE-94",
                owasp="A03:2021",
            ))

    # ── User-controlled URLs / paths with template extension ──
    template_ext_re = re.compile(
        r"(?:url|uri|path|redirect|next|return|file|template|page)\s*[=:].*?\.(?:twig|ftl|vm|jade|pug|ejs|hbs|mustache|handlebars|tpl|blade\.php)\b",
        re.I,
    )
    for param in params:
        if template_ext_re.search(f"{param['name']}={param['value']}"):
            findings.append(Finding(
                type="SSTI",
                location=param["location"],
                risk="medium",
                confidence="low",
                evidence=f"Parameter '{param['name']}' references a template file path — potential template inclusion.",
                verification=(
                    "Check if user-controlled template file paths are passed to include/render functions. "
                    "This could lead to Local File Inclusion (LFI) or SSTI."
                ),
                tags=["input-validation", "ssti", "lfi"],
                cwe="CWE-94",
                owasp="A03:2021",
            ))

    return findings


def analyze_java(text: str) -> list[Finding]:
    """
    Java-specific static analysis covering:
      - SQL Injection (JDBC / JPA / MyBatis / Spring Data)
      - Command Injection (Runtime / ProcessBuilder)
      - Path Traversal (File / Path / Files APIs)
      - XXE (DocumentBuilder / SAX / JAXB / StAX)
      - Deserialization (ObjectInputStream / XStream / Jackson / Kryo)
      - SSRF (URL / HttpURLConnection / RestTemplate / WebClient)
      - Open Redirect (HttpServletResponse.sendRedirect)
      - Cryptography Weaknesses (weak algos, ECB, static IV, MD5/SHA1 passwords)
      - Hardcoded Secrets (passwords, API keys in source)
      - Insecure Random (java.util.Random for security purposes)
      - Log Injection (SLF4J / Log4j with user input)
      - Spring Security Misconfigurations
      - Reflection / Class Loading risks
      - Expression Language Injection (SpEL)
    """
    if not is_java_source(text):
        return []

    findings: list[Finding] = []

    # ── SQL Injection ──────────────────────────────────────────────────────────
    sqli_patterns = [
        # JDBC string concatenation
        (r'(?:executeQuery|executeUpdate|execute|prepareStatement)\s*\(\s*(?:"|\+)[^)]*\+',
         "JDBC query built by string concatenation", "high", "high"),
        # String.format / + in query variable
        (r'String\s+\w*[Qq]uery\w*\s*=\s*(?:"[^"]*"\s*\+|String\.format\s*\()',
         "SQL query string assembled with concatenation or String.format", "high", "medium"),
        # HQL / JPQL concatenation
        (r'(?:createQuery|createNativeQuery)\s*\(\s*(?:"[^"]*"\s*\+|.*\+\s*\w)',
         "JPA/Hibernate query with concatenation (HQL/JPQL injection risk)", "high", "medium"),
        # MyBatis ${ } interpolation
        (r'\$\{(?!__)[^}]+\}',
         "MyBatis ${} interpolation used instead of #{} — direct SQL injection risk", "high", "high"),
        # Spring JdbcTemplate with +
        (r'jdbcTemplate\.\w+\s*\(\s*(?:"[^"]*"\s*\+|\w+\s*\+)',
         "JdbcTemplate query with string concatenation", "high", "medium"),
        # Criteria API unsafe usage
        (r'criteriaBuilder\.(?:literal|parameter)\s*\(\s*\w+\.get(?:Parameter|Attribute)',
         "CriteriaBuilder with potentially unsafe literal parameter", "medium", "low"),
    ]
    for pattern, evidence, risk, confidence in sqli_patterns:
        for match in re.finditer(pattern, text, re.S):
            findings.append(Finding(
                type="SQL Injection",
                location=f"Java source offset {match.start()}",
                risk=risk,
                confidence=confidence,
                evidence=evidence,
                verification=(
                    "Use PreparedStatement with ? placeholders, JPA named parameters (:param), "
                    "or MyBatis #{} binding. Never concatenate user input into SQL strings."
                ),
                tags=["java", "jdbc", "database"],
                cwe="CWE-89",
                owasp="A03:2021",
            ))

    # ── Command Injection ──────────────────────────────────────────────────────
    cmd_patterns = [
        (r'Runtime\.getRuntime\(\)\.exec\s*\(\s*(?!new\s+String\[)[^)]*\+',
         "Runtime.exec() with string concatenation (command injection risk)", "high", "high"),
        (r'Runtime\.getRuntime\(\)\.exec\s*\(\s*\w',
         "Runtime.exec() call — verify no user input reaches the command", "medium", "low"),
        (r'new\s+ProcessBuilder\s*\([^)]*\+',
         "ProcessBuilder constructed with concatenation", "high", "high"),
        (r'new\s+ProcessBuilder\s*\(\s*(?:Arrays\.asList|List\.of)?\s*\([^)]*request\.',
         "ProcessBuilder receiving data from HTTP request", "high", "high"),
        (r'\.command\s*\(\s*(?:Arrays\.asList|List\.of)?\s*\([^)]*\+',
         "ProcessBuilder.command() with string concatenation", "high", "medium"),
    ]
    for pattern, evidence, risk, confidence in cmd_patterns:
        for match in re.finditer(pattern, text, re.S):
            findings.append(Finding(
                type="Cmd Injection",
                location=f"Java source offset {match.start()}",
                risk=risk,
                confidence=confidence,
                evidence=evidence,
                verification=(
                    "Never pass user-controlled data to Runtime.exec() or ProcessBuilder. "
                    "Use an allowlist of permitted commands and pass arguments as a list, not a shell string."
                ),
                tags=["java", "rce", "process"],
                cwe="CWE-78",
                owasp="A03:2021",
            ))

    # ── Path Traversal ─────────────────────────────────────────────────────────
    path_patterns = [
        (r'new\s+File\s*\(\s*[^)]*(?:request\.|getParameter|getHeader)\s*\([^)]*\)',
         "new File() constructed with HTTP request data", "high", "high"),
        (r'Paths\.get\s*\([^)]*(?:request\.|getParameter|getHeader|param\.|pathVariable)',
         "Paths.get() with HTTP request data", "high", "high"),
        (r'Files\.\w+\s*\(\s*[^)]*(?:request\.|getParameter|getHeader)',
         "Files API called with HTTP request data", "high", "medium"),
        (r'new\s+FileInputStream\s*\([^)]*(?:request\.|getParameter|\+\s*\w)',
         "FileInputStream with potentially user-supplied path", "high", "medium"),
        (r'new\s+FileOutputStream\s*\([^)]*(?:request\.|getParameter|\+\s*\w)',
         "FileOutputStream with potentially user-supplied path", "high", "medium"),
        (r'\.toRealPath\(\)|\.getCanonicalPath\(\)',
         "Path canonicalisation call detected — ensure it is followed by base-directory check", "info", "medium"),
    ]
    for pattern, evidence, risk, confidence in path_patterns:
        for match in re.finditer(pattern, text, re.S):
            findings.append(Finding(
                type="Path Traversal",
                location=f"Java source offset {match.start()}",
                risk=risk,
                confidence=confidence,
                evidence=evidence,
                verification=(
                    "Canonicalise the path with toRealPath() or getCanonicalPath(), then verify "
                    "it starts with the expected base directory. Reject inputs containing '..' sequences."
                ),
                tags=["java", "lfi", "filesystem"],
                cwe="CWE-22",
                owasp="A01:2021",
            ))

    # ── XXE ───────────────────────────────────────────────────────────────────
    xxe_patterns = [
        (r'DocumentBuilderFactory\.newInstance\(\)',
         "DocumentBuilderFactory — must disable external entities and DOCTYPE", "high", "medium"),
        (r'SAXParserFactory\.newInstance\(\)',
         "SAXParserFactory — must disable external entity processing", "high", "medium"),
        (r'XMLInputFactory\.newInstance\(\)',
         "StAX XMLInputFactory — must set IS_SUPPORTING_EXTERNAL_ENTITIES=false", "high", "medium"),
        (r'TransformerFactory\.newInstance\(\)',
         "TransformerFactory — must disable external DTD/stylesheet access", "medium", "medium"),
        (r'new\s+XmlMapper\s*\(\)',
         "Jackson XmlMapper — ensure FEATURE_DISALLOW_DOCTYPE_DECL is set", "medium", "medium"),
        (r'XStream\s+\w+\s*=\s*new\s+XStream\s*\(\)',
         "XStream instantiation — vulnerable to XXE and deserialization without allowlist", "high", "high"),
        (r'Unmarshaller\s+\w+\s*=',
         "JAXB Unmarshaller — verify the underlying parser has XXE disabled", "medium", "low"),
        # Good pattern: feature disabled
        (r'setFeature\s*\(\s*"http://xml\.org/sax/features/external',
         "XML parser feature configuration detected — verify it is set to false", "info", "medium"),
    ]
    for pattern, evidence, risk, confidence in xxe_patterns:
        for match in re.finditer(pattern, text, re.S):
            findings.append(Finding(
                type="XXE",
                location=f"Java source offset {match.start()}",
                risk=risk,
                confidence=confidence,
                evidence=evidence,
                verification=(
                    "Disable external entity processing:\n"
                    "  factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);\n"
                    "  factory.setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", true);\n"
                    "  factory.setFeature(\"http://xml.org/sax/features/external-general-entities\", false);"
                ),
                tags=["java", "xml", "xxe"],
                cwe="CWE-611",
                owasp="A05:2021",
            ))

    # ── Insecure Deserialization ───────────────────────────────────────────────
    deser_patterns = [
        (r'new\s+ObjectInputStream\s*\(',
         "ObjectInputStream instantiation — Java deserialization is dangerous with untrusted data", "critical", "medium"),
        (r'\.readObject\s*\(\)',
         "ObjectInputStream.readObject() call — potential deserialization vulnerability", "critical", "medium"),
        (r'ObjectMapper\s*\(\)\s*(?:(?!\n).)*enableDefaultTyping',
         "Jackson ObjectMapper with enableDefaultTyping — polymorphic deserialization attack surface", "critical", "high"),
        (r'@JsonTypeInfo\s*\([^)]*use\s*=\s*JsonTypeInfo\.Id\.(?:CLASS|MINIMAL_CLASS)',
         "Jackson @JsonTypeInfo with CLASS or MINIMAL_CLASS — unsafe type resolution", "high", "high"),
        (r'new\s+XStream\s*\(\)',
         "XStream — allows arbitrary class instantiation without an allowlist by default", "critical", "high"),
        (r'Kryo\s+\w+\s*=\s*new\s+Kryo\s*\(\)',
         "Kryo instantiation — ensure class registration is enforced (kryo.setRegistrationRequired(true))", "high", "medium"),
        (r'SerializationUtils\.deserialize\s*\(',
         "Apache Commons SerializationUtils.deserialize() — deserializes arbitrary Java objects", "critical", "high"),
        (r'Base64\.(?:getDecoder\(\)\.decode|decodeBase64)\s*\([^)]*\)[^;]*readObject',
         "Base64-decoded data passed to deserialization — common attack vector", "critical", "high"),
        (r'new\s+(?:Yaml|SafeYaml)\s*\(\)',
         "SnakeYAML Yaml() — use SafeConstructor to prevent arbitrary object instantiation", "high", "medium"),
    ]
    for pattern, evidence, risk, confidence in deser_patterns:
        for match in re.finditer(pattern, text, re.S):
            findings.append(Finding(
                type="Insecure Deserialization",
                location=f"Java source offset {match.start()}",
                risk=risk,
                confidence=confidence,
                evidence=evidence,
                verification=(
                    "Never deserialize untrusted data with native Java serialization. "
                    "Use a safer format (JSON with strict schema), apply an allowlist filter "
                    "(e.g. ValidatingObjectInputStream), or use look-ahead deserialization filters (JEP 415)."
                ),
                tags=["java", "deserialization", "rce"],
                cwe="CWE-502",
                owasp="A08:2021",
            ))

    # ── SSRF ──────────────────────────────────────────────────────────────────
    ssrf_patterns = [
        (r'new\s+URL\s*\([^)]*(?:request\.|getParameter|getHeader|\+\s*\w)',
         "new URL() with HTTP request data — potential SSRF", "high", "medium"),
        (r'(?:HttpURLConnection|HttpsURLConnection)\s*\w+\s*=\s*\(.*\)\s*(?:new\s+URL|url)\.',
         "HttpURLConnection opened from a potentially user-influenced URL", "high", "medium"),
        (r'restTemplate\.\w+\s*\([^)]*(?:request\.|getParameter|getHeader|\+\s*\w)',
         "RestTemplate call with HTTP request data", "high", "medium"),
        (r'webClient\.\w+\(\)\s*\.uri\s*\([^)]*(?:request\.|getParameter|param\.|pathVariable)',
         "WebClient URI from HTTP request data", "high", "medium"),
        (r'new\s+URL\s*\(\s*(?:request\.|getParameter|getHeader)',
         "URL constructed directly from request parameter", "high", "high"),
        (r'okHttpClient\.newCall\s*\(\s*new\s+Request\.Builder\(\)\.url\s*\([^)]*\+',
         "OkHttp URL built with concatenation", "high", "medium"),
    ]
    for pattern, evidence, risk, confidence in ssrf_patterns:
        for match in re.finditer(pattern, text, re.S):
            findings.append(Finding(
                type="SSRF",
                location=f"Java source offset {match.start()}",
                risk=risk,
                confidence=confidence,
                evidence=evidence,
                verification=(
                    "Validate URLs against a strict allowlist of permitted hosts and schemes. "
                    "Block private IP ranges and cloud metadata endpoints. "
                    "Disable HTTP redirects or validate redirect targets."
                ),
                tags=["java", "ssrf", "outbound-request"],
                cwe="CWE-918",
                owasp="A10:2021",
            ))

    # ── Open Redirect ─────────────────────────────────────────────────────────
    redirect_patterns = [
        (r'response\.sendRedirect\s*\([^)]*(?:request\.|getParameter|getHeader|\+\s*\w)',
         "HttpServletResponse.sendRedirect() with request data", "high", "high"),
        (r'return\s+"redirect:\s*"\s*\+',
         "Spring MVC 'redirect:' return value with concatenation", "high", "medium"),
        (r'RedirectView\s*\(\s*[^)]*(?:request\.|getParameter|\+)',
         "RedirectView constructed with potentially user-supplied URL", "high", "medium"),
        (r'ResponseEntity\.status\s*\(\s*HttpStatus\.(?:FOUND|MOVED_PERMANENTLY|SEE_OTHER)\s*\)\s*\.location\s*\([^)]*\+',
         "ResponseEntity redirect with concatenated Location URI", "high", "medium"),
    ]
    for pattern, evidence, risk, confidence in redirect_patterns:
        for match in re.finditer(pattern, text, re.S):
            findings.append(Finding(
                type="Open Redirect",
                location=f"Java source offset {match.start()}",
                risk=risk,
                confidence=confidence,
                evidence=evidence,
                verification=(
                    "Validate redirect targets against an allowlist of permitted URLs or paths. "
                    "Reject scheme-relative URLs (//evil.com) and external hosts."
                ),
                tags=["java", "redirect"],
                cwe="CWE-601",
                owasp="A01:2021",
            ))

    # ── Cryptography Weaknesses ────────────────────────────────────────────────
    crypto_patterns = [
        (r'Cipher\.getInstance\s*\(\s*"(?:DES|RC2|RC4|Blowfish|AES/ECB)[^"]*"',
         "Weak or ECB-mode cipher: DES/RC4/AES-ECB are insecure", "high", "high"),
        (r'Cipher\.getInstance\s*\(\s*"AES"\s*\)',
         "AES without explicit mode/padding defaults to ECB in many JVMs — specify AES/GCM/NoPadding", "high", "high"),
        (r'MessageDigest\.getInstance\s*\(\s*"(?:MD5|SHA-?1)"\s*\)',
         "MD5/SHA-1 used for hashing — insufficient for password storage or integrity protection", "high", "high"),
        (r'(?:new\s+)?SecretKeySpec\s*\(\s*"[^"]{1,32}"\.getBytes',
         "Hardcoded secret key material in SecretKeySpec", "critical", "high"),
        (r'(?:IvParameterSpec|GCMParameterSpec)\s*\(\s*"[^"]+"\.getBytes',
         "Hardcoded IV/nonce — must be randomly generated per encryption", "high", "high"),
        (r'new\s+(?:java\.util\.)?Random\s*\(\)',
         "java.util.Random is not cryptographically secure — use SecureRandom for security purposes", "high", "medium"),
        (r'\.nextInt\s*\(\)|\.nextLong\s*\(\)|\.nextBytes\s*\(',
         "Random number generation — confirm SecureRandom is used for tokens/keys/nonces", "medium", "low"),
        (r'SSLContext\.getInstance\s*\(\s*"(?:SSL|SSLv2|SSLv3|TLS|TLSv1(?:\.1)?)"',
         "Obsolete/weak TLS version: use TLSv1.2 or TLSv1.3", "high", "high"),
        (r'KeyPairGenerator\.getInstance\s*\(\s*"RSA"\s*\)[^;]*;(?:[^;]*\n){0,3}[^;]*\.initialize\s*\(\s*(?:512|768|1024)\s*\)',
         "RSA key size below 2048 bits — insufficient for modern security", "high", "medium"),
        (r'TrustAllCerts|TrustManager\s*\[\s*\]\s*\{[^}]*public\s+void\s+checkClient|X509TrustManager[^}]*@Override[^}]*public\s+void\s+check(?:Client|Server)Trusted\s*\([^)]*\)\s*\{\s*\}',
         "Trust-all TrustManager — disables SSL/TLS certificate validation", "critical", "high"),
        (r'\.setHostnameVerifier\s*\(\s*(?:SSLConnectionSocketFactory\.ALLOW_ALL_HOSTNAME_VERIFIER|ALLOW_ALL|allHosts)',
         "Hostname verification disabled — MITM attack possible", "critical", "high"),
        (r'new\s+BCryptPasswordEncoder\s*\(\s*(?:[1-9]|10)\s*\)',
         "BCrypt strength parameter — values below 10 may be too fast for production", "info", "low"),
        (r'MessageDigest\.getInstance\s*\(\s*"SHA-?256"\s*\)[^;]*\.digest\s*\([^)]*password',
         "Plain SHA-256 for password hashing — use BCrypt, SCrypt, or Argon2 instead", "high", "medium"),
    ]
    for pattern, evidence, risk, confidence in crypto_patterns:
        for match in re.finditer(pattern, text, re.S):
            findings.append(Finding(
                type="Cryptography Weakness",
                location=f"Java source offset {match.start()}",
                risk=risk,
                confidence=confidence,
                evidence=evidence,
                verification=(
                    "Use AES-GCM (256-bit key), RSA-OAEP (≥2048 bits), TLSv1.3, "
                    "SecureRandom, and BCrypt/SCrypt/Argon2 for passwords. "
                    "Never hardcode keys or IVs."
                ),
                tags=["java", "cryptography", "weak-algo"],
                cwe="CWE-327",
                owasp="A02:2021",
            ))

    # ── Hardcoded Secrets ─────────────────────────────────────────────────────
    secret_patterns = [
        (r'(?:password|passwd|secret|apiKey|api_key|token|accessKey|privateKey)\s*=\s*"[^"]{4,}"',
         "Hardcoded credential or secret string literal", "critical", "medium"),
        (r'String\s+(?:PASSWORD|SECRET|API_KEY|TOKEN|KEY)\s*=\s*"[^"]+"',
         "Hardcoded constant with security-sensitive name", "critical", "high"),
        (r'\.setPassword\s*\(\s*"[^"]+"',
         "Literal string passed to setPassword()", "high", "high"),
        (r'\.setUsername\s*\(\s*"[^"]+"',
         "Literal string passed to setUsername()", "medium", "medium"),
        (r'BasicAuth(?:entication)?\s*\(\s*"[^"]+"\s*,\s*"[^"]+"',
         "Hardcoded credentials in BasicAuthentication call", "critical", "high"),
        (r'Authorization:\s*Basic\s+[A-Za-z0-9+/=]{10,}',
         "Base64-encoded Basic auth credentials in source", "critical", "high"),
    ]
    for pattern, evidence, risk, confidence in secret_patterns:
        for match in re.finditer(pattern, text, re.S):
            findings.append(Finding(
                type="Sensitive Exposure",
                location=f"Java source offset {match.start()}",
                risk=risk,
                confidence=confidence,
                evidence=evidence,
                verification=(
                    "Load credentials from environment variables, a secrets manager (Vault, AWS Secrets Manager), "
                    "or an encrypted configuration file. Never commit credentials to source control."
                ),
                tags=["java", "hardcoded-secrets", "information-disclosure"],
                cwe="CWE-798",
                owasp="A02:2021",
            ))

    # ── Log Injection ─────────────────────────────────────────────────────────
    log_patterns = [
        (r'(?:log(?:ger)?|LOG)\s*\.\s*(?:info|debug|warn|error|trace|fatal)\s*\([^)]*(?:request\.|getParameter|getHeader|\+\s*\w)',
         "Logger call with HTTP request data — potential log injection", "medium", "medium"),
        (r'(?:log(?:ger)?|LOG)\s*\.\s*(?:info|debug|warn|error)\s*\(\s*"[^"]*\{\}[^"]*"\s*,\s*(?:request\.|getParameter)',
         "SLF4J parameterised log with request data", "medium", "medium"),
    ]
    for pattern, evidence, risk, confidence in log_patterns:
        for match in re.finditer(pattern, text, re.S):
            findings.append(Finding(
                type="Log Injection",
                location=f"Java source offset {match.start()}",
                risk=risk,
                confidence=confidence,
                evidence=evidence,
                verification=(
                    "Sanitise user input before logging: strip newlines (\\n, \\r) and ANSI codes. "
                    "Use a structured logging format (JSON) to prevent log forging."
                ),
                tags=["java", "log-injection"],
                cwe="CWE-117",
                owasp="A09:2021",
            ))

    # ── Spring Security Misconfigurations ─────────────────────────────────────
    spring_sec_patterns = [
        (r'\.permitAll\s*\(\)',
         "permitAll() — verify this endpoint truly requires no authentication", "medium", "low"),
        (r'csrf\s*\(\s*\)\s*\.disable\s*\(\)',
         "CSRF protection disabled in Spring Security configuration", "high", "high"),
        (r'\.authorizeRequests\s*\(\)[^;]*\.anyRequest\s*\(\)\s*\.permitAll',
         "anyRequest().permitAll() — all endpoints are publicly accessible", "high", "high"),
        (r'headers\s*\(\s*\)\s*\.frameOptions\s*\(\s*\)\s*\.disable\s*\(\)',
         "X-Frame-Options disabled in Spring Security — clickjacking risk", "medium", "high"),
        (r'\.cors\s*\(\s*\)\s*\.and\s*\(\)',
         "CORS enabled in Spring Security — verify CorsConfigurationSource is restrictive", "medium", "low"),
        (r'@CrossOrigin\s*\(\s*(?:origins\s*=\s*"\*"|value\s*=\s*"\*")',
         "@CrossOrigin with wildcard origin — overly permissive CORS policy", "high", "high"),
        (r'@CrossOrigin(?!\s*\()',
         "@CrossOrigin without parameters defaults to allowing all origins", "medium", "medium"),
        (r'\.sessionManagement\s*\(\)[^;]*\.sessionCreationPolicy\s*\(\s*SessionCreationPolicy\.STATELESS',
         "Stateless session policy — ensure JWT/token validation is robust", "info", "low"),
        (r'new\s+(?:BCrypt|SCrypt|Pbkdf2)PasswordEncoder\s*\(\s*\)',
         "Password encoder instantiation — confirm strength parameters are production-appropriate", "info", "low"),
        (r'NoOpPasswordEncoder',
         "NoOpPasswordEncoder stores passwords in plain text — never use in production", "critical", "high"),
        (r'@PreAuthorize\s*\(\s*"(?:true|1)"\s*\)',
         "@PreAuthorize(\"true\") — always grants access, effectively disabling the check", "high", "high"),
    ]
    for pattern, evidence, risk, confidence in spring_sec_patterns:
        for match in re.finditer(pattern, text, re.S):
            findings.append(Finding(
                type="Authorization Bypass",
                location=f"Java source offset {match.start()}",
                risk=risk,
                confidence=confidence,
                evidence=f"Spring Security: {evidence}",
                verification=(
                    "Review the Spring Security configuration end-to-end. "
                    "Apply least-privilege: authenticate and authorise every endpoint by default."
                ),
                tags=["java", "spring-security", "access-control"],
                cwe="CWE-285",
                owasp="A01:2021",
            ))

    # ── SpEL / Expression Language Injection ──────────────────────────────────
    spel_patterns = [
        (r'new\s+SpelExpressionParser\s*\(\)',
         "SpEL ExpressionParser instantiation", "medium", "low"),
        (r'expressionParser\.parseExpression\s*\([^)]*(?:request\.|getParameter|getHeader|\+\s*\w)',
         "SpEL parseExpression() with HTTP request data — EL injection risk", "critical", "high"),
        (r'StandardEvaluationContext\s*\(\)',
         "StandardEvaluationContext allows full method invocation — use SimpleEvaluationContext for untrusted input", "high", "medium"),
        (r'@Value\s*\(\s*"#\{[^}]+getParameter',
         "@Value SpEL with getParameter — injection via property source", "high", "medium"),
    ]
    for pattern, evidence, risk, confidence in spel_patterns:
        for match in re.finditer(pattern, text, re.S):
            findings.append(Finding(
                type="EL Injection",
                location=f"Java source offset {match.start()}",
                risk=risk,
                confidence=confidence,
                evidence=evidence,
                verification=(
                    "Never pass user-controlled strings to SpEL parseExpression(). "
                    "Use SimpleEvaluationContext to restrict available types and methods."
                ),
                tags=["java", "spel", "el-injection", "rce"],
                cwe="CWE-917",
                owasp="A03:2021",
            ))

    # ── Reflection / Class Loading ─────────────────────────────────────────────
    reflection_patterns = [
        (r'Class\.forName\s*\([^)]*(?:request\.|getParameter|getHeader|\+\s*\w)',
         "Class.forName() with HTTP request data — unsafe class loading", "critical", "high"),
        (r'(?:ClassLoader|URLClassLoader).*\.loadClass\s*\([^)]*(?:request\.|getParameter|\+)',
         "ClassLoader.loadClass() with user-controlled class name", "critical", "high"),
        (r'Method\s+\w+\s*=\s*\w+\.getMethod\s*\([^)]*(?:request\.|getParameter|\+)',
         "Reflection getMethod() with user input", "high", "medium"),
        (r'\.invoke\s*\([^)]*(?:request\.|getParameter|\+\s*\w)',
         "Method.invoke() with potentially user-controlled arguments", "high", "medium"),
    ]
    for pattern, evidence, risk, confidence in reflection_patterns:
        for match in re.finditer(pattern, text, re.S):
            findings.append(Finding(
                type="Unsafe Reflection",
                location=f"Java source offset {match.start()}",
                risk=risk,
                confidence=confidence,
                evidence=evidence,
                verification=(
                    "Never pass user-controlled strings to Class.forName() or ClassLoader.loadClass(). "
                    "Use an allowlist of permitted class names if dynamic dispatch is required."
                ),
                tags=["java", "reflection", "rce"],
                cwe="CWE-470",
                owasp="A03:2021",
            ))

    return findings


# ──────────────────────────────────────────────────────────────────────────────
# Orchestration
# ──────────────────────────────────────────────────────────────────────────────

def dedupe_findings(findings: list[Finding]) -> list[Finding]:
    deduped: dict[tuple[str, str, str], Finding] = {}
    for finding in findings:
        existing = deduped.get(finding.key())
        if existing is None or RISK_ORDER[finding.risk] > RISK_ORDER[existing.risk]:
            deduped[finding.key()] = finding
    return sorted(
        deduped.values(),
        key=lambda item: (-RISK_ORDER[item.risk], item.type, item.location),
    )


def analyze(
    text: str,
    source_name: str = "stdin",
    enabled_types: set[str] | None = None,
) -> dict[str, Any]:
    t0 = time.perf_counter()
    message = parse_http_message(text)
    html = FormParser()
    html.feed(text)
    params = extract_params(message, text)

    all_findings: list[Finding] = []
    all_findings.extend(analyze_xss(text, html, message, params))
    all_findings.extend(analyze_sql_injection(text, params))
    all_findings.extend(analyze_uploads(html, message, text))
    all_findings.extend(analyze_ssrf(text, params, html))
    all_findings.extend(analyze_authz_bypass(text, message, params))
    all_findings.extend(analyze_open_redirect(text, message, params))
    all_findings.extend(analyze_path_traversal(text, params))
    all_findings.extend(analyze_command_injection(text, params))
    all_findings.extend(analyze_xxe(text, message))
    all_findings.extend(analyze_cors(message))
    all_findings.extend(analyze_sensitive_exposure(text, message, html))
    all_findings.extend(analyze_headers(message))
    all_findings.extend(analyze_error_handling(text))
    all_findings.extend(analyze_ssti(text, params))
    all_findings.extend(analyze_java(text))

    if enabled_types:
        normalized = {t.lower() for t in enabled_types}
        all_findings = [f for f in all_findings if f.type.lower() in normalized]

    deduped = dedupe_findings(all_findings)

    # ── Enrich findings with line/col/source_line ──
    for finding in deduped:
        # Extract offset(s) from location like "source offset 123", "Java source offset 123", or "source offset 100 → sink offset 200"
        offsets = [int(m) for m in re.findall(r"(?:(?:Java )?source offset )(\d+)", finding.location)]
        if offsets:
            primary_offset = offsets[0]
            line, col = _offset_to_line_col(text, primary_offset)
            finding.line = line
            finding.col = col
            finding.source_line = _get_source_line(text, primary_offset)
            # Replace "source offset NNN" or "Java source offset NNN" with human-readable line:col
            if len(offsets) == 1:
                loc_text = _format_location(text, primary_offset)
                finding.location = re.sub(
                    r"(?:Java )?source offset \d+",
                    loc_text,
                    finding.location,
                )
            else:
                # Multi-offset (e.g. taint chain): show both
                parts = re.split(r"\s*→\s*", finding.location)
                new_parts = []
                for p in parts:
                    m = re.search(r"(?:Java )?source offset (\d+)", p)
                    if m:
                        loc_text = _format_location(text, int(m.group(1)))
                        p = re.sub(r"(?:Java )?source offset \d+", loc_text, p)
                    new_parts.append(p)
                finding.location = " → ".join(new_parts)

    counts_by_risk: dict[str, int] = {}
    for finding in deduped:
        counts_by_risk[finding.risk] = counts_by_risk.get(finding.risk, 0) + 1

    elapsed_ms = round((time.perf_counter() - t0) * 1000, 1)

    return {
        "source": source_name,
        "summary": {
            "total_findings": len(deduped),
            "by_risk": counts_by_risk,
            "input_type": classify_input(message, text),
            "scan_ms": elapsed_ms,
        },
        "findings": [f.to_json() for f in deduped],
        "notes": [
            "Results are heuristic and must be validated manually.",
            "Verification guidance is defensive and intentionally omits exploit code.",
        ],
    }


def classify_input(message: dict[str, Any], text: str) -> str:
    if message.get("method"):
        return "http_request"
    if message.get("status_code"):
        return "http_response"
    if "<html" in text.lower() or "<form" in text.lower():
        return "html_or_template"
    if is_java_source(text):
        return "java_source"
    return "source_or_plaintext"


# ──────────────────────────────────────────────────────────────────────────────
# Output formatters
# ──────────────────────────────────────────────────────────────────────────────

def format_json(result: dict[str, Any], pretty: bool = False) -> str:
    return json.dumps(result, ensure_ascii=False, indent=2 if pretty else None)


def format_text(result: dict[str, Any]) -> str:
    lines: list[str] = []
    summary = result["summary"]
    source = result["source"]
    total = summary["total_findings"]
    by_risk = summary.get("by_risk", {})
    scan_ms = summary.get("scan_ms", "?")

    lines.append("=" * 72)
    lines.append(f"  vuln_analyzer  •  {source}")
    lines.append("=" * 72)
    lines.append(f"  Input type : {summary.get('input_type', 'unknown')}")
    lines.append(f"  Scan time  : {scan_ms} ms")
    lines.append(f"  Findings   : {total}  " + "  ".join(
        f"{RISK_EMOJI.get(r, '')} {r.upper()}={n}" for r, n in
        sorted(by_risk.items(), key=lambda x: -RISK_ORDER.get(x[0], 0))
    ))
    lines.append("")

    if not result["findings"]:
        lines.append("  No findings.")
    else:
        lines.append(f"  {'RISK':<10} {'CONF':<8} {'TYPE':<24} LOCATION")
        lines.append("  " + "-" * 68)
        for raw in result["findings"]:
            emoji = RISK_EMOJI.get(raw["risk"], "")
            lines.append(
                f"  {emoji}{raw['risk'].upper():<9} {raw['confidence']:<8} "
                f"{raw['type']:<24} {raw['location']}"
            )
            lines.append(f"    ▸ {raw['evidence']}")
            cwe = raw.get("cwe", "")
            owasp = raw.get("owasp", "")
            meta = "  ".join(filter(None, [cwe, owasp]))
            if meta:
                lines.append(f"    ▸ {meta}")
            lines.append(f"    ✓ {raw['verification']}")
            lines.append("")

    for note in result.get("notes", []):
        lines.append(f"  ⚠  {note}")
    lines.append("=" * 72)
    return "\n".join(lines)


def format_markdown(result: dict[str, Any]) -> str:
    lines: list[str] = []
    summary = result["summary"]
    source = result["source"]
    total = summary["total_findings"]
    by_risk = summary.get("by_risk", {})
    scan_ms = summary.get("scan_ms", "?")

    lines.append(f"# Security Analysis — `{source}`")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append(f"| Attribute | Value |")
    lines.append("|-----------|-------|")
    lines.append(f"| Input type | `{summary.get('input_type', 'unknown')}` |")
    lines.append(f"| Scan time | {scan_ms} ms |")
    lines.append(f"| Total findings | **{total}** |")
    for risk_level in ("critical", "high", "medium", "low", "info"):
        count = by_risk.get(risk_level, 0)
        if count:
            emoji = RISK_EMOJI.get(risk_level, "")
            lines.append(f"| {emoji} {risk_level.capitalize()} | {count} |")
    lines.append("")

    if not result["findings"]:
        lines.append("_No findings._")
    else:
        lines.append("## Findings")
        lines.append("")
        lines.append("| Risk | Type | Location | Evidence | Confidence | CWE | Tags |")
        lines.append("|------|------|----------|----------|------------|-----|------|")
        for raw in result["findings"]:
            emoji = RISK_EMOJI.get(raw["risk"], "")
            cwe_str = f"`{raw.get('cwe', '')}`" if raw.get("cwe") else "—"
            tags_str = " ".join(f"`{t}`" for t in raw.get("tags", [])) or "—"
            owasp_str = raw.get("owasp", "")
            owasp_part = f" / {owasp_str}" if owasp_str else ""
            lines.append(
                f"| {emoji} **{raw['risk'].upper()}** | {raw['type']} | `{raw['location']}` | "
                f"{raw['evidence'][:80]} | {raw['confidence']} | {cwe_str}{owasp_part} | {tags_str} |"
            )
        lines.append("")
        lines.append("## Verification Details")
        lines.append("")
        for i, raw in enumerate(result["findings"], start=1):
            emoji = RISK_EMOJI.get(raw["risk"], "")
            lines.append(f"### {i}. {emoji} [{raw['risk'].upper()}] {raw['type']}")
            lines.append(f"- **Location:** `{raw['location']}`")
            lines.append(f"- **Evidence:** {raw['evidence']}")
            lines.append(f"- **Confidence:** {raw['confidence']}")
            if raw.get("cwe"):
                lines.append(f"- **CWE:** [{raw['cwe']}](https://cwe.mitre.org/data/definitions/{raw['cwe'].replace('CWE-', '')}.html)")
            if raw.get("owasp"):
                lines.append(f"- **OWASP:** {raw['owasp']}")
            lines.append(f"- **How to verify:** {raw['verification']}")
            lines.append("")

    lines.append("---")
    for note in result.get("notes", []):
        lines.append(f"> ⚠️  {note}")

    return "\n".join(lines)


def format_sarif(results: list[dict[str, Any]]) -> str:
    """Emit a minimal SARIF 2.1.0 document for IDE/CI integration."""
    rules: list[dict] = []
    rule_ids_seen: set[str] = set()
    run_results: list[dict] = []

    for result in results:
        source = result.get("source", "unknown")
        for finding in result.get("findings", []):
            rule_id = re.sub(r"[^A-Za-z0-9]", "", finding["type"])
            if rule_id not in rule_ids_seen:
                rule_ids_seen.add(rule_id)
                rules.append({
                    "id": rule_id,
                    "name": finding["type"],
                    "shortDescription": {"text": finding["type"]},
                    "helpUri": (
                        f"https://cwe.mitre.org/data/definitions/"
                        f"{finding.get('cwe', '').replace('CWE-', '')}.html"
                        if finding.get("cwe") else "https://owasp.org"
                    ),
                    "properties": {
                        "tags": finding.get("tags", []),
                        "owasp": finding.get("owasp", ""),
                    },
                })
            level_map = {"critical": "error", "high": "error", "medium": "warning",
                         "low": "note", "info": "none"}
            run_results.append({
                "ruleId": rule_id,
                "level": level_map.get(finding["risk"], "note"),
                "message": {"text": f"{finding['evidence']} | {finding['verification']}"},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": source},
                        "region": {"startLine": 1},
                    },
                    "logicalLocations": [{"name": finding["location"]}],
                }],
                "properties": {
                    "confidence": finding.get("confidence", "medium"),
                    "cwe": finding.get("cwe", ""),
                },
            })

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "vuln_analyzer",
                    "version": "2.0.0",
                    "informationUri": "https://github.com/example/vuln_analyzer",
                    "rules": rules,
                }
            },
            "results": run_results,
        }],
    }
    return json.dumps(sarif, ensure_ascii=False, indent=2)


# ──────────────────────────────────────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────────────────────────────────────

def read_input(path: str | None) -> tuple[str, str]:
    if path:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read(), path
    return sys.stdin.read(), "stdin"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Static web security signal analyzer.\n"
            "Accepts HTTP messages, HTML, or source code snippets."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""examples:
  python vuln_analyzer.py request.txt --pretty
  python vuln_analyzer.py response.http --format markdown -o report.md
  python vuln_analyzer.py *.txt --format sarif -o results.sarif
  cat page.html | python vuln_analyzer.py --min-risk high
  python vuln_analyzer.py src.py --type "SQL Injection" --type "Cmd Injection"
""",
    )
    parser.add_argument(
        "inputs",
        nargs="*",
        metavar="FILE",
        help="Input file(s). Reads from stdin if omitted.",
    )
    parser.add_argument(
        "-o", "--output",
        metavar="FILE",
        help="Write output to this file instead of stdout.",
    )
    parser.add_argument(
        "--format",
        choices=["json", "text", "markdown", "sarif"],
        default="json",
        help="Output format (default: json).",
    )
    parser.add_argument(
        "--pretty",
        action="store_true",
        help="Pretty-print JSON output.",
    )
    parser.add_argument(
        "--min-risk",
        choices=list(RISK_ORDER.keys()),
        default="info",
        metavar="LEVEL",
        help="Only show findings at or above this risk level (info/low/medium/high/critical).",
    )
    parser.add_argument(
        "--type",
        action="append",
        dest="types",
        metavar="TYPE",
        help="Only report this vulnerability type (repeatable). E.g. --type XSS --type SQLi",
    )
    parser.add_argument(
        "--no-notes",
        action="store_true",
        help="Suppress disclaimer notes from output.",
    )
    return parser


def apply_filters(
    result: dict[str, Any],
    min_risk: str,
) -> dict[str, Any]:
    min_order = RISK_ORDER.get(min_risk, 0)
    filtered = [
        f for f in result["findings"]
        if RISK_ORDER.get(f["risk"], 0) >= min_order
    ]
    result = dict(result)
    result["findings"] = filtered
    result["summary"] = dict(result["summary"])
    result["summary"]["total_findings"] = len(filtered)
    counts: dict[str, int] = {}
    for f in filtered:
        counts[f["risk"]] = counts.get(f["risk"], 0) + 1
    result["summary"]["by_risk"] = counts
    return result


def main() -> int:
    args = build_parser().parse_args()
    enabled_types = set(args.types) if args.types else None

    # Collect inputs
    inputs: list[tuple[str, str]] = []
    if args.inputs:
        for pattern in args.inputs:
            for path in Path().glob(pattern) if "*" in pattern or "?" in pattern else [Path(pattern)]:
                try:
                    inputs.append((path.read_text(encoding="utf-8", errors="replace"), str(path)))
                except OSError as exc:
                    print(f"ERROR: cannot read '{path}': {exc}", file=sys.stderr)
                    return 1
    else:
        stdin_text = sys.stdin.read()
        if not stdin_text.strip():
            print("No input provided. Pass a file path or pipe content to stdin.", file=sys.stderr)
            return 2
        inputs.append((stdin_text, "stdin"))

    results: list[dict[str, Any]] = []
    for text, source_name in inputs:
        result = analyze(text, source_name, enabled_types=enabled_types)
        result = apply_filters(result, args.min_risk)
        if args.no_notes:
            result.pop("notes", None)
        results.append(result)

    # Format output
    fmt = args.format
    if fmt == "sarif":
        payload = format_sarif(results)
    elif len(results) == 1:
        r = results[0]
        if fmt == "json":
            payload = format_json(r, pretty=args.pretty)
        elif fmt == "text":
            payload = format_text(r)
        else:
            payload = format_markdown(r)
    else:
        # Multiple files
        if fmt == "json":
            payload = json.dumps(results, ensure_ascii=False, indent=2 if args.pretty else None)
        elif fmt == "text":
            payload = "\n\n".join(format_text(r) for r in results)
        else:
            payload = "\n\n---\n\n".join(format_markdown(r) for r in results)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(payload + "\n")
        print(f"Output written to {args.output}", file=sys.stderr)
    else:
        print(payload)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
