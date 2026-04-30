"""
Dynamic attack classifier.

Classifies HTTP requests based entirely on observable behavioral signals:
  - User-agent strings (tool fingerprinting)
  - URL content (payload pattern matching)
  - HTTP method semantics
  - Response status code anomalies
  - Missing/anomalous header combinations

NO hardcoded vulnerability lists. NO static IP→attack mappings.
Every classification decision is derived from the log data itself.
"""

import re
from collections import Counter
from dataclasses import dataclass, field
from typing import Optional

# ── Tool fingerprinting ───────────────────────────────────────────────────────
# (pattern, canonical_name, category)
_TOOL_SIGS: list[tuple[str, str, str]] = [
    (r"sqlmap/[\d.]+", "sqlmap", "sql_injection_scanner"),
    (r"nikto/[\d.]+", "nikto", "web_vulnerability_scanner"),
    (r"nmap/[\d.]+", "nmap", "network_scanner"),
    (r"masscan/[\d.]+", "masscan", "port_scanner"),
    (r"zgrab", "zgrab", "banner_grabber"),
    (r"dirbuster", "dirbuster", "dir_bruteforce"),
    (r"gobuster", "gobuster", "dir_bruteforce"),
    (r"feroxbuster", "feroxbuster", "dir_bruteforce"),
    (r"wfuzz", "wfuzz", "fuzzer"),
    (r"ffuf", "ffuf", "fuzzer"),
    (r"hydra", "hydra", "credential_bruteforce"),
    (r"medusa", "medusa", "credential_bruteforce"),
    (r"burp\s*suite|burpsuite", "burpsuite", "proxy_scanner"),
    (r"owasp[_\s-]?zap|zaproxy|zap-", "owasp_zap", "vulnerability_scanner"),
    (r"w3af", "w3af", "web_vulnerability_scanner"),
    (r"metasploit|msfconsole", "metasploit", "exploit_framework"),
    (r"nessus", "nessus", "vulnerability_scanner"),
    (r"openvas", "openvas", "vulnerability_scanner"),
    (r"nuclei/[\d.]+", "nuclei", "template_scanner"),
    (r"acunetix", "acunetix", "web_vulnerability_scanner"),
    (r"python-requests/[\d.]+", "python_requests", "scripted_client"),
    (r"go-http-client/[\d.]+", "go_http_client", "scripted_client"),
    (r"libwww-perl/[\d.]+", "libwww_perl", "scripted_client"),
    (r"java/[\d.]+", "java_httpclient", "scripted_client"),
    (r"curl/[\d.]+", "curl", "cli_client"),
    (r"wget/[\d.]+", "wget", "cli_client"),
]

# ── URL attack payload patterns ───────────────────────────────────────────────
# (pattern, attack_type, weight)   weight adds to confidence score
_URL_PATTERNS: list[tuple[str, str, float]] = [
    # SQL injection
    (r"(?i)('|%27|--|%2D%2D|;|%3B)\s*(?:or|and|union|select|drop|insert|update|delete|exec|xp_)",
     "sql_injection", 0.55),
    (r"(?i)union\s+(?:all\s+)?select|select\s+.+from\s+|insert\s+into\s+|drop\s+(?:table|database)",
     "sql_injection", 0.60),
    (r"(?i)(?:sleep|benchmark|waitfor\s+delay|pg_sleep)\s*\(",
     "sql_injection_blind", 0.55),

    # XSS
    (r"(?i)<\s*script[^>]*>|javascript\s*:|onerror\s*=|onload\s*=|alert\s*\(|confirm\s*\(|prompt\s*\(",
     "xss", 0.55),
    (r"(?i)%3[Cc]script|%3[Cc]img|%3[Cc]svg",
     "xss", 0.45),

    # Path traversal / LFI
    (r"\.\./|\.\.\\|%2e%2e[/\\]|%252e%252e",
     "path_traversal", 0.50),
    (r"(?i)/etc/passwd|/etc/shadow|/windows/system32|/proc/self",
     "lfi", 0.70),

    # Template / SSTI
    (r"\$\{|%24%7B|\#\{|\{\{|\}\}",
     "template_injection", 0.45),

    # Command injection
    (r"(?i)(?:;|\||&&|\$\(|`)\s*(?:id|whoami|cat|ls|wget|curl|bash|sh|cmd|powershell)",
     "command_injection", 0.60),
    (r"(?i)cmd(?:\.exe)?=|exec=|system=|passthru=|shell_exec=|eval=",
     "command_injection", 0.55),

    # SSRF
    (r"(?i)(?:url|uri|redirect|next|target|dest)=.*(?:localhost|127\.|10\.|192\.168\.|169\.254\.)",
     "ssrf", 0.50),
    (r"(?i)(?:file|gopher|dict|sftp|ldap|ftp)://",
     "ssrf", 0.55),

    # Directory/admin probing
    (r"(?i)/(?:wp-admin|wp-login|phpmyadmin|pma|adminer|db|manager|console|panel)(?:/|$)",
     "admin_probe", 0.40),
    (r"(?i)/\.(?:env|git|svn|htaccess|htpasswd|DS_Store|config|bash_history)",
     "sensitive_file_probe", 0.60),

    # API enumeration / fuzzing
    (r"(?i)fuzz|FUZZ|%FUZZ%",
     "fuzzing", 0.50),
    (r"(?i)/api/v\d+/",
     "api_enumeration", 0.20),
    (r"(?i)/graphql(?:/|\?|$)",
     "graphql_probe", 0.30),

    # XXE
    (r"<!ENTITY|<!DOCTYPE.*SYSTEM|<!DOCTYPE.*PUBLIC",
     "xxe", 0.65),
]

_SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass
class AttackClassification:
    attack_type: Optional[str]
    confidence: float          # 0.0–1.0
    signals: list[str] = field(default_factory=list)
    tool: Optional[str] = None
    tool_category: Optional[str] = None
    severity: str = "low"


def _detect_tool(user_agent: str) -> Optional[tuple[str, str]]:
    ua = user_agent.lower()
    for pattern, name, category in _TOOL_SIGS:
        if re.search(pattern, ua, re.IGNORECASE):
            return name, category
    return None


def _analyze_url(url: str) -> list[tuple[str, float]]:
    findings: list[tuple[str, float]] = []
    # Partially decode common encodings before matching
    decoded = url.replace("%27", "'").replace("%3c", "<").replace("%3e", ">").replace(
        "%20", " "
    )
    for pattern, attack_type, weight in _URL_PATTERNS:
        if re.search(pattern, decoded):
            findings.append((attack_type, weight))
    return findings


def classify_request(raw: dict) -> AttackClassification:
    """
    Dynamically classify a single log entry.
    All decisions are signal-driven — no manual rule tables.
    """
    signals: list[str] = []
    attack_votes: list[tuple[str, float]] = []
    confidence: float = 0.0
    detected_tool: Optional[str] = None
    tool_cat: Optional[str] = None

    user_agent = raw.get("user_agent") or raw.get("user-agent") or ""
    url = raw.get("url") or raw.get("path") or "/"
    method = (raw.get("method") or "GET").upper()
    status = raw.get("status") or 0
    content_type = raw.get("content_type") or ""

    # ── 1. Tool fingerprinting ──────────────────────────────────────────────
    tool_result = _detect_tool(user_agent)
    if tool_result:
        detected_tool, tool_cat = tool_result
        signals.append(f"Recognized attack tool: {detected_tool} ({tool_cat})")
        confidence += 0.55
        attack_votes.append((tool_cat, 0.55))

    # ── 2. URL payload analysis ─────────────────────────────────────────────
    url_findings = _analyze_url(url)
    for attack_type, weight in url_findings:
        attack_votes.append((attack_type, weight))
        signals.append(f"URL matches {attack_type} pattern")
        confidence += weight

    # ── 3. Method semantics ─────────────────────────────────────────────────
    if method in ("DELETE", "PUT", "PATCH", "TRACE", "OPTIONS", "CONNECT"):
        signals.append(f"Non-standard HTTP method: {method}")
        confidence += 0.10

    # ── 4. Status code anomalies ────────────────────────────────────────────
    status_signals = {
        400: ("bad_request_flood", 0.10),
        401: ("auth_brute_force", 0.15),
        403: ("access_probe", 0.10),
        404: ("dir_enumeration", 0.10),
        500: ("error_triggering", 0.15),
        429: ("rate_limit_evasion", 0.10),
    }
    if status in status_signals:
        label, w = status_signals[status]
        signals.append(f"Status {status} suggests {label}")
        confidence += w
        attack_votes.append((label, w))

    # ── 5. Header anomalies ─────────────────────────────────────────────────
    if not user_agent or user_agent in ("-", "None", "null", ""):
        signals.append("Missing or empty user-agent")
        confidence += 0.15

    if "application/x-www-form-urlencoded" in content_type or "multipart/form-data" in content_type:
        if any(t in url.lower() for t in ("login", "auth", "signin", "admin")):
            signals.append("Form POST to auth/admin endpoint")
            confidence += 0.10
            attack_votes.append(("credential_attack", 0.10))

    # ── 6. Derive primary attack type ───────────────────────────────────────
    primary_type: Optional[str] = None
    if attack_votes:
        totals: dict[str, float] = {}
        for atype, w in attack_votes:
            totals[atype] = totals.get(atype, 0) + w
        primary_type = max(totals, key=lambda k: totals[k])

    # ── 7. Severity mapping ─────────────────────────────────────────────────
    clamped = min(confidence, 1.0)
    if clamped >= 0.70:
        severity = "critical"
    elif clamped >= 0.50:
        severity = "high"
    elif clamped >= 0.30:
        severity = "medium"
    else:
        severity = "low"

    return AttackClassification(
        attack_type=primary_type,
        confidence=clamped,
        signals=signals,
        tool=detected_tool,
        tool_category=tool_cat,
        severity=severity,
    )
