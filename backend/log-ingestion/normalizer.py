"""
Log normalizer.

Converts raw log dicts from multiple sources (Juice Shop HTTP proxy,
Logstash-processed syslog/auth.log) into a uniform NormalizedLog dataclass.
All field extraction is driven by the log content itself — no static mappings.
"""

import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional


@dataclass
class NormalizedLog:
    log_id: str                    # Deterministic SHA-256 prefix for idempotency
    timestamp: datetime
    source_type: str               # e.g. "juice-shop", "auth", "syslog"

    # Network
    client_ip: str
    method: Optional[str] = None
    url: Optional[str] = None
    endpoint: Optional[str] = None   # URL path without query string
    query_string: Optional[str] = None

    # HTTP
    status_code: Optional[int] = None
    user_agent: Optional[str] = None
    referer: Optional[str] = None
    content_type: Optional[str] = None
    response_time_ms: Optional[int] = None

    # Auth / system
    username: Optional[str] = None
    event_type: Optional[str] = None  # http_request | ssh_success | ssh_failure | …

    raw: dict = field(default_factory=dict)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _first_ip(value: Any) -> str:
    if not value:
        return "0.0.0.0"
    return str(value).split(",")[0].strip() or "0.0.0.0"


def _split_url(url: Optional[str]) -> tuple[Optional[str], Optional[str]]:
    if not url:
        return None, None
    idx = url.find("?")
    if idx == -1:
        return url, None
    return url[:idx], url[idx + 1:]


def _parse_ts(ts: Any) -> datetime:
    if isinstance(ts, datetime):
        return ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)
    if isinstance(ts, (int, float)):
        return datetime.fromtimestamp(ts, tz=timezone.utc)
    if isinstance(ts, str):
        _FMTS = [
            "%Y-%m-%dT%H:%M:%S.%fZ",
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%dT%H:%M:%S.%f%z",
            "%Y-%m-%dT%H:%M:%S%z",
            "%Y-%m-%dT%H:%M:%S.%f",
            "%Y-%m-%dT%H:%M:%S",
            "%Y/%m/%d %H:%M:%S",
            "%d/%b/%Y:%H:%M:%S %z",
            "%b %d %H:%M:%S",
            "%b  %d %H:%M:%S",
        ]
        for fmt in _FMTS:
            try:
                dt = datetime.strptime(ts.strip(), fmt)
                return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
            except ValueError:
                continue
    return datetime.now(tz=timezone.utc)


def _make_id(d: dict) -> str:
    key = json.dumps(
        {k: d.get(k, "") for k in ("ip", "method", "url", "status", "timestamp")},
        sort_keys=True,
    )
    return hashlib.sha256(key.encode()).hexdigest()[:16]


def _classify_system_event(message: str) -> str:
    m = message.lower()
    if "accepted password" in m or "accepted publickey" in m:
        return "ssh_success"
    if "failed password" in m or "authentication failure" in m:
        return "ssh_failure"
    if "invalid user" in m:
        return "ssh_invalid_user"
    if "connection closed" in m or "disconnected" in m:
        return "ssh_disconnect"
    if "sudo" in m:
        return "sudo_command"
    if "session opened" in m:
        return "session_opened"
    if "session closed" in m:
        return "session_closed"
    return "system_event"


# ── Normalizers ───────────────────────────────────────────────────────────────

def _normalize_app_log(raw: dict) -> NormalizedLog:
    ip = _first_ip(
        raw.get("x_forwarded_for")
        or raw.get("ip")
        or raw.get("remote_addr")
        or raw.get("client_ip")
    )
    url = raw.get("url") or raw.get("path") or "/"
    endpoint, qs = _split_url(url)

    return NormalizedLog(
        log_id=_make_id({**raw, "ip": ip}),
        timestamp=_parse_ts(raw.get("timestamp") or raw.get("_received_at")),
        source_type=raw.get("source") or "application",
        client_ip=ip,
        method=raw.get("method"),
        url=url,
        endpoint=endpoint,
        query_string=qs,
        status_code=raw.get("status"),
        user_agent=raw.get("user_agent") or raw.get("user-agent"),
        referer=raw.get("referer"),
        content_type=raw.get("content_type"),
        response_time_ms=raw.get("response_time_ms"),
        username=raw.get("username") or raw.get("user"),
        event_type="http_request",
        raw=raw,
    )


def _normalize_system_log(raw: dict) -> NormalizedLog:
    message = raw.get("message") or raw.get("log_message") or ""

    # Extract IP from syslog message text
    m = re.search(r"from\s+(\d{1,3}(?:\.\d{1,3}){3})", message)
    ip = m.group(1) if m else "0.0.0.0"

    # Extract username
    u = re.search(
        r"(?:for invalid user|for user|invalid user|user)\s+(\S+)", message, re.IGNORECASE
    )
    username = u.group(1) if u else None

    # Source file path for source_type label
    log_obj = raw.get("log") or {}
    file_path = (
        log_obj.get("file", {}).get("path", "")
        if isinstance(log_obj, dict)
        else str(log_obj)
    )
    source_type = "auth" if "auth" in file_path else "syslog"

    return NormalizedLog(
        log_id=hashlib.sha256(message.encode()).hexdigest()[:16],
        timestamp=_parse_ts(raw.get("@timestamp") or raw.get("timestamp")),
        source_type=source_type,
        client_ip=ip,
        username=username,
        event_type=_classify_system_event(message),
        raw=raw,
    )


# ── Public API ────────────────────────────────────────────────────────────────

def normalize(raw: dict) -> NormalizedLog:
    """Route to the correct normalizer based on log structure."""
    # Logstash-processed syslog entries carry @timestamp and a message field
    if raw.get("@timestamp") or (raw.get("log") and not raw.get("method")):
        return _normalize_system_log(raw)
    # Application logs carry an HTTP method
    return _normalize_app_log(raw)
