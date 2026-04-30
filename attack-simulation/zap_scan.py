#!/usr/bin/env python3
"""
OWASP ZAP automated attack simulation.

Runs a full spider + AJAX spider + active scan against the deployed Juice Shop
and saves alerts, request history, and an HTML report to ./scan-results/.

Usage:
  export TARGET_URL=https://your-juice-shop.onrender.com
  export ZAP_API_KEY=zapapikey
  python zap_scan.py

Prerequisites:
  pip install python-owasp-zap-v2.4
  ZAP running (docker-compose up -d zap) or locally on ZAP_PORT.
"""

import json
import logging
import os
import sys
import time
from datetime import datetime
from pathlib import Path

try:
    from zapv2 import ZAPv2
except ImportError:
    sys.exit("ERROR: install python-owasp-zap-v2.4  →  pip install python-owasp-zap-v2.4")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger("zap-scan")

# ── Config from environment ───────────────────────────────────────────────────
TARGET_URL    = os.environ.get("TARGET_URL",    "http://localhost:8080")
ZAP_API_KEY   = os.environ.get("ZAP_API_KEY",   "zapapikey")
ZAP_HOST      = os.environ.get("ZAP_HOST",      "localhost")
ZAP_PORT      = int(os.environ.get("ZAP_PORT",  "8090"))
OUTPUT_DIR    = Path(os.environ.get("SCAN_OUTPUT_DIR", "./scan-results"))
CONTEXT_NAME  = "JuiceShop"

OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
_ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")


# ── Helpers ───────────────────────────────────────────────────────────────────

def _wait_for_zap(zap: ZAPv2, retries: int = 40) -> None:
    for i in range(retries):
        try:
            zap.core.version
            log.info("ZAP is ready (version %s)", zap.core.version)
            return
        except Exception:
            log.info("Waiting for ZAP… (%d/%d)", i + 1, retries)
            time.sleep(3)
    sys.exit("ERROR: ZAP did not become ready in time")


def _poll(label: str, status_fn, interval: int = 3) -> None:
    while True:
        try:
            pct = int(status_fn())
        except Exception:
            pct = 0
        log.info("%s: %d%%", label, pct)
        if pct >= 100:
            break
        time.sleep(interval)


def _save(name: str, data: object) -> Path:
    path = OUTPUT_DIR / f"{name}_{_ts}.json"
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
    log.info("Saved → %s", path)
    return path


# ── Scan phases ───────────────────────────────────────────────────────────────

def run_spider(zap: ZAPv2) -> None:
    log.info("── Spider scan ──────────────────────────────────────────")
    scan_id = zap.spider.scan(TARGET_URL, contextname=CONTEXT_NAME, apikey=ZAP_API_KEY)
    _poll("Spider", lambda: zap.spider.status(scan_id))
    results = zap.spider.results(scan_id)
    log.info("Spider found %d URLs", len(results))
    _save("spider_urls", {"target": TARGET_URL, "urls": results})


def run_ajax_spider(zap: ZAPv2, timeout_secs: int = 180) -> None:
    """AJAX spider for the Angular SPA frontend."""
    log.info("── AJAX spider ──────────────────────────────────────────")
    zap.ajaxSpider.scan(TARGET_URL, contextname=CONTEXT_NAME, apikey=ZAP_API_KEY)
    deadline = time.time() + timeout_secs
    while time.time() < deadline:
        status = zap.ajaxSpider.status
        log.info("AJAX spider status: %s", status)
        if status == "stopped":
            break
        time.sleep(5)
    results = zap.ajaxSpider.results(start=0, count=100)
    log.info("AJAX spider found %d results", len(results) if isinstance(results, list) else "?")


def run_active_scan(zap: ZAPv2) -> str:
    log.info("── Active vulnerability scan ────────────────────────────")
    scan_id = zap.ascan.scan(
        TARGET_URL,
        contextid=zap.context.context(CONTEXT_NAME)["id"],
        apikey=ZAP_API_KEY,
    )
    _poll("Active scan", lambda: zap.ascan.status(scan_id), interval=5)
    log.info("Active scan complete")
    return scan_id


def save_results(zap: ZAPv2) -> None:
    # Alerts
    alerts = zap.core.alerts(baseurl=TARGET_URL)
    by_risk: dict[str, int] = {}
    for a in alerts:
        by_risk[a.get("risk", "Unknown")] = by_risk.get(a.get("risk", "Unknown"), 0) + 1
    _save(
        "alerts",
        {"scan_time": datetime.utcnow().isoformat(), "target": TARGET_URL,
         "total": len(alerts), "by_risk": by_risk, "alerts": alerts},
    )
    log.info("Alert breakdown: %s", by_risk)

    # Request history (capped at 1000)
    messages = zap.core.messages(baseurl=TARGET_URL, start=0, count=1000)
    history = [
        {
            "id": m.get("id"),
            "method": m.get("requestHeader", "").split(" ")[0] if m.get("requestHeader") else "",
            "url": m.get("requestHeader", "").split("\n")[0] if m.get("requestHeader") else "",
            "status_code": m.get("statusCode"),
            "timestamp": m.get("timestamp"),
            "note": m.get("note", ""),
        }
        for m in (messages if isinstance(messages, list) else [])
    ]
    _save("request_history", {"target": TARGET_URL, "count": len(history), "requests": history})

    # HTML report
    report_html = zap.core.htmlreport(apikey=ZAP_API_KEY)
    report_path = OUTPUT_DIR / f"report_{_ts}.html"
    report_path.write_text(report_html, encoding="utf-8")
    log.info("HTML report → %s", report_path)


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    log.info("Target: %s", TARGET_URL)
    log.info("ZAP:    %s:%d", ZAP_HOST, ZAP_PORT)

    zap = ZAPv2(
        apikey=ZAP_API_KEY,
        proxies={
            "http":  f"http://{ZAP_HOST}:{ZAP_PORT}",
            "https": f"http://{ZAP_HOST}:{ZAP_PORT}",
        },
    )

    _wait_for_zap(zap)

    # Fresh session for clean results
    zap.core.new_session(apikey=ZAP_API_KEY)

    # Create scoped context
    ctx_id = zap.context.new_context(CONTEXT_NAME, apikey=ZAP_API_KEY)
    zap.context.include_in_context(CONTEXT_NAME, f"{TARGET_URL}.*", apikey=ZAP_API_KEY)
    log.info("Context '%s' (id=%s) scoped to %s.*", CONTEXT_NAME, ctx_id, TARGET_URL)

    run_spider(zap)
    # run_ajax_spider(zap)
    run_active_scan(zap)
    save_results(zap)

    log.info("Scan complete. Results in %s/", OUTPUT_DIR)


if __name__ == "__main__":
    main()
