"""
Log Receiver Service  — port 5000
Accepts structured JSON logs from the Juice Shop logging proxy (and any other
app). Validates, enriches, then forwards asynchronously to the ingestion
service. A local deque acts as a short-term buffer when the ingestion service
is temporarily unavailable.
"""

import asyncio
import logging
import os
import threading
from collections import deque
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any, Optional

import httpx
from fastapi import BackgroundTasks, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("log-receiver")

INGESTION_URL = os.getenv("INGESTION_SERVICE_URL", "http://log-ingestion:5001/ingest")
MAX_QUEUE_SIZE = int(os.getenv("MAX_QUEUE_SIZE", "10000"))
DRAIN_INTERVAL_SECS = float(os.getenv("DRAIN_INTERVAL_SECS", "5"))

_buffer: deque[dict] = deque(maxlen=MAX_QUEUE_SIZE)
_buffer_lock = threading.Lock()


# ── Pydantic models ──────────────────────────────────────────────────────────

class LogEntry(BaseModel):
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    ip: str
    method: str
    url: str
    status: int
    user_agent: Optional[str] = ""
    referer: Optional[str] = ""
    response_time_ms: Optional[int] = None
    source: Optional[str] = "unknown"
    host: Optional[str] = ""
    content_type: Optional[str] = ""
    accept: Optional[str] = ""
    x_forwarded_for: Optional[str] = ""
    content_length: Optional[Any] = None

    model_config = {"extra": "allow"}   # accept arbitrary extra fields


# ── HTTP forwarding helpers ──────────────────────────────────────────────────

async def _post(client: httpx.AsyncClient, url: str, payload: Any) -> bool:
    try:
        r = await client.post(url, json=payload, timeout=5.0)
        return r.status_code < 500
    except Exception as exc:
        logger.debug("forward failed: %s", exc)
        return False


async def _forward(data: dict, client: httpx.AsyncClient) -> None:
    ok = await _post(client, INGESTION_URL, data)
    if not ok:
        with _buffer_lock:
            _buffer.append(data)


async def _forward_batch(entries: list[dict], client: httpx.AsyncClient) -> None:
    batch_url = INGESTION_URL.replace("/ingest", "/ingest/batch")
    ok = await _post(client, batch_url, entries)
    if not ok:
        with _buffer_lock:
            _buffer.extend(entries)


async def _drain_loop(client: httpx.AsyncClient) -> None:
    """Periodically retry buffered log entries."""
    while True:
        await asyncio.sleep(DRAIN_INTERVAL_SECS)
        with _buffer_lock:
            if not _buffer:
                continue
            batch = list(_buffer)
            _buffer.clear()

        retry_url = INGESTION_URL.replace("/ingest", "/ingest/batch")
        if not await _post(client, retry_url, batch):
            with _buffer_lock:
                _buffer.extendleft(reversed(batch))


# ── Lifespan ─────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    limits = httpx.Limits(max_connections=100, max_keepalive_connections=20)
    client = httpx.AsyncClient(limits=limits)
    app.state.client = client
    drain_task = asyncio.create_task(_drain_loop(client))
    logger.info("Log receiver started. Forwarding to %s", INGESTION_URL)
    yield
    drain_task.cancel()
    await client.aclose()


# ── App ───────────────────────────────────────────────────────────────────────

app = FastAPI(title="Log Receiver", version="1.0.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["POST", "GET"],
    allow_headers=["*"],
)


def _enrich(data: dict, request: Request) -> dict:
    data["_received_at"] = datetime.now(timezone.utc).isoformat()
    data["_receiver_ip"] = request.client.host if request.client else "unknown"
    return data


@app.post("/log", status_code=202)
async def receive_single(
    entry: LogEntry,
    background_tasks: BackgroundTasks,
    request: Request,
):
    data = _enrich(entry.model_dump(), request)
    background_tasks.add_task(_forward, data, request.app.state.client)
    return {"status": "accepted"}


@app.post("/logs/batch", status_code=202)
async def receive_batch(
    entries: list[LogEntry],
    background_tasks: BackgroundTasks,
    request: Request,
):
    batch = [_enrich(e.model_dump(), request) for e in entries]
    background_tasks.add_task(_forward_batch, batch, request.app.state.client)
    return {"status": "accepted", "count": len(batch)}


@app.get("/health")
async def health():
    with _buffer_lock:
        buffered = len(_buffer)
    return {
        "status": "healthy",
        "buffered_logs": buffered,
        "ingestion_url": INGESTION_URL,
    }


@app.get("/metrics")
async def metrics():
    with _buffer_lock:
        return {"buffer_size": len(_buffer), "buffer_capacity": MAX_QUEUE_SIZE}
