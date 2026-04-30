"""
Log Ingestion Service — port 5001

Receives structured log dicts from:
  - log-receiver (Juice Shop HTTP logs)
  - Logstash HTTP output (syslog / auth.log)

Normalizes each entry, classifies attack behaviour, then writes nodes and
relationships into Neo4j. All graph data originates from real logs.
"""

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware

from attack_detector import classify_request
from graph_builder import GraphBuilder
from normalizer import normalize

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("log-ingestion")

_graph = GraphBuilder()


@asynccontextmanager
async def lifespan(app: FastAPI):
    await _graph.connect()
    await _graph.ensure_schema()
    logger.info("Log ingestion service ready")
    yield
    await _graph.close()


app = FastAPI(title="Log Ingestion Service", version="1.0.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["POST", "GET"],
    allow_headers=["*"],
)


@app.post("/ingest", status_code=200)
async def ingest_single(request: Request):
    try:
        raw = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON body")

    try:
        log = normalize(raw)
        cls = classify_request(raw)
        await _graph.ingest(log, cls)
        return {
            "status": "ingested",
            "log_id": log.log_id,
            "attack_type": cls.attack_type,
            "severity": cls.severity,
            "confidence": round(cls.confidence, 3),
        }
    except Exception as exc:
        logger.error("Ingestion error: %s", exc, exc_info=True)
        raise HTTPException(status_code=500, detail=str(exc))


@app.post("/ingest/batch", status_code=200)
async def ingest_batch(request: Request):
    try:
        entries = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON body")

    if not isinstance(entries, list):
        raise HTTPException(status_code=400, detail="Expected a JSON array")

    ok: list[dict] = []
    errors: list[dict] = []

    for raw in entries:
        try:
            log = normalize(raw)
            cls = classify_request(raw)
            await _graph.ingest(log, cls)
            ok.append({"log_id": log.log_id, "severity": cls.severity})
        except Exception as exc:
            logger.error("Batch item error: %s", exc)
            errors.append({"error": str(exc)})

    return {"ingested": len(ok), "errors": len(errors)}


@app.get("/health")
async def health():
    try:
        async with _graph._driver.session() as s:
            result = await s.run("RETURN 1 AS ok")
            await result.single()
        return {"status": "healthy", "neo4j": "connected"}
    except Exception as exc:
        return {"status": "degraded", "neo4j": str(exc)}
