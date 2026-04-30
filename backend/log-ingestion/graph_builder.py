"""
Graph builder.

Writes normalized log entries as Neo4j nodes and relationships.
Every node and edge originates from real log data — nothing is manually inserted.

Node types:   IP · Endpoint · User · Event · Tool
Relationships: INITIATES · TARGETS · ATTACKS · USES_TOOL · AUTH_ATTEMPT · RETURNS
"""

import logging
import os
from datetime import datetime, timezone
from typing import Optional

from neo4j import AsyncDriver, AsyncGraphDatabase

from attack_detector import AttackClassification
from normalizer import NormalizedLog

logger = logging.getLogger("graph-builder")

_SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}


class GraphBuilder:
    def __init__(self) -> None:
        self._driver: Optional[AsyncDriver] = None

    async def connect(self) -> None:
        uri  = os.environ.get("NEO4J_URI",      "neo4j://127.0.0.1:7687")
        user = os.environ.get("NEO4J_USER",     "neo4j")
        pw   = os.environ.get("NEO4J_PASSWORD", "rendertest")
        self._driver = AsyncGraphDatabase.driver(uri, auth=(user, pw))
        await self._driver.verify_connectivity()
        logger.info("Connected to Neo4j at %s", uri)

    async def close(self) -> None:
        if self._driver:
            await self._driver.close()

    async def ensure_schema(self) -> None:
        stmts = [
            # Uniqueness constraints
            "CREATE CONSTRAINT ip_unique IF NOT EXISTS FOR (n:IP) REQUIRE n.address IS UNIQUE",
            "CREATE CONSTRAINT endpoint_unique IF NOT EXISTS FOR (n:Endpoint) REQUIRE n.path IS UNIQUE",
            "CREATE CONSTRAINT user_unique IF NOT EXISTS FOR (n:User) REQUIRE n.username IS UNIQUE",
            "CREATE CONSTRAINT event_unique IF NOT EXISTS FOR (n:Event) REQUIRE n.event_id IS UNIQUE",
            "CREATE CONSTRAINT tool_unique IF NOT EXISTS FOR (n:Tool) REQUIRE n.name IS UNIQUE",
            # Performance indexes
            "CREATE INDEX ip_attacker IF NOT EXISTS FOR (n:IP) ON (n.is_attacker)",
            "CREATE INDEX event_ts IF NOT EXISTS FOR (n:Event) ON (n.timestamp)",
            "CREATE INDEX event_severity IF NOT EXISTS FOR (n:Event) ON (n.severity)",
            "CREATE INDEX event_attack_type IF NOT EXISTS FOR (n:Event) ON (n.attack_type)",
            "CREATE INDEX endpoint_hits IF NOT EXISTS FOR (n:Endpoint) ON (n.hit_count)",
        ]
        async with self._driver.session() as s:
            for stmt in stmts:
                try:
                    await s.run(stmt)
                except Exception as exc:
                    logger.debug("Schema stmt warning: %s", exc)
        logger.info("Neo4j schema ready")

    # ── Public entry point ──────────────────────────────────────────────────

    async def ingest(self, log: NormalizedLog, cls: AttackClassification) -> None:
        async with self._driver.session() as s:
            await self._upsert_ip(s, log, cls)
            if log.endpoint:
                await self._upsert_endpoint(s, log)
            if log.username:
                await self._upsert_user(s, log)
            if cls.tool:
                await self._upsert_tool(s, cls)
                await self._rel_ip_uses_tool(s, log.client_ip, cls.tool)
            event_id = self._event_id(log)
            await self._upsert_event(s, log, cls, event_id)
            await self._rel_ip_initiates_event(s, log.client_ip, event_id)
            if log.endpoint:
                await self._rel_event_targets_endpoint(s, event_id, log.endpoint)
                if cls.confidence > 0.25:
                    await self._rel_ip_attacks_endpoint(s, log.client_ip, log.endpoint, cls)
            if log.username and log.endpoint:
                await self._rel_user_auth_attempt(s, log)

    # ── Upserts ─────────────────────────────────────────────────────────────

    async def _upsert_ip(self, s, log: NormalizedLog, cls: AttackClassification) -> None:
        srank = _SEVERITY_RANK.get(cls.severity, 0)
        await s.run(
            """
            MERGE (ip:IP {address: $address})
            ON CREATE SET
                ip.first_seen     = $ts,
                ip.last_seen      = $ts,
                ip.request_count  = 1,
                ip.is_attacker    = $is_atk,
                ip.detected_tools = $tools,
                ip.attack_types   = $atypes,
                ip.max_severity   = $severity,
                ip.severity_rank  = $srank
            ON MATCH SET
                ip.last_seen     = $ts,
                ip.request_count = ip.request_count + 1,
                ip.is_attacker   = ip.is_attacker OR $is_atk,
                ip.max_severity  = CASE
                    WHEN $srank > ip.severity_rank THEN $severity ELSE ip.max_severity END,
                ip.severity_rank = CASE
                    WHEN $srank > ip.severity_rank THEN $srank ELSE ip.severity_rank END
            """,
            address=log.client_ip,
            ts=log.timestamp.isoformat(),
            is_atk=cls.confidence > 0.30,
            tools=[cls.tool] if cls.tool else [],
            atypes=[cls.attack_type] if cls.attack_type else [],
            severity=cls.severity,
            srank=srank,
        )

    async def _upsert_endpoint(self, s, log: NormalizedLog) -> None:
        await s.run(
            """
            MERGE (ep:Endpoint {path: $path})
            ON CREATE SET
                ep.first_seen  = $ts,
                ep.last_seen   = $ts,
                ep.hit_count   = 1
            ON MATCH SET
                ep.last_seen = $ts,
                ep.hit_count = ep.hit_count + 1
            """,
            path=log.endpoint,
            ts=log.timestamp.isoformat(),
        )

    async def _upsert_user(self, s, log: NormalizedLog) -> None:
        await s.run(
            """
            MERGE (u:User {username: $username})
            ON CREATE SET u.first_seen = $ts, u.source_ips = [$ip]
            ON MATCH SET  u.last_seen  = $ts
            """,
            username=log.username,
            ts=log.timestamp.isoformat(),
            ip=log.client_ip,
        )

    async def _upsert_tool(self, s, cls: AttackClassification) -> None:
        await s.run(
            """
            MERGE (t:Tool {name: $name})
            ON CREATE SET t.category = $cat
            """,
            name=cls.tool,
            cat=cls.tool_category or cls.attack_type or "unknown",
        )

    async def _upsert_event(
        self, s, log: NormalizedLog, cls: AttackClassification, event_id: str
    ) -> None:
        await s.run(
            """
            MERGE (ev:Event {event_id: $eid})
            ON CREATE SET
                ev.timestamp   = $ts,
                ev.type        = $etype,
                ev.method      = $method,
                ev.url         = $url,
                ev.status_code = $status,
                ev.user_agent  = $ua,
                ev.attack_type = $atype,
                ev.confidence  = $conf,
                ev.severity    = $sev,
                ev.signals     = $signals,
                ev.source      = $source
            """,
            eid=event_id,
            ts=log.timestamp.isoformat(),
            etype=log.event_type or "http_request",
            method=log.method,
            url=log.url,
            status=log.status_code,
            ua=log.user_agent,
            atype=cls.attack_type,
            conf=cls.confidence,
            sev=cls.severity,
            signals=cls.signals,
            source=log.source_type,
        )

    # ── Relationships ────────────────────────────────────────────────────────

    async def _rel_ip_initiates_event(self, s, ip: str, event_id: str) -> None:
        await s.run(
            """
            MATCH (ip:IP {address: $ip})
            MATCH (ev:Event {event_id: $eid})
            MERGE (ip)-[:INITIATES]->(ev)
            """,
            ip=ip, eid=event_id,
        )

    async def _rel_event_targets_endpoint(self, s, event_id: str, path: str) -> None:
        await s.run(
            """
            MATCH (ev:Event {event_id: $eid})
            MATCH (ep:Endpoint {path: $path})
            MERGE (ev)-[:TARGETS]->(ep)
            """,
            eid=event_id, path=path,
        )

    async def _rel_ip_attacks_endpoint(
        self, s, ip: str, path: str, cls: AttackClassification
    ) -> None:
        await s.run(
            """
            MATCH (ip:IP {address: $ip})
            MATCH (ep:Endpoint {path: $path})
            MERGE (ip)-[r:ATTACKS]->(ep)
            ON CREATE SET
                r.first_seen   = $ts,
                r.last_seen    = $ts,
                r.attack_count = 1,
                r.attack_type  = $atype,
                r.max_severity = $sev
            ON MATCH SET
                r.last_seen    = $ts,
                r.attack_count = r.attack_count + 1
            """,
            ip=ip, path=path,
            ts=datetime.now(timezone.utc).isoformat(),
            atype=cls.attack_type,
            sev=cls.severity,
        )

    async def _rel_ip_uses_tool(self, s, ip: str, tool: str) -> None:
        await s.run(
            """
            MATCH (ip:IP {address: $ip})
            MATCH (t:Tool {name: $tool})
            MERGE (ip)-[:USES_TOOL]->(t)
            """,
            ip=ip, tool=tool,
        )

    async def _rel_user_auth_attempt(self, s, log: NormalizedLog) -> None:
        success = log.status_code in (200, 201, 302)
        await s.run(
            """
            MATCH (u:User {username: $uname})
            MATCH (ep:Endpoint {path: $path})
            MERGE (u)-[r:AUTH_ATTEMPT]->(ep)
            ON CREATE SET
                r.first_attempt = $ts,
                r.last_attempt  = $ts,
                r.attempt_count = 1,
                r.success       = $success
            ON MATCH SET
                r.last_attempt  = $ts,
                r.attempt_count = r.attempt_count + 1,
                r.success       = r.success OR $success
            """,
            uname=log.username,
            path=log.endpoint,
            ts=log.timestamp.isoformat(),
            success=success,
        )

    # ── Internal helpers ─────────────────────────────────────────────────────

    @staticmethod
    def _event_id(log: NormalizedLog) -> str:
        return f"{log.log_id}_{log.timestamp.isoformat()}"
