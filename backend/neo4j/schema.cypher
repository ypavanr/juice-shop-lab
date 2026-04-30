// ============================================================
// Neo4j Schema — Attack Graph
// Run once at startup (graph_builder.py calls ensure_schema()
// automatically, but you can also run this manually).
// ============================================================

// ── Uniqueness constraints ────────────────────────────────────────────────────

CREATE CONSTRAINT ip_unique IF NOT EXISTS
  FOR (n:IP) REQUIRE n.address IS UNIQUE;

CREATE CONSTRAINT endpoint_unique IF NOT EXISTS
  FOR (n:Endpoint) REQUIRE n.path IS UNIQUE;

CREATE CONSTRAINT user_unique IF NOT EXISTS
  FOR (n:User) REQUIRE n.username IS UNIQUE;

CREATE CONSTRAINT event_unique IF NOT EXISTS
  FOR (n:Event) REQUIRE n.event_id IS UNIQUE;

CREATE CONSTRAINT tool_unique IF NOT EXISTS
  FOR (n:Tool) REQUIRE n.name IS UNIQUE;

// ── Performance indexes ───────────────────────────────────────────────────────

CREATE INDEX ip_attacker IF NOT EXISTS
  FOR (n:IP) ON (n.is_attacker);

CREATE INDEX ip_severity IF NOT EXISTS
  FOR (n:IP) ON (n.max_severity);

CREATE INDEX event_timestamp IF NOT EXISTS
  FOR (n:Event) ON (n.timestamp);

CREATE INDEX event_severity IF NOT EXISTS
  FOR (n:Event) ON (n.severity);

CREATE INDEX event_attack_type IF NOT EXISTS
  FOR (n:Event) ON (n.attack_type);

CREATE INDEX endpoint_hit_count IF NOT EXISTS
  FOR (n:Endpoint) ON (n.hit_count);
