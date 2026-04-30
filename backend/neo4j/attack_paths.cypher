// ============================================================
// Attack Path Analysis Queries
// Paste into Neo4j Browser at http://localhost:7474
// All queries are read-only (MATCH / RETURN).
// ============================================================

// ── 1. Full attack graph — all paths up to 5 hops ────────────────────────────
MATCH p = (a:IP {is_attacker: true})-[*1..5]->(target)
WHERE NOT a = target
RETURN p
LIMIT 100;


// ── 2. Kill-chain view: attacker → event → endpoint ──────────────────────────
MATCH (ip:IP)-[:INITIATES]->(ev:Event)-[:TARGETS]->(ep:Endpoint)
WHERE ip.is_attacker = true
RETURN
  ip.address        AS attacker_ip,
  ev.attack_type    AS technique,
  ev.severity       AS severity,
  ep.path           AS target,
  ev.timestamp      AS timestamp
ORDER BY ev.timestamp DESC
LIMIT 200;


// ── 3. Top targeted endpoints ─────────────────────────────────────────────────
MATCH (ip:IP)-[r:ATTACKS]->(ep:Endpoint)
RETURN
  ep.path                     AS endpoint,
  COUNT(DISTINCT ip)          AS unique_attackers,
  SUM(r.attack_count)         AS total_attack_count,
  COLLECT(DISTINCT r.attack_type) AS techniques_used
ORDER BY total_attack_count DESC
LIMIT 20;


// ── 4. Most active attackers ──────────────────────────────────────────────────
MATCH (ip:IP)-[:INITIATES]->(ev:Event)
WHERE ip.is_attacker = true
RETURN
  ip.address                      AS ip,
  COUNT(ev)                       AS event_count,
  COLLECT(DISTINCT ev.attack_type) AS attack_types,
  ip.max_severity                 AS max_severity,
  ip.first_seen                   AS first_seen,
  ip.last_seen                    AS last_seen
ORDER BY event_count DESC
LIMIT 50;


// ── 5. Tool usage inventory ───────────────────────────────────────────────────
MATCH (ip:IP)-[:USES_TOOL]->(t:Tool)
RETURN
  t.name          AS tool,
  t.category      AS category,
  COUNT(DISTINCT ip) AS ip_count,
  COLLECT(ip.address) AS ips
ORDER BY ip_count DESC;


// ── 6. Brute-force detection (≥5 auth events from same IP) ───────────────────
MATCH (ip:IP)-[:INITIATES]->(ev:Event)
WHERE ev.type IN ['ssh_failure', 'auth_failure']
   OR ev.attack_type IN ['credential_attack', 'auth_brute_force', 'credential_bruteforce']
WITH ip, COUNT(ev) AS fail_count
WHERE fail_count >= 5
RETURN
  ip.address  AS attacker_ip,
  fail_count
ORDER BY fail_count DESC;


// ── 7. Multi-stage attacks (different techniques on same target) ──────────────
MATCH (ip:IP)-[:INITIATES]->(e1:Event)-[:TARGETS]->(ep:Endpoint),
      (ip)-[:INITIATES]->(e2:Event)-[:TARGETS]->(ep)
WHERE e1.event_id <> e2.event_id
  AND e1.timestamp < e2.timestamp
  AND e1.attack_type <> e2.attack_type
RETURN
  ip.address       AS attacker,
  e1.attack_type   AS stage_1,
  e2.attack_type   AS stage_2,
  ep.path          AS target,
  duration.between(
    datetime(e1.timestamp),
    datetime(e2.timestamp)
  ).minutes        AS minutes_between
ORDER BY minutes_between
LIMIT 50;


// ── 8. Credential stuffing / repeated auth failures per user ─────────────────
MATCH (u:User)-[r:AUTH_ATTEMPT]->(ep:Endpoint)
WHERE r.attempt_count > 3 AND r.success = false
RETURN
  u.username        AS username,
  ep.path           AS endpoint,
  r.attempt_count   AS failed_attempts,
  r.first_attempt   AS first_attempt,
  r.last_attempt    AS last_attempt
ORDER BY failed_attempts DESC;


// ── 9. Reconnaissance chain: enumeration → exploitation ──────────────────────
MATCH (ip:IP)-[:INITIATES]->(recon:Event)
WHERE recon.attack_type IN ['dir_enumeration', 'admin_probe', 'api_enumeration',
                             'sensitive_file_probe', 'fuzzing']
WITH ip, COLLECT(recon) AS recon_events
MATCH (ip)-[:INITIATES]->(exploit:Event)
WHERE exploit.severity IN ['high', 'critical']
  AND exploit.timestamp > recon_events[-1].timestamp
RETURN
  ip.address          AS attacker_ip,
  SIZE(recon_events)  AS recon_event_count,
  exploit.attack_type AS exploit_technique,
  exploit.severity    AS severity
ORDER BY recon_event_count DESC
LIMIT 30;


// ── 10. Real-time attack dashboard summary ────────────────────────────────────
MATCH (ip:IP {is_attacker: true})
OPTIONAL MATCH (ip)-[:INITIATES]->(ev:Event)
OPTIONAL MATCH (ip)-[:ATTACKS]->(ep:Endpoint)
RETURN
  ip.address              AS attacker_ip,
  COUNT(DISTINCT ev)      AS events,
  COUNT(DISTINCT ep)      AS endpoints_targeted,
  ip.max_severity         AS max_severity,
  ip.detected_tools       AS tools,
  ip.first_seen           AS first_seen,
  ip.last_seen            AS last_seen
ORDER BY events DESC;


// ── 11. MITRE-style technique frequency ──────────────────────────────────────
MATCH (ev:Event)
WHERE ev.attack_type IS NOT NULL
RETURN
  ev.attack_type         AS technique,
  COUNT(ev)              AS occurrences,
  COLLECT(DISTINCT ev.severity) AS severities
ORDER BY occurrences DESC;


// ── 12. Time-windowed attack bursts (last 1 hour) ────────────────────────────
MATCH (ip:IP)-[:INITIATES]->(ev:Event)
WHERE datetime(ev.timestamp) > datetime() - duration('PT1H')
  AND ip.is_attacker = true
RETURN
  ip.address        AS attacker_ip,
  COUNT(ev)         AS events_last_hour,
  MAX(ev.severity)  AS max_severity
ORDER BY events_last_hour DESC
LIMIT 20;
