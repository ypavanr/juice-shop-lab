#!/usr/bin/env bash
# ============================================================
# Cybersecurity Lab — End-to-End Startup Script
#
# What this script does:
#   1. Validates .env and required tools
#   2. Builds Docker images
#   3. Starts Neo4j and waits for it to be healthy
#   4. Starts log-ingestion and log-receiver
#   5. Starts Logstash
#   6. Starts OWASP ZAP
#   7. Optionally installs + starts Filebeat (system logs)
#   8. Prints service URLs
#   9. Optionally runs ZAP scan if --scan flag is passed
#
# Usage:
#   ./run.sh           # start all services
#   ./run.sh --scan    # start services then immediately run ZAP scan
#   ./run.sh --stop    # stop all containers
# ============================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# ── Colour helpers ────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
log()  { echo -e "${GREEN}[$(date '+%H:%M:%S')]${NC} $*"; }
warn() { echo -e "${YELLOW}[$(date '+%H:%M:%S')] WARN:${NC} $*"; }
fail() { echo -e "${RED}[$(date '+%H:%M:%S')] ERROR:${NC} $*" >&2; exit 1; }

# ── Handle --stop ─────────────────────────────────────────────────────────────
if [[ "${1:-}" == "--stop" ]]; then
  log "Stopping all services…"
  docker compose down
  log "Done."
  exit 0
fi

# ── Load .env ─────────────────────────────────────────────────────────────────
if [[ ! -f .env ]]; then
  fail ".env not found. Run: cp .env.example .env && vi .env"
fi
set -a; source .env; set +a

# ── Validate required vars ────────────────────────────────────────────────────
[[ -z "${NEO4J_PASSWORD:-}" ]]  && fail "NEO4J_PASSWORD not set in .env"
[[ -z "${BACKEND_VM_IP:-}" ]]   && fail "BACKEND_VM_IP not set in .env"
[[ "${NEO4J_PASSWORD}" == "ChangeMe_Strong_Password_1" ]] && \
  warn "Using default NEO4J_PASSWORD — change it before exposing to the internet"

# ── Dependency check ──────────────────────────────────────────────────────────
command -v docker &>/dev/null || fail "docker is not installed"
COMPOSE="docker compose"
command -v docker-compose &>/dev/null && COMPOSE="docker-compose"
log "Using compose: $COMPOSE"

# ── Build ─────────────────────────────────────────────────────────────────────
log "Building images (this may take a few minutes on first run)…"
$COMPOSE build

# ── Start Neo4j first ─────────────────────────────────────────────────────────
log "Starting Neo4j…"
$COMPOSE up -d neo4j
log "Waiting for Neo4j to become healthy…"
until [[ "$(docker inspect --format='{{.State.Health.Status}}' neo4j 2>/dev/null)" == "healthy" ]]; do
  printf "."
  sleep 3
done
echo ""
log "Neo4j is healthy"

# ── Start ingestion layer ─────────────────────────────────────────────────────
log "Starting log-ingestion…"
$COMPOSE up -d log-ingestion
until curl -sf http://localhost:5001/health &>/dev/null; do
  printf "."
  sleep 2
done
echo ""
log "log-ingestion is healthy"

log "Starting log-receiver…"
$COMPOSE up -d log-receiver
until curl -sf http://localhost:5000/health &>/dev/null; do
  printf "."
  sleep 2
done
echo ""
log "log-receiver is healthy"

# ── Start Logstash ────────────────────────────────────────────────────────────
log "Starting Logstash (takes ~60s to initialise)…"
$COMPOSE up -d logstash

# ── Start ZAP ─────────────────────────────────────────────────────────────────
log "Starting OWASP ZAP…"
$COMPOSE up -d zap
sleep 5

# ── Filebeat (system-level, host install) ────────────────────────────────────
if command -v filebeat &>/dev/null; then
  log "Starting Filebeat for system log collection…"
  sudo filebeat -e \
    -c "$SCRIPT_DIR/backend/filebeat/filebeat.yml" \
    -E "output.logstash.hosts=[\"localhost:5044\"]" &
  FILEBEAT_PID=$!
  log "Filebeat PID: $FILEBEAT_PID"
else
  warn "filebeat not installed — system log collection disabled"
  warn "Install on Ubuntu/Debian:"
  warn "  curl -L -O https://artifacts.elastic.co/downloads/beats/filebeat/filebeat-8.13.0-amd64.deb"
  warn "  sudo dpkg -i filebeat-8.13.0-amd64.deb"
fi

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
log "══════════════════════════════════════════════════════════"
log "  Cybersecurity Lab — All Services Running"
log "══════════════════════════════════════════════════════════"
log "  Neo4j Browser    : http://localhost:7474"
log "  Log Receiver     : http://localhost:5000  (Juice Shop → here)"
log "  Log Ingestion    : http://localhost:5001"
log "  ZAP API          : http://localhost:8090"
log "  Logstash Beats   : localhost:5044"
log ""
log "  Juice Shop URL   : ${TARGET_URL:-not set in .env}"
log "  Backend IP       : ${BACKEND_VM_IP}"
log ""
log "  Render env var to set:"
log "    LOG_RECEIVER_URL = http://${BACKEND_VM_IP}:5000/log"
log ""
log "  Neo4j queries: backend/neo4j/attack_paths.cypher"
log "══════════════════════════════════════════════════════════"

# ── Optional: run ZAP scan immediately ───────────────────────────────────────
if [[ "${1:-}" == "--scan" ]]; then
  if [[ -z "${TARGET_URL:-}" ]]; then
    warn "TARGET_URL not set — skipping scan"
  else
    log "Running ZAP scan against $TARGET_URL…"
    cd attack-simulation
    pip install -q -r requirements.txt
    TARGET_URL="$TARGET_URL" \
    ZAP_API_KEY="${ZAP_API_KEY:-zapapikey}" \
    ZAP_HOST="localhost" \
    ZAP_PORT="${ZAP_PORT:-8090}" \
    python zap_scan.py
    cd ..
    log "Scan complete. Results in attack-simulation/scan-results/"
  fi
fi
