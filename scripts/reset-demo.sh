#!/usr/bin/env bash
set -euo pipefail

MODE="${1:-baseline}" # baseline | patch | defender | combined
CONTROL_HEADER="X-Control-Token: demo-control-local"
LAB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "[*] Resetting demo state for mode: ${MODE}"

# Helper to exec in container directly or compose fallback
dex() {
  local container="$1"
  shift
  if docker ps --format '{{.Names}}' | grep -q "^${container}\$"; then
    docker exec "$container" "$@"
  else
    local svc="${container#demo-}"
    docker compose -f "$LAB_DIR/docker-compose.yml" exec -T "$svc" "$@"
  fi
}

# 1. Reset microservice in-memory state
dex demo-edge curl -s -H "$CONTROL_HEADER" -X POST http://localhost:8000/internal/reset > /dev/null 2>&1 || true
dex demo-identity curl -s -H "$CONTROL_HEADER" -X POST http://localhost:8000/internal/reset > /dev/null 2>&1 || true
dex demo-workflow curl -s -H "$CONTROL_HEADER" -X POST http://localhost:8000/internal/reset > /dev/null 2>&1 || true
dex demo-records curl -s -H "$CONTROL_HEADER" -X POST http://localhost:8000/internal/reset > /dev/null 2>&1 || true

# 2. Reset ML defender state
dex demo-defender curl -s -H "$CONTROL_HEADER" -X POST http://localhost:9000/internal/reset > /dev/null 2>&1 || true

case "${MODE}" in
  baseline|patch)
    echo "[*] Setting ML defender to OBSERVE-ONLY mode..."
    dex demo-defender curl -s -H "$CONTROL_HEADER" -H "Content-Type: application/json" -X POST -d '{"mode":"observe"}' http://localhost:9000/internal/mode > /dev/null 2>&1 || true
    ;;
  defender|combined)
    echo "[*] Setting ML defender to ACTIVE-REVOCATION mode..."
    dex demo-defender curl -s -H "$CONTROL_HEADER" -H "Content-Type: application/json" -X POST -d '{"mode":"active"}' http://localhost:9000/internal/mode > /dev/null 2>&1 || true
    ;;
esac

# 3. Configure WAF virtual patch
case "${MODE}" in
  baseline|defender)
    echo "[*] Configuring WAF in DETECTION-ONLY mode..."
    if docker ps --format '{{.Names}}' | grep -q "^demo-waf\$"; then
      docker exec -u 0 demo-waf sh -c "cat /etc/modsecurity.d/rules-storage/rule-99001-detect.conf > /etc/modsecurity.d/owasp-crs/rules/RESPONSE-999-DEMO-VIRTUAL-PATCH.conf"
      docker exec -u 0 demo-waf nginx -s reload > /dev/null 2>&1
    fi
    ;;
  patch|combined)
    echo "[*] Configuring WAF in BLOCKING mode..."
    if docker ps --format '{{.Names}}' | grep -q "^demo-waf\$"; then
      docker exec -u 0 demo-waf sh -c "cat /etc/modsecurity.d/rules-storage/rule-99001-block.conf > /etc/modsecurity.d/owasp-crs/rules/RESPONSE-999-DEMO-VIRTUAL-PATCH.conf"
      docker exec -u 0 demo-waf nginx -s reload > /dev/null 2>&1
    fi
    ;;
  *)
    echo "Unknown mode: ${MODE}. Expected: baseline | patch | defender | combined"
    exit 1
    ;;
esac

echo "[+] Reset complete. Lab configured for run: ${MODE}"
