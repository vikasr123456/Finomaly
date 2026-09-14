#!/usr/bin/env bash
# Start the scoring API and the analyst dashboard locally, in mock mode.
#
#   ./scripts/run_local.sh            # generated tokens, printed once
#   DEMO_API_TOKEN=... DASHBOARD_TOKEN=... ./scripts/run_local.sh
#
# Ctrl+C stops both. Nothing here is an EnterPro deployment; it is two uvicorn
# processes on loopback with a SQLite file under ./run/ .
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APP_DIR="$ROOT/app"
RUN_DIR="$ROOT/run"
mkdir -p "$RUN_DIR"
chmod 700 "$RUN_DIR"

API_PORT="${API_PORT:-8000}"
DASH_PORT="${DASH_PORT:-8001}"
API_BASE="http://127.0.0.1:${API_PORT}"
DASH_BASE="http://127.0.0.1:${DASH_PORT}"

new_secret() { python3 -c 'import secrets; print(secrets.token_urlsafe(32))'; }

# Placeholders and empty values make both services fail closed, so generate
# strong ephemeral secrets when the operator has not supplied real ones.
if [[ -z "${DEMO_API_TOKEN:-}" || "${DEMO_API_TOKEN}" == \<* ]]; then
  DEMO_API_TOKEN="$(new_secret)"; GENERATED_SERVICE_TOKEN=1
else GENERATED_SERVICE_TOKEN=0; fi
if [[ -z "${DASHBOARD_TOKEN:-}" || "${DASHBOARD_TOKEN}" == \<* ]]; then
  DASHBOARD_TOKEN="$(new_secret)"; GENERATED_DASH_TOKEN=1
else GENERATED_DASH_TOKEN=0; fi

export DEMO_API_TOKEN DASHBOARD_TOKEN
export QWEN_MODE="${QWEN_MODE:-mock}"
export DEMO_DB_PATH="${DEMO_DB_PATH:-$RUN_DIR/fraud_demo.sqlite3}"
export FRAUD_API_BASE_URL="$API_BASE"
export FRAUD_API_ALLOW_PRIVATE_HTTP=0
export DASHBOARD_SECURE_COOKIES=0

PIDS=()
cleanup() {
  trap - EXIT INT TERM
  for pid in "${PIDS[@]:-}"; do kill "$pid" 2>/dev/null || true; done
  wait 2>/dev/null || true
  echo "Stopped. Database kept at $DEMO_DB_PATH"
}
trap cleanup EXIT INT TERM

wait_for_health() {
  local url="$1" name="$2"
  for _ in $(seq 1 60); do
    if python3 -c "
import sys, urllib.request
try:
    sys.exit(0 if urllib.request.urlopen('$url', timeout=2).status == 200 else 1)
except Exception:
    sys.exit(1)
"; then return 0; fi
    sleep 0.5
  done
  echo "ERROR: $name did not become healthy at $url" >&2
  return 1
}

cd "$APP_DIR"
python3 -m uvicorn fraud_demo:app --host 127.0.0.1 --port "$API_PORT" --workers 1 \
  > "$RUN_DIR/api.log" 2>&1 &
PIDS+=("$!")
wait_for_health "$API_BASE/health" "scoring API"

python3 -m uvicorn dashboard:app --host 127.0.0.1 --port "$DASH_PORT" --workers 1 \
  > "$RUN_DIR/dashboard.log" 2>&1 &
PIDS+=("$!")
wait_for_health "$DASH_BASE/health" "dashboard BFF"

cat <<EOF

  Fraud & Anomaly Detection prototype (MOCK mode: ${QWEN_MODE})

  Dashboard      ${DASH_BASE}
  Scoring API    ${API_BASE}   (interactive docs at ${API_BASE}/docs)
  Database       ${DEMO_DB_PATH}
  Logs           ${RUN_DIR}/api.log , ${RUN_DIR}/dashboard.log

EOF
if [[ "$GENERATED_SERVICE_TOKEN" == 1 ]]; then
  echo "  DEMO_API_TOKEN (generated for this session, used by the simulator):"
  echo "    ${DEMO_API_TOKEN}"
fi
if [[ "$GENERATED_DASH_TOKEN" == 1 ]]; then
  echo "  DASHBOARD_TOKEN (generated for this session, use it to sign in):"
  echo "    ${DASHBOARD_TOKEN}"
fi
cat <<EOF

  Stream synthetic traffic in another terminal:
    cd ${APP_DIR}
    DEMO_API_TOKEN='${DEMO_API_TOKEN}' python3 fraud_demo.py --stream --rate 2 --count 40 --anomaly-rate 0.25 --assess

  Press Ctrl+C to stop.
EOF

wait
