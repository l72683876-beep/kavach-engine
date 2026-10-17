#!/usr/bin/env bash
# Boots the full three-tier stack for real: engine -> demo app -> browser UI.
# Sizes itself to the machine: 2-core laptop or 4-core Codespace, same command.
set -euo pipefail
cd "$(dirname "$0")/.."

CORES="$(nproc 2>/dev/null || echo 2)"
GWORKERS=$(( 2 * CORES + 1 ))
EWORKERS=$(( CORES > 2 ? 4 : 2 ))
echo "cores: $CORES -> gunicorn workers $GWORKERS, engine workers $EWORKERS"

WEBHOOK_TOKEN="${WEBHOOK_TOKEN:-whsec-$(head -c16 /dev/urandom | od -An -tx1 | tr -d ' \n')}"
pkill -f "kavach -seats" 2>/dev/null || true
pkill -f gunicorn 2>/dev/null || true
sleep 1

cd engine
./kavach -seats 20000 -workers "$EWORKERS" -ip-rate 0 \
  -api-keys appkey:aurora-app -hmac-secret appsecret \
  -webhook-url "http://127.0.0.1:9000/api/kavach-webhook?token=$WEBHOOK_TOKEN" &
cd ..

cd examples/demo-app
KAVACH_KEY=appkey KAVACH_SECRET=appsecret KAVACH_WEBHOOK_TOKEN="$WEBHOOK_TOKEN" \
python3 -m gunicorn -w "$GWORKERS" --threads 4 -b 0.0.0.0:9000 --timeout 120 \
  app:app &
APP_PID=$!
sleep 3

echo
echo "=========================================="
echo " Aurora Nights LIVE:  http://localhost:9000"
echo " 20,000 seats, hold expiry 300s, engine on :8080"
echo " stop with:  make demo-stop"
echo "=========================================="
wait "$APP_PID"
