#!/usr/bin/env bash
# Deterministic red-team battery runner: starts fresh targets with the exact
# config the battery expects, runs sim/redteam_battery.py, then stops them.
#   engine_red  127.0.0.1:8091  50 seats, auth+HMAC+user limits ON, IP limit off
#   engine_red2 127.0.0.1:8092  61 seats (drain caps at 60: the last-seat cases
#                               need exactly 61), no rate limits
#   app_red     127.0.0.1:9001  demo app wired to 8091, webhook token whsec-redtest
# State logs go to a temp dir so a previous run's bookings.jsonl can never be
# replayed into a fresh target (that made targets report sold > total).
set -e
cd "$(dirname "$0")/.."
pkill -x kavach 2>/dev/null || true
pkill -f 'demo-app/app.py' 2>/dev/null || true
sleep 1
sleep 1
GO=${GO:-go}
command -v "$GO" >/dev/null 2>&1 || GO=/tmp/go/bin/go
$GO build -o engine/kavach ./engine
TMP=$(mktemp -d)
./engine/kavach -seats 50 -workers 4 -api-keys testkey:tenant1,otherkey:tenant2 \
  -hmac-secret testsecret -hold-ttl 30 -ip-rate 0 \
  -log "$TMP/bt1_bookings.jsonl" -holds-log "$TMP/bt1_holds.jsonl" \
  -addr 127.0.0.1:8091 >/dev/null 2>&1 &
P1=$!
./engine/kavach -seats 61 -workers 4 -api-keys testkey:tenant1,otherkey:tenant2 \
  -hmac-secret testsecret -hold-ttl 30 -ip-rate 0 -user-rate 0 \
  -log "$TMP/bt2_bookings.jsonl" -holds-log "$TMP/bt2_holds.jsonl" \
  -addr 127.0.0.1:8092 >/dev/null 2>&1 &
P2=$!
./engine/kavach -seats 10 -workers 2 -api-keys testkey:tenant1,otherkey:tenant2 \
  -hmac-secret testsecret -hold-ttl 3 -ip-rate 0 -user-rate 0 \
  -log "$TMP/bt3_bookings.jsonl" -holds-log "$TMP/bt3_holds.jsonl" \
  -addr 127.0.0.1:8095 >/dev/null 2>&1 &
P3=$!
KAVACH_URL=http://127.0.0.1:8091 KAVACH_KEY=testkey KAVACH_SECRET=testsecret \
KAVACH_WEBHOOK_TOKEN=whsec-redtest PORT=9001 python3 examples/demo-app/app.py >/dev/null 2>&1 &
P4=$!
sleep 3
for p in 8091 8092 8095; do curl -sf -o /dev/null "http://127.0.0.1:$p/seats" || { echo "target $p not up"; kill $P1 $P2 $P3 $P4 2>/dev/null; exit 1; }; done
curl -sf -o /dev/null "http://127.0.0.1:9001/" || { echo "app target not up"; kill $P1 $P2 $P3 2>/dev/null; exit 1; }
python3 sim/redteam_battery.py
RC=$?
kill $P1 $P2 $P3 $P4 2>/dev/null || true
rm -rf "$TMP"
exit $RC
