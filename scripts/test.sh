#!/usr/bin/env bash
# One command for everything: build, vet, race detector, an end-to-end burst
# with an independent log verification, and every acceptance suite.
# Usage: bash scripts/test.sh [--full]
#   --full also runs the chaos, recovery and cluster suites (slower).
set -u
cd "$(dirname "$0")/.."
FAILED=0
RESULTS=""
step() { printf '\n=== %s ===\n' "$1"; }
ok()   { RESULTS="$RESULTS\nPASS  $1"; }
fail() { RESULTS="$RESULTS\nFAIL  $1"; FAILED=1; }

step "Build, vet, race detector"
(cd engine && go build -o kavach .) && (cd engine && go vet ./...) \
  && (cd engine && go test -race ./...) \
  && ok "build + vet + go test -race" || fail "build + vet + go test -race"

step "End-to-end burst + independent verification"
rm -f engine/smoke*.jsonl
(cd engine && ./kavach -seats 200 -workers 4 -ip-rate 0 \
  -log smoke.jsonl -holds-log smoke_holds.jsonl) & E=$!
for i in $(seq 1 40); do curl -sf http://127.0.0.1:8080/seats >/dev/null && break; sleep 0.5; done
python3 sim/simulate.py --users 2000 && \
  python3 sim/verify.py engine/smoke.jsonl 200 engine/smoke_holds.jsonl \
  && ok "burst 2000 users / 200 seats + verify" || fail "burst + verify"
kill $E 2>/dev/null; wait $E 2>/dev/null

run_suite() {
  local name="$1" flags="$2" seats="$3" script="$4"
  step "Suite: $name"
  rm -f engine/st*.jsonl
  (cd engine && ./kavach -seats "$seats" -workers 4 -ip-rate 0 \
    -log st.jsonl -holds-log st_holds.jsonl $flags) & E=$!
  sleep 2
  python3 "sim/$script" 8080 && ok "$name" || fail "$name"
  kill $E 2>/dev/null; wait $E 2>/dev/null
}

run_suite "security (14 checks)"    "-api-keys testkey:tenant1 -hmac-secret testsecret" 100 security_test.py
run_suite "lifecycle (19 checks)"   "-api-keys testkey:tenant1,otherkey:tenant2 -hmac-secret testsecret -hold-ttl 3" 100 lifecycle_test.py
run_suite "waitlist (14 checks)"    "-api-keys testkey:tenant1 -hmac-secret testsecret -hold-ttl 10 -webhook-url http://127.0.0.1:9099/hook" 10 waitlist_test.py

run_suite "red-team (39 checks)"    "-api-keys testkey:tenant1,otherkey:tenant2 -hmac-secret testsecret -hold-ttl 5" 50 redteam.py

step "Suite: SDK (python)"
rm -f engine/sdk*.jsonl
(cd engine && ./kavach -seats 3 -workers 2 -ip-rate 0 \
  -api-keys sdkkey:sdktenant -hmac-secret sdksecret -hold-ttl 10 \
  -log sdk.jsonl -holds-log sdk_holds.jsonl) & E=$!
sleep 2
python3 sdk/test_sdks.py && ok "sdk python (11 checks)" || fail "sdk python"
kill $E 2>/dev/null; wait $E 2>/dev/null

if [ "${1:-}" = "--full" ]; then
  step "Full extras (chaos, recovery, cluster)"
  # the sim scripts Popen with cwd="engine" themselves, so run them from the repo root
  python3 sim/chaos_test.py 8091    && ok "chaos"    || fail "chaos"
  python3 sim/recovery_test.py 8090 && ok "recovery" || fail "recovery"
  python3 sim/snapshot_test.py 8096 && ok "snapshot + compaction" || fail "snapshot + compaction"
  python3 sim/cluster_test.py 8101  && ok "cluster"  || fail "cluster"
fi

echo; echo "================ RESULT ================"
printf "%b\n" "$RESULTS"
echo "========================================"
[ "$FAILED" = 0 ] && echo "ALL TESTS PASSED" || echo "SOME TESTS FAILED"
exit $FAILED
