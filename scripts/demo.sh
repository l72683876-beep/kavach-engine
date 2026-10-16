#!/usr/bin/env bash
# One-click Kavach demo: builds the engine, books a seat live, proves
# idempotency, runs a mini stampede, and independently verifies the log.
# No arguments. Used by the Codespaces postCreateCommand and `make demo`.
set -e
cd "$(dirname "$0")/.."
echo "== Building Kavach..."
(cd engine && go build -o kavach .)
rm -f engine/demo*.jsonl
(cd engine && ./kavach -seats 100 -workers 4 -ip-rate 0 \
  -log demo.jsonl -holds-log demo_holds.jsonl) & ENGINE_PID=$!
trap 'kill $ENGINE_PID 2>/dev/null || true' EXIT
for i in $(seq 1 40); do curl -sf http://127.0.0.1:8080/seats >/dev/null && break; sleep 0.5; done

echo
echo "== Idempotency: booking three times with the SAME idempotency key..."
for i in 1 2 3; do
  curl -s -X POST http://127.0.0.1:8080/book -H 'Content-Type: application/json' \
    -d '{"user_id":"lucky","idempotency_key":"demo-key-1","seats":1}'
  echo
done

echo
echo "== Mini stampede: 2,000 users hit 100 seats at once..."
python3 sim/simulate.py --users 2000 --seats 100 || true

echo
echo "== Independent verification from the log alone:"
python3 sim/verify.py engine/demo.jsonl 100 engine/demo_holds.jsonl

echo
echo "== Final inventory (total 100, sold 100, free 0 expected):"
curl -s http://127.0.0.1:8080/seats
echo
echo "Demo done. Full acceptance suites: make test"
