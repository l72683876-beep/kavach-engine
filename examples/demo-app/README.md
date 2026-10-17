# Aurora Nights Live: Kavach behind a real three-tier app

A small but complete concert-ticketing website that uses Kavach the way a
third-party developer would: through the [Python SDK](../../sdk/python),
over the engine's HTTP API with HMAC signing. It exists to answer one
question with real measurements: **what happens to the engine's guarantees
when it is actually behind a web application, instead of tested alone?**

```
browser (static HTML/JS)  ->  Flask app (Python)  ->  Kavach engine (Go)
     the product                  SDK, HMAC,            holds, confirms,
     payment simulation           money layer           releases, waitlist
```

The engine sees only holds, confirms, releases and waitlist joins. The
simulated payment and pricing live in the app layer on purpose: Kavach is
an inventory engine, not a checkout.

## What the flow demonstrates

1. **Hold** the customer picks seats; the app reserves them through
   Kavach. The seats now belong to them for 60 s.
2. **Pay** the app's simulated gateway confirms the hold in Kavach on
   success, or releases the seats back on failure/abandonment.
3. **Sell out** when the show is full the board flips and latecomers join
   the engine's waitlist (first come, first served).
4. **Retry safely** every hold carries an idempotency key; a dropped
   request re-sent with the same key can never double-book.

## Run it

```bash
pip install flask

# terminal 1: the engine (200 seats, hold expires after 60 s)
cd engine && ./kavach -seats 200 -workers 4 -ip-rate 0 \
    -api-keys appkey:aurora-app -hmac-secret appsecret -hold-ttl 60

# terminal 2: the app + UI
cd examples/demo-app && python3 app.py
# open http://127.0.0.1:9000, click "Hold seats & pay"

# the same flow, hammered by 2,000 simultaneous buyers
python3 loadtest_app.py 9000 2000 100
```

## Measured end to end (through the app, not around it)

Two-core shared sandbox; engine, app and load generator on the same box.
Raw machine-readable run: [direct-engine-run.json](direct-engine-run.json),
load-test transcript: [app-loadtest-run.txt](app-loadtest-run.txt).

| Metric (2000 buyers, 200 seats, concurrency 100) | Direct engine | Through the full stack |
|---|---|---|
| wall time | 1.9 s | 7.5 s |
| throughput | 1,040 req/s | 266 buyer flows/s (hold+pay+seat reads) |
| confirmed / sold out | 181 / 1,819 | 185 / 1,815 |
| seats finally sold | 198 | 200 (exact, no double-sell) |
| errors | 0 | 0 |
| end-to-end latency | not the point here | p50 286 ms, p95 667 ms, p99 934 ms |

The double-sell oracle is the engine's own final readout: the app's
confirmed seats (200) must equal `sold` (200), and the load test fails
hard otherwise (`DOUBLE-SELL CHECK: PASS`). The p95 through the stack is
the web layer's cost, not the engine's; the engine's own latency profile
is in [RESULTS.md](../../RESULTS.md).

The direct-engine column is a same-scale rerun (2,000 users, 200 seats,
fresh engine) so the two columns measure the same rush, with and without
the web app in front.
