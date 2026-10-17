#!/usr/bin/env python3
"""Real-world load test: hammers the DEMO APP (not the engine) exactly like
a flash-sale crowd would: refresh the seat board, hold seats, pay.

    python3 loadtest_app.py [app_port] [buyers] [concurrency]

Every number is measured end to end THROUGH the Flask app; the engine
sits one hop behind it. The engine's final /seats readout is the
double-sell oracle: app pay_confirmed must equal engine sold.
"""
import http.client, json, sys, threading, time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 9000
USERS = int(sys.argv[2]) if len(sys.argv) > 2 else 2000
CONC = int(sys.argv[3]) if len(sys.argv) > 3 else 100
HOST = "127.0.0.1"
lat, out, lock = [], Counter(), threading.Lock()
seats_confirmed = [0]

def one(i):
    c = http.client.HTTPConnection(HOST, PORT, timeout=60)
    t0 = time.perf_counter()
    try:
        if i % 5 == 0:  # ~20% of the crowd also refreshes the seat board
            c.request("GET", "/api/seats"); c.getresponse().read()
        body = json.dumps({"user_id": f"u{i}", "seats": 2 if i % 10 == 0 else 1})
        c.request("POST", "/api/hold", body=body, headers={"Content-Type": "application/json"})
        r = json.loads(c.getresponse().read())
        with lock: out["hold_ok" if r.get("ok") else "hold_" + str(r.get("status", "?"))] += 1
        if r.get("ok"):
            c.request("POST", "/api/pay", body=json.dumps(
                {"reservation_id": r["reservation_id"], "user_id": f"u{i}"}),
                headers={"Content-Type": "application/json"})
            p = json.loads(c.getresponse().read())
            with lock:
                out["pay_confirmed" if p.get("ok") else "pay_released"] += 1
                if p.get("ok"): seats_confirmed[0] += len(p.get("seats", []))
    except Exception:
        with lock: out["error"] += 1
    finally:
        c.close()
        with lock: lat.append((time.perf_counter() - t0) * 1000)

t0 = time.perf_counter()
with ThreadPoolExecutor(max_workers=CONC) as ex:
    list(ex.map(one, range(USERS)))
wall = time.perf_counter() - t0
lat.sort()

c = http.client.HTTPConnection(HOST, PORT, timeout=30)
c.request("GET", "/api/seats"); seats = json.loads(c.getresponse().read())
c.request("GET", "/api/metrics"); met = json.loads(c.getresponse().read())

p = lambda q: lat[int(q * (len(lat) - 1))]
print(f"\napp load test: {USERS} buyers, concurrency {CONC}, wall {wall:.1f}s")
print(f"throughput: {USERS / wall:.0f} buyer flows/s")
print(f"end-to-end latency ms (hold+pay through the app): p50 {p(.50):.0f}  p95 {p(.95):.0f}  p99 {p(.99):.0f}  max {lat[-1]:.0f}")
for k, v in sorted(out.items()):
    print(f"  {k}: {v}")
print(f"seats confirmed by the app: {seats_confirmed[0]}")
print(f"engine: {seats}")
print(f"engine requests received (through app): {met.get('received')}  rate limited: {met.get('rate_limited', 0) + met.get('user_rate_limited', 0) + met.get('ip_rate_limited', 0)}")
ok = seats["sold"] == seats_confirmed[0] and out["error"] == 0
print("DOUBLE-SELL CHECK:", "PASS" if ok else "FAIL")
sys.exit(0 if ok else 1)
