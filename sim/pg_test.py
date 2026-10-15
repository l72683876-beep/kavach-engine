#!/usr/bin/env python3
"""Kavach Postgres write-behind acceptance tests. Requires a Postgres server
running and the engine built with `go build -tags postgres` as ./kavach_pg.
The write-behind contract: the local append-only log is the source of truth;
Postgres mirrors it asynchronously; Postgres downtime never blocks a request;
restart resumes from the stored cursor without duplicating rows."""
import json, subprocess, sys, time, urllib.request

DSN_ENV = {"KAVACH_PG_DSN": "postgres://kavach@127.0.0.1:5432/postgres?sslmode=disable"}
DSN = DSN_ENV["KAVACH_PG_DSN"]
PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8200
results = []

def check(name, ok, detail=""):
    results.append(ok)
    print(("PASS  " if ok else "FAIL  ") + name + (("  " + str(detail)) if detail else ""))

def sql(q):
    out = subprocess.run(["go", "run", "./pgq", q], cwd="engine", env={**dict(__import__("os").environ), **DSN_ENV},
                         capture_output=True, text=True, timeout=120)
    if out.returncode != 0:
        raise RuntimeError(out.stderr.strip())
    lines = [line for line in out.stdout.strip().splitlines() if line]
    return [val.strip() for line in lines for val in line.split(" | ")]

def req(method, path, body=None):
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(f"http://127.0.0.1:{PORT}{path}", data=data, method=method,
                               headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(r, timeout=20) as resp:
        return resp.status, json.loads(resp.read() or b"{}")

def start_engine():
    p = subprocess.Popen(["./kavach_pg", "-seats", "50", "-workers", "4", "-ip-rate", "0", "-user-rate", "0",
                          "-pg-dsn", DSN, "-node-id", "t1", "-addr", f"127.0.0.1:{PORT}",
                          "-log", "pg_bookings.jsonl", "-holds-log", "pg_holds.jsonl"],
                         cwd="engine", stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1.0)
    return p

def wait_for(cond, timeout=25, what="rows"):
    end = time.time() + timeout
    last = None
    while time.time() < end:
        try:
            last = cond()
            if last:
                return last
        except Exception as e:
            last = e
        time.sleep(0.5)
    raise TimeoutError(f"{what} did not arrive; last={last}")

def bookings_in_pg():
    n = sql("SELECT count(*) FROM kavach_events WHERE source='pg_bookings.jsonl'")[0]
    return int(n)

subprocess.run(["go", "run", "./pgq", "DROP TABLE IF EXISTS kavach_events, kavach_ship_state"],
               cwd="engine", env={**dict(__import__("os").environ), **DSN_ENV}, capture_output=True, timeout=120)
for f in ["pg_bookings.jsonl", "pg_holds.jsonl"]:
    try:
        import os
        os.remove("engine/" + f)
    except FileNotFoundError:
        pass

eng = start_engine()
for i in range(10):
    st, d = req("POST", "/book", {"user_id": f"u{i}", "idempotency_key": f"k{i}", "seats": 1})
    assert st == 200 and d["status"] == "confirmed", d

n = wait_for(lambda: bookings_in_pg() if bookings_in_pg() >= 10 else None, what="10 bookings in Postgres")
check("10 bookings shipped to Postgres", n == 10, n)
check("cursor is stored in Postgres", int(sql("SELECT byte_offset FROM kavach_ship_state WHERE source='pg_bookings.jsonl'")[0]) > 0)

# restart: the new process resumes from the stored cursor, no duplicates
eng.kill(); eng.wait()
eng = start_engine()
for i in range(10, 15):
    st, d = req("POST", "/book", {"user_id": f"u{i}", "idempotency_key": f"k{i}", "seats": 1})
    assert st == 200 and d["status"] == "confirmed", d
n = wait_for(lambda: bookings_in_pg() if bookings_in_pg() >= 15 else None, what="15 bookings after restart")
total, uniq = sql("SELECT count(*), count(DISTINCT line_off) FROM kavach_events WHERE source='pg_bookings.jsonl'")
check("restart resumes from the cursor, no duplicate rows", int(total) == 15 and total == uniq, f"total={total} distinct={uniq}")

# Postgres down: the engine must keep serving, then catch up when it returns
subprocess.run(["/workspace/pg/pgdist/bin/pg_ctl", "-D", "/workspace/pg/data", "stop", "-m", "fast"],
               capture_output=True, timeout=60)
time.sleep(1)
confirmed_during_outage = 0
for i in range(15, 20):
    st, d = req("POST", "/book", {"user_id": f"u{i}", "idempotency_key": f"k{i}", "seats": 1})
    if st == 200 and d["status"] == "confirmed":
        confirmed_during_outage += 1
check("requests keep succeeding while Postgres is down", confirmed_during_outage == 5, confirmed_during_outage)

subprocess.run(["/workspace/pg/pgdist/bin/pg_ctl", "-D", "/workspace/pg/data",
                "-l", "/workspace/pg/pg.log", "-o", "-p 5432 -k /tmp -c listen_addresses=127.0.0.1", "start"],
               capture_output=True, timeout=60)
time.sleep(2)
n = wait_for(lambda: bookings_in_pg() if bookings_in_pg() >= 20 else None, what="catch-up after Postgres returns")
total, uniq = sql("SELECT count(*), count(DISTINCT line_off) FROM kavach_events WHERE source='pg_bookings.jsonl'")
check("catches up after the outage, still no duplicates", int(total) == 20 and total == uniq, f"total={total} distinct={uniq}")

st, m = req("GET", "/metrics")
check("metrics report the sink", m.get("pg_shipped", 0) >= 10 and m.get("pg_failed", 0) >= 1, {k: m.get(k) for k in ("pg_shipped", "pg_failed")})

eng.kill(); eng.wait()
fails = results.count(False)
print(f"\n{len(results) - fails}/{len(results)} passed")
sys.exit(1 if fails else 0)
