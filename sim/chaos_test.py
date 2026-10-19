#!/usr/bin/env python3
"""Kavach chaos acceptance tests. The engine runs with random worker stalls
and a steady rate of contained worker panics; a rush must still sell exactly
the right number of seats, never double-sell, and never crash the process."""
import json, subprocess, sys, time, urllib.request

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8091
ENGINE = "./kavach"
results = []
def check(name, ok, detail=""):
    results.append(ok)
    print(("PASS  " if ok else "FAIL  ") + name + (("  " + str(detail)) if detail else ""))

def get(path):
    with urllib.request.urlopen(f"http://127.0.0.1:{PORT}{path}", timeout=10) as r:
        return json.loads(r.read() or b"{}")

import glob as _glob
for _f in _glob.glob("engine/snapshot-*.bin") + _glob.glob("engine/*.snap-*"):
    try:
        os.remove(_f)
    except OSError:
        pass

for f in ["ch_bookings.jsonl", "ch_holds.jsonl"]:
    subprocess.run(["rm", "-f", "engine/" + f])

p = subprocess.Popen([ENGINE, "-seats", "2000", "-workers", "8", "-ip-rate", "0", "-user-rate", "0",
                      "-chaos-prob", "0.05", "-chaos-stall-ms", "700", "-chaos-panic", "0.04",
                      "-log", "ch_bookings.jsonl", "-holds-log", "ch_holds.jsonl", "-addr", f":{PORT}"],
                     cwd="engine", stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
time.sleep(0.8)
try:
    m = get("/metrics")
    check("engine up with chaos on", "chaos_panics" in m, m.get("chaos_panics"))

    subprocess.run([sys.executable, "sim/simulate.py", "--total", "4000", "--users", "2000",
                    "--concurrency", "500", "--base", f"http://127.0.0.1:{PORT}"], timeout=300)

    time.sleep(1)
    seats = get("/seats")
    check("exactly 2000 seats sold under chaos", seats.get("sold") == 2000, seats)
    check("no double-sell: held plus sold accounted", seats["total"] == seats["sold"] + seats["held"] + seats["free"], seats)

    m = get("/metrics")
    check("chaos stalls actually injected", m.get("chaos_stalls", 0) > 0, m.get("chaos_stalls"))
    check("chaos panics actually injected and contained", m.get("chaos_panics", 0) > 0, m.get("chaos_panics"))
    alive = p.poll() is None
    check("engine survived the chaos run", alive, f"poll={p.poll()}")

    v = subprocess.run([sys.executable, "sim/verify.py", "engine/ch_bookings.jsonl", "2000"],
                       capture_output=True, text=True)
    check("verify.py: no duplicates, no oversell", "ok" in v.stdout.lower() or "duplicate_count\": 0" in v.stdout, v.stdout[-400:])
finally:
    p.terminate()
fails = results.count(False)
print(f"\n{len(results) - fails}/{len(results)} passed")
sys.exit(1 if fails else 0)
