#!/usr/bin/env python3
"""Kavach crash-chaos acceptance tests. Write bursts are SIGKILLed MID-FLIGHT
(the hardest crash: no cleanup, no flush, the process just ceases), then the
engine restarts on the same logs. The contract under test: every write the
engine ACKNOWLEDGED survives (persist-before-ack), nothing is double-sold,
holds and their TTLs come back exactly, and a truncated/garbage WAL tail is
skipped without corrupting state."""
import json, os, signal, subprocess, sys, threading, time, urllib.request, urllib.error
from concurrent.futures import ThreadPoolExecutor

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8123
ENGINE = "./kavach"
results = []

def check(name, ok, detail=""):
    results.append(ok)
    print(("PASS  " if ok else "FAIL  ") + name + (("  " + str(detail)) if detail else ""))

def req(method, path, body=None, timeout=10):
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(f"http://127.0.0.1:{PORT}{path}", data=data, method=method,
                               headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(r, timeout=timeout) as resp:
            return resp.status, json.loads(resp.read() or b"{}")
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read() or b"{}")
        except Exception:
            return e.code, {}
    except Exception:
        return 0, {}  # connection lost mid-write: outcome unknown

def start(logs=("cw_bookings.jsonl", "cw_holds.jsonl"), seats=5000, ttl=6):
    errf = open(f"engine/crash_stderr_{PORT}.log", "ab")
    p = subprocess.Popen([ENGINE, "-seats", str(seats), "-workers", "4", "-hold-ttl", str(ttl),
                          "-ip-rate", "0", "-log", logs[0], "-holds-log", logs[1],
                          "-addr", f":{PORT}"], cwd="engine",
                         stdout=subprocess.DEVNULL, stderr=errf)
    deadline = time.time() + 10
    while time.time() < deadline:
        try:
            req("GET", "/seats", timeout=2)
            return p
        except Exception:
            time.sleep(0.1)
    raise RuntimeError("engine did not come up")

def burst_books(stop_at, acked, lock, prefix):
    """Sequential books from one client until the kill lands; acked ones recorded."""
    i = 0
    while not stop_at.is_set():
        key = f"{prefix}-{i}"
        st, d = req("POST", "/book", {"user_id": key, "idempotency_key": key, "seats": 1})
        if st == 200 and d.get("status") == "confirmed":
            with lock:
                acked[key] = d.get("booking_id", "")
        i += 1

def burst_holds(stop_at, acked, lock, prefix):
    i = 0
    while not stop_at.is_set():
        key = f"{prefix}-h{i}"
        st, d = req("POST", "/reserve", {"user_id": key, "idempotency_key": key, "seats": 1})
        if st == 200 and d.get("status") == "held":
            with lock:
                acked[key] = d.get("reservation_id", "")
        i += 1

# ---- 1. SIGKILL mid booking-burst: every acked booking must survive ----
import glob as _glob
for _f in _glob.glob("engine/snapshot-*.bin") + _glob.glob("engine/*.snap-*"):
    try:
        os.remove(_f)
    except OSError:
        pass

for f in ["cw_bookings.jsonl", "cw_holds.jsonl"]:
    try: os.remove("engine/" + f)
    except FileNotFoundError: pass
p = start()
acked = {}
lock = threading.Lock()
stop = threading.Event()
threads = [threading.Thread(target=burst_books, args=(stop, acked, lock, f"t{i}")) for i in range(10)]
for t in threads: t.start()
time.sleep(1.0)
os.kill(p.pid, signal.SIGKILL)   # mid-flight: requests are on the wire right now
p.wait()
stop.set()
for t in threads: t.join()
time.sleep(0.3)
print(f"  acked before kill: {len(acked)}")

p = start()
st, seats = {}, {}
for _ in range(5):
    st, seats = req("GET", "/seats")
    if st == 200 and "total" in seats: break
    time.sleep(0.5)
check("restart after mid-burst kill", st == 200 and "total" in seats, seats)
check("no oversell after crash: accounted", seats["total"] == seats["sold"] + seats["held"] + seats["free"], seats)
check("sold >= acked bookings", seats["sold"] >= len(acked), f"sold={seats['sold']} acked={len(acked)}")

lost, wrong = [], []
for key, bid in acked.items():
    st, d = req("POST", "/book", {"user_id": key, "idempotency_key": key, "seats": 1})
    if st != 200 or d.get("status") != "confirmed":
        lost.append(key)
    elif bid and d.get("booking_id") != bid:
        wrong.append(key)
check("every acked booking survived the kill", not lost, f"lost={lost[:3]} n={len(lost)}")
check("acked bookings replay to the same booking id", not wrong, f"wrong={wrong[:3]} n={len(wrong)}")

st, m = req("GET", "/metrics")
check("recovery replayed the WAL", m.get("recovery_replayed_lines", 0) > 0, m.get("recovery_replayed_lines"))

# the WAL itself: no duplicates, no oversell
v = subprocess.run([sys.executable, "sim/verify.py", "engine/cw_bookings.jsonl", str(seats["sold"])],
                   capture_output=True, text=True)
check("verify.py clean on post-crash WAL", "duplicate_count\": 0" in v.stdout, v.stdout[-300:])

# ---- 2. SIGKILL mid hold-burst: acked holds restored, TTL still applies ----
p.send_signal(signal.SIGKILL); p.wait()
for f in ["cw_bookings.jsonl", "cw_holds.jsonl"]:
    try: os.remove("engine/" + f)
    except FileNotFoundError: pass
p = start()
holds = {}
stop = threading.Event()
threads = [threading.Thread(target=burst_holds, args=(stop, holds, lock, f"t{i}")) for i in range(10)]
for t in threads: t.start()
time.sleep(1.2)
os.kill(p.pid, signal.SIGKILL)
p.wait()
stop.set()
for t in threads: t.join()
time.sleep(0.3)
print(f"  acked holds before kill: {len(holds)}")

p = start()
st, seats = {}, {}
for _ in range(5):
    st, seats = req("GET", "/seats")
    if st == 200 and "total" in seats: break
    time.sleep(0.5)
check("holds restored after mid-burst kill", seats["held"] >= len(holds), f"held={seats['held']} acked={len(holds)}")
missing = []
def probe(key_rid):
    key, rid = key_rid
    st, d = req("GET", f"/reservation?id={rid}")
    return key if (st != 200 or d.get("status") != "held") else None
# concurrent: the scan must finish inside the hold TTL, serially it cannot
with ThreadPoolExecutor(20) as ex:
    missing = [k for k in ex.map(probe, holds.items()) if k]
check("every acked hold survived the kill", not missing, f"missing={missing[:3]} n={len(missing)}")
if missing:
    with open("engine/missing_holds.json", "w") as f:
        json.dump(missing, f)
    # grep the holds WAL for the missing rids: were they even fsynced before ack?
    wal = open("engine/cw_holds.jsonl", "rb").read().decode("utf-8", "replace")
    in_wal = [k for k in missing if f'"reservation_id":"{holds[k]}"' in wal or f'"reservation_id": "{holds[k]}"' in wal]
    with open("engine/missing_in_wal.json", "w") as f:
        json.dump({"missing": len(missing), "in_wal": in_wal}, f)
    print(f"  DEBUG: {len(in_wal)}/{len(missing)} missing rids found in holds WAL")

# TTL expiry still works on restored holds: everything drains back
deadline = time.time() + 15
while time.time() < deadline:
    st, seats = req("GET", "/seats")
    if seats["held"] == 0 and seats["free"] == seats["total"] - seats["sold"]:
        break
    time.sleep(0.5)
check("restored holds expire on TTL, seats return", seats["held"] == 0, seats)

# ---- 3. truncated/garbage WAL tail: skipped, state intact ----
p.send_signal(signal.SIGKILL); p.wait()
with open("engine/cw_bookings.jsonl", "ab") as f:
    f.write(b'{"ts":"2026-10-19T03:00:00Z","type":"book","user_id":"garbage","seats":99')  # truncated mid-JSON
    f.write(b'\n\xff\xfe not json at all\n')                                               # binary junk
p = start()
st, seats = {}, {}
for _ in range(5):
    st, seats = req("GET", "/seats")
    if st == 200 and "total" in seats: break
    time.sleep(0.5)
check("engine boots on a garbage WAL tail", st == 200 and "total" in seats, seats)
check("garbage tail applied nothing", seats["sold"] < seats["total"], seats)
st, m = req("GET", "/metrics")
check("recovery still replayed the real lines", m.get("recovery_replayed_lines", 0) > 0, m.get("recovery_replayed_lines"))

p.send_signal(signal.SIGKILL); p.wait()
fails = results.count(False)
print(f"\n{len(results) - fails}/{len(results)} passed")
sys.exit(1 if fails else 0)
