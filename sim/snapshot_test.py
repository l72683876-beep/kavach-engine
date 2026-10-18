#!/usr/bin/env python3
"""Kavach WAL snapshot + compaction acceptance tests.

The engine runs with snapshots ON, takes real traffic, and gets SIGKILLed
mid-flight, the hardest possible crash. On restart the state must come back
exactly, the newest snapshot must be used (only a short tail replayed), and
old log segments must be compacted away. Run with the engine already built:
    cd engine && go build -o kavach . && cd .. && python3 sim/snapshot_test.py
"""
import atexit, json, os, signal, subprocess, sys, time, urllib.request, urllib.error

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8096
PROCS = []

def _killall():
    for proc in PROCS:
        try:
            os.kill(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass

atexit.register(_killall)
ENGINE = "./kavach"
LOGS = ["snap_bookings.jsonl", "snap_holds.jsonl"]
results = []

def check(name, ok, detail=""):
    results.append(ok)
    print(("PASS  " if ok else "FAIL  ") + name + (("  " + str(detail)) if detail else ""))

def req(method, path, body=None):
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(f"http://127.0.0.1:{PORT}{path}", data=data, method=method,
                               headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(r, timeout=10) as resp:
            return resp.status, json.loads(resp.read() or b"{}")
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")

def start():
    subprocess.run(["pkill", "-f", "snap_bookings.jsonl"], stderr=subprocess.DEVNULL)
    time.sleep(0.5)
    p = subprocess.Popen([ENGINE, "-seats", "50", "-workers", "4", "-hold-ttl", "300", "-ip-rate", "0",
                          "-log", "snap_bookings.jsonl", "-holds-log", "snap_holds.jsonl",
                          "-snapshot-every", "30", "-snapshot-interval", "5",
                          "-addr", f":{PORT}"], cwd="engine",
                         stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    for _ in range(60):
        try:
            req("GET", "/seats")
            break
        except Exception:
            time.sleep(0.2)
    PROCS.append(p)
    return p

for f in LOGS:
    for suffix in ["", ".snap-1", ".snap-2", ".snap-3"]:
        try:
            os.remove("engine/" + f + suffix)
        except FileNotFoundError:
            pass
for seq in range(1, 6):
    try:
        os.remove(f"engine/snapshot-{seq}.bin")
    except FileNotFoundError:
        pass

# ---- phase 1: traffic with snapshots turning over at least once ----
p = start()
st, seats = req("GET", "/seats")
check("engine up, 50 free", seats == {"total": 50, "sold": 0, "held": 0, "free": 50}, seats)

st, b1 = req("POST", "/book", {"user_id": "buyer1", "idempotency_key": "bk-1", "seats": 2})
check("booked 2 (pre-snapshot)", st == 200 and b1.get("status") == "confirmed", b1)

# enough events to cross -snapshot-every=30, so snapshot 1 lands and rotates
for i in range(35):
    req("POST", "/reserve", {"user_id": f"holder{i}", "idempotency_key": f"hold-{i}", "seats": 1})

time.sleep(1.5)  # give the snapshot trigger a beat
segs = [f for f in os.listdir("engine") if f.startswith("snap_bookings.jsonl.snap-")]
snaps = [f for f in os.listdir("engine") if f.startswith("snapshot-") and f.endswith(".bin")]
check("snapshot written and logs rotated", len(snaps) >= 1 and len(segs) >= 1, f"{snaps} {segs}")

# a reservation created AFTER the snapshot: recovery must find it in the tail
st, r_mid = req("POST", "/reserve", {"user_id": "mid", "idempotency_key": "hold-mid", "seats": 3})
mid_rid = r_mid.get("reservation_id", "")
check("reserved 3 (post-snapshot)", st == 200 and r_mid.get("status") == "held", r_mid)

# fill the house so the waitlist is the only way in
for i in range(25):
    req("POST", "/reserve", {"user_id": f"filler{i}", "idempotency_key": f"fill-{i}", "seats": 1})
st, seats = req("GET", "/seats")
check("house filled: 0 free", seats.get("free") == 0, seats)

st, r_over = req("POST", "/reserve", {"user_id": "over", "idempotency_key": "over-1", "seats": 1})
check("overflow returns sold_out", r_over.get("status") == "sold_out", (st, r_over))

st, w = req("POST", "/waitlist", {"user_id": "waiter", "idempotency_key": "wl-1", "seats": 1})
check("waitlist joined", st == 200 and w.get("status") == "queued", w)

st, seats = req("GET", "/seats")
before = seats
st, wl_before = req("GET", "/waitlist?user_id=waiter")

os.kill(p.pid, signal.SIGKILL)  # no cleanup at all
p.wait()
time.sleep(0.5)

# ---- phase 2: restart on the same logs, snapshot + tail must reconstruct ----
p = start()
st, seats = req("GET", "/seats")
check("seats identical after crash", seats == before, f"{before} -> {seats}")

st, r2 = req("GET", f"/reservation?id={mid_rid}")
check("post-snapshot reservation restored", st == 200 and r2.get("status") == "held", r2)

st, status = req("GET", "/status?idempotency_key=bk-1")
check("pre-snapshot booking idempotency restored",
      st == 200 and status.get("booking_id") == b1.get("booking_id"), status)

# idempotent replay: the same key must NOT book again
st, dup = req("POST", "/book", {"user_id": "buyer1", "idempotency_key": "bk-1", "seats": 2})
check("replay returns the same booking", st == 200 and dup.get("booking_id") == b1.get("booking_id"), dup)

st, metrics = req("GET", "/metrics")
lines = metrics.get("recovery_replayed_lines", -1)
total_events = 2 + 35 + 1 + 25 + 1  # book + holders + mid + fillers + waitlist
check("recovery replayed only a tail (snapshot carried the rest)",
      0 < lines < total_events, f"tail={lines} total~{total_events}")

st, wl_after = req("GET", "/waitlist?user_id=waiter")
check("waitlist entry survived", wl_after == wl_before, f"{wl_before} -> {wl_after}")

# keep running: a second snapshot cycle on restored state must also be clean.
# Release the mid hold first so the bookings have room, which also proves a
# released hold survives snapshot + crash.
st, rel = req("POST", "/release", {"reservation_id": mid_rid})
check("released post-snapshot hold", st == 200 and rel.get("status") == "released", (st, rel))
st, seats_b = req("GET", "/seats")
free_before = seats_b.get("free", 0)
booked_after = 0
for i in range(5):
    st, d = req("POST", "/book", {"user_id": f"post{i}", "idempotency_key": f"post-{i}", "seats": 1})
    if st == 200 and d.get("status") == "confirmed":
        booked_after += 1
check("booked every freed seat after recovery", booked_after == free_before, f"booked={booked_after} free={free_before}")
# the interval trigger needs 5s of age on the restarted engine; poll so the
# check never races the ticker
deadline = time.time() + 20
total = 0
while time.time() < deadline:
    st, metrics = req("GET", "/metrics")
    total = metrics.get("snapshots_total", 0)
    if total >= 2:
        break
    time.sleep(1)
check("snapshot landed after recovery", total >= 1, total)
st, seats2 = req("GET", "/seats")
# the freed seats went partly to the waiting waiter (waitlist fulfilment):
# what must hold is that nothing was lost or double-sold
check("post-recovery snapshot state is clean",
      seats2.get("sold") == before.get("sold") + booked_after
      and seats2.get("sold", 0) + seats2.get("held", 0) == seats2.get("total", -1), seats2)

os.kill(p.pid, signal.SIGKILL)
p.wait()

# ---- phase 3: compaction actually happened ----
all_segs = sorted(f for f in os.listdir("engine") if f.startswith("snap_bookings.jsonl.snap-"))
check("old segments compacted (2-deep retention)", len(all_segs) <= 2, all_segs)

try:
    stderr = p.stderr.read().decode() if p.stderr else ""
except Exception:
    stderr = ""
print("\n--- engine stderr on restart ---")
print(stderr[-1200:] if stderr else "(none)")

print(f"\nTOTAL {len(results)}  PASS {sum(results)}  FAIL {len(results) - sum(results)}")
sys.exit(0 if all(results) else 1)
