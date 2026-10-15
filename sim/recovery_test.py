#!/usr/bin/env python3
"""Kavach restart-recovery acceptance tests. Book and hold, SIGKILL the
engine, restart on the same logs, and prove every seat, reservation, waitlist
position and idempotency key came back exactly as it was."""
import json, os, signal, subprocess, sys, time, urllib.request, urllib.error

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8090
ENGINE = "./kavach"
LOGS = ["rec_bookings.jsonl", "rec_holds.jsonl"]
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
    p = subprocess.Popen([ENGINE, "-seats", "50", "-workers", "4", "-hold-ttl", "5", "-ip-rate", "0",
                          "-log", "rec_bookings.jsonl", "-holds-log", "rec_holds.jsonl",
                          "-addr", f":{PORT}"], cwd="engine",
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(0.8)
    return p

for f in LOGS:
    try:
        os.remove("engine/" + f)
    except FileNotFoundError:
        pass

p = start()
st, seats = req("GET", "/seats")
check("engine up, 50 free", seats == {"total": 50, "sold": 0, "held": 0, "free": 50}, seats)
st, b = req("POST", "/book", {"user_id": "buyer", "idempotency_key": "bk-1", "seats": 2})
check("booked 2 before the crash", st == 200 and b.get("status") == "confirmed", b)
st, r1 = req("POST", "/reserve", {"user_id": "holder", "idempotency_key": "hold-1", "seats": 3})
rid = r1.get("reservation_id", "")
check("reserved 3 before the crash", st == 200 and r1.get("status") == "held", r1)
# fill the house so the waitlist is the only way in
for i in range(45):
    st, d = req("POST", "/reserve", {"user_id": f"filler{i}", "idempotency_key": f"fill-{i}", "seats": 1})
st, seats = req("GET", "/seats")
check("house filled: 0 free", seats == {"total": 50, "sold": 2, "held": 48, "free": 0}, seats)
st, w = req("POST", "/waitlist", {"user_id": "waiter", "idempotency_key": "wl-1", "seats": 1})
check("waitlist joined before the crash", st == 200 and w.get("status") == "queued", w)

os.kill(p.pid, signal.SIGKILL)  # the hardest possible crash: no cleanup at all
p.wait()
time.sleep(0.5)

p = start()
st, seats = req("GET", "/seats")
check("after restart: sold and held restored exactly",
      seats == {"total": 50, "sold": 2, "held": 48, "free": 0}, seats)
st, d = req("GET", f"/reservation?id={rid}")
check("reservation survives the crash", st == 200 and d.get("status") == "held", d)
st, d = req("POST", "/confirm", {"reservation_id": rid, "user_id": "holder"})
check("hold can still be confirmed after restart", st == 200 and d.get("status") == "confirmed", d)
st, d = req("GET", "/waitlist?user_id=waiter")
check("waitlist position survives the crash", st == 200 and d.get("entries") and d["entries"][0]["position"] == 1, d)
st, d = req("POST", "/book", {"user_id": "buyer", "idempotency_key": "bk-1", "seats": 2})
check("pre-crash idempotency key still resolves", st == 200 and d.get("booking_id") == b.get("booking_id"), d)

# the restored hold expiry is honored: every filler hold expires, seats
# return, and the restored waitlist entry is fulfilled automatically.
# Poll for the window rather than sleeping a fixed number of seconds.
deadline = time.time() + 12
seats = {}
while time.time() < deadline:
    st, seats = req("GET", "/seats")
    if seats["sold"] == 5 and seats["held"] == 1 and seats["free"] == 44:
        break
    time.sleep(0.5)
check("expired holds returned to the pool after restart",
      seats.get("sold") == 5 and seats.get("held") == 1 and seats.get("free") == 44, seats)
st, d = req("GET", "/waitlist?user_id=waiter")
check("restored waitlist entry was auto-fulfilled", st == 200 and d.get("entries") == [], d)
st, d = req("GET", "/metrics")
check("recovery did not corrupt counters",
      d.get("confirmed") == 1 and d.get("holds_expired", 0) >= 45 and d.get("waitlist_fulfilled") == 1, d)

os.kill(p.pid, signal.SIGKILL)
p.wait()
fails = results.count(False)
print(f"\n{len(results) - fails}/{len(results)} passed")
sys.exit(1 if fails else 0)
