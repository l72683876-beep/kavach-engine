#!/usr/bin/env python3
"""Kavach multi-node acceptance tests. Three engine nodes form a cluster via
seat-range sharding: every node owns a disjoint slice, requests forward
around the ring when a slice runs out, and the never-double-sell invariant
must hold across ALL nodes."""
import json, os, signal, subprocess, sys, time, urllib.request, urllib.error

BASE_PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8101
N = 3
PEERS = ",".join(f"127.0.0.1:{BASE_PORT+i}" for i in range(N))
results = []
procs = {}

def check(name, ok, detail=""):
    results.append(ok)
    print(("PASS  " if ok else "FAIL  ") + name + (("  " + str(detail)) if detail else ""))

def req(node, method, path, body=None):
    port = BASE_PORT + node
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(f"http://127.0.0.1:{port}{path}", data=data, method=method,
                               headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(r, timeout=15) as resp:
            return resp.status, json.loads(resp.read() or b"{}")
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")

def start(node):
    i = BASE_PORT + node
    p = subprocess.Popen(["./kavach", "-seats", "100", "-workers", "4", "-ip-rate", "0", "-user-rate", "0",
                          "-peers", PEERS, "-addr", f"127.0.0.1:{i}",
                          "-log", f"cl{node}_bookings.jsonl", "-holds-log", f"cl{node}_holds.jsonl"],
                         cwd="engine", stdout=subprocess.DEVNULL,
                         stderr=open(f"engine/cl{node}_stderr.log", "ab"))
    procs[node] = p
    time.sleep(0.7)
    return p

for n in range(N):
    for f in [f"cl{n}_bookings.jsonl", f"cl{n}_holds.jsonl"]:
        try:
            os.remove("engine/" + f)
        except FileNotFoundError:
            pass
for n in range(N):
    start(n)

st, s = req(0, "GET", "/seats")
check("cluster view: 300 seats across 3 nodes",
      st == 200 and s.get("cluster") and s["total"] == 300 and s["free"] == 300, s)

# fill node 0's slice locally
for i in range(100):
    st, d = req(0, "POST", "/reserve", {"user_id": f"f{i}", "idempotency_key": f"fk{i}", "seats": 1})
st, s = req(0, "GET", "/seats?local=1")
check("node 0 slice full (100 held)", s.get("held") == 100 and s.get("free") == 0, s)

# cross-node reserve through node 0: forwarded to the next ring node
st, d = req(0, "POST", "/reserve", {"user_id": "x1", "idempotency_key": "xk1", "seats": 1})
rid = d.get("reservation_id", "")
check("reserve forwarded off the full node", st == 200 and d.get("status") == "held" and rid.startswith("RSV10"), d)

# confirm it from a THIRD node: forwarded again to the owner
st, d = req(2, "POST", "/confirm", {"reservation_id": rid, "user_id": "x1"})
check("confirm forwarded from another node", st == 200 and d.get("status") == "confirmed", d)

# read it back from yet another node
st, d = req(0, "GET", f"/reservation?id={rid}")
check("reservation readable from any node", st == 200 and d.get("status") == "confirmed", d)

# drain the rest of the cluster through node 0 only
sold_now = 0
drained = False
for i in range(250):
    st, d = req(0, "POST", "/book", {"user_id": f"b{i}", "idempotency_key": f"bk{i}", "seats": 1})
    if d.get("status") == "confirmed":
        sold_now += 1
    if d.get("status") == "sold_out":
        drained = True
        break
check("cluster drained through a single entry node", drained and sold_now == 199, f"sold_now={sold_now}")

st, s = req(1, "GET", "/seats")
check("cluster sold exactly 200, held 100, free 0",
      s.get("sold") == 200 and s.get("held") == 100 and s.get("free") == 0, s)

# no double-sell across ALL node logs
seats_seen, bookings = set(), 0
for n in range(N):
    for line in open(f"engine/cl{n}_bookings.jsonl"):
        e = json.loads(line)
        bookings += 1
        for seat in e["seats"]:
            assert seat not in seats_seen, f"seat {seat} sold twice"
            seats_seen.add(seat)
check("no seat sold twice across the cluster", len(seats_seen) == 200 and bookings == 200,
      f"unique={len(seats_seen)} bookings={bookings}")

# sharded recovery: kill node 1 hard, restart on its logs
procs[1].send_signal(signal.SIGKILL)
procs[1].wait()
time.sleep(0.5)
start(1)
st, s = req(1, "GET", "/seats?local=1")
check("restarted node restored its slice", s.get("sold") == 100 and s.get("held") == 0 and s.get("free") == 0, s)
st, s = req(0, "GET", "/seats")
check("cluster totals survive a node restart",
      s.get("sold") == 200 and s.get("held") == 100 and s.get("free") == 0, s)

st, m = req(0, "GET", "/metrics")
check("forwarding actually happened", m.get("forwarded", 0) > 0, m.get("forwarded"))

for p in procs.values():
    p.kill()
fails = results.count(False)
print(f"\n{len(results) - fails}/{len(results)} passed")
sys.exit(1 if fails else 0)
