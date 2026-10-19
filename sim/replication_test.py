#!/usr/bin/env python3
"""Kavach replication e2e: one leader, one follower. The follower must converge
with the leader under traffic, reject writes with 503, survive a SIGKILL and
catch up from its own WAL on restart, and re-attach when the leader itself
restarts. The never-double-sell invariant must hold on both nodes."""
import hashlib, hmac, json, os, signal, socket, subprocess, sys, time, urllib.request, urllib.error

subprocess.run(["pkill", "-x", "kavach"], capture_output=True)
time.sleep(1.0)

BASE_PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8111
L, F = BASE_PORT, BASE_PORT + 1
results = []

def check(name, ok, detail=""):
    results.append(ok)
    print(("PASS  " if ok else "FAIL  ") + name + (("  " + str(detail)) if detail else ""))

def req(port, method, path, body=None):
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(f"http://127.0.0.1:{port}{path}", data=data, method=method,
                               headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(r, timeout=15) as resp:
            return resp.status, json.loads(resp.read() or b"{}")
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read() or b"{}")

def start(port, node, extra):
    p = subprocess.Popen(["./kavach", "-seats", "100", "-workers", "4", "-ip-rate", "0",
                          "-user-rate", "0", "-replicate-key", "replkey",
                          "-replicate-secret", "replsecret",
                          "-log", f"repl_{node}_bookings.jsonl",
                          "-holds-log", f"repl_{node}_holds.jsonl",
                          "-addr", f"127.0.0.1:{port}"] + extra,
                         cwd="engine", stdout=subprocess.DEVNULL,
                         stderr=open(f"engine/repl_{node}_stderr.log", "ab"))
    time.sleep(0.7)
    return p

def wait_converged(want_sold, limit=12.0):
    end = time.time() + limit
    last = None
    while time.time() < end:
        try:
            st, s = req(F, "GET", "/seats")
            last = s
            if s.get("sold") == want_sold:
                return True, s
        except Exception:
            pass
        time.sleep(0.3)
    return False, last

for n in ["L", "F"]:
    for suf in ["bookings", "holds"]:
        import glob as _glob
for _f in _glob.glob("engine/snapshot-*.bin") + _glob.glob("engine/*.snap-*"):
    try:
        os.remove(_f)
    except OSError:
        pass

for f in [f"repl_{n}_{suf}.jsonl"]:
            try: os.remove("engine/" + f)
            except FileNotFoundError: pass

leader = start(L, "L", [])
follower = start(F, "F", ["-replicate-from", f"http://127.0.0.1:{L}"])

# 1) burst on the leader while the follower tails it
confirmed = 0
for i in range(60):
    st, d = req(L, "POST", "/book", {"user_id": f"u{i}", "idempotency_key": f"bk{i}", "seats": 1})
    if d.get("status") == "confirmed":
        confirmed += 1
check("burst 60 books on leader", confirmed == 60, f"confirmed={confirmed}")

ok, s = wait_converged(60)
check("follower converged to 60 sold", ok and s.get("free") == 40, f"seats={s}")

# 2) follower must reject writes
st, d = req(F, "POST", "/book", {"user_id": "w", "idempotency_key": "wk1", "seats": 1})
check("follower rejects write with 503 follower", st == 503 and d.get("status") == "follower", f"st={st} d={d}")

# 3) SIGKILL follower, more traffic on leader, restart -> catch up from own WAL
follower.send_signal(signal.SIGKILL); follower.wait()
for i in range(60, 80):
    req(L, "POST", "/book", {"user_id": f"u{i}", "idempotency_key": f"bk{i}", "seats": 1})
follower = start(F, "F", ["-replicate-from", f"http://127.0.0.1:{L}"])
ok, s = wait_converged(80)
check("follower restart catches up to 80 from its own WAL", ok and s.get("free") == 20, f"seats={s}")

# 4) SIGKILL the leader too, restart it, new traffic, follower re-attaches
leader.send_signal(signal.SIGKILL); leader.wait()
leader = start(L, "L", [])
for i in range(80, 85):
    st, d = req(L, "POST", "/book", {"user_id": f"u{i}", "idempotency_key": f"bk{i}", "seats": 1})
    if d.get("status") != "confirmed":
        check("post-leader-restart booking", False, f"st={st} d={d}")
ok, s = wait_converged(85)
check("follower re-attaches after leader restart, converges to 85", ok and s.get("free") == 15, f"seats={s}")

st, sL = req(L, "GET", "/seats")
st, sF = req(F, "GET", "/seats")
check("leader and follower agree exactly", sL.get("sold") == sF.get("sold") and sL.get("free") == sF.get("free"), f"L={sL} F={sF}")

# 5) failover: the leader dies for good, the follower is promoted and takes over
leader.send_signal(signal.SIGKILL); leader.wait()

def repl_req(port, method, path, secret="replsecret"):
    ts = str(int(time.time()))
    rid = f"e2e{time.time_ns()}"
    mac = hmac.new(secret.encode(), (ts + "\n" + rid + "\n" + method + "\n" + path + "\nreplkey\n").encode(), hashlib.sha256).hexdigest()
    r = urllib.request.Request(f"http://127.0.0.1:{port}{path}", data=b"" if method == "POST" else None, method=method,
                               headers={"Authorization": "Bearer replkey", "X-Kavach-Timestamp": ts,
                                        "X-Kavach-Request-Id": rid, "X-Kavach-Signature": mac})
    try:
        with urllib.request.urlopen(r, timeout=15) as resp:
            return resp.status, json.loads(resp.read() or b"{}")
    except urllib.error.HTTPError as e:
        raw = e.read() or b"{}"
        try:
            return e.code, json.loads(raw)
        except Exception:
            return e.code, {"raw": raw.decode(errors="replace")}

st, d = repl_req(F, "POST", "/internal/promote", secret="wrongsecret")
check("promote with wrong secret rejected", st == 401, f"st={st} d={d}")
st, d = repl_req(F, "POST", "/internal/promote")
check("promote succeeds with signed request", st == 200 and d.get("status") == "promoted", f"st={st} d={d}")

confirmed = 0
for i in range(85, 90):
    st, d = req(F, "POST", "/book", {"user_id": f"u{i}", "idempotency_key": f"bk{i}", "seats": 1})
    if d.get("status") == "confirmed":
        confirmed += 1
check("promoted follower serves writes", confirmed == 5, f"confirmed={confirmed}")

st, s = req(F, "GET", "/seats")
check("promoted follower state advanced to 90", s.get("sold") == 90 and s.get("free") == 10, f"seats={s}")
st, d = req(F, "GET", "/metrics")
check("role reports leader after promote", d.get("role") == "leader", f"role={d.get('role')}")

follower.send_signal(signal.SIGTERM)
time.sleep(0.5)
print(f"\n{sum(results)}/{len(results)} passed")
sys.exit(0 if all(results) else 1)
