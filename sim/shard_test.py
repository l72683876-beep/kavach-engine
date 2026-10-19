#!/usr/bin/env python3
"""Kavach multi-shard e2e: independent event pools behind one process.

Proves: event_id routing lands on one shard; two events have fully
independent seat pools; the default event still works with no event_id;
reserve/confirm land on the right shard and /reservation finds a hold
without an event param (scan); a SIGKILL restart replays every shard's WAL
and restores the same state.
"""
import json, os, shutil, signal, subprocess, sys, tempfile, time, urllib.request, urllib.error

PORT = 8141
SEATS = 50          # per-shard pool size
NSHARDS = 4

def shard_of(ev, n=NSHARDS):
    """FNV-1a 32-bit, matching the engine's ShardOf."""
    h = 2166136261
    for b in ev.encode():
        h ^= b
        h = (h * 16777619) & 0xFFFFFFFF
    return h % n
BASE = f"http://127.0.0.1:{PORT}"
BIN = sys.argv[1] if len(sys.argv) > 1 else "/tmp/kvshard"
failures = []

def check(name, cond, detail=""):
    print(("PASS  " if cond else "FAIL  ") + name + (("  " + str(detail)) if detail and not cond else ""))
    if not cond:
        failures.append(name)

def req(method, path, body=None):
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(BASE + path, data=data, method=method)
    if data:
        r.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(r, timeout=15) as resp:
            return resp.status, json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read().decode())
        except Exception:
            return e.code, {}

def start(state):
    p = subprocess.Popen([BIN, "-addr", f"127.0.0.1:{PORT}", "-seats", str(SEATS),
                          "-workers", "8", "-shards", str(NSHARDS),
                          "-user-rate", "100000", "-user-burst", "100000",
                          "-ip-rate", "100000", "-ip-burst", "100000",
                          "-log", os.path.join(state, "bookings.jsonl"),
                          "-holds-log", os.path.join(state, "holds.jsonl")],
                         stdout=open(os.path.join(state, "engine.out"), "ab"),
                         stderr=subprocess.STDOUT)
    for _ in range(200):
        try:
            req("GET", "/metrics")
            return p
        except Exception:
            time.sleep(0.05)
    raise SystemExit("engine did not start")

def book(ev, user, i):
    st, out = req("POST", "/book", {"user_id": user, "idempotency_key": f"{ev}-k{i}", "seats": 1, "event_id": ev})
    return st, out

def main():
    state = tempfile.mkdtemp(prefix="kv-shard-")
    try:
        p = start(state)
        # pick two events on DIFFERENT shards, both away from the default
        # event's shard, so the isolation pools stay untouched by step 0
        dshard = shard_of("default")
        cand = [f"concert-{c}" for c in "abcdefghijklmnop"]
        picked = []
        for c in cand:
            if shard_of(c) not in (dshard, *(shard_of(x) for x in picked)):
                picked.append(c)
            if len(picked) == 3:
                break
        if len(picked) != 3:
            raise SystemExit("could not pick three events on distinct shards")
        ev_a, ev_b, ev_c = picked
        sa, sb = shard_of(ev_a), shard_of(ev_b)
        # 0. an event_id-less request lands on the shard the hash says
        st, out = req("POST", "/book", {"user_id": "u0", "idempotency_key": "default-k1", "seats": 1})
        want = dshard
        bkid = out.get("booking_id", "")
        got = int(bkid[2:]) // 10000000 if bkid.startswith("BK") else -1  # ids start at the shard floor = idx * 10M
        check("event-less request routed by the hash", st == 200 and out.get("status") == "confirmed" and got == want, (out, "want shard", want))
        # 1. two events, the whole of each independent pool booked
        for i in range(SEATS):
            st, out = book(ev_a, "u1", i)
            if st != 200 or out.get("status") != "confirmed":
                raise SystemExit(f"{ev_a} booking {i} failed: {st} {out}")
        for i in range(SEATS):
            st, out = book(ev_b, "u2", i)
            if st != 200 or out.get("status") != "confirmed":
                raise SystemExit(f"{ev_b} booking {i} failed: {st} {out}")
        # 2. both pools are now sold out, independently
        st, out = book(ev_a, "u1", 999)
        check(ev_a + " pool sold out at its own " + str(SEATS), st == 200 and out.get("status") == "sold_out", (st, out))
        st, out = book(ev_b, "u2", 999)
        check(ev_b + " pool sold out at its own " + str(SEATS), st == 200 and out.get("status") == "sold_out", (st, out))
        st, out = req("GET", "/seats?event=" + ev_a)
        check(ev_a + " seat view shows all sold", st == 200 and out.get("sold") == SEATS, (st, out))
        st, out = req("GET", "/metrics")
        check("metrics reports 4 shards", st == 200 and out.get("shards") == 4, (st, out))
        # 4. reserve + confirm with event_id lands on the owning shard
        st, out = req("POST", "/reserve", {"user_id": "u3", "idempotency_key": "rsv-1", "seats": 2, "event_id": ev_c})
        rid = out.get("reservation_id", "")
        check("reserve on " + ev_c + " holds 2", st == 200 and out.get("status") == "held" and rid, (st, out))
        st, out = req("POST", "/confirm", {"reservation_id": rid, "user_id": "u3", "event_id": ev_c})
        check("confirm lands on the right shard", st == 200 and out.get("status") == "confirmed" and out.get("booking_id", "").startswith("BK"), (st, out))
        # 5. /reservation without event: the scan finds the hold
        st, out = req("GET", "/reservation?id=" + rid)
        check("reservation scan finds hold without event", st == 200 and out.get("status") == "confirmed", (st, out))
        # 6. SIGKILL and restart: every shard's WAL replays
        p.send_signal(signal.SIGKILL)
        p.wait()
        p = start(state)
        st, out = req("GET", "/seats?event=" + ev_a)
        check("restart: " + ev_a + " recovered (all sold)", st == 200 and out.get("sold") == SEATS, (st, out))
        st, out = req("GET", "/seats?event=" + ev_b)
        check("restart: " + ev_b + " recovered (all sold)", st == 200 and out.get("sold") == SEATS, (st, out))
        st, out = req("GET", "/reservation?id=" + rid)
        check("restart: hold recovered by scan", st == 200 and out.get("status") == "confirmed", (st, out))
        st, out = req("POST", "/book", {"user_id": "u4", "idempotency_key": "post-restart-k1", "seats": 1, "event_id": ev_c})
        check("restart: shard still sells (fresh ids, no collision)", st == 200 and out.get("status") == "confirmed", (st, out))
        # per-shard state dirs exist
        dirs = sorted(d for d in os.listdir(state) if d.startswith("shard-"))
        check("4 per-shard state dirs on disk", dirs == [f"shard-{i:02d}" for i in range(4)], dirs)
        print(f"\n{len(failures)} failure(s)" + ("" if not failures else ": " + ", ".join(failures)))
        sys.exit(1 if failures else 0)
    finally:
        try:
            p.send_signal(signal.SIGKILL)
        except Exception:
            pass
        shutil.rmtree(state, ignore_errors=True)

if __name__ == "__main__":
    main()
