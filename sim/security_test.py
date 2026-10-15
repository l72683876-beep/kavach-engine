#!/usr/bin/env python3
"""Kavach security acceptance tests: run against a live engine started with
-auth (api keys + HMAC). Exit non-zero on any failure."""
import hashlib, hmac, http.client, json, sys, time, uuid
from concurrent.futures import ThreadPoolExecutor

HOST, PORT = "127.0.0.1", int(sys.argv[1]) if len(sys.argv) > 1 else 8080
API_KEY, SECRET = "testkey", "testsecret"
results = []

def request(method, path, body=None, auth=True, sign=True, ts_drift=0, rid=None, key=API_KEY, secret=SECRET):
    body_bytes = json.dumps(body).encode() if body is not None else b""
    conn = http.client.HTTPConnection(HOST, PORT, timeout=30)
    headers = {"Content-Type": "application/json"}
    if auth:
        headers["Authorization"] = "Bearer " + key
        ts = str(int(time.time()) + ts_drift)
        rid = rid or uuid.uuid4().hex
        headers["X-Kavach-Timestamp"] = ts
        headers["X-Kavach-Request-Id"] = rid
        if sign:
            mac = hmac.new(secret.encode(), (ts + "\n" + rid + "\n").encode() + body_bytes, hashlib.sha256)
            headers["X-Kavach-Signature"] = mac.hexdigest()
    conn.request(method, path, body=body_bytes if body is not None else None, headers=headers)
    r = conn.getresponse(); raw = r.read(); conn.close()
    return r.status, (json.loads(raw) if raw else {})

def check(name, ok, detail=""):
    results.append((name, ok))
    print(("PASS  " if ok else "FAIL  ") + name + (("  " + detail) if detail else ""))

# 1: no auth header at all
st, d = request("POST", "/book", {"user_id": "u1", "idempotency_key": "k1", "seats": 1}, auth=False)
check("unauthenticated request rejected", st == 401 and d.get("status") == "unauthorized", f"{st} {d}")

# 2: wrong bearer key
st, d = request("POST", "/book", {"user_id": "u1", "idempotency_key": "k2", "seats": 1}, key="wrongkey")
check("wrong api key rejected", st == 401, f"{st} {d}")

# 3: bad signature
st, d = request("POST", "/book", {"user_id": "u1", "idempotency_key": "k3", "seats": 1}, sign=False)
check("unsigned request rejected in hmac mode", st == 401, f"{st} {d}")

# 4: tampered signature (signed with the wrong secret)
st2, d2 = request("POST", "/book", {"user_id": "u1", "idempotency_key": "k5", "seats": 1}, sign=True, secret="othersecret")
check("tampered signature rejected", st2 == 401, f"{st2} {d2}")

# 5: stale timestamp
st, d = request("POST", "/book", {"user_id": "u1", "idempotency_key": "k6", "seats": 1}, ts_drift=-4000)
check("stale timestamp rejected", st == 401, f"{st} {d}")

# 6: valid signed request books
st, d = request("POST", "/book", {"user_id": "priya", "idempotency_key": "ok-1", "seats": 1})
check("valid signed request confirmed", st == 200 and d.get("status") == "confirmed", f"{st} {d}")
booking_id = d.get("booking_id", "")

# 7: replay of the exact same signed request (same request id) is rejected
ts = str(int(time.time()))
def raw_replay():
    body = json.dumps({"user_id": "priya", "idempotency_key": "ok-1", "seats": 1}).encode()
    mac = hmac.new(SECRET.encode(), (ts + "\n" + "fixed-rid-1" + "\n").encode() + body, hashlib.sha256).hexdigest()
    conn = http.client.HTTPConnection(HOST, PORT, timeout=30)
    conn.request("POST", "/book", body=body, headers={
        "Content-Type": "application/json", "Authorization": "Bearer " + API_KEY,
        "X-Kavach-Timestamp": ts, "X-Kavach-Request-Id": "fixed-rid-1", "X-Kavach-Signature": mac})
    r = conn.getresponse(); data = json.loads(r.read()); conn.close()
    return r.status, data
st1, d1 = raw_replay()
st2, d2 = raw_replay()
check("replayed request rejected", st1 == 200 and st2 == 401 and d2.get("status") == "replay", f"{st1}/{st2} {d2}")

# 8: same idempotency key + same payload -> same booking (idempotent)
st, d = request("POST", "/book", {"user_id": "priya", "idempotency_key": "ok-1", "seats": 1})
check("same key same payload returns same booking", st == 200 and d.get("booking_id") == booking_id, f"{st} {d}")

# 9: same key, different payload -> conflict
st, d = request("POST", "/book", {"user_id": "priya", "idempotency_key": "ok-1", "seats": 2})
check("same key different payload rejected", st == 200 and d.get("status") == "idempotency_conflict", f"{st} {d}")

# 10: status endpoint resolves an ambiguous key
st, d = request("GET", "/status?idempotency_key=ok-1")
check("status endpoint returns stored outcome", st == 200 and d.get("booking_id") == booking_id, f"{st} {d}")

# 11: oversized body rejected
big = {"user_id": "u", "idempotency_key": "big", "seats": 1, "junk": "x" * 40000}
st, d = request("POST", "/book", big)
check("oversized body rejected", st == 400, f"{st}")

# 12: unknown field rejected (strict schema)
st, d = request("POST", "/book", {"user_id": "u", "idempotency_key": "uf", "seats": 1, "admin": True})
check("unknown field rejected", st == 400, f"{st}")

# 13: mini rush with auth on, no double-sell
N_SEATS, N_REQ = 100, 2000
seats_before = request("GET", "/seats")[1]
def one(i):
    return request("POST", "/book", {"user_id": f"rush{i}", "idempotency_key": f"rush-{i}", "seats": 1})
with ThreadPoolExecutor(max_workers=200) as ex:
    out = list(ex.map(one, range(N_REQ)))
confirmed = [d for st_, d in out if d.get("status") == "confirmed"]
seats_after = request("GET", "/seats")[1]
sold_expected = seats_after["sold"] - seats_before["sold"]
ids = set(d.get("booking_id") for d in confirmed)
free_before = seats_before["free"]
check("authed rush: exactly the free seats sold", len(confirmed) == free_before and sold_expected == free_before,
      f"confirmed={len(confirmed)} delta={sold_expected} free_before={free_before}")
check("authed rush: all booking ids unique", len(ids) == len(confirmed), f"ids={len(ids)}")

fails = [n for n, ok in results if not ok]
print(f"\n{len(results) - len(fails)}/{len(results)} passed")
sys.exit(1 if fails else 0)
