#!/usr/bin/env python3
"""Kavach hold/confirm lifecycle acceptance tests: run against a live engine
started with -auth (api keys + HMAC) and a short -hold-ttl (3s recommended).
Exit non-zero on any failure."""
import hashlib, hmac, http.client, json, sys, time, uuid
from concurrent.futures import ThreadPoolExecutor

HOST, PORT = "127.0.0.1", int(sys.argv[1]) if len(sys.argv) > 1 else 8080
API_KEY, TENANT2_KEY, SECRET = "testkey", "otherkey", "testsecret"
results = []

def request(method, path, body=None, key=API_KEY, sign=True, auth=True):
    body_bytes = json.dumps(body).encode() if body is not None else b""
    conn = http.client.HTTPConnection(HOST, PORT, timeout=30)
    headers = {"Content-Type": "application/json"}
    if auth:
        ts = str(int(time.time()))
        rid = uuid.uuid4().hex
        headers["Authorization"] = "Bearer " + key
        headers["X-Kavach-Timestamp"] = ts
        headers["X-Kavach-Request-Id"] = rid
        if sign:
            mac = hmac.new(SECRET.encode(), (ts + "\n" + rid + "\n" + method + "\n" + path + "\n").encode() + body_bytes, hashlib.sha256)
            headers["X-Kavach-Signature"] = mac.hexdigest()
    conn.request(method, path, body=body_bytes if body is not None else None, headers=headers)
    r = conn.getresponse(); raw = r.read(); conn.close()
    return r.status, (json.loads(raw) if raw else {})

def check(name, ok, detail=""):
    results.append((name, ok))
    print(("PASS  " if ok else "FAIL  ") + name + (("  " + detail) if detail else ""))

seats0 = request("GET", "/seats")[1]

# 1: reserve holds seats and reports a TTL
st, d = request("POST", "/reserve", {"user_id": "priya", "idempotency_key": "r1", "seats": 2})
check("reserve returns held with reservation id and ttl",
      st == 200 and d.get("status") == "held" and len(d.get("seats", [])) == 2 and d.get("hold_seconds", 0) > 0, f"{st} {d}")
rid1 = d.get("reservation_id", "")

# 2: seats moved out of free
seats1 = request("GET", "/seats")[1]
check("reserve removes seats from free pool", seats1["free"] == seats0["free"] - 2 and seats1["held"] >= 2, f"{seats0} -> {seats1}")

# 3: same idempotency key returns the same reservation
st, d = request("POST", "/reserve", {"user_id": "priya", "idempotency_key": "r1", "seats": 2})
check("re-reserve same key same reservation", st == 200 and d.get("reservation_id") == rid1, f"{st} {d}")

# 4: same key different payload is a conflict
st, d = request("POST", "/reserve", {"user_id": "priya", "idempotency_key": "r1", "seats": 3})
check("re-reserve same key different payload conflicted", st == 409 and d.get("status") == "idempotency_conflict", f"{st} {d}")

# 5: confirm turns the hold into a booking
st, d = request("POST", "/confirm", {"reservation_id": rid1, "user_id": "priya"})
check("confirm returns confirmed with booking id", st == 200 and d.get("status") == "confirmed" and d.get("booking_id"), f"{st} {d}")
bid1 = d.get("booking_id", "")
seats2 = request("GET", "/seats")[1]
check("confirm moves seats to sold", seats2["sold"] == seats1["sold"] + 2, f"{seats1} -> {seats2}")

# 6: re-confirm is idempotent (same booking back)
st, d = request("POST", "/confirm", {"reservation_id": rid1, "user_id": "priya"})
check("re-confirm returns the same booking", st == 200 and d.get("booking_id") == bid1, f"{st} {d}")

# 7: reserve then release frees the seats again
st, d = request("POST", "/reserve", {"user_id": "amit", "idempotency_key": "r2", "seats": 3})
rid2 = d.get("reservation_id", "")
st, d = request("POST", "/release", {"reservation_id": rid2})
check("release returns released", st == 200 and d.get("status") == "released", f"{st} {d}")
seats3 = request("GET", "/seats")[1]
check("release returns seats to the free pool", seats3["free"] == seats1["free"], f"{seats1} -> {seats3}")

# 8: confirm after release is rejected
st, d = request("POST", "/confirm", {"reservation_id": rid2, "user_id": "amit"})
check("confirm after release rejected", st == 409 and d.get("status") == "released", f"{st} {d}")

# 9: confirm of an unknown reservation is a 404, never a leak
st, d = request("POST", "/confirm", {"reservation_id": "RSV99999999", "user_id": "amit"})
check("confirm unknown reservation is 404", st == 404, f"{st} {d}")

# 10: another tenant cannot see or confirm our reservation
st, d = request("GET", "/reservation?id=" + rid1, key=TENANT2_KEY)
check("other tenant cannot read our reservation", st == 404, f"{st} {d}")
st, d = request("POST", "/confirm", {"reservation_id": rid1, "user_id": "priya"}, key=TENANT2_KEY)
check("other tenant cannot confirm our reservation", st == 404, f"{st} {d}")

# 11: expiry returns abandoned holds to the free pool (engine hold-ttl = 3s)
st, d = request("POST", "/reserve", {"user_id": "gopal", "idempotency_key": "r3", "seats": 2})
rid3 = d.get("reservation_id", "")
time.sleep(4.5)
seats4 = request("GET", "/seats")[1]
st, d = request("GET", "/reservation?id=" + rid3)
check("expired hold is reported expired", d.get("status") == "expired", f"{d}")
check("expiry returns seats to the free pool", seats4["free"] == seats1["free"], f"{seats4}")

# 12: confirm after expiry is rejected, the seats are gone
st, d = request("POST", "/confirm", {"reservation_id": rid3, "user_id": "gopal"})
check("confirm after expiry rejected", st == 409 and d.get("status") == "expired", f"{st} {d}")

# 13: rush of reserves: exactly the free seats can be held, then all confirmed
seats_rush0 = request("GET", "/seats")[1]
free_now = seats_rush0["free"]
def one(i):
    return request("POST", "/reserve", {"user_id": f"rush{i}", "idempotency_key": f"rush-{i}", "seats": 1})
with ThreadPoolExecutor(max_workers=200) as ex:
    out = list(ex.map(one, range(free_now * 3)))
held = [(f"rush{i}", d) for i, (st_, d) in dict(zip(range(free_now * 3), out)).items() if d.get("status") == "held"]
check("rush: exactly the free seats get held", len(held) == free_now, f"held={len(held)} free={free_now}")
def confirm_one(t):
    user, d = t
    return request("POST", "/confirm", {"reservation_id": d["reservation_id"], "user_id": user})
with ThreadPoolExecutor(max_workers=100) as ex:
    cout = list(ex.map(confirm_one, held))
confirmed = [d for st_, d in cout if d.get("status") == "confirmed"]
seatsF = request("GET", "/seats")[1]
ids = set(d.get("booking_id") for d in confirmed)
check("rush: all holds confirmed, no oversell", len(confirmed) == free_now and seatsF["sold"] - seats_rush0["sold"] == free_now and seatsF["free"] == 0,
      f"confirmed={len(confirmed)} sold_delta={seatsF['sold'] - seats_rush0['sold']} free={seatsF['free']}")
check("rush: all booking ids unique", len(ids) == len(confirmed), f"ids={len(ids)}")

fails = [n for n, ok in results if not ok]
print(f"\n{len(results) - len(fails)}/{len(results)} passed")
sys.exit(1 if fails else 0)
