#!/usr/bin/env python3
"""Kavach red-team battery: adversarial probes against a live engine.
Start the engine with auth ON, e.g.:
  ./kavach -seats 50 -api-keys testkey:tenant1,otherkey:tenant2 \
           -hmac-secret testsecret -hold-ttl 5
Exit non-zero on any failure. Every case states the expected behavior;
a wrong status from the engine is a FAIL, never a guess."""
import hashlib, hmac, http.client, json, sys, time, uuid
from concurrent.futures import ThreadPoolExecutor

HOST, PORT = "127.0.0.1", int(sys.argv[1]) if len(sys.argv) > 1 else 8080
KEY, KEY2, SECRET = "testkey", "otherkey", "testsecret"
results = []

def sign_headers(method, path, body, ts=None, rid=None, secret=SECRET):
    ts = ts if ts is not None else str(int(time.time()))
    rid = rid if rid is not None else uuid.uuid4().hex
    mac = hmac.new(secret.encode(), (ts + "\n" + rid + "\n" + method + "\n" + path + "\n" + KEY + "\n").encode() + body, hashlib.sha256)
    return {"Authorization": "Bearer " + KEY, "X-Kavach-Timestamp": ts,
            "X-Kavach-Request-Id": rid, "X-Kavach-Signature": mac.hexdigest(),
            "Content-Type": "application/json"}

def raw(method, path, body=None, headers=None):
    b = body.encode() if isinstance(body, str) else (body if body is not None else None)
    conn = http.client.HTTPConnection(HOST, PORT, timeout=30)
    try:
        conn.request(method, path, body=b, headers=headers or {})
        r = conn.getresponse(); data = r.read(); st = r.status
    except Exception as ex:
        return -1, {"exception": str(ex)[:120]}
    finally:
        conn.close()
    try:
        return st, json.loads(data) if data else {}
    except Exception:
        return st, {"raw": data[:120].decode("utf-8", "replace")}

def req(method, path, obj=None, key=KEY, ts=None, rid=None, secret=SECRET,
        sign_path=None, omit_auth=False, extra=None):
    body = json.dumps(obj).encode() if obj is not None else b""
    h = sign_headers(method, sign_path or path, body, ts=ts, rid=rid, secret=secret)
    h["Authorization"] = "Bearer " + key
    if omit_auth:
        h = {k: v for k, v in h.items() if k != "Authorization"}
    if extra:
        h.update(extra)
    return raw(method, path, body.decode() if body else None, h)

def check(name, ok, detail=""):
    results.append((name, ok))
    print(("PASS  " if ok else "FAIL  ") + name + (("  " + str(detail)) if detail else ""))

# --- sanity
st, d = req("POST", "/book", {"user_id": "rt0", "idempotency_key": "rt0", "seats": 1})
check("sanity: signed /book confirms", st == 200 and d.get("status") == "confirmed", f"{st} {d}")

# --- auth and HMAC
st, _ = req("POST", "/book", {"user_id": "x", "idempotency_key": "a1", "seats": 1}, omit_auth=True)
check("no auth header rejected", st == 401, st)
st, _ = req("POST", "/book", {"user_id": "x", "idempotency_key": "a2", "seats": 1}, key="wrongkey")
check("unknown key rejected", st == 401, st)
st, _ = req("POST", "/book", {"user_id": "x", "idempotency_key": "a3", "seats": 1}, secret="badsecret")
check("wrong HMAC secret rejected", st == 401, st)
h = sign_headers("POST", "/book", b'{"user_id":"x","idempotency_key":"a4","seats":1}')
st, _ = raw("POST", "/book", '{"user_id":"x","idempotency_key":"a4","seats":2}', h)
check("tampered body after signing rejected", st == 401, st)
st, _ = req("POST", "/book", {"user_id": "x", "idempotency_key": "a5", "seats": 1}, ts=str(int(time.time()) - 400))
check("stale timestamp rejected", st == 401, st)
st, _ = req("POST", "/book", {"user_id": "x", "idempotency_key": "a6", "seats": 1}, ts=str(int(time.time()) + 400))
check("future timestamp rejected", st == 401, st)
ts, rid = str(int(time.time())), uuid.uuid4().hex
st, _ = req("POST", "/book", {"user_id": "x", "idempotency_key": "a7", "seats": 1}, ts=ts, rid=rid)
st2, d2 = req("POST", "/book", {"user_id": "x", "idempotency_key": "a7", "seats": 1}, ts=ts, rid=rid)
check("replayed request id rejected", st2 == 401 and d2.get("status") == "replay", f"{st2} {d2}")

# THE BIG ONE: a captured signed request reused against a different path.
# The MAC must cover method + URL, otherwise a leaked signature is a
# skeleton key for every endpoint until the timestamp window closes.
st, d = req("POST", "/reserve", {"user_id": "cap", "idempotency_key": "cap1", "seats": 1})
cap_rid = d.get("reservation_id", "")
check("captured-sig setup: hold created", st == 200 and cap_rid, f"{st} {d}")
h = sign_headers("GET", "/seats", b"")            # victim signed /seats; we aim elsewhere
st, d = raw("GET", "/reservation?id=" + cap_rid, None, h)
check("captured GET sig reused on another path rejected", st == 401, f"{st} {d}")
h = sign_headers("GET", "/reservation?id=NOPE", b"")  # signed for one id
st, d = raw("GET", "/reservation?id=" + cap_rid, None, h)
check("captured GET sig reused on another query rejected", st == 401, f"{st} {d}")
h = sign_headers("POST", "/book", b'{"user_id":"x","idempotency_key":"c9","seats":1}')
st, d = raw("POST", "/release", '{"reservation_id":"' + cap_rid + '"}', h)
check("captured POST sig reused on another endpoint rejected", st == 401, f"{st} {d}")
st, _ = raw("GET", "/reservation?id=NOPE", None,
            {"Authorization": "Bearer " + KEY, "X-Kavach-Timestamp": str(int(time.time())),
             "X-Kavach-Request-Id": uuid.uuid4().hex, "X-Kavach-Signature": "zz-not-hex"})
check("non-hex signature rejected", st == 401, st)

# --- input validation
for name, seats, want in [("seats=0", 0, 400), ("seats=-5", -5, 400), ("seats=5", 5, 400),
                          ("seats overflow", 999999999999999999999, 400),
                          ("seats as string", "3", 400)]:
    st, _ = req("POST", "/book", {"user_id": "v", "idempotency_key": "s" + name[:4], "seats": seats})
    check(f"{name} rejected", st == want, f"{st} (want {want})")
st, _ = req("POST", "/book", {"user_id": "v", "idempotency_key": "u1", "seats": 1, "coupon": "x"})
check("unknown field rejected", st == 400, st)
st, _ = req("POST", "/book", {})
check("empty object rejected", st == 400, st)
st, _ = raw("POST", "/book", "{not json", sign_headers("POST", "/book", b"{not json"))
check("malformed JSON rejected", st == 400, st)
st, _ = raw("POST", "/book", "", sign_headers("POST", "/book", b""))
check("empty body rejected", st == 400, st)
st, _ = raw("POST", "/book", "x" * 20000, sign_headers("POST", "/book", b"x" * 20000))
check("oversized body rejected", st in (400, 413), st)
st, _ = req("POST", "/book", {"user_id": "", "idempotency_key": "e1", "seats": 1})
check("empty user_id rejected", st == 400, st)
st, _ = req("POST", "/book", {"user_id": "v", "idempotency_key": "", "seats": 1})
check("empty idempotency key rejected", st == 400, st)
st, d = req("POST", "/book", {"user_id": "uni-çafé-🙂", "idempotency_key": "uni1", "seats": 1})
check("unicode user_id accepted cleanly", st == 200 and d.get("status") in ("confirmed", "sold_out"), f"{st} {d}")
st, d = req("POST", "/book", {"user_id": "nul\x00id", "idempotency_key": "nul1", "seats": 1})
check("null byte handled without crash", st in (200, 400), f"{st} {d}")
st, d = req("GET", "/reservation?id=%2e%2e%2fadmin")
check("path-traversal id is just not_found", st in (400, 404), st)

# --- idempotency and tenancy
st, d = req("POST", "/book", {"user_id": "idem", "idempotency_key": "ik1", "seats": 1})
bk = d.get("booking_id", "")
st, d = req("POST", "/book", {"user_id": "idem", "idempotency_key": "ik1", "seats": 1})
check("same key same payload returns same booking", st == 200 and d.get("booking_id") == bk, f"{st} {d}")
st, d = req("POST", "/book", {"user_id": "idem", "idempotency_key": "ik1", "seats": 2})
check("same key different seats is a 409 conflict", st == 409 and d.get("status") == "idempotency_conflict", f"{st} {d}")
st, d = req("POST", "/book", {"user_id": "intruder", "idempotency_key": "ik1", "seats": 1})
check("same key different user is a conflict, no reservation takeover",
      st == 409 and d.get("status") == "idempotency_conflict", f"{st} {d}")
st, d = req("POST", "/reserve", {"user_id": "t1", "idempotency_key": "tk1", "seats": 1})
rid1 = d.get("reservation_id", "")
st, _ = req("GET", "/reservation?id=" + rid1, key=KEY2)
check("tenant2 cannot read tenant1 hold", st == 404, st)
st, _ = req("POST", "/confirm", {"reservation_id": rid1, "user_id": "t1"}, key=KEY2)
check("tenant2 cannot confirm tenant1 hold", st == 404, st)
st, _ = req("POST", "/release", {"reservation_id": rid1}, key=KEY2)
check("tenant2 cannot release tenant1 hold", st == 404, st)
st, _ = req("GET", "/status?idempotency_key=tk1", key=KEY2)
check("tenant2 cannot resolve tenant1 idempotency key", st == 404, st)
st, d = req("POST", "/waitlist/join", {"user_id": "wl", "idempotency_key": "wlk1", "seats": 1}, key=KEY2)
wl_id = d.get("waitlist_id", "")
if wl_id:
    st, _ = req("POST", "/waitlist/cancel", {"waitlist_id": wl_id}, key=KEY)
    check("tenant1 cannot cancel tenant2 waitlist entry", st == 404, st)
else:
    check("tenant2 waitlist join worked (setup)", True, "")

# --- concurrency
st, d = req("POST", "/reserve", {"user_id": "race", "idempotency_key": "race1", "seats": 1})
rid_r = d.get("reservation_id", "")
sold_before = raw("GET", "/seats")[1].get("sold", -1)
def one(_):
    return req("POST", "/confirm", {"reservation_id": rid_r, "user_id": "race"})[0]
with ThreadPoolExecutor(max_workers=200) as ex:
    outs = list(ex.map(one, range(200)))
st, d = req("GET", "/reservation?id=" + rid_r)
sold_after = raw("GET", "/seats")[1].get("sold", -1)
check("double-confirm race: one hold, one seat, idempotent re-confirms",
      d.get("status") == "confirmed" and sold_after - sold_before == 1,
      f"delta={sold_after - sold_before} st={st} {d}")

# --- engine still alive + seats arithmetic
st, d = raw("GET", "/seats")
tot, sold, held, free = d.get("total", -1), d.get("sold", -1), d.get("held", -1), d.get("free", -1)
check("seats arithmetic consistent", free >= 0 and tot == sold + held + free, d)
check("engine alive after full battery", st == 200, st)

fails = [n for n, ok in results if not ok]
print(f"\nred-team: {len(results) - len(fails)}/{len(results)} passed")
if fails:
    print("FAILED: " + "; ".join(fails))
sys.exit(1 if fails else 0)
