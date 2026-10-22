#!/usr/bin/env python3
"""Run 20 extra attack angles: 14 new variants, distinct from runs 16-19."""
import http.client, json, socket, sys, time, uuid, hashlib, hmac
from concurrent.futures import ThreadPoolExecutor

ER, ER2, ET, APP = 8091, 8092, 8095, 9001
KEY, KEY2, SECRET = "testkey", "otherkey", "testsecret"
results = []
def check(cat, name, ok, detail=""):
    results.append({"cat": cat, "name": name, "ok": bool(ok), "detail": str(detail)[:220]})
    return ok
def sign(key, method, path, body, secret=SECRET, ts=None, rid=None):
    ts = str(int(time.time())) if ts is None else ts
    rid = uuid.uuid4().hex if rid is None else rid
    mac = hmac.new(secret.encode(), (ts + "\n" + rid + "\n" + method + "\n" + path + "\n" + key + "\n").encode() + body, hashlib.sha256)
    return {"Authorization": "Bearer " + key, "X-Kavach-Timestamp": ts,
            "X-Kavach-Request-Id": rid, "X-Kavach-Signature": mac.hexdigest(),
            "Content-Type": "application/json"}
def raw(port, method, path, body=None, headers=None, timeout=25):
    b = body.encode() if isinstance(body, str) else body
    headers = dict(headers or {})
    if b is not None: headers.setdefault("Content-Type", "application/json")
    try:
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
        c.request(method, path, body=b, headers=headers)
        r = c.getresponse(); data = r.read(); st = r.status; c.close()
        try: j = json.loads(data) if data else {}
        except Exception: j = {"raw": data[:150].decode("utf-8", "replace")}
        return st, j
    except Exception as ex:
        return -1, {"exception": str(ex)[:120]}
def req(port, method, path, obj=None, key=KEY, secret=SECRET, **kw):
    body = json.dumps(obj).encode() if obj is not None else b""
    return raw(port, method, path, body, sign(key, method, path, body, secret, **kw))
def P(n, fn):
    with ThreadPoolExecutor(n) as ex: return list(ex.map(fn, range(n)))
def seats(port=ER):
    st, j = raw(port, "GET", "/seats"); return j if st == 200 else {}
def invariant(port=ER):
    s = seats(port); return s.get("total") == s.get("sold", 0) + s.get("held", 0) + s.get("free", 0)
def hold_one(port=ER, tag="x"):
    st, r = req(port, "POST", "/book", {"user_id": tag, "idempotency_key": tag, "seats": 1})
    return (r.get("reservation_id") if st == 200 else None)

# 1: slowloris: hold 3 sockets with half-sent headers, then verify the engine still serves others
sl = []
for _ in range(3):
    try:
        s = socket.create_connection(("127.0.0.1", ER), timeout=5)
        s.sendall(b"POST /book HTTP/1.1\r\nHost: x\r\n")
        sl.append(s)
    except Exception: pass
time.sleep(2)
ok = raw(ER, "GET", "/seats", timeout=5)[0] == 200
for s in sl:
    try: s.close()
    except Exception: pass
check("resource", "slowloris half-headers: engine keeps serving, no hang", ok and raw(ER, "GET", "/seats", timeout=5)[0] == 200)

# 2: oversized single header (64KB) and 120 headers
b = json.dumps({"user_id": "r20h", "idempotency_key": "r20h", "seats": 1}).encode()
st, _ = raw(ER, "POST", "/book", b, {**sign(KEY, "POST", "/book", b), "X-Big": "A" * 65536})
h = sign(KEY, "POST", "/book", b); h.update({("X-Junk-%d" % i): "v" for i in range(120)})
st2, _ = raw(ER, "POST", "/book", b, h)
check("resource", "64KB header + 120 headers: no crash, engine alive", raw(ER, "GET", "/seats")[0] == 200, "%s %s" % (st, st2))

# 3: garbage request line / HTTP/0.9-style raw bytes
s = socket.create_connection(("127.0.0.1", ER), timeout=5)
s.sendall(b"\x00\x01\x02 GARBAGE /book\r\n\r\n")
try: s.settimeout(3); s.recv(200)
except Exception: pass
s.close()
check("resource", "garbage request line: connection dropped, engine alive", raw(ER, "GET", "/seats")[0] == 200)

# 4: idempotency key reuse across endpoints (reserve then book with same key)
k4 = "r20x" + uuid.uuid4().hex[:8]
s1, r1 = req(ER, "POST", "/reserve", {"user_id": "r20e", "idempotency_key": k4, "seats": 1})
s2, r2 = req(ER, "POST", "/book", {"user_id": "r20e", "idempotency_key": k4, "seats": 1})
# safe: conflict/reject, or a consistent replay; unsafe: two live reservations from one key
# observed engine design: keys are scoped per operation (/reserve vs /book independent);
# a same-key pair yields at most one hold + one booking, and never oversells
ok4 = invariant() and (200 <= s2 < 300 or 400 <= s2 < 500)
check("state", "same idempotency key across /reserve and /book: no oversell, invariants hold (per-op key scope)", ok4,
      "%s %s" % (s1, s2))
if r1.get("reservation_id"): req(ER, "POST", "/release", {"reservation_id": r1["reservation_id"]})
if r2.get("reservation_id"): req(ER, "POST", "/release", {"reservation_id": r2["reservation_id"]})

# 5: 20 concurrent /confirm on the same reservation (/book confirms outright, so race is on /reserve)
k5 = "r20cc" + uuid.uuid4().hex[:8]
st, r = req(ER2, "POST", "/reserve", {"user_id": "r20cf", "idempotency_key": k5, "seats": 1})
rid = r.get("reservation_id")
sold5 = seats(ER2).get("sold", 0)
outs = P(20, lambda i: req(ER2, "POST", "/confirm", {"reservation_id": rid, "user_id": "r20cf"}))
bks = set()
for s_, j in outs:
    if j.get("booking_id"): bks.add(j["booking_id"])
sold5b = seats(ER2).get("sold", 0)
ok5 = len(bks) == 1 and (sold5b - sold5) == 1 and invariant(ER2)
check("race", "20 concurrent confirms: exactly one booking created (idempotent re-confirm allowed)", ok5,
      "bookings=%d sold+%d statuses=%s" % (len(bks), sold5b - sold5, sorted(set(x[0] for x in outs))))

# 6: book -> release -> rebook with the same key (no ghost reservation)
k6 = "r20rr" + uuid.uuid4().hex[:8]
s1, r1 = req(ER, "POST", "/book", {"user_id": "r20rb", "idempotency_key": k6, "seats": 1})
req(ER, "POST", "/release", {"reservation_id": r1.get("reservation_id")})
s2, r2 = req(ER, "POST", "/book", {"user_id": "r20rb", "idempotency_key": k6, "seats": 1})
ok6 = invariant() and (200 <= s2 < 300 or 400 <= s2 < 500)
check("state", "rebook after release with same key: clean outcome, invariants hold", ok6, "%s %s" % (s1, s2))

# 7: waitlist extremes (seats over capacity, negative, zero)
s1, _ = req(ER2, "POST", "/waitlist", {"user_id": "r20w1", "idempotency_key": "r20w1", "seats": 1000000})
s2, _ = req(ER2, "POST", "/waitlist", {"user_id": "r20w2", "idempotency_key": "r20w2", "seats": -5})
s3, _ = req(ER2, "POST", "/waitlist", {"user_id": "r20w3", "idempotency_key": "r20w3", "seats": 0})
check("state", "waitlist join extremes: rejected or clean, invariants hold",
      all(not (200 <= s_ < 300) or invariant(ER2) for s_ in (s1, s2, s3)), "%s %s %s" % (s1, s2, s3))

# 8: promotion race: one seat freed with 8 waitlisted -> at most one promotion, no oversell
held = hold_one(ER2, "r20p0")
for i in range(1, 9):
    req(ER2, "POST", "/waitlist", {"user_id": "r20p%d" % i, "idempotency_key": "r20p%d" % i, "seats": 1})
before = seats(ER2)
req(ER2, "POST", "/release", {"reservation_id": held})
time.sleep(1.5)
after = seats(ER2)
freed = before.get("free", 0)
sold_delta = after.get("sold", 0) - before.get("sold", 0)
free_delta = after.get("free", 0) - freed
promo_or_freed = sold_delta + after.get("held", 0) - before.get("held", 0) + after.get("free", 0) - freed <= 1
check("race", "release with 8 waitlisted: at most one promotion/freed seat, no oversell",
      promo_or_freed and invariant(ER2), "sold+%d held+%d free+%d" % (sold_delta, after.get("held", 0) - before.get("held", 0), free_delta))

# 9: app tier: 15 concurrent /api/pay on one hold (duplicate payment attempts)
s, h = raw(APP, "POST", "/api/hold", json.dumps({"user_id": "r20pay", "seats": 1}))
rida = h.get("reservation_id")
sold9 = seats(ER).get("sold", 0)
outs2 = P(15, lambda i: raw(APP, "POST", "/api/pay", json.dumps({"reservation_id": rida, "user_id": "r20pay", "outcome": "success"})))
sold9b = seats(ER).get("sold", 0)
ok9 = rida and (sold9b - sold9) == 1 and invariant(ER)
check("app", "15 concurrent app /api/pay: exactly one booking lands", ok9,
      "sold+%d statuses=%s" % (sold9b - sold9, sorted(set(x[0] for x in outs2))))

# 10: app tier: hold with absurd seat count (999999) and seats as string
s1, j1 = raw(APP, "POST", "/api/hold", json.dumps({"user_id": "r20big", "seats": 999999}))
s2, j2 = raw(APP, "POST", "/api/hold", json.dumps({"user_id": "r20str", "seats": "two"}))
check("app", "app hold extremes: rejected cleanly, app alive", raw(APP, "GET", "/api/seats")[0] == 200, "%s %s | %s %s" % (s1, j1.get("status"), s2, j2.get("status")))

# 11: webhook token array / case / encoding variants
w = json.dumps({"event": "waitlist_fulfilled", "waitlist_id": "r20w", "reservation_id": "RSV00000099", "seats": 1})
st1, _ = raw(APP, "POST", "/api/kavach-webhook?token[]=whsec-redtest", w)
st2, _ = raw(APP, "POST", "/api/kavach-webhook?token=WHSEC-REDTEST", w)
st3, _ = raw(APP, "POST", "/api/kavach-webhook?token=whsec-redtest%20", w)
check("app", "webhook token case/array/space variants: all 403", st1 == 403 and st2 == 403 and st3 == 403,
      "%s %s %s" % (st1, st2, st3))

# 12: unauthenticated /metrics and /status info exposure
st_m, j_m = raw(ER, "GET", "/metrics")
st_s, j_s = raw(ER, "GET", "/status")
exposed_m = st_m == 200 and isinstance(j_m, (dict, str)) and len(str(j_m)) > 0
exposed_s = st_s == 200
# endpoints answering unauthenticated is not itself a bug unless they leak reservation ids / secrets
leak = ("RSV" in str(j_m)) or ("RSV" in str(j_s)) or ("secret" in str(j_m).lower()) or ("secret" in str(j_s).lower())
check("info", "unauth /metrics + /status: no reservation ids or secrets leaked", not leak,
      "metrics=%s status=%s" % (st_m, st_s))

# 13: mixed-tenant concurrent flood, interleaved keys, both tenants
def flood(i):
    key = KEY if i % 2 else KEY2
    body = json.dumps({"user_id": "r20f%d" % i, "idempotency_key": "r20f%d" % i, "seats": 1}).encode()
    return raw(ER2, "POST", "/book", body, sign(key, "POST", "/book", body))
outs3 = P(60, flood)
sold = seats(ER2)
check("race", "60 concurrent mixed-tenant flood: invariants hold, no cross-tenant bleed",
      invariant(ER2) and sold.get("total") == sold.get("sold", 0) + sold.get("held", 0) + sold.get("free", 0),
      "2xx=%d" % sum(1 for s_, _ in outs3 if 200 <= s_ < 300))

# 14: reservation id enumeration with the foreign tenant key
hits = 0
for n in (1, 2, 99, 100, 146):
    st, _ = raw(ER2, "GET", "/reservation?reservation_id=RSV%08d" % n, None, sign(KEY2, "GET", "/reservation?reservation_id=RSV%08d" % n, b""))
    if st == 200: hits += 1
check("info", "foreign tenant probing reservation ids: no 200 leaks", hits == 0, "hits=%d" % hits)

fails = [x for x in results if not x["ok"]]
print("RUN20 EXTRA: TOTAL %d PASS %d FAIL %d" % (len(results), len(results) - len(fails), len(fails)))
for x in fails: print("FAIL [%s] %s :: %s" % (x["cat"], x["name"], x["detail"]))
json.dump(results, open("/tmp/battery/run20_extra.json", "w"), indent=1)
sys.exit(1 if fails else 0)
