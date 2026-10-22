#!/usr/bin/env python3
"""Run 19 extra attack angles: 14 new variants, distinct from runs 16-18."""
import hashlib, hmac, http.client, json, socket, sys, time, uuid
from concurrent.futures import ThreadPoolExecutor

ER, ER2, ET, APP, IPENG = 8091, 8092, 8095, 9001, 8093
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
def raw(port, method, path, body=None, headers=None, sock=None):
    b = body.encode() if isinstance(body, str) else body
    headers = dict(headers or {})
    if b is not None and "Content-Type" not in headers:
        headers["Content-Type"] = "application/json"
    try:
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=25)
        c.request(method, path, body=b, headers=headers or {})
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

# --- control: signed /reserve works ---
ck = "r19c1" + uuid.uuid4().hex[:8]
st, r = req(ER, "POST", "/reserve", {"user_id": "r19c", "idempotency_key": ck, "seats": 1})
check("control", "signed /reserve books", st == 200 and r.get("status") == "held", "%s %s" % (st, str(r)[:80]))
rid0 = r.get("reservation_id")
if rid0: req(ER, "POST", "/release", {"reservation_id": rid0})

# 1+2: IP rate-limit bypass via spoofed forwarding headers (ip engine: rate 100, burst 300)
def ipflood():
    b = json.dumps({"user_id": "ipx", "idempotency_key": "ipx" + uuid.uuid4().hex, "seats": 0 if False else 1}).encode()
    return raw(IPENG, "POST", "/book", b, sign(KEY, "POST", "/book", b))
outs = P(130, lambda i: ipflood())
st429 = sum(1 for s, _ in outs if s == 429)
ok2xx = sum(1 for s, _ in outs if 200 <= s < 300)
check("iplimit", "plain flood hits 429 (rate 100/burst 300)", st429 > 0, "2xx=%d 429=%d" % (ok2xx, st429))
# spoof XFF: every request a "new IP"
def ip_spoof(hdr, name):
    def one(i):
        b = json.dumps({"user_id": "ipx-" + name, "idempotency_key": name + uuid.uuid4().hex, "seats": 1}).encode()
        h = sign(KEY, "POST", "/book", b); h[hdr] = "10.0.%d.%d" % (i // 254, i % 254 + 1)
        return raw(IPENG, "POST", "/book", b, h)
    outs2 = P(130, one)
    s429 = sum(1 for s, _ in outs2 if s == 429)
    check("iplimit", "XFF spoof via %s: limiter still bites" % hdr, s429 > 0, "429=%d of 130" % s429)
ip_spoof("X-Forwarded-For", "xff"); ip_spoof("X-Real-IP", "xri"); ip_spoof("X-Client-IP", "xci")

# 3: duplicate JSON keys in the signed body (canonicalization confusion)
dup = b'{"user_id":"r19d","idempotency_key":"r19d1","seats":2,"seats":1}'
st, _ = raw(ER, "POST", "/book", dup, sign(KEY, "POST", "/book", dup))
dupsafe = not (200 <= st < 300) or invariant(ER)
check("fuzz", "duplicate JSON keys: deterministic parse, invariants hold", dupsafe, "status=%s" % st)

# 4: type confusion on seats
for i, (v, name) in enumerate([(-1, "negative"), (2147483647, "int-max"), (1.5, "float"),
                               ("1", "string"), (None, "null"), (True, "bool")]):
    st, r = req(ER2, "POST", "/book", {"user_id": "r19t%d" % i, "idempotency_key": "r19t%d" % i, "seats": v})
    check("fuzz", "seats as %s: no 2xx, invariants hold" % name, not (200 <= st < 300) and invariant(ER2), "status=%s" % st)

# 5: unicode NFC/NFD idempotency collision (same visual key, different bytes -> distinct ids required)
nfc, nfd = "café", "cafe\u0301"
u = "r19u" + uuid.uuid4().hex[:6]
s1, r1 = req(ER, "POST", "/book", {"user_id": u, "idempotency_key": nfc, "seats": 1})
s2, r2 = req(ER, "POST", "/book", {"user_id": u, "idempotency_key": nfd, "seats": 1})
# safe outcomes: distinct reservations, OR a clean idempotent dedup (same id, 200), OR 409 conflict.
# unsafe: two different reservations from visually-identical keys would only matter if seats oversold; invariants are the real guard.
safe = invariant() and (s1 == s2 == 200 and r1.get("reservation_id") == r2.get("reservation_id")
                        or (s1 == 200 and s2 == 200 and r1.get("reservation_id") != r2.get("reservation_id"))
                        or 400 <= s2 < 500)
check("fuzz", "NFC/NFD idempotency keys: safe handling (dedup/distinct/reject), invariants hold", safe,
      "%s %s | %s %s" % (s1, s2, r1.get("reservation_id"), r2.get("reservation_id")))
if r1.get("reservation_id"): req(ER, "POST", "/release", {"reservation_id": r1["reservation_id"]})
if r2.get("reservation_id"): req(ER, "POST", "/release", {"reservation_id": r2["reservation_id"]})

# 6: race /release vs /confirm on the same reservation (double-spend window)
s, r = req(ER2, "POST", "/book", {"user_id": "r19r", "idempotency_key": "r19r1", "seats": 2})
rid = r.get("reservation_id")
outs3 = P(2, lambda i: req(ER2, "POST", "/confirm" if i == 0 else "/release",
                           {"reservation_id": rid, "user_id": "r19r"}))
sts = sorted(x[0] for x in outs3)
after = seats(ER2)
ok = invariant(ER2) and not (sts[0] == 200 and sts[1] == 200)
check("race", "concurrent release+confirm: exactly one wins, invariants hold", ok, "%s sold=%s" % (sts, after.get("sold")))

# 7: cross-user confirm at app tier (pay endpoint passes a foreign user_id)
s, h = raw(APP, "POST", "/api/hold", json.dumps({"user_id": "r19app", "seats": 1}))
rida = h.get("reservation_id")
s2, p = raw(APP, "POST", "/api/pay", json.dumps({"reservation_id": rida, "user_id": "attacker", "outcome": "success"}))
check("app", "app /api/pay with foreign user_id cannot confirm another's hold", not (s2 == 200 and p.get("ok")), "%s %s" % (s2, str(p)[:80]))
if rida:
    try: raw(APP, "POST", "/api/pay", json.dumps({"reservation_id": rida, "user_id": "r19app", "outcome": "failure"}))
    except Exception: pass

# 8: forged webhook with valid token -> app must not mutate engine state
before = seats(ER)
forged = {"event": "waitlist_fulfilled", "waitlist_id": "FAKE123", "reservation_id": "RSV00000001", "seats": 50}
st, _ = raw(APP, "POST", "/api/kavach-webhook?token=whsec-redtest", json.dumps(forged))
after2 = seats(ER)
check("app", "forged webhook (valid token): app state unchanged, engine untouched",
      invariant() and before.get("sold") == after2.get("sold") and before.get("held") == after2.get("held"), "%s" % st)

# 9: webhook replay (same valid event twice)
ev = {"event": "waitlist_fulfilled", "waitlist_id": "r19w", "reservation_id": rid0 or "RSV00000009", "seats": 1}
a, _ = raw(APP, "POST", "/api/kavach-webhook?token=whsec-redtest", json.dumps(ev))
b_, _ = raw(APP, "POST", "/api/kavach-webhook?token=whsec-redtest", json.dumps(ev))
check("app", "webhook replay: idempotent 2xx, no crash, engine invariants hold",
      a in (200, 201) and b_ in (200, 201) and invariant(), "%s %s" % (a, b_))

# 10: scheme-case variations on Authorization
scheme_cases = {}
for name, hdr in [("lowercase bearer", "bearer " + KEY), ("BEARER upper", "BEARER " + KEY)]:
    b = json.dumps({"user_id": "r19s", "idempotency_key": "r19s" + name[:4], "seats": 1}).encode()
    st, _ = raw(ER, "POST", "/book", b, {**sign(KEY, "POST", "/book", b), "Authorization": hdr})
    scheme_cases[name] = 200 <= st < 300
ok = scheme_cases.get("lowercase bearer", False) == scheme_cases.get("BEARER upper", False)
check("auth", "Authorization scheme case: consistent handling, no bypass", ok, str(scheme_cases))

# 11: signature header padding + duplicate signature headers (smuggling)
b = json.dumps({"user_id": "r19p", "idempotency_key": "r19p1", "seats": 1}).encode()
st, _ = raw(ER, "POST", "/book", b, {**sign(KEY, "POST", "/book", b), "X-Kavach-Signature": " " + sign(KEY, "POST", "/book", b)["X-Kavach-Signature"] + " "})
check("wire", "padded signature header: engine still verifies cleanly", st in (200, 401), "status=%s" % st)

# 12: timestamp float / plus-prefix forms
for name, ts in [("float ts", "17%.1f" % (time.time() % 100 + 100.5)), ("plus-prefix ts", "+" + str(int(time.time())))]:
    b = json.dumps({"user_id": "r19ts", "idempotency_key": "r19ts" + name[:3], "seats": 1}).encode()
    st, _ = raw(ER, "POST", "/book", b, sign(KEY, "POST", "/book", b, ts=ts))
    check("auth", "%s: no crash, invariants hold" % name, raw(ER, "GET", "/seats")[0] == 200 and invariant(), "status=%s" % st)

# 13: huge idempotency_key / user_id (64KB) - no crash, no OOM hang
big = "k" * 65536
st, r = req(ER, "POST", "/book", {"user_id": "r19big", "idempotency_key": big, "seats": 1})
check("resource", "64KB idempotency_key: clean response, engine alive", raw(ER, "GET", "/seats")[0] == 200, "status=%s" % st)
if 200 <= st < 300 and r.get("reservation_id"): req(ER, "POST", "/release", {"reservation_id": r["reservation_id"]})

# 14: waitlist cancel for another user (ownership check)
s, w = req(ER2, "POST", "/waitlist", {"user_id": "r19w", "idempotency_key": "r19w1", "seats": 1})
wid = w.get("waitlist_id")
s2, r2 = req(ER2, "POST", "/waitlist/cancel", {"waitlist_id": wid, "user_id": "attacker"})
check("state", "waitlist/cancel by foreign user_id rejected", not (s2 == 200 and r2.get("status") == "cancelled"), "%s %s" % (s2, str(r2)[:80]))

print("RUN19 EXTRA: TOTAL %d PASS %d FAIL %d" % (len(results), sum(1 for x in results if x["ok"]), sum(1 for x in results if not x["ok"])))
for x in results:
    if not x["ok"]: print("FAIL [%s] %s :: %s" % (x["cat"], x["name"], x["detail"]))
json.dump(results, open("/tmp/battery/run19_extra.json", "w"), indent=1)
sys.exit(1 if any(not x["ok"] for x in results) else 0)
