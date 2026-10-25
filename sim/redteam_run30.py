#!/usr/bin/env python3
"""Run 30 extras: 14 new angles (HMAC binds body/method/path, confirm+release
race on one rid, concurrent /book on one idem key, concurrent waitlist join,
app pay outcome=failed, app waitlist bounds, 10KB idem key, emoji user_id,
per-tenant HMAC cross-secret confusion, auth header extras, form content-type,
null-byte user_id, int32-overflow seats)."""
import hashlib, hmac, http.client, json, sys, time, uuid
from concurrent.futures import ThreadPoolExecutor
ER, AR, ER2, EH = 8091, 9001, 8092, 8097
KEY, KEY2 = "testkey", "otherkey"
results = []
def check(cat, name, ok, detail=""):
    results.append({"cat": cat, "name": name, "ok": bool(ok), "detail": str(detail)[:220]})
    print(("PASS" if ok else "FAIL"), name, ("| " + str(detail)[:120]) if detail else "")
    return ok
def sign(key, method, path, body, secret, ts=None, rid=None):
    ts = str(int(time.time())) if ts is None else ts
    rid = uuid.uuid4().hex if rid is None else rid
    mac = hmac.new(secret.encode(), (ts + "\n" + rid + "\n" + method + "\n" + path + "\n" + key + "\n").encode() + body, hashlib.sha256)
    return {"Authorization": "Bearer " + key, "X-Kavach-Timestamp": ts,
            "X-Kavach-Request-Id": rid, "X-Kavach-Signature": mac.hexdigest(),
            "Content-Type": "application/json"}
def raw(port, method, path, body=None, headers=None):
    b = body.encode() if isinstance(body, str) else body
    headers = dict(headers or {})
    if b is not None and "Content-Type" not in headers:
        headers["Content-Type"] = "application/json"
    try:
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=25)
        c.request(method, path, body=b, headers=headers or {})
        r = c.getresponse(); data = r.read(); st = r.status; c.close()
        try:
            j = json.loads(data) if data else {}
        except Exception:
            j = {"raw": data[:150].decode("utf-8", "replace")}
        return st, j
    except Exception as ex:
        return -1, {"exception": str(ex)[:120]}
def req(port, method, path, obj=None, key=KEY, secret="testsecret", **kw):
    body = json.dumps(obj).encode() if obj is not None else b""
    return raw(port, method, path, body, sign(key, method, path, body, secret, **kw))
def post(port, path, obj, **kw):
    return req(port, "POST", path, obj, **kw)
def seats(port):
    return raw(port, "GET", "/seats")[1]
def P(n, fn):
    with ThreadPoolExecutor(n) as ex:
        return list(ex.map(fn, range(n)))

# 1. HMAC binds the body: sign body A, send body B
bodyA = json.dumps({"user_id": "rt30-ba", "idempotency_key": "k30-ba", "seats": 1}).encode()
bodyB = json.dumps({"user_id": "rt30-ba", "idempotency_key": "k30-ba", "seats": 2}).encode()
hA = sign(KEY, "POST", "/reserve", bodyA, "testsecret")
hA.pop("Content-Type")
r1 = raw(ER, "POST", "/reserve", bodyB, hA)
check("auth", "HMAC binds body: signed-A body-B rejected 401", r1[0] == 401, str(r1[0]))
# 2. HMAC binds method and path
rid2 = post(ER, "/reserve", {"user_id": "rt30-mp", "idempotency_key": "k30-mp", "seats": 1})
st_get = raw(ER, "GET", "/reserve", None, sign(KEY, "POST", "/reserve", bodyA, "testsecret"))[0]
st_case = post(ER, "/reserve", {"user_id": "rt30-mp2", "idempotency_key": "k30-mp2", "seats": 1},
               key=KEY, ts=None, rid=None)  # baseline ok
# signed for /reserve, sent to /RESERVE
bC = json.dumps({"user_id": "rt30-case", "idempotency_key": "k30-case", "seats": 1}).encode()
hC = sign(KEY, "POST", "/reserve", bC, "testsecret"); hC.pop("Content-Type")
st_case_send = raw(ER, "POST", "/RESERVE", bC, hC)[0]
check("auth", "HMAC binds method+path: wrong-method and wrong-case rejected", st_get in (401, 404, 405) and st_case_send in (401, 404), "GET=%s RESERVE=%s" % (st_get, st_case_send))
# 3. confirm+release race on one rid
sb = seats(ER)
r3 = post(ER, "/reserve", {"user_id": "rt30-cr", "idempotency_key": "k30-cr", "seats": 1})
rid3 = r3[1].get("reservation_id") if r3[0] == 200 else None
outs = P(10, lambda i: post(ER, "/confirm", {"reservation_id": rid3, "user_id": "rt30-cr"})[0] if i % 2 == 0
         else post(ER, "/release", {"reservation_id": rid3})[0])
sa = seats(ER)
conserved = sa["free"] + sa["held"] + sa["sold"] == sb["free"] + sb["held"] + sb["sold"]
check("race", "confirm+release race on one rid: conserved, no 5xx", rid3 and all(o < 500 for o in outs) and conserved and sa["sold"] - sb["sold"] <= 1, "%s sold %d->%d" % (outs, sb["sold"], sa["sold"]))
# 4. concurrent /book same idem key
sb = seats(ER)
bk_key = "k30-bk-%d" % int(time.time())
outs = P(20, lambda i: post(ER, "/book", {"user_id": "rt30-bk", "idempotency_key": bk_key, "seats": 2}))
ok200 = [o for o in outs if o[0] == 200]
bids = {o[1].get("booking_id") for o in ok200 if o[1].get("booking_id")}
time.sleep(2)  # /book confirms asynchronously; let the counters settle
sa = seats(ER)
check("race", "20x /book same idem: one booking_id, sold exactly +2", all(o[0] < 500 for o in outs) and len(bids) <= 1 and sa["sold"] - sb["sold"] == 2, "%s bids=%s sold %d->%d" % ([o[0] for o in outs], len(bids), sb["sold"], sa["sold"]))
# 5. concurrent waitlist join same idem
outs = P(10, lambda i: post(ER2, "/waitlist", {"user_id": "rt30-wj", "idempotency_key": "k30-wj", "seats": 1}))
wids = {o[1].get("waitlist_id") for o in outs if o[0] == 200}
check("race", "10x concurrent waitlist join same idem: no duplicates, no 5xx", all(o[0] < 500 for o in outs) and len(wids) <= 1, "%s wids=%s" % ([o[0] for o in outs], len(wids)))
# 6. app pay outcome=failed, then success
hold = raw(AR, "POST", "/api/hold", json.dumps({"user_id": "rt30-pay", "seats": 1}))
rid6 = hold[1].get("reservation_id") if hold[0] == 200 else None
sb = seats(ER)
f6 = raw(AR, "POST", "/api/pay", json.dumps({"reservation_id": rid6, "outcome": "failed"})) if rid6 else (-1, {})
sm = seats(ER)
hold2 = raw(AR, "POST", "/api/hold", json.dumps({"user_id": "rt30-pay2", "seats": 1}))
rid6b = hold2[1].get("reservation_id") if hold2[0] == 200 else None
s6 = raw(AR, "POST", "/api/pay", json.dumps({"reservation_id": rid6b, "outcome": "success"})) if rid6b else (-1, {})
sa = seats(ER)
conserved = sa["free"] + sa["held"] + sa["sold"] == sb["free"] + sb["held"] + sb["sold"]
check("app", "pay outcome=failed clean, success still confirms once", f6[0] < 500 and s6[0] == 200 and conserved and sa["sold"] - sb["sold"] <= 1, "failed=%s mid=%s success=%s sold %d->%d" % (f6[0], sm["sold"], s6[0], sb["sold"], sa["sold"]))
# 7. app waitlist bounds
sb = seats(ER)
w0 = raw(AR, "POST", "/api/waitlist", json.dumps({"user_id": "rt30-aw0", "seats": 0}))
wm = raw(AR, "POST", "/api/waitlist", json.dumps({"user_id": "rt30-awm", "seats": -1}))
sa = seats(ER)
check("app", "app waitlist seats 0/-1 rejected, engine untouched", w0[0] < 500 and wm[0] < 500 and sa["free"] == sb["free"] and sa["sold"] == sb["sold"], "%s %s free %d->%d" % (w0[0], wm[0], sb["free"], sa["free"]))
# 8. 10KB idempotency key
big = "k30-" + "x" * 10000
r8 = post(ER, "/reserve", {"user_id": "rt30-big", "idempotency_key": big, "seats": 1})
ok = r8[0] in (200, 400, 413, 422)
if r8[0] == 200:
    rid8 = r8[1].get("reservation_id")
    c8 = post(ER, "/confirm", {"reservation_id": rid8, "user_id": "rt30-big"})
    ok = ok and c8[0] == 200
    try:
        json.loads(open("/tmp/battery/state/bt8091_bookings.jsonl", "rb").read().strip().split(b"\n")[-1].decode("utf-8", "replace"))
    except Exception as ex:
        ok = False
        r8 = (r8[0], str(ex)[:80])
check("fuzz", "10KB idem key: clean, log stays single-line JSON", ok, "reserve=%s %s" % (r8[0], r8[1] if isinstance(r8[1], str) else ""))
# 9. emoji user_id
r9 = post(ER, "/reserve", {"user_id": "rt30-\U0001F39F\uFE0F", "idempotency_key": "k30-emoji", "seats": 1})
ok = r9[0] == 200
if ok:
    rid9 = r9[1].get("reservation_id")
    c9 = post(ER, "/confirm", {"reservation_id": rid9, "user_id": "rt30-\U0001F39F\uFE0F"})
    ok = c9[0] == 200
    try:
        json.loads(open("/tmp/battery/state/bt8091_bookings.jsonl", "rb").read().strip().split(b"\n")[-1].decode("utf-8", "replace"))
    except Exception as ex:
        ok = False
check("fuzz", "emoji user_id: reserve+confirm clean, log single-line", ok, "reserve=%s" % r9[0])
# 10. per-tenant HMAC: cross-secret confusion on 8097
bT = json.dumps({"user_id": "rt30-t", "idempotency_key": "k30-t1", "seats": 1}).encode()
wrong = post(EH, "/reserve", {"user_id": "rt30-t", "idempotency_key": "k30-t1", "seats": 1}, key=KEY, secret="secretB")
wrong2 = post(EH, "/reserve", {"user_id": "rt30-t", "idempotency_key": "k30-t2", "seats": 1}, key=KEY2, secret="secretA")
right = post(EH, "/reserve", {"user_id": "rt30-t", "idempotency_key": "k30-t3", "seats": 1}, key=KEY, secret="secretA")
check("auth", "per-tenant HMAC: cross-tenant secret rejected, correct accepted", wrong[0] == 401 and wrong2[0] == 401 and right[0] == 200, "%s %s %s" % (wrong[0], wrong2[0], right[0]))
# 11. auth header extras + unknown X-Kavach-* headers
bX = json.dumps({"user_id": "rt30-x", "idempotency_key": "k30-x", "seats": 1}).encode()
hX = sign(KEY, "POST", "/reserve", bX, "testsecret"); hX.pop("Content-Type")
hX["Authorization"] = "Bearer testkey extra"
sx = raw(ER, "POST", "/reserve", bX, dict(hX))[0]
hY = sign(KEY, "POST", "/reserve", bX, "testsecret", rid=uuid.uuid4().hex)
hY.pop("Content-Type"); hY["X-Kavach-Extra"] = "junk"; hY["X-Kavach-Foo"] = "bar"
sy = raw(ER, "POST", "/reserve", bX, dict(hY))[0]
check("auth", "3-part bearer rejected; unknown X-Kavach-* ignored", sx in (400, 401) and sy == 200, "extra=%s unknown=%s" % (sx, sy))
# 12. JSON body with form-urlencoded content-type
bF = json.dumps({"user_id": "rt30-form", "idempotency_key": "k30-form", "seats": 1}).encode()
hF = sign(KEY, "POST", "/reserve", bF, "testsecret"); hF.pop("Content-Type")
hF["Content-Type"] = "application/x-www-form-urlencoded"
r12 = raw(ER, "POST", "/reserve", bF, hF)
check("fuzz", "JSON body with form content-type: no 5xx, state sane", r12[0] < 500, "st=%s" % r12[0])
# 13. null byte in user_id
r13 = post(ER, "/reserve", {"user_id": "rt30\u0000x", "idempotency_key": "k30-nul", "seats": 1})
ok = r13[0] in (400, 422)
if r13[0] == 200:
    rid13 = r13[1].get("reservation_id")
    c13 = post(ER, "/confirm", {"reservation_id": rid13, "user_id": "rt30\u0000x"})
    ok = c13[0] == 200
    try:
        json.loads(open("/tmp/battery/state/bt8091_bookings.jsonl", "rb").read().strip().split(b"\n")[-1].decode("utf-8", "replace"))
    except Exception:
        ok = False
check("fuzz", "null byte in user_id: rejected or log-safe", ok, "reserve=%s" % r13[0])
# 14. int32-overflow seats
o1 = post(ER, "/reserve", {"user_id": "rt30-ov", "idempotency_key": "k30-ov1", "seats": 2147483648})
o2 = post(ER, "/reserve", {"user_id": "rt30-ov", "idempotency_key": "k30-ov2", "seats": -2147483649})
check("fuzz", "int32-overflow seats rejected cleanly", o1[0] in (400, 422) and o2[0] in (400, 422), "%s %s" % (o1[0], o2[0]))

fails = [r for r in results if not r["ok"]]
json.dump({"run": 30, "results": results}, open("/tmp/battery/run30_extra.json", "w"), indent=1)
print("EXTRA: %d/%d pass, %d fail" % (len(results) - len(fails), len(results), len(fails)))
sys.exit(1 if fails else 0)
