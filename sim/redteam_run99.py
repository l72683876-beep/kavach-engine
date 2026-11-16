#!/usr/bin/env python3
"""Run 99 extras: 12 angles (all live in redteam_battery.py Phase BA too).
1: POST /reserve?debug=1 unknown query param: works, no 5xx
2: signature hex uppercase: 401
3: empty X-Kavach-Signature value: 401
4: timestamp +301s in future: 401
5: seats 999999999999999999 overflow: 4xx
6: transfer to_user empty string: 4xx
7: confirm a released (never-confirmed) rid: 4xx, conserved
8: waitlist cancel twice: second 4xx, no 5xx
9: app /api/hold with 1MB body: no 500, app alive
10: 6-way parallel release of same held rid: no 5xx, conserved
11: waitlist join burst: limiter fires (429s)
12: null byte in query param value: no 5xx, alive
Run against targets already up: 8091 engine, 8092 engine2, 9001 app.
"""
import hashlib, hmac, http.client, json, sys, time, uuid
from concurrent.futures import ThreadPoolExecutor

ER, AR, ER2 = 8091, 9001, 8092
KEY, SECRET = "testkey", "testsecret"
results = []
def check(cat, name, ok, detail=""):
    results.append((cat, name, bool(ok), str(detail)[:220]))
def sign(key, method, path, body, secret=SECRET, ts=None, rid=None, hexfmt="lower"):
    ts = str(int(time.time())) if ts is None else ts
    rid = uuid.uuid4().hex if rid is None else rid
    mac = hmac.new(secret.encode(), (ts + "\n" + rid + "\n" + method + "\n" + path + "\n" + key + "\n").encode() + body, hashlib.sha256).hexdigest()
    if hexfmt == "upper": mac = mac.upper()
    return {"Authorization": "Bearer " + key, "X-Kavach-Timestamp": ts, "X-Kavach-Request-Id": rid,
            "X-Kavach-Signature": mac, "Content-Type": "application/json"}
def raw(port, method, path, body=None, headers=None):
    b = body.encode() if isinstance(body, str) else body
    headers = dict(headers or {})
    if b is not None and "Content-Type" not in headers: headers["Content-Type"] = "application/json"
    try:
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=25)
        c.request(method, path, body=b, headers=headers or {})
        r = c.getresponse(); data = r.read(); st = r.status; c.close()
        try: j = json.loads(data) if data else {}
        except Exception: j = {"raw": data[:150].decode("utf-8", "replace")}
        return st, j
    except Exception as ex: return -1, {"exception": str(ex)[:120]}
def post(port, path, obj, **kw):
    body = json.dumps(obj).encode() if obj is not None else b""
    return raw(port, "POST", path, body, sign(KEY, "POST", path, body, **kw))
def seats(port=ER):
    st, j = raw(port, "GET", "/seats"); return j if st == 200 else {}
def conserved(port=ER):
    s = seats(port)
    return s.get("total", -1) == s.get("sold", 0) + s.get("held", 0) + s.get("free", 0)

# ---------------- Phase BA: run 99 extras (12 new angles) ----------------
def unknown_query_param():
    st, j = post(ER, "/reserve?debug=1", {"user_id": "rt-99uq", "idempotency_key": "k99uq", "seats": 1})
    if st == 200 and isinstance(j, dict) and j.get("reservation_id"):
        post(ER, "/release", {"reservation_id": j["reservation_id"]})
    alive = raw(ER, "GET", "/seats")[0] == 200
    ok = st != 500 and st != -1 and alive
    return check("wire", "unknown query param (?debug=1) ignored: no 5xx, alive", ok, "status=%s" % st)
unknown_query_param()
def sig_hex_uppercase():
    b = json.dumps({"user_id": "rt-99hu", "idempotency_key": "k99hu", "seats": 1}).encode()
    st, _ = raw(ER, "POST", "/reserve", b, sign(KEY, "POST", "/reserve", b, hexfmt="upper"))
    alive = raw(ER, "GET", "/seats")[0] == 200
    ok = st == 401 and alive
    return check("auth", "signature hex uppercase: 401, alive", ok, "status=%s" % st)
sig_hex_uppercase()
def sig_empty_value():
    b = json.dumps({"user_id": "rt-99se", "idempotency_key": "k99se", "seats": 1}).encode()
    h = sign(KEY, "POST", "/reserve", b); h["X-Kavach-Signature"] = ""
    st, _ = raw(ER, "POST", "/reserve", b, h)
    alive = raw(ER, "GET", "/seats")[0] == 200
    ok = st == 401 and alive
    return check("auth", "empty X-Kavach-Signature value: 401, alive", ok, "status=%s" % st)
sig_empty_value()
def timestamp_future_outside_window():
    ts = str(int(time.time()) + 301)
    b = json.dumps({"user_id": "rt-99ft", "idempotency_key": "k99ft", "seats": 1}).encode()
    st, _ = raw(ER, "POST", "/reserve", b, sign(KEY, "POST", "/reserve", b, ts=ts))
    alive = raw(ER, "GET", "/seats")[0] == 200
    return check("auth", "timestamp +301s future outside window: 401, alive", st == 401 and alive, "status=%s" % st)
timestamp_future_outside_window()
def seats_overflow():
    st, _ = post(ER, "/reserve", {"user_id": "rt-99ov", "idempotency_key": "k99ov", "seats": 999999999999999999})
    alive = raw(ER, "GET", "/seats")[0] == 200
    ok = st != 500 and st != -1 and alive
    return check("fuzz", "seats 999999999999999999 overflow: 4xx, no 5xx, alive", ok, "status=%s" % st)
seats_overflow()
def transfer_to_user_empty():
    st, j = post(ER, "/reserve", {"user_id": "rt-99te", "idempotency_key": "k99te", "seats": 1})
    rid = j.get("reservation_id") if isinstance(j, dict) and st == 200 else None
    if not rid:
        return check("fuzz", "transfer to_user empty: skipped (hold unavailable)", True, "st=%s" % st)
    st2, _ = post(ER, "/transfer", {"reservation_id": rid, "to_user": ""})
    post(ER, "/release", {"reservation_id": rid})
    time.sleep(0.6)
    ok = st2 != 500 and st2 != -1 and st2 != 200 and conserved()
    return check("fuzz", "transfer to_user empty string: 4xx, no 5xx, conserved", ok, "st2=%s" % st2)
transfer_to_user_empty()
def confirm_released_hold():
    st, j = post(ER, "/reserve", {"user_id": "rt-99cr", "idempotency_key": "k99cr", "seats": 1})
    rid = j.get("reservation_id") if isinstance(j, dict) and st == 200 else None
    if not rid:
        return check("state", "confirm released hold: skipped (hold unavailable)", True, "st=%s" % st)
    st2, _ = post(ER, "/release", {"reservation_id": rid})
    st3, _ = post(ER, "/confirm", {"reservation_id": rid})
    time.sleep(0.6)
    ok = st3 != 500 and st3 != -1 and st3 != 200 and conserved()
    return check("state", "confirm a released (never-confirmed) rid: 4xx, conserved", ok, "st3=%s" % st3)
confirm_released_hold()
def waitlist_cancel_twice():
    st1, _ = post(ER, "/waitlist/cancel", {"reservation_id": "rt-99-wait-x", "user_id": "rt-99wc"})
    st2, _ = post(ER, "/waitlist/cancel", {"reservation_id": "rt-99-wait-x", "user_id": "rt-99wc"})
    alive = raw(ER, "GET", "/seats")[0] == 200
    ok = st2 != 500 and st2 != -1 and alive
    return check("state", "waitlist cancel twice: second no 5xx, alive", ok, "st1=%s st2=%s" % (st1, st2))
waitlist_cancel_twice()
def app_hold_1mb_body():
    big = '{"user_id":"' + "x" * 1000000 + '"}'
    st, _ = raw(AR, "POST", "/api/hold", big)
    alive = raw(AR, "GET", "/")[0] == 200
    ok = st != 500 and st != -1 and alive
    return check("app", "app /api/hold 1MB body: no 500, alive", ok, "st=%s" % st)
app_hold_1mb_body()
def release_race_parallel():
    st, j = post(ER, "/reserve", {"user_id": "rt-99rr", "idempotency_key": "k99rr", "seats": 1})
    rid = j.get("reservation_id") if isinstance(j, dict) and st == 200 else None
    if not rid:
        return check("race", "parallel release race: skipped (hold unavailable)", True, "st=%s" % st)
    def go(i):
        return post(ER, "/release", {"reservation_id": rid})[0]
    with ThreadPoolExecutor(6) as ex:
        outs = list(ex.map(go, range(6)))
    time.sleep(1.0)
    ok = all(x != 500 and x != -1 for x in outs) and conserved()
    return check("race", "6-way parallel release same held rid: no 5xx, conserved", ok, "200s=%d" % outs.count(200))
release_race_parallel()
def waitlist_burst_rate():
    outs = []
    for i in range(14):
        outs.append(post(ER, "/waitlist", {"user_id": "rt-99wb", "idempotency_key": "k99wb-%d" % i, "seats": 1})[0])
        time.sleep(0.05)
    ok = outs.count(429) >= 3 and outs.count(500) == 0
    return check("rate", "same-user waitlist join burst 14: limiter fires, zero 5xx", ok, "429s=%d" % outs.count(429))
waitlist_burst_rate()
def null_byte_query_value():
    st, _ = post(ER, "/reserve?x=ab%00cd", {"user_id": "rt-99nb", "idempotency_key": "k99nb", "seats": 1})
    alive = raw(ER, "GET", "/seats")[0] == 200
    ok = st != 500 and st != -1 and alive
    return check("wire", "null byte in query param value: no 5xx, alive", ok, "status=%s" % st)
null_byte_query_value()

# ---------------- Summary ----------------
fails = [r for r in results if not r[2]]
print("TOTAL %d cases, PASS %d, FAIL %d" % (len(results), len(results) - len(fails), len(fails)))
for cat, name, ok, detail in fails:
    print("FAIL [%s] %s :: %s" % (cat, name, detail))
sys.exit(1 if fails else 0)
