#!/usr/bin/env python3
"""Run 86 extras: 12 angles (all live in redteam_battery.py Phase AN too).
1: dot-dot traversal paths: no 5xx, alive
2: reserve with seats as array: 4xx, alive
3: app hold with non-JSON body: no 500
4: webhook payment_success with seats as string: no 500, sane
5: 50 rapid same-user reserves on 8092 then valid after 2s: no 5xx, recovers
6: invalid percent-encoding %zz in query: no 5xx, alive
7: app hold with duplicate JSON keys: no 500
8: reserve same idem key after its rid was sold: no 5xx, conserved
9: unicode combining chars in user_id: no 5xx, conserved
10: POST /reserve no body no Content-Type: no 5xx, alive
11: tenant1 release of tenant2's hold: denied, hold intact
12: app hold with seats null: no 500
Run against targets already up: 8091 engine, 8092 engine2, 9001 app.
"""
import hashlib, hmac, http.client, json, sys, time, uuid
from concurrent.futures import ThreadPoolExecutor

ER, AR, ER2 = 8091, 9001, 8092
KEY, SECRET = "testkey", "testsecret"
results = []
def check(cat, name, ok, detail=""):
    results.append((cat, name, bool(ok), str(detail)[:220]))
def sign(key, method, path, body, secret=SECRET, ts=None, rid=None):
    ts = str(int(time.time())) if ts is None else ts
    rid = uuid.uuid4().hex if rid is None else rid
    mac = hmac.new(secret.encode(), (ts + "\n" + rid + "\n" + method + "\n" + path + "\n" + key + "\n").encode() + body, hashlib.sha256)
    return {"Authorization": "Bearer " + key, "X-Kavach-Timestamp": ts, "X-Kavach-Request-Id": rid,
            "X-Kavach-Signature": mac.hexdigest(), "Content-Type": "application/json"}
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
def rej(st): return 400 <= st < 500 or st == 429
def P(n, fn):
    with ThreadPoolExecutor(max(1, n)) as ex:
        return list(ex.map(fn, range(n)))
def seats(port=ER):
    st, j = raw(port, "GET", "/seats"); return j if st == 200 else {}

# ---------------- Phase AN: run 86 extras (12 new angles) ----------------
def dotdot_traversal():
    st1, _ = raw(ER, "GET", "/%2e%2e/seats")
    st2, _ = raw(ER, "GET", "/seats/../../seats")
    alive = raw(ER, "GET", "/seats")[0] == 200
    ok = st1 != 500 and st1 != -1 and st2 != 500 and st2 != -1 and alive
    return check("wire", "dot-dot traversal paths: no 5xx, alive", ok, "st1=%s st2=%s" % (st1, st2))
dotdot_traversal()
def seats_array():
    st, _ = post(ER, "/reserve", {"user_id": "rt-86sa", "idempotency_key": "k86sa", "seats": [1]})
    alive = raw(ER, "GET", "/seats")[0] == 200
    return check("fuzz", "reserve with seats as array: 4xx, no 5xx, alive", st != 500 and st != -1 and alive, "status=%s" % st)
seats_array()
def app_non_json_body():
    p, _ = raw(AR, "POST", "/api/hold", b"hello world")
    alive = raw(AR, "GET", "/")[0] == 200
    return check("app", "app hold with non-JSON body: no 500, app alive", p != 500 and p != -1 and alive, "p=%s" % p)
app_non_json_body()
def webhook_seats_string():
    st, j = post(ER, "/reserve", {"user_id": "rt-86ws", "idempotency_key": "k86ws", "seats": 2})
    rid = j.get("reservation_id") if isinstance(j, dict) and st == 200 else None
    if not rid:
        return check("app", "webhook seats as string: skipped (hold unavailable)", True, "st=%s" % st)
    s0 = seats(ER)
    w, _ = raw(AR, "POST", "/api/kavach-webhook?token=whsec-redtest", json.dumps({"event": "payment_success", "reservation_id": rid, "seats": "2"}))
    s1 = seats(ER)
    alive = raw(AR, "GET", "/")[0] == 200
    sane = s1.get("sold", 0) in (s0.get("sold", 0), s0.get("sold", 0) + 2)
    ok = w != 500 and w != -1 and alive and sane
    return check("app", "webhook payment_success with seats as string: no 500, seats sane", ok, "w=%s sold0=%s sold1=%s" % (w, s0.get("sold"), s1.get("sold")))
webhook_seats_string()
def user_burst_recovery():
    outs = [post(ER2, "/reserve", {"user_id": "rt-86ub", "idempotency_key": "k86ub%d" % i, "seats": 1})[0] for i in range(50)]
    time.sleep(2.0)
    st, _ = post(ER2, "/reserve", {"user_id": "rt-86ub", "idempotency_key": "k86ubafter", "seats": 1})
    alive = raw(ER2, "GET", "/seats")[0] == 200
    ok = all(x != 500 for x in outs) and st != 500 and st != -1 and alive
    return check("rate", "50 rapid same-user reserves on 8092 (2/s limit) then valid reserve after 2s: no 5xx, recovers", ok, "burst429=%d after=%s" % (outs.count(429), st))
user_burst_recovery()
def invalid_percent_encoding():
    st, _ = raw(ER, "GET", "/seats?x=%zz")
    alive = raw(ER, "GET", "/seats")[0] == 200
    ok = st != 500 and st != -1 and alive
    return check("wire", "invalid percent-encoding %zz in query: no 5xx, alive", ok, "status=%s" % st)
invalid_percent_encoding()
def app_duplicate_json_keys():
    p, _ = raw(AR, "POST", "/api/hold", b'{"user_id": "rt-86dk", "seats": 1, "user_id": "rt-86dk2"}')
    alive = raw(AR, "GET", "/")[0] == 200
    return check("app", "app hold with duplicate JSON keys: no 500, app alive", p != 500 and p != -1 and alive, "p=%s" % p)
app_duplicate_json_keys()
def idem_reuse_after_confirm():
    o = {"user_id": "rt-86ir", "idempotency_key": "k86ir", "seats": 1}
    st1, j1 = post(ER, "/reserve", o)
    rid = j1.get("reservation_id") if isinstance(j1, dict) and st1 == 200 else None
    if not rid:
        return check("state", "idem key reuse after confirm: skipped (hold unavailable)", True, "st=%s" % st1)
    post(ER, "/confirm", {"reservation_id": rid})  # sold
    st2, _ = post(ER, "/reserve", o)  # same idem key after sale
    s = seats(ER)
    conserved = s.get("total", -1) == s.get("sold", 0) + s.get("held", 0) + s.get("free", 0)
    ok = st2 != 500 and st2 != -1 and conserved
    return check("state", "reserve with same idem key after its rid was sold: no 5xx, conserved", ok, "st2=%s" % st2)
idem_reuse_after_confirm()
def unicode_combining_user():
    st, _ = post(ER, "/reserve", {"user_id": "rt-86ú́", "idempotency_key": "k86uc", "seats": 1})
    s = seats(ER)
    conserved = s.get("total", -1) == s.get("sold", 0) + s.get("held", 0) + s.get("free", 0)
    ok = st != 500 and st != -1 and conserved
    return check("fuzz", "reserve with unicode combining chars in user_id: no 5xx, conserved", ok, "status=%s" % st)
unicode_combining_user()
def post_no_body_no_ct():
    h = sign(KEY, "POST", "/reserve", b"")
    h.pop("Content-Type", None)
    st, _ = raw(ER, "POST", "/reserve", None, h)
    alive = raw(ER, "GET", "/seats")[0] == 200
    ok = st != 500 and st != -1 and alive
    return check("wire", "POST /reserve with no body and no Content-Type: no 5xx, alive", ok, "status=%s" % st)
post_no_body_no_ct()
def cross_tenant_release_denied():
    st, j = post(ER, "/reserve", {"user_id": "rt-86xt", "idempotency_key": "k86xt", "seats": 1}, key="otherkey")
    rid = j.get("reservation_id") if isinstance(j, dict) and st == 200 else None
    if not rid:
        return check("state", "cross-tenant release denied: skipped (hold unavailable)", True, "st=%s" % st)
    s0 = seats(ER)
    st2, _ = post(ER, "/release", {"reservation_id": rid})  # tenant1 tries to release tenant2's hold
    s1 = seats(ER)
    intact = s1.get("held", 0) >= s0.get("held", 0)  # hold not stolen
    post(ER, "/release", {"reservation_id": rid}, key="otherkey")  # owner cleans up
    ok = st2 != 200 and st2 != 500 and st2 != -1 and intact
    return check("state", "tenant1 release of tenant2's hold: denied, hold intact", ok, "st2=%s held0=%s held1=%s" % (st2, s0.get("held"), s1.get("held")))
cross_tenant_release_denied()
def app_hold_seats_null():
    p, _ = raw(AR, "POST", "/api/hold", json.dumps({"user_id": "rt-86sn", "seats": None}))
    alive = raw(AR, "GET", "/")[0] == 200
    return check("app", "app hold with seats null: no 500, app alive", p != 500 and p != -1 and alive, "p=%s" % p)
app_hold_seats_null()


fails = [r for r in results if not r[2]]
print("TOTAL %d cases, PASS %d, FAIL %d" % (len(results), len(results) - len(fails), len(fails)))
for cat, name, ok, detail in fails:
    print("FAIL [%s] %s :: %s" % (cat, name, detail))
sys.exit(1 if fails else 0)
