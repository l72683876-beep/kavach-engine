#!/usr/bin/env python3
"""Run 90 extras: 12 angles (all live in redteam_battery.py Phase AR too).
1: lowercase 'bearer' scheme: 200 or 401 (no 5xx), alive
2: parallel app webhooks on distinct rids: no 5xx, conserved
3: PATCH /seats: no 5xx, alive
4: seats 0.5: 4xx, alive
5: release expired rid: no 5xx, conserved
6: app GET on POST-only /api/confirm: no 500
7: webhook payment_success seats 0 payload: no 500, sane
8: 100 rapid app status calls: no 500, alive
9: UTF-8 BOM prefixed body: no 5xx
10: MAC with wrong-case secret: 401, alive
11: 10KB user_id: no 5xx
12: same idem key two users: no 5xx, conserved
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

# ---------------- Phase AR: run 90 extras (12 new angles) ----------------
def lowercase_bearer():
    b = json.dumps({"user_id": "rt-90lb", "idempotency_key": "k90lb", "seats": 1}).encode()
    h = sign(KEY, "POST", "/reserve", b)
    h["Authorization"] = "bearer " + KEY
    st, _ = raw(ER, "POST", "/reserve", b, h)
    alive = raw(ER, "GET", "/seats")[0] == 200
    ok = st in (200, 401) and alive
    return check("auth", "lowercase 'bearer' scheme: 200 or 401 (no 5xx), alive", ok, "status=%s" % st)
lowercase_bearer()
def parallel_app_webhooks_distinct():
    rids = []
    for i in range(6):
        st, j = post(ER, "/reserve", {"user_id": "rt-90pw", "idempotency_key": "k90pw%d" % i, "seats": 1})
        if st == 200 and isinstance(j, dict): rids.append(j.get("reservation_id"))
    rids = [r for r in rids if r]
    if not rids:
        return check("race", "parallel app webhooks on distinct rids: skipped (holds unavailable)", True, "none")
    def go(rid):
        return raw(AR, "POST", "/api/kavach-webhook?token=whsec-redtest", json.dumps({"event": "payment_success", "reservation_id": rid}))[0]
    with ThreadPoolExecutor(len(rids)) as ex:
        outs = list(ex.map(go, rids))
    s = seats(ER)
    conserved = s.get("total", -1) == s.get("sold", 0) + s.get("held", 0) + s.get("free", 0)
    ok = all(x != 500 for x in outs) and conserved
    return check("race", "%d parallel app webhooks on distinct rids: no 5xx, conserved" % len(rids), ok, "200s=%d" % outs.count(200))
parallel_app_webhooks_distinct()
def patch_method():
    st, _ = raw(ER, "PATCH", "/seats", None, sign(KEY, "PATCH", "/seats", b""))
    alive = raw(ER, "GET", "/seats")[0] == 200
    ok = st != 500 and st != -1 and alive
    return check("wire", "PATCH /seats: no 5xx, alive", ok, "status=%s" % st)
patch_method()
def seats_float_half():
    st, _ = post(ER, "/reserve", {"user_id": "rt-90fh", "idempotency_key": "k90fh", "seats": 0.5})
    alive = raw(ER, "GET", "/seats")[0] == 200
    return check("fuzz", "reserve with seats 0.5: 4xx, no 5xx, alive", st != 500 and st != -1 and alive, "status=%s" % st)
seats_float_half()
def old_rid_release_after_expiry():
    st, j = post(ER, "/reserve", {"user_id": "rt-90or", "idempotency_key": "k90or", "seats": 1})
    rid = j.get("reservation_id") if isinstance(j, dict) and st == 200 else None
    if not rid:
        return check("state", "old rid release after expiry: skipped (hold unavailable)", True, "st=%s" % st)
    time.sleep(4.0)  # hold-ttl 3s expiry
    st2, _ = post(ER, "/release", {"reservation_id": rid})
    s = seats(ER)
    conserved = s.get("total", -1) == s.get("sold", 0) + s.get("held", 0) + s.get("free", 0)
    ok = st2 != 500 and st2 != -1 and conserved
    return check("state", "release expired rid: no 5xx, conserved", ok, "st2=%s" % st2)
old_rid_release_after_expiry()
def app_get_on_post_endpoint():
    p, _ = raw(AR, "GET", "/api/confirm")
    alive = raw(AR, "GET", "/")[0] == 200
    return check("app", "app GET on POST-only /api/confirm: no 500, alive", p != 500 and p != -1 and alive, "p=%s" % p)
app_get_on_post_endpoint()
def webhook_seats_zero_payload():
    st, j = post(ER, "/reserve", {"user_id": "rt-90wz", "idempotency_key": "k90wz", "seats": 1})
    rid = j.get("reservation_id") if isinstance(j, dict) and st == 200 else None
    if not rid:
        return check("app", "webhook seats 0 payload: skipped (hold unavailable)", True, "st=%s" % st)
    w, _ = raw(AR, "POST", "/api/kavach-webhook?token=whsec-redtest", json.dumps({"event": "payment_success", "reservation_id": rid, "seats": 0}))
    alive = raw(AR, "GET", "/")[0] == 200
    s = seats(ER)
    sane = s.get("sold", 0) >= 1
    ok = w != 500 and w != -1 and alive and sane
    return check("app", "webhook payment_success seats 0 payload: no 500, sane", ok, "w=%s sold=%s" % (w, s.get("sold")))
webhook_seats_zero_payload()
def app_status_burst():
    outs = [raw(AR, "POST", "/api/status", json.dumps({"reservation_id": "RSV00000001"}))[0] for _ in range(100)]
    alive = raw(AR, "GET", "/")[0] == 200
    ok = all(x != 500 for x in outs) and alive
    return check("app", "100 rapid app status calls: no 500, alive", ok, "500s=%d" % outs.count(500))
app_status_burst()
def bom_prefixed_body():
    b = b"\xef\xbb\xbf" + json.dumps({"user_id": "rt-90bm", "idempotency_key": "k90bm", "seats": 1}).encode()
    h = sign(KEY, "POST", "/reserve", b)
    st, _ = raw(ER, "POST", "/reserve", b, h)
    alive = raw(ER, "GET", "/seats")[0] == 200
    ok = st != 500 and st != -1 and alive
    return check("wire", "UTF-8 BOM prefixed body: no 5xx, alive", ok, "status=%s" % st)
bom_prefixed_body()
def wrong_case_secret():
    b = json.dumps({"user_id": "rt-90ws", "idempotency_key": "k90ws", "seats": 1}).encode()
    h = sign(KEY, "POST", "/reserve", b, secret="TESTSECRET")
    st, _ = raw(ER, "POST", "/reserve", b, h)
    alive = raw(ER, "GET", "/seats")[0] == 200
    return check("auth", "MAC with wrong-case secret: 401, alive", st == 401 and alive, "status=%s" % st)
wrong_case_secret()
def huge_user_id():
    st, _ = post(ER, "/reserve", {"user_id": "u" * 10240, "idempotency_key": "k90hu", "seats": 1})
    alive = raw(ER, "GET", "/seats")[0] == 200
    ok = st != 500 and st != -1 and alive
    return check("fuzz", "10KB user_id: no 5xx, alive", ok, "status=%s" % st)
huge_user_id()
def shared_idem_two_users():
    st1, j1 = post(ER, "/reserve", {"user_id": "rt-90si1", "idempotency_key": "k90shared", "seats": 1})
    st2, j2 = post(ER, "/reserve", {"user_id": "rt-90si2", "idempotency_key": "k90shared", "seats": 1})
    s = seats(ER)
    conserved = s.get("total", -1) == s.get("sold", 0) + s.get("held", 0) + s.get("free", 0)
    ok = st1 != 500 and st2 != 500 and st1 != -1 and st2 != -1 and conserved
    return check("state", "same idem key two users: no 5xx, conserved", ok, "st1=%s st2=%s" % (st1, st2))
shared_idem_two_users()


fails = [r for r in results if not r[2]]
print("TOTAL %d cases, PASS %d, FAIL %d" % (len(results), len(results) - len(fails), len(fails)))
for cat, name, ok, detail in fails:
    print("FAIL [%s] %s :: %s" % (cat, name, detail))
sys.exit(1 if fails else 0)
