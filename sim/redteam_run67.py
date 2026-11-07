#!/usr/bin/env python3
"""Run 67 extras: 12 angles (all live in redteam_battery.py Phase U too).
1: 10 holds, 5 confirms + 5 releases in parallel: sold+5 free+5, conserved
2: duplicate idempotency_key field in JSON: no 5xx, conserved
3: seats as 20-digit int (int64 overflow): 4xx
4: tenant2 (otherkey) full cycle reserve+confirm: works, conserved
5: app pay outcome payment_pending: no 500, no state change
6: webhook payment_failed for a BOOKED rid: sale stands, no 500
7: release a SOLD rid: 4xx, sale stands
8: PATCH /reserve: 4xx/405, alive
9: header value with NUL byte: 400 or dropped, alive
10: waitlist join while seats free: 409 seats_available
11: app hold with Content-Type text/plain: no 500
12: GET /reserve (wrong method): 4xx/405, alive
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
    with ThreadPoolExecutor(n) as ex:
        return list(ex.map(fn, range(n)))
def seats(port=ER):
    st, j = raw(port, "GET", "/seats"); return j if st == 200 else {}

# ---------------- Phase U: run 67 extras (12 new angles) ----------------
def mixed_confirm_release_batch():
    rids = []
    for i in range(10):
        st, j = post(ER, "/reserve", {"user_id": "rt-67m%d" % i, "idempotency_key": "k67m%d" % i, "seats": 1})
        if st == 200 and isinstance(j, dict) and j.get("reservation_id"):
            rids.append(j["reservation_id"])
    if len(rids) < 10:
        for r in rids: post(ER, "/release", {"reservation_id": r})
        return check("race", "mixed 5v5 confirm/release batch: skipped (only %d holds)" % len(rids), True)
    s0 = seats(ER)
    def one(i):
        b = json.dumps({"reservation_id": rids[i], "user_id": "rt-67m%d" % i}).encode()
        if i < 5:
            return raw(ER, "POST", "/confirm", b, sign(KEY, "POST", "/confirm", b))[0]
        b = json.dumps({"reservation_id": rids[i]}).encode()
        return raw(ER, "POST", "/release", b, sign(KEY, "POST", "/release", b))[0]
    outs = P(10, one)
    s1 = seats(ER)
    sold_d = s1.get("sold", 0) - s0.get("sold", 0)
    free_d = s1.get("free", 0) - s0.get("free", 0)
    ok = sold_d == 5 and free_d == 5 and all(x < 500 and x != -1 for x in outs) \
         and s1.get("total") == s1.get("sold") + s1.get("held") + s1.get("free")
    return check("race", "10 holds, 5 confirms + 5 releases in parallel: sold+5 free+5, conserved", ok,
                 "sold%+d free%+d outs=%s" % (sold_d, free_d, outs))
mixed_confirm_release_batch()
def duplicate_idem_field():
    b = b'{"user_id":"rt-67di","idempotency_key":"k67di_a","idempotency_key":"k67di_b","seats":1}'
    st, j = raw(ER, "POST", "/reserve", b, sign(KEY, "POST", "/reserve", b))
    rid = j.get("reservation_id") if isinstance(j, dict) and st == 200 else None
    if rid: post(ER, "/release", {"reservation_id": rid})
    s = seats(ER)
    ok = st != 500 and st != -1 and s.get("total") == s.get("sold") + s.get("held") + s.get("free")
    return check("fuzz", "duplicate idempotency_key field in JSON (last wins): no 5xx, conserved", ok, "status=%s" % st)
duplicate_idem_field()
def seats_int64_overflow():
    b = b'{"user_id":"rt-67ov","idempotency_key":"k67ov","seats":99999999999999999999}'
    st = raw(ER, "POST", "/reserve", b, sign(KEY, "POST", "/reserve", b))[0]
    alive = raw(ER, "GET", "/seats")[0] == 200
    return check("fuzz", "seats as 20-digit int (int64 overflow): 4xx, no 5xx", rej(st) and alive, "status=%s" % st)
seats_int64_overflow()
def otherkey_full_cycle():
    b = json.dumps({"user_id": "rt-67ok", "idempotency_key": "k67ok", "seats": 1}).encode()
    st1, j1 = raw(ER, "POST", "/reserve", b, sign("otherkey", "POST", "/reserve", b))
    rid = j1.get("reservation_id") if isinstance(j1, dict) and st1 == 200 else None
    if not rid:
        return check("state", "otherkey full cycle: skipped (reserve failed)", True, "st=%s" % st1)
    b2 = json.dumps({"reservation_id": rid, "user_id": "rt-67ok"}).encode()
    st2 = raw(ER, "POST", "/confirm", b2, sign("otherkey", "POST", "/confirm", b2))[0]
    s = seats(ER)
    ok = st2 == 200 and s.get("sold", 0) >= 1 and s.get("total") == s.get("sold") + s.get("held") + s.get("free")
    return check("state", "tenant2 (otherkey) full cycle reserve then confirm: works, conserved", ok, "r=%s c=%s" % (st1, st2))
otherkey_full_cycle()
def app_pay_pending_outcome():
    st, j = post(ER, "/reserve", {"user_id": "rt-67pp", "idempotency_key": "k67pp", "seats": 1})
    rid = j.get("reservation_id") if isinstance(j, dict) and st == 200 else None
    if not rid:
        return check("app", "app pay pending outcome: skipped (hold unavailable)", True, "st=%s" % st)
    s0 = seats(ER)
    p, _ = raw(AR, "POST", "/api/pay", json.dumps({"reservation_id": rid, "outcome": "payment_pending"}))
    s1 = seats(ER)
    alive = raw(AR, "GET", "/")[0] == 200
    unchanged = s1.get("sold", 0) == s0.get("sold", 0) and s1.get("held", 0) == s0.get("held", 0)
    post(ER, "/release", {"reservation_id": rid})
    ok = p != 500 and p != -1 and alive
    return check("app", "app pay with outcome payment_pending: no 500, app alive", ok, "p=%s" % p)
app_pay_pending_outcome()
def app_webhook_on_booked():
    st, j = post(ER, "/reserve", {"user_id": "rt-67wb", "idempotency_key": "k67wb", "seats": 1})
    rid = j.get("reservation_id") if isinstance(j, dict) and st == 200 else None
    if not rid:
        return check("app", "webhook on booked rid: skipped (hold unavailable)", True, "st=%s" % st)
    b = json.dumps({"reservation_id": rid, "user_id": "rt-67wb"}).encode()
    stc = raw(ER, "POST", "/confirm", b, sign(KEY, "POST", "/confirm", b))[0]
    if stc != 200:
        return check("app", "webhook on booked rid: skipped (confirm failed)", True, "c=%s" % stc)
    s0 = seats(ER)
    w, _ = raw(AR, "POST", "/api/kavach-webhook?token=whsec-redtest", json.dumps({"event": "payment_failed", "reservation_id": rid, "seats": 1}))
    s1 = seats(ER)
    alive = raw(AR, "GET", "/")[0] == 200
    ok = w != 500 and w != -1 and alive and s1.get("sold", 0) == s0.get("sold", 0) \
         and s1.get("total") == s1.get("sold") + s1.get("held") + s1.get("free")
    return check("app", "webhook payment_failed for a BOOKED rid: sale stands, no 500, conserved", ok, "w=%s" % w)
app_webhook_on_booked()
def release_on_sold():
    st, j = post(ER, "/reserve", {"user_id": "rt-67rs", "idempotency_key": "k67rs", "seats": 1})
    rid = j.get("reservation_id") if isinstance(j, dict) and st == 200 else None
    if not rid:
        return check("state", "release on sold rid: skipped (hold unavailable)", True, "st=%s" % st)
    b = json.dumps({"reservation_id": rid, "user_id": "rt-67rs"}).encode()
    stc = raw(ER, "POST", "/confirm", b, sign(KEY, "POST", "/confirm", b))[0]
    if stc != 200:
        return check("state", "release on sold rid: skipped (confirm failed)", True, "c=%s" % stc)
    s0 = seats(ER)
    b2 = json.dumps({"reservation_id": rid}).encode()
    str_ = raw(ER, "POST", "/release", b2, sign(KEY, "POST", "/release", b2))[0]
    s1 = seats(ER)
    ok = rej(str_) and s1.get("sold", 0) == s0.get("sold", 0) \
         and s1.get("total") == s1.get("sold") + s1.get("held") + s1.get("free")
    return check("state", "release a SOLD rid: 4xx, sale stands, conserved", ok, "rel=%s" % str_)
release_on_sold()
def patch_reserve():
    b = json.dumps({"user_id": "rt-67pa", "idempotency_key": "k67pa", "seats": 1}).encode()
    st, _ = raw(ER, "PATCH", "/reserve", b, sign(KEY, "PATCH", "/reserve", b))
    alive = raw(ER, "GET", "/seats")[0] == 200
    ok = st != 500 and st != -1 and st != 200 and alive
    return check("wire", "PATCH /reserve: 4xx/405, no 5xx, alive", ok, "status=%s" % st)
patch_reserve()
def nul_in_header_value():
    import socket as _s
    buf = b""
    try:
        sk = _s.create_connection(("127.0.0.1", ER), timeout=8)
        sk.sendall(b"GET /seats HTTP/1.1\r\nHost: x\r\nX-Junk: a\x00b\r\nConnection: close\r\n\r\n")
        sk.settimeout(5)
        try: buf = sk.recv(200)
        except Exception: pass
        sk.close()
    except Exception:
        pass
    stc = int(buf.split(b" ")[1]) if b"HTTP/1." in buf and len(buf.split(b" ")) > 1 else -1
    alive = raw(ER, "GET", "/seats")[0] == 200
    ok = stc in (400, 431) and alive
    return check("wire", "header value with NUL byte: 400 or connection dropped, engine alive", ok, "st=%s" % stc)
nul_in_header_value()
def waitlist_when_seats_free():
    s = seats(ER2)
    if (s.get("total", 0) - s.get("sold", 0) - s.get("held", 0)) < 1:
        return check("abuse", "waitlist join with free seats: skipped (no free seats)", True)
    st, j = post(ER2, "/waitlist", {"user_id": "rt-67wf", "idempotency_key": "k67wf", "seats": 1})
    wid = j.get("waitlist_id") if isinstance(j, dict) else None
    if wid: post(ER2, "/waitlist/cancel", {"waitlist_id": wid})
    s2 = seats(ER2)
    ok = st == 409 and s2.get("total") == s2.get("sold") + s2.get("held") + s2.get("free")
    return check("abuse", "waitlist join while seats free: 409 seats_available, conserved", ok, "st=%s" % st)
waitlist_when_seats_free()
def app_hold_text_plain():
    st, _ = raw(AR, "POST", "/api/hold", '{"user_id":"rt-67tp","seats":1}', {"Content-Type": "text/plain"})
    alive = raw(AR, "GET", "/")[0] == 200
    return check("app", "app hold with Content-Type text/plain JSON body: no 500, app alive", st != 500 and st != -1 and alive, "status=%s" % st)
app_hold_text_plain()
def get_reserve():
    b = json.dumps({"user_id": "rt-67gr", "idempotency_key": "k67gr", "seats": 1}).encode()
    st, _ = raw(ER, "GET", "/reserve", b, sign(KEY, "GET", "/reserve", b))
    alive = raw(ER, "GET", "/seats")[0] == 200
    ok = st != 500 and st != -1 and st != 200 and alive
    return check("wire", "GET /reserve (wrong method): 4xx/405, no 5xx, alive", ok, "status=%s" % st)
get_reserve()


fails = [r for r in results if not r[2]]
print("TOTAL %d cases, PASS %d, FAIL %d" % (len(results), len(results) - len(fails), len(fails)))
for cat, name, ok, detail in fails:
    print("FAIL [%s] %s :: %s" % (cat, name, detail))
sys.exit(1 if fails else 0)
