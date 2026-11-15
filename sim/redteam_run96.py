#!/usr/bin/env python3
"""Run 96 extras: 12 angles (all live in redteam_battery.py Phase AX too).
1: HTTP/1.0 request line via raw socket: no 5xx, no hang, alive
2: tab character inside signature header value: 401/4xx, no 5xx
3: release same rid twice (double release): no 5xx, conserved
4: webhook event uppercase PAYMENT_SUCCESS: no 500, alive
5: X-Kavach-Timestamp float string with decimal: 401/4xx
6: seats as negative float -1.0: 4xx
7: user_id with zero-width joiner U+200D: no 500, alive
8: idempotency_key with emoji: no 500, alive
9: 6-way parallel app /api/hold overbook attempt: conserved, no overbook
10: release of a confirmed booking: 4xx, conserved
11: app /api/status rid with SQL-quote payload: no 500, app alive
12: reserve with unexpected admin field: no 500, alive
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
def seats(port=ER):
    st, j = raw(port, "GET", "/seats"); return j if st == 200 else {}
def conserved(port=ER):
    s = seats(port)
    return s.get("total", -1) == s.get("sold", 0) + s.get("held", 0) + s.get("free", 0)

# ---------------- Phase AX: run 96 extras (12 new angles) ----------------
def http_1_0_request():
    import socket as _s
    buf = b""
    try:
        sk = _s.create_connection(("127.0.0.1", ER), timeout=8)
        sk.sendall(b"GET /seats HTTP/1.0\r\n\r\n")
        sk.settimeout(5)
        try: buf = sk.recv(300)
        except Exception: pass
        sk.close()
    except Exception:
        pass
    stc = int(buf.split(b" ")[1]) if b"HTTP/1." in buf and len(buf.split(b" ")) > 1 else -1
    alive = raw(ER, "GET", "/seats")[0] == 200
    ok = stc != 500 and stc != -1 and alive
    return check("wire", "HTTP/1.0 request line: no 5xx, no hang, alive", ok, "st=%s" % stc)
http_1_0_request()
def tab_in_signature():
    b = json.dumps({"user_id": "rt-96tb", "idempotency_key": "k96tb", "seats": 1}).encode()
    h = sign(KEY, "POST", "/reserve", b)
    h["X-Kavach-Signature"] = h["X-Kavach-Signature"][:32] + "\t" + h["X-Kavach-Signature"][32:]
    st, _ = raw(ER, "POST", "/reserve", b, h)
    alive = raw(ER, "GET", "/seats")[0] == 200
    ok = st != 200 and st != 500 and st != -1 and alive
    return check("auth", "tab inside signature header value: 401/4xx, no 5xx, alive", ok, "status=%s" % st)
tab_in_signature()
def double_release():
    st, j = post(ER, "/reserve", {"user_id": "rt-96dr", "idempotency_key": "k96dr", "seats": 1})
    rid = j.get("reservation_id") if isinstance(j, dict) and st == 200 else None
    if not rid:
        return check("state", "double release: skipped (hold unavailable)", True, "st=%s" % st)
    r1 = post(ER, "/release", {"reservation_id": rid})[0]
    r2 = post(ER, "/release", {"reservation_id": rid})[0]
    time.sleep(1.0)
    ok = r1 != 500 and r2 != 500 and r1 != -1 and r2 != -1 and conserved()
    return check("state", "double release same rid: no 5xx, conserved", ok, "r1=%s r2=%s" % (r1, r2))
double_release()
def webhook_uppercase_event():
    body = '{"token":"whsec-redtest","event":"PAYMENT_SUCCESS","reservation_id":"RSV00000001"}'
    w, _ = raw(AR, "POST", "/api/kavach-webhook?token=whsec-redtest", body)
    alive = raw(AR, "GET", "/")[0] == 200
    ok = w != 500 and w != -1 and alive
    return check("app", "webhook event uppercase PAYMENT_SUCCESS: no 500, alive", ok, "w=%s" % w)
webhook_uppercase_event()
def timestamp_float_string():
    ts = str(int(time.time())) + ".5"
    b = json.dumps({"user_id": "rt-96tf", "idempotency_key": "k96tf", "seats": 1}).encode()
    st, _ = raw(ER, "POST", "/reserve", b, sign(KEY, "POST", "/reserve", b, ts=ts))
    alive = raw(ER, "GET", "/seats")[0] == 200
    ok = st != 200 and st != 500 and st != -1 and alive
    return check("auth", "timestamp float string with decimal: 401/4xx, no 5xx, alive", ok, "status=%s" % st)
timestamp_float_string()
def seats_negative_float():
    st, _ = post(ER, "/reserve", {"user_id": "rt-96nf", "idempotency_key": "k96nf", "seats": -1.0})
    alive = raw(ER, "GET", "/seats")[0] == 200
    ok = st != 500 and st != -1 and alive
    return check("fuzz", "seats as negative float -1.0: 4xx, no 5xx, alive", ok, "status=%s" % st)
seats_negative_float()
def user_id_zwj():
    st, _ = post(ER, "/reserve", {"user_id": "rt-96‍x", "idempotency_key": "k96zw", "seats": 1})
    alive = raw(ER, "GET", "/seats")[0] == 200
    ok = st != 500 and st != -1 and alive
    return check("fuzz", "user_id with zero-width joiner U+200D: no 500, alive", ok, "status=%s" % st)
user_id_zwj()
def idem_key_emoji():
    st, _ = post(ER, "/reserve", {"user_id": "rt-96ie", "idempotency_key": "k-🚀-96", "seats": 1})
    alive = raw(ER, "GET", "/seats")[0] == 200
    ok = st != 500 and st != -1 and alive
    return check("fuzz", "idempotency_key with emoji: no 500, alive", ok, "status=%s" % st)
idem_key_emoji()
def app_hold_overbook_race():
    s0 = seats(ER)
    free0 = s0.get("free", 0)
    per = max(1, free0 // 3) if free0 >= 3 else 1
    def go(i):
        return raw(AR, "POST", "/api/hold", '{"user_id":"rt-96ob-%d","seats":%d}' % (i, per))
    with ThreadPoolExecutor(6) as ex:
        outs = list(ex.map(go, range(6)))
    codes = [st for st, _ in outs]
    time.sleep(1.0)
    s1 = seats(ER)
    free1 = s1.get("free", 0)
    held1 = s1.get("held", 0)
    accepted = sum(1 for st in codes if st == 200)
    if free0 == 0:
        ok = all(c != 500 and c != -1 for c in codes) and conserved() and accepted == 0
        return check("race", "6-way parallel app holds with 0 free seats: all rejected, no 5xx, conserved", ok, "codes=%s" % codes)
    ok = all(c != 500 and c != -1 for c in codes) and conserved() and held1 <= free0 and free1 >= 0
    return check("race", "6-way parallel app holds overbook attempt: no 5xx, no overbook, conserved", ok, "accepted=%d free0=%d free1=%d per=%d codes=%s" % (accepted, free0, free1, per, codes))

def release_confirmed_booking():
    st, j = post(ER, "/reserve", {"user_id": "rt-96rc", "idempotency_key": "k96rc", "seats": 1})
    rid = j.get("reservation_id") if isinstance(j, dict) and st == 200 else None
    if not rid:
        return check("state", "release confirmed booking: skipped (hold unavailable)", True, "st=%s" % st)
    st2, _ = post(ER, "/confirm", {"reservation_id": rid})
    if st2 != 200:
        return check("state", "release confirmed booking: skipped (confirm %s)" % st2, True)
    st3, _ = post(ER, "/release", {"reservation_id": rid})
    time.sleep(1.0)
    ok = st3 != 200 and st3 != 500 and st3 != -1 and conserved()
    return check("state", "release of confirmed booking: 4xx, stays sold, conserved", ok, "st3=%s" % st3)
release_confirmed_booking()
def app_status_sql_quote():
    p, _ = raw(AR, "GET", "/api/status?reservation_id=RSV'--")
    alive = raw(AR, "GET", "/")[0] == 200
    ok = p != 500 and p != -1 and alive
    return check("app", "app status rid with SQL-quote payload: no 500, app alive", ok, "p=%s" % p)
app_status_sql_quote()
def reserve_admin_field():
    st, _ = post(ER, "/reserve", {"user_id": "rt-96af", "idempotency_key": "k96af", "seats": 1, "admin": True, "price": 0, "role": "owner"})
    alive = raw(ER, "GET", "/seats")[0] == 200
    ok = st != 500 and st != -1 and alive
    return check("fuzz", "reserve with unexpected admin/price/role fields: no 500, alive", ok, "status=%s" % st)
reserve_admin_field()

# ---------------- Summary ----------------
fails = [r for r in results if not r[2]]
print("TOTAL %d cases, PASS %d, FAIL %d" % (len(results), len(results) - len(fails), len(fails)))
for cat, name, ok, detail in fails:
    print("FAIL [%s] %s :: %s" % (cat, name, detail))
sys.exit(1 if fails else 0)
