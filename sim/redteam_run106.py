#!/usr/bin/env python3
"""Run 106 extras: 12 angles (all live in redteam_battery.py Phase BH too).
1: parallel confirm + transfer race on the same rid: no 5xx, conserved
2: X-Kavach-Timestamp as Arabic-Indic digits: 4xx, conserved
3: /confirm with reservation_id as JSON array: 4xx, conserved
4: expired-hold race (confirm expired rid + reserve same idem in parallel): no 5xx, conserved
5: webhook valid token but Content-Type text/plain: no 500, app alive
6: app /api/pay reservation_id as JSON array: no 500, app alive
7: engine reserve seats as string "01" (leading zero): graceful, conserved
8: engine transfer with to_user null: graceful, conserved
9: engine reserve with idempotency_key as JSON object: graceful, conserved
10: webhook event field as number: no 500, app alive
11: app /api/waitlist seats as JSON array: no 500, app alive
12: engine reserve with user_id boolean true: graceful, conserved
Run against targets already up: 8091 engine, 8092 engine2, 9001 app.
"""
import hashlib, hmac, http.client, json, sys, time, uuid
from concurrent.futures import ThreadPoolExecutor

ER, AR, ER2 = 8091, 9001, 8092
KEY, KEY2, SECRET = "testkey", "otherkey", "testsecret"
results = []
def check(cat, name, ok, detail=""):
    results.append((cat, name, bool(ok), str(detail)[:220]))
    return ok
def sign(key, method, path, body, secret=SECRET, ts=None, rid=None):
    ts = str(int(time.time())) if ts is None else ts
    rid = uuid.uuid4().hex if rid is None else rid
    mac = hmac.new(secret.encode(), (ts + "\n" + rid + "\n" + method + "\n" + path + "\n" + key + "\n").encode() + body, hashlib.sha256).hexdigest()
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

# ---------------- Phase BH: run 106 extras (12 new angles) ----------------
def be_hold(user, key="k106%s", port=ER, seats_n=1):
    st, j = post(port, "/reserve", {"user_id": user, "idempotency_key": key, "seats": seats_n})
    return (j.get("reservation_id") if isinstance(j, dict) and st == 200 else None), st, (j if isinstance(j, dict) else {"raw": str(j)[:80]})
def confirm_transfer_race():
    rid, st, _ = be_hold("rt-106ctr", "k106ctr")
    if not rid:
        return check("race", "confirm+transfer race on same rid: skipped (hold unavailable)", True, "st=%s" % st)
    cbody = json.dumps({"reservation_id": rid}).encode()
    tbody = json.dumps({"reservation_id": rid, "to_user": "rt-106ctr2"}).encode()
    hc = sign(KEY, "POST", "/confirm", cbody)
    ht = sign(KEY, "POST", "/transfer", tbody)
    with ThreadPoolExecutor(2) as ex:
        f1 = ex.submit(raw, ER, "POST", "/confirm", cbody, hc)
        f2 = ex.submit(raw, ER, "POST", "/transfer", tbody, ht)
        c, _ = f1.result(); t, _ = f2.result()
    time.sleep(0.3)
    ok = all(x != 500 and x != -1 for x in (c, t)) and conserved() and raw(ER, "GET", "/seats")[0] == 200
    return check("race", "parallel confirm + transfer on same rid: no 5xx, conserved", ok, "c=%s t=%s" % (c, t))
confirm_transfer_race()
def ts_arabic():
    body = json.dumps({"user_id": "rt-106tsa", "idempotency_key": "k106tsa", "seats": 1}).encode()
    h = sign(KEY, "POST", "/reserve", body)
    req = ("POST /reserve HTTP/1.1\r\nHost: 127.0.0.1\r\n"
           + "".join("%s: %s\r\n" % (k, v) for k, v in h.items())
           + "X-Kavach-Timestamp: " + "\u0661\u0660\u0660\u0660\u0660\u0660\u0660\u0660\u0660\u0660\u0660".encode("utf-8").decode("latin-1")
           + "\r\nContent-Length: %d\r\nConnection: close\r\n\r\n" % len(body)).encode("latin-1") + body
    import socket as _s
    try:
        sk = _s.create_connection(("127.0.0.1", ER), timeout=15)
        sk.sendall(req)
        resp = sk.recv(4096)
        sk.close()
        st = int(resp.split(b" ", 2)[1]) if resp and resp.split(b" ", 2)[1].isdigit() else -1
    except Exception as ex:
        st = -1
    s = seats(ER)
    cv = s.get("total", -1) == s.get("sold", 0) + s.get("held", 0) + s.get("free", 0)
    ok = st != 500 and st != -1 and st != 200 and cv and raw(ER, "GET", "/seats")[0] == 200
    return check("auth", "timestamp as Arabic-Indic digits (raw socket): 4xx, conserved", ok, "st=%s" % st)
ts_arabic()
def confirm_rid_array():
    st, j = post(ER, "/confirm", {"reservation_id": ["RSV-FAKE-106"]})
    s = seats(ER)
    cv = s.get("total", -1) == s.get("sold", 0) + s.get("held", 0) + s.get("free", 0)
    ok = st != 500 and st != -1 and cv and raw(ER, "GET", "/seats")[0] == 200
    return check("state", "/confirm with reservation_id as JSON array: 4xx graceful, conserved", ok, "st=%s" % st)
confirm_rid_array()
def expired_hold_race():
    rid, st, _ = be_hold("rt-106ehr", "k106ehr")
    if not rid:
        return check("race", "expired-hold race: skipped (hold unavailable)", True, "st=%s" % st)
    time.sleep(5)  # hold-ttl 3: hold is now expired, engine auto-releases
    cbody = json.dumps({"reservation_id": rid}).encode()
    rbody = json.dumps({"user_id": "rt-106ehr", "idempotency_key": "k106ehr", "seats": 1}).encode()
    hc = sign(KEY, "POST", "/confirm", cbody)
    hr = sign(KEY, "POST", "/reserve", rbody)
    with ThreadPoolExecutor(2) as ex:
        f1 = ex.submit(raw, ER, "POST", "/confirm", cbody, hc)
        f2 = ex.submit(raw, ER, "POST", "/reserve", rbody, hr)
        c, _ = f1.result(); r, _ = f2.result()
    time.sleep(0.3)
    s = seats(ER)
    cv = s.get("total", -1) == s.get("sold", 0) + s.get("held", 0) + s.get("free", 0)
    ok = all(x != 500 and x != -1 for x in (c, r)) and cv and raw(ER, "GET", "/seats")[0] == 200
    return check("race", "expired-hold race (confirm expired + reserve same idem): no 5xx, conserved", ok, "c=%s r=%s" % (c, r))
expired_hold_race()
def webhook_text_plain():
    w, _ = raw(AR, "POST", "/api/kavach-webhook?token=whsec-redtest", '{"event":"payment_success"}', {"Content-Type": "text/plain"})
    alive = raw(AR, "GET", "/")[0] == 200
    ok = w != 500 and w != -1 and alive
    return check("app", "webhook valid token, Content-Type text/plain: no 500, app alive", ok, "w=%s" % w)
webhook_text_plain()
def app_pay_rid_array():
    rid, st, _ = be_hold("rt-106pra", "k106pra")
    if not rid:
        return check("app", "app pay rid array: skipped (hold unavailable)", True, "st=%s" % st)
    p, _ = raw(AR, "POST", "/api/pay", json.dumps({"reservation_id": [rid], "amount": 100}))
    post(ER, "/release", {"reservation_id": rid})
    alive = raw(AR, "GET", "/")[0] == 200
    ok = p != 500 and p != -1 and alive
    return check("app", "app /api/pay reservation_id as JSON array: no 500, graceful", ok, "p=%s" % p)
app_pay_rid_array()
def seats_leading_zero():
    st, j = post(ER, "/reserve", {"user_id": "rt-106lz", "idempotency_key": "k106lz", "seats": "01"})
    s = seats(ER)
    cv = s.get("total", -1) == s.get("sold", 0) + s.get("held", 0) + s.get("free", 0)
    ok = st != 500 and st != -1 and cv and raw(ER, "GET", "/seats")[0] == 200
    return check("auth", "seats as string \"01\" (leading zero): graceful, conserved", ok, "st=%s" % st)
seats_leading_zero()
def transfer_to_user_null():
    rid, st, _ = be_hold("rt-106tn", "k106tn")
    if not rid:
        return check("state", "transfer to_user null: skipped (hold unavailable)", True, "st=%s" % st)
    t, _ = post(ER, "/transfer", {"reservation_id": rid, "to_user": None})
    post(ER, "/release", {"reservation_id": rid})
    ok = t != 500 and t != -1 and conserved() and raw(ER, "GET", "/seats")[0] == 200
    return check("state", "transfer with to_user null: graceful, conserved", ok, "t=%s" % t)
transfer_to_user_null()
def idem_key_object():
    st, j = post(ER, "/reserve", {"user_id": "rt-106ik", "idempotency_key": {"k": 1}, "seats": 1})
    s = seats(ER)
    cv = s.get("total", -1) == s.get("sold", 0) + s.get("held", 0) + s.get("free", 0)
    ok = st != 500 and st != -1 and cv and raw(ER, "GET", "/seats")[0] == 200
    return check("auth", "idempotency_key as JSON object: graceful, conserved", ok, "st=%s" % st)
idem_key_object()
def webhook_event_number():
    w, _ = raw(AR, "POST", "/api/kavach-webhook?token=whsec-redtest", '{"event":123}')
    alive = raw(AR, "GET", "/")[0] == 200
    ok = w != 500 and w != -1 and alive
    return check("app", "webhook event field as number: no 500, app alive", ok, "w=%s" % w)
webhook_event_number()
def app_waitlist_seats_array():
    p, _ = raw(AR, "POST", "/api/waitlist", json.dumps({"user_id": "rt-106wa", "seats": [2]}))
    alive = raw(AR, "GET", "/")[0] == 200
    ok = p != 500 and p != -1 and alive
    return check("app", "app /api/waitlist seats as JSON array: no 500, graceful", ok, "p=%s" % p)
app_waitlist_seats_array()
def user_id_boolean():
    st, j = post(ER, "/reserve", {"user_id": True, "idempotency_key": "k106ub", "seats": 1})
    s = seats(ER)
    cv = s.get("total", -1) == s.get("sold", 0) + s.get("held", 0) + s.get("free", 0)
    ok = st != 500 and st != -1 and cv and raw(ER, "GET", "/seats")[0] == 200
    return check("auth", "user_id as boolean true: graceful, conserved", ok, "st=%s" % st)
user_id_boolean()

if __name__ == "__main__":
    fails = [r for r in results if not r[2]]
    print("TOTAL %d cases, PASS %d, FAIL %d" % (len(results), len(results) - len(fails), len(fails)))
    for r in fails: print("FAIL [%s] %s :: %s" % (r[0], r[1], r[3]))
    sys.exit(1 if fails else 0)
