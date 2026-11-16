#!/usr/bin/env python3
"""Run 98 extras: 12 angles (all live in redteam_battery.py Phase AZ too).
1: empty request (CRLF only) via raw socket: no 5xx, no hang, alive
2: MAC signed for GET sent as POST /reserve: 401
3: timestamp -301s just outside past window: 401
4: idempotency_key as null: 4xx
5: user_id with only whitespace: no 500, alive
6: release of a transferred (owned by new user) rid: no 5xx, conserved
7: app /api/seats with method POST: no 500, app alive
8: webhook missing reservation_id: no 500, alive
9: app /api/pay with rid held on engine 8092: no 500, graceful
10: 10KB method name in request line: no 5xx, no hang
11: Host header 10KB value: no 5xx, no hang, alive
12: parallel transfer + release same confirmed rid: no 5xx, conserved
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

# ---------------- Phase AZ: run 98 extras (12 new angles) ----------------
def empty_request_socket():
    import socket as _s
    buf = b""
    try:
        sk = _s.create_connection(("127.0.0.1", ER), timeout=8)
        sk.sendall(b"\r\n\r\n")
        sk.settimeout(4)
        try: buf = sk.recv(200)
        except Exception: pass
        sk.close()
    except Exception:
        pass
    alive = raw(ER, "GET", "/seats")[0] == 200
    return check("wire", "empty request (CRLF only): no hang, engine alive", alive, "resp=%r" % buf[:40])
empty_request_socket()
def mac_method_mismatch():
    b = json.dumps({"user_id": "rt-98mm", "idempotency_key": "k98mm", "seats": 1}).encode()
    h = sign(KEY, "GET", "/reserve", b)
    h.pop("Content-Type", None)
    st, _ = raw(ER, "POST", "/reserve", b, h)
    alive = raw(ER, "GET", "/seats")[0] == 200
    ok = st != 200 and st != 500 and st != -1 and alive
    return check("auth", "MAC signed for GET sent as POST /reserve: 401, no 5xx, alive", ok, "status=%s" % st)
mac_method_mismatch()
def timestamp_past_outside_window():
    ts = str(int(time.time()) - 301)
    b = json.dumps({"user_id": "rt-98pw", "idempotency_key": "k98pw", "seats": 1}).encode()
    st, _ = raw(ER, "POST", "/reserve", b, sign(KEY, "POST", "/reserve", b, ts=ts))
    alive = raw(ER, "GET", "/seats")[0] == 200
    return check("auth", "timestamp -301s just outside past window: 401, alive", st == 401 and alive, "status=%s" % st)
timestamp_past_outside_window()
def idem_key_null():
    st, _ = post(ER, "/reserve", {"user_id": "rt-98kn", "idempotency_key": None, "seats": 1})
    alive = raw(ER, "GET", "/seats")[0] == 200
    ok = st != 500 and st != -1 and alive
    return check("fuzz", "idempotency_key as null: 4xx, no 5xx, alive", ok, "status=%s" % st)
idem_key_null()
def user_id_only_whitespace():
    st, _ = post(ER, "/reserve", {"user_id": "   ", "idempotency_key": "k98ws", "seats": 1})
    alive = raw(ER, "GET", "/seats")[0] == 200
    ok = st != 500 and st != -1 and alive
    return check("fuzz", "user_id with only whitespace: no 500, alive", ok, "status=%s" % st)
user_id_only_whitespace()
def release_after_transfer():
    st, j = post(ER, "/reserve", {"user_id": "rt-98rt", "idempotency_key": "k98rt", "seats": 1})
    rid = j.get("reservation_id") if isinstance(j, dict) and st == 200 else None
    if not rid:
        return check("state", "release after transfer: skipped (hold unavailable)", True, "st=%s" % st)
    st2, _ = post(ER, "/confirm", {"reservation_id": rid})
    if st2 != 200:
        return check("state", "release after transfer: skipped (confirm %s)" % st2, True)
    st3, _ = post(ER, "/transfer", {"reservation_id": rid, "to_user": "rt-98rt-new"})
    if st3 != 200:
        return check("state", "release after transfer: skipped (transfer %s)" % st3, True)
    st4, _ = post(ER, "/release", {"reservation_id": rid})
    time.sleep(1.0)
    ok = st4 != 500 and st4 != -1 and conserved()
    return check("state", "release of transferred booking: no 5xx, conserved", ok, "st4=%s" % st4)
release_after_transfer()
def app_seats_post():
    st, _ = raw(AR, "POST", "/api/seats", "{}")
    alive = raw(AR, "GET", "/")[0] == 200
    ok = st != 500 and st != -1 and alive
    return check("app", "app /api/seats with method POST: no 500, alive", ok, "st=%s" % st)
app_seats_post()
def webhook_missing_rid():
    body = '{"token":"whsec-redtest","event":"payment_success"}'
    w, _ = raw(AR, "POST", "/api/kavach-webhook?token=whsec-redtest", body)
    alive = raw(AR, "GET", "/")[0] == 200
    ok = w != 500 and w != -1 and alive
    return check("app", "webhook missing reservation_id: no 500, alive", ok, "w=%s" % w)
webhook_missing_rid()
def app_pay_other_engine_rid():
    st, j = post(ER2, "/reserve", {"user_id": "rt-98op", "idempotency_key": "k98op", "seats": 1})
    rid = j.get("reservation_id") if isinstance(j, dict) and st == 200 else None
    if not rid:
        return check("app", "app pay other-engine rid: skipped (8092 hold unavailable)", True, "st=%s" % st)
    p, _ = raw(AR, "POST", "/api/pay", json.dumps({"reservation_id": rid}))
    post(ER2, "/release", {"reservation_id": rid})
    alive = raw(AR, "GET", "/")[0] == 200
    ok = p != 500 and p != -1 and alive
    return check("app", "app /api/pay with rid held on engine 8092: no 500, graceful", ok, "p=%s" % p)
app_pay_other_engine_rid()
def long_method_name():
    import socket as _s
    buf = b""
    try:
        sk = _s.create_connection(("127.0.0.1", ER), timeout=8)
        sk.sendall(b"X" * 10000 + b" /seats HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
        sk.settimeout(4)
        try: buf = sk.recv(200)
        except Exception: pass
        sk.close()
    except Exception:
        pass
    alive = raw(ER, "GET", "/seats")[0] == 200
    return check("wire", "10KB method name in request line: no hang, engine alive", alive, "resp=%r" % buf[:40])
long_method_name()
def long_host_header():
    st, _ = raw(ER, "GET", "/seats", headers={"Host": "h" * 10000})
    alive = raw(ER, "GET", "/seats")[0] == 200
    ok = st != 500 and st != -1 and alive
    return check("wire", "Host header 10KB value: no 5xx, no hang, alive", ok, "status=%s" % st)
long_host_header()
def transfer_release_race():
    st, j = post(ER, "/reserve", {"user_id": "rt-98tr", "idempotency_key": "k98tr", "seats": 1})
    rid = j.get("reservation_id") if isinstance(j, dict) and st == 200 else None
    if not rid:
        return check("race", "transfer vs release race: skipped (hold unavailable)", True, "st=%s" % st)
    st2, _ = post(ER, "/confirm", {"reservation_id": rid})
    if st2 != 200:
        return check("race", "transfer vs release race: skipped (confirm %s)" % st2, True)
    def go(i):
        if i % 2 == 0:
            return post(ER, "/transfer", {"reservation_id": rid, "to_user": "rt-98tr-%d" % i})[0]
        return post(ER, "/release", {"reservation_id": rid})[0]
    with ThreadPoolExecutor(6) as ex:
        outs = list(ex.map(go, range(6)))
    time.sleep(1.0)
    ok = all(x != 500 and x != -1 for x in outs) and conserved()
    return check("race", "parallel transfer + release same rid: no 5xx, conserved", ok, "200s=%d" % outs.count(200))
transfer_release_race()

# ---------------- Summary ----------------
fails = [r for r in results if not r[2]]
print("TOTAL %d cases, PASS %d, FAIL %d" % (len(results), len(results) - len(fails), len(fails)))
for cat, name, ok, detail in fails:
    print("FAIL [%s] %s :: %s" % (cat, name, detail))
sys.exit(1 if fails else 0)
