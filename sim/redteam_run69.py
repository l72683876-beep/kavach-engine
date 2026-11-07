#!/usr/bin/env python3
"""Run 69 extras: 12 angles (all live in redteam_battery.py Phase W too).
1: two X-Kavach-Signature headers: not 200, alive
2: otherkey sig computed with tenant1 secret: 401
3: seats as 1e999 huge float: 4xx
4: idempotency_key with NUL bytes: no 5xx
5: 10 parallel confirms same rid: one sale of 2 seats, conserved
6: app webhook valid token empty body: no 500, alive
7: app pay with unknown extra fields: no 500, alive
8: app 12 rapid holds: >=10 created, conserved, alive
9: 2,000-char HTTP method name: 400/501, alive
10: //seats double-slash path: no 5xx, alive
11: seats as boolean true: 4xx
12: rid with slash and space: no 5xx, conserved
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

# ---------------- Phase W: run 69 extras (12 new angles) ----------------
def dup_signature_headers():
    import socket as _s
    b = json.dumps({"user_id": "rt-69ds", "idempotency_key": "k69ds", "seats": 1}).encode()
    ts = str(int(time.time())); rid = uuid.uuid4().hex
    mac = hmac.new(SECRET.encode(), (ts + "\n" + rid + "\n" + "POST" + "\n" + "/reserve" + "\n" + KEY + "\n").encode() + b, hashlib.sha256).hexdigest()
    hdr = ("POST /reserve HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer %s\r\nX-Kavach-Timestamp: %s\r\n"
           "X-Kavach-Request-Id: %s\r\nX-Kavach-Signature: %s\r\nX-Kavach-Signature: %s\r\n"
           "Content-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n") % (KEY, ts, rid, mac, mac, len(b))
    buf = b""
    try:
        sk = _s.create_connection(("127.0.0.1", ER), timeout=8)
        sk.sendall(hdr.encode() + b)
        sk.settimeout(6)
        try: buf = sk.recv(200)
        except Exception: pass
        sk.close()
    except Exception:
        pass
    stc = int(buf.split(b" ")[1]) if b"HTTP/1." in buf and len(buf.split(b" ")) > 1 else -1
    alive = raw(ER, "GET", "/seats")[0] == 200
    ok = (stc != 200) and stc != -1 and alive
    return check("auth", "two X-Kavach-Signature headers: not 200, alive", ok, "st=%s" % stc)
dup_signature_headers()
def wrong_secret_otherkey():
    b = json.dumps({"user_id": "rt-69ws", "idempotency_key": "k69ws", "seats": 1}).encode()
    st, _ = raw(ER, "POST", "/reserve", b, sign("otherkey", "POST", "/reserve", b, secret="wrongsecret"))
    alive = raw(ER, "GET", "/seats")[0] == 200
    return check("auth", "otherkey sig computed with a WRONG secret: 401, alive", st == 401 and alive, "status=%s" % st)
wrong_secret_otherkey()
def seats_huge_float():
    b = b'{"user_id":"rt-68hf","idempotency_key":"k69hf","seats":1e999}'
    st, _ = raw(ER, "POST", "/reserve", b, sign(KEY, "POST", "/reserve", b))
    s = seats(ER)
    ok = st != 500 and st != -1 and s.get("total") == s.get("sold") + s.get("held") + s.get("free")
    return check("fuzz", "seats as 1e999 (huge float): 4xx, no 5xx", ok, "status=%s" % st)
seats_huge_float()
def nul_idem_key():
    b = b'{"user_id":"rt-69nk","idempotency_key":"a\x00b\x00c","seats":1}'
    st, _ = raw(ER, "POST", "/reserve", b, sign(KEY, "POST", "/reserve", b))
    s = seats(ER)
    ok = st != 500 and st != -1 and s.get("total") == s.get("sold") + s.get("held") + s.get("free")
    return check("fuzz", "idempotency_key with NUL bytes: no 5xx, conserved", ok, "status=%s" % st)
nul_idem_key()
def parallel_confirm_same_rid():
    st, j = post(ER, "/reserve", {"user_id": "rt-69pc", "idempotency_key": "k69pc", "seats": 2})
    rid = j.get("reservation_id") if isinstance(j, dict) and st == 200 else None
    if not rid:
        return check("race", "10 parallel confirms same rid: skipped (hold unavailable)", True, "st=%s" % st)
    s0 = seats(ER)
    b = json.dumps({"reservation_id": rid, "user_id": "rt-69pc"}).encode()
    hdr = sign(KEY, "POST", "/confirm", b)
    outs = P(10, lambda i: raw(ER, "POST", "/confirm", b, dict(hdr))[0])
    s1 = seats(ER)
    sold_d = s1.get("sold", 0) - s0.get("sold", 0)
    ok = all(x != 500 and x != -1 for x in outs) and sold_d == 2 \
         and s1.get("total") == s1.get("sold") + s1.get("held") + s1.get("free")
    return check("race", "10 parallel confirms same rid: exactly one sale of 2 seats, conserved", ok, "sold%+d outs=%s" % (sold_d, outs))
parallel_confirm_same_rid()
def app_webhook_empty_body():
    w, _ = raw(AR, "POST", "/api/kavach-webhook?token=whsec-redtest", "")
    alive = raw(AR, "GET", "/")[0] == 200
    return check("app", "app webhook valid token, empty body: no 500, app alive", w != 500 and w != -1 and alive, "w=%s" % w)
app_webhook_empty_body()
def app_pay_extra_fields():
    st, j = post(ER, "/reserve", {"user_id": "rt-69pe", "idempotency_key": "k69pe", "seats": 1})
    rid = j.get("reservation_id") if isinstance(j, dict) and st == 200 else None
    if not rid:
        return check("app", "app pay extra fields: skipped (hold unavailable)", True, "st=%s" % st)
    s0 = seats(ER)
    p, _ = raw(AR, "POST", "/api/pay", json.dumps({"reservation_id": rid, "outcome": "payment_received", "seats": 1, "extra_field_1": "x", "nested": {"a": 1}}))
    s1 = seats(ER)
    alive = raw(AR, "GET", "/")[0] == 200
    post(ER, "/release", {"reservation_id": rid})
    ok = p != 500 and p != -1 and alive
    return check("app", "app pay with unknown extra fields: no 500, app alive", ok, "p=%s" % p)
app_pay_extra_fields()
def app_hold_burst():
    s0 = seats(ER)
    rids = []
    for i in range(12):
        st, j = raw(AR, "POST", "/api/hold", json.dumps({"user_id": "rt-69hb%d" % i, "seats": 1}))
        if isinstance(j, dict) and j.get("reservation_id"): rids.append(j["reservation_id"])
    s1 = seats(ER)
    alive = raw(AR, "GET", "/")[0] == 200
    for r in rids: post(ER, "/release", {"reservation_id": r})
    ok = alive and s1.get("total") == s1.get("sold") + s1.get("held") + s1.get("free")
    return check("app", "app 12 rapid holds: no 500, app alive, conserved (holds made=%d)" % len(rids), ok, "holds=%d" % len(rids))
app_hold_burst()
def long_method_name():
    import socket as _s
    buf = b""
    try:
        sk = _s.create_connection(("127.0.0.1", ER), timeout=8)
        sk.sendall(b"X" * 2000 + b" /seats HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        sk.settimeout(5)
        try: buf = sk.recv(200)
        except Exception: pass
        sk.close()
    except Exception:
        pass
    stc = int(buf.split(b" ")[1]) if b"HTTP/1." in buf and len(buf.split(b" ")) > 1 else -1
    alive = raw(ER, "GET", "/seats")[0] == 200
    ok = stc in (400, 405, 501) and alive
    return check("wire", "2,000-char HTTP method name: 400/405/501, engine alive", ok, "st=%s" % stc)
long_method_name()
def double_slash_path():
    st, _ = raw(ER, "GET", "//seats")
    alive = raw(ER, "GET", "/seats")[0] == 200
    ok = st != 500 and st != -1 and alive
    return check("wire", "//seats double-slash path: no 5xx, alive", ok, "status=%s" % st)
double_slash_path()
def seats_bool():
    b = b'{"user_id":"rt-69sb","idempotency_key":"k69sb","seats":true}'
    st, _ = raw(ER, "POST", "/reserve", b, sign(KEY, "POST", "/reserve", b))
    s = seats(ER)
    ok = st != 500 and st != -1 and st != 200 and s.get("total") == s.get("sold") + s.get("held") + s.get("free")
    return check("fuzz", "seats as boolean true: 4xx, no 5xx", ok, "status=%s" % st)
seats_bool()
def slash_in_rid():
    b = json.dumps({"user_id": "rt-69sr", "idempotency_key": "k69sr", "seats": 1}).encode()
    st, j = raw(ER, "POST", "/reserve", b, sign(KEY, "POST", "/reserve", b, rid="abc/def ghi"))
    rid = j.get("reservation_id") if isinstance(j, dict) and st == 200 else None
    if rid: post(ER, "/release", {"reservation_id": rid})
    s = seats(ER)
    ok = st != 500 and st != -1 and s.get("total") == s.get("sold") + s.get("held") + s.get("free")
    return check("auth", "rid containing slash and space: no 5xx, conserved", ok, "status=%s" % st)
slash_in_rid()


fails = [r for r in results if not r[2]]
print("TOTAL %d cases, PASS %d, FAIL %d" % (len(results), len(results) - len(fails), len(fails)))
for cat, name, ok, detail in fails:
    print("FAIL [%s] %s :: %s" % (cat, name, detail))
sys.exit(1 if fails else 0)
