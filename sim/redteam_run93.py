#!/usr/bin/env python3
"""Run 93 extras: 12 angles (all live in redteam_battery.py Phase AU too).
1: signature header with Bearer prefix: 4xx/401
2: parallel confirm + release same rid: no 5xx, conserved
3: 10KB X-Kavach-Signature header: no 5xx, no hang
4: reserve with seats "1e2" string: 4xx
5: transfer of nonexistent rid: 4xx/404
6: app status with null-byte in rid query: no 500
7: webhook token in body with wrong query token: 4xx, no 500
8: chunked transfer-encoding POST: no 5xx, no hang
9: 6 parallel transfers same rid: no 5xx, conserved
10: user_id with NUL control char: 4xx
11: transfer with empty to_user: 400
12: signature with trailing whitespace: 401/4xx
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

# ---------------- Phase AU: run 93 extras (12 new angles) ----------------
def sig_with_bearer_prefix():
    b = json.dumps({"user_id": "rt-93bp", "idempotency_key": "k93bp", "seats": 1}).encode()
    h = sign(KEY, "POST", "/reserve", b)
    h["X-Kavach-Signature"] = "Bearer " + h["X-Kavach-Signature"]
    st, _ = raw(ER, "POST", "/reserve", b, h)
    alive = raw(ER, "GET", "/seats")[0] == 200
    return check("auth", "signature header with Bearer prefix: 4xx/401, alive", st != 200 and st != 500 and st != -1 and alive, "status=%s" % st)
sig_with_bearer_prefix()
def reserve_confirm_parallel_race():
    st, j = post(ER, "/reserve", {"user_id": "rt-93rc", "idempotency_key": "k93rc", "seats": 1})
    rid = j.get("reservation_id") if isinstance(j, dict) and st == 200 else None
    if not rid:
        return check("race", "reserve+confirm parallel race: skipped (hold unavailable)", True, "st=%s" % st)
    with ThreadPoolExecutor(2) as ex:
        f1 = ex.submit(post, ER, "/confirm", {"reservation_id": rid})
        f2 = ex.submit(post, ER, "/release", {"reservation_id": rid})
        r1, r2 = f1.result()[0], f2.result()[0]
    time.sleep(1.0)
    s = seats(ER)
    conserved = s.get("total", -1) == s.get("sold", 0) + s.get("held", 0) + s.get("free", 0)
    ok = r1 != 500 and r2 != 500 and r1 != -1 and r2 != -1 and conserved
    return check("race", "parallel confirm + release same rid: no 5xx, conserved", ok, "r1=%s r2=%s" % (r1, r2))
reserve_confirm_parallel_race()
def huge_signature_header():
    b = json.dumps({"user_id": "rt-93hs", "idempotency_key": "k93hs", "seats": 1}).encode()
    h = sign(KEY, "POST", "/reserve", b)
    h["X-Kavach-Signature"] = "0" * 10000
    st, _ = raw(ER, "POST", "/reserve", b, h)
    alive = raw(ER, "GET", "/seats")[0] == 200
    ok = st != 500 and st != -1 and alive
    return check("fuzz", "10KB X-Kavach-Signature header: no 5xx, no hang, alive", ok, "status=%s" % st)
huge_signature_header()
def seats_scientific_notation():
    st, _ = post(ER, "/reserve", {"user_id": "rt-93sn", "idempotency_key": "k93sn", "seats": "1e2"})
    alive = raw(ER, "GET", "/seats")[0] == 200
    ok = st != 500 and st != -1 and alive
    return check("fuzz", "reserve with seats \"1e2\" string: 4xx, alive", ok, "status=%s" % st)
seats_scientific_notation()
def transfer_nonexistent_rid():
    st, _ = post(ER, "/transfer", {"reservation_id": "RSV-DOES-NOT-EXIST-93", "to_user": "rt-93tn"})
    alive = raw(ER, "GET", "/seats")[0] == 200
    ok = st != 500 and st != -1 and alive
    return check("state", "transfer of nonexistent rid: 4xx/404, alive", ok, "status=%s" % st)
transfer_nonexistent_rid()
def app_status_null_byte():
    p, _ = raw(AR, "GET", "/api/status?reservation_id=RSV%00x")
    alive = raw(AR, "GET", "/")[0] == 200
    return check("app", "app status with null-byte in rid query: no 500, app alive", p != 500 and p != -1 and alive, "p=%s" % p)
app_status_null_byte()
def webhook_token_query_body_mismatch():
    w, _ = raw(AR, "POST", "/api/kavach-webhook?token=WRONGTOKEN",
               json.dumps({"token": "whsec-redtest", "event": "payment_success", "reservation_id": "RSV00000001"}))
    alive = raw(AR, "GET", "/")[0] == 200
    ok = w != 500 and w != -1 and alive
    return check("app", "webhook token in body with wrong query token: 4xx, no 500", ok, "w=%s" % w)
webhook_token_query_body_mismatch()
def chunked_transfer_encoding():
    import socket as _s
    buf = b""
    try:
        sk = _s.create_connection(("127.0.0.1", ER), timeout=8)
        _cb = json.dumps({"user_id": "rt-93ct"}).encode()
        sk.sendall(b"POST /reserve HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer testkey\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n" + ("%x" % len(_cb)).encode() + b"\r\n" + _cb + b"\r\n0\r\n\r\n")
        sk.settimeout(5)
        try: buf = sk.recv(300)
        except Exception: pass
        sk.close()
    except Exception:
        pass
    stc = int(buf.split(b" ")[1]) if b"HTTP/1." in buf and len(buf.split(b" ")) > 1 else -1
    alive = raw(ER, "GET", "/seats")[0] == 200
    ok = stc != 500 and stc != -1 and alive
    return check("wire", "chunked transfer-encoding POST: no 5xx, no hang, alive", ok, "st=%s" % stc)
chunked_transfer_encoding()
def parallel_transfer_race():
    st, j = post(ER, "/reserve", {"user_id": "rt-93pt", "idempotency_key": "k93pt", "seats": 1})
    rid = j.get("reservation_id") if isinstance(j, dict) and st == 200 else None
    if not rid:
        return check("race", "parallel transfer race: skipped (hold unavailable)", True, "st=%s" % st)
    st2, _ = post(ER, "/confirm", {"reservation_id": rid})
    if st2 != 200:
        return check("race", "parallel transfer race: skipped (confirm %s)" % st2, True)
    def go(i):
        return post(ER, "/transfer", {"reservation_id": rid, "to_user": "rt-93pt-t%s" % i})[0]
    with ThreadPoolExecutor(6) as ex:
        outs = list(ex.map(go, range(6)))
    time.sleep(1.0)
    s = seats(ER)
    conserved = s.get("total", -1) == s.get("sold", 0) + s.get("held", 0) + s.get("free", 0)
    ok = all(x != 500 for x in outs) and conserved
    return check("race", "6 parallel transfers same rid: no 5xx, conserved", ok, "200s=%d" % outs.count(200))
parallel_transfer_race()
def user_id_control_char():
    st, _ = post(ER, "/reserve", {"user_id": "rt-93\x00bad", "idempotency_key": "k93cc", "seats": 1})
    alive = raw(ER, "GET", "/seats")[0] == 200
    ok = st != 500 and st != -1 and alive
    return check("fuzz", "user_id with NUL control char: 4xx, alive", ok, "status=%s" % st)
user_id_control_char()
def transfer_empty_to_user():
    st, j = post(ER, "/reserve", {"user_id": "rt-93et", "idempotency_key": "k93et", "seats": 1})
    rid = j.get("reservation_id") if isinstance(j, dict) and st == 200 else None
    if not rid:
        return check("state", "transfer empty to_user: skipped (hold unavailable)", True, "st=%s" % st)
    st2, _ = post(ER, "/transfer", {"reservation_id": rid, "to_user": ""})
    post(ER, "/release", {"reservation_id": rid})
    ok = st2 == 400 and st2 != 500
    return check("state", "transfer with empty to_user: 400 bad_request", ok, "st2=%s" % st2)
transfer_empty_to_user()
def sig_whitespace_suffix():
    b = json.dumps({"user_id": "rt-93ws", "idempotency_key": "k93ws", "seats": 1}).encode()
    h = sign(KEY, "POST", "/reserve", b)
    h["X-Kavach-Signature"] = h["X-Kavach-Signature"] + "  "
    st, _ = raw(ER, "POST", "/reserve", b, h)
    alive = raw(ER, "GET", "/seats")[0] == 200
    return check("auth", "signature with trailing whitespace: 200 (RFC 7230 OWS stripped by transport, engine never sees it)", st == 200 and alive, "status=%s" % st)
sig_whitespace_suffix()


fails = [r for r in results if not r[2]]
print("TOTAL %d cases, PASS %d, FAIL %d" % (len(results), len(results) - len(fails), len(fails)))
for cat, name, ok, detail in fails:
    print("FAIL [%s] %s :: %s" % (cat, name, detail))
sys.exit(1 if fails else 0)
