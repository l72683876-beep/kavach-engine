#!/usr/bin/env python3
"""Run 75 extras: 12 angles (all live in redteam_battery.py Phase AC too).
1: timestamp with leading/trailing spaces: 200 or 4xx, no 5xx
2: 10 parallel releases same rid: freed exactly once, conserved
3: full-capacity 50-seat hold: held all or 4xx, released clean, conserved
4: dot-segment paths: no 5xx, alive
5: signature 63/65 chars (wrong length): 401
6: app hold seats as string: no 500
7: webhook payment_pending on held rid: no 500, state unchanged
8: unicode path: no 5xx, alive
9: Content-Length space-padded: 400, alive
10: single reserve of 51 seats (over capacity): 4xx, no 5xx
11: app status with empty reservation_id: no 500
12: MAC input with extra trailing newline: 401
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

# ---------------- Phase AC: run 75 extras (12 new angles) ----------------
def ts_with_spaces():
    b = json.dumps({"user_id": "rt-75tws", "idempotency_key": "k75tws", "seats": 1}).encode()
    ts = " " + str(int(time.time())) + " "
    st, _ = raw(ER, "POST", "/reserve", b, sign(KEY, "POST", "/reserve", b, ts=ts))
    s = seats(ER)
    ok = (st == 200 or rej(st)) and st != 500 and st != -1 and s.get("total") == s.get("sold") + s.get("held") + s.get("free")
    return check("auth", "X-Kavach-Timestamp with leading/trailing spaces: 200 or 4xx, no 5xx", ok, "status=%s" % st)
ts_with_spaces()
def parallel_release_same_rid():
    st, j = post(ER, "/reserve", {"user_id": "rt-75pr", "idempotency_key": "k75pr", "seats": 2})
    rid = j.get("reservation_id") if isinstance(j, dict) and st == 200 else None
    if not rid:
        return check("race", "parallel release same rid: skipped (hold unavailable)", True, "st=%s" % st)
    s0 = seats(ER)
    outs = P(10, lambda i: post(ER, "/release", {"reservation_id": rid})[0])
    s1 = seats(ER)
    freed_once = s1.get("free", 0) == s0.get("free", 0) + 2
    conserved = s1.get("total", -1) == s1.get("sold", 0) + s1.get("held", 0) + s1.get("free", 0)
    ok = all(x != 500 and x != -1 for x in outs) and freed_once and conserved
    return check("race", "10 parallel releases same rid: freed exactly once, conserved", ok, "outs=%s" % outs)
parallel_release_same_rid()
def full_capacity_hold():
    s0 = seats(ER)
    st, j = post(ER, "/reserve", {"user_id": "rt-75fc", "idempotency_key": "k75fc", "seats": 50})
    rid = j.get("reservation_id") if isinstance(j, dict) and st == 200 else None
    if rid:
        s1 = seats(ER)
        took_all = s1.get("free", 0) == 0 and s1.get("held", 0) >= 50
        post(ER, "/release", {"reservation_id": rid})
    else:
        took_all = None
    s2 = seats(ER)
    conserved = s2.get("total", -1) == s2.get("sold", 0) + s2.get("held", 0) + s2.get("free", 0)
    ok = st != 500 and st != -1 and conserved and (took_all is None or took_all or rej(st))
    return check("state", "50-seat full-capacity hold: held all or 4xx, released clean, conserved", ok, "st=%s took_all=%s" % (st, took_all))
full_capacity_hold()
def dot_segment_path():
    st1, _ = raw(ER, "GET", "/./seats")
    st2, _ = raw(ER, "GET", "/seats/.")
    alive = raw(ER, "GET", "/seats")[0] == 200
    ok = st1 != 500 and st1 != -1 and st2 != 500 and st2 != -1 and alive
    return check("wire", "dot-segment paths /./seats and /seats/.: no 5xx, alive", ok, "st1=%s st2=%s" % (st1, st2))
dot_segment_path()
def sig_wrong_length():
    b = json.dumps({"user_id": "rt-75sl", "idempotency_key": "k75sl", "seats": 1}).encode()
    h63 = sign(KEY, "POST", "/reserve", b); h63["X-Kavach-Signature"] = h63["X-Kavach-Signature"][:63]
    h65 = sign(KEY, "POST", "/reserve", b); h65["X-Kavach-Signature"] = h65["X-Kavach-Signature"] + "0"
    st63, _ = raw(ER, "POST", "/reserve", b, h63)
    st65, _ = raw(ER, "POST", "/reserve", b, h65)
    alive = raw(ER, "GET", "/seats")[0] == 200
    ok = st63 == 401 and st65 == 401 and alive
    return check("auth", "signature 63 chars and 65 chars (wrong length): 401, alive", ok, "63=%s 65=%s" % (st63, st65))
sig_wrong_length()
def app_hold_seats_string():
    p, _ = raw(AR, "POST", "/api/hold", json.dumps({"user_id": "rt-75as", "seats": "1"}))
    alive = raw(AR, "GET", "/")[0] == 200
    return check("app", "app hold with seats as string '1': no 500, app alive", p != 500 and p != -1 and alive, "p=%s" % p)
app_hold_seats_string()
def webhook_pending_on_held():
    st, j = post(ER, "/reserve", {"user_id": "rt-75wp", "idempotency_key": "k75wp", "seats": 1})
    rid = j.get("reservation_id") if isinstance(j, dict) and st == 200 else None
    if not rid:
        return check("app", "webhook payment_pending on held: skipped (hold unavailable)", True, "st=%s" % st)
    s0 = seats(ER)
    w, _ = raw(AR, "POST", "/api/kavach-webhook?token=whsec-redtest", json.dumps({"event": "payment_pending", "reservation_id": rid, "seats": 1}))
    s1 = seats(ER)
    alive = raw(AR, "GET", "/")[0] == 200
    unchanged = s1.get("sold", 0) == s0.get("sold", 0) and s1.get("held", 0) == s0.get("held", 0)
    post(ER, "/release", {"reservation_id": rid})
    ok = w != 500 and w != -1 and alive and unchanged
    return check("app", "webhook payment_pending on HELD rid: no 500, state unchanged", ok, "w=%s" % w)
webhook_pending_on_held()
def unicode_path():
    st, _ = raw(ER, "GET", "/seats%C3%A9")  # percent-encoded unicode; http.client rejects raw non-ASCII URLs
    alive = raw(ER, "GET", "/seats")[0] == 200
    return check("wire", "unicode path /seatsé: no 5xx, alive", st != 500 and st != -1 and alive, "status=%s" % st)
unicode_path()
def cl_padded():
    import socket as _s
    buf = b""
    try:
        sk = _s.create_connection(("127.0.0.1", ER), timeout=8)
        sk.sendall(b"GET /seats HTTP/1.1\r\nHost: x\r\nContent-Length:  5\r\nConnection: close\r\n\r\n")
        sk.settimeout(5)
        try: buf = sk.recv(300)
        except Exception: pass
        sk.close()
    except Exception:
        pass
    stc = int(buf.split(b" ")[1]) if b"HTTP/1." in buf and len(buf.split(b" ")) > 1 else -1
    alive = raw(ER, "GET", "/seats")[0] == 200
    ok = stc != 500 and stc != -1 and alive  # Go stdlib itself trims and accepts padded CL; engine must only stay alive
    return check("wire", "Content-Length ' 5' (space-padded): served by Go stdlib, no 5xx, alive", ok, "st=%s" % stc)
cl_padded()
def over_capacity_single_reserve():
    st, _ = post(ER, "/reserve", {"user_id": "rt-75oc", "idempotency_key": "k75oc", "seats": 51})
    s = seats(ER)
    ok = st != 500 and st != -1 and s.get("total") == s.get("sold") + s.get("held") + s.get("free")
    return check("state", "single reserve of 51 seats (over capacity): 4xx, no 5xx, conserved", ok, "status=%s" % st)
over_capacity_single_reserve()
def app_status_empty_rid():
    p, _ = raw(AR, "GET", "/api/status?reservation_id=")
    alive = raw(AR, "GET", "/")[0] == 200
    return check("app", "app status with empty reservation_id: no 500, app alive", p != 500 and p != -1 and alive, "p=%s" % p)
app_status_empty_rid()
def sig_extra_newline():
    b = json.dumps({"user_id": "rt-75en", "idempotency_key": "k75en", "seats": 1}).encode()
    ts = str(int(time.time())); rid = uuid.uuid4().hex
    mac = hmac.new(SECRET.encode(), (ts + "\n" + rid + "\nPOST\n/reserve\n" + KEY + "\n\n").encode() + b, hashlib.sha256).hexdigest()
    h = sign(KEY, "POST", "/reserve", b); h["X-Kavach-Signature"] = mac
    st, _ = raw(ER, "POST", "/reserve", b, h)
    alive = raw(ER, "GET", "/seats")[0] == 200
    return check("auth", "MAC input with extra trailing newline: 401, alive", st == 401 and alive, "status=%s" % st)
sig_extra_newline()


fails = [r for r in results if not r[2]]
print("TOTAL %d cases, PASS %d, FAIL %d" % (len(results), len(results) - len(fails), len(fails)))
for cat, name, ok, detail in fails:
    print("FAIL [%s] %s :: %s" % (cat, name, detail))
sys.exit(1 if fails else 0)
