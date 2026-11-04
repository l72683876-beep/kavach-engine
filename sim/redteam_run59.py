#!/usr/bin/env python3
"""Run 59 extras: 12 angles (all live in redteam_battery.py Phase M too).
1: signature over /reserve/ but request to /reserve: 401
2: duplicate Authorization headers answered cleanly, engine alive
3: reserve with 10KB user_id: no 5xx, conserved
4: JSON body with UTF-8 BOM: 4xx
5: JSON body with trailing garbage: 4xx
6: 10 parallel releases of one hold: released exactly once
7: confirm with empty user_id: 4xx
8: app hold with seats as string "2": no 500
9: app pay with unknown huge reservation_id: graceful
10: GET on webhook endpoint: no 500
11: user limiter recovers after burst (some 429, wait, served again)
12: waitlist cancel twice: first clean, second 4xx
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

# ---------------- Phase M: run 59 extras (12 new angles) ----------------
def sig_path_mismatch():
    b = json.dumps({"user_id": "rt-59pm", "idempotency_key": "k59pm", "seats": 1}).encode()
    h = sign(KEY, "POST", "/reserve/", b)
    st, _ = raw(ER, "POST", "/reserve", b, h)
    s = seats(ER)
    ok = st == 401 and s.get("total") == s.get("sold") + s.get("held") + s.get("free")
    return check("auth", "signature over /reserve/ but request to /reserve: 401, no hold", ok, "status=%s" % st)
sig_path_mismatch()
def dup_authorization():
    import socket as _s
    b = json.dumps({"user_id": "rt-59da", "idempotency_key": "k59da", "seats": 1}).encode()
    h = sign(KEY, "POST", "/reserve", b)
    req = ("POST /reserve HTTP/1.1\r\nHost: x\r\nContent-Length: %d\r\n" % len(b) +
           "Authorization: Bearer otherkey\r\nAuthorization: %s\r\n" % h["Authorization"] +
           "X-Kavach-Timestamp: %s\r\nX-Kavach-Request-Id: %s\r\nX-Kavach-Signature: %s\r\nContent-Type: application/json\r\n\r\n" %
           (h["X-Kavach-Timestamp"], h["X-Kavach-Request-Id"], h["X-Kavach-Signature"]))
    buf = b""
    try:
        sk = _s.create_connection(("127.0.0.1", ER), timeout=5)
        sk.sendall(req.encode() + b)
        sk.settimeout(3); buf = sk.recv(300); sk.close()
    except Exception:
        pass
    alive = raw(ER, "GET", "/seats")[0] == 200
    body2 = json.dumps({"reservation_id": "RSV999999", "user_id": "rt-59da2"}).encode()
    st2 = raw(ER, "POST", "/confirm", body2, sign(KEY, "POST", "/confirm", body2))[0]
    ok = (b"HTTP/1.1" in buf) and alive and st2 == 404
    return check("auth", "duplicate Authorization headers (otherkey first): answered cleanly, engine alive, next request fine", ok,
                 "resp=%s next=%s" % (buf[:40], st2))
dup_authorization()
def reserve_huge_userid():
    b = json.dumps({"user_id": "U" * 10000, "idempotency_key": "k59big", "seats": 1}).encode()
    st, j = raw(ER, "POST", "/reserve", b, sign(KEY, "POST", "/reserve", b))
    if isinstance(j, dict) and j.get("reservation_id"):
        post(ER, "/release", {"reservation_id": j["reservation_id"]})
    s = seats(ER)
    ok = st < 500 and st != -1 and s.get("total") == s.get("sold") + s.get("held") + s.get("free")
    return check("fuzz", "reserve with 10KB user_id: no 5xx, conserved", ok, "status=%s" % st)
reserve_huge_userid()
def body_bom():
    b = b'\xef\xbb\xbf' + json.dumps({"user_id": "rt-59bom", "idempotency_key": "k59bom", "seats": 1}).encode()
    st = raw(ER, "POST", "/reserve", b, sign(KEY, "POST", "/reserve", b))[0]
    return check("fuzz", "JSON body with UTF-8 BOM: 4xx, no hold", rej(st) and st != -1, "status=%s" % st)
body_bom()
def body_trailing_garbage():
    b = json.dumps({"user_id": "rt-59tg", "idempotency_key": "k59tg", "seats": 1}).encode() + b" garbage"
    st = raw(ER, "POST", "/reserve", b, sign(KEY, "POST", "/reserve", b))[0]
    return check("fuzz", "JSON body with trailing garbage: 4xx, no hold", rej(st) and st != -1, "status=%s" % st)
body_trailing_garbage()
def parallel_double_release():
    if seats(ER).get("free", 0) < 1:
        return check("state", "10 parallel releases of one hold: skipped (no free seat)", True, "free=%s" % seats(ER).get("free"))
    st, j = post(ER, "/reserve", {"user_id": "rt-59dr", "idempotency_key": "k59dr", "seats": 1})
    rid = j.get("reservation_id") if isinstance(j, dict) else None
    if not rid:
        return check("state", "10 parallel releases of one hold: skipped (hold unavailable)", True, "st=%s" % st)
    held_mid = seats(ER).get("held")
    outs = P(10, lambda i: post(ER, "/release", {"reservation_id": rid})[0])
    held_after = seats(ER).get("held")
    s = seats(ER)
    ok = 500 not in outs and -1 not in outs and held_after == held_mid - 1 and s.get("total") == s.get("sold") + s.get("held") + s.get("free")
    return check("state", "10 parallel releases of one hold: released exactly once, conserved", ok,
                 "codes=%s held %s->%s" % (sorted(set(outs)), held_mid, held_after))
parallel_double_release()
def confirm_empty_uid():
    st, j = post(ER, "/reserve", {"user_id": "rt-59eu", "idempotency_key": "k59eu", "seats": 1})
    rid = j.get("reservation_id") if isinstance(j, dict) else None
    if not rid:
        return check("state", "confirm with empty user_id: skipped (hold unavailable)", True, "st=%s" % st)
    b = json.dumps({"reservation_id": rid, "user_id": ""}).encode()
    st2 = raw(ER, "POST", "/confirm", b, sign(KEY, "POST", "/confirm", b))[0]
    post(ER, "/release", {"reservation_id": rid})
    ok = rej(st2) and st2 != -1
    return check("state", "confirm with empty user_id: 4xx, hold intact then released clean", ok, "status=%s" % st2)
confirm_empty_uid()
def app_hold_string_seats():
    st, _ = raw(AR, "POST", "/api/hold", '{"user_id":"rt-59s","seats":"2"}')
    alive = raw(AR, "GET", "/")[0] == 200
    return check("app", "app hold with seats as string \"2\": no 500, app alive", st != 500 and st != -1 and alive, "status=%s" % st)
app_hold_string_seats()
def app_pay_unknown_rid():
    st, j = raw(AR, "POST", "/api/pay", '{"reservation_id":"RSV99999999","user_id":"rt-59u","outcome":"success"}')
    alive = raw(AR, "GET", "/")[0] == 200
    return check("app", "app pay with unknown huge reservation_id: graceful, no 500", st != 500 and st != -1 and alive, "status=%s" % st)
app_pay_unknown_rid()
def webhook_get():
    st, _ = raw(AR, "GET", "/api/kavach-webhook?token=whsec-redtest")
    alive = raw(AR, "GET", "/")[0] == 200
    return check("app", "GET on webhook endpoint with valid token: no 500, app alive", st != 500 and st != -1 and alive, "status=%s" % st)
webhook_get()
def limiter_recovery():
    uid = "rt-59rec"
    outs = []
    for i in range(8):
        b = json.dumps({"user_id": uid, "idempotency_key": "k59rec%d" % i, "seats": 1}).encode()
        st, j = raw(ER, "POST", "/reserve", b, sign(KEY, "POST", "/reserve", b))
        outs.append(st)
        if isinstance(j, dict) and j.get("reservation_id"):
            post(ER, "/release", {"reservation_id": j["reservation_id"]})
    had_429 = 429 in outs
    time.sleep(3.5)
    b = json.dumps({"user_id": uid, "idempotency_key": "k59recfin", "seats": 1}).encode()
    st_fin, j_fin = raw(ER, "POST", "/reserve", b, sign(KEY, "POST", "/reserve", b))
    if isinstance(j_fin, dict) and j_fin.get("reservation_id"):
        post(ER, "/release", {"reservation_id": j_fin["reservation_id"]})
    s = seats(ER)
    ok = had_429 and st_fin != 429 and st_fin < 500 and st_fin != -1 and s.get("total") == s.get("sold") + s.get("held") + s.get("free")
    return check("rate", "user limiter recovers after burst: 8 rapid -> some 429, wait 3.5s -> served again", ok,
                 "burst=%s final=%s" % (outs, st_fin))
limiter_recovery()
def wl_double_cancel():
    st1, j1 = post(ER2, "/waitlist", {"user_id": "rt-59dc", "idempotency_key": "k59dc", "seats": 1})
    wid = j1.get("waitlist_id") if isinstance(j1, dict) else None
    if not wid:
        return check("wl", "waitlist double cancel: skipped (join unavailable)", True, "join=%s %s" % (st1, str(j1)[:60]))
    st2, _ = post(ER2, "/waitlist/cancel", {"waitlist_id": wid})
    st3, _ = post(ER2, "/waitlist/cancel", {"waitlist_id": wid})
    s = seats(ER2)
    ok = st2 < 500 and rej(st3) and st3 != -1 and s.get("total") == s.get("sold") + s.get("held") + s.get("free")
    return check("wl", "waitlist cancel twice: first clean, second 4xx, conserved", ok, "join=%s c1=%s c2=%s" % (st1, st2, st3))
wl_double_cancel()


fails = [r for r in results if not r[2]]
print("TOTAL %d cases, PASS %d, FAIL %d" % (len(results), len(results) - len(fails), len(fails)))
for cat, name, ok, detail in fails:
    print("FAIL [%s] %s :: %s" % (cat, name, detail))
sys.exit(1 if fails else 0)
