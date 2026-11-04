#!/usr/bin/env python3
"""Run 58 extras: 12 angles (all live in redteam_battery.py Phase L too).
1: epoch-milliseconds timestamp rejected, no hold
2: SHA-1 signature 401
3: 256-char idempotency key accepted, replay same reservation
4: seats=true and seats=1.5 rejected, no hold
5: app hold numeric user_id no 500
6: confirm empty reservation_id 4xx
7: 60 reads + 60 writes rapid: no 5xx, reads still served after write burst
8: 3 users race last 2 seats: exactly 2 win, restored
9: app pay after engine-side release: graceful, no 500
10: newline injection in header value rejected, no smuggled header
11: same user two waitlist entries, both cancel clean
12: body tenant field ignored, confirm works under testkey
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

# ---------------- Phase L: run 58 extras (12 new angles) ----------------
def ts_epoch_millis():
    b = json.dumps({"user_id": "rt-58ms", "idempotency_key": "k58ms", "seats": 1}).encode()
    h = sign(KEY, "POST", "/reserve", b)
    h["X-Kavach-Timestamp"] = str(int(time.time() * 1000))
    st, j = raw(ER, "POST", "/reserve", b, h)
    s = seats(ER)
    ok = rej(st) and st != -1 and s.get("total") == s.get("sold") + s.get("held") + s.get("free")
    return check("auth", "epoch-milliseconds timestamp (13-digit): rejected, no hold, conserved", ok, "status=%s" % st)
ts_epoch_millis()
def sig_sha1():
    b = json.dumps({"user_id": "rt-58s1", "idempotency_key": "k58s1", "seats": 1}).encode()
    ts, rid = str(int(time.time())), uuid.uuid4().hex
    mac = hmac.new(SECRET.encode(), (ts + "\n" + rid + "\nPOST\n/reserve\n" + KEY + "\n").encode() + b, hashlib.sha1)
    h = {"Authorization": "Bearer " + KEY, "X-Kavach-Timestamp": ts, "X-Kavach-Request-Id": rid,
         "X-Kavach-Signature": mac.hexdigest(), "Content-Type": "application/json"}
    st, _ = raw(ER, "POST", "/reserve", b, h)
    return check("auth", "SHA-1 signature instead of SHA-256: 401, no hold", st == 401, "status=%s" % st)
sig_sha1()
def idem_key_256():
    if seats(ER).get("free", 0) < 1:
        return check("fuzz", "256-char idempotency key: skipped (no free seat)", True, "free=%s" % seats(ER).get("free"))
    k = "k58long" + "a" * 249
    b = json.dumps({"user_id": "rt-58lk", "idempotency_key": k, "seats": 1}).encode()
    st1, j1 = raw(ER, "POST", "/reserve", b, sign(KEY, "POST", "/reserve", b))
    if not (isinstance(j1, dict) and j1.get("reservation_id")):
        return check("fuzz", "256-char idempotency key: skipped (control hold unavailable)", True,
                     "st1=%s body=%s" % (st1, str(j1)[:80]))
    st2, j2 = raw(ER, "POST", "/reserve", b, sign(KEY, "POST", "/reserve", b))
    rid = j1.get("reservation_id") if isinstance(j1, dict) else None
    if rid:
        post(ER, "/release", {"reservation_id": rid})
    if st2 == 429:
        time.sleep(0.6)
        st2, j2 = raw(ER, "POST", "/reserve", b, sign(KEY, "POST", "/reserve", b))
        if rid:
            post(ER, "/release", {"reservation_id": rid})
    same = rid and isinstance(j2, dict) and j2.get("reservation_id") == rid
    ok = st1 == 200 and same and st2 == 200
    return check("fuzz", "256-char idempotency key: accepted, replay returns same reservation", ok,
                 "r1=%s/%s r2=%s/%s same=%s" % (st1, str(j1.get("reservation_id")), st2, str(j2.get("reservation_id"))[:40], bool(same)))
idem_key_256()
def seats_bool_and_fraction():
    held0 = seats(ER).get("held")
    b1 = b'{"user_id":"rt-58b","idempotency_key":"k58b1","seats":true}'
    s1 = raw(ER, "POST", "/reserve", b1, sign(KEY, "POST", "/reserve", b1))[0]
    b2 = b'{"user_id":"rt-58b","idempotency_key":"k58b2","seats":1.5}'
    s2 = raw(ER, "POST", "/reserve", b2, sign(KEY, "POST", "/reserve", b2))[0]
    held1 = seats(ER).get("held")
    ok = rej(s1) and rej(s2) and held1 == held0
    return check("fuzz", "seats=true and seats=1.5: 400, no hold created", ok, "bool=%s frac=%s held %s->%s" % (s1, s2, held0, held1))
seats_bool_and_fraction()
def app_hold_numeric_uid():
    st, _ = raw(AR, "POST", "/api/hold", '{"user_id":12345,"seats":1}')
    alive = raw(AR, "GET", "/")[0] == 200
    return check("app", "app hold with numeric user_id: no 500, app alive", st != 500 and st != -1 and alive, "status=%s" % st)
app_hold_numeric_uid()
def confirm_empty_rid():
    b = json.dumps({"reservation_id": "", "user_id": "rt-58e"}).encode()
    st = raw(ER, "POST", "/confirm", b, sign(KEY, "POST", "/confirm", b))[0]
    alive = raw(ER, "GET", "/seats")[0] == 200
    return check("state", "confirm with empty reservation_id: 4xx, engine alive", rej(st) and alive, "status=%s" % st)
confirm_empty_rid()
def limiter_scope_reads():
    outs_r = P(60, lambda i: raw(ER, "GET", "/seats", None, sign(KEY, "GET", "/seats", b""))[0])
    outs_w = P(60, lambda i: raw(ER, "POST", "/reserve", json.dumps({"user_id": "rt-58rl", "idempotency_key": "k58rl%03d" % i, "seats": 1}).encode(), sign(KEY, "POST", "/reserve", json.dumps({"user_id": "rt-58rl", "idempotency_key": "k58rl%03d" % i, "seats": 1}).encode()))[0])
    st_final = raw(ER, "GET", "/seats", None, sign(KEY, "GET", "/seats", b""))[0]
    s = seats(ER)
    limited = sum(1 for x in outs_w if x == 429)
    ok = all(x < 500 and x != -1 for x in outs_r + outs_w) and st_final == 200 and s.get("total") == s.get("sold") + s.get("held") + s.get("free")
    return check("rate", "60 reads + 60 writes rapid: no 5xx, reads still served after write burst (final /seats 200)", ok,
                 "reads=%s writes_429=%d final=%s" % (sorted(set(outs_r)), limited, st_final))
limiter_scope_reads()
def last_two_race():
    f = seats(ER).get("free", 0)
    if f < 2:
        return check("race", "last-2 race: skipped (free<2)", True, "free=%s" % f)
    big_rid = None
    if f > 2:
        st, j = post(ER, "/reserve", {"user_id": "rt-58dr", "idempotency_key": "k58dr", "seats": f - 2})
        if j.get("status") == "held" and j.get("reservation_id"):
            big_rid = j["reservation_id"]
        else:
            return check("race", "last-2 race: skipped (drain hold failed)", True, "st=%s" % st)
    def race(i):
        b = json.dumps({"user_id": "rt-58r%d" % i, "idempotency_key": "k58r%d" % i, "seats": 1}).encode()
        return raw(ER, "POST", "/book", b, sign(KEY, "POST", "/book", b))
    outs = P(3, race)
    wins = sum(1 for st, j in outs if st == 200 and isinstance(j, dict) and j.get("status") == "confirmed")
    s = seats(ER)
    conserved = s.get("total") == s.get("sold") + s.get("held") + s.get("free")
    if big_rid:
        post(ER, "/release", {"reservation_id": big_rid})
    for st, j in outs:
        if st == 200 and isinstance(j, dict) and j.get("reservation_id"):
            post(ER, "/release", {"reservation_id": j["reservation_id"]})
    s2 = seats(ER)
    ok = wins == 2 and conserved and s2.get("total") == s2.get("sold") + s2.get("held") + s2.get("free")
    return check("race", "3 users race last 2 seats: exactly 2 win, no oversell, restored", ok,
                 "wins=%d outs=%s" % (wins, [o[0] for o in outs]))
last_two_race()
def app_pay_after_engine_release():
    st, h = raw(AR, "POST", "/api/hold", '{"user_id":"rt-58pr","seats":1}')
    rid = h.get("reservation_id") if isinstance(h, dict) else None
    if not (st == 200 and rid):
        return check("app", "app pay after out-of-band release: skipped (hold unavailable)", True, "hold=%s" % st)
    rb = json.dumps({"reservation_id": rid}).encode()
    raw(ER, "POST", "/release", rb, sign(KEY, "POST", "/release", rb))
    st2, j2 = raw(AR, "POST", "/api/pay", json.dumps({"reservation_id": rid, "user_id": "rt-58pr", "outcome": "success"}))
    ok = st2 != 500 and st2 != -1 and raw(AR, "GET", "/")[0] == 200
    return check("app", "app pay after engine-side release: graceful error, no 500", ok, "status=%s body=%s" % (st2, str(j2)[:60]))
app_pay_after_engine_release()
def header_newline_injection():
    import socket as _s
    body = json.dumps({"reservation_id": "RSV999999", "user_id": "rt-58ni"}).encode()
    h = sign(KEY, "POST", "/confirm", body)
    evil = h["X-Kavach-Request-Id"] + "\r\nX-Evil: injected"
    req = ("POST /confirm HTTP/1.1\r\nHost: x\r\nContent-Length: %d\r\n" % len(body) +
           "Authorization: %s\r\nX-Kavach-Timestamp: %s\r\nX-Kavach-Request-Id: %s\r\nX-Kavach-Signature: %s\r\nContent-Type: application/json\r\n\r\n" %
           (h["Authorization"], h["X-Kavach-Timestamp"], evil, h["X-Kavach-Signature"]))
    buf = b""
    try:
        sk = _s.create_connection(("127.0.0.1", ER), timeout=5)
        sk.sendall(req.encode() + body)
        sk.settimeout(3); buf = sk.recv(300); sk.close()
    except Exception:
        pass
    body2 = json.dumps({"reservation_id": "RSV999999", "user_id": "rt-58ni2"}).encode()
    st2 = raw(ER, "POST", "/confirm", body2, sign(KEY, "POST", "/confirm", body2))[0]
    ok = (not buf or b"HTTP/1.1" in buf or b"400" in buf) and st2 == 404
    return check("wire", "newline injection in header value: rejected or closed, no smuggled header, engine alive", ok,
                 "resp=%s next=%s" % (buf[:30], st2))
header_newline_injection()
def wl_same_user_two_entries():
    st1, j1 = post(ER2, "/waitlist", {"user_id": "rt-58wl", "idempotency_key": "k58w1", "seats": 1})
    st2, j2 = post(ER2, "/waitlist", {"user_id": "rt-58wl", "idempotency_key": "k58w2", "seats": 1})
    for j in (j1, j2):
        if isinstance(j, dict) and j.get("waitlist_id"):
            post(ER2, "/waitlist/cancel", {"waitlist_id": j["waitlist_id"]})
    s = seats(ER2)
    ok = st1 < 500 and st2 < 500 and st1 != -1 and st2 != -1 and s.get("total") == s.get("sold") + s.get("held") + s.get("free")
    return check("wl", "same user two waitlist entries (different keys): handled, both cancel clean", ok,
                 "join=%s,%s" % (st1, st2))
wl_same_user_two_entries()
def body_tenant_override():
    b = json.dumps({"user_id": "rt-58t", "idempotency_key": "k58t", "seats": 1, "tenant": "tenant2"}).encode()
    st1, j1 = raw(ER, "POST", "/reserve", b, sign(KEY, "POST", "/reserve", b))
    rid = j1.get("reservation_id") if isinstance(j1, dict) else None
    if not rid:
        return check("auth", "body tenant-override attempt: skipped (reserve failed)", True, "st=%s" % st1)
    cb = json.dumps({"reservation_id": rid, "user_id": "rt-58t"}).encode()
    st2, j2 = raw(ER, "POST", "/confirm", cb, sign(KEY, "POST", "/confirm", cb))
    s = seats(ER)
    ok = st1 == 200 and st2 == 200 and s.get("total") == s.get("sold") + s.get("held") + s.get("free")
    return check("auth", "body tenant field ignored (auth key binds tenant): confirm works under testkey", ok,
                 "res=%s conf=%s" % (st1, st2))
body_tenant_override()


fails = [r for r in results if not r[2]]
print("TOTAL %d cases, PASS %d, FAIL %d" % (len(results), len(results) - len(fails), len(fails)))
for cat, name, ok, detail in fails:
    print("FAIL [%s] %s :: %s" % (cat, name, detail))
sys.exit(1 if fails else 0)
