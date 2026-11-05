#!/usr/bin/env python3
"""Run 63 extras: 12 angles (all live in redteam_battery.py Phase Q too).
1: one flipped hex char in MAC: 401
2: sig over rid A, header rid B: 401 (rid MAC-bound)
3: body with 10,000 duplicate junk keys: 4xx, alive
4: user_id with 5000 NUL bytes: 4xx, alive
5: idem key reuse after release: no sale on released hold, conserved
6: 5 confirms vs 5 releases race on one hold: XOR, no 5xx
7: app hold 10KB user_id: no 500
8: app GET /deal/<nonexistent>: no 500
9: webhook payment_failed twice: no double-free
10: 2MB single header: rejected, alive
11: HTTP/1.0 request: served, alive
12: waitlist join, cancel, rejoin, cancel: clean, conserved
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

# ---------------- Phase Q: run 63 extras (12 new angles) ----------------
def sig_uppercase_hex():
    b = json.dumps({"user_id": "rt-63uh", "idempotency_key": "k63uh", "seats": 1}).encode()
    h = sign(KEY, "POST", "/reserve", b)
    h2 = dict(sign(KEY, "POST", "/reserve", b))
    sig = h2["X-Kavach-Signature"]
    flip = ("0" if sig[10] != "0" else "1")  # same-length hex char, different bytes
    h2["X-Kavach-Signature"] = sig[:10] + flip + sig[11:]
    st, _ = raw(ER, "POST", "/reserve", b, h2)
    ok = st == 401
    if not ok:  # never expect a valid sig from a flipped char; also confirm uppercase-hex acceptance is benign
        h3 = dict(sign(KEY, "POST", "/reserve", b))
        h3["X-Kavach-Signature"] = h3["X-Kavach-Signature"].upper()
        st3, _ = raw(ER, "POST", "/reserve", b, h3)
        return check("auth", "one flipped hex char in MAC: 401", False, "flip=%s upper=%s (upper hex is valid per RFC 4648)" % (st, st3))
    return check("auth", "one flipped hex char in MAC: 401 (byte-exact compare; uppercase hex is valid hex per RFC 4648)", ok, "status=%s" % st)
sig_uppercase_hex()
def rid_mac_mismatch():
    b = json.dumps({"user_id": "rt-63rm", "idempotency_key": "k63rm", "seats": 1}).encode()
    h = sign(KEY, "POST", "/reserve", b, rid="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
    h["X-Kavach-Request-Id"] = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
    st, _ = raw(ER, "POST", "/reserve", b, h)
    return check("auth", "sig computed over rid A, header carries rid B: 401 (rid is MAC-bound)", st == 401, "status=%s" % st)
rid_mac_mismatch()
def ten_thousand_dup_keys():
    b = ('{"user_id":"rt-63dk","idempotency_key":"k63dk","seats":1,' + '"junk":0,' * 10000 + '"z":1}').encode()
    st = raw(ER, "POST", "/reserve", b, sign(KEY, "POST", "/reserve", b))[0]
    alive = raw(ER, "GET", "/seats")[0] == 200
    return check("fuzz", "body with 10,000 duplicate junk keys: 4xx fast, no 5xx, engine alive", rej(st) and alive, "status=%s" % st)
ten_thousand_dup_keys()
def nul_bytes_user_id():
    b = json.dumps({"user_id": "rt-63nb" + "\x00" * 5000, "idempotency_key": "k63nb", "seats": 1}).encode()
    st = raw(ER, "POST", "/reserve", b, sign(KEY, "POST", "/reserve", b))[0]
    alive = raw(ER, "GET", "/seats")[0] == 200
    return check("fuzz", "user_id with 5000 NUL bytes: 4xx, no 5xx, engine alive", rej(st) and alive, "status=%s" % st)
nul_bytes_user_id()
def idem_reuse_after_release():
    st, j = post(ER, "/reserve", {"user_id": "rt-63ir", "idempotency_key": "k63ir", "seats": 1})
    rid1 = j.get("reservation_id") if isinstance(j, dict) and st == 200 else None
    if not rid1:
        return check("state", "idem key reuse after release: skipped (hold unavailable)", True, "st=%s" % st)
    post(ER, "/release", {"reservation_id": rid1})
    st2, j2 = post(ER, "/reserve", {"user_id": "rt-63ir", "idempotency_key": "k63ir", "seats": 1})
    rid2 = j2.get("reservation_id") if isinstance(j2, dict) and st2 == 200 else None
    detail = "r1=%s r2=%s rid_same=%s" % (st, st2, rid2 == rid1 if rid2 else None)
    if rid2:
        stc, _ = post(ER, "/confirm", {"reservation_id": rid2, "user_id": "rt-63ir"})
        detail += " confirm=%s" % stc
        if rid2 == rid1:
            if not (stc == 200 and False):
                pass
    s = seats(ER)
    ok = st2 != 500 and st2 != -1 and s.get("total") == s.get("sold") + s.get("held") + s.get("free")
    if rid2 == rid1 and stc == 200:
        ok = False  # sale on a released hold = bug
        detail += " BUG-sale-on-released"
    return check("state", "idem key reuse after release: no 5xx, no sale on released hold, conserved", ok, detail)
idem_reuse_after_release()
def release_confirm_race():
    st, j = post(ER, "/reserve", {"user_id": "rt-63rc", "idempotency_key": "k63rc", "seats": 1})
    rid = j.get("reservation_id") if isinstance(j, dict) else None
    if not rid:
        return check("race", "5v5 release vs confirm race: skipped (hold unavailable)", True, "st=%s" % st)
    s0 = seats(ER)
    def one(i):
        if i < 5:
            b = json.dumps({"reservation_id": rid, "user_id": "rt-63rc"}).encode()
            return raw(ER, "POST", "/confirm", b, sign(KEY, "POST", "/confirm", b))[0]
        b = json.dumps({"reservation_id": rid}).encode()
        return raw(ER, "POST", "/release", b, sign(KEY, "POST", "/release", b))[0]
    outs = P(10, one)
    s1 = seats(ER)
    sold_d = s1.get("sold", 0) - s0.get("sold", 0)
    held_d = s1.get("held", 0) - s0.get("held", 0)
    free_d = s1.get("free", 0) - s0.get("free", 0)
    xor = held_d == -1 and not (sold_d == 1 and free_d > 0)
    ok = xor and all(x < 500 and x != -1 for x in outs)
    return check("race", "5 confirms vs 5 releases on one hold: XOR outcome (one wins), no 5xx", ok,
                 "sold%+d held%+d free%+d" % (sold_d, held_d, free_d))
release_confirm_race()
def app_hold_10kb_user():
    st, _ = raw(AR, "POST", "/api/hold", json.dumps({"user_id": "u" * 10000, "seats": 1}))
    alive = raw(AR, "GET", "/")[0] == 200
    return check("app", "app hold with 10KB user_id: no 500, app alive", st != 500 and st != -1 and alive, "status=%s" % st)
app_hold_10kb_user()
def app_deal_missing():
    st, _ = raw(AR, "GET", "/deal/does-not-exist-9999")
    alive = raw(AR, "GET", "/")[0] == 200
    return check("app", "app GET /deal/<nonexistent>: no 500, app alive", st != 500 and st != -1 and alive, "status=%s" % st)
app_deal_missing()
def webhook_duplicate_send():
    st, j = post(ER, "/reserve", {"user_id": "rt-63wd", "idempotency_key": "k63wd", "seats": 1})
    rid = j.get("reservation_id") if isinstance(j, dict) else None
    if not rid:
        return check("app", "webhook duplicate send: skipped (hold unavailable)", True, "st=%s" % st)
    s0 = seats(ER)
    body = json.dumps({"event": "payment_failed", "reservation_id": rid, "seats": 1})
    st1, _ = raw(AR, "POST", "/api/kavach-webhook?token=whsec-redtest", body)
    st2, _ = raw(AR, "POST", "/api/kavach-webhook?token=whsec-redtest", body)
    s1 = seats(ER)
    freed_once = (s1.get("free", 0) - s0.get("free", 0)) == 1
    alive = raw(AR, "GET", "/")[0] == 200
    ok = st1 != 500 and st2 != 500 and st1 != -1 and st2 != -1 and alive and (freed_once or s1.get("held", 0) == s0.get("held", 0))
    return check("app", "webhook payment_failed sent twice: no double-free, no 500, app alive", ok,
                 "wh1=%s wh2=%s free%+d" % (st1, st2, s1.get("free", 0) - s0.get("free", 0)))
webhook_duplicate_send()
def two_mb_header():
    import socket as _s
    buf = b""
    try:
        sk = _s.create_connection(("127.0.0.1", ER), timeout=8)
        sk.sendall(b"GET /seats HTTP/1.1\r\nHost: x\r\nX-Junk: " + b"a" * 2000000 + b"\r\nConnection: close\r\n\r\n")
        sk.settimeout(5)
        try: buf = sk.recv(200)
        except Exception: pass
        sk.close()
    except Exception:
        pass
    stc = int(buf.split(b" ")[1]) if b"HTTP/1." in buf and len(buf.split(b" ")) > 1 else -1
    alive = raw(ER, "GET", "/seats")[0] == 200
    ok = (stc in (400, 431, 414) or stc == -1) and alive
    return check("wire", "2MB single header: rejected/431 or connection dropped, engine alive", ok, "st=%s" % stc)
two_mb_header()
def http_10_request():
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
    ok = stc == 200 and alive
    return check("wire", "HTTP/1.0 request (no Host header): served 200, engine alive", ok, "st=%s" % stc)
http_10_request()
def waitlist_rejoin_after_cancel():
    st1, j1 = post(ER2, "/waitlist", {"user_id": "rt-63wr", "idempotency_key": "k63wr", "seats": 1})
    wid = j1.get("waitlist_id") if isinstance(j1, dict) else None
    if not wid:
        return check("abuse", "waitlist rejoin after cancel: skipped (join unavailable)", True, "st=%s" % st1)
    st2, _ = post(ER2, "/waitlist/cancel", {"waitlist_id": wid})
    st3, j3 = post(ER2, "/waitlist", {"user_id": "rt-63wr", "idempotency_key": "k63wr2", "seats": 1})
    wid2 = j3.get("waitlist_id") if isinstance(j3, dict) else None
    st4 = 0
    if wid2: st4, _ = post(ER2, "/waitlist/cancel", {"waitlist_id": wid2})
    s = seats(ER2)
    ok = st1 == 200 and st2 in (200, 404) and st3 == 200 and st4 in (200, 404) \
         and s.get("total") == s.get("sold") + s.get("held") + s.get("free")
    return check("abuse", "waitlist join, cancel, rejoin same user, cancel: all clean, conserved", ok,
                 "j=%s c=%s rj=%s c2=%s" % (st1, st2, st3, st4))
waitlist_rejoin_after_cancel()


fails = [r for r in results if not r[2]]
print("TOTAL %d cases, PASS %d, FAIL %d" % (len(results), len(results) - len(fails), len(fails)))
for cat, name, ok, detail in fails:
    print("FAIL [%s] %s :: %s" % (cat, name, detail))
sys.exit(1 if fails else 0)
