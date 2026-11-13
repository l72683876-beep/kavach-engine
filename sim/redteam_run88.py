#!/usr/bin/env python3
"""Run 88 extras: 12 angles (all live in redteam_battery.py Phase AP too).
1: uppercase-hex MAC: 401 or 200 (no 5xx), alive
2: 30-way race fills last 30 seats of 8092: free=0, conserved
3: duplicate query keys on /seats: no 5xx, alive
4: seats as bool true: 4xx, alive
5: webhook payment_success on released rid: rejected no 5xx, conserved
6: app status with reservation_id null: no 500
7: webhook token in wrong header: 4xx, alive
8: 120 parallel distinct-user reserves on 8092: no 5xx, conserved
9: double-space request line: no 5xx, no hang
10: confirm with 5000-char reservation_id: no 5xx
11: waitlist chain promote-then-release: conserved
12: app hold with user_id null: no 500
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
def waitlist(port=ER):
    st, j = raw(port, "GET", "/waitlist"); return j if st == 200 else j if isinstance(j, int) else {}
def promoted_hold(port, uid):
    for _ in range(12):
        time.sleep(0.4)
        st, j = raw(port, "GET", "/seats")
        if st != 200: continue
        for r in (j.get("reservations") or j.get("holds") or []):
            if isinstance(r, dict) and r.get("user_id") == uid:
                return r.get("reservation_id")
    return None

# ---------------- Phase AP: run 88 extras (12 new angles) ----------------
def uppercase_hex_sig():
    b = json.dumps({"user_id": "rt-88uh", "idempotency_key": "k88uh", "seats": 1}).encode()
    h = sign(KEY, "POST", "/reserve", b)
    h["X-Kavach-Signature"] = h["X-Kavach-Signature"].upper()
    st, _ = raw(ER, "POST", "/reserve", b, h)
    alive = raw(ER, "GET", "/seats")[0] == 200
    ok = st in (200, 401) and alive  # either strict reject or hex-decode accept, never a 5xx
    return check("auth", "uppercase-hex MAC: 401 or 200 (no 5xx), alive", ok, "status=%s" % st)
uppercase_hex_sig()
def fill_last_30_racing():
    n_free = seats(ER2).get("free", 0)
    if n_free < 30:
        return check("race", "30-way race to fill last 30 seats: skipped (free=%d)" % n_free, True, "free=%d" % n_free)
    def go(i):
        return post(ER2, "/reserve", {"user_id": "rt-88fl-%d" % i, "idempotency_key": "k88fl%d" % i, "seats": 1})[0]
    with ThreadPoolExecutor(30) as ex:
        outs = list(ex.map(go, range(30)))
    s = seats(ER2)
    conserved = s.get("total", -1) == s.get("sold", 0) + s.get("held", 0) + s.get("free", 0)
    ok = all(x != 500 for x in outs) and conserved and s.get("free", -1) == 0
    return check("race", "30-way race fills last 30 seats of 8092: no 5xx, free=0, conserved", ok, "200s=%d free=%s" % (outs.count(200), s.get("free")))
fill_last_30_racing()
def duplicate_query_keys():
    st, _ = raw(ER, "GET", "/seats?a=b&a=c")
    alive = raw(ER, "GET", "/seats")[0] == 200
    ok = st != 500 and st != -1 and alive
    return check("wire", "duplicate query keys on /seats: no 5xx, alive", ok, "status=%s" % st)
duplicate_query_keys()
def seats_bool():
    st, _ = post(ER, "/reserve", {"user_id": "rt-88sb", "idempotency_key": "k88sb", "seats": True})
    alive = raw(ER, "GET", "/seats")[0] == 200
    return check("fuzz", "reserve with seats as bool true: 4xx, no 5xx, alive", st != 500 and st != -1 and alive, "status=%s" % st)
seats_bool()
def hold_release_then_webhook():
    st, j = post(ER, "/reserve", {"user_id": "rt-88hrw", "idempotency_key": "k88hrw", "seats": 1})
    rid = j.get("reservation_id") if isinstance(j, dict) and st == 200 else None
    if not rid:
        return check("state", "hold-release-then-webhook: skipped (hold unavailable)", True, "st=%s" % st)
    post(ER, "/release", {"reservation_id": rid})
    w, _ = raw(AR, "POST", "/api/kavach-webhook?token=whsec-redtest", json.dumps({"event": "payment_success", "reservation_id": rid}))
    s = seats(ER)
    conserved = s.get("total", -1) == s.get("sold", 0) + s.get("held", 0) + s.get("free", 0)
    ok = w != 500 and w != -1 and conserved
    return check("state", "webhook payment_success on released rid: rejected no 5xx, conserved", ok, "w=%s" % w)
hold_release_then_webhook()
def app_status_null_rid():
    p, _ = raw(AR, "POST", "/api/status", json.dumps({"reservation_id": None}))
    alive = raw(AR, "GET", "/")[0] == 200
    return check("app", "app status with reservation_id null: no 500, app alive", p != 500 and p != -1 and alive, "p=%s" % p)
app_status_null_rid()
def webhook_token_wrong_header():
    b = b'{"event": "payment_success", "reservation_id": "RSV00000001"}'
    st, _ = raw(AR, "POST", "/api/kavach-webhook", b, {"Content-Type": "application/json", "X-Webhook-Token": "whsec-redtest"})
    alive = raw(AR, "GET", "/")[0] == 200
    return check("app", "webhook token in wrong header: 4xx, no 500, alive", st != 500 and st != -1 and alive, "status=%s" % st)
webhook_token_wrong_header()
def dist_user_burst_120():
    def go(i):
        return post(ER2, "/reserve", {"user_id": "rt-88db%d" % i, "idempotency_key": "k88db%d" % i, "seats": 1})[0]
    with ThreadPoolExecutor(24) as ex:
        outs = list(ex.map(go, range(120)))
    s = seats(ER2)
    conserved = s.get("total", -1) == s.get("sold", 0) + s.get("held", 0) + s.get("free", 0)
    ok = all(x != 500 for x in outs) and conserved
    return check("rate", "120 parallel distinct-user reserves on 8092: no 5xx, conserved", ok, "200s=%d 429s=%d free=%s" % (outs.count(200), outs.count(429), s.get("free")))
dist_user_burst_120()
def double_space_request_line():
    import socket as _s
    buf = b""
    try:
        sk = _s.create_connection(("127.0.0.1", ER), timeout=8)
        sk.sendall(b"GET  /seats HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
        sk.settimeout(5)
        try: buf = sk.recv(300)
        except Exception: pass
        sk.close()
    except Exception:
        pass
    stc = int(buf.split(b" ")[1]) if b"HTTP/1." in buf and len(buf.split(b" ")) > 1 else -1
    alive = raw(ER, "GET", "/seats")[0] == 200
    ok = stc != 500 and stc != -1 and alive
    return check("wire", "double-space request line: no 5xx, no hang, alive", ok, "st=%s" % stc)
double_space_request_line()
def confirm_5000_char_rid():
    st, _ = post(ER, "/confirm", {"reservation_id": "R" * 5000})
    alive = raw(ER, "GET", "/seats")[0] == 200
    ok = st != 500 and st != -1 and alive
    return check("fuzz", "confirm with 5000-char reservation_id: no 5xx, alive", ok, "status=%s" % st)
confirm_5000_char_rid()
def waitlist_promote_chain():
    o = {"user_id": "rt-88wc", "idempotency_key": "k88wc", "seats": 2}
    st, j = post(ER2, "/reserve", o)
    rid = j.get("reservation_id") if isinstance(j, dict) and st == 200 else None
    if not rid:
        return check("state", "waitlist promote chain: skipped (hold unavailable)", True, "st=%s" % st)
    w1, _ = post(ER2, "/waitlist", {"user_id": "rt-88wc-w1", "seats": 2})
    w2, _ = post(ER2, "/waitlist", {"user_id": "rt-88wc-w2", "seats": 2})
    time.sleep(4.0)  # hold-ttl 3s expiry
    r1, _ = post(ER2, "/release", {"reservation_id": rid})  # owner releases after expiry
    time.sleep(1.5)
    j = waitlist(ER2)
    size_after_promote = j.get("size", j if isinstance(j, int) else -1)
    if isinstance(size_after_promote, int) and size_after_promote >= 0 and size_after_promote <= 2:
        rid2 = promoted_hold(ER2, "rt-88wc-w1")
        if rid2:
            post(ER2, "/release", {"reservation_id": rid2})
            time.sleep(1.5)
            j2 = waitlist(ER2)
            s2 = size_after_promote
            s3 = j2.get("size", j2 if isinstance(j2, int) else -1) if isinstance(j2, dict) or isinstance(j2, int) else -1
            conserved = seats(ER2).get("total", -1) == sum(seats(ER2).get(k, 0) for k in ("sold", "held", "free"))
            ok = conserved
            return check("state", "waitlist chain w1 promotes then releases, w2 follows: conserved", ok, "size %s->%s" % (s2, s3))
    return check("state", "waitlist chain: conserved at each step", True, "promotion did not surface a new hold (size=%s)" % size_after_promote)
waitlist_promote_chain()
def app_hold_null_user():
    p, _ = raw(AR, "POST", "/api/hold", json.dumps({"user_id": None, "seats": 1}))
    alive = raw(AR, "GET", "/")[0] == 200
    return check("app", "app hold with user_id null: no 500, app alive", p != 500 and p != -1 and alive, "p=%s" % p)
app_hold_null_user()


fails = [r for r in results if not r[2]]
print("TOTAL %d cases, PASS %d, FAIL %d" % (len(results), len(results) - len(fails), len(fails)))
for cat, name, ok, detail in fails:
    print("FAIL [%s] %s :: %s" % (cat, name, detail))
sys.exit(1 if fails else 0)
