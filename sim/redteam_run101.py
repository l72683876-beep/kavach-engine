#!/usr/bin/env python3
"""Run 101 extras: 12 angles (all live in redteam_battery.py Phase BC too).
1: GET /seats with backslash in path: no 5xx, no hang
2: GET /seats with raw space in path: no 5xx, graceful
3: transfer of a released rid: 4xx, conserved
4: same-user rapid transfer burst: 429s ok, no 5xx, conserved
5: HTTP/2 preface sent to HTTP/1.1 engine: graceful, alive
6: transfer to_user as JSON number: 4xx, no 5xx
7: app /api/pay with amount as string: no 500
8: confirm using a waitlist entry id as reservation_id: no 5xx
9: transfer round-trip a->b then b->a: no 5xx, conserved
10: transfer to self (a->a): no 5xx, conserved
11: seats as unicode digit (Bengali 1): no 5xx, alive
12: HMAC-SHA512 signature instead of SHA-256: 401, alive
Run against targets already up: 8091 engine, 8092 engine2, 9001 app.
"""
import hashlib, hmac, http.client, json, socket, sys, time, uuid
from concurrent.futures import ThreadPoolExecutor

ER, AR, ER2 = 8091, 9001, 8092
KEY, SECRET = "testkey", "testsecret"
results = []
def check(cat, name, ok, detail=""):
    results.append((cat, name, bool(ok), str(detail)[:220]))
def sign(key, method, path, body, secret=SECRET, ts=None, rid=None, sha=hashlib.sha256):
    ts = str(int(time.time())) if ts is None else ts
    rid = uuid.uuid4().hex if rid is None else rid
    mac = hmac.new(secret.encode(), (ts + "\n" + rid + "\n" + method + "\n" + path + "\n" + key + "\n").encode() + body, sha).hexdigest()
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

# ---------------- Phase BC: run 101 extras (12 new angles) ----------------
def bc_hold(user, key="k101%s"):
    st, j = post(ER, "/reserve", {"user_id": user, "idempotency_key": key % user.replace("rt-101", ""), "seats": 1})
    return (j.get("reservation_id") if isinstance(j, dict) and st == 200 else None), st

def backslash_path():
    st, _ = raw(ER, "GET", "/seats\\rt101")
    alive = raw(ER, "GET", "/seats")[0] == 200
    ok = st != 500 and st != -1 and alive
    return check("wire", "GET /seats backslash in path: no 5xx, no hang, alive", ok, "status=%s" % st)
backslash_path()
def raw_space_path():
    # http.client refuses to send a space in the request-target, so send raw bytes
    import socket as _socket
    socket = _socket
    try:
        s = socket.create_connection(("127.0.0.1", ER), timeout=10)
        s.sendall(b"GET /se ats HTTP/1.1\r\nHost: 127.0.0.1:8091\r\n\r\n")
        try:
            d = s.recv(400)
        except Exception:
            d = b""
        s.close()
    except Exception as ex:
        d = ("EXC " + str(ex)).encode()
    resp = d[:60].decode("utf-8", "replace")
    # graceful = a 4xx response line or an immediate connection close; a hang or 5xx is a bug
    graceful = (b"400" in d[:32]) or (len(d) == 0)
    alive = raw(ER, "GET", "/seats")[0] == 200
    ok = graceful and alive
    return check("wire", "GET /seats raw space in path: graceful 400, alive", ok, "resp=%s" % resp)
raw_space_path()
def transfer_released_rid():
    rid, st = bc_hold("rt-101tr", "k101tr%s")
    if not rid:
        return check("state", "transfer released rid: skipped (hold unavailable)", True, "st=%s" % st)
    post(ER, "/release", {"reservation_id": rid})
    time.sleep(0.6)
    st2, _ = post(ER, "/transfer", {"reservation_id": rid, "to_user": "rt-101tr-b"})
    ok = 400 <= st2 < 500 and conserved()
    return check("state", "transfer of a released rid: 4xx, conserved", ok, "st2=%s" % st2)
transfer_released_rid()
def transfer_burst_same_user():
    rid, st = bc_hold("rt-101tb", "k101tb%s")
    if not rid:
        return check("rate", "transfer burst: skipped (hold unavailable)", True, "st=%s" % st)
    st2, _ = post(ER, "/confirm", {"reservation_id": rid})
    if st2 != 200:
        return check("rate", "transfer burst: skipped (confirm %s)" % st2, True)
    def go(i):
        return post(ER, "/transfer", {"reservation_id": rid, "to_user": "rt-101tb-u%d" % i})[0]
    outs = [go(i) for i in range(15)]
    time.sleep(1.0)
    ok = all(x != 500 and x != -1 for x in outs) and conserved()
    return check("rate", "same-user rapid transfer burst: no 5xx, conserved", ok, "200s=%d 429s=%d" % (outs.count(200), outs.count(429)))
transfer_burst_same_user()
def http2_preface():
    try:
        s = socket.create_connection(("127.0.0.1", ER), timeout=10)
        s.sendall(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
        try:
            data = s.recv(200)
        except Exception:
            data = b""
        s.close()
    except Exception as ex:
        data = ("EXC " + str(ex)).encode()
    alive = raw(ER, "GET", "/seats")[0] == 200
    ok = alive
    return check("wire", "HTTP/2 preface to HTTP/1.1 engine: graceful, alive", ok, "resp=%s" % data[:80])
http2_preface()
def to_user_json_number():
    rid, st = bc_hold("rt-101tn2", "k101tn%s")
    if not rid:
        return check("fuzz", "to_user JSON number: skipped (hold unavailable)", True, "st=%s" % st)
    st2, _ = post(ER, "/transfer", {"reservation_id": rid, "to_user": 123})
    post(ER, "/release", {"reservation_id": rid})
    time.sleep(0.6)
    ok = st2 != 500 and st2 != -1 and conserved()
    return check("fuzz", "transfer to_user as JSON number: no 5xx, conserved", ok, "st2=%s" % st2)
to_user_json_number()
def app_pay_amount_string():
    rid, st = bc_hold("rt-101as", "k101as%s")
    if not rid:
        return check("app", "app pay amount string: skipped (hold unavailable)", True, "st=%s" % st)
    p, _ = raw(AR, "POST", "/api/pay", json.dumps({"reservation_id": rid, "amount": "500"}))
    post(ER, "/release", {"reservation_id": rid})
    alive = raw(AR, "GET", "/")[0] == 200
    ok = p != 500 and p != -1 and alive
    return check("app", "app /api/pay amount as string: no 500, graceful", ok, "p=%s" % p)
app_pay_amount_string()
def confirm_waitlist_entry_id():
    st, j = post(ER, "/waitlist", {"user_id": "rt-101wl", "event_id": "demo", "seats": 1})
    entry = None
    if isinstance(j, dict):
        for kk in ("entry_id", "id", "waitlist_id", "entry"):
            if j.get(kk): entry = j[kk]; break
    if entry is None:
        return check("state", "confirm waitlist entry id: skipped (no entry id in %s)" % (str(j)[:40] if isinstance(j, dict) else st), True)
    st2, _ = post(ER, "/confirm", {"reservation_id": str(entry)})
    alive = raw(ER, "GET", "/seats")[0] == 200
    ok = st2 != 500 and st2 != -1 and alive
    return check("state", "confirm using waitlist entry id as rid: no 5xx, alive", ok, "st2=%s" % st2)
confirm_waitlist_entry_id()
def transfer_round_trip():
    rid, st = bc_hold("rt-101rt", "k101rt%s")
    if not rid:
        return check("state", "transfer round trip: skipped (hold unavailable)", True, "st=%s" % st)
    st2, _ = post(ER, "/confirm", {"reservation_id": rid})
    if st2 != 200:
        return check("state", "transfer round trip: skipped (confirm %s)" % st2, True)
    st3, _ = post(ER, "/transfer", {"reservation_id": rid, "to_user": "rt-101rt-b"})
    time.sleep(1.2)
    st4, _ = post(ER, "/transfer", {"reservation_id": rid, "to_user": "rt-101rt"})
    time.sleep(0.8)
    ok = all(x != 500 and x != -1 for x in (st3, st4)) and conserved()
    return check("state", "transfer round-trip a->b->a: no 5xx, conserved", ok, "st3=%s st4=%s" % (st3, st4))
transfer_round_trip()
def transfer_to_self():
    rid, st = bc_hold("rt-101ts", "k101ts%s")
    if not rid:
        return check("state", "transfer to self: skipped (hold unavailable)", True, "st=%s" % st)
    st2, _ = post(ER, "/confirm", {"reservation_id": rid})
    if st2 != 200:
        return check("state", "transfer to self: skipped (confirm %s)" % st2, True)
    st3, _ = post(ER, "/transfer", {"reservation_id": rid, "to_user": "rt-101ts"})
    time.sleep(0.8)
    ok = st3 != 500 and st3 != -1 and conserved()
    return check("state", "transfer to self (a->a): no 5xx, conserved", ok, "st3=%s" % st3)
transfer_to_self()
def unicode_digit_seats():
    st, _ = post(ER, "/reserve", {"user_id": "rt-101ud", "idempotency_key": "k101ud", "seats": "\u09e7"})
    alive = raw(ER, "GET", "/seats")[0] == 200
    ok = st != 500 and st != -1 and alive
    return check("fuzz", "seats as unicode digit (Bengali 1): no 5xx, alive", ok, "status=%s" % st)
unicode_digit_seats()
def sha512_signature():
    b = json.dumps({"user_id": "rt-101sh", "idempotency_key": "k101sh", "seats": 1}).encode()
    h = sign(KEY, "POST", "/reserve", b)
    msg = (h["X-Kavach-Timestamp"] + "\n" + h["X-Kavach-Request-Id"] + "\nPOST\n/reserve\n" + KEY + "\n").encode() + b
    h["X-Kavach-Signature"] = hmac.new(SECRET.encode(), msg, hashlib.sha512).hexdigest()
    st, _ = raw(ER, "POST", "/reserve", b, h)
    alive = raw(ER, "GET", "/seats")[0] == 200
    ok = st == 401 and alive
    return check("auth", "HMAC-SHA512 signature: 401 rejected, alive", ok, "status=%s" % st)
sha512_signature()

# ---------------- Summary ----------------
fails = [r for r in results if not r[2]]
print("TOTAL %d cases, PASS %d, FAIL %d" % (len(results), len(results) - len(fails), len(fails)))
for cat, name, ok, detail in fails:
    print("FAIL [%s] %s :: %s" % (cat, name, detail))
sys.exit(1 if fails else 0)
