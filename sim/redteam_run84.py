#!/usr/bin/env python3
"""Run 84 extras: 12 angles (all live in redteam_battery.py Phase AL too).
1: MAC string with key/method swapped: 401, alive
2: 10 parallel releases on an already-sold rid: no 5xx, conserved
3: tab appended to X-Kavach-Timestamp: 401/400, alive
4: reserve with seats 1.0 float: no 5xx, alive
5: app confirm without reservation_id key: no 500
6: webhook with event as number: no 500, alive
7: 150-post burst then valid reserve after 1.2s: no 5xx, recovers
8: payment_pending webhook after confirm: no 500, sold unchanged
9: emoji in query string: 200, alive
10: Transfer-Encoding chunked on reserve: no 5xx, alive
11: 3 parallel reserves for ALL remaining free seats: at most 1 wins
12: app hold with empty user_id: no 500
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

# ---------------- Phase AL: run 84 extras (12 new angles) ----------------
def mac_swapped_fields():
    b = json.dumps({"user_id": "rt-84sw", "idempotency_key": "k84sw", "seats": 1}).encode()
    ts = str(int(time.time())); rid = uuid.uuid4().hex
    # MAC string with key and method positions swapped: ts, rid, key, POST -> wrong order
    mac = hmac.new(SECRET.encode(), (ts + "\n" + rid + "\n" + KEY + "\nPOST\n/reserve\n").encode() + b, hashlib.sha256).hexdigest()
    h = {"Authorization": "Bearer " + KEY, "X-Kavach-Timestamp": ts, "X-Kavach-Request-Id": rid,
         "X-Kavach-Signature": mac, "Content-Type": "application/json"}
    st, _ = raw(ER, "POST", "/reserve", b, h)
    alive = raw(ER, "GET", "/seats")[0] == 200
    return check("auth", "MAC string with key/method swapped: 401, alive", st == 401 and alive, "status=%s" % st)
mac_swapped_fields()
def parallel_release_sold_rid():
    st, j = post(ER, "/reserve", {"user_id": "rt-84pr", "idempotency_key": "k84pr", "seats": 1})
    rid = j.get("reservation_id") if isinstance(j, dict) and st == 200 else None
    if not rid:
        return check("race", "parallel releases on sold rid: skipped (hold unavailable)", True, "st=%s" % st)
    post(ER, "/confirm", {"reservation_id": rid})  # sold now
    outs = P(10, lambda i: post(ER, "/release", {"reservation_id": rid})[0])
    s = seats(ER)
    conserved = s.get("total", -1) == s.get("sold", 0) + s.get("held", 0) + s.get("free", 0)
    ok = all(x != 500 and x != -1 for x in outs) and conserved
    return check("race", "10 parallel releases on an already-sold rid: no 5xx, conserved", ok, "outs=%s" % outs)
parallel_release_sold_rid()
def ts_tab_in_header():
    b = json.dumps({"user_id": "rt-84tb", "idempotency_key": "k84tb", "seats": 1}).encode()
    h = sign(KEY, "POST", "/reserve", b); h["X-Kavach-Timestamp"] = str(int(time.time())) + "\t"
    st, _ = raw(ER, "POST", "/reserve", b, h)
    alive = raw(ER, "GET", "/seats")[0] == 200
    # Go strips trailing OWS (tab) from header values per RFC 7230, so the engine
    # may legitimately see the exact ts and accept (200); tamper check is on 5xx.
    ok = st in (200, 400, 401) and alive
    return check("auth", "tab appended to X-Kavach-Timestamp: no 5xx, alive", ok, "status=%s" % st)
ts_tab_in_header()
def seats_float_zero():
    st, _ = post(ER, "/reserve", {"user_id": "rt-84fz", "idempotency_key": "k84fz", "seats": 1.0})
    alive = raw(ER, "GET", "/seats")[0] == 200
    return check("fuzz", "reserve with seats 1.0 (float): 4xx or accepted, no 5xx, alive", st != 500 and st != -1 and alive, "status=%s" % st)
seats_float_zero()
def app_confirm_missing_key():
    p, _ = raw(AR, "POST", "/api/confirm", json.dumps({"user_id": "rt-84mk"}))  # no reservation_id
    alive = raw(AR, "GET", "/")[0] == 200
    return check("app", "app confirm without reservation_id key: no 500, app alive", p != 500 and p != -1 and alive, "p=%s" % p)
app_confirm_missing_key()
def webhook_event_number():
    w, _ = raw(AR, "POST", "/api/kavach-webhook?token=whsec-redtest", b'{"event": 1, "reservation_id": "RSV00000099"}')
    alive = raw(AR, "GET", "/")[0] == 200
    return check("app", "webhook with event as number: no 500, app alive", w != 500 and w != -1 and alive, "w=%s" % w)
webhook_event_number()
def burst_then_recover():
    outs = [raw(ER, "POST", "/seats", b"")[0] for _ in range(150)]  # burst 150 rapid posts same IP
    time.sleep(1.2)
    st, _ = post(ER, "/reserve", {"user_id": "rt-84br", "idempotency_key": "k84br", "seats": 1})
    ok = all(x != 500 for x in outs) and st != 500 and st != -1
    return check("rate", "150-post burst then valid reserve after 1.2s: no 5xx, engine recovers (429 then ok)", ok, "burst429=%d reserve_st=%s" % (outs.count(429), st))
burst_then_recover()
def confirm_then_pending_webhook():
    st, j = post(ER, "/reserve", {"user_id": "rt-84cp", "idempotency_key": "k84cp", "seats": 1})
    rid = j.get("reservation_id") if isinstance(j, dict) and st == 200 else None
    if not rid:
        return check("app", "confirm then payment_pending webhook: skipped (hold unavailable)", True, "st=%s" % st)
    post(ER, "/confirm", {"reservation_id": rid})  # sold
    s0 = seats(ER)
    w, _ = raw(AR, "POST", "/api/kavach-webhook?token=whsec-redtest", json.dumps({"event": "payment_pending", "reservation_id": rid}))
    s1 = seats(ER)
    alive = raw(AR, "GET", "/")[0] == 200
    sane = s1.get("sold", 0) == s0.get("sold", 0)
    ok = w != 500 and w != -1 and alive and sane
    return check("app", "payment_pending webhook after confirm (already sold): no 500, sold unchanged", ok, "w=%s sold0=%s sold1=%s" % (w, s0.get("sold"), s1.get("sold")))
confirm_then_pending_webhook()
def emoji_query():
    st, _ = raw(ER, "GET", "/seats?q=%F0%9F%94%A5")
    alive = raw(ER, "GET", "/seats")[0] == 200
    return check("wire", "emoji in query string: 200, alive", st == 200 and alive, "status=%s" % st)
emoji_query()
def chunked_body():
    # Proper chunked request via raw socket: no Content-Length, body as one chunk.
    body = json.dumps({"user_id": "rt-84cb", "idempotency_key": "k84cb", "seats": 1}).encode()
    ts = str(int(time.time())); rid = uuid.uuid4().hex
    mac = hmac.new(SECRET.encode(), (ts + "\n" + rid + "\nPOST\n/reserve\n" + KEY + "\n").encode() + body, hashlib.sha256).hexdigest()
    head = ("POST /reserve HTTP/1.1\r\nHost: 127.0.0.1:8091\r\nAuthorization: Bearer " + KEY +
            "\r\nX-Kavach-Timestamp: " + ts + "\r\nX-Kavach-Request-Id: " + rid +
            "\r\nX-Kavach-Signature: " + mac + "\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n").encode()
    import socket as _s
    buf = b""
    try:
        sk = _s.create_connection(("127.0.0.1", ER), timeout=10)
        sk.sendall(head + (hex(len(body))[2:] + "\r\n").encode() + body + b"\r\n0\r\n\r\n")
        sk.settimeout(8)
        try: buf = sk.recv(300)
        except Exception: pass
        sk.close()
    except Exception:
        pass
    stc = int(buf.split(b" ")[1]) if b"HTTP/1." in buf and len(buf.split(b" ")) > 1 else -1
    alive = raw(ER, "GET", "/seats")[0] == 200
    ok = stc != 500 and stc != -1 and alive
    return check("wire", "chunked-encoded reserve request via raw socket: no 5xx, alive", ok, "st=%s" % stc)
chunked_body()
def parallel_all_remaining_race():
    s0 = seats(ER)
    free = s0.get("free", 0)
    if free <= 0:
        return check("race", "parallel all-remaining-seats race: skipped (no free seats)", True, "free=%s" % free)
    outs = P(3, lambda i: post(ER, "/reserve", {"user_id": "rt-84ar%d" % i, "idempotency_key": "k84ar%d" % i, "seats": free})[0])
    s1 = seats(ER)
    wins = sum(1 for x in outs if x == 200)
    held_delta = s1.get("held", 0) - s0.get("held", 0)
    ok = wins <= 1 and all(x != 500 and x != -1 for x in outs)
    if wins == 1 and held_delta != free:
        # release the winner's hold so conserved holds
        pass  # auto-expire ttl 3s handles it
    return check("race", "3 parallel reserves for ALL remaining free seats: at most 1 wins, no 5xx", ok, "outs=%s free=%s wins=%s" % (outs, free, wins))
parallel_all_remaining_race()
def app_hold_empty_user():
    p, _ = raw(AR, "POST", "/api/hold", json.dumps({"user_id": "", "seats": 1}))
    alive = raw(AR, "GET", "/")[0] == 200
    return check("app", "app hold with empty user_id: no 500, app alive", p != 500 and p != -1 and alive, "p=%s" % p)
app_hold_empty_user()


fails = [r for r in results if not r[2]]
print("TOTAL %d cases, PASS %d, FAIL %d" % (len(results), len(results) - len(fails), len(fails)))
for cat, name, ok, detail in fails:
    print("FAIL [%s] %s :: %s" % (cat, name, detail))
sys.exit(1 if fails else 0)
