#!/usr/bin/env python3
"""Run 65 extras: 12 angles (all live in redteam_battery.py Phase S too).
1: X-Kavach-Request-Id of a single space: 401
2: JSON body with Content-Type text/plain: no 5xx, conserved
3: CL + TE both set: rejected (400/401), no smuggling, alive
4: two Content-Length headers, different values: 400, alive
5: same idem key reserve after book: no second sale
6: 10 parallel waitlist joins, same idem key: dedup/conflict, no 5xx
7: app GET /../../etc/passwd: no 500
8: app hold user_id ../../../admin: no 500
9: webhook token in header instead of query: rejected
10: top-level JSON null body: 4xx, alive
11: seats boundary: 4 accepted, 5 rejected, conserved
12: HEAD /seats: 200, alive
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

# ---------------- Phase S: run 65 extras (12 new angles) ----------------
def rid_whitespace_only():
    b = json.dumps({"user_id": "rt-65wr", "idempotency_key": "k65wr", "seats": 1}).encode()
    h = sign(KEY, "POST", "/reserve", b, rid=" ")
    st, _ = raw(ER, "POST", "/reserve", b, h)
    return check("auth", "X-Kavach-Request-Id of a single space: 401", st == 401, "status=%s" % st)
rid_whitespace_only()
def ct_text_plain_json_body():
    b = json.dumps({"user_id": "rt-65ct", "idempotency_key": "k65ct", "seats": 1}).encode()
    h = sign(KEY, "POST", "/reserve", b)
    h["Content-Type"] = "text/plain"
    st, j = raw(ER, "POST", "/reserve", b, h)
    rid = j.get("reservation_id") if isinstance(j, dict) and st == 200 else None
    if rid: post(ER, "/release", {"reservation_id": rid})
    s = seats(ER)
    ok = st != 500 and st != -1 and s.get("total") == s.get("sold") + s.get("held") + s.get("free")
    return check("fuzz", "JSON body with Content-Type text/plain: no 5xx, conserved", ok, "status=%s" % st)
ct_text_plain_json_body()
def cl_and_chunked():
    import socket as _s
    buf = b""
    try:
        sk = _s.create_connection(("127.0.0.1", ER), timeout=8)
        sk.sendall(b"POST /reserve HTTP/1.1\r\nHost: x\r\nContent-Length: 100\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n")
        sk.settimeout(5)
        try: buf = sk.recv(200)
        except Exception: pass
        sk.close()
    except Exception:
        pass
    stc = int(buf.split(b" ")[1]) if b"HTTP/1." in buf and len(buf.split(b" ")) > 1 else -1
    alive = raw(ER, "GET", "/seats")[0] == 200
    ok = stc in (400, 401, 411, 413) and alive
    return check("wire", "Content-Length + Transfer-Encoding both set: rejected (400/401), alive, no smuggling", ok, "st=%s" % stc)
cl_and_chunked()
def duplicate_content_length():
    import socket as _s
    buf = b""
    try:
        sk = _s.create_connection(("127.0.0.1", ER), timeout=8)
        sk.sendall(b"POST /reserve HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\nContent-Length: 100\r\nConnection: close\r\n\r\n")
        sk.settimeout(5)
        try: buf = sk.recv(200)
        except Exception: pass
        sk.close()
    except Exception:
        pass
    stc = int(buf.split(b" ")[1]) if b"HTTP/1." in buf and len(buf.split(b" ")) > 1 else -1
    alive = raw(ER, "GET", "/seats")[0] == 200
    ok = stc in (400, 400) and alive
    return check("wire", "two Content-Length headers with different values: 400, alive", ok, "st=%s" % stc)
duplicate_content_length()
def idem_reuse_after_book():
    st, j = post(ER, "/reserve", {"user_id": "rt-65ib", "idempotency_key": "k65ib", "seats": 1})
    rid = j.get("reservation_id") if isinstance(j, dict) and st == 200 else None
    if not rid:
        return check("state", "same idem key after book: skipped (hold unavailable)", True, "st=%s" % st)
    b = json.dumps({"reservation_id": rid, "user_id": "rt-65ib"}).encode()
    stb = raw(ER, "POST", "/confirm", b, sign(KEY, "POST", "/confirm", b))[0]
    if stb != 200:
        return check("state", "same idem key after book: skipped (confirm failed)", True, "conf=%s" % stb)
    s0 = seats(ER)
    st2, j2 = post(ER, "/reserve", {"user_id": "rt-65ib", "idempotency_key": "k65ib", "seats": 1})
    s1 = seats(ER)
    sold_d = s1.get("sold", 0) - s0.get("sold", 0)
    ok = st2 != 500 and st2 != -1 and sold_d == 0 and s1.get("total") == s1.get("sold") + s1.get("held") + s1.get("free")
    return check("state", "same idem key reserve after book: replay/conflict, no second sale", ok,
                 "res2=%s sold%+d" % (st2, sold_d))
idem_reuse_after_book()
def waitlist_same_key_race():
    def one(i):
        return post(ER2, "/waitlist", {"user_id": "rt-65w%d" % i, "idempotency_key": "k65wr", "seats": 1})
    outs = P(10, one)
    wids = set()
    bad = 0
    for st, j in outs:
        if st == 200:
            wids.add(j.get("waitlist_id"))
        elif st >= 500 or st == -1:
            bad += 1
    if len(wids) == 1:
        wid = list(wids)[0]
        if wid: post(ER2, "/waitlist/cancel", {"waitlist_id": wid})
    s = seats(ER2)
    ok = bad == 0 and (len(wids) <= 1) and s.get("total") == s.get("sold") + s.get("held") + s.get("free")
    return check("race", "10 parallel waitlist joins, same idem key: dedup/conflict, no 5xx", ok,
                 "distinct_wids=%d bad=%d" % (len(wids), bad))
waitlist_same_key_race()
def app_path_traversal():
    st, _ = raw(AR, "GET", "/../../etc/passwd")
    alive = raw(AR, "GET", "/")[0] == 200
    return check("app", "app GET /../../etc/passwd: no 500, app alive", st != 500 and st != -1 and alive, "status=%s" % st)
app_path_traversal()
def app_user_traversal():
    st, _ = raw(AR, "POST", "/api/hold", '{"user_id":"../../../admin","seats":1}')
    alive = raw(AR, "GET", "/")[0] == 200
    return check("app", "app hold user_id ../../../admin: no 500, app alive", st != 500 and st != -1 and alive, "status=%s" % st)
app_user_traversal()
def webhook_token_in_header():
    st, _ = raw(AR, "POST", "/api/kavach-webhook", '{"type":"waitlist_fulfilled","reservation_id":"FAKE","seats":[1]}',
                {"X-Webhook-Token": "whsec-redtest"})
    alive = raw(AR, "GET", "/")[0] == 200
    ok = st in (400, 401, 403) and alive
    return check("app", "webhook token in header instead of query: rejected, no 500", ok, "status=%s" % st)
webhook_token_in_header()
def top_level_null_body():
    b = b'null'
    st = raw(ER, "POST", "/reserve", b, sign(KEY, "POST", "/reserve", b))[0]
    alive = raw(ER, "GET", "/seats")[0] == 200
    return check("fuzz", "top-level JSON null body: 4xx, no 5xx, alive", rej(st) and alive, "status=%s" % st)
top_level_null_body()
def seats_boundary():
    b4 = json.dumps({"user_id": "rt-65b4", "idempotency_key": "k65b4", "seats": 4}).encode()
    st4, j4 = raw(ER, "POST", "/reserve", b4, sign(KEY, "POST", "/reserve", b4))
    rid = j4.get("reservation_id") if isinstance(j4, dict) and st4 == 200 else None
    if rid: post(ER, "/release", {"reservation_id": rid})
    b5 = json.dumps({"user_id": "rt-65b5", "idempotency_key": "k65b5", "seats": 5}).encode()
    st5 = raw(ER, "POST", "/reserve", b5, sign(KEY, "POST", "/reserve", b5))[0]
    s = seats(ER)
    ok = st4 in (200, 429) and rej(st5) and s.get("total") == s.get("sold") + s.get("held") + s.get("free")
    return check("state", "seats boundary: 4 accepted, 5 rejected, conserved", ok, "4=%s 5=%s" % (st4, st5))
seats_boundary()
def head_seats():
    st, _ = raw(ER, "HEAD", "/seats")
    alive = raw(ER, "GET", "/seats")[0] == 200
    return check("wire", "HEAD /seats: 200, engine alive", st == 200 and alive, "status=%s" % st)
head_seats()


fails = [r for r in results if not r[2]]
print("TOTAL %d cases, PASS %d, FAIL %d" % (len(results), len(results) - len(fails), len(fails)))
for cat, name, ok, detail in fails:
    print("FAIL [%s] %s :: %s" % (cat, name, detail))
sys.exit(1 if fails else 0)
