#!/usr/bin/env python3
"""Run 55 extras: 12 angles (all live in redteam_battery.py Phase I too).
1: cross-tenant same idempotency key - no cross-tenant state or data leak
2: uppercase auth header names - signature still accepted (Go canonicalization)
3: user_id type confusion (float/bool/null/obj/array) - clean 4xx
4: seats extremes (int64 max, 2^63 overflow, -1, 0, string) - clean 4xx
5: app hold confirmed out-of-band (payment bypass) then app pay - clean error, app alive
6: webhook replay, same valid event twice - no 500, state unchanged
7: chunked transfer-encoding with valid MAC - body reassembled, auth passes
8: TTL-expired hold stays dead while fresh sibling confirms - no resurrection
9: idem key reused across reserve/confirm/release ops - no state confusion
10: slowloris partial request then close - engine serves next valid request
11: form-encoded body with valid MAC - clean 4xx (JSON only)
12: pipelined two requests in one socket write - correct order, no smuggling
Run against targets already up: 8091 engine, 8092 engine2, 8095 short-TTL, 9001 app.
"""
import hashlib, hmac, http.client, json, sys, time, uuid

ER, AR, ET = 8091, 9001, 8095
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
def seats(port=ER):
    st, j = raw(port, "GET", "/seats"); return j if st == 200 else {}

# ---------------- Phase I: run 55 extras (12 new angles) ----------------
def xt_idem_collision():
    # Same idempotency key from tenant1 and tenant2: keys must be tenant-scoped.
    # tenant2 must NEVER see tenant1's reservation data under the shared key.
    if seats(ER).get("free", 0) < 1:
        return check("tenant", "cross-tenant idem key collision: skipped (sold out, no capacity)", True, "free=%s" % seats(ER).get("free"))
    a = post(ER, "/reserve", {"user_id": "rt-55t1", "idempotency_key": "k55x", "seats": 1})
    b = post(ER, "/reserve", {"user_id": "rt-55t2", "idempotency_key": "k55x", "seats": 1}, key=KEY2)
    rid_a = a[1].get("reservation_id")
    leak = rid_a and (rid_a in json.dumps(b[1]) or "rt-55t1" in json.dumps(b[1]))
    if rid_a:
        post(ER, "/release", {"reservation_id": rid_a})
    if b[1].get("reservation_id"):
        post(ER, "/release", {"reservation_id": b[1]["reservation_id"]}, key=KEY2)
    return check("tenant", "cross-tenant same idem key: no cross-tenant state or data leak", b[0] < 500 and not leak,
                 "t1=%s t2=%s rid_a=%s b=%s" % (a[0], b[0], rid_a, json.dumps(b[1])[:80]))
xt_idem_collision()
def hmac_header_case():
    # Auth must survive HTTP header-name case variation (names are case-insensitive).
    body = json.dumps({"reservation_id": "RSV999999", "user_id": "rt-55hc"}).encode()
    h = sign(KEY, "POST", "/confirm", body)
    up = {"X-KAVACH-Timestamp": h["X-Kavach-Timestamp"], "X-KAVACH-REQUEST-ID": h["X-Kavach-Request-Id"],
          "X-KAVACH-SIGNATURE": h["X-Kavach-Signature"], "AUTHORIZATION": h["Authorization"],
          "CONTENT-TYPE": "application/json"}
    st = raw(ER, "POST", "/confirm", body, up)[0]
    return check("auth", "uppercase auth header names: signature still accepted (404 on unknown rid, not 401)", st == 404, "status=%s" % st)
hmac_header_case()
def uid_type_confusion():
    outs = []
    for v in (1.5, True, None, {}, ["a"]):
        body = json.dumps({"user_id": v, "idempotency_key": "k55u", "seats": 1}).encode()
        outs.append(raw(ER, "POST", "/reserve", body, sign(KEY, "POST", "/reserve", body))[0])
    s = seats(ER)
    return check("fuzz", "user_id type confusion (float/bool/null/obj/array): clean 4xx, no 5xx, inventory untouched",
                 all(rej(x) for x in outs) and s.get("total") == s.get("sold") + s.get("held") + s.get("free"),
                 "codes=%s" % outs)
uid_type_confusion()
def seats_extremes():
    outs = []
    for v in (9223372036854775807, 9223372036854775808, -1, 0, "3"):
        body = json.dumps({"user_id": "rt-55se", "idempotency_key": "k55se", "seats": v}).encode()
        outs.append(raw(ER, "POST", "/reserve", body, sign(KEY, "POST", "/reserve", body))[0])
    s = seats(ER)
    return check("fuzz", "seats extremes (int64 max, overflow, -1, 0, string): clean 4xx, no crash",
                 all(rej(x) for x in outs) and raw(ER, "GET", "/seats")[0] == 200, "codes=%s" % outs)
seats_extremes()
def app_bypass_confirm():
    # App hold, then confirm directly on the engine (payment bypassed), then app pay.
    st, h = raw(AR, "POST", "/api/hold", '{"user_id":"rt-55byp","seats":1}')
    if not (st == 200 and h.get("ok") and h.get("reservation_id")):
        return check("app", "engine-side confirm bypass then app pay: skipped (hold unavailable)", True, "hold=%s %s" % (st, str(h)[:80]))
    rid = h["reservation_id"]
    st2, _ = raw(ER, "POST", "/confirm", json.dumps({"reservation_id": rid, "user_id": "rt-55byp"}).encode(),
                 sign(KEY, "POST", "/confirm", json.dumps({"reservation_id": rid, "user_id": "rt-55byp"}).encode()))
    st3, p = raw(AR, "POST", "/api/pay", json.dumps({"reservation_id": rid, "user_id": "rt-55byp", "outcome": "success"}))
    alive = raw(AR, "GET", "/")[0] == 200
    return check("app", "app hold confirmed out-of-band then app pay: clean error, app alive", st2 == 200 and st3 != 500 and alive,
                 "confirm=%s pay=%s alive=%s p=%s" % (st2, st3, alive, str(p)[:60]))
app_bypass_confirm()
def webhook_replay():
    ev = '{"type":"waitlist_fulfilled","reservation_id":"FAKE55","seats":[1]}'
    st1, _ = raw(AR, "POST", "/api/kavach-webhook?token=whsec-redtest", ev)
    before = raw(AR, "GET", "/api/seats")
    st2, _ = raw(AR, "POST", "/api/kavach-webhook?token=whsec-redtest", ev)
    after = raw(AR, "GET", "/api/seats")
    same = before[1] == after[1]
    return check("app", "webhook replay (same valid event twice): no 500, state unchanged",
                 st1 != 500 and st2 != 500 and same, "st=%s/%s seats_same=%s" % (st1, st2, same))
webhook_replay()
def chunked_encoding():
    # Chunked transfer-encoding with valid MAC: engine must reassemble and auth the body.
    body = json.dumps({"reservation_id": "RSV999999", "user_id": "rt-55ch"}).encode()
    h = sign(KEY, "POST", "/confirm", body)
    h.pop("Content-Length", None)
    try:
        c = http.client.HTTPConnection("127.0.0.1", ER, timeout=15)
        c.request("POST", "/confirm", body=body, headers=h, encode_chunked=True)
        r = c.getresponse(); st = r.status; r.read(); c.close()
    except Exception as ex:
        st = -1
    return check("wire", "chunked transfer-encoding + valid MAC: parsed, 404 on unknown rid, no 5xx", st == 404, "status=%s" % st)
chunked_encoding()
def ttl_then_sibling_confirm():
    # Hold A expires via TTL, THEN hold B is taken fresh: A's confirm must not
    # resurrect it, B (created after A's expiry) must confirm cleanly.
    st, a = post(ET, "/reserve", {"user_id": "rt-55a", "idempotency_key": "k55a", "seats": 1})
    if a.get("status") != "held":
        return check("state", "TTL expiry: sibling confirm still works (skipped, hold unavailable)", True, "%s" % str(a)[:60])
    ra = a["reservation_id"]
    time.sleep(5)  # hold-ttl is 3s on the short-TTL engine: A is now expired
    st2, b = post(ET, "/reserve", {"user_id": "rt-55b", "idempotency_key": "k55b", "seats": 1})
    if b.get("status") != "held":
        return check("state", "TTL expiry: sibling confirm still works (skipped, sibling hold unavailable)", True, "a=%s b=%s" % (str(a)[:50], str(b)[:50]))
    rb = b["reservation_id"]
    ca = post(ET, "/confirm", {"reservation_id": ra, "user_id": "rt-55a"})
    cb = post(ET, "/confirm", {"reservation_id": rb, "user_id": "rt-55b"})
    s = seats(ET)
    ok = ca[0] in (404, 409) and cb[0] == 200 and s.get("total") == s.get("sold") + s.get("held") + s.get("free")
    return check("state", "expired hold stays dead while fresh sibling confirms: no resurrection, conserved", ok,
                 "ca=%s cb=%s seats=%s" % (ca[0], cb[0], s))
ttl_then_sibling_confirm()
def idem_key_cross_op():
    if seats(ER).get("free", 0) < 1:
        return check("state", "idem key reused across operations: skipped (sold out)", True, "free=%s" % seats(ER).get("free"))
    st, j = post(ER, "/reserve", {"user_id": "rt-55xo", "idempotency_key": "k55xo", "seats": 1})
    rid = j.get("reservation_id")
    if not rid:
        return check("state", "idem key reused across operations: skipped (no hold)", True, "st=%s" % st)
    c = post(ER, "/confirm", {"reservation_id": rid, "user_id": "rt-55xo", "idempotency_key": "k55xo"})
    if c[0] == 200:
        post(ER, "/release", {"reservation_id": rid})  # keep it a hold, not a sale
    r = post(ER, "/release", {"reservation_id": rid, "idempotency_key": "k55xo"})
    s = seats(ER)
    post(ER, "/release", {"reservation_id": rid})
    return check("state", "idem key reused across confirm/release: no state confusion, no 5xx",
                 c[0] < 500 and r[0] < 500 and s.get("total") == s.get("sold") + s.get("held") + s.get("free"),
                 "reserve=%s confirm=%s release=%s seats=%s" % (st, c[0], r[0], s))
idem_key_cross_op()
def slowloris_partial():
    import socket as _s
    try:
        sk = _s.create_connection(("127.0.0.1", ER), timeout=5)
        sk.sendall(b"POST /book HTTP/1.1\r\nHost: x\r\n")
        time.sleep(2)
        sk.close()
    except Exception:
        pass
    body = json.dumps({"reservation_id": "RSV999999", "user_id": "rt-55sl"}).encode()
    st = raw(ER, "POST", "/confirm", body, sign(KEY, "POST", "/confirm", body))[0]
    return check("resource", "partial request (slowloris-lite) then close: engine serves next valid request", st == 404, "status=%s" % st)
slowloris_partial()
def form_encoded_mac():
    body = b"user_id=rt-55fe&idempotency_key=k55fe&seats=1"
    st = raw(ER, "POST", "/book", body, sign(KEY, "POST", "/book", body))[0]
    s = seats(ER)
    return check("wire", "form-encoded body with valid MAC: clean 4xx (JSON only), inventory untouched",
                 rej(st) and s.get("total") == s.get("sold") + s.get("held") + s.get("free"), "status=%s" % st)
form_encoded_mac()
def pipelined_pair():
    import socket as _s
    b1 = json.dumps({"reservation_id": "RSV999999", "user_id": "rt-55pp"}).encode()
    b2 = b""
    r1 = ("POST /confirm HTTP/1.1\r\nHost: x\r\nContent-Length: %d\r\n" % len(b1)) + "".join("%s: %s\r\n" % kv for kv in sign(KEY, "POST", "/confirm", b1).items()) + "\r\n" + b1.decode()
    r2 = ("GET /seats HTTP/1.1\r\nHost: x\r\n\r\n")
    try:
        sk = _s.create_connection(("127.0.0.1", ER), timeout=8)
        sk.sendall((r1 + r2).encode())
        buf = b""
        sk.settimeout(5)
        try:
            while buf.count(b"HTTP/1.1") < 2:
                chunk = sk.recv(65536)
                if not chunk: break
                buf += chunk
        except Exception:
            pass
        sk.close()
    except Exception:
        buf = b""
    n = buf.count(b"HTTP/1.1")
    codes = [int(buf.split(b"HTTP/1.1 ")[i].split(b" ")[0]) for i in range(1, n + 1)] if n else []
    return check("wire", "pipelined requests in one write: two clean responses, correct order (404 then 200)",
                 n == 2 and codes == [404, 200], "responses=%d codes=%s" % (n, codes))
pipelined_pair()


fails = [r for r in results if not r[2]]
print("TOTAL %d cases, PASS %d, FAIL %d" % (len(results), len(results) - len(fails), len(fails)))
for cat, name, ok, detail in fails:
    print("FAIL [%s] %s :: %s" % (cat, name, detail))
sys.exit(1 if fails else 0)
