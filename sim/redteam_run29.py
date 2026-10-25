#!/usr/bin/env python3
"""Run 29 extras: 14 new angles (cross-tenant idem isolation, rid cross-path
replay, timestamp edge/space, duplicate auth headers, CRLF log injection,
homoglyph user isolation, cross-user confirm, idem-with-different-seats,
chunked transfer, deep JSON nesting, waitlist double-cancel, app webhook
token placement, app hold type fuzz, body shape fuzz)."""
import hashlib, hmac, http.client, json, socket, sys, time, uuid
ER, AR, ER2, ET, EH = 8091, 9001, 8092, 8095, 8097
KEY, KEY2, SECRET = "testkey", "otherkey", "testsecret"
results = []
def check(cat, name, ok, detail=""):
    results.append({"cat": cat, "name": name, "ok": bool(ok), "detail": str(detail)[:220]})
    print(("PASS" if ok else "FAIL"), name, ("| " + str(detail)[:120]) if detail else "")
    return ok
def sign(key, method, path, body, secret=SECRET, ts=None, rid=None):
    ts = str(int(time.time())) if ts is None else ts
    rid = uuid.uuid4().hex if rid is None else rid
    mac = hmac.new(secret.encode(), (ts + "\n" + rid + "\n" + method + "\n" + path + "\n" + key + "\n").encode() + body, hashlib.sha256)
    return {"Authorization": "Bearer " + key, "X-Kavach-Timestamp": ts,
            "X-Kavach-Request-Id": rid, "X-Kavach-Signature": mac.hexdigest(),
            "Content-Type": "application/json"}
def raw(port, method, path, body=None, headers=None, host="127.0.0.1"):
    b = body.encode() if isinstance(body, str) else body
    headers = dict(headers or {})
    if b is not None and "Content-Type" not in headers:
        headers["Content-Type"] = "application/json"
    try:
        c = http.client.HTTPConnection(host, port, timeout=25)
        c.request(method, path, body=b, headers=headers or {})
        r = c.getresponse(); data = r.read(); st = r.status; c.close()
        try:
            j = json.loads(data) if data else {}
        except Exception:
            j = {"raw": data[:150].decode("utf-8", "replace")}
        return st, j
    except Exception as ex:
        return -1, {"exception": str(ex)[:120]}
def req(port, method, path, obj=None, key=KEY, secret=SECRET, **kw):
    body = json.dumps(obj).encode() if obj is not None else b""
    return raw(port, method, path, body, sign(key, method, path, body, secret, **kw))
def post(port, path, obj, **kw):
    return req(port, "POST", path, obj, **kw)
def seats(port):
    return raw(port, "GET", "/seats")[1]
def rawsock(port, method, path, header_lines, body=b""):
    # truly duplicate header lines over a raw socket
    reqline = "%s %s HTTP/1.1\r\nHost: 127.0.0.1\r\n" % (method, path)
    for k, v in header_lines:
        reqline += "%s: %s\r\n" % (k, v)
    reqline += "Content-Length: %d\r\nConnection: close\r\n\r\n" % len(body)
    try:
        s = socket.create_connection(("127.0.0.1", port), timeout=10)
        s.sendall(reqline.encode("latin-1") + body)
        chunks = []
        while True:
            d = s.recv(65536)
            if not d: break
            chunks.append(d)
        s.close()
        data = b"".join(chunks)
        st = int(data.split(b" ")[1]) if b" " in data.split(b"\r\n", 1)[0] else -1
        return st, data[:200].decode("utf-8", "replace")
    except Exception as ex:
        return -1, str(ex)[:120]
def chunked(port, method, path, obj, key=KEY, secret=SECRET):
    body = json.dumps(obj).encode()
    h = sign(key, method, path, body, secret)
    hdr = method + " " + path + " HTTP/1.1\r\nHost: 127.0.0.1\r\n"
    for k, v in h.items():
        hdr += "%s: %s\r\n" % (k, v)
    hdr += "Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
    wire = hdr.encode("latin-1") + ("%x\r\n" % len(body)).encode() + body + b"\r\n0\r\n\r\n"
    try:
        s = socket.create_connection(("127.0.0.1", port), timeout=10)
        s.sendall(wire)
        chunks = []
        while True:
            d = s.recv(65536)
            if not d: break
            chunks.append(d)
        s.close()
        data = b"".join(chunks)
        st = int(data.split(b" ")[1]) if b" " in data.split(b"\r\n", 1)[0] else -1
        return st, data[:200].decode("utf-8", "replace")
    except Exception as ex:
        return -1, str(ex)[:120]

s0 = seats(ER)
# 1. cross-tenant idem key isolation
r1 = post(ER, "/reserve", {"user_id": "rt29-xt", "idempotency_key": "k29-xt", "seats": 1})
r2 = post(ER, "/reserve", {"user_id": "rt29-xt", "idempotency_key": "k29-xt", "seats": 1}, key=KEY2)
ok = r1[0] == 200 and (r2[0] == 409 or (r2[0] == 200 and r2[1].get("reservation_id") != r1[1].get("reservation_id")))
ok = ok and r2[0] < 500
check("xtenant", "same idem key across tenants: isolated or clean 409, no leak", ok, "%s rid1=%s | %s rid2=%s" % (r1[0], r1[1].get("reservation_id"), r2[0], r2[1].get("reservation_id") if isinstance(r2[1], dict) else r2[1]))
# 2. rid reuse across different path/method
rid = (r1[1] or {}).get("reservation_id") if r1[0] == 200 else None
if rid:
    s_before = seats(ER)
    st, j = raw(ER, "GET", "/seats", None, sign(KEY, "GET", "/seats", b"", rid=rid))
    ok = st in (200, 401) and seats(ER) == s_before
    check("replay", "reserve rid reused as GET /seats request-id: deterministic clean", ok, "st=%s" % st)
else:
    check("replay", "reserve rid reused across path", False, "reserve failed %s" % r1[0])
# 3. timestamp just inside window + spaces
ts_in = str(int(time.time()) + 290)
r3 = post(ER, "/reserve", {"user_id": "rt29-tsin", "idempotency_key": "k29-tsin", "seats": 1}, ts=ts_in)
check("auth", "timestamp +290s (inside window) accepted", r3[0] == 200, str(r3[0]))
ts_sp = " %d " % int(time.time())
r3b = post(ER, "/reserve", {"user_id": "rt29-tssp", "idempotency_key": "k29-tssp", "seats": 1}, ts=ts_sp)
check("auth", "timestamp with surrounding spaces cleanly rejected", r3b[0] in (400, 401), str(r3b[0]))
# 4. duplicate Authorization headers (two different keys) via raw socket
body = json.dumps({"user_id": "rt29-dup", "idempotency_key": "k29-dup", "seats": 1}).encode()
h = sign(KEY, "POST", "/reserve", body)
hl = [("Authorization", "Bearer " + KEY), ("Authorization", "Bearer " + KEY2)] + \
     [(k, v) for k, v in h.items() if k != "Authorization" and k != "Content-Type"]
st1, _ = rawsock(ER, "POST", "/reserve", hl, body)
h2 = sign(KEY, "POST", "/reserve", body)
hl2 = [("Authorization", "Bearer " + KEY), ("Authorization", "Bearer " + KEY2)] + \
     [(k, v) for k, v in h2.items() if k != "Authorization" and k != "Content-Type"]
st2, _ = rawsock(ER, "POST", "/reserve", hl2, body)
check("auth", "duplicate Authorization headers: deterministic, no 5xx", st1 == st2 and st1 in (200, 400, 401) and st1 < 500, "%s then %s" % (st1, st2))
# 5. CRLF / newline in user_id (log injection)
sA = seats(ER)
r5 = post(ER, "/reserve", {"user_id": "rt29\nEVIL", "idempotency_key": "k29-crlf", "seats": 1})
ok = r5[0] in (400, 422)
if r5[0] == 200:
    rid5 = r5[1].get("reservation_id")
    c5 = post(ER, "/confirm", {"reservation_id": rid5, "user_id": "rt29\nEVIL"})
    ok = c5[0] == 200
    if ok:
        try:
            lines = open("/tmp/battery/state/bt8091_bookings.jsonl", "rb").read().strip().split(b"\n")
            ok = json.loads(lines[-1].decode("utf-8", "replace")) is not None
        except Exception as ex:
            ok = False
            r5 = (r5[0], str(ex)[:80])
check("log", "newline in user_id: rejected or log stays single-line JSON", ok, "reserve=%s %s" % (r5[0], r5[1] if not ok else ""))
# 6. homoglyph user isolation (Cyrillic a vs Latin a)
sB = seats(ER)
r6 = post(ER, "/reserve", {"user_id": "u\u043029", "idempotency_key": "k29-hg", "seats": 1})
rid6 = r6[1].get("reservation_id") if r6[0] == 200 else None
c6 = post(ER, "/confirm", {"reservation_id": rid6, "user_id": "ua29"}) if rid6 else (-1, {})
check("state", "homoglyph user cannot confirm another user's hold", c6[0] in (403, 404, 409), "reserve=%s confirm=%s" % (r6[0], c6[0]))
# 7. plain cross-user confirm (probe: capability-token design?)
r7 = post(ER, "/reserve", {"user_id": "rt29-u1", "idempotency_key": "k29-xu", "seats": 1})
rid7 = r7[1].get("reservation_id") if r7[0] == 200 else None
c7 = post(ER, "/confirm", {"reservation_id": rid7, "user_id": "rt29-u2"}) if rid7 else (-1, {})
soldA = seats(ER)["sold"]
check("state", "cross-user confirm rejected (same tenant, different user_id)", c7[0] in (403, 404, 409), "reserve=%s confirm=%s sold=%s" % (r7[0], c7[0], soldA))
# 8. same idem key, different seats payload
sC = seats(ER)
r8a = post(ER, "/reserve", {"user_id": "rt29-ds", "idempotency_key": "k29-ds", "seats": 1})
r8b = post(ER, "/reserve", {"user_id": "rt29-ds", "idempotency_key": "k29-ds", "seats": 3})
ridA = r8a[1].get("reservation_id") if r8a[0] == 200 else None
ridB = r8b[1].get("reservation_id") if isinstance(r8b[1], dict) and r8b[0] == 200 else None
sC2 = seats(ER)
ok = r8b[0] < 500 and (r8b[0] == 409 or (ridB == ridA and sC2["free"] == sC["free"] - 1))
check("state", "idem key reuse with different seats: replay or clean 409, no extra hold", ok, "a=%s b=%s rid_same=%s free %s->%s" % (r8a[0], r8b[0], ridA == ridB, sC["free"], sC2["free"]))
# 9. chunked transfer-encoding
sD = seats(ER)
r9 = chunked(ER, "POST", "/reserve", {"user_id": "rt29-ch", "idempotency_key": "k29-ch", "seats": 1})
check("fuzz", "chunked transfer-encoding handled cleanly", r9[0] in (200, 400, 411, 422), "st=%s %s" % (r9[0], r9[1][:80] if isinstance(r9[1], str) else ""))
# 10. deep JSON nesting
deep = ("{\"seats\":1,\"user_id\":\"rt29-deep\",\"idempotency_key\":\"k29-deep\",\"x\":" + "[" * 500 + "]" * 500 + "}").encode()
r10 = raw(ER, "POST", "/reserve", deep, sign(KEY, "POST", "/reserve", deep))
check("fuzz", "500-deep JSON nesting: no 5xx, engine alive", r10[0] < 500 and seats(ER)["total"] == 50, "st=%s" % r10[0])
# 11. waitlist double-cancel + duplicate idem join
w1 = post(ER2, "/waitlist", {"user_id": "rt29-wl", "idempotency_key": "k29-wl", "seats": 1})
wid = w1[1].get("waitlist_id") if w1[0] == 200 else None
cx1 = post(ER2, "/waitlist/cancel", {"waitlist_id": wid}) if wid else (-1, {})
cx2 = post(ER2, "/waitlist/cancel", {"waitlist_id": wid}) if wid else (-1, {})
w2 = post(ER2, "/waitlist", {"user_id": "rt29-wl", "idempotency_key": "k29-wl", "seats": 1})
ok = w1[0] == 200 and cx1[0] == 200 and cx2[0] in (200, 404) and w2[0] < 500
check("state", "waitlist cancel twice: second clean; idem re-join deterministic", ok, "join=%s c1=%s c2=%s rejoin=%s" % (w1[0], cx1[0], cx2[0], w2[0]))
# 12. app webhook token placement
h401 = raw(AR, "POST", "/api/kavach-webhook", json.dumps({"event": "confirmed", "reservation_id": "RSV1"}).encode(), {"X-Webhook-Token": "whsec-redtest"})
b401 = raw(AR, "POST", "/api/kavach-webhook", json.dumps({"token": "whsec-redtest", "event": "confirmed"}).encode())
g400 = raw(AR, "POST", "/api/kavach-webhook?token=whsec-redtest", b"not-json{{", {"Content-Type": "application/json"})
check("app", "webhook token only in query; garbage body handled clean", h401[0] in (400, 401, 403) and b401[0] in (400, 401, 403) and g400[0] < 500, "hdr=%s body=%s garbage=%s" % (h401[0], b401[0], g400[0]))
# 13. app hold type fuzz
a1 = raw(AR, "POST", "/api/hold", json.dumps({"user_id": "rt29-app", "seats": "2"}))
a2 = raw(AR, "POST", "/api/hold", json.dumps({"user_id": "rt29-app", "seats": 1.5}))
check("app", "app /api/hold rejects string/float seats cleanly", a1[0] < 500 and a2[0] < 500 and not (isinstance(a1[1], dict) and a1[1].get("ok")), "%s %s | %s %s" % (a1[0], a2[0], str(a1[1])[:60], str(a2[1])[:60]))
# 14. body shape fuzz: /book without idem key, /release typed rid
r14a = post(ER, "/book", {"user_id": "rt29-bf", "seats": 1})
r14b = post(ER, "/release", {"reservation_id": 12345})
r14c = post(ER, "/release", {"reservation_id": [1, 2]})
check("fuzz", "/book no idem key + /release typed rid: all clean 4xx", r14a[0] in (400, 422) and r14b[0] in (400, 404, 422) and r14c[0] in (400, 404, 422), "%s %s %s" % (r14a[0], r14b[0], r14c[0]))

fails = [r for r in results if not r["ok"]]
json.dump({"run": 29, "results": results}, open("/tmp/battery/run29_extra.json", "w"), indent=1)
print("EXTRA: %d/%d pass, %d fail" % (len(results) - len(fails), len(results), len(fails)))
sys.exit(1 if fails else 0)
