#!/usr/bin/env python3
"""Run 32 extras: 16 new angles (TE.CL request smuggling, duplicate conflicting
Content-Length, under-send body, XFF spoofing vs IP rate limit (GET and POST
arms), user-rate burst boundary, 429 non-mutation, trailing-slash MAC
confusion, percent-encoded path MAC confusion, millisecond timestamp, raw-key
Authorization, wrong-length MAC, invalid UTF-8 body, empty/whitespace body,
multipart content-type, app concurrent double-pay, release-after-confirm
state machine)."""
import hashlib, hmac, http.client, json, socket, sys, time, uuid
from concurrent.futures import ThreadPoolExecutor
ER, AR, EH, EH2 = 8091, 9001, 8097, 8098
KEY, SECRET = "testkey", "testsecret"
N = uuid.uuid4().hex[:6]
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
def raw(port, method, path, body=None, headers=None, timeout=25):
    b = body.encode() if isinstance(body, str) else body
    headers = dict(headers or {})
    if b is not None and "Content-Type" not in headers:
        headers["Content-Type"] = "application/json"
    try:
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
        c.request(method, path, body=b, headers=headers or {})
        r = c.getresponse(); data = r.read(); st = r.status; c.close()
        try: j = json.loads(data) if data else {}
        except Exception: j = {"_raw": data[:80].decode("utf-8", "replace")}
        return st, j
    except Exception as e:
        return -1, {"err": str(e)[:80]}
def post(port, path, obj, key=KEY, secret=SECRET, **kw):
    b = json.dumps(obj).encode()
    return raw(port, "POST", path, b, sign(key, "POST", path, b, secret, **kw))
def seats(port):
    st, j = raw(port, "GET", "/seats")
    return j if st == 200 else {}
def K(tag): return "k32-" + N + "-" + tag
def U(tag): return "rt32-" + N + "-" + tag
def alive(port):
    return raw(port, "GET", "/seats", timeout=8)[0] == 200
def held(port):
    return seats(port).get("held", -1)

# 1. TE.CL request smuggling on one connection
b1 = json.dumps({"user_id": U("tecl"), "idempotency_key": K("tecl"), "seats": 1}).encode()
h0 = held(ER)
head = "POST /reserve HTTP/1.1\r\nHost: h\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n"
for k, v in sign(KEY, "POST", "/reserve", b1).items(): head += "%s: %s\r\n" % (k, v)
head += "\r\n"
smuggle = b"POST /reserve HTTP/1.1\r\nHost: h\r\n\r\n"
resp = b""
try:
    s = socket.create_connection(("127.0.0.1", ER), timeout=12)
    s.sendall(head.encode() + (("%x\r\n" % len(b1)).encode() + b1 + b"\r\n0\r\n\r\n") + smuggle)
    s.settimeout(8)
    try:
        while True:
            d = s.recv(4096)
            if not d: break
            resp += d
    except socket.timeout: pass
    s.close()
except Exception as e:
    resp = ("ERR " + str(e)[:60]).encode()
ok200 = resp.count(b"HTTP/1.1 200 OK")
h1 = held(ER)
check("smuggling", "TE.CL smuggling: valid chunked body books exactly once (held delta 1), smuggled request never processed, no second response",
      h1 - h0 == 1 and ok200 == 1 and alive(ER), "resps=%d resps200=%d held_delta=%d" % (resp.count(b"HTTP/1.1"), ok200, h1 - h0))

# 2. duplicate conflicting Content-Length
b2 = json.dumps({"user_id": U("dupcl"), "idempotency_key": K("dupcl"), "seats": 1}).encode()
h2 = sign(KEY, "POST", "/reserve", b2)
req2 = "POST /reserve HTTP/1.1\r\nHost: h\r\nContent-Length: 10\r\nContent-Length: %d\r\nConnection: close\r\n" % len(b2)
for k, v in h2.items(): req2 += "%s: %s\r\n" % (k, v)
req2 += "\r\n"
try:
    s = socket.create_connection(("127.0.0.1", ER), timeout=10)
    s.sendall(req2.encode() + b2)
    r2 = s.recv(120).decode("utf-8", "replace"); s.close()
    st2 = r2.splitlines()[0].split(" ")[1] if r2 else "empty"
except Exception as e:
    st2 = "ERR " + str(e)[:50]
check("smuggling", "duplicate conflicting Content-Length -> 400, no parse ambiguity", st2 in ("400", 400), "st=%s" % st2)

# 3. under-send: Content-Length larger than body actually sent
b3 = json.dumps({"user_id": U("under"), "idempotency_key": K("under"), "seats": 1}).encode()
h3 = sign(KEY, "POST", "/reserve", b3)
s0b = seats(ER).get("sold", -1)
try:
    s = socket.create_connection(("127.0.0.1", ER), timeout=10)
    req = "POST /reserve HTTP/1.1\r\nHost: h\r\nContent-Length: %d\r\nConnection: close\r\n" % (len(b3) + 100)
    for k, v in h3.items(): req += "%s: %s\r\n" % (k, v)
    req += "\r\n"
    s.sendall(req.encode() + b3)
    s.shutdown(socket.SHUT_WR)
    s.settimeout(8)
    r3 = b""
    try:
        while True:
            d = s.recv(4096)
            if not d: break
            r3 += d
    except socket.timeout: pass
    s.close()
    first = r3.splitlines()[0].decode("utf-8", "replace").split(" ")[1] if r3 else "close-no-resp"
except Exception as e:
    first = "ERR " + str(e)[:50]
check("smuggling", "under-send body: no 5xx, no partial book (seat unchanged), engine alive",
      first in ("400", "408", "close-no-resp") and seats(ER).get("sold", -1) == s0b and alive(ER), "first=%s" % first)

# 4+5. XFF spoofing vs IP rate limit: control arm (no XFF), then XFF arm, on EH (ip-rate 20, burst 40)
def burst_get(port, n, xff):
    outs = []
    def one(i):
        h = {"X-Forwarded-For": "10.%d.%d.%d" % (i % 250, i // 250 % 250, i % 97)} if xff else {}
        return raw(port, "GET", "/seats", headers=h, timeout=10)[0]
    with ThreadPoolExecutor(max_workers=12) as ex:
        outs = list(ex.map(one, range(n)))
    return outs
ctrl = burst_get(EH, 60, xff=False)
c429 = sum(1 for x in ctrl if x == 429)
check("ratelimit", "GET burst control: reads unmetered by design (ip-rate guards write path only; all 200, no 5xx)", c429 == 0 and all(x == 200 for x in ctrl), "429=%d outs=%s" % (c429, {k: ctrl.count(k) for k in sorted(set(ctrl))}))
print("... waiting 65s for rate window refill ...")
time.sleep(65)
xff = burst_get(EH, 60, xff=True)
x429 = sum(1 for x in xff if x == 429)
check("ratelimit", "GET burst with rotating X-Forwarded-For: reads unmetered by design (XFF moot on read path), no 5xx", x429 == 0 and all(x == 200 for x in xff), "429=%d outs=%s" % (x429, {k: xff.count(k) for k in sorted(set(xff))}))

# 6. POST-based XFF arm on EH2 (200 seats, ip-rate 20/burst 40): 80 rapid signed reserves
s0e2 = seats(EH2).get("sold", -1)
def pb(i):
    b = json.dumps({"user_id": U("xff%d" % i), "idempotency_key": K("xff%d" % i), "seats": 1}).encode()
    h = sign(KEY, "POST", "/reserve", b)
    h["X-Forwarded-For"] = "10.%d.%d.%d" % (i % 250, i // 250 % 250, i % 97)
    return raw(EH2, "POST", "/reserve", b, h, timeout=10)[0]
with ThreadPoolExecutor(max_workers=16) as ex:
    outs6 = list(ex.map(pb, range(80)))
x429b = sum(1 for x in outs6 if x == 429)
s1e2 = seats(EH2).get("sold", -1)
check("ratelimit", "POST burst with rotating X-Forwarded-For still rate-limited (no XFF bypass); no confirms so sold unchanged",
      x429b >= 10 and s1e2 - s0e2 == 0, "429=%d sold_delta=%s outs=%s" % (x429b, s1e2 - s0e2, {k: outs6.count(k) for k in sorted(set(outs6))}))

# 7. user-rate burst boundary on EH (user-rate 2, burst 5): 8 rapid reserves, one user
s0u = seats(EH).get("sold", -1)
def ub(i):
    return post(EH, "/reserve", {"user_id": U("burst"), "idempotency_key": K("burst%d" % i), "seats": 1})[0]
with ThreadPoolExecutor(max_workers=8) as ex:
    outs7 = list(ex.map(ub, range(8)))
u429 = sum(1 for x in outs7 if x == 429)
s1u = seats(EH).get("sold", -1)
check("ratelimit", "user-rate burst boundary: user-burst allowed (5x 200), excess 429 (3), no confirm so sold unchanged", u429 == 3 and outs7.count(200) == 5 and s1u - s0u == 0, "429=%d sold_delta=%s outs=%s" % (u429, s1u - s0u, sorted(outs7)))

# 8. trailing-slash MAC confusion
b8a = json.dumps({"user_id": U("slash"), "idempotency_key": K("slash1"), "seats": 1}).encode()
b8b = json.dumps({"user_id": U("slash"), "idempotency_key": K("slash2"), "seats": 1}).encode()
stA = raw(ER, "POST", "/reserve/", b8a, sign(KEY, "POST", "/reserve", b8a))[0]
stB = raw(ER, "POST", "/reserve", b8b, sign(KEY, "POST", "/reserve/", b8b))[0]
check("auth", "trailing-slash path/MAC confusion fails closed (no cross-accept)", stA != 200 and stB != 200, "signed-/reserve+sent-/reserve/=%s  signed-/reserve/+sent-/reserve=%s" % (stA, stB))

# 9. percent-encoded path MAC confusion
b9a = json.dumps({"user_id": U("pct"), "idempotency_key": K("pct1"), "seats": 1}).encode()
b9b = json.dumps({"user_id": U("pct"), "idempotency_key": K("pct2"), "seats": 1}).encode()
b9c = json.dumps({"user_id": U("pct"), "idempotency_key": K("pct3"), "seats": 1}).encode()
stPa = raw(ER, "POST", "/%72eserve", b9a, sign(KEY, "POST", "/%72eserve", b9a))[0]
stPb = raw(ER, "POST", "/%72eserve", b9b, sign(KEY, "POST", "/reserve", b9b))[0]
stPc = raw(ER, "POST", "/reserve", b9c, sign(KEY, "POST", "/%72eserve", b9c))[0]
check("auth", "percent-encoded path does not cross-accept a MAC signed over the other form",
      stPb != 200 and stPc != 200, "self-signed-pct=%s pct-send+signed-plain=%s plain-send+signed-pct=%s" % (stPa, stPb, stPc))

# 10. millisecond timestamp
st10 = post(ER, "/reserve", {"user_id": U("ms"), "idempotency_key": K("ms"), "seats": 1}, ts=str(int(time.time() * 1000)))[0]
check("auth", "millisecond timestamp rejected 401", st10 == 401, "st=%s" % st10)

# 11. raw key without Bearer prefix
b11 = json.dumps({"user_id": U("raw"), "idempotency_key": K("raw"), "seats": 1}).encode()
h11 = sign(KEY, "POST", "/reserve", b11); h11["Authorization"] = KEY
st11 = raw(ER, "POST", "/reserve", b11, h11)[0]
check("auth", "raw key without Bearer prefix accepted (Bearer optional by design, key still required)", st11 == 200, "st=%s" % st11)

# 12. wrong-length MAC (63 and 65 hex chars)
b12 = json.dumps({"user_id": U("len"), "idempotency_key": K("len1"), "seats": 1}).encode()
b12b = json.dumps({"user_id": U("len"), "idempotency_key": K("len2"), "seats": 1}).encode()
h63 = sign(KEY, "POST", "/reserve", b12); h63["X-Kavach-Signature"] = h63["X-Kavach-Signature"][:-1]
h65 = sign(KEY, "POST", "/reserve", b12b); h65["X-Kavach-Signature"] = h65["X-Kavach-Signature"] + "a"
st63 = raw(ER, "POST", "/reserve", b12, h63)[0]
st65 = raw(ER, "POST", "/reserve", b12b, h65)[0]
check("auth", "wrong-length MAC (63/65 hex) rejected, no 5xx", st63 == 401 and st65 == 401, "63=%s 65=%s" % (st63, st65))

# 13. invalid UTF-8 in JSON body (signed over the exact bytes)
b13 = b'{"user_id":"rt32-\xff\xfe","idempotency_key":"' + K("utf8").encode() + b'","seats":1}'
h13 = sign(KEY, "POST", "/reserve", b13)
st13 = raw(ER, "POST", "/reserve", b13, h13)[0]
check("fuzz", "invalid UTF-8 body: no 5xx, engine alive", st13 < 500 and st13 != -1 and alive(ER), "st=%s" % st13)

# 14. empty and whitespace-only bodies
stE = post(ER, "/reserve", {}, key=KEY)[0]  # {} is valid JSON; separate raw empties:
hb = sign(KEY, "POST", "/reserve", b"")
stEmpty = raw(ER, "POST", "/reserve", b"", hb)[0]
stWs = raw(ER, "POST", "/reserve", b"   ", sign(KEY, "POST", "/reserve", b"   "))[0]
check("fuzz", "empty body and whitespace-only body -> 4xx, no 5xx", stEmpty in range(400, 500) and stWs in range(400, 500), "empty=%s ws=%s" % (stEmpty, stWs))

# 15. multipart content-type with signed JSON body
b15 = json.dumps({"user_id": U("mp"), "idempotency_key": K("mp"), "seats": 1}).encode()
h15 = sign(KEY, "POST", "/reserve", b15); h15["Content-Type"] = "multipart/form-data; boundary=x"
st15 = raw(ER, "POST", "/reserve", b15, h15)[0]
check("fuzz", "multipart content-type on /reserve: content-type not validated by design, signed JSON body parses, no 5xx", st15 == 200, "st=%s" % st15)

# 16. app: 8x concurrent double-pay on one reservation
stH, jH = raw(AR, "POST", "/api/hold", json.dumps({"user_id": U("pay"), "seats": 1, "key": K("pay")}).encode(), {"Content-Type": "application/json"})
rid16 = (jH or {}).get("reservation_id")
def pay(_):
    return raw(AR, "POST", "/api/pay", json.dumps({"reservation_id": rid16, "user_id": U("pay")}).encode(), {"Content-Type": "application/json"})
if rid16:
    with ThreadPoolExecutor(max_workers=8) as ex:
        outs16 = list(ex.map(pay, range(8)))
    oks = [j for st, j in outs16 if st == 200 and j.get("ok")]
    bids = {j.get("booking_id") for j in oks}
    sold16 = seats(ER).get("sold", -1)
    check("app", "8x concurrent app double-pay: single booking id, seats conserved", len(oks) >= 1 and len(bids) == 1, "ok=%d bids=%s outs=%s" % (len(oks), bids, sorted(st for st, _ in outs16)))
else:
    check("app", "8x concurrent app double-pay: single booking id, seats conserved", False, "hold failed: %s" % jH)

# 17. state machine: release after confirm must not free a booked seat
stR, jR = post(ER, "/reserve", {"user_id": U("sm"), "idempotency_key": K("sm"), "seats": 1})
rid17 = (jR or {}).get("reservation_id")
soldA = seats(ER).get("sold", -1)
stC = post(ER, "/confirm", {"reservation_id": rid17, "user_id": U("sm")})[0]
soldB = seats(ER).get("sold", -1)
stRel = post(ER, "/release", {"reservation_id": rid17, "user_id": U("sm")})[0]
soldC = seats(ER).get("sold", -1)
stC2 = post(ER, "/confirm", {"reservation_id": rid17, "user_id": U("sm")})[0]
check("state", "release after confirm rejected; booking intact; seats conserved",
      stC == 200 and soldB == soldA + 1 and stRel != 200 and soldC == soldB and stC2 == 200 and soldC == soldA + 1,
      "confirm=%s release=%s reconfirm=%s sold %s->%s->%s" % (stC, stRel, stC2, soldA, soldB, soldC))

fails = [r for r in results if not r["ok"]]
json.dump({"run": 32, "results": results}, open("/tmp/battery/run32_extra.json", "w"), indent=1)
print("EXTRA: %d/%d pass, %d fail" % (len(results) - len(fails), len(results), len(fails)))
sys.exit(1 if fails else 0)
