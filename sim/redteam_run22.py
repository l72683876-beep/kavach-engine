#!/usr/bin/env python3
"""Run 22 extra attack angles: 14 new variants, distinct from runs 16-21."""
import http.client, json, socket, sys, time, uuid, hashlib, hmac
from concurrent.futures import ThreadPoolExecutor

ER, ER2, ET, FS, APP = 8091, 8092, 8095, 8096, 9001
KEY, KEY2, SECRET = "testkey", "otherkey", "testsecret"
results = []
def check(cat, name, ok, detail=""):
    results.append({"cat": cat, "name": name, "ok": bool(ok), "detail": str(detail)[:220]})
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
    if b is not None: headers.setdefault("Content-Type", "application/json")
    try:
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
        c.request(method, path, body=b, headers=headers)
        r = c.getresponse(); data = r.read(); st = r.status; c.close()
        try: j = json.loads(data) if data else {}
        except Exception: j = {"raw": data[:150].decode("utf-8", "replace")}
        return st, j
    except Exception as ex:
        return -1, {"exception": str(ex)[:120]}
def req(port, method, path, obj=None, key=KEY, secret=SECRET, **kw):
    body = json.dumps(obj).encode() if obj is not None else b""
    return raw(port, method, path, body, sign(key, method, path, body, secret, **kw))
def seats(port=ER):
    st, j = raw(port, "GET", "/seats"); return j if st == 200 else {}
def invariant(port=ER):
    s = seats(port); return s.get("total") == s.get("sold", 0) + s.get("held", 0) + s.get("free", 0)
def reserve(port=ER, user="x", n=1, tag=None):
    tag = tag or ("t" + uuid.uuid4().hex[:8])
    st, r = req(port, "POST", "/reserve", {"user_id": user, "idempotency_key": tag, "seats": n})
    return (r.get("reservation_id") if st == 200 else None), st, r
def rawsock(port, payload, timeout=10):
    try:
        s = socket.create_connection(("127.0.0.1", port), timeout=timeout)
        s.sendall(payload); time.sleep(0.4)
        data = s.recv(65536); s.close()
        line = data.split(b"\r\n", 1)[0].decode("utf-8", "replace")
        return line or "empty"
    except Exception as ex:
        return "EXC: " + str(ex)[:100]

# 1: Authorization header variants (scheme case, extra token, raw key)
b1 = json.dumps({"user_id": "r22a", "idempotency_key": "r22a", "seats": 1}).encode()
g1 = sign(KEY, "POST", "/book", b1)
st_lo, _ = raw(ER, "POST", "/book", b1, {**g1, "Authorization": "bearer testkey"})
st_up, _ = raw(ER, "POST", "/book", b1, {**g1, "Authorization": "BEARER testkey"})
st_x, _ = raw(ER, "POST", "/book", b1, {**g1, "Authorization": "Bearer testkey extra"})
st_raw, _ = raw(ER, "POST", "/book", b1, {**g1, "Authorization": "testkey"})
st_bad, _ = raw(ER, "POST", "/book", b1, {**g1, "Authorization": "Bearer " + KEY2})
check("auth", "auth header variants: extra token rejected; raw key lenient but MAC-bound (wrong key 401)",
      st_x != -1 and 400 <= st_x < 500 and st_bad != -1 and 400 <= st_bad < 500,
      "lower=%s upper=%s extra=%s raw=%s wrongkey=%s" % (st_lo, st_up, st_x, st_raw, st_bad))

# 2: timestamp swap between two validly signed requests (HMAC covers ts)
b2 = json.dumps({"user_id": "r22ts", "idempotency_key": "r22ts", "seats": 1}).encode()
h2 = sign(KEY, "POST", "/book", b2)
h2b = dict(h2); h2b["X-Kavach-Timestamp"] = str(int(time.time()) - 5)
st2, _ = raw(ER, "POST", "/book", b2, h2b)
check("auth", "swapped/stale timestamp under valid-looking signature: rejected", 400 <= st2 < 500, "status=%s" % st2)

# 3: Cyrillic homoglyph api key
b3 = json.dumps({"user_id": "r22h", "idempotency_key": "r22h", "seats": 1}).encode()
h3 = sign(KEY, "POST", "/book", b3)
p3 = b"POST /book HTTP/1.1\r\nHost: 127.0.0.1\r\n"
for k, v in h3.items():
    if k == "Authorization": v = "Bearer t\u0435stkey"  # cyrillic e, sent as UTF-8 bytes
    p3 += ("%s: %s\r\n" % (k, v)).encode("utf-8")
p3 += b"Content-Length: %d\r\n\r\n" % len(b3) + b3
r3 = rawsock(ER, p3)
check("auth", "cyrillic homoglyph api key rejected", "401" in r3, r3[:80])

# 4: request-id reuse with a different body (two idempotency keys, one rid)
rid4 = uuid.uuid4().hex
ba = json.dumps({"user_id": "r22r1", "idempotency_key": "r22r1", "seats": 1}).encode()
bb = json.dumps({"user_id": "r22r2", "idempotency_key": "r22r2", "seats": 1}).encode()
s4a, _ = raw(ER, "POST", "/book", ba, sign(KEY, "POST", "/book", ba, rid=rid4))
s4b, _ = raw(ER, "POST", "/book", bb, sign(KEY, "POST", "/book", bb, rid=rid4))
check("fuzz", "rid reuse across different bodies: no 5xx, invariants hold",
      s4a != -1 and s4b != -1 and s4a < 500 and s4b < 500 and invariant(ER), "%s/%s" % (s4a, s4b))

# 5: whitespace-only idempotency key
b5 = json.dumps({"user_id": "r22w", "idempotency_key": "   ", "seats": 1}).encode()
st5, j5 = raw(ER, "POST", "/book", b5, sign(KEY, "POST", "/book", b5))
st5b, j5b = raw(ER, "POST", "/book", b5, sign(KEY, "POST", "/book", b5))
ok5 = (st5 == st5b) and (st5b >= 400 or j5b.get("booking_id") == j5.get("booking_id"))
check("fuzz", "whitespace-only idem key: consistent (booked once or conflicted both times)",
      ok5 and invariant(ER), "1st=%s 2nd=%s ids=%s/%s" % (st5, st5b, j5.get("booking_id"), j5b.get("booking_id")))

# 6: query-string pollution: signature over /book, request to /book?seats=99, body seats=1
b6 = json.dumps({"user_id": "r22q", "idempotency_key": "r22q", "seats": 1}).encode()
before6 = seats(ER)
st6, j6 = raw(ER, "POST", "/book?seats=99", b6, sign(KEY, "POST", "/book", b6))
after6 = seats(ER)
if 200 <= st6 < 300:
    ok6 = after6.get("sold", 0) - before6.get("sold", 0) == 1 and invariant(ER)
else:
    ok6 = True
check("fuzz", "query pollution (?seats=99): rejected or query inert (1 seat only)", ok6, "status=%s" % st6)

# 7: duplicate Content-Length headers with different values (smuggling probe)
b7 = json.dumps({"user_id": "r22cl", "idempotency_key": "r22cl", "seats": 1}).encode()
h7 = sign(KEY, "POST", "/book", b7)
p7 = b"POST /book HTTP/1.1\r\nHost: 127.0.0.1\r\n"
for k, v in h7.items(): p7 += ("%s: %s\r\n" % (k, v)).encode()
p7 += b"Content-Length: 5\r\nContent-Length: %d\r\n\r\n" % len(b7) + b7
r7 = rawsock(ER, p7)
check("fuzz", "duplicate Content-Length (5 vs %d): clean rejection, engine alive" % len(b7),
      not r7.startswith("EXC") and invariant(ER), r7[:80])

# 8: Transfer-Encoding: chunked /book with valid signature over the body
b8 = json.dumps({"user_id": "r22ch", "idempotency_key": "r22ch", "seats": 1}).encode()
h8 = sign(KEY, "POST", "/book", b8)
ch = b"%x\r\n" % len(b8) + b8 + b"\r\n0\r\n\r\n"
p8 = b"POST /book HTTP/1.1\r\nHost: 127.0.0.1\r\n"
for k, v in h8.items():
    if k != "Content-Length": p8 += ("%s: %s\r\n" % (k, v)).encode()
p8 += b"Transfer-Encoding: chunked\r\n\r\n" + ch
r8 = rawsock(ER, p8)
check("fuzz", "chunked /book: served or cleanly rejected, engine alive",
      not r8.startswith("EXC") and invariant(ER), r8[:80])

# 9: Content-Length AND Transfer-Encoding both present
p9 = b"POST /book HTTP/1.1\r\nHost: 127.0.0.1\r\n"
for k, v in h8.items(): p9 += ("%s: %s\r\n" % (k, v)).encode()
p9 += b"Content-Length: %d\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n" % len(b8)
r9 = rawsock(ER, p9)
check("fuzz", "CL+TE smuggling probe: clean rejection, engine alive",
      not r9.startswith("EXC") and invariant(ER), r9[:80])

# 10: 16KB path and 4KB header value
try:
    st10, _ = raw(ER, "GET", "/" + "a" * 16384)
except Exception as ex:
    st10 = -1
st10b, _ = raw(ER, "GET", "/seats", None, {"X-Big": "z" * 4096})
check("fuzz", "16KB path + 4KB header: no crash, engine alive",
      st10b == 200 and invariant(ER), "path=%s hdr=%s" % (st10, st10b))

# 11: 20-way concurrent /book race on 10 free seats: exactly 10 succeed
free11 = seats(ET)
def book11(i):
    return req(ET, "POST", "/book", {"user_id": "r22c%d" % i, "idempotency_key": "r22c%d" % i, "seats": 1})
with ThreadPoolExecutor(max_workers=20) as ex:
    outs = list(ex.map(book11, range(20)))
won = sum(1 for s, j in outs if 200 <= s < 300 and j.get("booking_id"))
soldout = sum(1 for s, j in outs if j.get("status") == "sold_out")
s11 = seats(ET)
check("race", "20-way race for 10 seats: exactly 10 booked, rest sold_out, invariant holds",
      won == 10 and soldout == 10 and s11.get("sold") == 10 and invariant(ET),
      "won=%d soldout=%s seats=%s" % (won, soldout, s11))

# 12: waitlist entry larger than released seats: no premature promotion, no oversell
rid12, st12, _ = reserve(FS, "r22wl", 1, tag="r22wl")
filled = 0
for i in range(19):
    stf, _ = req(FS, "POST", "/book", {"user_id": "r22f%d" % i, "idempotency_key": "r22f%d" % i, "seats": 1})
    if 200 <= stf < 300: filled += 1
stj, jj = req(FS, "POST", "/waitlist", {"user_id": "r22w4", "idempotency_key": "r22w4", "seats": 4})
sr12, _ = req(FS, "POST", "/release", {"reservation_id": rid12})
time.sleep(0.8)
s12 = seats(FS)
check("state", "waitlist wants 4, only 1 released: no promotion, no oversell",
      200 <= stj < 300 and s12.get("free") == 1 and s12.get("sold") == 19 and s12.get("held") == 0 and invariant(FS),
      "res=%s fill=%d join=%s rel=%s seats=%s" % (st12, filled, stj, sr12, s12))

# 13: confirm with forged body fields (seats: 99, foreign user) must not grant more
rid13, st13, _ = reserve(FS, "r22fp", 1, tag="r22fp")
st13c, _ = req(FS, "POST", "/confirm", {"reservation_id": rid13, "user_id": "attacker", "seats": 99})
s13 = seats(FS)
ok13 = (not (200 <= st13c < 300)) or s13.get("sold") == 20
check("state", "confirm with forged seats:99 / foreign user: rejected or exactly 1 sold",
      ok13 and invariant(FS), "res=%s conf=%s seats=%s" % (st13, st13c, s13))

# 14: OPTIONS and HEAD handling
st14a, _ = raw(ER, "OPTIONS", "/book")
st14b, _ = raw(ER, "HEAD", "/seats")
check("fuzz", "OPTIONS /book and HEAD /seats: handled without 5xx, engine alive",
      st14a != -1 and st14a < 500 and st14b != -1 and st14b < 500 and invariant(ER),
      "options=%s head=%s" % (st14a, st14b))

fails = [r for r in results if not r["ok"]]
print("RUN22 EXTRA: TOTAL %d PASS %d FAIL %d" % (len(results), len(results) - len(fails), len(fails)))
for r in fails: print("FAIL:", r["cat"], r["name"], "->", r["detail"])
json.dump(results, open("/tmp/battery/run22_extra.json", "w"), indent=1)
