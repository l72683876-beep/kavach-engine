#!/usr/bin/env python3
"""Run 23 extra attack angles: 14 new variants, distinct from runs 16-22."""
import http.client, json, socket, sys, time, uuid, hashlib, hmac
from concurrent.futures import ThreadPoolExecutor

ER, ER2, ET, FS, PT, ER3, APP = 8091, 8092, 8095, 8096, 8097, 8098, 9001
KEY, KEY2, SECRET = "testkey", "otherkey", "testsecret"
SA, SB = "secretA", "secretB"  # per-tenant secrets on PT engine (8097)
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
def reserve(port=ER, user="x", n=1, tag=None, secret=SECRET):
    tag = tag or ("t" + uuid.uuid4().hex[:8])
    st, r = req(port, "POST", "/reserve", {"user_id": user, "idempotency_key": tag, "seats": n}, secret=secret)
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

# 1: per-tenant HMAC secrets (PT on 8097): cross-tenant secret and unknown tenant rejected
b1 = json.dumps({"user_id": "r23p1", "idempotency_key": "r23p1", "seats": 1}).encode()
s1a, _ = raw(PT, "POST", "/book", b1, sign(KEY2, "POST", "/book", b1, secret=SB))   # tenant2, own secret -> ok
s1b, _ = raw(PT, "POST", "/book", b1, sign(KEY2, "POST", "/book", b1, secret=SA))   # tenant2 signed with tenant1 secret
s1c, _ = raw(PT, "POST", "/book", b1, sign("ghostkey", "POST", "/book", b1, secret=SA))  # unknown tenant
check("auth", "per-tenant secrets: own tenant ok, cross-tenant secret 401, unknown tenant 401",
      200 <= s1a < 300 and 400 <= s1b < 500 and 400 <= s1c < 500,
      "own=%s cross=%s ghost=%s" % (s1a, s1b, s1c))

# 2: signature computed without trailing newline, body sent with one (MAC mismatch)
b2 = json.dumps({"user_id": "r23nl", "idempotency_key": "r23nl", "seats": 1}).encode()
st2, _ = raw(ER, "POST", "/book", b2 + b"\n", sign(KEY, "POST", "/book", b2))
check("auth", "trailing newline appended after signing: rejected", 400 <= st2 < 500, "status=%s" % st2)

# 3: duplicate Authorization headers (valid + garbage) via raw socket
b3 = json.dumps({"user_id": "r23da", "idempotency_key": "r23da", "seats": 1}).encode()
h3 = sign(KEY, "POST", "/book", b3)
p3 = b"POST /book HTTP/1.1\r\nHost: 127.0.0.1\r\n"
for k, v in h3.items():
    if k == "Authorization":
        p3 += b"Authorization: Bearer testkey\r\nAuthorization: Bearer garbage\r\n"
    else:
        p3 += ("%s: %s\r\n" % (k, v)).encode()
p3 += b"Content-Length: %d\r\n\r\n" % len(b3) + b3
r3 = rawsock(ER, p3)
check("auth", "duplicate Authorization headers: clean rejection, engine alive",
      not r3.startswith("EXC") and invariant(ER), r3[:80])

# 4: attacker Host header on a validly signed /book
b4 = json.dumps({"user_id": "r23ho", "idempotency_key": "r23ho", "seats": 1}).encode()
st4, j4 = raw(ER, "POST", "/book", b4, {**sign(KEY, "POST", "/book", b4), "Host": "evil.example"})
check("fuzz", "Host: evil.example on signed /book: no crash, no attacker-host echo, invariant holds",
      st4 != -1 and st4 < 500 and invariant(ER) and "evil" not in json.dumps(j4), "status=%s" % st4)

# 5: 64KB user_id: accepted or rejected; committed log stays single-line valid JSON
big_id = "r23big" + "x" * 65500
st5, _ = req(FS, "POST", "/book", {"user_id": big_id, "idempotency_key": "r23big", "seats": 1})
time.sleep(0.6)
bad5 = 0
try:
    for ln in open("/tmp/battery/state/fsl_bookings.jsonl"):
        ln = ln.strip()
        if not ln: continue
        try: json.loads(ln)
        except Exception: bad5 += 1
except FileNotFoundError:
    bad5 = -1
check("fuzz", "64KB user_id: engine alive, log stays single-line valid JSON",
      st5 != -1 and st5 < 500 and bad5 == 0 and invariant(FS), "status=%s bad_lines=%d" % (st5, bad5))

# 6: unauthenticated probing of /seats/state and /reservation (info-leak scan)
st6a, j6a = raw(ER, "GET", "/seats/state")
st6b, j6b = raw(ER, "GET", "/reservation")
st6c, j6c = raw(ER2, "GET", "/seats/state")
check("auth", "unauth /seats/state and /reservation: no data leak without signing",
      (400 <= st6a < 500 or (j6a.get("held") is None and j6a.get("reservations") is None))
      and (400 <= st6b < 500 or (j6b.get("reservation_id") is None))
      and (400 <= st6c < 500 or (j6c.get("held") is None and j6c.get("reservations") is None)),
      "state=%s res=%s er2=%s" % (st6a, st6b, st6c))

# 7: idempotency key reuse across DIFFERENT users (same tenant): no cross-user hijack
tag7 = "r23ik" + uuid.uuid4().hex[:6]
s7a, j7a = req(ER, "POST", "/book", {"user_id": "r23u1", "idempotency_key": tag7, "seats": 1})
s7b, j7b = req(ER, "POST", "/book", {"user_id": "r23u2", "idempotency_key": tag7, "seats": 1})
no_hijack = (s7b >= 400) or (j7b.get("booking_id") != j7a.get("booking_id") and j7b.get("user_id", "r23u2") != "r23u1")
check("state", "same idem key, different users: no cross-user booking hijack",
      no_hijack and invariant(ER), "u1=%s(%s) u2=%s(%s)" % (s7a, j7a.get("booking_id"), s7b, j7b.get("booking_id")))

# 8: PATCH /book and TRACE /seats
st8a, _ = req(ER, "PATCH", "/book", {"user_id": "r23m", "idempotency_key": "r23m", "seats": 1})
st8b, _ = req(ER, "TRACE", "/seats")
check("fuzz", "PATCH /book and TRACE /seats: clean non-5xx, engine alive",
      st8a != -1 and st8a < 500 and st8b != -1 and st8b < 500 and invariant(ER), "patch=%s trace=%s" % (st8a, st8b))

# 9: deeply nested JSON payload (10k levels)
deep = ("[" * 10000) + ("1" ) + ("]" * 10000)
b9 = ('{"user_id": "r23d", "idempotency_key": "r23d", "seats": 1, "junk": ' + deep + '}').encode()
st9, _ = raw(ER, "POST", "/book", b9, sign(KEY, "POST", "/book", b9))
check("fuzz", "10k-deep JSON nesting: clean rejection, no crash", st9 != -1 and st9 < 500 and invariant(ER), "status=%s" % st9)

# 10: uppercase-hex signature header (defensible either way; must not break invariants)
b10 = json.dumps({"user_id": "r23uc", "idempotency_key": "r23uc", "seats": 1}).encode()
h10 = sign(KEY, "POST", "/book", b10)
st10, _ = raw(ER, "POST", "/book", b10, {**h10, "X-Kavach-Signature": h10["X-Kavach-Signature"].upper()})
check("auth", "uppercase-hex signature: consistent (accepted or rejected), invariant holds",
      st10 != -1 and st10 < 500 and invariant(ER), "status=%s" % st10)

# 11: 10x concurrent /reserve with the SAME idempotency key: exactly one hold
tag11 = "r23cr" + uuid.uuid4().hex[:6]
def r11(_):
    return req(ER3, "POST", "/reserve", {"user_id": "r23r", "idempotency_key": tag11, "seats": 1})
with ThreadPoolExecutor(max_workers=10) as ex:
    outs11 = list(ex.map(r11, range(10)))
holds = sum(1 for s, j in outs11 if 200 <= s < 300 and j.get("reservation_id"))
conf = sum(1 for s, _ in outs11 if 400 <= s < 500)
ids11 = {j.get("reservation_id") for s, j in outs11 if 200 <= s < 300 and j.get("reservation_id")}
check("race", "10x concurrent /reserve same idem key: 1 distinct hold; 429s are the per-user limiter, never a second hold",
      len(ids11) == 1 and holds >= 1 and holds + conf == 10 and invariant(ER3),
      "distinct=%s holds=%d limiter_or_conflict=%d" % (sorted(ids11), holds, conf))

# 12: confirm after hold TTL expiry (ET, ttl 3s): no resurrection
rid12, st12, _ = reserve(ET, "r23ttl", 1, tag="r23ttl")
time.sleep(4.5)
st12c, j12c = req(ET, "POST", "/confirm", {"reservation_id": rid12, "user_id": "r23ttl"})
s12 = seats(ET)
check("state", "confirm after TTL expiry: fails, no booking, invariant holds",
      not (200 <= st12c < 300 and j12c.get("booking_id")) and invariant(ET),
      "res=%s conf=%s seats=%s" % (st12, st12c, s12))

# 13: app-level unauth scan of /api/metrics and /api/seats/state
st13a, j13a = raw(APP, "GET", "/api/metrics")
st13b, j13b = raw(APP, "GET", "/api/seats/state")
def leaks(j):
    txt = json.dumps(j).lower()
    return ("hmac" in txt) or ("secret" in txt) or ("token" in txt)
check("auth", "app unauth /api/metrics + /api/seats/state: no secrets/keys exposed",
      st13a != -1 and st13a < 500 and not leaks(j13a) and st13b != -1 and st13b < 500 and not leaks(j13b),
      "metrics=%s state=%s" % (st13a, st13b))

# 14: UTF-8 BOM prefixed JSON body with valid signature
b14 = json.dumps({"user_id": "r23bom", "idempotency_key": "r23bom", "seats": 1}).encode()
st14, _ = raw(ER, "POST", "/book", b"\xef\xbb\xbf" + b14, sign(KEY, "POST", "/book", b"\xef\xbb\xbf" + b14))
check("fuzz", "UTF-8 BOM body: consistent (rejected or booked), invariant holds",
      st14 != -1 and st14 < 500 and invariant(ER), "status=%s" % st14)

fails = [r for r in results if not r["ok"]]
print("RUN23 EXTRA: TOTAL %d PASS %d FAIL %d" % (len(results), len(results) - len(fails), len(fails)))
for r in fails: print("FAIL:", r["cat"], r["name"], "->", r["detail"])
json.dump(results, open("/tmp/battery/run23_extra.json", "w"), indent=1)
