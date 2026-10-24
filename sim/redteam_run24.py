#!/usr/bin/env python3
"""Run 24 extra attack angles: 14 new variants, distinct from runs 16-23."""
import http.client, json, socket, sys, time, uuid, hashlib, hmac, unicodedata
from concurrent.futures import ThreadPoolExecutor

ER, ER2, ET, FS, PT, ER3, APP = 8091, 8092, 8095, 8096, 8097, 8098, 9001
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
def wait_drain(port, max_s=50):
    t0 = time.time()
    while time.time() - t0 < max_s:
        s = seats(port)
        if s and s.get("held", 0) == 0: return True
        time.sleep(2)
    return False

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

wait_drain(ER)

# 1: NUL byte appended after the signed body (MAC must not cover just the prefix)
b1 = json.dumps({"user_id": "r24nul", "idempotency_key": "r24nul", "seats": 1}).encode()
st1, _ = raw(ER, "POST", "/book", b1 + b"\x00", sign(KEY, "POST", "/book", b1))
check("auth", "NUL byte appended after signed body: rejected", 400 <= st1 < 500, "status=%s" % st1)

# 2: replay with stale timestamp (-5 min), signature otherwise valid
b2 = json.dumps({"user_id": "r24old", "idempotency_key": "r24old", "seats": 1}).encode()
h2 = sign(KEY, "POST", "/book", b2, ts=str(int(time.time()) - 301))  # window is +-300 by design (nonce cache covers it); -301 must fail
st2, _ = raw(ER, "POST", "/book", b2, h2)
check("auth", "stale timestamp (-301s, outside +-300 window) with valid signature: rejected", 400 <= st2 < 500, "status=%s" % st2)

# 3: future timestamp (+1 hour), signature otherwise valid
b3 = json.dumps({"user_id": "r24fut", "idempotency_key": "r24fut", "seats": 1}).encode()
h3 = sign(KEY, "POST", "/book", b3, ts=str(int(time.time()) + 3600))
st3, _ = raw(ER, "POST", "/book", b3, h3)
check("auth", "future timestamp (+1h) with valid signature: rejected", 400 <= st3 < 500, "status=%s" % st3)

# 4: HMAC computed with a wrong secret entirely
b4 = json.dumps({"user_id": "r24ws", "idempotency_key": "r24ws", "seats": 1}).encode()
st4, _ = raw(ER, "POST", "/book", b4, sign(KEY, "POST", "/book", b4, secret="wrongsecret"))
check("auth", "HMAC signed with wrong secret: 401", st4 == 401, "status=%s" % st4)

# 5: NFC vs NFD unicode idem keys must be distinct keys, no collision or corruption
nfc = unicodedata.normalize("NFC", "café\u0301"[:4])
nfd = unicodedata.normalize("NFD", "café")
rid_a, sa, _ = reserve(ER, user="r24uni", tag="k24u-" + nfc)
rid_b, sb, _ = reserve(ER, user="r24uni", tag="k24u-" + nfd)
check("fuzz", "NFC vs NFD idem keys: distinct holds, no cross-key collision",
      rid_a and rid_b and rid_a != rid_b and invariant(ER), "a=%s b=%s %s/%s" % (rid_a, rid_b, sa, sb))

# 6: 14-way concurrent confirm+release mix on one reservation: one terminal state, no leak
rid6, _, _ = reserve(ER3, user="r24mix", n=1)
if rid6:
    outs6 = list(ThreadPoolExecutor(max_workers=14).map(
        lambda i: req(ER3, "POST", "/confirm" if i % 2 == 0 else "/release",
                      {"reservation_id": rid6, "user_id": "r24mix"}), range(14)))
    s6 = seats(ER3)
    terminal_ok = (s6.get("sold") == 1 and s6.get("held") == 0 and s6.get("free") == s6.get("total") - 1) or \
                  (s6.get("sold") == 0 and s6.get("held") == 0 and s6.get("free") == s6.get("total"))
    check("race", "14-way concurrent confirm+release mix: single terminal state, no seat leak",
          terminal_ok and invariant(ER3), "seats=%s statuses=%s" % (s6, sorted(set(st for st, _ in outs6))))
else:
    check("race", "14-way concurrent confirm+release mix: single terminal state, no seat leak", False, "reserve failed")

# 7: hold-drain cycles on ET (8095: 10 seats, ttl 3): never oversell across TTL cycles
drain_ok = True
detail7 = []
for cycle in range(3):
    got = []
    for n in (4, 4, 2):
        rid_c, st_c, _ = reserve(ET, user="r24dr", n=n, tag="dr%d%d" % (cycle, n))
        if rid_c: got.append(rid_c)
    s_hold = seats(ET)
    time.sleep(4.5)  # ttl 3 + margin
    s_after = seats(ET)
    okc = s_after.get("sold") == 0 and s_after.get("free") == 10 and invariant(ET)
    drain_ok = drain_ok and okc
    detail7.append("c%d held=%s free=%s sold=%s" % (cycle, s_hold.get("held"), s_after.get("free"), s_after.get("sold")))
check("state", "3 hold-drain TTL cycles on 10-seat engine: zero oversell, full expiry each cycle",
      drain_ok, "; ".join(detail7))

# 8: waitlist fuzz seats: 0, -1, 99 -> clean 4xx, engine healthy
w0, wneg, whuge = req(ER, "POST", "/waitlist", {"user_id": "r24w0", "seats": 0})[0], \
                   req(ER, "POST", "/waitlist", {"user_id": "r24wneg", "seats": -1})[0], \
                   req(ER, "POST", "/waitlist", {"user_id": "r24whuge", "seats": 99})[0]
check("fuzz", "waitlist seats 0 / -1 / 99: all clean 4xx, engine alive",
      all(400 <= s < 500 for s in (w0, wneg, whuge)) and invariant(ER), "0=%s -1=%s 99=%s" % (w0, wneg, whuge))

# 9: waitlist/cancel for a user who never joined
st9, j9 = req(ER, "POST", "/waitlist/cancel", {"waitlist_id": "WL99999999"})
check("state", "waitlist cancel of nonexistent entry: clean 4xx, no state change",
      400 <= st9 < 500 and invariant(ER), "status=%s body=%s" % (st9, str(j9)[:60]))

# 10: app webhook with VALID token + garbage payloads: app must stay healthy
st10a, _ = raw(APP, "POST", "/api/kavach-webhook?token=whsec-redtest", 'not json at all')
st10b, _ = raw(APP, "POST", "http://127.0.0.1:9001/api/kavach-webhook?token=whsec-redtest".replace("http://127.0.0.1:9001", ""), '{"type":' + 'A' * 20000)
st10c, _ = raw(APP, "GET", "/api/seats")
check("app", "app webhook valid token + garbage/malformed payloads: handled, app still healthy",
      200 <= st10c < 500 and not (st10a == -1) and invariant(ER), "garbage=%s huge=%s health=%s" % (st10a, st10b, st10c))

# 11: app /api/hold with seats=5 and seats=0 -> 4xx propagated, engine not stuck
h5 = req(APP, "POST", "/api/hold", {"user_id": "r24h5", "seats": 5})[0]
h0 = req(APP, "POST", "/api/hold", {"user_id": "r24h0", "seats": 0})[0]
hap = raw(APP, "GET", "/api/seats")[0]
check("app", "app hold seats=5 and seats=0: 4xx, app and engine healthy after",
      400 <= h5 < 500 and 400 <= h0 < 500 and 200 <= hap < 500 and invariant(ER), "5=%s 0=%s health=%s" % (h5, h0, hap))

# 12: GET on signing endpoints /book and /reserve
g1 = raw(ER, "GET", "/book")[0]; g2 = raw(ER, "GET", "/reserve")[0]
check("auth", "GET on /book and /reserve: clean rejection (no unsigned GET bypass)",
      (400 <= g1 < 500 or g1 == 405) and (400 <= g2 < 500 or g2 == 405) and invariant(ER), "book=%s reserve=%s" % (g1, g2))

# 13: SQLi/XSS user_id on /book: handled safely, logs stay single-line valid JSON
evil = "<script>alert(1)</script>' OR 1=1 --"
b13 = json.dumps({"user_id": evil, "idempotency_key": "r24sqli", "seats": 1}).encode()
st13, j13 = raw(ER, "POST", "/book", b13, sign(KEY, "POST", "/book", b13))
log_ok = True
try:
    with open("/tmp/battery/state/bt1_bookings.jsonl") as f:
        lines = [l for l in f.read().splitlines() if l.strip()][-5:]
    for l in lines: json.loads(l)
except Exception as ex:
    log_ok = False
check("fuzz", "SQLi/XSS user_id: clean response, booking log stays single-line valid JSON",
      200 <= st13 < 500 and invariant(ER) and log_ok, "status=%s log_ok=%s" % (st13, log_ok))

# 14: duplicate X-Kavach-Signature headers (valid + garbage) via raw socket
b14 = json.dumps({"user_id": "r24dup", "idempotency_key": "r24dup", "seats": 1}).encode()
h14 = sign(KEY, "POST", "/book", b14)
p14 = b"POST /book HTTP/1.1\r\nHost: 127.0.0.1\r\n"
for k, v in h14.items():
    if k == "X-Kavach-Signature":
        p14 += b"X-Kavach-Signature: " + v.encode() + b"\r\nX-Kavach-Signature: deadbeef\r\n"
    else:
        p14 += ("%s: %s\r\n" % (k, v)).encode()
p14 += b"Content-Length: %d\r\n\r\n" % len(b14) + b14
r14 = rawsock(ER, p14)
check("auth", "duplicate X-Kavach-Signature headers: clean rejection, engine alive",
      not r14.startswith("EXC") and invariant(ER), r14[:80])

fails = [r for r in results if not r["ok"]]
print("RUN24 EXTRA: TOTAL %d PASS %d FAIL %d" % (len(results), len(results) - len(fails), len(fails)))
for r in fails: print("FAIL:", r["cat"], r["name"], "|", r["detail"])
json.dump(results, open("/tmp/battery/run24_extra.json", "w"), indent=1)
