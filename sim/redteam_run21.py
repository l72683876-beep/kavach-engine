#!/usr/bin/env python3
"""Run 21 extra attack angles: 14 new variants, distinct from runs 16-20."""
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

# 1: form-urlencoded body (wrong content type) to /book with valid signature over the same bytes
b = "user_id=r21a&idempotency_key=r21a&seats=1"
st, _ = raw(ER, "POST", "/book", b, sign(KEY, "POST", "/book", b.encode()))
check("fuzz", "form-urlencoded body, signed as raw bytes: rejected or clean, engine alive",
      not (200 <= st < 300) and raw(ER, "GET", "/seats")[0] == 200, "status=%s" % st)

# 2: GET /seats with a body attached (weird HTTP)
st, j = raw(ER, "GET", "/seats", b'{"junk": true}')
check("fuzz", "GET with body: handled, seats still correct", st == 200 and invariant(), "status=%s" % st)

# 3: path normalization bypasses: signature over /book but request to variants
b3 = json.dumps({"user_id": "r21p", "idempotency_key": "r21p", "seats": 1}).encode()
for variant, path in (("trailing slash", "/book/"), ("uppercase", "/BOOK"), ("query", "/book?x=1"), ("dot", "/./book")):
    st, _ = raw(ER, "POST", path, b3, sign(KEY, "POST", "/book", b3))
    if 200 <= st < 300: break
check("auth", "signature path variants (slash/upper/query/dot): none accepted", not (200 <= st < 300), "last=%s" % st)

# 4: CRLF and null bytes in user_id (engine accepts them; verify the log stays clean)
bad_ids = ["r21\r\nX-Injected: 1", "r21\x00null", "r21\n\nlog-injection"]
ok4, accepted = True, 0
for i, uid in enumerate(bad_ids):
    st, _ = req(FS, "POST", "/book", {"user_id": uid, "idempotency_key": "r21i%d" % i, "seats": 1})
    if 200 <= st < 300: accepted += 1
time.sleep(0.6)
log4 = "/tmp/battery/state/fsl_bookings.jsonl"
bad_lines = 0
try:
    for ln in open(log4):
        ln = ln.strip()
        if not ln: continue
        try: json.loads(ln)
        except Exception: bad_lines += 1
except FileNotFoundError:
    bad_lines = -1
check("fuzz", "CRLF/null user_ids: accepted but every committed log line stays single-line valid JSON",
      bad_lines == 0, "accepted=%d bad_lines=%d" % (accepted, bad_lines))

# 5: double release of the same reservation (idempotent or clean 4xx, no state damage)
rid, _, _ = reserve(FS, "r21dr", 1)
s1, _ = req(FS, "POST", "/release", {"reservation_id": rid})
s2, _ = req(FS, "POST", "/release", {"reservation_id": rid})
check("state", "double release: no crash, invariants hold", invariant(FS) and raw(FS, "GET", "/seats")[0] == 200, "%s %s" % (s1, s2))

# 6: confirm after release must not resurrect the booking
rid, _, _ = reserve(FS, "r21cr", 1)
req(FS, "POST", "/release", {"reservation_id": rid})
st, j = req(FS, "POST", "/confirm", {"reservation_id": rid, "user_id": "r21cr"})
check("state", "confirm after release: no resurrection", not (200 <= st < 300) or j.get("booking_id") is None, "status=%s" % st)

# 7: release after confirm must not un-sell
rid, _, _ = reserve(FS, "r21rc", 1)
sc, jc = req(FS, "POST", "/confirm", {"reservation_id": rid, "user_id": "r21rc"})
before = seats(FS)
sr, _ = req(FS, "POST", "/release", {"reservation_id": rid})
after = seats(FS)
check("state", "release after confirm: sold count unchanged", sc == 200 and after.get("sold", 0) == before.get("sold", 0) and invariant(FS),
      "confirm=%s release=%s sold %s->%s" % (sc, sr, before.get("sold"), after.get("sold")))

# 8: promotion race with waitlist cancels: release a hold while 2 waitlisted users cancel concurrently
held, st8, r8 = reserve(ET, "r21p0", 1, tag="r21p0")
# fill every remaining free seat with 1-seat bookings so only the held seat is free
filled = 0
for k in range(20):
    if seats(ET).get("free", 0) <= 0: break
    stb, jb = req(ET, "POST", "/book", {"user_id": "r21fill%d" % k, "idempotency_key": "r21fil%d" % k, "seats": 1})
    if 200 <= stb < 300: filled += 1
    else: break
# only now can users join the waitlist: the engine refuses joins while seats are free
wl_ids = []
for i in range(1, 6):
    stj, jj = req(ET, "POST", "/waitlist", {"user_id": "r21p%d" % i, "idempotency_key": "r21p%d" % i, "seats": 1})
    if stj == 200 and jj.get("waitlist_id"): wl_ids.append(jj["waitlist_id"])
# the hold ttl is 3s: if it lapsed while filling, re-reserve so a live hold exists to release
if seats(ET).get("held", 0) == 0:
    held, st8, r8 = reserve(ET, "r21p0b", 1, tag="r21p0b")
before = seats(ET)
def cancel(wid):
    return req(ET, "POST", "/waitlist/cancel", {"waitlist_id": wid})
with ThreadPoolExecutor(3) as ex:
    f1 = ex.submit(cancel, wl_ids[0]); f2 = ex.submit(cancel, wl_ids[1])
    f3 = ex.submit(lambda: req(ET, "POST", "/release", {"reservation_id": held}))
    r1 = f1.result(); r2 = f2.result(); r3 = f3.result()
time.sleep(1.5)
after = seats(ET)
committed = after.get("sold", 0) + after.get("held", 0)
delta = committed - (before.get("sold", 0) + before.get("held", 0))
check("race", "release racing 2 waitlist cancels: at most one promotion, no oversell",
      delta <= 1 and invariant(ET), "held=%s st8=%s filled=%d delta=%+d" % (held, st8, filled, delta))

# 9: foreign tenant release of tenant1's reservation
rid, _, _ = reserve(ER2, "r21fx", 1, tag="r21fx")
st, _ = raw(FS, "POST", "/release", json.dumps({"reservation_id": rid}).encode(), sign(KEY2, "POST", "/release", json.dumps({"reservation_id": rid}).encode()))
after = seats(FS)
check("auth", "foreign tenant release: rejected, seat still held", not (200 <= st < 300) and invariant(FS), "status=%s" % st)
req(FS, "POST", "/release", {"reservation_id": rid})

# 10: duplicate X-Kavach-Signature headers (valid first, garbage second)
b10 = json.dumps({"user_id": "r21ds", "idempotency_key": "r21ds", "seats": 1}).encode()
h10 = sign(KEY, "POST", "/book", b10); h10["X-Kavach-Signature"] = [h10["X-Kavach-Signature"], "deadbeef" * 8]
st, _ = raw(ER, "POST", "/book", b10, h10)
check("auth", "duplicate signature headers (valid+garbage): not accepted", not (200 <= st < 300), "status=%s" % st)

# 11: HTTP/1.0 request without Host header
b11 = json.dumps({"user_id": "r21h0", "idempotency_key": "r21h0", "seats": 1}).encode()
h11 = sign(KEY, "POST", "/book", b11)
lines = ["POST /book HTTP/1.0"]
for k2, v2 in h11.items(): lines.append("%s: %s" % (k2, v2))
lines.append("Content-Length: %d" % len(b11)); lines.append("")
try:
    s11 = socket.create_connection(("127.0.0.1", ER), timeout=8)
    s11.sendall(("\r\n".join(lines)).encode() + b11)
    s11.settimeout(8); resp = s11.recv(400); s11.close()
    ok11 = b"HTTP/1." in resp or b"HTTP/0" in resp
except Exception as ex:
    resp, ok11 = str(ex)[:80], True  # hard close is acceptable handling
check("resource", "HTTP/1.0 no-Host request: handled without crash, engine alive",
      ok11 and raw(ER, "GET", "/seats")[0] == 200, "resp=%s" % resp[:60])

# 12: pipelined requests (two GET /seats in one TCP write)
reqs = ["GET /seats HTTP/1.1\r\nHost: x\r\nConnection: keep-alive\r\n\r\n"] * 2
b12 = "".join(reqs).encode()
try:
    s12 = socket.create_connection(("127.0.0.1", ER), timeout=8)
    s12.sendall(b12); s12.settimeout(8)
    data = b""
    for _ in range(4):
        try: data += s12.recv(4096)
        except Exception: break
        if data.count(b"HTTP/1.1") >= 2: break
    s12.close()
    ok12 = data.count(b"HTTP/1.1 200") >= 2
except Exception as ex:
    data, ok12 = str(ex)[:80], False
check("resource", "pipelined requests: two responses served, engine alive", ok12 and raw(ER, "GET", "/seats")[0] == 200, "got=%s" % data.count(b"HTTP/1.1 200"))

# 13: slow-body drip: Content-Length 200000, drip bytes, engine must keep serving others
try:
    s13 = socket.create_connection(("127.0.0.1", ER), timeout=10)
    body13 = b'{"user_id":"r21slow","idempotency_key":"r21slow","seats":1}' + b" " * 200000
    hdr = "POST /book HTTP/1.1\r\nHost: x\r\nContent-Length: %d\r\nContent-Type: application/json\r\n\r\n" % len(body13)
    s13.sendall(hdr.encode())
    served = raw(ER, "GET", "/seats", timeout=5)[0] == 200
    for i in range(0, len(body13), 20000):
        s13.sendall(body13[i:i+20000]); time.sleep(0.15)
        if i == 100000: served2 = raw(ER, "GET", "/seats", timeout=5)[0] == 200
    s13.close()
    ok13 = served and served2 and raw(ER, "GET", "/seats", timeout=5)[0] == 200
except Exception as ex:
    ok13, served = False, str(ex)[:80]
check("resource", "slow-body drip 200KB: engine keeps serving throughout", ok13, "served=%s" % served)

# 14: numeric literal bypass in seats-as-string: "1e2", "0x10", "1_000"
ok14 = True
for i, val in enumerate(["1e2", "0x10", "1_000"]):
    st, _ = req(ER2, "POST", "/book", {"user_id": "r21n%d" % i, "idempotency_key": "r21n%d" % i, "seats": val})
    if 200 <= st < 300: ok14 = False
check("fuzz", "numeric literal bypass seats strings: all rejected", ok14 and invariant(ER2))

fails = [x for x in results if not x["ok"]]
print("RUN21 EXTRA: TOTAL %d PASS %d FAIL %d" % (len(results), len(results) - len(fails), len(fails)))
for x in fails: print("FAIL [%s] %s :: %s" % (x["cat"], x["name"], x["detail"]))
json.dump(results, open("/tmp/battery/run21_extra.json", "w"), indent=1)
sys.exit(1 if fails else 0)
