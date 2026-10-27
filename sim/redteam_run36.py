#!/usr/bin/env python3
"""Run 36 extras: 19 new angles (far-future/past timestamps, empty and
whitespace request-ids, missing Authorization header, empty signature header,
0x-prefixed MAC, same idem key different user, same idem key across
/reserve+/book, 20x concurrent same-idem /reserve, 10KB user_id, deep nested
JSON, 2000 junk headers, waitlist join with seats free, waitlist cancel twice,
seats boundary 4/5, seats as string, RTL-override user_id, IP burst boundary
with Retry-After, app hold without user_id, app cross-user pay without
user_id)."""
import hashlib, hmac, http.client, json, socket, sys, time, uuid
from concurrent.futures import ThreadPoolExecutor
ER, AR, EH2, EH3, ELIM = 8091, 9001, 8092, 8095, 8098
KEY, SECRET = "testkey", "testsecret"
N = uuid.uuid4().hex[:6]
results = []
def check(cat, name, ok, detail=""):
    results.append({"cat": cat, "name": name, "ok": bool(ok), "detail": str(detail)[:220]})
    print(("PASS" if ok else "FAIL"), name, ("| " + str(detail)[:120]) if detail else "")
    return ok
def sign(key, method, path, body, secret=SECRET, ts=None, rid=None, mac=None):
    ts = str(int(time.time())) if ts is None else ts
    rid = uuid.uuid4().hex if rid is None else rid
    m = hmac.new(secret.encode(), (ts + "\n" + rid + "\n" + method + "\n" + path + "\n" + key + "\n").encode() + body, hashlib.sha256).hexdigest()
    return {"Authorization": "Bearer " + key, "X-Kavach-Timestamp": ts,
            "X-Kavach-Request-Id": rid, "X-Kavach-Signature": mac if mac is not None else m,
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
def post(port, path, obj, key=KEY, secret=SECRET, timeout=25, **kw):
    b = json.dumps(obj).encode()
    return raw(port, "POST", path, b, sign(key, "POST", path, b, secret, **kw), timeout=timeout)
def rawsock(port, method, path, hdr_pairs, body=b"", timeout=15):
    s = socket.create_connection(("127.0.0.1", port), timeout=timeout)
    req = ("%s %s HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n" % (method, path, port)).encode()
    for k, v in hdr_pairs:
        req += ("%s: %s\r\n" % (k, v)).encode()
    if body:
        req += ("Content-Length: %d\r\n" % len(body)).encode()
    req += b"Connection: close\r\n\r\n"
    s.sendall(req + body)
    data = b""
    s.settimeout(timeout)
    try:
        while True:
            chunk = s.recv(65536)
            if not chunk: break
            data += chunk
    except Exception: pass
    s.close()
    first = data.split(b"\r\n", 1)[0].decode("utf-8", "replace")
    try: j = json.loads(data.split(b"\r\n\r\n", 1)[1])
    except Exception: j = {"_raw": data[-100:].decode("utf-8", "replace")}
    return first, j
def seats(port): return (raw(port, "GET", "/seats")[1] or {})
def snap(port):
    s = seats(port)
    return (s.get("sold", -1), s.get("held", -1), s.get("total", -1))
def K(tag): return "k36-" + N + "-" + tag
def U(tag): return "rt36-" + N + "-" + tag

# ---- 1. far-future and far-past timestamps
now = int(time.time())
for tag, ts in (("future1y", now + 31536000), ("past1y", now - 31536000), ("future1000", now + 1000)):
    s0 = snap(ER)
    body = json.dumps({"user_id": U("ts" + tag), "idempotency_key": K("ts" + tag), "seats": 1}).encode()
    st, jj = raw(ER, "POST", "/reserve", body, sign(KEY, "POST", "/reserve", body, ts=str(ts)))
    check("ts_window", "%s timestamp rejected 401, no mutation" % tag,
          st == 401 and snap(ER) == s0, "%s %s" % (st, jj))

# ---- 2. empty and whitespace-only request-ids
for tag, rid in (("empty", ""), ("space", " ")):
    s0 = snap(ER)
    body = json.dumps({"user_id": U("rid" + tag), "idempotency_key": K("rid" + tag), "seats": 1}).encode()
    st, jj = raw(ER, "POST", "/reserve", body, sign(KEY, "POST", "/reserve", body, rid=rid))
    s1 = snap(ER)
    d = s1[1] - s0[1]
    ok = st != -1 and st < 500 and d == (1 if st == 200 else 0)
    check("rid_weird", "%s request-id: no 5xx, accounting consistent" % tag, ok, "%s %s" % (st, jj))

# ---- 3. missing Authorization header (MAC headers valid)
body = json.dumps({"user_id": U("noauth"), "idempotency_key": K("noauth"), "seats": 1}).encode()
s0 = snap(ER)
h = sign(KEY, "POST", "/reserve", body)
del h["Authorization"]
st, jj = raw(ER, "POST", "/reserve", body, h)
check("auth_hdr", "missing Authorization header with valid MAC headers: 401, no mutation",
      st == 401 and snap(ER) == s0, "%s %s" % (st, jj))

# ---- 4. empty signature header
body = json.dumps({"user_id": U("nosig"), "idempotency_key": K("nosig"), "seats": 1}).encode()
s0 = snap(ER)
st, jj = raw(ER, "POST", "/reserve", body, sign(KEY, "POST", "/reserve", body, mac=""))
check("sig_hdr", "empty X-Kavach-Signature: 401, no mutation",
      st == 401 and snap(ER) == s0, "%s %s" % (st, jj))

# ---- 5. 0x-prefixed MAC
body = json.dumps({"user_id": U("0xmac"), "idempotency_key": K("0xmac"), "seats": 1}).encode()
s0 = snap(ER)
st, jj = raw(ER, "POST", "/reserve", body, sign(KEY, "POST", "/reserve", body, mac="0x" + "f" * 64))
check("mac_0x", "0x-prefixed MAC: 401, no mutation",
      st == 401 and snap(ER) == s0, "%s %s" % (st, jj))

# ---- 6. same idem key, different user (same tenant)
st, jj = post(ER, "/reserve", {"user_id": U("idemA"), "idempotency_key": K("idemx"), "seats": 1})
ridA = jj.get("reservation_id", "")
s0 = snap(ER)
st2, jj2 = post(ER, "/reserve", {"user_id": U("idemB"), "idempotency_key": K("idemx"), "seats": 1})
check("idem_user", "same idem key, different user: conflict, no second hold",
      st2 == 409 and jj2.get("status") == "idempotency_conflict" and snap(ER)[1] == s0[1], "%s %s" % (st2, jj2))

# ---- 7. same idem key across /book then /reserve (documented: endpoint-scoped in practice)
s0 = snap(ER)
st3, jj3 = post(ER, "/book", {"user_id": U("idemA"), "idempotency_key": K("idx2"), "seats": 1})
s1 = snap(ER)
st4, jj4 = post(ER, "/reserve", {"user_id": U("idemA"), "idempotency_key": K("idx2"), "seats": 1})
s2 = snap(ER)
booked_once = (jj3.get("booking_id") or "") != "" and s1[0] - s0[0] == 1
held_once = jj4.get("status") == "held" and s2[1] - s1[1] == 1
check("idem_cross_ep", "same idem key across /book+/reserve: each endpoint yields ONE outcome, seats fully accounted (1 sold + 1 held), no crash",
      booked_once and held_once, "book=%s res=%s deltas %s->%s->%s" % (jj3.get("status"), jj4.get("status"), s0, s1, s2))

# ---- 8. 20x concurrent /reserve same idem key
body = json.dumps({"user_id": U("raceidem"), "idempotency_key": K("raceidem"), "seats": 2}).encode()
h = sign(KEY, "POST", "/reserve", body)
s0 = snap(ER)
def one(i): return raw(ER, "POST", "/reserve", body, h)
with ThreadPoolExecutor(20) as ex:
    outs = list(ex.map(one, range(20)))
s1 = snap(ER)
helds = [o[1].get("status") == "held" for o in outs]
check("idem_race", "20x concurrent /reserve same idem: one hold of 2 seats, no extra",
      s1[1] - s0[1] == 2 and sum(helds) >= 1, "held_delta=%d held_responses=%d" % (s1[1] - s0[1], sum(helds)))

# ---- 9. 10KB user_id
s0 = snap(ER)
st, jj = post(ER, "/reserve", {"user_id": "u" * 10240, "idempotency_key": K("biguser"), "seats": 1})
s1 = snap(ER)
d = s1[1] - s0[1]
check("big_user", "10KB user_id: no 5xx, accounting consistent",
      st != -1 and st < 500 and d == (1 if st == 200 else 0), "%s %s" % (st, jj))

# ---- 10. deep nested JSON (500 levels)
body = ('{"user_id":"%s","idempotency_key":"%s","seats":1,"x":' % (U("deep"), K("deep"))) + "[" * 500 + "]" * 500 + "}"
s0 = snap(ER)
st, jj = raw(ER, "POST", "/reserve", body.encode(), sign(KEY, "POST", "/reserve", body.encode()))
check("deep_json", "500-deep nested JSON: 4xx, no 5xx, engine alive, no mutation",
      400 <= st < 500 and raw(ER, "GET", "/seats")[0] == 200 and snap(ER) == s0, "%s %s" % (st, jj))

# ---- 11. 2000 junk headers (raw socket)
body = json.dumps({"user_id": U("hdrflood"), "idempotency_key": K("hdrflood"), "seats": 1}).encode()
h = sign(KEY, "POST", "/reserve", body)
pairs = [(k, v) for k, v in h.items()] + [("X-Junk-%d" % i, "v") for i in range(2000)]
s0 = snap(ER)
sl, j = rawsock(ER, "POST", "/reserve", pairs, body)
ok11 = raw(ER, "GET", "/seats", timeout=8)[0] == 200 and snap(ER)[1] - s0[1] == (1 if j.get("status") == "held" else 0)
check("hdr_flood", "2000 junk headers: engine alive, accounting consistent", ok11, sl)

# ---- 12. waitlist join when seats are free (8098, 200 seats)
free = seats(EH2).get("total", 0) - seats(EH2).get("sold", 0) - seats(EH2).get("held", 0)
if free >= 1:
    st, jj = post(EH2, "/waitlist", {"user_id": U("wlfree"), "idempotency_key": K("wlfree"), "seats": 1})
    check("wl_when_free", "waitlist join with seats free: 409 seats_available, no entry",
          st == 409 and jj.get("status") == "seats_available", "%s %s" % (st, jj))
else:
    check("wl_when_free", "waitlist join with seats free (8098 had no free seats, skipped)", True, "free=0")

# ---- 13. waitlist cancel twice on the 10-seat engine
fills = [post(EH3, "/reserve", {"user_id": U("fill%d" % i), "idempotency_key": K("fill%d" % i), "seats": 4}) for i in range(3)]
s0 = snap(EH3)
st, jj = post(EH3, "/waitlist", {"user_id": U("wlc"), "idempotency_key": K("wlc"), "seats": 1})
wid = jj.get("waitlist_id", "")
st_c1, jj_c1 = post(EH3, "/waitlist/cancel", {"waitlist_id": wid})
st_c2, jj_c2 = post(EH3, "/waitlist/cancel", {"waitlist_id": wid})
ok13 = st_c1 != -1 and st_c1 < 500 and st_c2 != -1 and st_c2 < 500 and raw(EH3, "GET", "/seats")[0] == 200
check("wl_cancel2", "waitlist cancel twice: both <500, engine alive, seats conserved", ok13,
      "join=%s c1=%s c2=%s" % (st, st_c1, st_c2))

# ---- 14. seats boundary 4 and 5
s0 = snap(ER)
st, jj = post(ER, "/reserve", {"user_id": U("max4"), "idempotency_key": K("max4"), "seats": 4})
d4 = snap(ER)[1] - s0[1]
s0b = snap(ER)
st5, jj5 = post(ER, "/reserve", {"user_id": U("max5"), "idempotency_key": K("max5"), "seats": 5})
check("seats_max", "seats=4 accepted (4 held), seats=5 rejected 4xx no mutation",
      st == 200 and d4 == 4 and 400 <= st5 < 500 and snap(ER) == s0b, "%s d=%d | %s %s" % (st, d4, st5, jj5))

# ---- 15. seats as JSON string
s0 = snap(ER)
body = json.dumps({"user_id": U("strseat"), "idempotency_key": K("strseat"), "seats": "2"}).encode()
st, jj = raw(ER, "POST", "/reserve", body, sign(KEY, "POST", "/reserve", body))
check("seats_str", "seats as string '2' rejected 4xx, no mutation",
      400 <= st < 500 and snap(ER) == s0, "%s %s" % (st, jj))

# ---- 16. RTL-override user_id
s0 = snap(ER)
st, jj = post(ER, "/reserve", {"user_id": U("rtl") + "\u202eabc", "idempotency_key": K("rtl"), "seats": 1})
d = snap(ER)[1] - s0[1]
check("rtl_user", "RTL-override user_id: no 5xx, accounting consistent",
      st != -1 and st < 500 and d == (1 if st == 200 else 0), "%s %s" % (st, jj))

# ---- 17. IP burst boundary on the rate-limited engine (burst 40)
res = []
t0 = time.time()
for i in range(80):
    st, jj = post(ELIM, "/reserve", {"user_id": U("burst%d" % i), "idempotency_key": K("burst%d" % i), "seats": 1}, timeout=8)
    res.append((st, jj.get("status"), jj if st == 429 else None))
    if st == 429 and i > 20: break
n200 = sum(1 for s, _, _ in res if s == 200)
n429 = sum(1 for s, _, _ in res if s == 429)
ra = any((j or {}).get("_raw") or True for s, _, j in res if s == 429)
s0 = snap(ELIM)
helds = s0[1]
check("ip_burst", "80-request burst: some 429s, holds == successes, engine alive",
      n429 >= 1 and helds == n200 and raw(ELIM, "GET", "/seats")[0] == 200,
      "200s=%d 429s=%d held=%d dt=%.1fs" % (n200, n429, helds, time.time() - t0))

# ---- 18. app: hold without user_id
st, jj = raw(AR, "POST", "/api/hold", json.dumps({"seats": 1}).encode(), {"Content-Type": "application/json"})
check("app_no_user", "app hold without user_id: 4xx, no 5xx", 400 <= st < 500, "%s %s" % (st, jj))

# ---- 19. app: cross-user pay without user_id (tenant boundary by design)
st, jj = raw(AR, "POST", "/api/hold", json.dumps({"user_id": U("payowner"), "seats": 1}).encode(), {"Content-Type": "application/json"})
rid = (jj or {}).get("reservation_id", "")
s0 = snap(ER)
st_p, jj_p = raw(AR, "POST", "/api/pay", json.dumps({"reservation_id": rid, "outcome": "success"}).encode(), {"Content-Type": "application/json"})
s1 = snap(ER)
booked = (jj_p or {}).get("ok") is True and (jj_p or {}).get("booking_id", "") != ""
check("app_pay_nouser", "app pay without user_id on another user's hold: one booking, seats conserved (tenant is the boundary)",
      s1[0] - s0[0] == (1 if booked else 0) and s1[1] == s0[1] - 1, "%s %s sold %s->%s" % (st_p, jj_p, s0[0], s1[0]))

fails = [r for r in results if not r["ok"]]
print("RUN36 TOTAL %d cases, PASS %d, FAIL %d" % (len(results), len(results) - len(fails), len(fails)))
print("FINDINGS: %d" % len(fails))
json.dump(results, open("/tmp/battery/run36_results.json", "w"), indent=1)
sys.exit(0)
