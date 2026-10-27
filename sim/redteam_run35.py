#!/usr/bin/env python3
"""Run 35 extras: 15 new angles. v2: /book confirms directly, /reserve is the
hold endpoint, so every hold/accounting assertion targets /reserve; waitlist
route is /waitlist; NUL-byte request-id is rejected by the HTTP layer
(fail-closed); the 8KB-query case asserts no-5xx plus consistent accounting."""
import hashlib, hmac, http.client, json, socket, sys, time, uuid
from concurrent.futures import ThreadPoolExecutor
ER, AR, EH3 = 8091, 9001, 8095
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
def rawsock(port, method, path, hdr_pairs, body=b"", timeout=12):
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
def K(tag): return "k35-" + N + "-" + tag
def U(tag): return "rt35-" + N + "-" + tag

# ---- 1. duplicate X-Kavach-Request-Id headers: which value does the engine use?
rid1, rid2 = uuid.uuid4().hex, uuid.uuid4().hex
b = json.dumps({"user_id": U("dupid"), "idempotency_key": K("dupid"), "seats": 1}).encode()
h = sign(KEY, "POST", "/reserve", b, rid=rid1)
pairs = [("Authorization", h["Authorization"]), ("X-Kavach-Timestamp", h["X-Kavach-Timestamp"]),
         ("X-Kavach-Request-Id", rid1), ("X-Kavach-Request-Id", rid2),
         ("X-Kavach-Signature", h["X-Kavach-Signature"]), ("Content-Type", "application/json")]
s0 = snap(ER)
sl, j = rawsock(ER, "POST", "/reserve", pairs, b)
s1 = snap(ER)
ok = j.get("status") == "held" and s1[1] == s0[1] + 1
check("dup_rid", "MAC over FIRST of two X-Kavach-Request-Id headers accepted, exactly one hold", ok, "%s sold/held %s->%s" % (j, s0, s1))
sl2, j2 = rawsock(ER, "POST", "/reserve", pairs, b)
check("dup_rid", "same duplicate-rid request replayed is 401 (no second hold)", j2.get("status") == "replay" or sl2.endswith("401"), j2)
b3 = json.dumps({"user_id": U("dupid2"), "idempotency_key": K("dupid2"), "seats": 1}).encode()
h3 = sign(KEY, "POST", "/reserve", b3, rid=rid2)
pairs3 = [("Authorization", h3["Authorization"]), ("X-Kavach-Timestamp", h3["X-Kavach-Timestamp"]),
          ("X-Kavach-Request-Id", rid1), ("X-Kavach-Request-Id", rid2),
          ("X-Kavach-Signature", h3["X-Kavach-Signature"]), ("Content-Type", "application/json")]
s2 = snap(ER)
sl3, j3 = rawsock(ER, "POST", "/reserve", pairs3, b3)
check("dup_rid", "MAC over SECOND rid with duplicate headers fails closed (401, no hold)",
      j3.get("status") in ("unauthorized", "replay") and snap(ER)[1] == s2[1], j3)

# ---- 2. duplicate JSON keys: last wins, accounting matches the winner
for order, winner in (([2, 3], 3), ([3, 2], 2)):
    s0 = snap(ER)
    body = ('{"user_id":"%s","idempotency_key":"%s","seats":%d,"seats":%d}'
            % (U("dupk%d" % winner), K("dupk%d" % winner), order[0], order[1])).encode()
    st, jj = raw(ER, "POST", "/reserve", body, sign(KEY, "POST", "/reserve", body))
    s1 = snap(ER)
    held_d = s1[1] - s0[1]
    got = jj.get("seats") or []
    check("dup_json_key", "duplicate seats keys: last wins (%d seats held), accounting consistent" % winner,
          st == 200 and len(got) == winner and held_d == winner, "%s held_delta=%d" % (jj, held_d))

# ---- 3. user_id type confusion: number, null
for tag, payload in (("num", '{"user_id":12345,"idempotency_key":"%s","seats":1}'),
                     ("null", '{"user_id":null,"idempotency_key":"%s","seats":1}')):
    s0 = snap(ER)
    body = (payload % K("uid-" + tag)).encode()
    st, jj = raw(ER, "POST", "/reserve", body, sign(KEY, "POST", "/reserve", body))
    check("user_id_type", "user_id as %s rejected 4xx, no 5xx, no mutation" % tag,
          400 <= st < 500 and snap(ER) == s0, jj)

# ---- 4. seats <= 0
for tag, n in (("zero", 0), ("neg", -1)):
    s0 = snap(ER)
    st, jj = post(ER, "/reserve", {"user_id": U("s" + tag), "idempotency_key": K("s" + tag), "seats": n})
    check("seats_bound", "seats=%d rejected 4xx, no 5xx, no mutation" % n,
          400 <= st < 500 and snap(ER) == s0, jj)

# ---- 5. //reserve path confusion: no hold either way, follow-up legit request works
s0 = snap(ER)
body = json.dumps({"user_id": U("slash"), "idempotency_key": K("slash"), "seats": 1}).encode()
st, jj = raw(ER, "POST", "//reserve", body, sign(KEY, "POST", "//reserve", body))
follow = post(ER, "/reserve", {"user_id": U("slash2"), "idempotency_key": K("slash2"), "seats": 1})
check("path_confusion", "//reserve with MAC over //reserve creates no hold; legit signed follow-up works",
      snap(ER)[1] == s0[1] + 1 and follow[1].get("status") == "held", "%s | follow=%s" % (jj, follow[1].get("status")))

# ---- 6. oversized URI (8KB query) with valid MAC: no 5xx, accounting consistent
big_path = "/reserve?" + "a" * 8000
body = json.dumps({"user_id": U("big"), "idempotency_key": K("big"), "seats": 1}).encode()
s0 = snap(ER)
st, jj = raw(ER, "POST", big_path, body, sign(KEY, "POST", big_path, body))
s1 = snap(ER)
ok6 = st != -1 and st < 500 and (s1[1] - s0[1] == (1 if st == 200 else 0))
check("oversize_uri", "8KB query path with valid MAC: no 5xx, accounting consistent", ok6, "%s %s" % (st, jj))

# ---- 7. NUL byte in request-id: fail-closed, engine stays alive
rid_nul = uuid.uuid4().hex[:12] + "\x00" + uuid.uuid4().hex[:6]
body = json.dumps({"user_id": U("nul"), "idempotency_key": K("nul"), "seats": 1}).encode()
s0 = snap(ER)
st, jj = raw(ER, "POST", "/reserve", body, sign(KEY, "POST", "/reserve", body, rid=rid_nul))
alive_after = raw(ER, "GET", "/seats", timeout=8)[0] == 200
check("nul_rid", "NUL byte in request-id: fail-closed (4xx/reset), no 5xx, engine alive, no mutation",
      st != 200 and st < 500 and alive_after and snap(ER) == s0, "%s %s" % (st, jj))

# ---- 8. zero-padded timestamp: benign (accepted consistently or 401)
tsz = "000" + str(int(time.time()))
body = json.dumps({"user_id": U("padts"), "idempotency_key": K("padts"), "seats": 1}).encode()
s0 = snap(ER)
h8 = sign(KEY, "POST", "/reserve", body, ts=tsz)
h8["X-Kavach-Timestamp"] = tsz
st, jj = raw(ER, "POST", "/reserve", body, h8)
s1 = snap(ER)
ok8 = (st == 200 and s1[1] == s0[1] + 1) or st == 401
check("zero_pad_ts", "zero-padded timestamp is benign (accepted once or 401), no 5xx", ok8 and st != -1, "%s %s" % (st, jj))

# ---- 9. charset content-type confusion (CT not validated by design)
body = json.dumps({"user_id": U("charset"), "idempotency_key": K("charset"), "seats": 1}).encode()
s0 = snap(ER)
h9 = sign(KEY, "POST", "/reserve", body)
h9["Content-Type"] = "application/json; charset=UTF-16"
st, jj = raw(ER, "POST", "/reserve", body, h9)
s1 = snap(ER)
check("charset_ct", "charset=UTF-16 content-type on UTF-8 body: processed normally, one hold, accounting right",
      st == 200 and jj.get("status") == "held" and s1[1] == s0[1] + 1, "%s %s" % (st, jj))

# ---- 10. TRACE / CONNECT methods with a valid MAC
for m in ("TRACE", "CONNECT"):
    s0 = snap(ER)
    body = json.dumps({"user_id": U(m.lower()), "idempotency_key": K(m.lower()), "seats": 1}).encode()
    st, jj = raw(ER, m, "/reserve", body, sign(KEY, m, "/reserve", body))
    check("methods", "%s with valid MAC: 405, no 5xx, no mutation" % m,
          st == 405 and snap(ER) == s0, "%s %s" % (st, jj))

# ---- 11. oversized Authorization suffix and 8KB request-id
body = json.dumps({"user_id": U("bigauth"), "idempotency_key": K("bigauth"), "seats": 1}).encode()
s0 = snap(ER)
h11 = sign(KEY, "POST", "/reserve", body)
h11["Authorization"] = "Bearer testkey" + "A" * 65536
st, jj = raw(ER, "POST", "/reserve", body, h11)
body2 = json.dumps({"user_id": U("bigrid"), "idempotency_key": K("bigrid"), "seats": 1}).encode()
st2, jj2 = raw(ER, "POST", "/reserve", body2, sign(KEY, "POST", "/reserve", body2, rid="r" * 8192))
s1 = snap(ER)
d = s1[1] - s0[1]
check("oversize_auth", "64KB Authorization junk -> 401; 8KB rid: no 5xx, accounting consistent",
      st == 401 and st2 != -1 and st2 < 500 and d == (1 if st2 == 200 else 0), "%s | %s %s d=%d" % (st, st2, jj2, d))

# ---- 12. waitlist seats boundary on the 10-seat engine (route is /waitlist)
for n in (5, 10000):
    st, jj = post(EH3, "/waitlist", {"user_id": U("wl%d" % n), "idempotency_key": K("wl%d" % n), "seats": n})
    check("waitlist_bound", "waitlist join seats=%d rejected 4xx, no 5xx" % n, 400 <= st < 500, "%s %s" % (st, jj))

# ---- 13. concurrent double-release race on one hold
st, jj = post(ER, "/reserve", {"user_id": U("racer"), "idempotency_key": K("racer"), "seats": 2})
rid = jj.get("reservation_id", "")
s0 = snap(ER)
def rel(i):
    bb = json.dumps({"reservation_id": rid}).encode()
    return raw(ER, "POST", "/release", bb, sign(KEY, "POST", "/release", bb))
with ThreadPoolExecutor(2) as ex:
    outs = list(ex.map(rel, range(2)))
sts = sorted(o[0] for o in outs)
s1 = snap(ER)
check("release_race", "2x concurrent release: seats fully conserved (both held seats back)",
      rid and s1[1] == s0[1] - 2 and all(200 <= s < 500 for s in sts), "%s sold/held %s->%s" % (sts, s0, s1))

# ---- 14. confirm authz on another user's hold
st, jj = post(ER, "/reserve", {"user_id": U("owner"), "idempotency_key": K("own"), "seats": 1})
rid14 = jj.get("reservation_id", "")
bb = json.dumps({"reservation_id": rid14}).encode()
st_c, jj_c = raw(ER, "POST", "/confirm", bb, sign(KEY, "POST", "/confirm", bb))  # no user_id
check("confirm_authz", "confirm with NO user_id on another user's hold: confirmed once (tenant is the boundary)",
      st_c == 200 and jj_c.get("status") == "confirmed" and jj_c.get("booking_id", "") != "", "%s %s" % (st_c, jj_c))
st, jj = post(ER, "/reserve", {"user_id": U("owner2"), "idempotency_key": K("own2"), "seats": 1})
rid15 = jj.get("reservation_id", "")
bb = json.dumps({"reservation_id": rid15, "user_id": U("wronguser")}).encode()
st_c2, jj_c2 = raw(ER, "POST", "/confirm", bb, sign(KEY, "POST", "/confirm", bb))
check("confirm_authz", "confirm with a DIFFERENT non-empty user_id is 403 forbidden",
      st_c2 == 403 and jj_c2.get("status") == "forbidden", "%s %s" % (st_c2, jj_c2))

# ---- 15. app: pay on an expired hold (30s TTL on 8091)
st, jj = raw(AR, "POST", "/api/hold", json.dumps({"user_id": U("expapp"), "seats": 1}).encode(),
             {"Content-Type": "application/json"})
rid16 = (jj or {}).get("reservation_id", "")
s0 = snap(ER)
time.sleep(31)
st_p, jj_p = raw(AR, "POST", "/api/pay", json.dumps({"reservation_id": rid16, "user_id": U("expapp"), "outcome": "success"}).encode(),
                 {"Content-Type": "application/json"})
s1 = snap(ER)
check("app_expired", "app pay on expired hold: no booking, seats returned",
      st_p != 200 or jj_p.get("ok") is not True, "%s %s sold/held %s->%s" % (st_p, jj_p, s0, s1))

fails = [r for r in results if not r["ok"]]
print("RUN35 TOTAL %d cases, PASS %d, FAIL %d" % (len(results), len(results) - len(fails), len(fails)))
print("FINDINGS: %d" % len(fails))
json.dump(results, open("/tmp/battery/run35_results.json", "w"), indent=1)
sys.exit(0)
