#!/usr/bin/env python3
"""Run 31 extras: 15 new angles (HMAC query-string binding, duplicate signature
headers read deterministically, CRLF request-id smuggling, float/negative/plus
timestamps, JSON number forms for seats, unicode-escape user_id, triple race on
one rid, N-way concurrent confirm, duplicate waitlist join, app hold bool/list
fuzz, idem key bool/whitespace/100KB, bearer tab/case, method-override +
OPTIONS/HEAD, pipelined unsigned request proven by seat delta, webhook body
tamper proven by seat delta)."""
import hashlib, hmac, http.client, json, socket, sys, time, uuid
from concurrent.futures import ThreadPoolExecutor
ER, AR, ER2 = 8091, 9001, 8092
KEY, KEY2, SECRET = "testkey", "otherkey", "testsecret"
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
def raw(port, method, path, body=None, headers=None):
    b = body.encode() if isinstance(body, str) else body
    headers = dict(headers or {})
    if b is not None and "Content-Type" not in headers:
        headers["Content-Type"] = "application/json"
    try:
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=25)
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
def K(tag): return "k31-" + N + "-" + tag
def U(tag): return "rt31-" + N + "-" + tag

# 1. HMAC query-string binding
b1 = json.dumps({"user_id": U("qs"), "idempotency_key": K("qs1"), "seats": 1}).encode()
st_t = raw(ER, "POST", "/reserve?x=1", b1, sign(KEY, "POST", "/reserve", b1))[0]
st_s = raw(ER, "POST", "/reserve?x=2", b1, sign(KEY, "POST", "/reserve?x=2", b1))[0]
check("auth", "query string outside MAC -> 401; signed full URI accepted", st_t == 401 and st_s in (200, 409), "tampered=%s signed=%s" % (st_t, st_s))

# 2. duplicate signature headers: each call signs over ITS OWN ts/rid so the
# "valid" line is truly valid for exactly the header block it rides on.
b2 = json.dumps({"user_id": U("dup"), "idempotency_key": K("dup2"), "seats": 1}).encode()
def dup_sig(first, second):
    ts = str(int(time.time())); rid = uuid.uuid4().hex
    mac = hmac.new(SECRET.encode(), (ts + "\n" + rid + "\nPOST\n/reserve\n" + KEY + "\n").encode() + b2, hashlib.sha256).hexdigest()
    use = {"V": mac, "I": "0" * 64}
    head = "POST /reserve HTTP/1.1\r\nHost: h\r\nContent-Length: %d\r\nConnection: close\r\n" % len(b2)
    head += "Authorization: Bearer " + KEY + "\r\n"
    head += "X-Kavach-Timestamp: %s\r\nX-Kavach-Request-Id: %s\r\n" % (ts, rid)
    head += "X-Kavach-Signature: %s\r\nX-Kavach-Signature: %s\r\n" % (use[first], use[second])
    head += "Content-Type: application/json\r\n\r\n"
    try:
        s = socket.create_connection(("127.0.0.1", ER), timeout=10)
        s.sendall(head.encode() + b2)
        r = s.recv(200).decode("utf-8", "replace"); s.close()
        return r.splitlines()[0].split(" ")[1] if r else "empty"
    except Exception as e:
        return "ERR " + str(e)[:60]
r_vv = dup_sig("V", "V")   # both lines valid and identical
r_if = dup_sig("I", "V")   # invalid first, valid second
r_vf = dup_sig("V", "I")   # valid first, invalid second
check("auth", "duplicate signature headers fail closed or read one deterministic value (no ambiguity bypass)",
      r_if == "401" and r_vf in ("200", "401", "409") and r_vf == r_vv, "I,V=%s V,I=%s V,V=%s" % (r_if, r_vf, r_vv))

# 3. request-id with CRLF (header injection) via raw socket
b3 = json.dumps({"user_id": U("crlf"), "idempotency_key": K("crlf"), "seats": 1}).encode()
h3 = sign(KEY, "POST", "/reserve", b3, rid="abc\r\nX-Inj: 1")
req3 = "POST /reserve HTTP/1.1\r\nHost: h\r\nContent-Length: %d\r\nConnection: close\r\n" % len(b3)
for k, v in h3.items():
    req3 += "%s: %s\r\n" % (k, v.replace("\r\n", " ")) if k == "X-Kavach-Request-Id" else "%s: %s\r\n" % (k, v)
req3 += "X-Kavach-Request-Id: abc\r\nX-Inj: 1\r\n"  # real injected header line
try:
    s = socket.create_connection(("127.0.0.1", ER), timeout=10)
    s.sendall((req3 + "\r\n").encode() + b3)
    r3 = s.recv(200).decode("utf-8", "replace"); s.close()
except Exception as e:
    r3 = "ERR " + str(e)[:60]
code3 = r3.splitlines()[0].split(" ")[1] if r3 and " " in r3.splitlines()[0] else "ERR"
check("auth", "request-id CRLF smuggling rejected (4xx, no 5xx, no injection passthrough)", code3 in ("400", "401", "403", "406"), code3)

# 4. timestamp variants: float, negative, plus-signed
b4 = json.dumps({"user_id": U("ts"), "idempotency_key": K("ts"), "seats": 1}).encode()
t_ok = raw(ER, "POST", "/reserve", b4, sign(KEY, "POST", "/reserve", b4, ts=str(int(time.time()))))[0]
t_float = raw(ER, "POST", "/reserve", b4, sign(KEY, "POST", "/reserve", b4, ts=str(float(int(time.time())))))[0]
t_neg = raw(ER, "POST", "/reserve", b4, sign(KEY, "POST", "/reserve", b4, ts=str(-int(time.time()))))[0]
t_plus = raw(ER, "POST", "/reserve", b4, sign(KEY, "POST", "/reserve", b4, ts="+" + str(int(time.time()))))[0]
check("auth", "float/negative timestamps rejected (401), int accepted, plus-sign same instant benign", t_ok == 200 and t_float == 401 and t_neg == 401 and t_plus in (200, 409),
      "int=%s float=%s neg=%s plus=%s" % (t_ok, t_float, t_neg, t_plus))

# 5. seats JSON number forms
def seats_form(form):
    b = ('{"user_id":"%s","idempotency_key":"%s","seats":%s}' % (U("n"), K("n"), form)).encode()
    return raw(ER, "POST", "/reserve", b, sign(KEY, "POST", "/reserve", b))[0]
f01, f02, f03, f04 = seats_form("2e0"), seats_form("1E2"), seats_form("-0"), seats_form("9007199254740993")
check("input", "exponent/neg-zero/2^53+1 seats rejected or safe (no 5xx, no silent oversell)", all(x in (400, 422) for x in (f01, f02, f03, f04)),
      "2e0=%s 1E2=%s -0=%s big=%s" % (f01, f02, f03, f04))

# 6. unicode-escaped user_id normalizes, never 5xx
bu_esc = ('{"user_id":"%s\\\\u0075u","idempotency_key":"%s","seats":1}' % (U("uu"), K("uu"))).encode().decode("utf-8").replace("\\\\u0075", "\\u0075").encode()
st_u = raw(ER, "POST", "/reserve", bu_esc, sign(KEY, "POST", "/reserve", bu_esc))[0]
check("input", "unicode-escaped user_id handled sanely (200/4xx, never 5xx)", st_u in (200, 400, 409, 422), st_u)

# 7. triple race on one rid: confirm + release + confirm concurrently
st7, j7 = post(ER, "/reserve", {"user_id": U("tr"), "idempotency_key": K("tr"), "seats": 2})
rid7 = (j7 or {}).get("reservation_id")
free7 = seats(ER).get("free")
def c7(kind):
    if kind == "c": return post(ER, "/confirm", {"reservation_id": rid7, "user_id": U("tr")})[0]
    return post(ER, "/release", {"reservation_id": rid7, "user_id": U("tr")})[0]
outs7 = list(ThreadPoolExecutor(3).map(c7, ["c", "r", "c"])) if rid7 else []
time.sleep(0.5)
net = (seats(ER).get("free") or 0) - (free7 or 0)
check("race", "confirm+release+confirm race on one rid: seats conserved", rid7 is not None and net in (0, 2), "outs=%s net=%s" % (outs7, net))

# 8. 8x concurrent confirm on same rid: exactly one success
st8, j8 = post(ER, "/reserve", {"user_id": U("c8"), "idempotency_key": K("c8"), "seats": 2})
rid8 = (j8 or {}).get("reservation_id")
def conf8(_):
    return post(ER, "/confirm", {"reservation_id": rid8, "user_id": U("c8")})[0]
free8_pre = seats(ER).get("free")
outs8 = list(ThreadPoolExecutor(8).map(conf8, range(8))) if rid8 else [0] * 8
time.sleep(0.5)
free8_post = seats(ER).get("free")
# reserve held 2 (already off free_pre). Confirm is idempotent: all-200 allowed ONLY if seats conserved (free unchanged)
check("race", "8x concurrent confirm same rid: idempotent, seats conserved (no double-consume)",
      rid8 is not None and all(o in (200, 400, 401, 404, 409, 410) for o in outs8) and (free8_post or 0) == (free8_pre or 0),
      "outs=%s free %s->%s" % (outs8, free8_pre, free8_post))

# 9. duplicate waitlist join (ER2 is sold out by design after the battery)
wjb = json.dumps({"user_id": U("w"), "idempotency_key": K("w1"), "seats": 1}).encode()
w1 = raw(ER2, "POST", "/waitlist", wjb, sign(KEY, "POST", "/waitlist", wjb))
wjb2 = json.dumps({"user_id": U("w"), "idempotency_key": K("w2"), "seats": 1}).encode()
w2 = raw(ER2, "POST", "/waitlist", wjb2, sign(KEY, "POST", "/waitlist", wjb2))
check("waitlist", "duplicate waitlist join: first 200, second 200-or-4xx (no crash, no dup entry explosion)",
      w1[0] == 200 and w2[0] in (200, 400, 409, 422), "%s/%s" % (w1[0], w2[0]))

# 10. app hold: bool seats and list user_id rejected
ha = raw(AR, "POST", "/api/hold", json.dumps({"user_id": U("hb"), "seats": True}))
hb = raw(AR, "POST", "/api/hold", json.dumps({"user_id": [U("hl")], "seats": 1}))
check("app", "app hold: bool seats and list user_id rejected (4xx, no 5xx)", 500 not in (ha[0], hb[0]) and ha[0] >= 400 and hb[0] >= 400, "%s/%s" % (ha[0], hb[0]))

# 11. idem key: bool, whitespace-only, 100KB
b_a = ('{"user_id":"%s","idempotency_key":true,"seats":1}' % U("ik")).encode()
k_bool = raw(ER, "POST", "/reserve", b_a, sign(KEY, "POST", "/reserve", b_a))[0]
b_b = json.dumps({"user_id": U("ik2"), "idempotency_key": "   ", "seats": 1}).encode()
k_ws = raw(ER, "POST", "/reserve", b_b, sign(KEY, "POST", "/reserve", b_b))[0]
b_c = json.dumps({"user_id": U("ik3"), "idempotency_key": "x" * 100000, "seats": 1}).encode()
k_big = raw(ER, "POST", "/reserve", b_c, sign(KEY, "POST", "/reserve", b_c))[0]
check("input", "idem key bool/whitespace/100KB: no 5xx, bool not silently accepted", k_bool in (400, 422) and k_ws in (200, 400, 409, 422) and k_big in (200, 400, 409, 413, 422),
      "%s/%s/%s" % (k_bool, k_ws, k_big))

# 12. bearer tab and wrong case rejected
b12 = json.dumps({"user_id": U("bw"), "idempotency_key": K("bw"), "seats": 1}).encode()
h12 = sign(KEY, "POST", "/reserve", b12)
ok12 = True
for variant in ("tab", "wrong_case"):
    hv = dict(h12); hv["Authorization"] = {"tab": "Bearer\ttestkey", "wrong_case": "Bearer TestKey"}[variant]
    stv = raw(ER, "POST", "/reserve", b12, hv)[0]
    ok12 = ok12 and stv in (401, 403)
check("auth", "bearer tab and wrong-case not accepted", ok12, "tab/case both 401" if ok12 else "one accepted")

# 13. method override ignored; OPTIONS/HEAD safe
b13 = json.dumps({"user_id": U("mo"), "idempotency_key": K("mo"), "seats": 1}).encode()
h13 = sign(KEY, "POST", "/reserve", b13)
h13["X-HTTP-Method-Override"] = "DELETE"
mo = raw(ER, "POST", "/reserve", b13, h13)[0]
opt = raw(ER, "OPTIONS", "/reserve")[0]
head = raw(ER, "HEAD", "/seats")[0]
check("auth", "method-override ignored; OPTIONS/HEAD safe (no 5xx)", mo in (200, 400, 401, 405) and opt in (200, 204, 401, 404, 405) and head in (200, 401, 404, 405), "ovr=%s opt=%s head=%s" % (mo, opt, head))

# 14. pipelined unsigned request: proven by seat delta, not just response codes
b14 = json.dumps({"user_id": U("pipe"), "idempotency_key": K("pipe"), "seats": 2}).encode()
h14 = sign(KEY, "POST", "/reserve", b14)
req1 = "POST /reserve HTTP/1.1\r\nHost: h\r\nContent-Length: %d\r\n" % len(b14)
req1 += "".join("%s: %s\r\n" % (k, v) for k, v in h14.items()) + "Connection: keep-alive\r\n\r\n"
unsigned = json.dumps({"user_id": U("pipe2"), "idempotency_key": K("pipe2"), "seats": 2}).encode()
req2 = "POST /reserve HTTP/1.1\r\nHost: h\r\nContent-Length: %d\r\nContent-Type: application/json\r\nAuthorization: Bearer testkey\r\nConnection: close\r\n\r\n" % len(unsigned)
free_pre = seats(ER).get("free")
try:
    s = socket.create_connection(("127.0.0.1", ER), timeout=10)
    s.sendall(req1.encode() + b14 + req2.encode() + unsigned)
    buf = b""; s.settimeout(5)
    try:
        while buf.count(b"HTTP/1.1") < 2:
            chunk = s.recv(65536)
            if not chunk: break
            buf += chunk
    except Exception:
        pass
    s.close()
except Exception as e:
    buf = ("ERR " + str(e)[:60]).encode()
codes14 = [l.split(" ")[1] for l in buf.decode("utf-8", "replace").split("\r\n") if l.startswith("HTTP/1.1")]
time.sleep(0.5)
free_post = seats(ER).get("free")
# signed first holds 2 seats; the unsigned second must NOT execute (delta == 2, and if a second response exists it must be 401)
second_ran = free_post == (free_pre or 0) - 4
check("auth", "pipelined unsigned request never executes (seat delta exactly the signed request's, 401 if answered)",
      len(codes14) >= 1 and not second_ran and (len(codes14) == 1 or "401" in codes14[1:]),
      "codes=%s free %s->%s" % (codes14, free_pre, free_post))

# 15. app webhook: valid token, forged event types must not mutate seats
wh = raw(AR, "POST", "/api/kavach-webhook", json.dumps({"type": "waitlist_fulfilled", "user_id": U("wh"), "seats": 5, "token": "whsec-redtest"}))
free_pre_wh = seats(ER).get("free")
wh2 = raw(AR, "POST", "/api/kavach-webhook", json.dumps({"type": "admin_override", "action": "release_all", "token": "whsec-redtest"}))
time.sleep(0.3)
free_after_wh = seats(ER).get("free")
check("app", "webhook body tamper (forged event types) rejected, seats unchanged", wh[0] >= 400 and wh2[0] >= 400 and free_after_wh == free_pre_wh,
      "%s/%s free=%s->%s" % (wh[0], wh2[0], free_pre_wh, free_after_wh))

fails = [r for r in results if not r["ok"]]
json.dump({"run": 31, "results": results}, open("/tmp/battery/run31_extra.json", "w"), indent=1)
print("EXTRA: %d/%d pass, %d fail" % (len(results) - len(fails), len(results), len(fails)))
sys.exit(1 if fails else 0)
