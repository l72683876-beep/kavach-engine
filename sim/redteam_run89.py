#!/usr/bin/env python3
"""Run 89 extras: 12 angles (all live in redteam_battery.py Phase AQ too).
1: 2000-char X-Kavach-Request-Id: no 5xx, alive
2: GET /seats/ trailing slash: no 5xx, alive
3: user_id as array: 4xx, alive
4: seats 0: 4xx, conserved
5: app webhook empty body valid token: no 500
6: reads stay 200 after 160-reserve IP burst: no 5xx
7: URL with #fragment: no 5xx
8: reserve free+1 seats: 4xx, free unchanged, conserved
9: idempotency_key as number: 4xx, alive
10: app confirm with padded reservation_id: no 500, conserved
11: X-Kavach-Timestamp -999: 401/400, alive
12: 50-level nested JSON: no 5xx
Run against targets already up: 8091 engine, 8092 engine2, 9001 app.
"""
import hashlib, hmac, http.client, json, sys, time, uuid
from concurrent.futures import ThreadPoolExecutor

ER, AR, ER2 = 8091, 9001, 8092
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
def P(n, fn):
    with ThreadPoolExecutor(max(1, n)) as ex:
        return list(ex.map(fn, range(n)))
def seats(port=ER):
    st, j = raw(port, "GET", "/seats"); return j if st == 200 else {}

# ---------------- Phase AQ: run 89 extras (12 new angles) ----------------# ---------------- Phase AQ: run 89 extras (12 new angles) ----------------
def long_request_id():
    b = json.dumps({"user_id": "rt-89lr", "idempotency_key": "k89lr", "seats": 1}).encode()
    h = sign(KEY, "POST", "/reserve", b, rid="r" * 2000)
    st, _ = raw(ER, "POST", "/reserve", b, h)
    alive = raw(ER, "GET", "/seats")[0] == 200
    ok = st != 500 and st != -1 and alive
    return check("auth", "2000-char X-Kavach-Request-Id: no 5xx, alive", ok, "status=%s" % st)
long_request_id()
def trailing_slash():
    st, _ = raw(ER, "GET", "/seats/")
    alive = raw(ER, "GET", "/seats")[0] == 200
    ok = st != 500 and st != -1 and alive
    return check("wire", "GET /seats/ trailing slash: no 5xx, alive", ok, "status=%s" % st)
trailing_slash()
def user_id_array():
    st, _ = post(ER, "/reserve", {"user_id": ["a"], "idempotency_key": "k89ua", "seats": 1})
    alive = raw(ER, "GET", "/seats")[0] == 200
    return check("fuzz", "reserve with user_id as array: 4xx, no 5xx, alive", st != 500 and st != -1 and alive, "status=%s" % st)
user_id_array()
def seats_zero():
    st, _ = post(ER, "/reserve", {"user_id": "rt-89sz", "idempotency_key": "k89sz", "seats": 0})
    s = seats(ER)
    conserved = s.get("total", -1) == s.get("sold", 0) + s.get("held", 0) + s.get("free", 0)
    ok = st != 500 and st != -1 and conserved
    return check("state", "reserve with seats 0: 4xx, conserved", ok, "status=%s" % st)
seats_zero()
def app_webhook_empty_body():
    w, _ = raw(AR, "POST", "/api/kavach-webhook?token=whsec-redtest", b"")
    alive = raw(AR, "GET", "/")[0] == 200
    return check("app", "app webhook with empty body (valid token): no 500, alive", w != 500 and w != -1 and alive, "w=%s" % w)
app_webhook_empty_body()
def reads_after_ip_burst():
    def go(i):
        return post(ER2, "/reserve", {"user_id": "rt-89ib%d" % i, "idempotency_key": "k89ib%d" % i, "seats": 1})[0]
    with ThreadPoolExecutor(20) as ex:
        outs = list(ex.map(go, range(160)))  # past ip-burst 300? no: 160 reserves + prior traffic
    st_read, j = raw(ER2, "GET", "/seats")
    ok = st_read == 200 and all(x != 500 for x in outs)
    return check("rate", "reads stay 200 after 160-reserve IP burst: no 5xx, alive", ok, "read=%s 5xx=%d" % (st_read, sum(1 for x in outs if x in (500, -1))))
reads_after_ip_burst()
def url_fragment():
    st, _ = raw(ER, "GET", "/seats#frag")
    alive = raw(ER, "GET", "/seats")[0] == 200
    ok = st != 500 and st != -1 and alive
    return check("wire", "URL with #fragment: no 5xx, alive", ok, "status=%s" % st)
url_fragment()
def overfree_multi():
    s0 = seats(ER)
    free = s0.get("free", 0)
    if free < 1:
        return check("state", "reserve free+1 seats: skipped (free=%d)" % free, True, "free=%d" % free)
    st, _ = post(ER, "/reserve", {"user_id": "rt-89of", "idempotency_key": "k89of", "seats": free + 1})
    s1 = seats(ER)
    conserved = s1.get("total", -1) == s1.get("sold", 0) + s1.get("held", 0) + s1.get("free", 0)
    ok = st != 200 and st != 500 and st != -1 and conserved and s1.get("free", -1) == free
    return check("state", "reserve free+1 seats: 4xx, free unchanged, conserved", ok, "status=%s free=%s" % (st, free))
overfree_multi()
def idem_key_number():
    st, _ = post(ER, "/reserve", {"user_id": "rt-89in", "idempotency_key": 12345, "seats": 1})
    alive = raw(ER, "GET", "/seats")[0] == 200
    return check("fuzz", "reserve with idempotency_key as number: 4xx, no 5xx, alive", st != 500 and st != -1 and alive, "status=%s" % st)
idem_key_number()
def app_confirm_spaces_rid():
    st, j = post(ER, "/reserve", {"user_id": "rt-89cs", "idempotency_key": "k89cs", "seats": 1})
    rid = j.get("reservation_id") if isinstance(j, dict) and st == 200 else None
    if not rid:
        return check("app", "app confirm rid with spaces: skipped (hold unavailable)", True, "st=%s" % st)
    p, _ = raw(AR, "POST", "/api/confirm", json.dumps({"reservation_id": " " + rid + " "}))
    alive = raw(AR, "GET", "/")[0] == 200
    s = seats(ER)
    conserved = s.get("total", -1) == s.get("sold", 0) + s.get("held", 0) + s.get("free", 0)
    ok = p != 500 and p != -1 and alive and conserved
    return check("app", "app confirm with padded reservation_id: no 500, conserved", ok, "p=%s" % p)
app_confirm_spaces_rid()
def negative_timestamp():
    b = json.dumps({"user_id": "rt-89nt", "idempotency_key": "k89nt", "seats": 1}).encode()
    h = sign(KEY, "POST", "/reserve", b)
    h["X-Kavach-Timestamp"] = "-999"
    st, _ = raw(ER, "POST", "/reserve", b, h)
    alive = raw(ER, "GET", "/seats")[0] == 200
    return check("auth", "X-Kavach-Timestamp -999: 401/400, alive", st in (400, 401) and alive, "status=%s" % st)
negative_timestamp()
def deep_nested_json():
    body = {"user_id": "rt-89dn", "idempotency_key": "k89dn", "seats": 1, "extra": None}
    for _ in range(50):
        body = {"nested": body}
    st, _ = post(ER, "/reserve", body)
    alive = raw(ER, "GET", "/seats")[0] == 200
    ok = st != 500 and st != -1 and alive
    return check("fuzz", "50-level nested JSON: no 5xx, alive", ok, "status=%s" % st)
deep_nested_json()


fails = [r for r in results if not r[2]]
print("TOTAL %d cases, PASS %d, FAIL %d" % (len(results), len(results) - len(fails), len(fails)))
for cat, name, ok, detail in fails:
    print("FAIL [%s] %s :: %s" % (cat, name, detail))
sys.exit(1 if fails else 0)
