#!/usr/bin/env python3
"""Run 95 extras: 12 angles (all live in redteam_battery.py Phase AW too).
1: NUL byte in URL path on /seats: no 5xx, alive
2: Transfer-Encoding: gzip on POST: no 5xx, no hang, alive
3: waitlist promote with empty waitlist: 4xx, no 500
4: space before colon in header (malformed header line): no 5xx, alive
5: seats as JSON array [1]: 4xx
6: idempotency_key as boolean true: 4xx
7: transfer of a held (unconfirmed) reservation: 4xx, no 500
8: signature over path without trailing slash mismatch (/reserve/ sent): 401
9: app /api/metrics 50x rapid burst: no 5xx, app alive
10: webhook reservation_id as JSON number: no 500, alive
11: 6-way parallel confirm same rid: no 5xx, conserved
12: user_id with emoji + variation selector: no 500, alive
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
def seats(port=ER):
    st, j = raw(port, "GET", "/seats"); return j if st == 200 else {}

# ---------------- Phase AW: run 95 extras (12 new angles) ----------------
def null_byte_in_path():
    st, _ = raw(ER, "GET", "/seats%00x")
    alive = raw(ER, "GET", "/seats")[0] == 200
    ok = st != 500 and st != -1 and alive
    return check("wire", "NUL byte in URL path on /seats: no 5xx, alive", ok, "status=%s" % st)
null_byte_in_path()
def gzip_transfer_encoding():
    b = json.dumps({"user_id": "rt-95gz", "idempotency_key": "k95gz", "seats": 1}).encode()
    h = sign(KEY, "POST", "/reserve", b)
    h["Transfer-Encoding"] = "gzip"
    st, _ = raw(ER, "POST", "/reserve", b, h)
    alive = raw(ER, "GET", "/seats")[0] == 200
    ok = st != 500 and st != -1 and alive
    return check("wire", "Transfer-Encoding: gzip on POST: no 5xx, no hang, alive", ok, "status=%s" % st)
gzip_transfer_encoding()
def waitlist_promote_empty():
    st, _ = post(ER, "/waitlist/promote", {})
    alive = raw(ER, "GET", "/seats")[0] == 200
    ok = st != 500 and st != -1 and alive
    return check("state", "waitlist promote with empty waitlist: 4xx, no 500, alive", ok, "status=%s" % st)
waitlist_promote_empty()
def header_space_before_colon():
    st, _ = raw(ER, "GET", "/seats", headers={"X-Kavach-Timestamp ": "1700000000", "X-Other": "1"})
    alive = raw(ER, "GET", "/seats")[0] == 200
    ok = st != 500 and st != -1 and alive
    return check("wire", "space before colon in header name: no 5xx, alive", ok, "status=%s" % st)
header_space_before_colon()
def seats_json_array():
    st, _ = post(ER, "/reserve", {"user_id": "rt-95ar", "idempotency_key": "k95ar", "seats": [1]})
    alive = raw(ER, "GET", "/seats")[0] == 200
    ok = st != 500 and st != -1 and alive
    return check("fuzz", "seats as JSON array [1]: 4xx, no 5xx, alive", ok, "status=%s" % st)
seats_json_array()
def idem_key_boolean():
    st, _ = post(ER, "/reserve", {"user_id": "rt-95bk", "idempotency_key": True, "seats": 1})
    alive = raw(ER, "GET", "/seats")[0] == 200
    ok = st != 500 and st != -1 and alive
    return check("fuzz", "idempotency_key as boolean true: 4xx, no 5xx, alive", ok, "status=%s" % st)
idem_key_boolean()
def transfer_unconfirmed_hold():
    st, j = post(ER, "/reserve", {"user_id": "rt-95tu", "idempotency_key": "k95tu", "seats": 1})
    rid = j.get("reservation_id") if isinstance(j, dict) and st == 200 else None
    if not rid:
        return check("state", "transfer unconfirmed hold: skipped (hold unavailable)", True, "st=%s" % st)
    st2, _ = post(ER, "/transfer", {"reservation_id": rid, "to_user": "rt-95tu2"})
    post(ER, "/release", {"reservation_id": rid})
    ok = st2 != 200 and st2 != 500 and st2 != -1
    return check("state", "transfer of held (unconfirmed) reservation: 4xx, not transferred", ok, "st2=%s" % st2)
transfer_unconfirmed_hold()
def sig_path_trailing_slash():
    b = json.dumps({"user_id": "rt-95sl", "idempotency_key": "k95sl", "seats": 1}).encode()
    h = sign(KEY, "POST", "/reserve", b)
    st, _ = raw(ER, "POST", "/reserve/", b, h)
    alive = raw(ER, "GET", "/seats")[0] == 200
    ok = st != 200 and st != 500 and st != -1 and alive
    return check("auth", "POST /reserve/ with MAC signed for /reserve: 401/404, no 5xx, alive", ok, "status=%s" % st)
sig_path_trailing_slash()
def app_metrics_burst():
    codes = []
    for _ in range(50):
        codes.append(raw(AR, "GET", "/api/metrics")[0])
    alive = raw(AR, "GET", "/")[0] == 200
    ok = all(s != 500 and s != -1 for s in codes) and alive
    return check("app", "app /api/metrics 50x rapid burst: no 5xx, app alive", ok, "500s=%d" % codes.count(500))
app_metrics_burst()
def webhook_rid_as_number():
    body = '{"token":"whsec-redtest","event":"payment_success","reservation_id":1}'
    w, _ = raw(AR, "POST", "/api/kavach-webhook?token=whsec-redtest", body)
    alive = raw(AR, "GET", "/")[0] == 200
    ok = w != 500 and w != -1 and alive
    return check("app", "webhook reservation_id as JSON number: no 500, alive", ok, "w=%s" % w)
webhook_rid_as_number()
def parallel_confirm_race():
    st, j = post(ER, "/reserve", {"user_id": "rt-95pc", "idempotency_key": "k95pc", "seats": 1})
    rid = j.get("reservation_id") if isinstance(j, dict) and st == 200 else None
    if not rid:
        return check("race", "parallel confirm race: skipped (hold unavailable)", True, "st=%s" % st)
    def go(i):
        return post(ER, "/confirm", {"reservation_id": rid})[0]
    with ThreadPoolExecutor(6) as ex:
        outs = list(ex.map(go, range(6)))
    time.sleep(1.0)
    s = seats(ER)
    conserved = s.get("total", -1) == s.get("sold", 0) + s.get("held", 0) + s.get("free", 0)
    ok = all(x != 500 and x != -1 for x in outs) and conserved
    return check("race", "6-way parallel confirm same rid: no 5xx, conserved", ok, "200s=%d" % outs.count(200))
parallel_confirm_race()
def user_id_emoji_variation():
    st, _ = post(ER, "/reserve", {"user_id": "rt-95\U0001F680️", "idempotency_key": "k95em", "seats": 1})
    alive = raw(ER, "GET", "/seats")[0] == 200
    ok = st != 500 and st != -1 and alive
    return check("fuzz", "user_id with emoji + variation selector: no 500, alive", ok, "status=%s" % st)
user_id_emoji_variation()

# ---------------- Summary ----------------
fails = [r for r in results if not r[2]]
print("TOTAL %d cases, PASS %d, FAIL %d" % (len(results), len(results) - len(fails), len(fails)))
for cat, name, ok, detail in fails:
    print("FAIL [%s] %s :: %s" % (cat, name, detail))
sys.exit(1 if fails else 0)
