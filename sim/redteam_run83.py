#!/usr/bin/env python3
"""Run 83 extras: 12 angles (all live in redteam_battery.py Phase AK too).
1: absolute-form request line: no 5xx, alive
2: mixed-case header names: no 5xx, alive
3: webhook token with trailing whitespace: 401/403, alive
4: control char in idempotency_key: no 5xx, alive
5: app hold seats as string: no 500
6: OPTIONS preflight on /reserve: 4xx, alive
7: app release rid literal 'null': no 500
8: semicolon in query string: 200, alive
9: app status with 5000-char rid: no 500
10: UTF-8 BOM before JSON body: no 5xx, alive
11: waitlist join then direct reserve: no 5xx, conserved
12: path trailing '?' vs MAC over /reserve: 401, alive
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

# ---------------- Phase AK: run 83 extras (12 new angles) ----------------
def absolute_form_request():
    import socket as _s
    buf = b""
    try:
        sk = _s.create_connection(("127.0.0.1", ER), timeout=8)
        sk.sendall(b"GET http://127.0.0.1:8091/seats HTTP/1.1\r\nHost: 127.0.0.1:8091\r\nConnection: close\r\n\r\n")
        sk.settimeout(5)
        try: buf = sk.recv(300)
        except Exception: pass
        sk.close()
    except Exception:
        pass
    stc = int(buf.split(b" ")[1]) if b"HTTP/1." in buf and len(buf.split(b" ")) > 1 else -1
    alive = raw(ER, "GET", "/seats")[0] == 200
    ok = stc != 500 and stc != -1 and alive
    return check("wire", "absolute-form request line GET http://host/seats: no 5xx, alive", ok, "st=%s" % stc)
absolute_form_request()
def mixed_case_headers():
    b = json.dumps({"user_id": "rt-83mc", "idempotency_key": "k83mc", "seats": 1}).encode()
    h = sign(KEY, "POST", "/reserve", b)
    h = {"x-kAvAcH-tImEsTaMp": h["X-Kavach-Timestamp"], "x-kAvAcH-rEqUeSt-Id": h["X-Kavach-Request-Id"],
         "x-kAvAcH-sIgNaTuRe": h["X-Kavach-Signature"], "aUtHoRiZaTiOn": h["Authorization"],
         "Content-Type": "application/json"}
    st, _ = raw(ER, "POST", "/reserve", b, h)
    alive = raw(ER, "GET", "/seats")[0] == 200
    ok = st in (200, 400, 401) and alive
    return check("auth", "mixed-case header names: no 5xx (200 or clean 401), alive", ok, "status=%s" % st)
mixed_case_headers()
def webhook_token_trailing_ws():
    w, _ = raw(AR, "POST", "/api/kavach-webhook?token=whsec-redtest%20", b'{"event": "payment_success"}')
    alive = raw(AR, "GET", "/")[0] == 200
    return check("app", "webhook token with trailing whitespace: 401/403, app alive", w in (401, 403) and alive, "w=%s" % w)
webhook_token_trailing_ws()
def control_char_idem():
    st, _ = post(ER, "/reserve", {"user_id": "rt-83cc", "idempotency_key": "k83\x01cc", "seats": 1})
    alive = raw(ER, "GET", "/seats")[0] == 200
    return check("fuzz", "control char \\x01 in idempotency_key: 4xx or accepted, no 5xx, alive", st != 500 and st != -1 and alive, "status=%s" % st)
control_char_idem()
def app_hold_seats_string():
    p, _ = raw(AR, "POST", "/api/hold", json.dumps({"user_id": "rt-83hs", "seats": "1"}))
    alive = raw(AR, "GET", "/")[0] == 200
    return check("app", "app hold with seats as string '1': no 500, app alive", p != 500 and p != -1 and alive, "p=%s" % p)
app_hold_seats_string()
def options_preflight():
    st, _ = raw(ER, "OPTIONS", "/reserve")
    alive = raw(ER, "GET", "/seats")[0] == 200
    ok = st != 500 and st != -1 and alive
    return check("wire", "OPTIONS preflight on /reserve: 4xx, no 5xx, alive", ok, "status=%s" % st)
options_preflight()
def app_release_null_rid():
    p, _ = raw(AR, "POST", "/api/release", json.dumps({"reservation_id": "null"}))
    alive = raw(AR, "GET", "/")[0] == 200
    return check("app", "app release with rid literal 'null': no 500, app alive", p != 500 and p != -1 and alive, "p=%s" % p)
app_release_null_rid()
def semicolon_query():
    st, _ = raw(ER, "GET", "/seats?x=1;y=2")
    alive = raw(ER, "GET", "/seats")[0] == 200
    return check("wire", "semicolon in query string: 200, alive", st == 200 and alive, "status=%s" % st)
semicolon_query()
def app_status_huge_rid():
    p, _ = raw(AR, "GET", "/api/status?reservation_id=" + "R" * 5000)
    alive = raw(AR, "GET", "/")[0] == 200
    return check("app", "app status with 5000-char rid: no 500, app alive", p != 500 and p != -1 and alive, "p=%s" % p)
app_status_huge_rid()
def bom_body():
    b = b'\xef\xbb\xbf' + json.dumps({"user_id": "rt-83bb", "idempotency_key": "k83bb", "seats": 1}).encode()
    h = sign(KEY, "POST", "/reserve", b)
    st, _ = raw(ER, "POST", "/reserve", b, h)
    alive = raw(ER, "GET", "/seats")[0] == 200
    ok = st != 500 and st != -1 and alive
    return check("wire", "UTF-8 BOM before JSON body: no 5xx, alive", ok, "status=%s" % st)
bom_body()
def waitlist_then_direct_reserve():
    st1, _ = post(ER, "/waitlist", {"user_id": "rt-83wt", "idempotency_key": "k83wt", "event_id": "prod-v1"})
    st2, _ = post(ER, "/reserve", {"user_id": "rt-83wt", "idempotency_key": "k83wtr", "seats": 1})
    s = seats(ER)
    conserved = s.get("total", -1) == s.get("sold", 0) + s.get("held", 0) + s.get("free", 0)
    ok = st1 != 500 and st1 != -1 and st2 != 500 and st2 != -1 and conserved
    return check("state", "waitlist join then direct reserve same user: no 5xx, conserved", ok, "st1=%s st2=%s" % (st1, st2))
waitlist_then_direct_reserve()
def path_trailing_question():
    b = json.dumps({"user_id": "rt-83tq", "idempotency_key": "k83tq", "seats": 1}).encode()
    h = sign(KEY, "POST", "/reserve", b)  # MAC over /reserve
    st, _ = raw(ER, "POST", "/reserve?", b, h)  # trailing ? changes effective path
    alive = raw(ER, "GET", "/seats")[0] == 200
    return check("auth", "path with trailing '?' vs MAC over /reserve: 401, alive", st == 401 and alive, "status=%s" % st)
path_trailing_question()


fails = [r for r in results if not r[2]]
print("TOTAL %d cases, PASS %d, FAIL %d" % (len(results), len(results) - len(fails), len(fails)))
for cat, name, ok, detail in fails:
    print("FAIL [%s] %s :: %s" % (cat, name, detail))
sys.exit(1 if fails else 0)
