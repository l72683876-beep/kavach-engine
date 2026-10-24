#!/usr/bin/env python3
"""Run 27 extra attack angles: 14 new variants, distinct from runs 19-26 (run26 helpers)."""
import json, time, http.client, subprocess, concurrent.futures as cf

ER, ET, FS, PT, ER3 = "http://127.0.0.1:8091", "http://127.0.0.1:8095", "http://127.0.0.1:8096", "http://127.0.0.1:8097", "http://127.0.0.1:8098"
APP = "http://127.0.0.1:9001"
KEY, KEY2, SECRET, SA = "testkey", "otherkey", "testsecret", "secretA"

def port_of(base): return int(base.rsplit(":", 1)[1])

def seats(base):
    try:
        c = http.client.HTTPConnection("127.0.0.1", port_of(base), timeout=5)
        c.request("GET", "/seats"); r = c.getresponse(); d = r.read(); c.close()
        return json.loads(d)
    except Exception:
        return {}

def invariant(s): return s.get("total") == s.get("free",0) + s.get("held",0) + s.get("sold",0)

def mac_of(secret, ts, rid, method, path, key, b):
    import hmac, hashlib
    return hmac.new(secret.encode(), (ts+"\n"+rid+"\n"+method+"\n"+path+"\n"+key+"\n").encode()+b.encode(), hashlib.sha256).hexdigest()

def req(base, method, path, body=None, key=KEY, secret=SECRET, raw_body=None, ts=None, rid=None, mac_override=None, auth=None, headers_extra=None):
    b = raw_body if raw_body is not None else (json.dumps(body) if body is not None else "")
    ts = ts if ts is not None else str(int(time.time()))
    rid = rid if rid is not None else "k27-%d" % time.time_ns()
    mac = mac_override if mac_override is not None else mac_of(secret, ts, rid, method, path, key, b)
    h = {"Authorization": auth if auth is not None else "Bearer "+key,
         "X-Kavach-Timestamp": ts, "X-Kavach-Request-Id": rid, "X-Kavach-Signature": mac,
         "Content-Type": "application/json"}
    if headers_extra: h.update(headers_extra)
    host, port = base.rsplit(":", 1)[0].replace("http://",""), port_of(base)
    try:
        c = http.client.HTTPConnection(host, port, timeout=15)
        c.request(method, path, body=b.encode() if b else None, headers=h)
        r = c.getresponse(); d = r.read().decode(); c.close()
        try: return r.status, json.loads(d)
        except Exception: return r.status, {"raw": d[:120]}
    except Exception as ex:
        return -1, {"raw": str(ex)[:120]}

def reserve(base, user, tag, seats_n=1, key=KEY, secret=SECRET):
    return req(base, "POST", "/reserve", {"user_id": user, "seats": seats_n, "idempotency_key": tag}, key=key, secret=secret)

def wait_drain(base, max_s=55):
    t0 = time.time()
    while time.time() - t0 < max_s:
        s = seats(base)
        if s and s.get("held", 0) == 0: return True
        time.sleep(2)
    return False

R = []
def check(name, ok, detail=""):
    R.append((ok, name, detail)); print(("PASS" if ok else "FAIL"), name, detail)

wait_drain(ER); wait_drain(FS)

# 1: seats = -1 (negative): clean reject, no hold consumed
s1a = seats(FS)
st1, j1 = req(FS, "POST", "/reserve", raw_body='{"user_id":"r27neg","seats":-1,"idempotency_key":"k27-neg"}')
s1b = seats(FS)
check("fuzz seats=-1: clean reject, no hold consumed", st1 in (400,422) and s1a == s1b and invariant(s1b),
      f"st={st1} j={json.dumps(j1)[:60]}")

# 2: seats = 4.5 (fractional): clean reject
st2, j2 = req(FS, "POST", "/reserve", raw_body='{"user_id":"r27frac","seats":4.5,"idempotency_key":"k27-frac"}')
s2 = seats(FS)
check("fuzz seats=4.5: clean reject, no 500", st2 in (400,422) and invariant(s2), f"st={st2} j={json.dumps(j2)[:60]}")

# 3: user_id as JSON array: clean reject, no 500
st3, j3 = req(FS, "POST", "/reserve", raw_body='{"user_id":["r27arr"],"seats":1,"idempotency_key":"k27-arr"}')
s3 = seats(FS)
check("fuzz user_id as JSON array: clean reject, no 500", st3 in (200,400,422) and st3 != 500 and invariant(s3),
      f"st={st3} j={json.dumps(j3)[:60]}")

# 4: idempotency_key as JSON number: clean reject, no 500
st4, j4 = req(FS, "POST", "/reserve", raw_body='{"user_id":"r27num","seats":1,"idempotency_key":42}')
s4 = seats(FS)
check("fuzz idempotency_key as number: clean reject, no 500", st4 in (200,400,422) and st4 != 500 and invariant(s4),
      f"st={st4} j={json.dumps(j4)[:60]}")

# 5: valid JSON with Content-Type text/plain: parsed or clean reject, no 500, no hold leak
s5a = seats(FS)
st5, j5 = req(FS, "POST", "/reserve", {"user_id":"r27ct","seats":1,"idempotency_key":"k27-ct"}, headers_extra={"Content-Type":"text/plain"})
s5b = seats(FS)
leaked = s5b.get("held",0) - s5a.get("held",0)
check("fuzz text/plain content-type with valid JSON: no 500, hold accounting consistent",
      st5 in (200,400,415) and (st5==200 or leaked==0) and invariant(s5b), f"st={st5} leaked={leaked}")

# 6: duplicate seats JSON keys: deterministic single-value handling, no 500, no double hold
st6, j6 = req(FS, "POST", "/reserve", raw_body='{"user_id":"r27dup","seats":1,"seats":1,"idempotency_key":"k27-dup"}')
s6 = seats(FS)
check("fuzz duplicate seats JSON keys: deterministic, no 500", st6 in (200,400,422) and st6 != 500 and invariant(s6),
      f"st={st6} j={json.dumps(j6)[:60]}")

# 7: leading-zero timestamp ("007..."): no 500, valid-verify or reject both fine
st7, j7 = req(ER, "POST", "/reserve", {"user_id":"r27lz","seats":1,"idempotency_key":"k27-lz"}, ts="00"+str(int(time.time())))
s7 = seats(ER)
check("auth leading-zero timestamp: no 500, no bypass", st7 in (200,400,401,403) and st7 != 500 and invariant(s7),
      f"st={st7} j={json.dumps(j7)[:60]}")

# 8: lowercase bearer scheme with a WRONG key: must not pass
st8, j8 = req(ER, "POST", "/reserve", {"user_id":"r27lc","seats":1,"idempotency_key":"k27-lc"}, auth="bearer wrongkey")
s8 = seats(ER)
check("auth lowercase scheme + wrong key: rejected, no bypass", st8 in (401,403) and invariant(s8),
      f"st={st8} j={json.dumps(j8)[:60]}")

# 9: path traversal in /reservation?id=../../secret: 404, no crash, no leak
st9, j9 = req(ER, "GET", "/reservation?id=../../secrets", key=KEY)
check("fuzz path traversal in /reservation id: clean 404, no crash", st9 in (400,404), f"st={st9} j={json.dumps(j9)[:60]}")

# 10: 10KB junk query string on /seats: still 200, no crash
junk = "?" + "&".join("junk%d=x" % i for i in range(300))
st10, j10 = req(ER, "GET", "/seats"+junk, key=KEY)
check("fuzz 10KB junk query on /seats: still serves, no crash", st10==200 and invariant(j10), f"st={st10}")

# 11: seat reuse after release: released seat is bookable again, invariant holds
st11, j11 = reserve(ER, "r27reuse", "k27-reuse")
rid11 = j11.get("reservation_id")
st11r, j11r = req(ER, "POST", "/release", {"reservation_id": rid11})
st11b, j11b = reserve(ER, "r27reuse2", "k27-reuse2")
s11 = seats(ER)
check("state seat reuse after release: seat bookable again exactly once, invariant holds",
      st11==200 and st11r==200 and st11b==200 and invariant(s11), f"rel={st11r} re-reserve={st11b} seats={json.dumps(s11)}")

# 12: app pay by a different user on user A's hold: at most one sale, invariant holds
sh12, j12 = req(APP, "POST", "/api/hold", {"user_id": "r27userA", "seats": 1})
rid12 = j12.get("reservation_id")
sold12a = seats(ER).get("sold",0)
st12, j12b = req(APP, "POST", "/api/pay", {"reservation_id": rid12, "card": "4111111111111111", "user_id": "r27userB"})
sold12b = seats(ER).get("sold",0)
s12 = seats(ER)
check("app pay by different user on A's hold: at most one sale, no crash",
      rid12 and st12 in (200,400,403,404,409) and (sold12b - sold12a) <= 1 and invariant(s12),
      f"rid={rid12} pay_st={st12} sold={sold12a}->{sold12b}")

# 13: waitlist cancel for a never-existing waitlist_id: clean 404/400, no 500
st13, j13 = req(ER, "POST", "/waitlist/cancel", {"waitlist_id": "k27-fake-never", "event_id": "x"})
check("abuse waitlist cancel for nonexistent id: clean reject, no 500", st13 in (400,404,409) and st13 != 500,
      f"st={st13} j={json.dumps(j13)[:60]}")

# 14: HMAC with wrong-case secret ("testSecret"): 401
st14, j14 = req(ER, "POST", "/reserve", {"user_id":"r27case","seats":1,"idempotency_key":"k27-case"}, secret="testSecret")
s14 = seats(ER)
check("auth wrong-case HMAC secret: rejected, no bypass", st14 in (401,403) and invariant(s14), f"st={st14} j={json.dumps(j14)[:60]}")

json.dump([{"name": n, "pass": ok, "detail": d} for ok, n, d in R], open("/tmp/battery/run27_extra.json","w"), indent=1)
fails = sum(1 for ok,_,_ in R if not ok)
print(f"RUN27 EXTRA: TOTAL {len(R)} PASS {len(R)-fails} FAIL {fails}")
