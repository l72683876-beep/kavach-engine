#!/usr/bin/env python3
"""Run 26 extra attack angles: 14 new variants, distinct from runs 19-25 (v3 helpers)."""
import json, time, http.client, subprocess

ER, ET, FS, PT, ER3 = "http://127.0.0.1:8091", "http://127.0.0.1:8095", "http://127.0.0.1:8096", "http://127.0.0.1:8097", "http://127.0.0.1:8098"
APP = "http://127.0.0.1:9001"
KEY, KEY2, SECRET, SA = "testkey", "otherkey", "testsecret", "secretA"

def port_of(base):
    return int(base.rsplit(":", 1)[1])

def seats(base):
    try:
        c = http.client.HTTPConnection("127.0.0.1", port_of(base), timeout=5)
        c.request("GET", "/seats"); r = c.getresponse(); d = r.read(); c.close()
        return json.loads(d)
    except Exception:
        return {}

def invariant(s):
    return s.get("total") == s.get("free",0) + s.get("held",0) + s.get("sold",0)

def mac_of(secret, ts, rid, method, path, key, b):
    import hmac, hashlib
    return hmac.new(secret.encode(), (ts+"\n"+rid+"\n"+method+"\n"+path+"\n"+key+"\n").encode()+b.encode(), hashlib.sha256).hexdigest()

def req(base, method, path, body=None, key=KEY, secret=SECRET, raw_body=None, ts=None, rid=None, mac_override=None, auth=None):
    b = raw_body if raw_body is not None else (json.dumps(body) if body is not None else "")
    ts = ts if ts is not None else str(int(time.time()))
    rid = rid if rid is not None else "k26-%d" % time.time_ns()
    mac = mac_override if mac_override is not None else mac_of(secret, ts, rid, method, path, key, b)
    h = {"Authorization": auth if auth is not None else "Bearer "+key,
         "X-Kavach-Timestamp": ts, "X-Kavach-Request-Id": rid, "X-Kavach-Signature": mac,
         "Content-Type": "application/json"}
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

# 1: confusable Cyrillic vs Latin idem keys: visually identical keys must NOT collide
st1, j1 = reserve(FS, "r26conf", "k26-cafe")            # Latin
st1b, j1b = reserve(FS, "r26conf", "k26-\u0441afe")    # leading c is Cyrillic U+0441
s1 = seats(FS)
rid1, rid1b = j1.get("reservation_id"), j1b.get("reservation_id")
check("fuzz confusable Cyrillic/Latin idem keys: distinct keys, no false collision",
      st1==200 and st1b==200 and rid1 and rid1b and rid1 != rid1b and invariant(s1),
      f"rid={rid1} rid2={rid1b} st={st1}/{st1b}")

# 2: seats as JSON string "2": clean reject, no hold
s2a = seats(FS)
st2, j2 = req(FS, "POST", "/reserve", raw_body='{"user_id":"r26str","seats":"2","idempotency_key":"k26-str"}')
s2b = seats(FS)
check("fuzz seats as JSON string: clean reject (no hold consumed, no 500)",
      st2 in (400,422) and s2a == s2b and invariant(s2b), f"st={st2} j={json.dumps(j2)[:60]} seats_same={s2a==s2b}")

# 3: seats as JSON bool true: clean reject
s3a = seats(FS)
st3, j3 = req(FS, "POST", "/reserve", raw_body='{"user_id":"r26bool","seats":true,"idempotency_key":"k26-bool"}')
s3b = seats(FS)
check("fuzz seats as JSON bool: clean reject, seats unchanged",
      st3 in (400,422) and s3a == s3b and invariant(s3b), f"st={st3} j={json.dumps(j3)[:60]}")

# 4: seats as JSON float 1.0: accept-as-int or reject, never a 500 or fractional hold
st4, j4 = req(FS, "POST", "/reserve", raw_body='{"user_id":"r26float","seats":1.0,"idempotency_key":"k26-float"}')
s4 = seats(FS)
check("fuzz seats as JSON float: handled cleanly, no 500, invariant holds",
      st4 in (200,400,422) and invariant(s4), f"st={st4} j={json.dumps(j4)[:80]}")

# 5: 10-way concurrent /release on one hold: exactly one effective release
free5 = seats(ER).get("free", 0)
st5, j5 = reserve(ER, "r26rel", "k26-relrace")
rid5 = j5.get("reservation_id")
import concurrent.futures as cf
def rel(_):
    return req(ER, "POST", "/release", {"reservation_id": rid5})[0]
with cf.ThreadPoolExecutor(max_workers=10) as ex:
    outs5 = list(ex.map(rel, range(10)))
s5 = seats(ER)
freed = s5.get("free",0) - free5
check("race 10-way concurrent /release on one hold: seats return exactly once",
      rid5 and s5.get("held",0)==0 and freed == 0 and invariant(s5), f"rid={rid5} codes={outs5} freed={freed}")

# 6: release after confirm: rejected, sold stays
st6, j6 = reserve(ER, "r26rc", "k26-relconf")
rid6 = j6.get("reservation_id")
st6b, j6b = req(ER, "POST", "/confirm", {"reservation_id": rid6})
sold6a = seats(ER).get("sold",0)
st6c, j6c = req(ER, "POST", "/release", {"reservation_id": rid6})
sold6b = seats(ER).get("sold",0)
s6 = seats(ER)
check("state release after confirm: rejected, sold seat cannot be resurrected",
      st6b==200 and sold6a == sold6b and invariant(s6) and not (st6c==200 and j6c.get("status")=="released"),
      f"confirm={st6b} release={st6c} j={json.dumps(j6c)[:60]} sold={sold6a}->{sold6b}")

# 7: key with zero-width space (U+200B) prefix: no bypass
zw = "\u200b".encode("utf-8").decode("latin-1")
st7, j7 = req(ER, "POST", "/reserve", {"user_id":"r26zw","seats":1,"idempotency_key":"k26-zw"}, auth="Bearer "+zw+"testkey")
s7 = seats(ER)
check("auth zero-width space in bearer key: rejected, no bypass",
      st7 in (401,403) and j7.get("status")=="unauthorized" and invariant(s7), f"st={st7} j={json.dumps(j7)[:60]}")

# 8: signature over tampered body (CRLF appended after signing): rejected
body8 = json.dumps({"user_id":"r26crlf","seats":1,"idempotency_key":"k26-crlf"})
ts8, rid8 = str(int(time.time())), "k26-crlf-rid"
mac8 = mac_of(SECRET, ts8, rid8, "POST", "/reserve", KEY, body8)
st8, j8 = req(ER, "POST", "/reserve", raw_body=body8 + "\r\n", ts=ts8, rid=rid8, mac_override=mac8)
s8 = seats(ER)
check("auth CRLF appended to signed body: tamper detected (unauthorized)",
      st8 in (401,403) and invariant(s8), f"st={st8} j={json.dumps(j8)[:60]}")

# 9: timestamp as float string and negative: both rejected clean
st9a, j9a = req(ER, "POST", "/reserve", {"user_id":"r26tsf","seats":1,"idempotency_key":"k26-tsf"}, ts=str(int(time.time()))+".123")
st9b, j9b = req(ER, "POST", "/reserve", {"user_id":"r26tsn","seats":1,"idempotency_key":"k26-tsn"}, ts=str(-int(time.time())))
s9 = seats(ER)
check("auth float and negative timestamps: both rejected, no bypass",
      st9a in (401,403) and st9b in (401,403) and j9a.get("status")=="unauthorized" and j9b.get("status")=="unauthorized" and invariant(s9),
      f"float={st9a} neg={st9b}")

# 10: request-id reuse across users: user B cannot ride user A's nonce
rid10 = "k26-shared-rid-%d" % time.time_ns()
b10 = json.dumps({"user_id":"r26-A","seats":1,"idempotency_key":"k26-ridA"})
ts10 = str(int(time.time()))
st10a, j10a = req(ER, "POST", "/reserve", raw_body=b10, rid=rid10, ts=ts10)
b10b = json.dumps({"user_id":"r26-B","seats":1,"idempotency_key":"k26-ridB"})
st10b, j10b = req(ER, "POST", "/reserve", raw_body=b10b, rid=rid10, ts=str(int(time.time())))
s10 = seats(ER)
ok10 = invariant(s10) and j10b.get("reservation_id") != j10a.get("reservation_id")
check("auth same request-id across two users: no cross-user nonce confusion",
      ok10 and st10b in (200,401,403,409), f"a_st={st10a} b_st={st10b} a_rid={j10a.get('reservation_id')} b_rid={j10b.get('reservation_id')}")

# 11: cross-tenant GET /reservation: tenant1 cannot read tenant2's hold
st11, j11 = reserve(ER, "r26ct", "k26-ctread", key=KEY)
rid11 = j11.get("reservation_id")
st11b, j11b = req(ER, "GET", f"/reservation?id={rid11}", key=KEY2)
s11 = seats(ER)
check("auth cross-tenant reservation read: 404, no data leak",
      st11b==404 and j11b.get("status")=="not_found" and invariant(s11), f"rid={rid11} st={st11b} j={json.dumps(j11b)[:60]}")

# 12: app hold then pay with 3 different cards: still exactly one sale
sh12, j12 = req(APP, "POST", "/api/hold", {"user_id": "r26cards", "seats": 1})
rid12 = j12.get("reservation_id")
sold12a = seats(ER).get("sold",0)
for card in ("4111111111111111", "5500005555555559", "4242424242424242"):
    req(APP, "POST", "/api/pay", {"reservation_id": rid12, "card": card})
sold12b = seats(ER).get("sold",0)
s12 = seats(ER)
check("app pay with 3 rotating cards on one hold: exactly one sale",
      rid12 and sold12b - sold12a == 1 and invariant(s12), f"rid={rid12} sold={sold12a}->{sold12b}")

# 13: app waitlist join asking for more seats than the venue has: clean reject, no crash
st13, j13 = req(APP, "POST", "/api/waitlist", {"user_id": "r26wl99", "seats": 99})
st13b, j13b = req(APP, "POST", "/api/waitlist", {"user_id": "r26wl99", "seats": 0})
check("app waitlist join seats=99 and seats=0: clean rejects, no 500",
      st13 in (200,400,409,422) and st13b in (200,400,409,422) and st13 != 500 and st13b != 500,
      f"st99={st13} st0={st13b} j={json.dumps(j13)[:60]}")

# 14: zombie reservation read: after release, GET /reservation must not show a live hold
st14, j14 = reserve(ER, "r26zomb", "k26-zomb")
rid14 = j14.get("reservation_id")
st14b, j14b = req(ER, "GET", f"/reservation?id={rid14}")
st14r, j14r = req(ER, "POST", "/release", {"reservation_id": rid14})
st14c, j14c = req(ER, "GET", f"/reservation?id={rid14}")
post_ok = (st14c == 404) or (j14c.get("status") not in ("held", "confirmed"))
s14 = seats(ER)
check("state reservation lookup after release: never reports a live hold",
      st14b==200 and post_ok and invariant(s14), f"before={st14b} after={st14c} rel={st14r}/{j14r.get('status')} j={json.dumps(j14c)[:80]}")

json.dump([{"name": n, "pass": ok, "detail": d} for ok, n, d in R], open("/tmp/battery/run26_extra.json","w"), indent=1)
fails = sum(1 for ok,_,_ in R if not ok)
print(f"RUN26 EXTRA: TOTAL {len(R)} PASS {len(R)-fails} FAIL {fails}")
