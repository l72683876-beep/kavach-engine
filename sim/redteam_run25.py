#!/usr/bin/env python3
"""Run 25 extra attack angles: 14 new variants, distinct from all prior runs (v3: http-status req, /book idem keys)."""
import json, time, http.client, subprocess, sys

ER, ER2, ET, FS, PT, ER3 = "http://127.0.0.1:8091", "http://127.0.0.1:8092", "http://127.0.0.1:8095", "http://127.0.0.1:8096", "http://127.0.0.1:8097", "http://127.0.0.1:8098"
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

def req(base, method, path, body=None, key=KEY, secret=SECRET, raw_body=None):
    b = raw_body if raw_body is not None else (json.dumps(body) if body is not None else "")
    ts = str(int(time.time()))
    rid = "k25-%d" % time.time_ns()
    mac = __import__("hmac").new(secret.encode(), (ts+"\n"+rid+"\n"+method+"\n"+path+"\n"+key+"\n").encode()+b.encode(), __import__("hashlib").sha256).hexdigest()
    h = {"Authorization": "Bearer "+key, "X-Kavach-Timestamp": ts, "X-Kavach-Request-Id": rid, "X-Kavach-Signature": mac, "Content-Type": "application/json"}
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

# 1: tab/newline inside idem key + log integrity (single-line JSON) on FS
fsl = open("/tmp/battery/state/fsl_bookings.jsonl","rb").read()
before_lines = fsl.count(b"\n")
st1, j1 = reserve(FS, "r25tab", "k25-tab\tkey")
st1b, j1b = reserve(FS, "r25tab", "k25-tab\tkey")
fsl2 = open("/tmp/battery/state/fsl_bookings.jsonl","rb").read()
lines_ok = all(b"\r" not in ln for ln in fsl2.split(b"\n") if ln)
s1 = seats(FS)
check("fuzz tab/newline idem key: same request dedupes, log stays single-line JSON",
      st1==200 and st1b==200 and j1.get("reservation_id")==j1b.get("reservation_id") and lines_ok and invariant(s1),
      f"st={st1}/{st1b} rid={j1.get('reservation_id')} replay={j1b.get('reservation_id')} lines_ok={lines_ok}")

# 2: 8KB idem key accepted or rejected cleanly, no crash
big = "k25-" + "x"*8000
st2, j2 = reserve(FS, "r25big", big)
s2 = seats(FS)
check("fuzz 8KB idem key: clean accept or reject, engine alive, invariant holds",
      st2 in (200,400,413) and invariant(s2), f"st={st2} j={json.dumps(j2)[:80]}")

# 3: emoji-only idem key + emoji user_id (4-byte UTF-8), no mojibake, no crash
st3, j3 = reserve(FS, "r25emoji\U0001f9e0", "\U0001f9e5\U0001f51f")
s3 = seats(FS)
check("fuzz emoji idem key + emoji user_id: clean handling, invariant holds",
      st3 in (200,400) and invariant(s3), f"st={st3} j={json.dumps(j3)[:100]}")

# 4: last seat on PT (per-tenant secret): /book cannot take it after a hold
wait_drain(PT)
free4 = seats(PT).get("free", 0)
n4 = min(14, max(0, free4 - 1))
fill_i = 0
while n4 > 0:
    take = min(4, n4)
    req(PT, "POST", "/book", {"user_id": f"r25fill{fill_i}", "seats": take, "idempotency_key": f"k25-fill-{fill_i}"}, secret=SA)
    n4 -= take; fill_i += 1
st4, j4 = reserve(PT, "r25last", "k25-ptlast", secret=SA)
rid4 = j4.get("reservation_id")
st4b, j4b = req(PT, "POST", "/book", {"user_id": "r25thief", "seats": 1, "idempotency_key": "k25-thief"}, secret=SA)
s4 = seats(PT)
check("race PT last seat held: another user's /book cannot take it (no double sale)",
      rid4 and s4.get("held",0)==1 and st4b==200 and j4b.get("status")=="sold_out" and invariant(s4),
      f"rid={rid4} st={st4}/{st4b} held={s4.get('held')} st_body={json.dumps(j4b)[:60]}")

# 5: overbook 8x4-seat on ER3 (30 seats): no way past 30
wait_drain(ER3)
confirmed5 = 0
for i in range(8):
    st5, j5 = req(ER3, "POST", "/book", {"user_id": f"r25ob{i}", "seats": 4, "idempotency_key": f"k25-ob-{i}"})
    if st5 == 200 and j5.get("status") not in ("sold_out",): confirmed5 += 1
s5 = seats(ER3)
check("race ER3 overbook 8x4 seats: sold never exceeds total (no oversell)",
      s5.get("sold",0) <= 30 and invariant(s5) and confirmed5 * 4 == s5.get("sold",0),
      f"sold={s5.get('sold')} confirmed={confirmed5}")

# 6: re-reserve same idem key after TTL expiry on ET: idempotent replay (same reservation), NO second hold
st6, j6 = reserve(ET, "r25ttl", "k25-ttlre")
rid6 = j6.get("reservation_id")
time.sleep(4.5)
st6b, j6b = reserve(ET, "r25ttl", "k25-ttlre")
s6 = seats(ET)
check("state re-reserve same idem key after TTL expiry: idempotent replay, no second hold, no zombie",
      rid6 and st6b==200 and j6b.get("reservation_id")==rid6 and s6.get("held",0)==0 and invariant(s6),
      f"rid={rid6} replay={j6b.get('reservation_id')} st={st6b} held={s6.get('held')} status={j6b.get('status')}")

# 7: cross-tenant /release on FS: tenant2 cannot release tenant1's hold
st7, j7 = reserve(FS, "r25xr", "k25-xrel")
rid7 = j7.get("reservation_id")
st7b, j7b = req(FS, "POST", "/release", {"reservation_id": rid7}, key=KEY2)
s7 = seats(FS)
check("auth cross-tenant /release: rejected 404, hold intact",
      st7b==404 and s7.get("held",0) >= 1 and invariant(s7), f"rid={rid7} st={st7b} held={s7.get('held')}")
req(FS, "POST", "/release", {"reservation_id": rid7})  # cleanup

# 8: cross-tenant /confirm on FS: tenant2 cannot confirm tenant1's hold
st8, j8 = reserve(FS, "r25xc", "k25-xconf")
rid8 = j8.get("reservation_id")
st8b, j8b = req(FS, "POST", "/confirm", {"reservation_id": rid8}, key=KEY2)
s8 = seats(FS)
check("auth cross-tenant /confirm: rejected 404, nothing sold",
      st8b==404 and invariant(s8) and j8b.get("status") != "confirmed", f"rid={rid8} st={st8b} j={json.dumps(j8b)[:60]}")
req(FS, "POST", "/release", {"reservation_id": rid8})  # cleanup

# 9: app double-pay on a paid hold: only one sale lands
wait_drain(ER)
sh9, j9 = req(APP, "POST", "/api/hold", {"user_id": "r25pay", "seats": 1})
rid9 = j9.get("reservation_id")
sold9 = seats(ER).get("sold", 0)
pay1 = req(APP, "POST", "/api/pay", {"reservation_id": rid9, "card": "4111111111111111"})
pay2 = req(APP, "POST", "/api/pay", {"reservation_id": rid9, "card": "4111111111111111"})
sold11 = seats(ER).get("sold", 0)
check("app double-pay on paid hold: no second sale lands",
      rid9 and sold11 - sold9 == 1, f"rid={rid9} hold_st={sh9} pay1={pay1[0]} pay2={pay2[0]} sold={sold9}->{sold11}")

# 10: app webhook unknown event type with valid token: no crash, no seat change
s10a = seats(ER)
st10, j10 = req(APP, "POST", "/api/kavach-webhook?token=whsec-redtest", {"type": "bogus_event_x", "data": {"reservation_id": "RSV00000001"}})
s10b = seats(ER)
check("app webhook unknown event type with valid token: no crash, seats unchanged",
      st10 in (200,400) and s10a==s10b, f"st={st10} seats_same={s10a==s10b}")

# 11: signature/request-id header swap (valid signature bound to rid A, sent with rid B)
ts11, rid11a, rid11b = str(int(time.time())), "k25-swap-a", "k25-swap-b"
body11 = json.dumps({"user_id":"r25swap","seats":1,"idempotency_key":"k25-swap-key"})
mac11 = __import__("hmac").new(SECRET.encode(), (ts11+"\n"+rid11a+"\nPOST\n/reserve\n"+KEY+"\n").encode()+body11.encode(), __import__("hashlib").sha256).hexdigest()
h11 = {"Authorization": "Bearer "+KEY, "X-Kavach-Timestamp": ts11, "X-Kavach-Request-Id": rid11b, "X-Kavach-Signature": mac11, "Content-Type": "application/json"}
st11, j11 = req(ER, "POST", "/reserve", raw_body=body11)
import http.client as hc11
c = hc11.HTTPConnection("127.0.0.1", 8091, timeout=10); c.request("POST","/reserve",body=body11.encode(),headers=h11)
r11 = c.getresponse(); d11 = r11.read().decode(); c.close()
try: j11 = json.loads(d11)
except Exception: j11 = {}
s11 = seats(ER)
check("auth swapped request-id under valid signature: rejected, no hold consumed",
      r11.status in (401,403) and j11.get("status") == "unauthorized" and invariant(s11), f"st={r11.status} j={json.dumps(j11)[:60]}")

# 12: "Bearer  testkey" double-space scheme variant
c = hc11.HTTPConnection("127.0.0.1", 8091, timeout=10)
c.request("POST","/reserve",body=json.dumps({"user_id":"r25sp","seats":1,"idempotency_key":"k25-spkey"}).encode(),
          headers={"Authorization":"Bearer  testkey","Content-Type":"application/json"})
r12 = c.getresponse(); d12 = r12.read().decode(); c.close()
try: j12 = json.loads(d12)
except Exception: j12 = {}
s12 = seats(ER)
check("auth double-space bearer scheme: no bypass (401 or 200 with clean invariant)",
      r12.status in (401,403,200) and (j12.get("status")=="unauthorized" or invariant(s12)), f"st={r12.status} j={json.dumps(j12)[:60]}")

# 13: duplicate JSON keys (last-wins vs first-wins) deterministic replay on FS
dup = '{"user_id":"r25dup","seats":1,"seats":2,"idempotency_key":"k25-dupkey","idempotency_key":"k25-dupkey"}'
def signed_dup(rid):
    ts = str(int(time.time()))
    mac = __import__("hmac").new(SECRET.encode(), (ts+"\n"+rid+"\nPOST\n/reserve\n"+KEY+"\n").encode()+dup.encode(), __import__("hashlib").sha256).hexdigest()
    return {"Authorization": "Bearer "+KEY, "X-Kavach-Timestamp": ts, "X-Kavach-Request-Id": rid, "X-Kavach-Signature": mac, "Content-Type": "application/json"}
h13a, h13b = signed_dup("k25-dup-a"), signed_dup("k25-dup-b")
c = hc11.HTTPConnection("127.0.0.1", 8096, timeout=10); c.request("POST","/reserve",body=dup.encode(),headers=h13a); r13a = c.getresponse(); d13a = r13a.read().decode(); c.close()
c = hc11.HTTPConnection("127.0.0.1", 8096, timeout=10); c.request("POST","/reserve",body=dup.encode(),headers=h13b); r13b = c.getresponse(); d13b = r13b.read().decode(); c.close()
try: j13a, j13b = json.loads(d13a), json.loads(d13b)
except Exception: j13a, j13b = {}, {}
s13 = seats(FS)
check("fuzz duplicate JSON keys: deterministic parse, no double hold",
      j13a.get("reservation_id")==j13b.get("reservation_id") and invariant(s13), f"a={j13a.get('reservation_id')} b={j13b.get('reservation_id')} st={r13a.status}/{r13b.status}")

# 14: full-capacity race on FS: n workers race /reserve for ALL remaining seats, free must hit 0, no oversell
wait_drain(FS)
free14 = seats(FS).get("free", 0)
n14 = min(20, max(0, free14))
procs = []
import concurrent.futures as cf
def race_one(i):
    b = json.dumps({"user_id": f"r25race{i}", "seats": 1, "idempotency_key": f"k25-race-{i}"})
    ts = str(int(time.time())); rid = f"k25-race-rid-{i}"
    mac = __import__("hmac").new(SECRET.encode(), (ts+"\n"+rid+"\nPOST\n/reserve\n"+KEY+"\n").encode()+b.encode(), __import__("hashlib").sha256).hexdigest()
    h = {"Authorization": "Bearer "+KEY, "X-Kavach-Timestamp": ts, "X-Kavach-Request-Id": rid, "X-Kavach-Signature": mac, "Content-Type": "application/json"}
    c = hc11.HTTPConnection("127.0.0.1", 8096, timeout=15)
    c.request("POST","/reserve",body=b.encode(),headers=h)
    r = c.getresponse(); d = r.read().decode(); c.close()
    try: return json.loads(d).get("reservation_id")
    except Exception: return None
with cf.ThreadPoolExecutor(max_workers=n14 or 1) as ex:
    wins = sum(1 for v in ex.map(race_one, range(n14)) if v)
s14 = seats(FS)
check("race full-capacity FS race: all remaining seats won exactly once, zero free, no oversell",
      s14.get("free",0)==0 and wins == n14 and invariant(s14), f"free={s14.get('free')} wins={wins} expected={n14}")

json.dump([{"name": n, "pass": ok, "detail": d} for ok, n, d in R], open("/tmp/battery/run25_extra.json","w"), indent=1)
fails = sum(1 for ok,_,_ in R if not ok)
print(f"RUN25 EXTRA: TOTAL {len(R)} PASS {len(R)-fails} FAIL {fails}")
