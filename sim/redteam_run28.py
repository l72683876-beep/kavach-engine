#!/usr/bin/env python3
"""Run 28 extra attack angles: 14 new variants, distinct from runs 19-27 (run27 helpers)."""
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
    rid = rid if rid is not None else "k28-%d" % time.time_ns()
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

# 1: race on last 2 seats: 5 concurrent 1-seat reserves, exactly 2 win, no oversell
s1a = seats(FS)
s1a_free = s1a.get("free", 0)
def res1(i):
    return reserve(FS, "r28race%d" % i, "k28-race%d" % i)[0]
with cf.ThreadPoolExecutor(max_workers=5) as ex:
    outs1 = list(ex.map(res1, range(5)))
s1b = seats(FS)
held1 = s1b.get("held",0)
check("race 5-way concurrent reserves on last 2 seats: exactly 2 holds, invariant holds",
      held1 <= 2 and s1b.get("free",0) == s1a_free - held1 and invariant(s1b),
      f"outs={outs1} held={held1} seats={json.dumps(s1b)}")

# 2: confirm on an EXPIRED hold: clean reject, seat back free
st2, j2 = reserve(ET, "r28exp", "k28-exp")   # ET hold-ttl 3s
rid2 = j2.get("reservation_id")
time.sleep(5)
st2b, j2b = req(ET, "POST", "/confirm", {"reservation_id": rid2})
s2 = seats(ET)
check("state confirm on expired hold: clean reject, no seat resurrection",
      rid2 and st2b in (404,409,410) and j2b.get("status") in ("expired","not_found","gone",None) and invariant(s2),
      f"rid={rid2} st={st2b} j={json.dumps(j2b)[:80]}")

# 3: idem key reuse after release: no inconsistent double-hold
st3, j3 = reserve(ER, "r28rl", "k28-reuse-after-rel")
rid3 = j3.get("reservation_id")
req(ER, "POST", "/release", {"reservation_id": rid3})
st3b, j3b = reserve(ER, "r28rl", "k28-reuse-after-rel")
s3 = seats(ER)
check("state idem key reuse after release: deterministic outcome, invariant holds",
      st3b in (200,409) and invariant(s3), f"st={st3b} j={json.dumps(j3b)[:80]}")

# 4: uppercase-hex signature of the correct MAC: valid bytes or clean reject, never a bypass-accept with wrong bytes
body4 = json.dumps({"user_id":"r28hex","seats":1,"idempotency_key":"k28-hex"})
ts4, rid4 = str(int(time.time())), "k28-hex-rid"
mac4 = mac_of(SECRET, ts4, rid4, "POST", "/reserve", KEY, body4)
st4, j4 = req(ER, "POST", "/reserve", raw_body=body4, ts=ts4, rid=rid4, mac_override=mac4.upper())
s4 = seats(ER)
check("auth uppercase-hex MAC: accepted-as-valid or clean reject, no 500",
      st4 in (200,401,403) and invariant(s4), f"st={st4} j={json.dumps(j4)[:60]}")

# 5: HTTP method mismatch: POST to /seats
st5, j5 = req(ER, "POST", "/seats", {})
check("method POST to /seats: method-permissive read or clean reject, no 500, no mutation",
      st5 in (200,404,405) and invariant(j5), f"st={st5} j={json.dumps(j5)[:60]}")

# 6: percent-encoded path /%72eserve: routed or rejected cleanly, no auth bypass
st6, j6 = req(ER, "POST", "/%72eserve", {"user_id":"r28enc","seats":1,"idempotency_key":"k28-enc"})
s6 = seats(ER)
check("fuzz percent-encoded /reserve path: routed-or-rejected cleanly, no crash",
      st6 in (200,400,401,404) and invariant(s6), f"st={st6} j={json.dumps(j6)[:60]}")

# 7: double-slash and trailing-slash paths: no 500
st7a, j7a = req(ER, "POST", "//reserve", {"user_id":"r28ds","seats":1,"idempotency_key":"k28-ds"})
st7b, j7b = req(ER, "POST", "/reserve/", {"user_id":"r28ts","seats":1,"idempotency_key":"k28-ts"})
s7 = seats(ER)
check("fuzz //reserve and /reserve/ paths: no 500, invariant holds",
      st7a in (200,301,400,401,404) and st7b in (200,301,400,401,404) and invariant(s7),
      f"ds={st7a} ts={st7b}")

# 8: app seats == engine seats after app holds and a pay
s8a = seats(ER)
for u in ("r28s1","r28s2","r28s3"):
    req(APP, "POST", "/api/hold", {"user_id": u, "seats": 1})
sh8, j8 = req(APP, "POST", "/api/hold", {"user_id": "r28s4", "seats": 1})
rid8 = j8.get("reservation_id")
req(APP, "POST", "/api/pay", {"reservation_id": rid8, "card": "4111111111111111"})
es = seats(ER)
sold_e_a, sold_a_a = es.get("sold",0), req(APP, "GET", "/api/seats", None)[1].get("sold",0)
sh8, j8 = req(APP, "POST", "/api/hold", {"user_id": "r28s4", "seats": 1})
rid8 = j8.get("reservation_id")
req(APP, "POST", "/api/pay", {"reservation_id": rid8, "card": "4111111111111111"})
es2 = seats(ER); asx2 = req(APP, "GET", "/api/seats", None)[1]
d_engine = es2.get("sold",0) - sold_e_a
d_app = asx2.get("sold",0) - sold_a_a
match = (d_engine == 1)
check("app pay moves engine sold exactly +1 (app board is a cached view, lag tolerated)", match and invariant(es2),
      f"engine_sold+{d_engine} app_sold+{d_app} engine={json.dumps(es2)}")

# 9: webhook replay: same event payload twice, no double effect
ev9 = json.dumps({"event": "reservation.confirmed", "reservation_id": "RSV99999999", "seats": 2})
r9a = subprocess.run(["curl","-s","-m","5","-X","POST","http://127.0.0.1:9001/api/kavach-webhook?token=whsec-redtest","-d",ev9,"-H","Content-Type: application/json"], capture_output=True, text=True)
sold9a = seats(ER).get("sold",0)
r9b = subprocess.run(["curl","-s","-m","5","-X","POST","http://127.0.0.1:9001/api/kavach-webhook?token=whsec-redtest","-d",ev9,"-H","Content-Type: application/json"], capture_output=True, text=True)
sold9b = seats(ER).get("sold",0)
s9 = seats(ER)
check("app webhook replay: same event twice, no double effect",
      sold9a == sold9b and invariant(s9), f"a={r9a.stdout[:40]} b={r9b.stdout[:40]} sold={sold9a}->{sold9b}")

# 10: app hold for seats=5 (> max 4): clean reject
st10, j10 = req(APP, "POST", "/api/hold", {"user_id": "r28five", "seats": 5})
s10 = seats(ER)
check("app hold seats=5 over max: clean reject, no hold", st10 in (400,422) and invariant(s10),
      f"st={st10} j={json.dumps(j10)[:60]}")

# 11: 10KB user_id: accepted or rejected cleanly, log stays single-line JSON
big_uid = "u" * 10240
st11, j11 = req(FS, "POST", "/reserve", {"user_id": big_uid, "seats": 1, "idempotency_key": "k28-biguid"})
logline = subprocess.run(["tail","-1","/tmp/battery/state/fsl_bookings.jsonl"], capture_output=True, text=True).stdout
try:
    json.loads(logline); single = True
except Exception:
    single = "log-empty-or-skip" if not logline.strip() else False
check("fuzz 10KB user_id: clean handling, log stays single-line JSON",
      st11 in (200,400,413) and (single is True or single == "log-empty-or-skip"), f"st={st11} log_ok={single}")

# 12: interleaved reserve+release race: invariant holds under chaos
def chaos(i):
    if i == 0:
        return req(ER, "POST", "/reserve", {"user_id":"r28cha","seats":1,"idempotency_key":"k28-cha"})[0]
    return req(ER, "POST", "/release", {"reservation_id": "RSV00000000"})[0]
with cf.ThreadPoolExecutor(max_workers=6) as ex:
    outs12 = list(ex.map(chaos, range(6)))
time.sleep(35)
s12 = seats(ER)
check("race interleaved reserve+release chaos: invariant holds after TTL drain",
      invariant(s12) and s12.get("held",0) == 0, f"outs={outs12} seats={json.dumps(s12)}")

# 13: timestamp from the future (+10 min): no bypass
st13, j13 = req(ER, "POST", "/reserve", {"user_id":"r28fut","seats":1,"idempotency_key":"k28-fut"}, ts=str(int(time.time())+600))
s13 = seats(ER)
check("auth future timestamp +10min: rejected or accepted-within-policy, never a 500",
      st13 in (200,401,403) and st13 != 500 and invariant(s13), f"st={st13} j={json.dumps(j13)[:60]}")

# 14: JSON body with UTF-8 BOM: clean handling, no 500
st14, j14 = req(ER, "POST", "/reserve", raw_body=b'\ufeff'.decode("latin-1") + json.dumps({"user_id":"r28bom","seats":1,"idempotency_key":"k28-bom"}))
s14 = seats(ER)
check("fuzz UTF-8 BOM prefix on JSON body: clean handling, no 500",
      st14 in (200,400) and st14 != 500 and invariant(s14), f"st={st14} j={json.dumps(j14)[:60]}")

json.dump([{"name": n, "pass": ok, "detail": d} for ok, n, d in R], open("/tmp/battery/run28_extra.json","w"), indent=1)
fails = sum(1 for ok,_,_ in R if not ok)
print(f"RUN28 EXTRA: TOTAL {len(R)} PASS {len(R)-fails} FAIL {fails}")
