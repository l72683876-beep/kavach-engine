#!/usr/bin/env python3
"""Run 54 extras: 11 angles.
1: released rid + same-key re-reserve -> 200 replay of current state (released), no new hold
2: MAC computed with EMPTY secret -> 401
3: Authorization "Bearer  testkey" (double space) -> 401, no 5xx
4: app /api/hold seats=1.5 float -> 400
5: app /api/pay without reservation_id -> clean 4xx, app alive
7: kill engine, relaunch same log -> sold replayed (poll for port release first)
6: drained engine: wl join same key seats 1 then 2 -> 409 idempotency_conflict, one entry
9: MAC signed over clean body, body sent with trailing newline -> 401
10: user_id with leading space -> held or clean 400, no 5xx
11: 20 concurrent 1-seat reserves on 10-seat engine -> exactly 10 held, losers 409 (no auto-waitlist)
8: (last, own ip-budget) 30 /seats samples during 50 concurrent holds -> all conserved
"""
import hashlib, hmac, http.client, json, os, subprocess, threading, time, uuid
from concurrent.futures import ThreadPoolExecutor
from collections import Counter

KEY, KEY2, SECRET = "testkey", "otherkey", "testsecret"
EH1, EH2, EH5, EH3 = "http://127.0.0.1:8091", "http://127.0.0.1:8092", "http://127.0.0.1:8098", "http://127.0.0.1:8095"
APP = "http://127.0.0.1:9001"
LOGD = os.environ.get("K54_LOGDIR", "/tmp/battery/stateD54")
PASS = FAIL = 0

def check(name, desc, ok, detail=""):
    global PASS, FAIL
    tag = "PASS" if ok else "FAIL"
    if ok: PASS += 1
    else: FAIL += 1
    print("%s %s %s | %s" % (tag, name, desc, detail))

def mac_for(secret, ts, rid, method, uri, key, body):
    return hmac.new(secret.encode(), (ts+"\n"+rid+"\n"+method+"\n"+uri+"\n"+key+"\n").encode()+body, hashlib.sha256).hexdigest()

def send(host, method, uri, body, headers):
    p = host.split("//")[1].split(":")
    c = http.client.HTTPConnection(p[0], int(p[1]), timeout=10)
    c.request(method, uri, body=body, headers=headers)
    r = c.getresponse(); d = r.read(); st = r.status; c.close()
    try: j = json.loads(d) if d else {}
    except Exception: j = {"_raw": d[:200].decode("utf-8", "replace")}
    return st, j

def signed(host, method, uri, obj=None, key=KEY, secret=SECRET, rid=None, auth=None):
    body = json.dumps(obj).encode() if obj is not None else b""
    ts = str(int(time.time()))
    rid = rid or uuid.uuid4().hex
    mac = mac_for(secret, ts, rid, method, uri, key, body)
    h = {"Authorization": auth or ("Bearer "+key), "X-Kavach-Timestamp": ts, "X-Kavach-Request-Id": rid,
         "X-Kavach-Signature": mac, "Content-Type": "application/json"}
    return send(host, method, uri, body, h)

def seats_of(host):
    return signed(host, "GET", "/seats")[1]

U = lambda t: "r54-%s-%s" % (t, uuid.uuid4().hex[:6])
K = lambda t: "k54-%s-%s" % (t, uuid.uuid4().hex[:6])
cons = lambda s: s["sold"] + s["held"] + s["free"] == s["total"]

# ---- 1. confirm old rid after rekey
u1, k1 = U("rk"), K("rk")
st1, j1 = signed(EH5, "POST", "/reserve", {"user_id": u1, "idempotency_key": k1, "seats": 1})
old_rid = j1.get("reservation_id")
sr1, _ = signed(EH5, "POST", "/release", {"reservation_id": old_rid})
st1b, j1b = signed(EH5, "POST", "/reserve", {"user_id": u1, "idempotency_key": k1, "seats": 1})
st1c, j1c = signed(EH5, "POST", "/confirm", {"reservation_id": old_rid, "user_id": u1})
s1 = seats_of(EH5)
check("confirm_after_rekey", "released rid + same-key re-reserve: 200 replay of that reservation's current state (released), no new hold, no double-booking; confirm of released rid -> 409; conserved",
      st1 == 200 and sr1 == 200 and st1b == 200 and j1b.get("reservation_id") == old_rid and j1b.get("status") == "released" and st1c == 409 and cons(s1),
      "replay=%s/%s old_confirm=%s held=%s" % (j1b.get("reservation_id") == old_rid, j1b.get("status"), st1c, s1["held"]))

# ---- 2. MAC with empty secret
b2 = json.dumps({"user_id": U("es"), "idempotency_key": K("es"), "seats": 1}).encode()
ts2, rid2 = str(int(time.time())), uuid.uuid4().hex
mac2 = mac_for("", ts2, rid2, "POST", "/reserve", KEY, b2)
st2, j2 = send(EH5, "POST", "/reserve", b2, {"Authorization": "Bearer "+KEY, "X-Kavach-Timestamp": ts2,
               "X-Kavach-Request-Id": rid2, "X-Kavach-Signature": mac2, "Content-Type": "application/json"})
check("mac_empty_secret", "MAC computed with empty secret: 401 fail-closed", st2 == 401, "st=%s %s" % (st2, j2.get("status")))

# ---- 3. double-space bearer
st3, j3 = signed(EH5, "POST", "/reserve", {"user_id": U("bs"), "idempotency_key": K("bs"), "seats": 1}, auth="Bearer  "+KEY)
check("bearer_double_space", "'Bearer  key' double space: 401 (strict), no 5xx", st3 == 401, "st=%s %s" % (st3, j3.get("status")))

# ---- 4. app hold float seats
st4, j4 = send(APP, "POST", "/api/hold", json.dumps({"user_id": U("fl"), "seats": 1.5}).encode(), {"Content-Type": "application/json"})
check("app_hold_float", "app hold seats=1.5: clean 400", st4 == 400, "st=%s %s" % (st4, j4))

# ---- 5. app pay without reservation_id
st5, j5 = send(APP, "POST", "/api/pay", json.dumps({"user_id": U("pr"), "outcome": "success"}).encode(), {"Content-Type": "application/json"})
alive5 = send(APP, "GET", "/api/seats", None, {})[0] == 200
check("app_pay_missing_rid", "app pay without reservation_id: clean 4xx, app alive", st5 in (400, 404, 422) and alive5,
      "st=%s alive=%s" % (st5, alive5))

# ---- 7. engine restart state replay (8092): sell 5, kill, relaunch same log
for i in range(5):
    signed(EH2, "POST", "/book", {"user_id": U("rr"), "idempotency_key": K("rr%d" % i), "seats": 1})
pre7 = seats_of(EH2)
subprocess.run("pkill -f 'addr 127.0.0.1:8092'", shell=True)
relaunched = False
for _ in range(30):  # SIGTERM graceful shutdown can take seconds; poll for port release
    time.sleep(0.5)
    try:
        st_p, j_p = seats_of(EH2)
        continue  # still answering -> old engine alive
    except Exception:
        pass
    subprocess.Popen("nohup ./engine/kavach -seats 61 -workers 4 -api-keys testkey:tenant1,otherkey:tenant2 -hmac-secret testsecret -hold-ttl 30 -ip-rate 0 -user-rate 0 -log %s/bt2_bookings.jsonl -holds-log %s/bt2_holds.jsonl -addr 127.0.0.1:8092 >>/tmp/battery/8092.log 2>&1 &" % (LOGD, LOGD), shell=True, cwd="/workspace/kv")
    time.sleep(2.5)
    relaunched = True
    break
post7 = seats_of(EH2)
check("restart_replay_state", "engine killed (SIGTERM) and relaunched on same log: 5 sold replayed from bookings log",
      relaunched and pre7["sold"] == 5 and post7["sold"] == 5 and post7["free"] == 56 and cons(post7),
      "relaunched=%s pre_sold=%s post_sold=%s post_free=%s" % (relaunched, pre7["sold"], post7["sold"], post7["free"]))

# ---- 6. wl same key different seats (8092, drained to capacity first)
s6pre = seats_of(EH2)
need6 = s6pre["free"]
for i in range(need6):
    signed(EH2, "POST", "/reserve", {"user_id": U("dr"), "idempotency_key": K("dr%d" % i), "seats": 1})
s6d = seats_of(EH2)
u6, k6 = U("wk"), K("wk")
st6a, j6a = signed(EH2, "POST", "/waitlist", {"user_id": u6, "idempotency_key": k6, "seats": 1})
st6b, j6b = signed(EH2, "POST", "/waitlist", {"user_id": u6, "idempotency_key": k6, "seats": 2})
wl6 = signed(EH2, "GET", "/waitlist?user_id=" + u6)[1]
# the user-scoped view returns only this user's entries; entry fields: waitlist_id/seats/position
entries6 = wl6.get("entries", []) if isinstance(wl6.get("entries"), list) else []
n6 = len(entries6)
shaped6 = all("waitlist_id" in e and "seats" in e and "position" in e for e in entries6)
check("wl_same_key_diff_seats", "drained engine: wl join same key seats 1 then 2 -> 409 idempotency_conflict, one entry",
      s6d["free"] == 0 and st6a == 200 and j6a.get("status") == "queued" and st6b == 409 and n6 == 1 and shaped6,
      "free=%s a=%s/%s b=%s/%s entries=%s shaped=%s" % (s6d["free"], st6a, j6a.get("status"), st6b, j6b.get("status"), n6, shaped6))

# ---- 9. MAC body tamper: sign clean body, send with trailing newline
b9 = json.dumps({"user_id": U("bt"), "idempotency_key": K("bt"), "seats": 1}).encode()
ts9, rid9 = str(int(time.time())), uuid.uuid4().hex
mac9 = mac_for(SECRET, ts9, rid9, "POST", "/reserve", KEY, b9)
st9, j9 = send(EH5, "POST", "/reserve", b9 + b"\n", {"Authorization": "Bearer "+KEY, "X-Kavach-Timestamp": ts9,
               "X-Kavach-Request-Id": rid9, "X-Kavach-Signature": mac9, "Content-Type": "application/json"})
check("mac_body_tamper_newline", "body signed without newline, sent with trailing newline: 401 fail-closed", st9 == 401,
      "st=%s %s" % (st9, j9.get("status")))

# ---- 10. user_id leading space
st10, j10 = signed(EH5, "POST", "/reserve", {"user_id": " %s" % U("ls"), "idempotency_key": K("ls"), "seats": 1})
check("user_id_leading_space", "user_id with leading space: held or clean 400, no 5xx",
      st10 < 500 and ((st10 == 200 and j10.get("status") == "held") or st10 == 400),
      "st=%s %s" % (st10, j10.get("status")))

# ---- 11. reserve race on small engine (8095, 10 seats)
def h11(i):
    return signed(EH3, "POST", "/reserve", {"user_id": U("sm"), "idempotency_key": K("sm%d" % i), "seats": 1})
with ThreadPoolExecutor(max_workers=20) as ex:
    outs11 = list(ex.map(h11, range(20)))
held11 = sum(1 for s, j in outs11 if s == 200 and j.get("status") == "held")
losers11 = Counter(s for s, j in outs11 if not (s == 200 and j.get("status") == "held"))
s11 = seats_of(EH3)
losers11 = Counter((s, j.get("status")) for s, j in outs11 if not (s == 200 and j.get("status") == "held"))
check("reserve_race_small_engine", "20 concurrent 1-seat reserves on 10-seat engine: exactly 10 held, losers 200 status=sold_out (/reserve never auto-waitlists, unlike /book), conserved",
      held11 == 10 and all(s == 200 and t == "sold_out" for (s, t) in losers11) and cons(s11),
      "held=%s losers=%s seats=%s" % (held11, dict(losers11), s11))

# ---- 8. (last: ip budget spent here) invariants during churn (8098)
def h8(i):
    return signed(EH5, "POST", "/reserve", {"user_id": U("ch"), "idempotency_key": K("ch%d" % i), "seats": 1})
outs8 = []
t8 = threading.Thread(target=lambda: outs8.extend([h8(i)[0] for i in range(50)]))
t8.start()
samples8 = [seats_of(EH5) for _ in range(30)]
t8.join()
c8 = Counter(outs8)
ok8 = all(cons(s) for s in samples8)
check("invariants_during_churn", "30 /seats samples during 50 concurrent holds: every sample conserved; holds 200 or 429 (ip burst 40), no 5xx",
      ok8 and all(s in (200, 409, 429) for s in outs8),
      "holds=%s all_conserved=%s" % (dict(c8), ok8))

print("FINDINGS: %d" % FAIL)
print("TOTAL %d cases, PASS %d, FAIL %d" % (PASS+FAIL, PASS, FAIL))
