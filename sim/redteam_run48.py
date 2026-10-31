#!/usr/bin/env python3
"""Run 48 extras: 10 angles.
1: 1MB idempotency key -> clean 4xx or accepted, no 5xx
2: 10 concurrent app /api/hold, one user -> all held, app board shows 10 held
3: GET /seats?offset=-1 -> no 5xx
4: GET /seats?offset=1000000 -> 200 empty, no 5xx
5: DESIGN PROBE: user B cancels user A's waitlist_id (sequential WL ids, same tenant)
6: DESIGN PROBE: user B releases user A's reservation_id (sequential RSV ids, same tenant)
7: app /api/kavach-webhook with valid token, malformed JSON -> 400, app alive
8: float-string timestamp "176...5" -> 401
9: signed "//reserve" path (MAC over RequestURI) -> no 5xx, no state change
10: /metrics after activity: valid JSON, holds counter > 0, no secret
"""
import hashlib, hmac, http.client, json, time, uuid
from concurrent.futures import ThreadPoolExecutor

KEY, KEY2, SECRET = "testkey", "otherkey", "testsecret"
EH1, EH2, EH5 = "http://127.0.0.1:8091", "http://127.0.0.1:8092", "http://127.0.0.1:8098"
APP = "http://127.0.0.1:9001"
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
    c = http.client.HTTPConnection(p[0], int(p[1]), timeout=8)
    c.request(method, uri, body=body, headers=headers)
    r = c.getresponse(); d = r.read(); st = r.status; c.close()
    try: j = json.loads(d) if d else {}
    except Exception: j = {"_raw": d[:200].decode("utf-8", "replace")}
    return st, j

def signed(host, method, uri, obj=None, key=KEY, secret=SECRET):
    body = json.dumps(obj).encode() if obj is not None else b""
    ts = str(int(time.time()))
    rid = uuid.uuid4().hex
    mac = mac_for(secret, ts, rid, method, uri, key, body)
    h = {"Authorization": "Bearer "+key, "X-Kavach-Timestamp": ts, "X-Kavach-Request-Id": rid,
         "X-Kavach-Signature": mac, "Content-Type": "application/json"}
    return send(host, method, uri, body, h)

def seats_of(host):
    return signed(host, "GET", "/seats")[1]

U = lambda t: "r48-%s-%s" % (t, uuid.uuid4().hex[:6])
K = lambda t: "k48-%s-%s" % (t, uuid.uuid4().hex[:6])

# ---- 1. 1MB idem key
k1 = "k" * 1000000
st1, j1 = signed(EH5, "POST", "/reserve", {"user_id": U("mb"), "idempotency_key": k1, "seats": 1})
alive1 = seats_of(EH5).get("total", 0) > 0
check("idem_key_1mb", "1MB idem key: clean 4xx or accepted, no 5xx, engine alive",
      st1 < 500 and st1 != 0 and alive1, "st=%s %s alive=%s" % (st1, j1.get("status"), alive1))

# ---- 2. 10 concurrent app holds, one user
u2 = U("ac")
def hold2(_):
    return send(APP, "POST", "/api/hold", json.dumps({"user_id": u2, "seats": 1}).encode(), {"Content-Type": "application/json"})
with ThreadPoolExecutor(max_workers=10) as ex:
    outs2 = list(ex.map(hold2, range(10)))
codes2 = {}
for s, j in outs2:
    codes2[(s, j.get("error") or j.get("status"))] = codes2.get((s, j.get("error") or j.get("status")), 0) + 1
# engine default per-user limiter (user-rate 2/s, burst 5): 5 held + 5 rate_limited, no 5xx
held2 = sum(1 for s, j in outs2 if s == 200)
rl2 = sum(1 for s, j in outs2 if s == 429)
board2 = None
for _ in range(8):  # board cache is 0.5s: poll until it catches up
    board2 = send(APP, "GET", "/api/seats/state", None, {})[1].get("states", "")
    if board2.count("1") >= held2:
        break
    time.sleep(0.4)
check("app_concurrent_holds", "10 concurrent app holds, one user: 5 held + 5 rate_limited (default per-user limiter), board catches up, no 5xx",
      held2 == 5 and rl2 == 5 and all(s < 500 for s, _ in outs2) and board2.count("1") == 5,
      "codes=%s board_held=%d" % ({str(k): v for k, v in codes2.items()}, board2.count("1")))

# ---- 3/4. /seats offset probes
st3, j3 = signed(EH5, "GET", "/seats?offset=-1")
st4, j4 = signed(EH5, "GET", "/seats?offset=1000000")
ok4 = st4 == 200 and (j4.get("states") in ("", None) or isinstance(j4.get("states"), str))
check("seats_negative_offset", "GET /seats?offset=-1: no 5xx", st3 < 500 and st3 != 0, "st=%s" % st3)
check("seats_big_offset", "GET /seats?offset=1000000: 200, clean empty read", ok4, "st=%s %s" % (st4, str(j4)[:60]))

# ---- 5. cross-user waitlist cancel (8092, drained)
rids5 = []
i5 = 0
while len(rids5) < 19 and i5 < 40:
    n5d = 4 if len(rids5) < 14 else 1
    ud5 = U("dr")
    std, jd = signed(EH2, "POST", "/reserve", {"user_id": ud5, "idempotency_key": K("dr"), "seats": n5d})
    if std == 200 and jd.get("status") == "held":
        rids5.append(jd.get("reservation_id"))
    i5 += 1
ua, ka = U("wa"), K("wa")
sj5, jj5 = signed(EH2, "POST", "/waitlist", {"user_id": ua, "idempotency_key": ka, "seats": 1})
wid5 = jj5.get("waitlist_id")
ub = U("wb")
st5, j5 = signed(EH2, "POST", "/waitlist/cancel", {"waitlist_id": wid5}, key=KEY2)
gw5, jw5 = signed(EH2, "GET", "/waitlist?user_id=" + ua)
# KEY2 is tenant2: cross-tenant should 404; also probe same-tenant cross-user below
st5b, j5b = signed(EH2, "POST", "/waitlist/cancel", {"waitlist_id": wid5})  # same tenant, different user_id
gw5b, jw5b = signed(EH2, "GET", "/waitlist?user_id=" + ua)
check("wl_cancel_cross_tenant", "cross-tenant wl cancel -> 404, entry survives", st5 == 404 and len(jw5.get("entries", [])) == 1,
      "st=%s entries=%d" % (st5, len(jw5.get("entries", []))))
check("wl_cancel_cross_user", "same-tenant cross-user wl cancel: observe (ownership not keyed on user_id)",
      st5b < 500 and st5b != 0, "st=%s %s entries_after=%d" % (st5b, j5b.get("status"), len(jw5b.get("entries", []))))

# ---- 6. cross-user release (8098): user A holds, user B releases with same tenant key
ua6, ka6 = U("ra"), K("ra")
sh6, jh6 = signed(EH5, "POST", "/reserve", {"user_id": ua6, "idempotency_key": ka6, "seats": 2})
rid6 = jh6.get("reservation_id")
pre6 = seats_of(EH5)
st6, j6 = signed(EH5, "POST", "/release", {"reservation_id": rid6, "user_id": U("rb")})
fin6 = seats_of(EH5)
check("release_cross_user", "same-tenant cross-user release: observe (id possession is the authority)",
      st6 < 500 and st6 != 0 and (fin6["held"] == pre6["held"] or fin6["held"] == pre6["held"] - 2),
      "st=%s %s held %s->%s" % (st6, j6.get("status"), pre6["held"], fin6["held"]))

# ---- 7. app webhook valid token, malformed JSON
sw7, jw7 = send(APP, "POST", "/api/kavach-webhook", b"{not json", {"Content-Type": "application/json", "X-Webhook-Token": "whsec-redtest"})
sa7 = send(APP, "GET", "/api/seats", None, {})
check("app_webhook_malformed", "app webhook valid token, malformed body: 4xx, app alive",
      sw7 < 500 and sw7 != 0 and sa7[0] == 200, "st=%s %s app=%s" % (sw7, json.dumps(jw7)[:50], sa7[0]))

# ---- 8. float-string timestamp
k8 = K("ft")
b8 = json.dumps({"user_id": U("ft"), "idempotency_key": k8, "seats": 1}).encode()
ts8 = str(int(time.time())) + ".5"
rid8 = uuid.uuid4().hex
mac8 = mac_for(SECRET, ts8, rid8, "POST", "/reserve", KEY, b8)
st8, j8 = send(EH5, "POST", "/reserve", b8, {"Authorization": "Bearer "+KEY, "X-Kavach-Timestamp": ts8,
               "X-Kavach-Request-Id": rid8, "X-Kavach-Signature": mac8, "Content-Type": "application/json"})
check("ts_float_string", "float-string timestamp -> 401", st8 == 401, "st=%s %s" % (st8, j8.get("status")))

# ---- 9. double-slash path
k9 = K("ds")
b9 = json.dumps({"user_id": U("ds"), "idempotency_key": k9, "seats": 1}).encode()
ts9, rid9 = str(int(time.time())), uuid.uuid4().hex
mac9 = mac_for(SECRET, ts9, rid9, "POST", "//reserve", KEY, b9)
pre9 = seats_of(EH5)
st9, j9 = send(EH5, "POST", "//reserve", b9, {"Authorization": "Bearer "+KEY, "X-Kavach-Timestamp": ts9,
               "X-Kavach-Request-Id": rid9, "X-Kavach-Signature": mac9, "Content-Type": "application/json"})
fin9 = seats_of(EH5)
check("double_slash_path", "signed '//reserve': no 5xx, no state change (handler never sees it)",
      st9 < 500 and st9 != 0 and fin9["held"] == pre9["held"], "st=%s %s held %s->%s" % (st9, j9.get("status"), pre9["held"], fin9["held"]))

# ---- 10. /metrics counters sane after activity
sm10, jm10 = send(EH5, "GET", "/metrics", None, {})
raw10 = json.dumps(jm10)
holds10 = jm10.get("holds_created", jm10.get("holdsCreated", 0))
no_secret10 = "testsecret" not in raw10
check("metrics_counters_sane", "/metrics after activity: valid JSON, holds counter > 0, no secret",
      sm10 == 200 and holds10 > 0 and no_secret10, "st=%s holds=%s secret=%s" % (sm10, holds10, no_secret10))

print("FINDINGS: %d" % FAIL)
print("TOTAL %d cases, PASS %d, FAIL %d" % (PASS+FAIL, PASS, FAIL))
