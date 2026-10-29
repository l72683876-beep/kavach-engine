#!/usr/bin/env python3
"""Run 41 extras: 16 angles.
1: FIFO head-blocking: blocked 4-seat front starves the 1-seat behind it (free=1 and free=2,3)
2: idempotency key is case-sensitive: different case = different reservation
3: unicode idempotency key accepted; POST replay returns the stored result
4: 8KB idempotency key accepted, no 5xx; replay works
5: /reserve unknown extra field -> 400 (strict decode)
6: /waitlist unknown extra field -> 400
7: float timestamp "1700000000.5" -> 401
8: negative timestamp -> 401
9: timestamp overflow (21 digits) -> 401, no panic
10: /release with wrong event_id: no 5xx, seats conserved, hold still releasable with correct call
11: /waitlist seats=0 -> 400
12: Authorization header entirely missing -> 401
13: X-Kavach-Signature with "sha256:" prefix -> 401
14: uppercase hex signature: no 5xx (either accepted or 401, both safe)
15: UTF-8 BOM before JSON body -> 400
16: seats as float 1.0: no 5xx; if accepted, exactly 1 seat held
"""
import hashlib, hmac, http.client, json, time, uuid
from collections import Counter

KEY, KEY2, SECRET = "testkey", "otherkey", "testsecret"
EH1, EH2, EH5 = "http://127.0.0.1:8091", "http://127.0.0.1:8092", "http://127.0.0.1:8098"
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

def signed(host, method, uri, obj=None, key=KEY, secret=SECRET, ts=None, rid=None, auth="Bearer", upper_sig=False, prefix_sig=False):
    body = json.dumps(obj).encode() if obj is not None else b""
    ts = ts or str(int(time.time()))
    rid = rid or uuid.uuid4().hex
    mac = mac_for(secret, ts, rid, method, uri, key, body)
    if upper_sig: mac = mac.upper()
    if prefix_sig: mac = "sha256:" + mac
    h = {"X-Kavach-Timestamp": ts, "X-Kavach-Request-Id": rid, "X-Kavach-Signature": mac,
         "Content-Type": "application/json"}
    if auth is not None: h["Authorization"] = auth + " " + key
    return send(host, method, uri, body, h)

def seats_of(host):
    return signed(host, "GET", "/seats")[1]

U = lambda t: "r41-%s-%s" % (t, uuid.uuid4().hex[:6])
K = lambda t: "k41-%s-%s" % (t, uuid.uuid4().hex[:6])

# ---- 1. FIFO head-blocking starvation (8092, 61 seats, ttl 30)
rids = []
i = 0
while len(rids) < 19 and i < 40:
    n = 4 if len(rids) < 14 else 1
    ud = U("dr")
    st, j = signed(EH2, "POST", "/reserve", {"user_id": ud, "idempotency_key": K("dr"), "seats": n})
    if st == 200 and j.get("status") == "held":
        rids.append((j.get("reservation_id"), n))
    i += 1
ones = [r for r, n in rids if n == 1]
uA, kA = U("fA"), K("fA"); uB, kB = U("fB"), K("fB")
sa, ja = signed(EH2, "POST", "/waitlist", {"user_id": uA, "idempotency_key": kA, "seats": 4})
sb, jb = signed(EH2, "POST", "/waitlist", {"user_id": uB, "idempotency_key": kB, "seats": 1})
for rid in ones[:3]:  # free 1, then 2, then 3 seats; front 4-seat stays blocked
    signed(EH2, "POST", "/release", {"reservation_id": rid})
s3 = seats_of(EH2)
gA, jA = signed(EH2, "GET", "/waitlist?user_id=" + uA)
gB, jB = signed(EH2, "GET", "/waitlist?user_id=" + uB)
check("wl_head_block_starves", "front 4-seat blocked -> 1-seat behind NOT promoted at free=3, both queued",
      sa == 200 and sb == 200 and s3["free"] == 3 and len(jA.get("entries", [])) == 1 and len(jB.get("entries", [])) == 1,
      "free=%s A=%d B=%d" % (s3["free"], len(jA.get("entries", [])), len(jB.get("entries", []))))
signed(EH2, "POST", "/release", {"reservation_id": ones[3]})  # 4th free -> A promoted
gA2, jA2 = signed(EH2, "GET", "/waitlist?user_id=" + uA)
gB2, jB2 = signed(EH2, "GET", "/waitlist?user_id=" + uB)
check("wl_fifo_strict", "after 4th free A promoted (gone), B still queued",
      len(jA2.get("entries", [])) == 0 and len(jB2.get("entries", [])) == 1,
      "A=%d B=%d" % (len(jA2.get("entries", [])), len(jB2.get("entries", []))))

# ---- 2. idem key case-sensitive (8098)
kc = K("case")
sh, jh = signed(EH5, "POST", "/reserve", {"user_id": U("cs"), "idempotency_key": kc, "seats": 1})
stc, jc = signed(EH5, "POST", "/reserve", {"user_id": U("cs2"), "idempotency_key": kc.swapcase(), "seats": 1})
check("idem_case_sensitive", "different case idem key -> independent reservation",
      sh == 200 and stc == 200 and jc.get("reservation_id") != jh.get("reservation_id"),
      "rid1=%s rid2=%s" % (str(jh.get("reservation_id"))[:8], str(jc.get("reservation_id"))[:8]))

# ---- 3. unicode idem key + replay
ku = "k41-\U0001f510-" + uuid.uuid4().hex[:6]
uu3 = U("uni")
sh3, jh3 = signed(EH5, "POST", "/reserve", {"user_id": uu3, "idempotency_key": ku, "seats": 1})
sr3, jr3 = signed(EH5, "POST", "/reserve", {"user_id": uu3, "idempotency_key": ku, "seats": 1})
check("unicode_idem_key", "unicode idem key accepted; replay returns stored reservation",
      sh3 == 200 and sr3 == 200 and jr3.get("reservation_id") == jh3.get("reservation_id"),
      "hold=%s replay_rid_match=%s" % (sh3, jr3.get("reservation_id") == jh3.get("reservation_id")))

# ---- 4. 8KB idem key
kl = "L" * 8192
uu4 = U("long")
sh4, jh4 = signed(EH5, "POST", "/reserve", {"user_id": uu4, "idempotency_key": kl, "seats": 1})
sr4, jr4 = signed(EH5, "POST", "/reserve", {"user_id": uu4, "idempotency_key": kl, "seats": 1})
check("long_idem_key", "8KB idem key: no 5xx, replay consistent",
      sh4 < 500 and sr4 < 500 and jr4.get("reservation_id") == jh4.get("reservation_id"),
      "hold=%s replay=%s" % (sh4, sr4))

# ---- 5/6. strict decode: unknown fields
st5, j5 = signed(EH5, "POST", "/reserve", {"user_id": U("uf"), "idempotency_key": K("uf"), "seats": 1, "extra_field": "x"})
st6, j6 = signed(EH2, "POST", "/waitlist", {"user_id": U("wf"), "idempotency_key": K("wf"), "seats": 1, "extra_field": "x"})
check("reserve_unknown_field", "/reserve unknown field -> 400", st5 == 400, "st=%s %s" % (st5, j5.get("status")))
check("wl_unknown_field", "/waitlist unknown field -> 400", st6 == 400, "st=%s %s" % (st6, j6.get("status")))

# ---- 7/8/9. timestamp parsing (8098)
st7, _ = signed(EH5, "POST", "/reserve", {"user_id": U("t7"), "idempotency_key": K("t7"), "seats": 1}, ts="1700000000.5")
st8, _ = signed(EH5, "POST", "/reserve", {"user_id": U("t8"), "idempotency_key": K("t8"), "seats": 1}, ts="-123")
st9, _ = signed(EH5, "POST", "/reserve", {"user_id": U("t9"), "idempotency_key": K("t9"), "seats": 1}, ts="99999999999999999999")
check("float_ts", "float timestamp 401", st7 == 401, "st=%s" % st7)
check("negative_ts", "negative timestamp 401", st8 == 401, "st=%s" % st8)
check("ts_overflow", "21-digit timestamp 401, engine alive", st9 == 401 and seats_of(EH5)["free"] > 0, "st=%s" % st9)

# ---- 10. release with wrong event_id (8098)
u10, k10 = U("wev"), K("wev")
sh10, jh10 = signed(EH5, "POST", "/reserve", {"user_id": u10, "idempotency_key": k10, "seats": 2})
pre10 = seats_of(EH5)
srw, jrw = signed(EH5, "POST", "/release", {"reservation_id": jh10.get("reservation_id"), "event_id": "evt-does-not-exist"})
postw = seats_of(EH5)
srr, jrr = signed(EH5, "POST", "/release", {"reservation_id": jh10.get("reservation_id")})
postr = seats_of(EH5)
check("release_wrong_event_id", "release ignores event_id (contract: reservation_id + optional event_id): frees exactly once, re-release idempotent, no double-free",
      srw == 200 and jrw.get("status") == "released" and postw["free"] == pre10["free"] + 2 and srr == 200 and postr["free"] == postw["free"],
      "wrong=%s %s re-release=%s free %s->%s->%s" % (srw, jrw.get("status"), srr, pre10["free"], postw["free"], postr["free"]))

# ---- 11. waitlist seats=0 (8092)
st11, j11 = signed(EH2, "POST", "/waitlist", {"user_id": U("z"), "idempotency_key": K("z"), "seats": 0})
check("wl_seats_zero", "waitlist seats=0 -> 400", st11 == 400, "st=%s %s" % (st11, j11.get("status")))

# ---- 12. missing Authorization header
st12, j12 = signed(EH5, "POST", "/reserve", {"user_id": U("na"), "idempotency_key": K("na"), "seats": 1}, auth=None)
check("no_auth_header", "no Authorization header -> 401", st12 == 401, "st=%s %s" % (st12, j12.get("status")))

# ---- 13/14. signature encoding (8098)
st13, j13 = signed(EH5, "POST", "/reserve", {"user_id": U("sp"), "idempotency_key": K("sp"), "seats": 1}, prefix_sig=True)
st14, j14 = signed(EH5, "POST", "/reserve", {"user_id": U("su"), "idempotency_key": K("su"), "seats": 1}, upper_sig=True)
check("sig_prefix_sha256", "'sha256:'+hex signature -> 401", st13 == 401, "st=%s %s" % (st13, j13.get("status")))
check("sig_uppercase", "uppercase hex signature: no 5xx, engine alive", st14 < 500 and st14 != 0,
      "st=%s %s" % (st14, j14.get("status")))

# ---- 15. BOM body (8098)
body15 = b"\xef\xbb\xbf" + json.dumps({"user_id": U("bom"), "idempotency_key": K("bom"), "seats": 1}).encode()
ts15, rid15 = str(int(time.time())), uuid.uuid4().hex
mac15 = mac_for(SECRET, ts15, rid15, "POST", "/reserve", KEY, body15)
st15, j15 = send(EH5, "POST", "/reserve", body15, {"Authorization": "Bearer "+KEY, "X-Kavach-Timestamp": ts15,
                 "X-Kavach-Request-Id": rid15, "X-Kavach-Signature": mac15, "Content-Type": "application/json"})
check("bom_body", "BOM before JSON -> 400", st15 == 400, "st=%s %s" % (st15, j15.get("status")))

# ---- 16. float seats 1.0 (8098)
pre16 = seats_of(EH5)
st16, j16 = signed(EH5, "POST", "/reserve", {"user_id": U("fs"), "idempotency_key": K("fs"), "seats": 1.0})
post16 = seats_of(EH5)
ok16 = (st16 < 500) and (st16 == 400 or post16["held"] == pre16["held"] + 1)
check("float_seats", "seats 1.0: no 5xx; if accepted exactly 1 held", ok16,
      "st=%s %s held %s->%s" % (st16, j16.get("status"), pre16["held"], post16["held"]))

print("FINDINGS: %d" % FAIL)
print("TOTAL %d cases, PASS %d, FAIL %d" % (PASS+FAIL, PASS, FAIL))
