#!/usr/bin/env python3
"""Kavach waitlist acceptance tests. Run against a live engine started with
-auth, a short -hold-ttl (10s recommended), and a webhook URL pointing at the
receiver this script starts on port 9099. Exit non-zero on any failure."""
import hashlib, hmac, http.client, http.server, json, sys, threading, time, uuid

HOST, PORT = "127.0.0.1", int(sys.argv[1]) if len(sys.argv) > 1 else 8080
API_KEY, SECRET = "testkey", "testsecret"
HOOK_PORT = 9099
results = []
received = []
lock = threading.Lock()

class Hook(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(n) or b"{}")
        with lock:
            received.append(body)
        self.send_response(200); self.end_headers()
    def log_message(self, *a):
        pass

hook_server = http.server.ThreadingHTTPServer(("127.0.0.1", HOOK_PORT), Hook)
threading.Thread(target=hook_server.serve_forever, daemon=True).start()

def request(method, path, body=None):
    body_bytes = json.dumps(body).encode() if body is not None else b""
    conn = http.client.HTTPConnection(HOST, PORT, timeout=30)
    ts = str(int(time.time()))
    rid = uuid.uuid4().hex
    headers = {"Content-Type": "application/json", "Authorization": "Bearer " + API_KEY,
               "X-Kavach-Timestamp": ts, "X-Kavach-Request-Id": rid}
    mac = hmac.new(SECRET.encode(), (ts + "\n" + rid + "\n").encode() + body_bytes, hashlib.sha256)
    headers["X-Kavach-Signature"] = mac.hexdigest()
    conn.request(method, path, body=body_bytes if body is not None else None, headers=headers)
    r = conn.getresponse(); raw = r.read(); conn.close()
    return r.status, (json.loads(raw) if raw else {})

def check(name, ok, detail=""):
    results.append((name, ok))
    print(("PASS  " if ok else "FAIL  ") + name + (("  " + detail) if detail else ""))

# setup: fill every seat so the waitlist is the only way in
seats0 = request("GET", "/seats")[1]
reserves = {}
for i in range(seats0["free"]):
    st, d = request("POST", "/reserve", {"user_id": f"filler{i}", "idempotency_key": f"fill-{i}", "seats": 1})
    reserves[d["reservation_id"]] = (f"filler{i}", d["seats"][0])
check("setup: all seats held", request("GET", "/seats")[1]["free"] == 0)

# 1: join the waitlist when sold out
st, d = request("POST", "/waitlist", {"user_id": "u_w1", "idempotency_key": "w1", "seats": 1})
check("waitlist join returns queued with position 1", st == 200 and d.get("status") == "queued" and d.get("position") == 1, f"{st} {d}")
wid1 = d.get("waitlist_id", "")

# 2: idempotent join
st, d = request("POST", "/waitlist", {"user_id": "u_w1", "idempotency_key": "w1", "seats": 1})
check("re-join same key same waitlist id", st == 200 and d.get("waitlist_id") == wid1, f"{st} {d}")

# 3: same key different payload is a conflict
st, d = request("POST", "/waitlist", {"user_id": "u_w1", "idempotency_key": "w1", "seats": 2})
check("re-join same key different payload conflicted", st == 409, f"{st} {d}")

# 4: second in line sees position 2
st, d = request("POST", "/waitlist", {"user_id": "u_w2", "idempotency_key": "w2", "seats": 1})
wid2 = d.get("waitlist_id", "")
st, d = request("GET", "/waitlist?user_id=u_w2")
check("second entry sees position 2", st == 200 and d.get("entries") and d["entries"][0]["position"] == 2, f"{st} {d}")

# 5: release frees a seat, the FRONT of the line gets it automatically
rel_id = next(iter(reserves))
rel_user = reserves[rel_id][0]
st, d = request("POST", "/release", {"reservation_id": rel_id})
check("release ok", st == 200 and d.get("status") == "released", f"{st} {d}")
time.sleep(1.0)
st, d = request("GET", "/waitlist?user_id=u_w1")
check("front of line fulfilled and removed from waitlist", st == 200 and d.get("entries") == [], f"{st} {d}")
st, d = request("GET", "/waitlist?user_id=u_w2")
check("second entry moved to position 1", st == 200 and d.get("entries") and d["entries"][0]["position"] == 1, f"{st} {d}")
with lock:
    hooks = [h for h in received if h.get("event") == "waitlist_fulfilled"]
match = [h for h in hooks if h.get("user_id") == "u_w1"]
check("webhook fired for the fulfilled user", len(match) == 1 and match[0].get("reservation_id", "").startswith("RSV"), f"{hooks}")
# the auto-hold belongs to the waitlisted user and is a live reservation
if match:
    st, d = request("GET", "/reservation?id=" + match[0]["reservation_id"])
    check("auto-hold is a live held reservation", st == 200 and d.get("status") == "held" and d.get("booking_id") == "", f"{st} {d}")
else:
    check("auto-hold is a live held reservation", False, "no webhook received")

# 6: cancel removes the entry; the next release does NOT serve it
st, d = request("POST", "/waitlist", {"user_id": "u_w3", "idempotency_key": "w3", "seats": 1})
wid3 = d.get("waitlist_id", "")
st, d = request("POST", "/waitlist/cancel", {"waitlist_id": wid3})
check("cancel returns cancelled", st == 200 and d.get("status") == "cancelled", f"{st} {d}")
st, d = request("POST", "/waitlist", {"user_id": "u_w4", "idempotency_key": "w4", "seats": 1})
wid4 = d.get("waitlist_id", "")
# w2 is still in line, so the next freed seat goes to it first (FIFO);
# free a second seat for w4, and w3 (cancelled) must never be served
held_list = []
for rid_, (u, _) in reserves.items():
    st_, d_ = request("GET", "/reservation?id=" + rid_)
    if st_ == 200 and d_.get("status") == "held":
        held_list.append(rid_)
if held_list == [] and match:
    held_list = [match[0]["reservation_id"]]
st, d = request("POST", "/release", {"reservation_id": held_list[0]})  # -> w2
time.sleep(0.5)
st, d = request("POST", "/release", {"reservation_id": held_list[1]})  # -> w4
time.sleep(1.5)
with lock:
    hooks = [h for h in received if h.get("event") == "waitlist_fulfilled"]
w3hits = [h for h in hooks if h.get("user_id") == "u_w3"]
w4hits = [h for h in hooks if h.get("user_id") == "u_w4"]
w2hits = [h for h in hooks if h.get("user_id") == "u_w2"]
check("cancelled entry never fulfilled, next in line was", len(w3hits) == 0 and len(w4hits) == 1 and len(w2hits) == 1, f"w3={w3hits} w4={w4hits} w2={w2hits}")

# 7: unsigned request rejected
st, d = request("POST", "/waitlist", {"user_id": "x", "idempotency_key": "x", "seats": 1})
# (request always signs; forge a bad one manually)
import http.client as hc
body = json.dumps({"user_id": "x", "idempotency_key": "x", "seats": 1}).encode()
conn = hc.HTTPConnection(HOST, PORT, timeout=10)
conn.request("POST", "/waitlist", body=body, headers={"Content-Type": "application/json"})
r = conn.getresponse(); st_bad = r.status; conn.close()
check("unsigned waitlist join rejected", st_bad == 401, f"{st_bad}")

fails = [n for n, ok in results if not ok]
print(f"\n{len(results) - len(fails)}/{len(results)} passed")
sys.exit(1 if fails else 0)
