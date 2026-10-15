#!/usr/bin/env python3
"""Runs the Python SDK against a live engine (auth mode)."""
import sys
sys.path.insert(0, "sdk/python")
from kavach import Kavach, KavachError

k = Kavach("http://127.0.0.1:8080", api_key="sdkkey", hmac_secret="sdksecret")
ok = []
def check(name, cond, detail=""):
    ok.append(cond)
    print(("PASS  " if cond else "FAIL  ") + name + (("  " + str(detail)) if detail else ""))

b1 = k.book("sdkuser", "sdk-book-1", seats=1)
check("sdk book confirmed", b1.get("status") == "confirmed", b1)
b2 = k.book("sdkuser", "sdk-book-1", seats=1)
check("sdk idempotent retry same booking", b2.get("booking_id") == b1.get("booking_id"), b2)

r = k.reserve("sdkuser", "sdk-res-1", seats=2)
check("sdk reserve held", r.get("status") == "held", r)
c = k.confirm(r["reservation_id"], "sdkuser")
check("sdk confirm confirmed", c.get("status") == "confirmed", c)
c2 = k.confirm(r["reservation_id"], "sdkuser")
check("sdk re-confirm same booking", c2.get("booking_id") == c.get("booking_id"), c2)
try:
    rel = k.release(r["reservation_id"])
    check("sdk release on confirmed hold conflicts", False, rel)
except KavachError as e:
    check("sdk release on confirmed hold conflicts", e.status == 409 and e.body.get("status") == "confirmed", e.body)

w = k.waitlist_join("sdkuser", "sdk-wait-1", seats=1)
check("sdk waitlist join", w.get("status") == "queued", w)
lst = k.waitlist("sdkuser")
check("sdk waitlist list shows entry", any(e["waitlist_id"] == w["waitlist_id"] for e in lst.get("entries", [])), lst)
k.waitlist_cancel(w["waitlist_id"])
lst = k.waitlist("sdkuser")
check("sdk waitlist cancel removes entry", lst.get("entries") == [], lst)

s = k.seats()
check("sdk seats shape", {"total", "sold", "held", "free"} <= set(s.keys()), s)
m = k.metrics()
check("sdk metrics shape", "confirmed" in m and "holds_created" in m, m)

print(f"\n{sum(ok)}/{len(ok)} passed")
sys.exit(0 if all(ok) else 1)
