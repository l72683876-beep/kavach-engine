#!/usr/bin/env python3
"""Independent verifier for Kavach logs. From the logs alone it checks:

  1. every seat appears in at most one CONFIRMED booking (no double-sell)
  2. unique booking ids == number of booking records
  3. unique sold seats == the expected inventory size
  4. multi-seat bookings are reported explicitly (fewer bookings than seats
     is not a bug: one booking can hold several seats)
  5. with a holds log: still-held seats never overlap sold seats

Exit code 0 = PASS, 1 = FAIL, so scripts and CI can gate on it.
Restart invariants (post-crash equality) are proven by sim/recovery_test.py.
"""
import json, sys
from collections import Counter

path = sys.argv[1] if len(sys.argv) > 1 else "bookings.jsonl"
expected = int(sys.argv[2]) if len(sys.argv) > 2 else 5000
holds_path = sys.argv[3] if len(sys.argv) > 3 else None

seats, sizes, ids = [], Counter(), set()
n = 0
with open(path) as f:
    for line in f:
        b = json.loads(line)
        n += 1
        ids.add(b["booking_id"])
        seats.extend(b["seats"])
        sizes[len(b["seats"])] += 1

counts = Counter(seats)
dups = sorted(s for s, c in counts.items() if c > 1)
sold_unique = len(counts)

report = {
    "booking_records": n,
    "unique_booking_ids": len(ids),
    "ids_match_records": len(ids) == n,
    "seats_per_booking_histogram": {str(k): v for k, v in sorted(sizes.items())},
    "seats_sold_in_log": len(seats),
    "unique_sold_seats": sold_unique,
    "expected_seats": expected,
    "duplicate_seats": dups[:10],
    "duplicate_count": len(dups),
}
ok = len(ids) == n and sold_unique == expected and len(dups) == 0

if holds_path:
    state = {}
    with open(holds_path) as f:
        for line in f:
            h = json.loads(line)
            ev, rid = h.get("event"), h.get("reservation_id")
            if ev == "reserved":
                state[rid] = h.get("seats", [])
            elif ev in ("confirmed", "released", "expired"):
                state.pop(rid, None)
    held, held_ids = [], set()
    for rid, ss in state.items():
        held.extend(ss)
        held_ids.add(rid)
    overlap = sorted(set(held) & set(counts))
    report["holds_log"] = {
        "reservations_still_held": len(held_ids),
        "seats_still_held": len(held),
        "sold_plus_held": sold_unique + len(held),
        "overlap_sold_and_held": overlap[:10],
        "held_never_sold_ok": len(overlap) == 0,
    }
    ok = ok and len(overlap) == 0

report["verdict"] = "PASS" if ok else "FAIL"
print(json.dumps(report, indent=2))
sys.exit(0 if ok else 1)
