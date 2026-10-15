#!/usr/bin/env python3
"""Verify the booking log: no double sales, exact seat count, unique ids."""
import json, sys
path = sys.argv[1] if len(sys.argv) > 1 else "bookings.jsonl"
expected = int(sys.argv[2]) if len(sys.argv) > 2 else 5000
seats, ids = [], set()
n = 0
with open(path) as f:
    for line in f:
        b = json.loads(line)
        n += 1
        ids.add(b["booking_id"])
        seats.extend(b["seats"])
dup = [s for s in set(seats) if seats.count(s) > 1]
print(json.dumps({
    "bookings": n, "seats_sold_in_log": len(seats), "unique_booking_ids": len(ids),
    "expected_seats": expected,
    "duplicate_seats": dup[:10], "duplicate_count": len(dup),
    "accuracy_ok": len(seats) == expected and len(dup) == 0 and len(ids) == n,
}, indent=2))
