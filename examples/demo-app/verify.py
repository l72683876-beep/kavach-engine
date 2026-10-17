#!/usr/bin/env python3
"""Double-sell oracle: reads the engine's own write-ahead logs and proves
no seat was ever sold to two buyers. Exit 1 on any violation.

    python3 verify.py [bookings.jsonl] [holds.jsonl]
"""
import collections, json, sys

def pick(argv_val, *candidates):
    if argv_val:
        return argv_val
    for c in candidates:
        import os
        if os.path.exists(c):
            return c
    return candidates[0]

bookings_path = pick(sys.argv[1] if len(sys.argv) > 1 else None,
                     "../../engine/main_bookings.jsonl", "../../engine/bench_bookings.jsonl", "main_bookings.jsonl")
holds_path = pick(sys.argv[2] if len(sys.argv) > 2 else None,
                  "../../engine/main_holds.jsonl", "../../engine/bench_holds.jsonl", "main_holds.jsonl")

sold = collections.Counter()
bookings = 0
seats_per_booking = 0
try:
    with open(bookings_path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            rec = json.loads(line)
            for seat in rec["seats"]:
                sold[seat] += 1
            bookings += 1
            seats_per_booking += len(rec["seats"])
except FileNotFoundError:
    print(f"FAIL: {bookings_path} not found")
    sys.exit(1)

holds = 0
try:
    with open(holds_path) as f:
        holds = sum(1 for line in f if line.strip())
except FileNotFoundError:
    holds = -1  # holds log optional; bookings are the ground truth for double-sell

dupes = {s: c for s, c in sold.items() if c > 1}
total_sold_seats = len(sold)
print(f"bookings: {bookings}")
print(f"sold seat events: {seats_per_booking}")
print(f"unique sold seats: {total_sold_seats}")
print(f"holds seen: {holds}")
if dupes:
    worst = sorted(dupes.items(), key=lambda kv: -kv[1])[:10]
    print(f"FAIL: {len(dupes)} seats sold more than once, worst: {worst}")
    sys.exit(1)
print("PASS: zero double-sell, every seat sold at most once")
