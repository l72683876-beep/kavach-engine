# Kavach Security and Correctness Audit (v1 core → v1.5)

Date: 15 October 2026. Scope: a line-by-line audit of `engine/main.go`, run before
any v2 expansion, per the launch-bar plan in the architecture document.
Every fix below is covered by an automated test in `sim/security_test.py` (14/14 pass
against an engine started in authenticated mode).

## Findings and fixes

| # | Finding | Severity | Disposition |
|---|---|---|---|
| 1 | Booking log was flushed every 100 ms: a hard crash could lose the last window of bookings whose clients had already received `200 confirmed` (ack-before-persist) | High | Fixed: `appendLog` now writes, flushes, and fsyncs BEFORE the confirmation response is sent. A confirmed response means the record is on disk. |
| 2 | Idempotency trim could evict an in-flight `processing` entry, allowing a later duplicate | Medium | Fixed: trim evicts only entries idle over 10 minutes and never a `processing` entry |
| 3 | Idempotency was keyed by the raw key string only: reuse by another tenant, or with a different payload, went undetected | Medium | Fixed: keys are scoped per tenant and each operation stores a request fingerprint (SHA-256 of the exact body); a mismatch returns `idempotency_conflict` |
| 4 | The confirmed-result shortcut bypassed the fingerprint check, so the same key with a different payload replayed the old result instead of conflicting (caught by acceptance test 9) | Medium | Fixed |
| 5 | The request fingerprint covered key+user+seats but NOT the event: the same idempotency key reused on a different event silently replayed the first event's booking (found by red-team variant battery, run 11) | Medium | Fixed: fingerprints now bind the event (query `event` or body `event_id`, default `default`); same key on a different event returns `idempotency_conflict` on /book, /reserve and waitlist join; regression tests TestIdemKeyBoundToEvent + TestWaitlistKeyBoundToEvent |
| 5 | No authentication of any kind | High | Fixed: bearer API keys mapped to tenants via `-api-keys key:tenant,...`; empty spec keeps the two-minute local mode |
| 6 | No replay protection | Medium | Fixed in HMAC mode: `X-Kavach-Timestamp` within a ±5-minute window plus single-use `X-Kavach-Request-Id` nonces with expiry and periodic pruning |
| 7 | Only a per-user rate limit; no per-IP layer and no global capacity gate | Medium | Fixed: layered limits, per IP → per user → global in-flight cap (500,000); each layer independently disableable with `-ip-rate 0` etc. |
| 8 | Unbounded request body; unknown JSON fields silently accepted | Medium | Fixed: 16 KB body cap, strict schema with `DisallowUnknownFields` (reject, never sanitize silently) |
| 9 | A client that received an ambiguous timeout could not resolve it safely | Low | Fixed: `GET /status?idempotency_key=...` returns the stored outcome for the authenticated tenant |
| 10 | Verified sound, no change needed | — | CAS seat inventory (two workers can never hold the same seat; the fast-path sold counter is advisory and the scan re-checks), single-winner `claim()` race, latency-ring percentile math, bounded-queue admission |

## Deliberately not fixed in v1.5

These are v2 milestone scope, tracked in the architecture document:

- Single-process inventory; multi-node sharding with fenced ownership is Milestone 3
- File event log only; the Postgres write-behind projection is Milestone 3
- Hold/confirm reservation lifecycle is Milestone 2
- The distributed rate-limit store (Redis) with documented fail-open/fail-closed policies is Milestone 3

## How to reproduce

```bash
go build -o kavach . && ./kavach -seats 100 -workers 4 \
  -api-keys testkey:tenant1 -hmac-secret testsecret -ip-rate 0
python3 sim/security_test.py 8080
```
