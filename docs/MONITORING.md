# Engine-wide suspicious-activity monitoring (observation only)

Added 2026-11-21. The monitor watches every request the Go engine serves and
raises developer alerts when plain deterministic counters cross thresholds.

## The guarantee, stated honestly

**The monitor never blocks, slows, rejects or otherwise alters a request.**
There is no code path from its counters or alerts back into the request
path; it uses plain counters, never anomaly scores and never AI.

Two honest caveats:

1. The engine's existing controls (HMAC auth, the replay cache, the
   token-bucket rate limiters, the capacity gate) keep doing all enforcement,
   and **those rate limiters can still reject a genuine user** who exceeds
   their configured limits. No absolute zero-block guarantee can be made for
   the engine as a whole; this monitor itself adds no new blocking.
2. Alerts are developer guidance, not enforcement. Check the identity before
   acting on one.

## What it watches

Per identity (an authenticated tenant label, or a truncated SHA-256 of the
client IP), over a sliding window (default 60s):

| Alert type           | Trigger                                          | Default threshold |
|----------------------|--------------------------------------------------|-------------------|
| `auth_burst`         | failed authentications (401s from the auth path) | 20 per window     |
| `replay_burst`       | requests rejected as replays by the HMAC cache   | 5 per window      |
| `rate_limit_burst`   | 429 responses from the limiters (pushing on them)| 30 per window     |
| `flood`              | sheer request volume, per IP and per tenant      | 300 per window    |
| `server_error_spike` | engine-wide 5xx responses (attack or outage)     | 10 per window     |

Scope: this covers ALL engine HTTP traffic (the middleware wraps the whole
handler chain, including 405s, auth failures and rate-limited responses),
not just the Copilot layer. The Python Copilot app is a separate service.

## Privacy

Bodies, query strings and headers are never read or recorded. Alerts carry
only: timestamp, alert type, identity (tenant label or 12-hex IP hash),
reason text, count, window length and rate. The raw IP never appears.

## Configuration (CLI flags)

- `-monitor-off` turn the monitor off (default on, observation only)
- `-monitor-window` window seconds (60)
- `-monitor-max-identities` identities tracked per window (10000; memory
  stays bounded: two windows max, overflow identities share one counter)
- `-monitor-auth-burst`, `-monitor-replay-burst`, `-monitor-limited-burst`,
  `-monitor-flood`, `-monitor-error-spike` (0 disables an alert)
- `-monitor-log` alert log path (`alerts.jsonl`), `-monitor-log-max-mb`
  rotation size (5 MB; one previous generation kept as `alerts.jsonl.1`)
- `-monitor-webhook` POST alerts as JSON here (same body as the log)
- `-monitor-cooldown-seconds` minimum seconds between two alerts of the
  same type for one identity (30)

## Live counters

`GET /monitor` returns observation counters: mode `observe_only`, tracked
identities, overflow count, 5xx in the current window, alerts sent / dropped
/ webhook-failed, and alerts by type. No identities are listed there.

## Overhead

The observe path is a few atomic increments under a read-locked window
pointer. Alerts cross a buffered channel (256) that **drops rather than
blocks** when full, so a slow webhook can never slow a request. Concurrency
is exercised under `-race` in CI.
