# God-Level Roadmap

Where Kavach goes from production-grade to the reference engine for flash-sale
inventory. One rule stays fixed across every milestone: the hot path stays fast and
dependency-free by default, and every claim is measured, never claimed.

## 1. AI layer (IBM Granite) — started

- **Kavach Copilot** (`copilot/`): natural language in, real engine calls out, powered
  by IBM Granite behind a self-hosted auth proxy. Not in the hot path; tool
  allow-list only; seats clamped; every reply's numbers come from the engine.
- **Anomaly narration**: `/metrics` snapshots summarized into plain-language incident
  notes, so a small team can run a big sale.
- **NL configuration**: describe a sale in a sentence, get a checked KCL file.

## 2. v2.2: shared-state mode (Redis) — IN PROGRESS

Closes the two limits on the record in the README: global rate limiting and a
cluster-wide waitlist.

- [x] Optional Redis-backed token buckets (per-user, per-IP, global) shared
  across nodes behind one atomic Lua script (build tag `redis`, flag `-redis`);
  in-memory buckets remain the zero-dependency default, and a Redis outage
  fails open (the shared limiter must never take the sale down).
- [ ] Cluster-wide FIFO waitlist with cross-node promotion, preserving the
  front-of-line fairness rule exactly as single-node does today. In progress:
  the queue state moves to Redis lists so any node that frees seats serves the
  front of the shared line; replay and snapshot coupling needs its own battery
  phase before it ships.

## 3. v2.3: observability to the standard

- [x] Prometheus exposition on `/metrics/prometheus` (text format 0.0.4): every
  `/metrics` counter as `kavach_<name>_total`, gauges (`kavach_in_flight`,
  `kavach_replication_connected`, `kavach_last_snapshot_age_seconds`,
  `kavach_uptime_seconds`, `kavach_shards`), the replication role as
  `kavach_role_info{role=...}`, and latency percentiles as
  `kavach_latency_ms{quantile=...}` per shard (percentiles do not sum), plus
  `kavach_latency_samples`. The JSON `/metrics` endpoint keeps its exact shape
  for existing parsers.
- Structured JSON logs with trace ids (tracing.go already carries them); optional
  OpenTelemetry export.

## 4. v2.4: richer inventory

- [x] Multi-SKU atomic holds: one idempotent reservation spanning several
  items. `POST /reserve` accepts `items: [{sku, count}, ...]` (max 8 SKUs,
  1-4 units each, seats and items exclusive): every SKU is taken in name
  order and any shortage gives back everything before the caller sees a
  `shortage` map. SKUs come from `-skus "vip=100,standard=250"`; the `-seats`
  inventory stays the default SKU, every pre-2.4 path is untouched, and
  confirm/release/expiry/WAL replay/snapshot all restore per SKU. In this
  phase SKUs are node-local and multi-SKU holds are served locally only.
- [x] Attribute inventory: tier / row / section maps, not just counts.
  `-layout "vip=/etc/vip.json"` loads each SKU's attribute ranges
  (`{"ranges":[{"from":0,"to":49,"attrs":{"tier":"A","row":"12"}}]}`, first
  match wins); a reserve item names `attrs: {"tier": "A"}` and only seats
  matching the filter are taken, with the whole multi-SKU hold still
  all-or-nothing and the filter part of the idempotency fingerprint.
  Responses carry per-seat `seat_attrs`; a SKU without a layout rejects
  attribute requests.
- [x] Transfers and resale-lock on confirmed bookings.
  `POST /transfer {"reservation_id":"...","to_user":"..."}` hands a
  CONFIRMED booking to another user (persist-before-ack WAL event,
  replayed in order, so ownership survives restarts); an optional
  `user_id` must match the current owner, `resale_lock: true` at reserve
  time refuses every transfer with 409 `resale_locked`, and transferring
  to the current owner is idempotent. Responses now carry `user_id`.

## 5. Ship discipline

Every milestone lands only when `scripts/test.sh --full` stays green and the
red-team battery passes at zero findings; new surfaces earn their own battery
phase before they ship.
