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

- Prometheus / OpenMetrics exposition on `/metrics`, latency histograms with labels.
- Structured JSON logs with trace ids (tracing.go already carries them); optional
  OpenTelemetry export.

## 4. v2.4: richer inventory

- Multi-SKU atomic holds: one idempotent reservation spanning several items.
- Attribute inventory: tier / row / section maps, not just counts.
- Transfers and resale-lock on confirmed bookings.

## 5. Ship discipline

Every milestone lands only when `scripts/test.sh --full` stays green and the
red-team battery passes at zero findings; new surfaces earn their own battery
phase before they ship.
