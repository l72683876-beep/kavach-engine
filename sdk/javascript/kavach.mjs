/**
 * Kavach JavaScript SDK: the two-line integration for the Kavach booking engine.
 * Node 18+ (global fetch) and every modern browser.
 *
 * Quickstart (local engine, no auth):
 *
 *   import { Kavach } from "./kavach.mjs";
 *   const k = new Kavach("http://localhost:8080");
 *   console.log(await k.book("priya", "priya-booking-1", 1));
 *
 * Production engine (API key + HMAC signing):
 *
 *   const k = new Kavach("https://your-kavach-host",
 *     { apiKey: "sk_live_abc", hmacSecret: process.env.KAVACH_HMAC_SECRET });
 */
import { createHmac, randomUUID } from "node:crypto";

export class KavachError extends Error {
  constructor(status, body) {
    super(`Kavach returned ${status}: ${JSON.stringify(body)}`);
    this.status = status;
    this.body = body;
  }
}

export class Kavach {
  constructor(baseUrl = "http://127.0.0.1:8080", { apiKey = null, hmacSecret = null, timeoutMs = 30000 } = {}) {
    this.baseUrl = baseUrl.replace(/\/+$/, "");
    this.apiKey = apiKey;
    this.hmacSecret = hmacSecret;
    this.timeoutMs = timeoutMs;
  }

  headers(body) {
    const h = { "Content-Type": "application/json" };
    if (this.apiKey) {
      h["Authorization"] = "Bearer " + this.apiKey;
      if (this.hmacSecret) {
        const ts = String(Math.floor(Date.now() / 1000));
        const rid = randomUUID().replace(/-/g, "");
        const mac = createHmac("sha256", this.hmacSecret)
          .update(`${ts}\n${rid}\n`)
          .update(body)
          .digest("hex");
        h["X-Kavach-Timestamp"] = ts;
        h["X-Kavach-Request-Id"] = rid;
        h["X-Kavach-Signature"] = mac;
      }
    }
    return h;
  }

  async request(method, path, payload = undefined) {
    const body = payload === undefined ? null : JSON.stringify(payload);
    const res = await fetch(this.baseUrl + path, {
      method,
      headers: this.headers(body || new TextEncoder().encode("")),
      body,
      signal: AbortSignal.timeout(this.timeoutMs),
    });
    const text = await res.text();
    const data = text ? JSON.parse(text) : {};
    if (!res.ok) throw new KavachError(res.status, data);
    return data;
  }

  // ---- the cart flow ----

  book(userId, idempotencyKey, seats = 1) {
    return this.request("POST", "/book", { user_id: userId, idempotency_key: idempotencyKey, seats });
  }

  reserve(userId, idempotencyKey, seats = 1) {
    return this.request("POST", "/reserve", { user_id: userId, idempotency_key: idempotencyKey, seats });
  }

  confirm(reservationId, userId) {
    const payload = { reservation_id: reservationId };
    if (userId !== undefined) payload.user_id = userId;
    return this.request("POST", "/confirm", payload);
  }

  release(reservationId) {
    return this.request("POST", "/release", { reservation_id: reservationId });
  }

  reservation(reservationId) {
    return this.request("GET", "/reservation?id=" + reservationId);
  }

  // ---- waitlist ----

  waitlistJoin(userId, idempotencyKey, seats = 1) {
    return this.request("POST", "/waitlist", { user_id: userId, idempotency_key: idempotencyKey, seats });
  }

  waitlist(userId) {
    return this.request("GET", "/waitlist?user_id=" + userId);
  }

  waitlistCancel(waitlistId) {
    return this.request("POST", "/waitlist/cancel", { waitlist_id: waitlistId });
  }

  // ---- observability ----

  seats() {
    return this.request("GET", "/seats");
  }

  metrics() {
    return this.request("GET", "/metrics");
  }
}
