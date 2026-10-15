// Runs the JavaScript SDK against a live engine (auth mode).
import { Kavach, KavachError } from "./javascript/kavach.mjs";

const k = new Kavach("http://127.0.0.1:8080", { apiKey: "sdkkey", hmacSecret: "sdksecret" });
const results = [];
function check(name, cond, detail = "") {
  results.push(cond);
  console.log((cond ? "PASS  " : "FAIL  ") + name + (detail ? "  " + JSON.stringify(detail) : ""));
}

const b1 = await k.book("nodeuser", "node-book-1", 1);
check("js sdk book confirmed", b1.status === "confirmed", b1);
const b2 = await k.book("nodeuser", "node-book-1", 1);
check("js sdk idempotent retry same booking", b2.booking_id === b1.booking_id, b2);

const r = await k.reserve("nodeuser", "node-res-1", 2);
check("js sdk reserve held", r.status === "held", r);
const c = await k.confirm(r.reservation_id, "nodeuser");
check("js sdk confirm confirmed", c.status === "confirmed", c);
const c2 = await k.confirm(r.reservation_id, "nodeuser");
check("js sdk re-confirm same booking", c2.booking_id === c.booking_id, c2);

const w = await k.waitlistJoin("nodeuser", "node-wait-1", 1);
check("js sdk waitlist join", w.status === "queued", w);
await k.waitlistCancel(w.waitlist_id);
const lst = await k.waitlist("nodeuser");
check("js sdk waitlist cancel removes entry", lst.entries.length === 0, lst);

const s = await k.seats();
check("js sdk seats shape", ["total", "sold", "held", "free"].every((x) => x in s), s);
const m = await k.metrics();
check("js sdk metrics shape", "confirmed" in m && "holds_created" in m, m);

const pass = results.filter(Boolean).length;
console.log(`\n${pass}/${results.length} passed`);
process.exit(pass === results.length ? 0 : 1);
