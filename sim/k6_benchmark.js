// Kavach official k6 benchmark: a full cart flow at high concurrency.
// Every iteration reserves a seat and confirms it, like a real checkout.
// Run: k6 run sim/k6_benchmark.js (engine on 127.0.0.1:8080,
// limiters off, e.g. ./kavach -seats 5000 -workers 8 -ip-rate 0 -user-rate 0)
import http from 'k6/http';
import { check } from 'k6';

export const options = {
  scenarios: {
    booking_flow: {
      executor: 'ramping-vus',
      startVUs: 0,
      stages: [
        { duration: '10s', target: 200 }, // ramp to 200 users
        { duration: '30s', target: 200 }, // sustained load
      ],
    },
  },
};

export default function () {
  const user = `u${__VU}`;
  const idem = `k6-${__VU}-${__ITER}-${Math.random()}`;
  const res = http.post('http://127.0.0.1:8080/reserve',
    JSON.stringify({ user_id: user, idempotency_key: idem, seats: 1 }),
    { headers: { 'Content-Type': 'application/json' } });
  check(res, { 'reserve 200': (r) => r.status === 200 });
  const body = res.json();
  if (body.status === 'held') {
    const conf = http.post('http://127.0.0.1:8080/confirm',
      JSON.stringify({ reservation_id: body.reservation_id, user_id: user }),
      { headers: { 'Content-Type': 'application/json' } });
    check(conf, { 'confirm 200': (r) => r.status === 200 });
  }
}
