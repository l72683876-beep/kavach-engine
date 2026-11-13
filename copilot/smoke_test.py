"""Smoke test for copilot plumbing: stub engine + scripted decisions, no network."""
import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

import app as copilot


class StubEngine(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, obj):
        body = json.dumps(obj).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path.startswith("/seats"):
            self._send({"total": 100, "sold": 40, "held": 5, "free": 55})
        elif self.path.startswith("/reservation"):
            self._send({"reservation_id": "RSV00000001", "status": "held"})
        elif self.path.startswith("/waitlist"):
            self._send({"user_id": "guest", "position": 1})
        else:
            self._send({"error": "not_found"})

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        req = json.loads(self.rfile.read(n) or b"{}")
        seats = req.get("seats", 1)
        self._send({"status": "held", "reservation_id": "RSV00000001",
                    "seats": list(range(1, seats + 1))})


class Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.srv = HTTPServer(("127.0.0.1", 0), StubEngine)
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        copilot.ENGINE_URL = "http://127.0.0.1:%d" % cls.srv.server_address[1]

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def test_reserve_executes_and_clamps(self):
        out = copilot.run_tool("reserve", {"user_id": "priya", "seats": 2})
        self.assertEqual(out["status"], "held")
        self.assertEqual(out["seats"], [1, 2])
        out = copilot.run_tool("reserve", {"user_id": "priya", "seats": 999})
        self.assertEqual(out["seats"], list(range(1, copilot.MAX_SEATS + 1)))

    def test_seats_read(self):
        out = copilot.run_tool("seats", {})
        self.assertEqual(out["free"], 55)

    def test_unknown_tool_rejected(self):
        out = copilot.run_tool("drop_tables", {})
        self.assertEqual(out["error"], "unknown_tool")

    def test_parse_decision(self):
        d = copilot.parse_decision('```json\n{"tool":"reserve","args":{"seats":2}}\n```')
        self.assertEqual(d["tool"], "reserve")
        self.assertIsNone(copilot.parse_decision("no json here"))

    def test_anomaly_normal_then_burst(self):
        import anomaly
        anomaly._events.clear()
        for _ in range(2):
            anomaly.record("reserve", {"user_id": "sha", "seats": 2})
        r = anomaly.score("sha")
        self.assertEqual(r["verdict"], "normal")
        self.assertEqual(r["writes_1h"], 2)
        anomaly._events.clear()
        for _ in range(6):
            anomaly.record("reserve", {"user_id": "bot", "seats": 10})
        r = anomaly.score("bot")
        self.assertIn("burst", " ".join(r["flags"]))
        self.assertIn("max_seat_storm", " ".join(r["flags"]))
        self.assertIn(r["verdict"], ("suspicious", "abusive"))

    def test_anomaly_churn_flag(self):
        import anomaly
        anomaly._events.clear()
        for _ in range(3):
            anomaly.record("release", {"user_id": "churner"})
            anomaly.record("reserve", {"user_id": "churner", "seats": 1})
        anomaly.record("confirm", {"user_id": "churner", "reservation_id": "RSV1"})
        r = anomaly.score("churner")
        self.assertIn("churn", " ".join(r["flags"]))

    def test_anomaly_line_only_real_numbers(self):
        import anomaly
        r = {"user_id": "u", "verdict": "normal", "events_1h": 3,
             "writes_1h": 2, "score": 0, "flags": []}
        line = anomaly.summary_line(r)
        self.assertIn("normal", line)
        self.assertIn("flags: none", line)


if __name__ == "__main__":
    unittest.main()
