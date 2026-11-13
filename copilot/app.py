"""Kavach Copilot: a Granite-powered natural-language layer on top of the Kavach engine.

The copilot never touches the engine's hot path. It translates one natural-language
request into at most one engine call per turn, executes it with the caller's own
credentials, and returns the engine's real answer. It cannot invent inventory: every
number in a reply comes from the engine's response, never from the model.
"""
import json
import os
import uuid
import urllib.error
import urllib.request

from flask import Flask, jsonify, request

import anomaly

ENGINE_URL = os.environ.get("KAVACH_URL", "http://localhost:8080")
KAVACH_API_KEY = os.environ.get("KAVACH_API_KEY", "")
WATSONX_PROXY_URL = os.environ.get("WATSONX_PROXY_URL", "https://watsonx-auth-proxy.onrender.com")
IBM_API_KEY = os.environ.get("IBM_API_KEY", "")
WATSONX_PROJECT_ID = os.environ.get("WATSONX_PROJECT_ID", "")
MODEL_ID = os.environ.get("KAVACH_COPILOT_MODEL", "ibm/granite-4-h-small")
MAX_SEATS = int(os.environ.get("KAVACH_COPILOT_MAX_SEATS", "10"))

app = Flask(__name__)

SYSTEM_PROMPT = """You are Kavach Copilot, the natural-language layer for the Kavach inventory engine.
Reply with STRICT JSON only, no prose, no markdown fences.

Format (exactly one of):
{"tool": "<name>", "args": {...}}      -> execute one engine call
{"tool": "none", "answer": "<short answer>"}  -> when no engine call is needed

Tools:
- seats                          : how much inventory is free right now. args: {}
- book        {user_id, seats}   : direct instant booking.
- reserve     {user_id, seats}   : hold seats with a TTL (a cart, not a sale).
- confirm     {reservation_id, user_id} : turn an existing hold into a booking.
- release     {reservation_id}   : give held seats back.
- reservation_status {reservation_id} : what happened to this reservation.
- waitlist    {user_id, seats}   : join the FIFO line when sold out.
- waitlist_status {user_id}      : this user's place in the line.
- waitlist_cancel {waitlist_id}  : leave the line.

Rules:
- seats is an integer, 1..MAX_SEATS (MAX_SEATS=%(max_seats)d). Clamp silently.
- user_id defaults to "guest" when the user did not name one.
- Never call confirm or release without a reservation_id from this conversation.
- Never promise availability or prices; the engine decides.
- For questions about what Kavach is or what you can do, use tool "none" with a brief answer.""" % {"max_seats": MAX_SEATS}


def _http(method, url, headers=None, body=None, timeout=60):
    """One JSON request. Returns (status, parsed_body_or_{}). Never raises."""
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode() or "{}"
            return resp.status, json.loads(raw)
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read().decode() or "{}")
        except Exception:
            return e.code, {}
    except Exception as e:  # timeouts, refused connections
        return 0, {"error": "transport", "message": str(e)[:200]}


def engine_call(method, path, body=None):
    """Call the engine, return its parsed response body as a dict."""
    headers = {"Accept": "application/json"}
    if KAVACH_API_KEY:
        headers["Authorization"] = "Bearer " + KAVACH_API_KEY
    _status, parsed = _http(method, ENGINE_URL.rstrip("/") + path, headers, body)
    return parsed


def granite(messages, max_new_tokens=300):
    body = {
        "model_id": MODEL_ID,
        "project_id": WATSONX_PROJECT_ID,
        "messages": messages,
        "params": {"max_new_tokens": max_new_tokens, "temperature": 0.2, "top_p": 0.9},
    }
    status, data = _http(
        "POST", WATSONX_PROXY_URL.rstrip("/") + "/ml/v1/text/chat",
        {"X-IBM-Key": IBM_API_KEY, "Accept": "application/json"}, body,
    )
    if status != 200:
        return None, {"status": status, "error": data}
    try:
        return data["choices"][0]["message"]["content"], None
    except (KeyError, IndexError, TypeError):
        return None, {"status": 200, "error": "unexpected_response", "body": data}


def parse_decision(text):
    t = (text or "").strip()
    if t.startswith("```"):
        t = t.strip("`")
        if t.startswith("json"):
            t = t[4:]
    start, end = t.find("{"), t.rfind("}")
    if start == -1 or end <= start:
        return None
    try:
        d = json.loads(t[start:end + 1])
    except ValueError:
        return None
    return d if isinstance(d, dict) else None


def run_tool(name, args):
    """The only door to the engine. Allow-list, clamp, then execute."""
    if name not in TOOLS:
        return {"error": "unknown_tool", "tool": str(name)[:64]}
    if name in ("book", "reserve", "waitlist"):
        args = dict(args or {})
        try:
            seats = int(args.get("seats", 1))
        except (TypeError, ValueError):
            seats = 1
        args["seats"] = max(1, min(seats, MAX_SEATS))
        args["user_id"] = str(args.get("user_id") or "guest")[:64]
        args.setdefault("idempotency_key", "copilot-" + uuid.uuid4().hex)
    return TOOLS[name](args or {})


TOOLS = {
    "seats": lambda a: engine_call("GET", "/seats"),
    "book": lambda a: engine_call("POST", "/book", a),
    "reserve": lambda a: engine_call("POST", "/reserve", a),
    "confirm": lambda a: engine_call("POST", "/confirm",
                                     {"reservation_id": a.get("reservation_id"),
                                      "user_id": a.get("user_id") or "guest"}),
    "release": lambda a: engine_call("POST", "/release",
                                     {"reservation_id": a.get("reservation_id")}),
    "reservation_status": lambda a: engine_call(
        "GET", "/reservation?id=" + str(a.get("reservation_id") or "")),
    "waitlist": lambda a: engine_call("POST", "/waitlist", a),
    "waitlist_status": lambda a: engine_call(
        "GET", "/waitlist?user_id=" + str(a.get("user_id") or "guest")),
    "waitlist_cancel": lambda a: engine_call("POST", "/waitlist/cancel",
                                             {"waitlist_id": a.get("waitlist_id")}),
}

LABEL = {
    "seats": "Live inventory",
    "book": "Booked",
    "reserve": "Held",
    "confirm": "Confirmed",
    "release": "Released",
    "reservation_status": "Reservation status",
    "waitlist": "Queued",
    "waitlist_status": "Queue status",
    "waitlist_cancel": "Cancelled",
}


def phrase(tool, result):
    if isinstance(result, dict) and result.get("error"):
        return "That call failed. Engine said: " + json.dumps(result)
    if tool == "seats" and isinstance(result, dict):
        return "Live inventory: %s free, %s held, %s sold, of %s total." % (
            result.get("free", "?"), result.get("held", "?"),
            result.get("sold", "?"), result.get("total", "?"))
    ids = ["%s=%s" % (k, result[k]) for k in
           ("booking_id", "reservation_id", "waitlist_id") if isinstance(result, dict) and k in result]
    line = LABEL.get(tool, "Done") + (": " + ", ".join(ids) if ids else "") + "."
    return line + " Engine says: " + json.dumps(result)


@app.get("/health")
def health():
    return jsonify({"status": "ok", "model": MODEL_ID})


@app.get("/")
def index():
    return """<!doctype html><title>Kavach Copilot</title>
<body style="font-family:sans-serif;max-width:560px;margin:4rem auto">
<h1>Kavach Copilot</h1>
<p>Natural language in, real engine calls out. Powered by IBM Granite.</p>
<input id=q style="width:80%" placeholder="book 2 seats for priya">
<button onclick="go()">Ask</button><pre id=o></pre>
<script>
async function go(){const r=await fetch('/ask',{method:'POST',
headers:{'Content-Type':'application/json'},
body:JSON.stringify({question:document.getElementById('q').value})});
document.getElementById('o').textContent=JSON.stringify(await r.json(),null,2);}
</script></body>"""


@app.post("/ask")
def ask():
    payload = request.get_json(silent=True) or {}
    q = str(payload.get("question", "")).strip()
    if not q:
        return jsonify({"error": "missing_question"}), 400
    if not IBM_API_KEY or not WATSONX_PROJECT_ID:
        return jsonify({"error": "copilot_not_configured",
                        "hint": "set IBM_API_KEY and WATSONX_PROJECT_ID"}), 503
    messages = [{"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": q[:2000]}]
    text, err = granite(messages)
    if err is not None:
        return jsonify({"error": "model_call_failed", "detail": err}), 502
    decision = parse_decision(text)
    if decision is None:
        messages.append({"role": "user",
                         "content": "Reply with ONLY the JSON decision object. No other text."})
        text, err = granite(messages, max_new_tokens=200)
        if err is not None:
            return jsonify({"error": "model_call_failed", "detail": err}), 502
        decision = parse_decision(text)
    if decision is None:
        return jsonify({"error": "unparseable_model_output", "raw": text[:400]}), 502
    if decision.get("tool") == "none":
        return jsonify({"question": q, "tool": "none",
                        "answer": str(decision.get("answer", ""))[:500]})
    result = run_tool(decision.get("tool"), decision.get("args") or {})
    anomaly.record(decision.get("tool"), decision.get("args") or {})
    return jsonify({"question": q, "tool": decision.get("tool"),
                    "engine": result, "answer": phrase(decision.get("tool"), result)})


@app.post("/anomaly")
def anomaly_check():
    """Pattern score for one user, from the copilot's own recorded tool calls.
    Pure-local heuristics; narration needs an explicit narrate flag."""
    payload = request.get_json(silent=True) or {}
    r = anomaly.score(payload.get("user_id"))
    out = dict(r)
    if IBM_API_KEY and WATSONX_PROJECT_ID and payload.get("narrate"):
        text, err = anomaly.narrate(anomaly.pattern_messages(r), granite)
        out["narration"] = text
        if err is not None:
            out["narration_error"] = err
    return jsonify(out)


@app.get("/anomaly/metrics")
def anomaly_metrics():
    """The engine's own /metrics, optionally narrated by Granite into plain
    incident notes. Numbers come only from the engine's snapshot."""
    headers = {"Accept": "application/json"}
    if KAVACH_API_KEY:
        headers["Authorization"] = "Bearer " + KAVACH_API_KEY
    _status, metrics = _http("GET", ENGINE_URL.rstrip("/") + "/metrics", headers)
    out = {"engine_metrics_status": _status}
    if isinstance(metrics, dict):
        out["metrics"] = metrics
        if IBM_API_KEY and WATSONX_PROJECT_ID:
            text, err = anomaly.narrate(
                anomaly.metrics_messages(json.dumps(metrics)), granite)
            out["narration"] = text
            if err is not None:
                out["narration_error"] = err
    return jsonify(out)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5057)))
