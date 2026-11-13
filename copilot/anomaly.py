"""Kavach Copilot anomaly layer: local heuristics + Granite narration.

Not in the hot path. It observes only the tool calls the copilot itself makes,
scores each user's recent pattern with pure-local heuristics, and can ask
Granite to turn a user pattern or a metrics snapshot into plain-language
incident notes. It never blocks an engine call and never invents numbers:
every count here comes from recorded copilot activity or the engine's own
/metrics response.
"""
import json
import threading
import time
from collections import defaultdict, deque

WINDOW_S = 3600.0          # sliding window per user
SCORE_SUSPICIOUS = 4       # score >= this => suspicious
SCORE_ABUSIVE = 8          # score >= this => abusive
WRITE_TOOLS = ("book", "reserve", "waitlist")

_lock = threading.Lock()
_events = defaultdict(deque)   # user_id -> deque[(ts, tool, seats)]


def record(tool, args):
    """Record one copilot tool call so patterns are judged on real activity."""
    seats = None
    raw = (args or {}).get("seats")
    try:
        seats = int(raw) if raw is not None else None
    except (TypeError, ValueError):
        seats = None
    user = str((args or {}).get("user_id") or "guest")[:64]
    now = time.time()
    with _lock:
        d = _events[user]
        d.append((now, tool, seats))
        while d and now - d[0][0] > WINDOW_S:
            d.popleft()
        if not d:
            _events.pop(user, None)


def score(user_id):
    """Pure-local pattern score for one user. Returns a dict; never raises."""
    user = str(user_id or "guest")[:64]
    now = time.time()
    with _lock:
        evs = [e for e in _events.get(user, ()) if now - e[0] <= WINDOW_S]
    writes = [e for e in evs if e[1] in WRITE_TOOLS]
    releases = [e for e in evs if e[1] == "release"]
    confirms = [e for e in evs if e[1] == "confirm"]
    max_seat = [e for e in writes if e[2] is not None and e[2] >= 10]
    flags, s = [], 0
    if len(writes) >= 10:
        flags.append("high_write_rate(%d writes/1h)" % len(writes))
        s += 3
    if len(writes) >= 5 and now - writes[0][0] <= 60.0:
        flags.append("burst(5 writes in <=60s)")
        s += 3
    if len(max_seat) >= 5:
        flags.append("max_seat_storm(%d holds at max seats)" % len(max_seat))
        s += 2
    if len(releases) >= 3 and len(releases) >= len(confirms) + 2:
        flags.append("churn(%d releases vs %d confirms)" % (len(releases), len(confirms)))
        s += 2
    verdict = "abusive" if s >= SCORE_ABUSIVE else ("suspicious" if s >= SCORE_SUSPICIOUS else "normal")
    return {
        "user_id": user,
        "events_1h": len(evs),
        "writes_1h": len(writes),
        "score": s,
        "verdict": verdict,
        "flags": flags,
        "window_s": WINDOW_S,
    }


def summary_line(r):
    """One human-readable line from score(); numbers only from the score dict."""
    return "%s: %s, %d events/1h, %d writes, score %d, flags: %s" % (
        r["user_id"], r["verdict"], r["events_1h"], r["writes_1h"],
        r["score"], ", ".join(r["flags"]) or "none")


PATTERN_PROMPT = """You are the incident narrator for the Kavach inventory engine.
You get one user's activity pattern as JSON. Explain in 2 plain sentences whether
this looks like a normal customer, a scraper, or an abusive bot, and why. Use ONLY
the numbers in the JSON; invent nothing. No markdown."""

METRICS_PROMPT = """You are the incident narrator for the Kavach inventory engine.
You get a snapshot of the engine's own /metrics output. Summarize in at most 3
plain sentences whether anything looks abnormal right now (error rates, latency,
hold churn, waitlist spikes). Use ONLY numbers present in the snapshot; invent
nothing. No markdown."""


def narrate(messages, granite_fn, max_new_tokens=220):
    """Ask Granite for plain-language notes. Returns (text, err); never raises."""
    if granite_fn is None:
        return None, {"error": "granite_not_available"}
    return granite_fn(messages, max_new_tokens=max_new_tokens)


def pattern_messages(r):
    return [{"role": "system", "content": PATTERN_PROMPT},
            {"role": "user", "content": json.dumps(r)}]


def metrics_messages(metrics_text):
    return [{"role": "system", "content": METRICS_PROMPT},
            {"role": "user", "content": metrics_text[:4000]}]
