# Kavach Copilot

Natural-language layer on the Kavach engine, powered by IBM Granite. The copilot is
NOT in the hot path: it translates one user request into at most one engine call,
executes it with the caller's credentials, and returns the engine's real response.
It cannot invent inventory: every number in a reply comes from the engine.

## Run

```bash
pip install -r requirements.txt
export KAVACH_URL=http://localhost:8080        # your engine
export IBM_API_KEY=...                          # IBM Cloud API key, server-side only
export WATSONX_PROJECT_ID=...                   # your watsonx project id
export WATSONX_PROXY_URL=https://watsonx-auth-proxy.onrender.com  # or your own gateway
python3 app.py                                  # serves :5057
```

## API

```
POST /ask   {"question": "book 2 seats for priya"}
            -> {"tool": "reserve", "engine": {...engine response...}, "answer": "..."}
GET  /health
GET  /       tiny demo page
```

## Safety

- Tool allow-list only; seats clamped to `KAVACH_COPILOT_MAX_SEATS` (default 10).
- Every number in a reply comes from the engine's response, never the model.
- The IBM key never leaves the server's environment.
- Payment, pricing and user verification stay in YOUR application, as with Kavach itself.

## Test

`python3 smoke_test.py` exercises the plumbing against a stub engine with scripted
model decisions: no network, no key needed.
