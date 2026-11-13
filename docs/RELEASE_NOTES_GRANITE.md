# Granite release notes: the IBM watsonx layer (Nov 13, 2026)

What the IBM watsonx.ai work added to Kavach, in the order it shipped.

## 1. watsonx-auth-proxy (separate repo, live)

A tiny auth-exchange proxy: your IBM Cloud API key stays server-side, callers
send `X-IBM-Key`, the proxy exchanges it for a bearer token and forwards to
watsonx.ai. Deployed on Render with a keep-alive watchdog; no secrets in code.

## 2. Kavach Copilot (granite-4-h-small)

Natural-language layer on the engine, served on :5057:

- One request becomes at most one engine call, executed with the caller's own
  credentials. Not in the hot path.
- Tool allow-list only (9 tools: seats, book, reserve, confirm, release,
  reservation status, waitlist + status + cancel); seats clamped to a max.
- Every number in a reply comes from the engine's response, never the model.
- Inference confirmed end-to-end against watsonx.ai through the proxy.

## 3. Copilot fine-tuning dataset

370 train / 20 validation tool-decision examples (`copilot/tuning/`), built
from the engine's real tool surface so a Granite model can be tuned to make
better tool decisions. Tuning itself is paused: the trial WML plan does not
include the LoRA training runtime (`WXaaS-S-Lora` is absent from the account's
hardware specifications), so the run cannot resolve there.

## 4. Anomaly layer (this release)

- `copilot/anomaly.py`: per-user sliding-window heuristics (write rate, bursts,
  max-seat storms, hold/release churn) with a normal / suspicious / abusive
  verdict. Local-only, never blocks an engine call.
- `POST /anomaly` (optionally `narrate: true`) and `GET /anomaly/metrics`:
  Granite turns a user's pattern or the engine's own /metrics snapshot into
  plain-language incident notes, using only the numbers in the input.
- Covered by the offline smoke test (7 tests, no network, no key needed).

## What stayed fixed

The hot path is unchanged and dependency-free. Everything IBM sits behind an
optional service; without `IBM_API_KEY` and `WATSONX_PROJECT_ID` set, Kavach
runs exactly as it did before.
