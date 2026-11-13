# Kavach Copilot: Granite LoRA tuning dataset

Fine-tuning dataset for the Kavach Copilot tool-decision layer, built for
watsonx.ai Tuning Studio (base model `ibm/granite-3-1-8b-base`, LoRA).

## Files
- `train.jsonl` - 370 examples
- `validation.jsonl` - 20 examples

## Format
One JSON object per line: `{"input": "<user utterance>", "output": "<strict JSON decision>"}`.

The output is the Copilot's tool-decision schema:
- `{"tool":"<tool>","args":{...}}` for a concrete call
- `{"tool":null,"clarify":"..."}` when the ask is ambiguous or outside scope

Covered tools (matching copilot/app.py): seats, book, reserve, confirm,
release, reservation_status, waitlist, waitlist_status, waitlist_cancel.

Mixed Hindi/English (Hinglish) utterances are included deliberately, since
real users type both. Use the verbalizer
`### Input: {{input}} \n\n### Response: {{output}}` in the tuning job.

## Tuning plan (watsonx)
- base model: ibm/granite-3-1-8b-base
- method: LoRA (rank 8-32 is plenty for this narrow task)
- epochs: 3-5, max_seq_length 512, small batch
- cost at IBM list price: USD 6.30/GPU-hour on 1x A100 (WXaaS-S-Lora);
  a 15-30 minute pilot run is roughly USD 1.5-3.2
