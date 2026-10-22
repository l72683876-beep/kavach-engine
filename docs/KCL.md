# KCL: the Kavach Config Language

One small file that describes a flash sale, instead of a wall of CLI flags.
A `.kcl` file is plain text, one statement per line, `#` starts a comment,
and values carry units: `5m` is five minutes, `50ms` is fifty milliseconds,
`20/s` is twenty per second.

```bash
go run ./engine -config examples/diwali-drop.kcl
```

## Design goals

- **Readable by a non-programmer.** If you can write a shopping list, you can
  write a `.kcl` file. No brackets, no nesting, no programming language.
- **Errors that help.** Every bad line is reported with its line number, all
  errors come back in one pass, and an unknown setting lists the settings that
  actually exist.
- **One source of truth.** Every statement maps 1:1 to an existing CLI flag.
  Nothing in a `.kcl` file changes engine behaviour beyond what the flags
  already do; the file is a better way to WRITE the same configuration.

## Example

```kcl
# diwali-drop.kcl
sale "Diwali drop 2026"

seats 5000
workers 16
listen :8080
hold-ttl 5m
waitlist-cap 100000

rate-limit user 2/s burst 5
rate-limit ip 20/s burst 40

api-keys key1:shopA,key2:shopB
hmac-secret change-me
```

A complete annotated example lives in [`examples/diwali-drop.kcl`](../examples/diwali-drop.kcl).

## Precedence

CLI flags beat the file. `-config` loads the file first, then any flag you
typed explicitly on the command line overrides the file's value for that
setting. Statements the file does not mention fall back to the flag defaults.

## Grammar

One statement per line: `name value ...`. A quoted value may contain spaces:
`sale "Diwali drop 2026"`. Each setting may appear once. Unknown settings,
wrong value types, bad units and duplicates are rejected with line numbers.

## Statements

| Statement | Maps to flag | Example | Notes |
|---|---|---|---|
| `sale` | (none, label only) | `sale "Diwali drop"` | Descriptive label, logged at boot |
| `seats` | `-seats` | `seats 5000` | Whole number, 1 or more |
| `listen` | `-addr` | `listen :8080` | Host:port |
| `workers` | `-workers` | `workers 16` | Whole number, 1 or more |
| `hold-ttl` | `-hold-ttl` | `hold-ttl 5m` | At least 1s; bare number = seconds |
| `waitlist-cap` | `-waitlist-cap` | `waitlist-cap 100000` | 0 or more |
| `bookings-log` | `-log` | `bookings-log bookings.jsonl` | Path |
| `holds-log` | `-holds-log` | `holds-log holds.jsonl` | Path |
| `waitlist-webhook` | `-webhook-url` | `waitlist-webhook https://...` | URL |
| `rate-limit user` | `-user-rate`, `-user-burst` | `rate-limit user 2/s burst 5` | Rate needs `/s`, `/m` or `/h`; `burst N` optional; `0/s` disables |
| `rate-limit ip` | `-ip-rate`, `-ip-burst` | `rate-limit ip 20/s burst 40` | Same rules |
| `api-keys` | `-api-keys` | `api-keys key1:shopA` | `key:tenant` pairs, comma-separated |
| `hmac-secret` | `-hmac-secret` | `hmac-secret change-me` | Enables request signing |
| `node` | `-node-id` | `node n1` | Cluster node identity |
| `peers` | `-peers` | `peers :8081,:8082` | Every node incl. this one |
| `postgres` | `-pg-dsn` | `postgres postgres://...` | Needs `-tags postgres` build |
| `chaos-stall` | `-chaos-stall-ms` | `chaos-stall 50ms` | 0 disables |
| `chaos-prob` | `-chaos-prob` | `chaos-prob 0.01` | 0 to <1 |

## What a mistake looks like

```
line 3: unknown setting "seat-count". Valid settings: sale, seats, listen, workers, hold-ttl, ...
line 7: rate-limit user rate "20" has no unit; write 20/s (per second), 20/m or 5/h
line 9: seats wants a whole number of 1 or more, got "abc"
```

All of these come back together, in one run, before the engine starts.

## The parser itself

`kcl/` is a small, dependency-free Go package (no YAML, no TOML, no regexp
table): a tokenizer, a statement table, unit parsers for durations and rates,
and validation. Tests: `go test ./kcl/`.

## Not in the language yet

A few newer engine flags have no statement yet: `-shards`, `-hmac-secrets`
(per-tenant secrets), `-replicate-key`, `-replicate-secret`,
`-replicate-from`, `-otel-endpoint`, `-otel-ratio`, `-snapshot-every`,
`-snapshot-interval`. Those still go on the command line; they will join
KCL as the engine's surface settles.
