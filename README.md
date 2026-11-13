# llm-gateway

A reverse proxy that holds your inference API key so nothing else has to.

I wrote this because the same shape keeps showing up: a key pasted into a
frontend env var, no spend ceiling, and no record of who called what. You cannot
fix most of that from the app side. You can fix all of it from one hop in front.

Point it at an OpenAI-compatible endpoint, give each caller their own key, and
the real key stops moving.

```
client  --(gateway key)-->  llm-gateway  --(real key)-->  api.example.com
```

## what it does

- Keeps the upstream credential in one process. Clients never see it, and no
  header they send is forwarded.
- Per-key daily token budget and requests-per-minute limit, enforced before the
  request leaves the box.
- Per-key model allowlist on top of the global one, so the web app can reach the
  cheap model and nothing else.
- Clamps `max_tokens` / `max_completion_tokens` down to a ceiling you set.
- Caps request body size, so a stuck client cannot make you buffer a gigabyte.
- Scans the prompt with a small set of injection heuristics. Flags by default,
  blocks if you ask it to.
- Scrubs credential-shaped strings out of the response before it reaches the
  caller.
- Writes one JSON line per request: who, what model, how many tokens, how long,
  what the guard thought, how many redactions.

Zero dependencies. Standard library only, no `go.sum` to audit.

## what it does not do

- **It is not a prompt-injection defence.** The heuristic catches the version
  people copy out of a blog post. Anything rewritten by someone who knows what
  they are doing walks straight through. Its real value is that attempts land in
  the audit log, and after a month you know what is being tried.
- **Streamed responses are not scrubbed.** Buffering a stream to scan it means
  nobody gets tokens on time. If you need scanned streams, buffer and accept the
  latency — it is one branch in `internal/proxy/proxy.go`.
- **Token counts are exact only when the upstream reports them.** When it does
  not, they are `bytes/4`, which is close for prose and wrong for minified JSON.
- **State is in memory.** Restart the process and today's counters start at
  zero. One instance only. Two instances means two independent budgets, which is
  not a budget.
- **No PII redaction.** I left it out on purpose. Email and phone regexes mangle
  ordinary prose and people stop trusting the output. Credentials are worth the
  false positives; names are not.

## run it

```
cp config.example.json config.json
# edit upstream_key, then:

go build -trimpath -ldflags "-s -w" -o bin/llm-gateway ./cmd/gateway
./bin/llm-gateway -config config.json
```

`make build` is the same command. `make release` cross-compiles linux/amd64,
linux/arm64 and darwin/arm64.

Call it exactly like the API it fronts:

```
curl http://127.0.0.1:8080/v1/chat/completions \
  -H "Authorization: Bearer web-dev-0000000000000000" \
  -H "Content-Type: application/json" \
  -d '{"model":"gpt-4.1-mini","messages":[{"role":"user","content":"hi"}]}'
```

`upstream` is a base URL. The request path is appended, so `/v1/chat/completions`
arrives at the upstream unchanged.

## config

| field | meaning |
| :-- | :-- |
| `listen` | address to bind, default `127.0.0.1:8080` |
| `upstream` | base URL, must be `https` unless the host is loopback |
| `upstream_key` | the real credential |
| `upstream_key_file` | read the credential from a file instead, trimmed |
| `models` | global allowlist, empty means everything is denied |
| `max_body_bytes` | request size ceiling, default 32768 |
| `max_tokens` | ceiling applied to `max_tokens` in the body |
| `timeout_seconds` | per-request deadline toward the upstream |
| `injection_action` | `flag` or `block` |
| `audit_path` | JSONL path, `-` for stdout |
| `keys[]` | `name`, `secret`, `daily_tokens`, `requests_per_minute`, optional `models` |

Secrets must be at least 16 characters. Config refuses to load if two keys share
a secret, because that silently merges two budgets into one.

Prefer `upstream_key_file` in anything that is not your laptop. Environment
variables leak through `/proc`, crash dumps, and anything that prints its own
config.

## admin

`/__gw/health` and `/__gw/stats`, loopback only, no auth token. Anything that is
not from `127.0.0.1` or `::1` gets a 404. Key names and spend are not public.

`/__gw/stats` returns what each key has used today and how many requests it made
in the last minute. It is how I found out a cron job was retrying in a loop.

## the audit log

One line per request, JSON, append-only, mode `0600`:

```json
{"ts":"2026-11-13T09:24:28Z","id":"0b6893e94bc47716","key":"web","model":"gpt-4.1-mini","status":200,"stream":false,"prompt_tokens":11,"completion_tokens":7,"latency_ms":0,"injection_score":55,"injection_hits":["instruction_override","prompt_exfiltration"],"verdict":"injection_flagged","redactions":1,"ip":"127.0.0.1"}
```

`verdict` is the short version of why a request ended how it did:
`forwarded`, `injection_flagged`, `injection_blocked`, `rate_limited`,
`budget_exhausted`, `model_denied_for_key`, `unknown_key`, `upstream_error`.
`jq -r 'select(.verdict!="forwarded")|.verdict' audit.jsonl | sort | uniq -c`
is the first thing to run when something feels off.

## deploy notes

- Run it next to the app, not on the internet. If it has to be public, put it
  behind the same thing that fronts the app and keep `listen` off `0.0.0.0`.
- Give it its own unix user and its own file for the upstream key, `chmod 600`.
- `make build` uses `-trimpath -ldflags "-s -w"`: no build paths, no symbol
  table. That is not protection, it is hygiene. Anything shipped can be read by
  someone patient enough.
- Behind a load balancer, `RemoteAddr` is the balancer and the loopback check on
  the admin endpoints stops being meaningful. Trust `X-Forwarded-For` and you
  hand the check to whoever sets that header, so don't. Run the admin endpoints
  on a separate loopback listener if you need them in production.

## notes

- `go test ./...` covers the guard rules, the redactor, the header stripping, the
  clamp, the budget, and the loopback gate. It does not cover streaming.
- The guard patterns are in `internal/guard/guard.go` and are meant to be edited.
  Add what you actually see, delete what keeps firing on real traffic.
- MIT. Use it, fork it, no attribution required beyond keeping the licence.

— s9ss
