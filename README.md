# llm-gateway

A reverse proxy that holds your inference API key so nothing else has to.

I wrote this because the same shape keeps showing up: a key pasted into a
frontend env var, no spend ceiling, no record of who called what. You cannot fix
most of that from the app side. You can fix all of it from one hop in front.

```
client --(gateway key)--> llm-gateway --(real key)--> api.example.com
```

Point it at an OpenAI-compatible endpoint, give each caller their own key, and
the real key stops moving.

## what it does

- Keeps the upstream credential in one process. Clients never see it, and no
  header they send is forwarded.
- Per-key daily token budget and requests-per-minute limit, checked before the
  request leaves the box.
- Per-key model allowlist on top of the global one, so the web app can reach the
  cheap model and nothing else.
- Clamps `max_tokens` and `max_completion_tokens` down to a ceiling you set.
- Caps request body size so a stuck client cannot make you buffer a gigabyte.
- Scans the prompt with a small set of injection heuristics. Flags by default,
  blocks if you ask it to.
- Scrubs credential-shaped strings out of the response before the caller sees it.
- Writes one JSON line per request: who, what model, how many tokens, how long,
  what the guard thought, how many redactions.

Standard library only. There is no `go.sum`, so there is nothing to audit but the
files in this repo.

## what it does not do

- **It is not a prompt-injection defence.** The heuristic catches the version
  people copy out of a blog post. Anything rewritten by someone who knows what
  they are doing walks through. Its real value is that attempts land in the audit
  log, so after a month you know what is being tried.
- **Streamed responses are not scrubbed.** Buffering a stream to scan it means
  nobody gets tokens on time. If you need scanned streams, buffer and accept the
  latency, it is one branch in `internal/proxy/proxy.go`.
- **Token counts are exact only when the upstream reports them.** When it does
  not, they are `bytes/4`, close for prose and wrong for minified JSON.
- **State is in memory.** Restart and today's counters start at zero. One
  instance only. Two instances means two separate budgets, which is not a budget.
- **The admin endpoints assume a direct connection.** Behind a load balancer
  `RemoteAddr` is the balancer, so the loopback check stops meaning anything.
- **No PII redaction.** Left out on purpose. Email and phone regexes mangle
  ordinary prose and people stop trusting the output. Credentials are worth the
  false positives. Names are not.

## run it

```
cp config.example.json config.json
# edit upstream_key, then:

go build -trimpath -ldflags "-s -w" -o bin/llm-gateway ./cmd/gateway
./bin/llm-gateway -config config.json
```

`make build` is the same command. `make release` cross-compiles linux/amd64,
linux/arm64 and darwin/arm64.

Call it like the API it fronts:

```
curl http://127.0.0.1:8080/v1/chat/completions \
  -H "Authorization: Bearer web-dev-0000000000000000" \
  -H "Content-Type: application/json" \
  -d '{"model":"gpt-4.1-mini","messages":[{"role":"user","content":"hi"}]}'
```

`upstream` is a base URL and the request path is appended, so
`/v1/chat/completions` arrives unchanged.

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
one, because that silently merges two budgets.

Prefer `upstream_key_file` anywhere that is not your laptop. Environment
variables leak through `/proc`, crash dumps, and anything that prints its own
config.

## admin and the audit log

`/__gw/health` and `/__gw/stats` answer loopback only, no auth token, 404 from
anywhere else. `stats` shows what each key used today and how many requests it
made in the last minute. It is how I found out a cron job was retrying in a loop.

The audit log is one JSON line per request, append-only, mode `0600`. This is a
real line, not an example:

```json
{"ts":"2026-11-13T09:24:28.5849885Z","id":"0b6893e94bc47716","key":"web","model":"gpt-4.1-mini","status":200,"stream":false,"prompt_tokens":11,"completion_tokens":7,"latency_ms":0,"injection_score":55,"injection_hits":["instruction_override","prompt_exfiltration"],"verdict":"injection_flagged","redactions":1,"ip":"127.0.0.1"}
```

`verdict` is the short reason a request ended the way it did: `forwarded`,
`injection_flagged`, `injection_blocked`, `rate_limited`, `budget_exhausted`,
`model_denied_for_key`, `unknown_key`, `upstream_error`. To see only the ones
that were not clean:

```
jq -r 'select(.verdict!="forwarded")|.verdict' audit.jsonl | sort | uniq -c
```

## notes

- Run it next to the app, under its own user, with the upstream key in its own
  file at `chmod 600`.
- `-trimpath -ldflags "-s -w"` keeps build paths and the symbol table out of the
  binary. Hygiene, not protection. Anything shipped can be read by someone
  patient enough.
- `go test ./...` covers the guard rules, the redactor, header stripping, the
  clamp, the budget and the loopback gate. It does not cover streaming.
- The guard patterns are in `internal/guard/guard.go` and are meant to be edited.
  Add what you actually see, delete what keeps firing on real traffic.
- MIT. Keep the licence file and you are fine.

s9ss
