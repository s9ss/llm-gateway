# threat model

What this proxy defends and what it does not.

## the actual problem

The realistic failure is not a clever attacker. It is a key sitting in a browser
bundle, no spend ceiling, and nobody able to say which service burned the budget
last Tuesday. Three things fix that:

1. The upstream credential exists in one process, on one host, in one file.
2. Every caller gets a key with its own ceiling and its own model list.
3. Every request leaves a line with a name on it.

That is the whole model. The rest of this file is detail.

## assets

| asset | where it lives | what losing it means |
| :-- | :-- | :-- |
| upstream credential | config or `upstream_key_file` | full access to the provider account, including spend |
| caller secrets | config | impersonation of one caller, not the provider |
| audit log | `audit_path` | no record of abuse, and it is the only record |
| token budget | memory | unbounded spend until the provider rate-limits you |

## what the design stops

**The client never holds the real key.** A key pulled out of a browser bundle is
a gateway key. It has a budget, a model list, and can be revoked by deleting four
lines of config.

**Header smuggling.** The upstream request is built from scratch. Only
`Content-Type`, `Accept` and the gateway's own `Authorization` are set, so a
client sending `X-Forwarded-Host`, `Host`, `Cookie` or its own `Authorization`
changes nothing.

**Proxy hijack through the environment.** The transport uses `Proxy: nil` instead
of `ProxyFromEnvironment`. If someone can set `HTTPS_PROXY` on the host, they
would otherwise receive every upstream request, key included.

**Spend blowups from a bug.** Budget is checked before the request leaves. A
retry loop hits the rate limit in about a second instead of running all night.

**Model escalation.** A cheap caller cannot reach an expensive model even if it
knows the name.

**Long completions as a data channel.** `max_tokens` is clamped downward, so a
caller asking for 900k gets your ceiling.

**Accidental credential leak in output.** If the model repeats a key it saw in
context, the response is scrubbed before the client sees it.

**Admin exposure.** `/__gw/*` answers only to loopback. A key name and a spend
figure are not public.

## what it does not stop

**A determined prompt injection.** Six regular expressions. Encoding,
translation, indirection or plain rewriting defeats them. If your design requires
that injection cannot succeed, this is not the control you need.

**A malicious caller with a valid key.** They can spend their budget and reach
their models. That is what a key is.

**Credential theft from the host.** If someone can read `config.json` or the key
file, they have the key. File permissions are the control, not this program.

**Denial of service.** No connection limits beyond what the Go HTTP server gives
you. `max_body_bytes` stops a large body, not ten thousand small ones.

**A hostile upstream.** It can return anything up to the 8 MiB read cap, or hold
the connection until the timeout. TLS verification is on and config cannot turn
it off, which is the part that matters.

**Multi-instance consistency.** Budgets live in memory. Two processes are two
budgets. Scaling out needs a shared counter, which does not exist yet.

## how I would break it

Three of these are deployment, permissions or config. Three need code.

1. Pull a valid key out of a client bundle and use it inside its own limits,
   looking for what the model will repeat back. Redaction catches credential
   shapes, not secrets phrased as prose. **Needs code.**
2. Read `config.json` if permissions are wrong. Shortest path, and why the file
   is `0600` and separate from the code. **Permissions.**
3. Fill the disk with audit lines. No rotation exists. **Config.**
4. Send a streamed request carrying an injection. Streams skip redaction, and the
   guard only reads the way in. **Needs code.**
5. Reach `/__gw/stats` through a load balancer and check whether `RemoteAddr` is
   still loopback when it arrives. **Deployment.**
6. Sit on a connection until the timeout, repeatedly, with a valid key. Nothing
   caps concurrency per key. **Needs code.**

Items 1, 4 and 6 are the real ones. All three are listed above rather than
quietly omitted.
