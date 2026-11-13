# threat model

What this proxy is actually defending, and what it is not.

## what it is for

The realistic failure is not a clever attacker. It is a key in a browser bundle,
no spend ceiling, and nobody able to say which service burned the budget last
Tuesday. The gateway exists to make those three things impossible:

1. The upstream credential exists in one process, on one host, in one file.
2. Every caller gets a key with its own ceiling and its own model list.
3. Every request leaves a line with a name on it.

That is the whole threat model. Everything below is detail.

## assets

| asset | where it lives | what losing it means |
| :-- | :-- | :-- |
| upstream credential | config or `upstream_key_file` | full access to the provider account, including spend |
| caller secrets | config | impersonation of one caller, not the provider |
| audit log | `audit_path` | no record of abuse, and it is the only record |
| token budget | memory | unbounded spend until the provider rate-limits you |

## what the design stops

**Credential exposure on the client side.** The client never has the real key.
A key extracted from a browser bundle is a gateway key, which has a budget and a
model list and can be revoked by deleting four lines of config.

**Header smuggling.** The upstream request is built from scratch. Only
`Content-Type`, `Accept`, and the gateway's own `Authorization` are set. A client
sending `X-Forwarded-Host`, `Host`, `Cookie`, or its own `Authorization` changes
nothing.

**Proxy hijack through the environment.** The transport has `Proxy: nil` rather
than `ProxyFromEnvironment`. If someone can set `HTTPS_PROXY` on the host, they
would otherwise receive every upstream request, including the key.

**Spend blowups from a bug.** Budget is checked before the request leaves. A
retry loop in a client hits the rate limit in about a second instead of running
all night.

**Model escalation.** A cheap caller cannot reach an expensive model, even if it
knows the name.

**Long completions used as a data channel.** `max_tokens` is clamped downward. A
caller asking for 900k gets your ceiling.

**Accidental credential leak in output.** If the model repeats a key it saw in
context, the response is scrubbed before the client sees it.

**Admin exposure.** `/__gw/*` answers only to loopback. A key name and a spend
figure are not public information.

## what it does not stop

**A determined prompt injection.** The heuristic is six regular expressions.
Encoding, translation, indirection, or plain rewriting defeats it. It exists to
produce audit lines, not to be a boundary. If your design requires that an
injection cannot succeed, this is not the control you need.

**A malicious caller with a valid key.** They can spend their budget and reach
their models. That is what a key is.

**Credential theft from the host.** If someone can read `config.json` or the key
file, they have the key. File permissions and a dedicated user are the control,
not this program.

**Denial of service.** No connection limits beyond what the Go HTTP server gives
you. `max_body_bytes` stops a large body, not ten thousand small ones.

**A hostile upstream.** A compromised or malicious endpoint can return anything,
including oversized responses up to the 8 MiB read cap, or hold the connection
until the timeout. TLS verification is on and cannot be turned off through
config, which is the part that matters.

**Multi-instance consistency.** Budgets live in memory. Two processes are two
budgets. Scaling out needs a shared counter, which does not exist here yet.

## if I were attacking this

1. Take a valid key from a client bundle, then use it inside its own limits and
   look for what the model will repeat back. Redaction catches credential shapes,
   not secrets phrased as prose.
2. Read `config.json` if permissions are wrong. This is the shortest path and it
   is why the file is `0600` and separate from the code.
3. Fill the disk with audit lines. There is no rotation.
4. Send a streamed request with a prompt injection, since streams skip redaction
   and skip the guard on the way back.
5. Look at `/__gw/stats` from a request that arrives through the load balancer,
   and check whether `RemoteAddr` is still loopback when it gets there.

Items 1 and 4 are the two that need design changes, not config changes. Both are
listed above rather than hidden.
