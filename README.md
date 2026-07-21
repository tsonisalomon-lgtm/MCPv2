# MCPv2 — P2P AI Agent Protocol (hardened)

MCPv2 is a peer-to-peer protocol for AI agents to call tools on each other over
HTTP, with cross-provider tool/response translation (Claude, OpenAI, Gemini,
DeepSeek), file transfer, batching, rate limiting, and audit logging.

Every peer is simultaneously a client and a server: it runs a FastAPI service
and can also send batches of JSON-RPC-style "slots" to other peers.

This version has been through a correctness/security pass with a real test
suite (`test_scenarios.py`) that runs two independent peer processes and
drives dozens of scenarios against them, repeatedly. See **What was fixed**
below for exactly what changed and why, and **Security model** for what this
protocol is (and is not) safe to use for.

## Quick start

```bash
pip install -r requirements.txt

# Start a peer. By default it binds DIRECTLY to its public IP (never
# 0.0.0.0) - see "Binding: public IP by default" below for what that
# means and when it won't work.
python mcpv2.py --port 8000 --secret mySharedSecret --public-ip 203.0.113.10

# On startup it prints:
#   MCPV2_PEER_ADDRESS=mcpv2://203.0.113.10:8000/mcpv2
#   MCPV2_DEMO_SESSION_ADDRESS=mcpv2://203.0.113.10:8000/mcpv2?sessionId=...
# Share the first one; see below for what the second one is actually for.

# In another terminal, an interactive client
python mcpv2_cli.py
mcpv2> ReadyTo --port 8000 --secret mySharedSecret     # start + print address
mcpv2> ConnectTo mcpv2://203.0.113.10:8000/mcpv2        # real auth round trip
```

## Binding: public IP by default, never 0.0.0.0

`mcpv2.py` binds its socket directly to `--public-ip` (or the auto-detected
public IP if you don't pass one) by default. It does **not** fall back to
`0.0.0.0` silently.

This only works if that IP address is actually assigned to a local network
interface on the machine you're running on — true for a cloud VM with a
directly-attached public IP, **not** true if you're behind NAT, a home
router, or most cloud load balancers (in those setups the "public IP" is
translated at the network edge and isn't present on any local interface, so
binding to it will fail — this is a networking fact, not a bug in MCPv2).

If binding fails, `mcpv2.py` fails fast with an explicit error telling you
why and how to fix it: either run on a host where the public IP really is
a local interface, or pass `--bind-host 0.0.0.0` explicitly to bind all
local interfaces while still *advertising* the public IP via `--public-ip`
for others to connect to.

Manually use below if you have NAT in your cloud and make sure the port is opened to external:

python mcpv2.py --bind-host 0.0.0.0 --port 8000 --secret <mySharedSecret> --public-ip <public ip>

### The two addresses printed at startup

```
MCPV2_PEER_ADDRESS=mcpv2://<public_ip>:<port>/mcpv2
MCPV2_DEMO_SESSION_ADDRESS=mcpv2://<public_ip>:<port>/mcpv2?sessionId=<token>
```

- **`MCPV2_PEER_ADDRESS`** is the one to actually share. A real remote peer
  fetches its *own* sessionId (`GET /mcpv2/session`) and appends it — session
  tokens are bound to the caller's own IP as *this* peer observes it, which
  is generally not this peer's own public IP.
- **`MCPV2_DEMO_SESSION_ADDRESS`** has a token pre-attached that is only
  valid for a caller whose observed source IP equals this peer's own public
  IP — true for same-host testing, not for a genuinely different remote
  peer. It's printed as a convenience for local development, clearly
  labeled as such, not as a universal token.

Run the tests:

```bash
# Fast smoke test (one upload + process, two peers)
python test_file_transfer.py

# Full scenario suite: two peers, ~19 scenario categories, run 3x by default
python test_scenarios.py
MCPV2_TEST_ITERATIONS=10 python test_scenarios.py   # run more iterations

# CLI test suite: drives the actual interactive CLI process through
# every command (ReadyTo, StopTo, ConnectTo, SentTo, PayTo, PingTo, ...)
python test_cli.py
```

## Security model — read this before deploying anywhere real

MCPv2 authenticates with a **single shared HMAC secret** between peers, not
per-agent public-key identity. Anyone who holds the secret can:
- mint a valid session for any peer that shares it,
- call any skill that peer has registered,
- see that peer's full skill list via `/mcpv2/agent-card`.

This is a reasonable model for a **closed mesh of agents you control**
(e.g. sibling processes on a private network, or behind your own mTLS/VPN).
It is **not** equivalent to OAuth/mTLS-per-identity systems and should not be
exposed directly on the open internet. If you need that, put a real
authenticating reverse proxy in front of each peer and keep the shared
secret as a second, internal-only factor.

Other things that are explicitly **not** production security features here,
by design, in this codebase:
- `pay` is a stub. It returns a plausible-looking JSON shape
  (`status: pending`, a fake `transaction_id`) and moves no money. Do not
  wire it to anything that thinks a real payment happened.
- `--enable-mtls`/`ENV_ENABLE_MTLS` is a capability *flag* reported in
  `/health` and the agent card; this repo does not implement TLS client-cert
  verification. If you need mTLS, terminate it in a proxy (nginx/envoy) in
  front of the peer.
- `ToolSandbox` applies best-effort `RLIMIT_AS`/`RLIMIT_CPU` (POSIX only,
  silently skipped elsewhere) and runs each call with the process CWD
  pointed at a scratch temp directory. This is *not* a real isolation
  boundary (no seccomp, no namespaces, no separate uid). Don't load skill
  handlers whose code you don't trust and assume this contains them.

## What was fixed in this pass

Three real, reproduced bugs from the original codebase, plus hardening:

1. **Uploaded files used to silently vanish.** `ENV_FILE_STORE` defaulted to
   a *relative* path (`./mcpv2_files`), but every tool call runs inside
   `ToolSandbox.execute()`, which `os.chdir()`s into a fresh
   `tempfile.TemporaryDirectory()` for the duration of the call and deletes
   it immediately after. A relative file-store path resolved *inside* that
   throwaway directory, so `upload_file` would report success and then the
   file would be gone microseconds later.
   **Fix:** `ENV_FILE_STORE` is resolved to an absolute path once, at import
   time, before any sandboxing can happen. Verified with a real two-peer
   upload → list → process → delete round trip, at multiple file sizes,
   repeated across process restarts.

2. **Session expiry was split-brain and inconsistently enforced.** A
   session present in the server's in-memory bookkeeping dict was checked
   against a configurable timeout (default 1 hour), but *any* token with a
   valid HMAC that wasn't in that dict — including ones peers mint for
   themselves via `send_batch()`, which is the normal client-mode code
   path — fell through to a stateless check that only enforced a tight
   ±300 second window. Two tokens signed a second apart could end up with
   wildly different effective lifetimes depending on bookkeeping, not
   security intent, and a client-minted token was never actually bound by
   `ENV_SESSION_TIMEOUT` at all.
   **Fix:** the TTL is now embedded in the signed payload itself
   (`ip:nonce:issued_at:ttl`), so there's exactly one authoritative rule,
   checked one way, every time: the token is valid iff the HMAC matches,
   it isn't from the future beyond a small clock-skew tolerance, and
   `now <= issued_at + ttl`. The in-memory dict is now purely optional
   bookkeeping (active-session counts, manual early revocation via
   `SecureSession.revoke()`) and is never consulted for expiry decisions.
   Verified: tampered tokens, expired tokens, and future-dated forged
   tokens are all rejected with 401 in the test suite.

3. **Peers could silently bind to a different port than requested, with
   nothing downstream able to tell.** `find_available_port()` used to scan
   forward through a range and only mention the substitution in a log line
   nobody read programmatically. Two peers (or a peer and a test harness)
   could disagree about where the server actually was, producing confusing
   401s/connection failures far from the real cause — this is exactly what
   broke the original `test_file_transfer.py` when I reproduced it.
   **Fix:** binding is **strict by default** now — if the requested port is
   busy, the peer fails fast with a clear error instead of silently moving.
   Pass `--port-fallback` to opt back into scan-forward behavior. Either
   way, the peer now prints an unambiguous `MCPV2_BOUND_PORT=<port>` line
   to stdout and can write the bound port to a file via `--port-file`, so
   any caller can discover the real port reliably instead of guessing.

4. **Peers used to bind `0.0.0.0` by default and the CLI's `ReadyTo`/
   `ConnectTo` didn't actually do anything.** `ReadyTo` only printed a
   canned instruction string; it never started a process. `ConnectTo` only
   ever did a bare `/health` GET — it never proved a session would actually
   authenticate.
   **Fix:** peers now bind directly to their public IP by default (see
   "Binding: public IP by default" above), with a fast, clear, actionable
   error if that IP isn't a local interface (the NAT case). `ReadyTo` now
   actually spawns `mcpv2.py`, waits for it to report its real bound
   address via a log file (not `stdout=PIPE`, which deadlocks — see below),
   confirms `/health`, and prints the working address; `ConnectTo` now does
   a real authenticated `ping` round trip, auto-retries once with a fresh
   session if the one in the address is stale, and reports a specific
   failure reason at whichever step breaks. Verified end-to-end: started a
   peer via `ReadyTo`, connected to it via `ConnectTo`, confirmed the
   printed demo address genuinely authenticates a direct `curl` call, and
   confirmed the failure path reports connection-refused clearly when
   nothing is listening.

Additional hardening in this pass:
- **A `subprocess.PIPE` deadlock** was found and fixed in the test harness
  and the CLI's `ReadyTo`: piping a child peer's stdout/stderr without a
  reader thread means uvicorn's access logger eventually fills the OS pipe
  buffer (~64KB) once enough requests are logged, and the child blocks on
  `write()` forever — silently hanging the parent. Both now redirect to a
  real log file instead.
- **Session creation was unthrottled**, letting a client trivially bypass
  the per-session rate limit by minting a fresh session for every request.
  `GET /mcpv2/session` is now rate-limited per client IP too.
- **Path traversal guard** added around all file-store skills
  (`upload_file`, `process_instructions`, `delete_file`) via `_safe_path()`,
  which resolves and checks the target stays inside `ENV_FILE_STORE`, on
  top of the existing `os.path.basename()` stripping.
- **Batch size cap** (`MAX_BATCH_SIZE = 100`) added to `/mcpv2` to bound
  memory/CPU from a single oversized request.
- **`/mcpv2/ai/{provider}` now requires a valid session** too (it
  previously had no auth dependency at all, unlike the main `/mcpv2`
  endpoint).
- **Claude history adapter** used to read only `content[0]`, silently
  dropping every subsequent content block in a multi-block Claude message
  (e.g. text + tool_use in the same turn). It now flattens all text-bearing
  blocks in order.
- **OpenAI-format `arguments` parsing** now tolerates already-decoded dict
  arguments in addition to JSON strings, and won't crash on malformed JSON.
- Deprecated Pydantic v1 `.dict()` calls replaced with `.model_dump()`.

## What the test suite actually exercises

`test_scenarios.py` starts two real, independent peer processes (peer A,
stateless; peer B, LLM-context mode on, loaded with `custom_skills.json`)
and — by default, 3 times in a row — runs:

1. Health checks on both peers
2. Session issuance and reuse
3. Tampered-session rejection
4. Expired-session rejection (short TTL)
5. Future-dated / forged-timestamp session rejection
6. `ping`
7. `ask` in stateless mode
8. `ask` in stateful (LLM) mode across a **4-turn simulated conversation
   between two independent agents**, asserting context genuinely carries
   forward turn over turn
9. Full file lifecycle (`upload_file` → `list_files` → `process_instructions`
   → `delete_file`) at three different sizes, run repeatedly
10. `translate_history` across **all 12 provider-pair permutations**
    (claude/openai/gemini/deepseek)
11. `negotiate`
12. `pay` stub shape check
13. Unsupported-provider error path (`-32010`)
14. Unknown-method error path (`-32601`)
15. Rate limiter actually triggers `429` under a burst of requests
16. Custom skill loading from `custom_skills.json` and invocation
17. A mixed batch (one call that should succeed + one that should fail) in
    a single request, asserting each slot's result is independent

Current status: **55/55 checks passing** across 3 iterations in this
environment. Re-running with `MCPV2_TEST_ITERATIONS=N` for larger N is the
way to stress-test further; nothing in the design should make results
flaky run-to-run, but real networks/machines vary, so treat this as a
regression suite to run in CI, not a one-time certificate.

## Cross-host testing: what's actually been verified, and what hasn't

`test_scenarios.py` now runs peer A and peer B on **two distinct IP
addresses** (`127.0.0.1` and `127.0.0.2`) rather than sharing one, and each
peer binds directly to its own address (exercising the public-IP-binding
default for real, not just against a wildcard). This genuinely tests:
- that public-IP binding actually works when the IP is a real local
  interface,
- that session tokens are correctly bound per-IP (a token minted for one
  peer's address is rejected when replayed against the other),
- that the startup banner advertises the correct, working address for each
  peer independently.

**What this is not**: both addresses are still on the same physical
machine, reachable only through my sandboxed tool environment, which
restricts outbound networking to an allowlist of package registries (PyPI,
npm, GitHub, etc.) — it cannot reach an arbitrary second host or a real
public IP over the internet. So "two distinct IPs on one machine" is the
closest honest approximation available here to "two different hosts," not
a substitute for it.

If you want to actually validate this across two separate machines, the
setup is straightforward and doesn't require anything special from MCPv2
itself — it's a plain HTTP service:
1. Run `python mcpv2.py --port 8000 --secret <shared_secret> --public-ip <that machine's real public IP>` on machine A (on a network where that IP is genuinely reachable — a cloud VM with a public IP is the simplest case).
2. Do the same on machine B with the same `--secret`.
3. From machine B: `python mcpv2_cli.py`, then `ConnectTo mcpv2://<machine A's IP>:8000/mcpv2`.
4. Watch for the same failure modes this README already calls out: firewalls/security-group rules blocking the port, NAT meaning the "public IP" isn't locally bindable (use `--bind-host 0.0.0.0 --public-ip <public IP>` in that case), and clock skew beyond `MCPV2_CLOCK_SKEW` breaking session validation.

I have not run that two-machine version myself — I don't have access to a
second real host from here — so treat it as the next concrete validation
step for you to run, not something already confirmed.

## The CLI test suite (`test_cli.py`)

Drives the actual `mcpv2_cli.py` process the way a person would — piping
commands into its interactive prompt over stdin — rather than importing
its internals, so the interactive loop, argument parsing, and subprocess
lifecycle management are all genuinely exercised together. It covers:

- `help` lists every command
- `ReadyTo` starts a real peer and prints a working address
- `PingTo`, `ConnectTo` (fresh session), `SentTo` (prompt and file upload),
  `PayTo` against that peer
- an unknown command is handled gracefully
- `StopTo` by bare port number, `StopTo` by full `mcpv2://` address, and
  the `StopPeer` alias — each verified not just by its printed message but
  by confirming the OS port is actually free again afterward (i.e. the
  process really died, not just that a success message was printed)
- `exit` automatically stopping a peer that was never explicitly stopped
- `ConnectTo` recovering from a stale/invalid session embedded in the
  address (detects the 401, fetches a genuinely new session, retries,
  succeeds)
- `ConnectTo` against nothing listening at all (clear failure, no hang)
- the `SendTo` alias

Current status: **20/20 checks passing.**

Writing this suite caught two real bugs in the CLI, not the protocol core:

1. **Quoted multi-word prompts were silently torn apart.** The command
   parser used `cmd.split()` — a naive whitespace split — so
   `SentTo "hello there" mcpv2://...` was parsed as content `"hello`,
   address `there`, and the actual address argument silently discarded.
   **Fix:** switched to `shlex.split()`, which understands quoting the way
   a shell does, with a clear error message (instead of a wrong silent
   parse) if the quoting is unbalanced.
2. **`ConnectTo`'s retry-on-stale-session didn't actually fetch a new
   session.** After a 401 on the session embedded in the address, the
   retry path called `resolve_session(parsed)` — but that function's
   whole job is "return the address's cached sessionId if it has one,"
   so it just handed back the *same* invalid token and the retry failed
   identically every time. **Fix:** added `fetch_fresh_session()`, which
   always issues a brand-new `GET /mcpv2/session` regardless of what's
   cached in the parsed address, and pointed the retry path at it
   specifically.

Both were caught by writing the test that actually checks the *outcome*
("does the retry succeed?") rather than just that a command runs without
crashing — worth calling out since it's easy for a test suite to look
thorough while only checking that nothing throws.

## Protocol reference

### Endpoints
| Endpoint | Method | Auth | Description |
|---|---|---|---|
| `/health` | GET | none | Liveness + basic config info |
| `/mcpv2/session` | GET | rate-limited by IP | Issue a session token |
| `/mcpv2/agent-card` | GET | none | Capability/skill descriptor |
| `/mcpv2` | POST | session required | Batch of JSON-RPC slots |
| `/mcpv2/ai/{provider}` | POST | session required | Provider-native passthrough |

### Session token
```
sessionId = base64url(payload) + "." + HMAC_SHA256(secret, payload)
payload   = "<client_ip>:<nonce>:<issued_at>:<ttl>"
```
Valid iff: HMAC matches, `issued_at` isn't more than `MCPV2_CLOCK_SKEW`
(default 300s) in the future, and `now <= issued_at + ttl`.

### Request/response (batch)
```json
[
  { "jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {} },
  { "jsonrpc": "2.0", "id": 2, "method": "tools/call",
    "params": { "name": "ask", "arguments": { "query": "Hello" } },
    "context": { "provider": "gemini" } }
]
```
```json
[
  { "jsonrpc": "2.0", "id": 1, "result": { "tools": [ "..." ] } },
  { "jsonrpc": "2.0", "id": 2, "result": { "response": "..." } }
]
```

### Standard skills
`ask`, `upload_file`, `list_files`, `process_instructions`, `delete_file`,
`get_skill` (returns metadata only — does **not** execute `script`),
`ping`, `pay` (stub), `negotiate`, `translate_history`.

### Error codes
| Code | Meaning |
|---|---|
| -32700 | Parse error |
| -32600 | Invalid request |
| -32601 | Method not found |
| -32602 | Invalid params |
| -32603 | Internal error |
| -32001 | Invalid session |
| -32002 | Skill not found |
| -32003 | Skill execution error |
| -32004 | Tool execution error |
| -32005 | Rate limited |
| -32006 | Protocol version mismatch |
| -32007 | File not found |
| -32008 | Payment failed |
| -32009 | Capability violation |
| -32010 | Unsupported provider |

### Environment variables
| Variable | Default | Description |
|---|---|---|
| `MCPV2_PORT` | 8000 | TCP port |
| `MCPV2_SECRET` | auto-generated | Shared HMAC secret |
| `MCPV2_LLM_MODE` | 0 | Enable stateful `ask` context (1=on) |
| `MCPV2_SESSION_TIMEOUT` | 3600 | Token TTL in seconds |
| `MCPV2_CLOCK_SKEW` | 300 | Future-timestamp tolerance, seconds |
| `MCPV2_RATE_LIMIT` | 200 | Requests/sec per session |
| `MCPV2_SESSION_RATE_LIMIT` | 20 | Session creations/sec per client IP |
| `MCPV2_FILE_STORE` | `./mcpv2_files` | Resolved to an absolute path at startup |
| `MCPV2_ENABLE_MTLS` | 0 | Reported capability flag only (see security notes) |

### CLI (`mcpv2_cli.py`)
| Command | Description |
|---|---|
| `ReadyTo [--port 8000] [--secret <s>] [--public-ip <ip>] [--llm-mode]` | Actually starts a local peer subprocess, waits for it to report its real bound address and pass a health check, then prints the shareable `mcpv2://` address plus a same-host demo address. Peers started this way are tracked and stopped automatically on `exit`/`quit`. |
| `StopTo <port_or_mcpv2_address>` | Reverse of `ReadyTo`: stops a peer it started. Accepts either a bare port number or a full `mcpv2://` address, so you can copy-paste whichever `ReadyTo` printed. `StopPeer` is kept as a backward-compatible alias. |
| `ConnectTo mcpv2://host:port/...` | Actually attempts a connection: reachability check, then a real authenticated `ping` round trip (not just a health check) — auto-fetches a genuinely fresh session and retries once if the address's session is stale, and reports a specific, distinct failure reason at whichever step fails (malformed address / unreachable / session issuance failed / call rejected). On success, also prints the peer's skill list. |
| `SentTo "prompt" mcpv2://... [--provider claude\|openai\|gemini\|deepseek]` | Send a prompt (quoted multi-word prompts work correctly - see below) |
| `SentTo file.md mcpv2://...` | Upload a file |
| `PayTo 10.5 mcpv2://...` | Send a (stub) payment request |
| `PingTo mcpv2://...` | Latency check |
| `SendTo ...` | Alias for `SentTo` |

## Status: is this "ready, safe, and the next standard protocol"?

Directly, since the honest answer matters more than a comfortable one:

**No, and no single test run could establish that — here's what actually
changed hands vs. what didn't:**

- **What's solid now**: three previously-reproduced bugs (file-store
  persistence, session-expiry split-brain, silent port fallback) are fixed
  and covered by regression tests. Binding now defaults to the public IP
  with a fast, clear failure instead of a silent fallback to `0.0.0.0`.
  `ReadyTo`/`ConnectTo` in the CLI do real work now instead of being
  placeholders. 57 scenario assertions pass repeatedly across two
  independently-addressed peers, including the full cross-provider
  history-translation matrix, a genuine multi-turn stateful conversation,
  burst-triggered rate limiting, and mixed success/error batches.
- **What that does *not* mean**: none of this has had independent security
  review, adversarial fuzzing, or any real-world traffic. All the tests
  were written by the same author who wrote the fixes they're checking —
  that's useful for catching regressions, but it's the weakest form of
  validation there is, not a substitute for someone trying to break it who
  isn't also invested in it working.
- **The trust model is a hard ceiling, not a rough edge**: a single shared
  HMAC secret across all peers means "authentication" and "authorization"
  collapse into "do you know the string." That's fine for a mesh of agents
  you personally run; it is not what "safe to use between any two AI
  agents" would require, which is per-agent identity, scoped permissions,
  and revocation that doesn't mean rotating one secret for everyone.
- **"Next standard protocol" isn't an engineering claim at all.** Protocols
  become standards through independent implementations, competing designs
  being weighed against each other, and adoption over time — not through
  one codebase passing its own test suite. Nothing here has any of that
  yet, and I'm not in a position to predict whether it ever will.

**What would actually justify "ready" for real cross-organization
agent-to-agent use**: per-agent public-key identity (not a shared secret),
independent security review, real integration tests against a genuinely
separate host (see the cross-host section above — that's the next concrete
step, not something already done), a real payment integration if `pay` is
ever load-bearing, and — if standardization is actually the goal — a
written spec plus at least one independent implementation by people other
than its original author.

## Known limitations / good next steps

- Shared-secret auth means anyone with the secret is fully trusted; there's
  no per-peer scoping of which skills a given peer may call.
- `pay`, `negotiate`, and `get_skill` are protocol-shape stubs, not real
  integrations — wire them up to real systems before relying on them.
- `ToolSandbox`'s resource limits are POSIX-only and best-effort, not a
  hard isolation boundary.
- Provider history adapters are lossy on round-trip for complex multi-block
  messages (tool calls, images) — fine for plain text turns, not a full
  fidelity translator yet.
- No persistent storage for sessions/audit beyond the JSONL audit log and
  in-memory dicts; a restart drops all live sessions and LLM-mode context
  (by design, for now — add a real store if you need durability).
- Binding directly to a public IP fails outright behind NAT/most cloud load
  balancers — expected networking behavior, documented above, but worth
  restating here since it's the most likely first deployment surprise.

## License

MIT
