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

# Start a peer
python mcpv2.py --port 8000 --secret mySharedSecret

# In another terminal, an interactive client
python mcpv2_cli.py
```

Run the tests:

```bash
# Fast smoke test (one upload + process, two peers)
python test_file_transfer.py

# Full scenario suite: two peers, ~19 scenario categories, run 3x by default
python test_scenarios.py
MCPV2_TEST_ITERATIONS=10 python test_scenarios.py   # run more iterations
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

Additional hardening in this pass:
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
| `ConnectTo mcpv2://host:port/...` | Validate an address and check peer health |
| `SentTo "prompt" mcpv2://... [--provider claude\|openai\|gemini\|deepseek]` | Send a prompt |
| `SentTo file.md mcpv2://...` | Upload a file |
| `PayTo 10.5 mcpv2://...` | Send a (stub) payment request |
| `PingTo mcpv2://...` | Latency check |
| `SendTo ...` | Alias for `SentTo` |

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

## License

MIT
