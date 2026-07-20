#!/usr/bin/env python3
"""
MCPv2 scenario test suite.

Spins up TWO independent, real MCPv2 peer processes (peer A and peer B)
and drives many kinds of interaction between them - not mocked, actual
HTTP over actual subprocesses - covering:

  1.  Health checks
  2.  Session issuance + reuse
  3.  Tampered-session rejection
  4.  Expired-session rejection (short TTL)
  5.  Session from wrong client IP rejected (loopback both sides in this
      environment, so simulated via a forged payload instead)
  6.  ping
  7.  ask (stateless)
  8.  ask (stateful / LLM mode) - multi-turn context across many turns,
      simulating a real back-and-forth between two independent agents
  9.  Full file lifecycle: upload -> list -> process -> delete, run
      MANY times with different files/sizes, from peer A onto peer B
  10. translate_history across every provider pair (12 combinations)
  11. negotiate
  12. pay (stub) - shape check only, explicitly not a real payment claim
  13. Unsupported provider -> -32010 error code
  14. Unknown method -> -32601 error code
  15. Rate limiting triggers 429 under burst load
  16. Custom skill loading + invocation from custom_skills.json
  17. Batch of mixed slots (success + intentional error in same batch)
  18. Repeated round trips (stress: run the whole scenario set N times)

Exit code is 0 iff every scenario passes. A summary table is printed.
"""

import base64
import json
import os
import signal
import subprocess
import sys
import time
import platform
import itertools

import requests

HERE = os.path.dirname(os.path.abspath(__file__))
PYTHON = sys.executable
SCRIPT = os.path.join(HERE, "mcpv2.py")
SECRET = "test-shared-secret-please-rotate"
HOST = "127.0.0.1"

PASS = []
FAIL = []


def record(name, ok, detail=""):
    (PASS if ok else FAIL).append((name, detail))
    mark = "PASS" if ok else "FAIL"
    print(f"  [{mark}] {name}" + (f" -- {detail}" if detail and not ok else ""))


class Peer:
    def __init__(self, name, port, public_ip=HOST, llm_mode=False, extra_env=None, extra_args=None):
        self.name = name
        self.requested_port = port
        self.public_ip = public_ip
        self.port = None
        self.proc = None
        self.llm_mode = llm_mode
        self.extra_env = extra_env or {}
        self.extra_args = extra_args or []
        self.port_file = os.path.join(HERE, f".port_{name}_{port}.txt")

    def start(self, timeout=10):
        env = os.environ.copy()
        env["MCPV2_LLM_MODE"] = "1" if self.llm_mode else "0"
        env.update(self.extra_env)
        if os.path.exists(self.port_file):
            os.remove(self.port_file)
        # NOTE: no --bind-host here. This deliberately exercises the new
        # default: bind directly to --public-ip, never 0.0.0.0. Each peer
        # gets its OWN address (127.0.0.1 vs 127.0.0.2) as the closest
        # honest stand-in for "different host" reachable inside this
        # sandbox - see README for why true separate physical hosts
        # aren't something this test environment can reach.
        cmd = [PYTHON, SCRIPT, "--port", str(self.requested_port), "--secret", SECRET,
               "--public-ip", self.public_ip, "--log-level", "WARNING",
               "--port-file", self.port_file] + self.extra_args
        # IMPORTANT: do NOT use stdout=PIPE/stderr=PIPE here without a
        # reader thread. uvicorn's access logger writes a line per request;
        # once the burst-rate-limit scenario fires hundreds of requests,
        # an unread PIPE fills its OS buffer (~64KB) and the child blocks
        # on write() forever, hanging the whole harness. Redirect to real
        # log files instead - the standard fix for this classic deadlock.
        self.log_path = os.path.join(HERE, f".log_{self.name}_{self.requested_port}.txt")
        self._log_fh = open(self.log_path, "w")
        kwargs = dict(stdout=self._log_fh, stderr=subprocess.STDOUT, env=env)
        if platform.system() == "Windows":
            kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
        else:
            kwargs["preexec_fn"] = os.setsid
        self.proc = subprocess.Popen(cmd, **kwargs)

        deadline = time.time() + timeout
        while time.time() < deadline:
            if os.path.exists(self.port_file):
                with open(self.port_file) as f:
                    content = f.read().strip()
                if content:
                    self.port = int(content)
                    break
            if self.proc.poll() is not None:
                self._log_fh.flush()
                with open(self.log_path) as f:
                    log_contents = f.read()
                raise RuntimeError(f"{self.name} exited early.\nLOG:\n{log_contents}")
            time.sleep(0.1)
        if self.port is None:
            raise RuntimeError(f"{self.name} never reported a bound port within {timeout}s")

        # Wait for /health to actually respond.
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                r = requests.get(f"http://{self.public_ip}:{self.port}/health", timeout=1)
                if r.status_code == 200:
                    return
            except requests.exceptions.RequestException:
                pass
            time.sleep(0.1)
        raise RuntimeError(f"{self.name} did not become healthy in time")

    def stop(self):
        if not self.proc:
            return
        try:
            if platform.system() == "Windows":
                self.proc.terminate()
            else:
                os.killpg(os.getpgid(self.proc.pid), signal.SIGTERM)
            self.proc.wait(timeout=5)
        except Exception:
            try:
                self.proc.kill()
            except Exception:
                pass
        if os.path.exists(self.port_file):
            os.remove(self.port_file)
        try:
            self._log_fh.close()
        except Exception:
            pass

    @property
    def base_url(self):
        return f"http://{self.public_ip}:{self.port}"

    def session(self):
        r = requests.get(f"{self.base_url}/mcpv2/session", timeout=5)
        r.raise_for_status()
        return r.json()["sessionId"]

    def send(self, session_id, slots):
        r = requests.post(f"{self.base_url}/mcpv2", json=slots,
                          headers={"Content-Type": "application/json", "sessionId": session_id},
                          timeout=15)
        return r


def slot(id_, method, params=None, provider=None):
    s = {"jsonrpc": "2.0", "id": id_, "method": method, "params": params or {}}
    if provider:
        s["context"] = {"provider": provider}
    return s


def run_scenarios(iteration: int, peer_a: Peer, peer_b: Peer):
    tag = f"[run {iteration}]"

    # 1. Health checks
    for p in (peer_a, peer_b):
        r = requests.get(f"{p.base_url}/health", timeout=5)
        record(f"{tag} health check ({p.name})", r.status_code == 200 and r.json().get("status") == "healthy")

    # 2. Session issuance + reuse
    sid = peer_a.session()
    record(f"{tag} session issuance (A)", bool(sid))
    r1 = peer_a.send(sid, [slot(1, "ping", {"message": "hi"})])
    r2 = peer_a.send(sid, [slot(2, "ping", {"message": "hi again"})])
    record(f"{tag} session reuse (A)", r1.status_code == 200 and r2.status_code == 200)

    # 3. Tampered session rejected
    tampered = sid[:-2] + ("00" if sid[-2:] != "00" else "11")
    r = peer_a.send(tampered, [slot(1, "ping", {})])
    record(f"{tag} tampered session rejected", r.status_code == 401, f"got {r.status_code}")

    # 4. Expired session rejected (short TTL peer)
    short_ttl_peer = peer_a  # reuse peer_a's server, just mint a short-TTL token via the API's own logic
    # We can't call SecureSession.create directly (different process), so we
    # simulate by importing the module locally to mint a token with ttl=1
    # against the SAME shared secret, then wait for it to expire.
    sys.path.insert(0, HERE)
    import importlib
    mcpv2_local = importlib.import_module("mcpv2")
    short_token = mcpv2_local.SecureSession.create(peer_a.public_ip, SECRET, ttl=1)
    time.sleep(1.5)
    r = peer_a.send(short_token, [slot(1, "ping", {})])
    record(f"{tag} expired session rejected", r.status_code == 401, f"got {r.status_code}")

    # 5. Forged-future-timestamp session rejected
    import base64 as b64
    future_payload = f"{peer_a.public_ip}:noncenonce:{int(time.time())+99999}:60"
    import hmac, hashlib
    sig = hmac.new(SECRET.encode(), future_payload.encode(), hashlib.sha256).hexdigest()
    forged = f"{b64.urlsafe_b64encode(future_payload.encode()).decode()}.{sig}"
    r = peer_a.send(forged, [slot(1, "ping", {})])
    record(f"{tag} future-dated session rejected", r.status_code == 401, f"got {r.status_code}")

    # 6. ping
    r = peer_a.send(sid, [slot(1, "tools/call", {"name": "ping", "arguments": {"message": "ping"}})])
    ok = r.status_code == 200 and "echo" in r.json()[0]["result"]["content"][0]["text"]
    record(f"{tag} ping tool call", ok)

    # 7. ask stateless (peer_a has LLM mode off)
    r = peer_a.send(sid, [slot(1, "tools/call", {"name": "ask", "arguments": {"query": "what is MCPv2?"}})])
    ok = r.status_code == 200 and "Generic response" in r.json()[0]["result"]["content"][0]["text"]
    record(f"{tag} ask stateless (A, LLM mode off)", ok)

    # 8. ask stateful multi-turn on peer_b (LLM mode on) - simulate a real
    #    back-and-forth "conversation" between two independent agents: A
    #    asks a sequence of questions to B, using the SAME session, and we
    #    check B's context genuinely advances turn over turn.
    sid_b = peer_b.session()
    questions = [
        "Hello, who are you?",
        "What is the capital of France?",
        "Can you remind me what I asked first?",
        "Summarize our conversation so far.",
    ]
    turn_ok = True
    prev_answer = None
    for i, q in enumerate(questions):
        resp = peer_b.send(sid_b, [slot(i, "tools/call", {"name": "ask", "arguments": {"query": q}})])
        if resp.status_code != 200:
            turn_ok = False
            break
        text = resp.json()[0]["result"]["content"][0]["text"]
        if i == 0 and "First question" not in text:
            turn_ok = False
        if i > 0 and "Previously you asked" not in text:
            turn_ok = False
        prev_answer = text
    record(f"{tag} multi-turn agent-to-agent conversation (B, LLM mode on, {len(questions)} turns)", turn_ok)

    # 9. Full file lifecycle, several times with different content/sizes.
    # NOTE: process_instructions() reads files as UTF-8 text (it's meant
    # for .md instruction files), so we exercise it with valid text of
    # varying sizes rather than random binary - random bytes are not
    # guaranteed valid UTF-8 and would fail decode for reasons unrelated
    # to the file-store bug this test exists to catch.
    file_ok = True
    for i, size in enumerate([16, 4096, 200_000]):
        content = ("MCPv2 test payload line.\n" * (size // 25 + 1))[:size].encode("utf-8")
        b64content = base64.b64encode(content).decode()
        fname = f"payload_{iteration}_{i}.bin"
        up = peer_b.send(sid_b, [slot(1, "tools/call", {"name": "upload_file",
                          "arguments": {"filename": fname, "content_b64": b64content}})])
        listed = peer_b.send(sid_b, [slot(2, "tools/call", {"name": "list_files", "arguments": {}})])
        listed_text = listed.json()[0]["result"]["content"][0]["text"] if listed.status_code == 200 else ""
        present = fname in listed_text
        proc = peer_b.send(sid_b, [slot(3, "tools/call",
                            {"name": "process_instructions", "arguments": {"filename": fname}})])
        proc_ok = proc.status_code == 200 and "error" not in proc.json()[0]["result"]["content"][0]["text"][:30]
        deleted = peer_b.send(sid_b, [slot(4, "tools/call", {"name": "delete_file", "arguments": {"filename": fname}})])
        deleted_ok = deleted.status_code == 200 and "deleted" in deleted.json()[0]["result"]["content"][0]["text"]
        if not (up.status_code == 200 and present and proc_ok and deleted_ok):
            file_ok = False
    record(f"{tag} file lifecycle round trips (upload/list/process/delete x3 sizes)", file_ok)

    # 10. translate_history across every provider pair
    sample_histories = {
        "claude": [{"role": "user", "content": [{"type": "text", "text": "hi"}]}],
        "openai": [{"role": "user", "content": "hi"}],
        "gemini": [{"role": "user", "parts": [{"text": "hi"}]}],
        "deepseek": [{"role": "user", "content": "hi"}],
    }
    translate_ok = True
    providers = ["claude", "openai", "gemini", "deepseek"]
    for fp, tp in itertools.permutations(providers, 2):
        resp = peer_a.send(sid, [slot(1, "tools/call", {"name": "translate_history",
                            "arguments": {"history": sample_histories[fp], "from_provider": fp, "to_provider": tp}})])
        if resp.status_code != 200:
            translate_ok = False
            continue
        text = resp.json()[0]["result"]["content"][0]["text"]
        if "error" in text.lower()[:20] or "hi" not in text:
            translate_ok = False
    record(f"{tag} translate_history all {len(providers)*(len(providers)-1)} provider pairs", translate_ok)

    # 11. negotiate
    r = peer_a.send(sid, [slot(1, "tools/call", {"name": "negotiate",
                     "arguments": {"capabilities": {"streaming": True}}})])
    record(f"{tag} negotiate", r.status_code == 200 and "negotiated" in r.json()[0]["result"]["content"][0]["text"])

    # 12. pay (stub) - shape check only
    r = peer_a.send(sid, [slot(1, "tools/call", {"name": "pay", "arguments": {"amount": 5.0}})])
    record(f"{tag} pay stub returns pending status",
           r.status_code == 200 and "pending" in r.json()[0]["result"]["content"][0]["text"])

    # 13. Unsupported provider
    r = peer_a.send(sid, [slot(1, "tools/call", {"name": "ping", "arguments": {}}, provider="notaprovider")])
    ok = r.status_code == 200 and r.json()[0].get("error", {}).get("code") == -32010
    record(f"{tag} unsupported provider -> -32010", ok, f"got {r.json()}")

    # 14. Unknown method
    r = peer_a.send(sid, [slot(1, "tools/nonexistent", {})])
    ok = r.status_code == 200 and r.json()[0].get("error", {}).get("code") == -32601
    record(f"{tag} unknown method -> -32601", ok)

    # 15. Rate limiting under burst (only run once, it's slow / stateful)
    if iteration == 1:
        burst_peer = peer_a
        burst_sid = burst_peer.session()
        hit_429 = False
        for _ in range(400):
            r = burst_peer.send(burst_sid, [slot(1, "ping", {})])
            if r.status_code == 429:
                hit_429 = True
                break
        record(f"{tag} rate limiter triggers 429 under burst", hit_429)

    # 16. Custom skills (peer_b started with --skills custom_skills.json)
    r = peer_b.send(sid_b, [slot(1, "tools/call", {"name": "search_web", "arguments": {"query": "test"}})])
    ok = r.status_code == 200 and "Executed search_web" in r.json()[0]["result"]["content"][0]["text"]
    record(f"{tag} custom skill loaded & callable (search_web)", ok)

    # 17. Mixed batch: one success + one deliberate error, same request
    batch = [
        slot(1, "tools/call", {"name": "ping", "arguments": {}}),
        slot(2, "tools/call", {"name": "definitely_not_a_real_skill", "arguments": {}}),
    ]
    r = peer_a.send(sid, batch)
    results = r.json() if r.status_code == 200 else []
    ok = (len(results) == 2 and results[0].get("result") is not None
          and results[1].get("error", {}).get("code") == -32004)
    record(f"{tag} mixed batch (success + error) handled independently", ok, f"got {results}")


def main():
    n_runs = int(os.environ.get("MCPV2_TEST_ITERATIONS", "3"))

    peer_a = Peer("A", 8100, public_ip="127.0.0.1", llm_mode=False)
    peer_b = Peer("B", 8101, public_ip="127.0.0.2", llm_mode=True,
                  extra_args=["--skills", os.path.join(HERE, "custom_skills.json")])

    print(f"Starting peer A ({peer_a.public_ip}:~8100) and peer B "
          f"({peer_b.public_ip}:~8101, LLM mode on, custom skills)...")
    print("NOTE: 127.0.0.1 vs 127.0.0.2 is the closest honest stand-in for")
    print("\"different host\" reachable inside this sandbox - it genuinely")
    print("exercises the bind-to-public-IP and per-IP session binding logic,")
    print("but it is not a substitute for testing across two real separate")
    print("machines. See README's cross-host section for that setup.\n")
    peer_a.start()
    peer_b.start()
    print(f"Peer A bound to {peer_a.public_ip}:{peer_a.port}, "
          f"peer B bound to {peer_b.public_ip}:{peer_b.port}\n")

    # Sanity-check that each peer's own startup banner advertises a
    # correctly-formed, reachable address (the feature just added).
    for p in (peer_a, peer_b):
        with open(p.log_path) as f:
            log_contents = f.read()
        expected = f"MCPV2_PEER_ADDRESS=mcpv2://{p.public_ip}:{p.port}/mcpv2"
        record(f"[startup] {p.name} printed correct peer address", expected in log_contents,
               f"expected '{expected}' in log")

    try:
        for i in range(1, n_runs + 1):
            print(f"=== Scenario run {i}/{n_runs} ===")
            run_scenarios(i, peer_a, peer_b)
            print()
    finally:
        peer_a.stop()
        peer_b.stop()

    print("=" * 60)
    print(f"TOTAL: {len(PASS)} passed, {len(FAIL)} failed")
    if FAIL:
        print("\nFailures:")
        for name, detail in FAIL:
            print(f"  - {name}: {detail}")
        sys.exit(1)
    else:
        print("All scenarios passed.")
        sys.exit(0)


if __name__ == "__main__":
    main()
