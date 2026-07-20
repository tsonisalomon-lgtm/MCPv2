#!/usr/bin/env python3
"""
MCPv2 CLI - Full Interactive Command Interface with Provider Support.
"""

import atexit
import base64
import json
import os
import platform
import shlex
import signal
import subprocess
import sys
import time
from typing import Optional
from urllib.parse import urlparse, parse_qs

import requests

try:
    import readline  # noqa: F401  (nice-to-have on POSIX; optional on Windows)
except ImportError:
    pass

REQUEST_TIMEOUT = 30
HERE = os.path.dirname(os.path.abspath(__file__))
MCPV2_SCRIPT = os.path.join(HERE, "mcpv2.py")

# Peers started by ReadyTo in this CLI session, keyed by port, so we can
# report status and clean them up on exit instead of leaking processes.
_running_peers = {}


def _cleanup_all_peers():
    for port in list(_running_peers.keys()):
        _stop_peer(port, quiet=True)


atexit.register(_cleanup_all_peers)


def main():
    print("MCPv2 CLI - Full P2P AI Agent Control (Cross-Provider)")
    print("Type a command or 'help'")
    while True:
        try:
            cmd = input("mcpv2> ").strip()
            if not cmd:
                continue
            if cmd.lower() in ("exit", "quit"):
                if _running_peers:
                    print(f"Stopping {len(_running_peers)} peer(s) started by ReadyTo...")
                    _cleanup_all_peers()
                break
            if cmd.lower() == "help":
                print_help()
                continue
            parse_and_execute(cmd)
        except KeyboardInterrupt:
            print("\nExiting.")
            _cleanup_all_peers()
            break
        except Exception as e:
            print(f"Error: {e}")


def print_help():
    print("""
Commands:
  ReadyTo [--port 8000] [--secret <s>] [--public-ip <ip>] [--llm-mode]
                                   - Start a local peer and print its
                                     connectable mcpv2:// address.
  StopTo <port_or_mcpv2_address>   - Stop a peer previously started by
                                     ReadyTo (reverse of ReadyTo).
  ConnectTo <mcpv2_address>        - Actually attempt to connect to a peer
                                      (auth round trip, not just a ping) and
                                      report success or failure with why.
  SentTo <content_or_file> <addr> [--provider <provider>] - Send prompt or file.
  PayTo <amount> <addr>            - Request a (stub) payment.
  PingTo <addr>                    - Test connectivity and latency.
  SendTo ...                       - Alias for SentTo.
  StopPeer ...                     - Alias for StopTo.
  help                             - Show this help.
  exit/quit                        - Exit (stops any peers started by ReadyTo).

Address format: mcpv2://host:port/mcpv2?sessionId=<optional>
Provider flags: --provider claude|openai|gemini|deepseek

Note: MCPv2 peers bind directly to their public IP, never 0.0.0.0 - if
you're behind NAT and binding fails, pass --public-ip <ip-a-remote-peer-
would-connect-to> and see mcpv2.py's own error message for options.
""")


def parse_mcpv2_address(addr: str) -> Optional[dict]:
    try:
        parsed = urlparse(addr)
        if parsed.scheme != "mcpv2":
            return None
        host = parsed.hostname
        port = parsed.port
        query = parse_qs(parsed.query)
        session_id = query.get("sessionId", [None])[0]
        if not host or not port:
            return None
        return {"host": host, "port": port, "sessionId": session_id}
    except Exception:
        return None


def fetch_fresh_session(parsed: dict) -> Optional[str]:
    """Always issues a brand-new GET /mcpv2/session, ignoring any sessionId
    that might already be in `parsed`. Used both for the normal "no session
    in the address yet" case and for ConnectTo's retry-after-401 path,
    where reusing resolve_session() would be wrong: it would just hand
    back the same stale sessionId that's already cached in `parsed`
    instead of actually fetching a new one."""
    try:
        resp = requests.get(f"http://{parsed['host']}:{parsed['port']}/mcpv2/session",
                            timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        return resp.json().get("sessionId")
    except requests.exceptions.RequestException as e:
        print(f"Could not obtain a sessionId: {e}")
        return None


def resolve_session(parsed: dict) -> Optional[str]:
    """Return a usable sessionId for this address, fetching one if needed."""
    if parsed.get("sessionId"):
        return parsed["sessionId"]
    return fetch_fresh_session(parsed)


def post_slots(parsed: dict, session_id: str, slots: list) -> Optional[dict]:
    headers = {"Content-Type": "application/json", "sessionId": session_id}
    try:
        resp = requests.post(f"http://{parsed['host']}:{parsed['port']}/mcpv2",
                             json=slots, headers=headers, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        return resp.json()
    except requests.exceptions.HTTPError as e:
        print(f"Error: HTTP {e.response.status_code}: {e.response.text}")
        return None
    except requests.exceptions.RequestException as e:
        print(f"Error: {e}")
        return None


def send_prompt(prompt: str, addr: str, provider: str = None):
    parsed = parse_mcpv2_address(addr)
    if not parsed:
        print("Invalid address.")
        return
    session_id = resolve_session(parsed)
    if not session_id:
        return
    slot = {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": "ask", "arguments": {"query": prompt}}}
    if provider:
        slot["context"] = {"provider": provider}
    result = post_slots(parsed, session_id, [slot])
    if result is not None:
        print("Response:", json.dumps(result, indent=2))


def send_file(filepath: str, addr: str, provider: str = None):
    if not os.path.isfile(filepath):
        print(f"File {filepath} not found.")
        return
    with open(filepath, 'rb') as f:
        content_b64 = base64.b64encode(f.read()).decode()
    parsed = parse_mcpv2_address(addr)
    if not parsed:
        print("Invalid address.")
        return
    session_id = resolve_session(parsed)
    if not session_id:
        return
    filename = os.path.basename(filepath)
    slot = {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": {"name": "upload_file",
                       "arguments": {"filename": filename, "content_b64": content_b64}}}
    if provider:
        slot["context"] = {"provider": provider}
    result = post_slots(parsed, session_id, [slot])
    if result is not None:
        print("Upload response:", json.dumps(result, indent=2))


def send_ping(addr: str):
    parsed = parse_mcpv2_address(addr)
    if not parsed:
        print("Invalid address.")
        return
    session_id = resolve_session(parsed)
    if not session_id:
        return
    slot = {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
            "params": {"name": "ping", "arguments": {"message": "ping"}}}
    start = time.time()
    result = post_slots(parsed, session_id, [slot])
    if result is not None:
        print(f"Ping latency: {(time.time()-start)*1000:.2f} ms")
        print("Response:", json.dumps(result, indent=2))


def send_payment(amount: float, addr: str):
    parsed = parse_mcpv2_address(addr)
    if not parsed:
        print("Invalid address.")
        return
    session_id = resolve_session(parsed)
    if not session_id:
        return
    slot = {"jsonrpc": "2.0", "id": 4, "method": "tools/call",
            "params": {"name": "pay",
                       "arguments": {"amount": amount, "currency": "USD", "recipient": "peer@example.com"}}}
    result = post_slots(parsed, session_id, [slot])
    if result is not None:
        print("Payment (stub) response:", json.dumps(result, indent=2))


# ---------------------------------------------------------------------------
# ReadyTo: actually start a local peer, discover its real address, print it.
# ---------------------------------------------------------------------------

def cmd_ready_to(args):
    port = 8000
    secret = None
    public_ip = None
    llm_mode = False
    i = 0
    while i < len(args):
        if args[i] == "--port" and i + 1 < len(args):
            port = int(args[i + 1]); i += 2; continue
        if args[i] == "--secret" and i + 1 < len(args):
            secret = args[i + 1]; i += 2; continue
        if args[i] == "--public-ip" and i + 1 < len(args):
            public_ip = args[i + 1]; i += 2; continue
        if args[i] == "--llm-mode":
            llm_mode = True; i += 1; continue
        i += 1

    if not os.path.isfile(MCPV2_SCRIPT):
        print(f"Cannot find mcpv2.py next to this CLI at {MCPV2_SCRIPT}.")
        return
    if secret is None:
        secret = base64.b64encode(os.urandom(24)).decode()
        print(f"(No --secret given; generated one for this session: {secret})")
        print("Share this secret out-of-band with the peer you want to talk to.")

    log_path = os.path.join(HERE, f".readyto_{port}.log")
    env = os.environ.copy()
    env["MCPV2_LLM_MODE"] = "1" if llm_mode else "0"
    cmd = [sys.executable, MCPV2_SCRIPT, "--port", str(port), "--secret", secret,
           "--log-level", "WARNING"]
    if public_ip:
        cmd += ["--public-ip", public_ip]

    print(f"Starting peer on port {port}...")
    # Log to a real file, not subprocess.PIPE: an unread PIPE fills its OS
    # buffer once uvicorn's access logger writes enough lines and the
    # child blocks forever - a real deadlock we hit and fixed in testing.
    log_fh = open(log_path, "w")
    popen_kwargs = dict(stdout=log_fh, stderr=subprocess.STDOUT, env=env)
    if platform.system() == "Windows":
        popen_kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
    else:
        popen_kwargs["preexec_fn"] = os.setsid
    proc = subprocess.Popen(cmd, **popen_kwargs)

    bound_port = None
    peer_address = None
    demo_address = None
    deadline = time.time() + 20  # public-IP auto-detection can be slow/blocked
    while time.time() < deadline:
        if proc.poll() is not None:
            log_fh.flush()
            print(f"Peer exited immediately. Log ({log_path}):")
            print(open(log_path).read())
            return
        try:
            with open(log_path) as f:
                content = f.read()
        except FileNotFoundError:
            content = ""
        for line in content.splitlines():
            if line.startswith("MCPV2_BOUND_PORT="):
                bound_port = int(line.split("=", 1)[1])
            elif line.startswith("MCPV2_PEER_ADDRESS="):
                peer_address = line.split("=", 1)[1]
            elif line.startswith("MCPV2_DEMO_SESSION_ADDRESS="):
                demo_address = line.split("=", 1)[1]
        if bound_port and peer_address and demo_address:
            break
        time.sleep(0.2)

    if not (bound_port and peer_address):
        proc.terminate()
        log_fh.close()
        print(f"Peer did not report a bound address within 20s. Log ({log_path}):")
        print(open(log_path).read())
        return

    # Confirm it's actually serving, not just that it printed the banner.
    host_for_health = urlparse(peer_address).hostname
    healthy = False
    deadline = time.time() + 10
    while time.time() < deadline:
        try:
            r = requests.get(f"http://{host_for_health}:{bound_port}/health", timeout=1)
            if r.status_code == 200:
                healthy = True
                break
        except requests.exceptions.RequestException:
            pass
        time.sleep(0.2)

    _running_peers[bound_port] = {"proc": proc, "log_fh": log_fh, "log_path": log_path,
                                   "address": peer_address, "secret": secret}

    print("=" * 70)
    if healthy:
        print(f"Peer is ready and healthy on port {bound_port}.")
    else:
        print(f"Peer bound to port {bound_port} but did not answer /health "
              f"within 10s - it may still be starting. Check {log_path}.")
    print(f"  Share this address for others to connect to:")
    print(f"    {peer_address}")
    print(f"  They obtain their own sessionId via:")
    print(f"    GET http://{host_for_health}:{bound_port}/mcpv2/session")
    print(f"  Same-host demo address (session pre-attached, only valid for")
    print(f"  callers whose source IP matches this peer's public IP):")
    print(f"    {demo_address}")
    print(f"  Stop this peer with: StopTo {bound_port}   (or: StopTo {peer_address})")
    print("=" * 70)


def _resolve_stop_target(arg: str):
    """StopTo accepts either a bare port number or a full mcpv2:// address,
    mirroring the reverse of what ReadyTo prints (a port) and what
    ConnectTo/SentTo/PingTo accept (an address) - so the person doesn't
    have to remember which form this particular command wants."""
    arg = arg.strip()
    if arg.isdigit():
        return int(arg)
    parsed = parse_mcpv2_address(arg)
    if parsed:
        return parsed["port"]
    return None


def _stop_peer(port, quiet=False):
    info = _running_peers.pop(port, None)
    if not info:
        if not quiet:
            print(f"No peer started by ReadyTo is tracked on port {port}.")
        return
    proc = info["proc"]
    try:
        if platform.system() == "Windows":
            proc.terminate()
        else:
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        proc.wait(timeout=5)
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass
    try:
        info["log_fh"].close()
    except Exception:
        pass
    if not quiet:
        print(f"Stopped peer on port {port}.")


def cmd_connect_to(addr: str):
    """
    Actually attempt to connect: parse the address, then try a real
    authenticated round trip (a `ping` tool call), not just a bare TCP/
    health check. Reports success or failure with a specific reason:
      - malformed address
      - peer unreachable (connection error / timeout / DNS failure)
      - address's sessionId invalid/expired -> auto-fetch a fresh one and
        retry once, reporting which happened
      - authenticated call succeeded -> also show the peer's skill list
    """
    parsed = parse_mcpv2_address(addr)
    if not parsed:
        print(f"ConnectTo FAILED: '{addr}' is not a valid mcpv2:// address.")
        print("Expected format: mcpv2://host:port/mcpv2?sessionId=<optional>")
        return

    base = f"http://{parsed['host']}:{parsed['port']}"

    # Step 1: is the peer even reachable?
    try:
        r = requests.get(f"{base}/health", timeout=5)
        r.raise_for_status()
    except requests.exceptions.RequestException as e:
        print(f"ConnectTo FAILED: peer unreachable at {parsed['host']}:{parsed['port']} ({e}).")
        return

    # Step 2: do we have a session to try? If the address didn't carry one,
    # fetch one now.
    session_id = parsed.get("sessionId")
    original_session = session_id
    if not session_id:
        session_id = resolve_session(parsed)
        if not session_id:
            print(f"ConnectTo FAILED: peer is reachable but issuing a session failed.")
            return

    # Step 3: prove the session actually authenticates, with a real call.
    ping_slot = {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                 "params": {"name": "ping", "arguments": {"message": "connect-check"}}}
    resp = requests.post(f"{base}/mcpv2", json=[ping_slot],
                         headers={"Content-Type": "application/json", "sessionId": session_id},
                         timeout=REQUEST_TIMEOUT)

    if resp.status_code == 401 and session_id == original_session:
        # The session in the address was stale/invalid - get a genuinely
        # NEW one (not resolve_session(parsed), which would just hand back
        # the same stale value still cached in `parsed`) and retry once.
        print("Session in address was rejected (401); fetching a fresh one and retrying...")
        session_id = fetch_fresh_session(parsed)
        if not session_id:
            print("ConnectTo FAILED: could not obtain a fresh session either.")
            return
        resp = requests.post(f"{base}/mcpv2", json=[ping_slot],
                             headers={"Content-Type": "application/json", "sessionId": session_id},
                             timeout=REQUEST_TIMEOUT)

    if resp.status_code != 200 or resp.json()[0].get("error"):
        detail = resp.text if resp.status_code != 200 else resp.json()[0]["error"]
        print(f"ConnectTo FAILED: peer reachable and session issuance worked, "
              f"but the authenticated call failed: {detail}")
        return

    used_fresh = session_id != original_session
    print(f"ConnectTo SUCCESS: {parsed['host']}:{parsed['port']} is reachable and "
          f"authenticated (sessionId {'fetched fresh' if used_fresh else 'from address'}).")

    # Bonus: show what the peer can do, since we're already connected.
    try:
        card = requests.get(f"{base}/mcpv2/agent-card", timeout=5).json()
        skill_names = [s["name"] for s in card.get("skills", [])]
        print(f"  Peer: {card.get('name', '?')}")
        print(f"  Skills: {', '.join(skill_names) if skill_names else '(none)'}")
    except requests.exceptions.RequestException:
        pass
    print(f"  Working address for further calls:")
    print(f"    mcpv2://{parsed['host']}:{parsed['port']}/mcpv2?sessionId={session_id}")


def parse_and_execute(cmd):
    try:
        parts = shlex.split(cmd)
    except ValueError as e:
        # Unbalanced quotes etc. - shlex raises rather than silently
        # mis-splitting; give the person a clear message instead of a
        # traceback or (worse) quietly parsing it wrong.
        print(f"Could not parse that command: {e}")
        return
    if not parts:
        return
    action = parts[0].lower()
    args = parts[1:]

    if action == "readyto":
        cmd_ready_to(args)

    elif action in ("stopto", "stoppeer"):
        if not args:
            print("Usage: StopTo <port_or_mcpv2_address>")
            return
        port = _resolve_stop_target(args[0])
        if port is None:
            print(f"Usage: StopTo <port_or_mcpv2_address> - '{args[0]}' is neither "
                  f"a port number nor a valid mcpv2:// address.")
            return
        _stop_peer(port)

    elif action == "connectto":
        if not args:
            print("Usage: ConnectTo <address>")
            return
        cmd_connect_to(args[0])

    elif action in ("sentto", "sendto"):
        provider = None
        content = None
        addr = None
        i = 0
        while i < len(args):
            if args[i] == "--provider":
                if i + 1 < len(args):
                    provider = args[i + 1]
                i += 2
                continue
            if content is None:
                content = args[i]
            elif addr is None:
                addr = args[i]
            i += 1
        if not content or not addr:
            print("Usage: SentTo <content_or_file> <address> [--provider <provider>]")
            return
        if os.path.isfile(content):
            send_file(content, addr, provider)
        else:
            send_prompt(content, addr, provider)

    elif action == "payto":
        if len(args) < 2:
            print("Usage: PayTo <amount> <address>")
            return
        try:
            amount = float(args[0])
        except ValueError:
            print("Invalid amount.")
            return
        send_payment(amount, args[1])

    elif action == "pingto":
        if not args:
            print("Usage: PingTo <address>")
            return
        send_ping(args[0])

    else:
        print("Unknown command. Type 'help'.")


if __name__ == "__main__":
    main()
