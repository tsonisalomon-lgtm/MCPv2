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
    import readline  # noqa: F401 (nice-to-have on POSIX; optional on Windows)
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
  ReadyTo [--port <port>] [--secret <secret>] [--public-ip <ip>] [--bind-host <ip>] [--llm-mode]
          - Start a local MCPv2 peer and print its mcpv2:// address.
          - Default port: 8000, secret auto-generated if omitted, public-ip auto-detected.
          - Example: ReadyTo --port 9000 --secret mySecret --public-ip 203.0.113.42

  StopTo <port|address>   - Stop a peer previously started by ReadyTo.
          - Example: StopTo 8000   or   StopTo mcpv2://127.0.0.1:8000/mcpv2

  ConnectTo <address>     - Perform a full authentication round-trip with a remote peer.
          - Example: ConnectTo mcpv2://127.0.0.1:8000/mcpv2

  SentTo <content> <address> [--provider <provider>]
          - Send a prompt (plain text) or a file (path) to the remote peer.
          - provider flag: claude | openai | gemini | deepseek (optional)
          - Example (prompt): SentTo "Hello, how are you?" mcpv2://127.0.0.1:8000/mcpv2 --provider claude
          - Example (file):   SentTo instructions.md mcpv2://127.0.0.1:8000/mcpv2

  PayTo <amount> <address>  - Request a stub payment from the remote peer.
          - Example: PayTo 10.5 mcpv2://127.0.0.1:8000/mcpv2

  PingTo <address>          - Measure round-trip latency and echo a ping.
          - Example: PingTo mcpv2://127.0.0.1:8000/mcpv2

  SendTo ...                - Alias for SentTo (same syntax).

  StopPeer ...              - Alias for StopTo (same syntax).

  help                      - Show this help.

  exit/quit                 - Exit the CLI (stops any peers started by ReadyTo).

Address format: mcpv2://<host>:<port>/mcpv2?sessionId=<sessionId>
(If you omit the sessionId, the CLI will automatically fetch one via GET /mcpv2/session.)

Provider flags: --provider claude|openai|gemini|deepseek

Note: MCPv2 peers bind directly to their public IP by default. If you are behind NAT,
use --public-ip <ip> to advertise a different IP, and --bind-host 0.0.0.0 to listen
on all interfaces. See mcpv2.py --help for more.

You can also retrieve this help programmatically via GET /mcpv2/commands.
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
    try:
        resp = requests.get(f"http://{parsed['host']}:{parsed['port']}/mcpv2/session",
                            timeout=REQUEST_TIMEOUT)
        if resp.status_code == 200:
            return resp.json().get("sessionId")
    except Exception:
        pass
    return None

def _stop_peer(port_or_addr, quiet=False):
    port = None
    if isinstance(port_or_addr, int):
        port = port_or_addr
    elif isinstance(port_or_addr, str):
        if port_or_addr.startswith("mcpv2://"):
            parsed = parse_mcpv2_address(port_or_addr)
            if parsed:
                port = parsed["port"]
        elif port_or_addr.isdigit():
            port = int(port_or_addr)
    if port is None or port not in _running_peers:
        if not quiet:
            print(f"StopTo: no peer found on port {port_or_addr}")
        return False
    proc, _ = _running_peers.pop(port)
    if platform.system() == "Windows":
        proc.terminate()
    else:
        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
    if not quiet:
        print(f"Stopped peer on port {port}")
    return True

def _start_peer(port, secret, public_ip, llm_mode, bind_host=None):
    port_file = os.path.join(HERE, f".cli_port_{port}.txt")
    env = os.environ.copy()
    env["MCPV2_LLM_MODE"] = "1" if llm_mode else "0"
    cmd = [
        sys.executable, MCPV2_SCRIPT,
        "--port", str(port),
        "--secret", secret,
        "--public-ip", public_ip,
        "--log-level", "WARNING",
        "--port-file", port_file,
    ]
    if bind_host:
        cmd.extend(["--bind-host", bind_host])
    log_fh = open(port_file + ".log", "w")
    if platform.system() == "Windows":
        proc = subprocess.Popen(cmd, stdout=log_fh, stderr=subprocess.STDOUT,
                                creationflags=subprocess.CREATE_NEW_PROCESS_GROUP,
                                env=env)
    else:
        proc = subprocess.Popen(cmd, stdout=log_fh, stderr=subprocess.STDOUT,
                                preexec_fn=os.setsid, env=env)
    deadline = time.time() + 10
    bound_port = None
    while time.time() < deadline:
        if os.path.exists(port_file):
            content = open(port_file).read().strip()
            if content:
                bound_port = int(content)
                break
        if proc.poll() is not None:
            raise RuntimeError(f"Peer on port {port} exited early; see {port_file}.log")
        time.sleep(0.1)
    if bound_port is None:
        raise RuntimeError(f"Peer on port {port} never reported its bound port")
    deadline = time.time() + 10
    while time.time() < deadline:
        try:
            r = requests.get(f"http://{public_ip}:{bound_port}/health", timeout=1)
            if r.status_code == 200:
                return proc, bound_port
        except requests.exceptions.RequestException:
            pass
        time.sleep(0.1)
    raise RuntimeError(f"Peer on port {bound_port} did not become healthy in time")

def send_prompt(prompt: str, addr: str, provider: str = None):
    parsed = parse_mcpv2_address(addr)
    if not parsed:
        print("Invalid address.")
        return
    session_id = parsed["sessionId"]
    if not session_id:
        session_id = fetch_fresh_session(parsed)
    if not session_id:
        print("Could not obtain a valid sessionId.")
        return
    slot = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "ask", "arguments": {"query": prompt}}}
    if provider:
        slot["context"] = {"provider": provider}
    payload = [slot]
    headers = {"Content-Type": "application/json", "sessionId": session_id}
    try:
        resp = requests.post(f"http://{parsed['host']}:{parsed['port']}/mcpv2", json=payload, headers=headers, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        print("Response:", json.dumps(resp.json(), indent=2))
    except Exception as e:
        print(f"Error: {e}")

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
    session_id = parsed["sessionId"]
    if not session_id:
        session_id = fetch_fresh_session(parsed)
    if not session_id:
        print("Could not obtain a valid sessionId.")
        return
    filename = os.path.basename(filepath)
    slot = {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "upload_file", "arguments": {"filename": filename, "content_b64": content_b64}}}
    if provider:
        slot["context"] = {"provider": provider}
    payload = [slot]
    headers = {"Content-Type": "application/json", "sessionId": session_id}
    try:
        resp = requests.post(f"http://{parsed['host']}:{parsed['port']}/mcpv2", json=payload, headers=headers, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        print("Upload response:", json.dumps(resp.json(), indent=2))
    except Exception as e:
        print(f"Error: {e}")

def send_ping(addr: str):
    parsed = parse_mcpv2_address(addr)
    if not parsed:
        print("Invalid address.")
        return
    session_id = parsed["sessionId"]
    if not session_id:
        session_id = fetch_fresh_session(parsed)
    if not session_id:
        print("Could not obtain a valid sessionId.")
        return
    payload = [{"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "ping", "arguments": {"message": "ping"}}}]
    start = time.time()
    headers = {"Content-Type": "application/json", "sessionId": session_id}
    try:
        resp = requests.post(f"http://{parsed['host']}:{parsed['port']}/mcpv2", json=payload, headers=headers, timeout=10)
        end = time.time()
        resp.raise_for_status()
        print(f"Ping latency: {(end-start)*1000:.2f} ms")
        print("Response:", json.dumps(resp.json(), indent=2))
    except Exception as e:
        print(f"Error: {e}")

def send_payment(amount: float, addr: str):
    parsed = parse_mcpv2_address(addr)
    if not parsed:
        print("Invalid address.")
        return
    session_id = parsed["sessionId"]
    if not session_id:
        session_id = fetch_fresh_session(parsed)
    if not session_id:
        print("Could not obtain a valid sessionId.")
        return
    payload = [{"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "pay", "arguments": {"amount": amount, "currency": "USD", "recipient": "peer@example.com"}}}]
    headers = {"Content-Type": "application/json", "sessionId": session_id}
    try:
        resp = requests.post(f"http://{parsed['host']}:{parsed['port']}/mcpv2", json=payload, headers=headers, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        print("Payment response:", json.dumps(resp.json(), indent=2))
    except Exception as e:
        print(f"Error: {e}")

def parse_and_execute(cmd):
    parts = shlex.split(cmd)
    if not parts:
        return
    action = parts[0].lower()
    args = parts[1:]

    if action == "readyto":
        port = 8000
        secret = None
        public_ip = None
        llm_mode = False
        bind_host = None
        i = 0
        while i < len(args):
            if args[i] == "--port":
                if i+1 < len(args):
                    port = int(args[i+1]); i += 2
                else:
                    print("Missing port value."); return
            elif args[i] == "--secret":
                if i+1 < len(args):
                    secret = args[i+1]; i += 2
                else:
                    print("Missing secret value."); return
            elif args[i] == "--public-ip":
                if i+1 < len(args):
                    public_ip = args[i+1]; i += 2
                else:
                    print("Missing public-ip value."); return
            elif args[i] == "--llm-mode":
                llm_mode = True; i += 1
            elif args[i] == "--bind-host":
                if i+1 < len(args):
                    bind_host = args[i+1]; i += 2
                else:
                    print("Missing bind-host value."); return
            else:
                print(f"Unknown option: {args[i]}"); return
        if not secret:
            secret = "auto-" + base64.b64encode(os.urandom(16)).decode('ascii')[:12]
        if not public_ip:
            try:
                r = requests.get("https://api.ipify.org?format=json", timeout=5)
                public_ip = r.json().get("ip", "127.0.0.1")
            except Exception:
                public_ip = "127.0.0.1"
        try:
            proc, bound_port = _start_peer(port, secret, public_ip, llm_mode, bind_host)
            _running_peers[bound_port] = (proc, port)
            print(f"Peer is ready and healthy at mcpv2://{public_ip}:{bound_port}/mcpv2")
        except Exception as e:
            print(f"Failed to start peer: {e}")

    elif action in ("stopto", "stoppeer"):
        if not args:
            print(f"Usage: {action} <port|address>")
            return
        target = args[0]
        _stop_peer(target, quiet=False)

    elif action == "connectto":
        if not args:
            print("Usage: ConnectTo <address>")
            return
        addr = args[0]
        parsed = parse_mcpv2_address(addr)
        if not parsed:
            print("Invalid MCPv2 address.")
            return
        session_id = fetch_fresh_session(parsed)
        if not session_id:
            print("ConnectTo: failed to obtain a valid sessionId (peer unreachable or not healthy?)")
            return
        print(f"Connected to {parsed['host']}:{parsed['port']} (auth round trip successful)")

    elif action in ("sentto", "sendto"):
        provider = None
        content = None
        addr = None
        i = 0
        while i < len(args):
            if args[i] == "--provider":
                if i+1 < len(args):
                    provider = args[i+1]; i += 2
                else:
                    print("Missing provider value."); return
            else:
                if content is None:
                    content = args[i]
                elif addr is None:
                    addr = args[i]
                else:
                    print("Too many arguments.")
                    return
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
        addr = args[1]
        send_payment(amount, addr)

    elif action == "pingto":
        if not args:
            print("Usage: PingTo <address>")
            return
        addr = args[0]
        send_ping(addr)

    else:
        print("Unknown command. Type 'help'.")

if __name__ == "__main__":
    main()