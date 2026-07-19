#!/usr/bin/env python3
"""
MCPv2 CLI - Full Interactive Command Interface with Provider Support.
"""

import os
import sys
import json
import time
import base64
from typing import Optional
import requests
from urllib.parse import urlparse, parse_qs

try:
    import readline  # noqa: F401  (nice-to-have on POSIX; optional on Windows)
except ImportError:
    pass

REQUEST_TIMEOUT = 30


def main():
    print("MCPv2 CLI - Full P2P AI Agent Control (Cross-Provider)")
    print("Type a command or 'help'")
    while True:
        try:
            cmd = input("mcpv2> ").strip()
            if not cmd:
                continue
            if cmd.lower() in ("exit", "quit"):
                break
            if cmd.lower() == "help":
                print_help()
                continue
            parse_and_execute(cmd)
        except KeyboardInterrupt:
            print("\nExiting.")
            break
        except Exception as e:
            print(f"Error: {e}")


def print_help():
    print("""
Commands:
  ConnectTo <mcpv2_address>       - Validate a remote peer address.
  SentTo <content_or_file> <addr> [--provider <provider>] - Send prompt or file.
  PayTo <amount> <addr>           - Request a (stub) payment.
  PingTo <addr>                   - Test connectivity and latency.
  SendTo ...                      - Alias for SentTo.
  help                            - Show this help.
  exit/quit                       - Exit.

Address format: mcpv2://host:port/mcpv2?sessionId=<optional>
Provider flags: --provider claude|openai|gemini|deepseek

Note: this CLI is a client only. Start a peer separately with:
  python mcpv2.py --port 8000 --secret <shared_secret>
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


def resolve_session(parsed: dict) -> Optional[str]:
    """Return a usable sessionId for this address, fetching one if needed."""
    if parsed.get("sessionId"):
        return parsed["sessionId"]
    try:
        resp = requests.get(f"http://{parsed['host']}:{parsed['port']}/mcpv2/session",
                            timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        return resp.json().get("sessionId")
    except requests.exceptions.RequestException as e:
        print(f"Could not obtain a sessionId: {e}")
        return None


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


def parse_and_execute(cmd):
    parts = cmd.split()
    if not parts:
        return
    action = parts[0].lower()
    args = parts[1:]

    if action == "connectto":
        if not args:
            print("Usage: ConnectTo <address>")
            return
        parsed = parse_mcpv2_address(args[0])
        if not parsed:
            print("Invalid MCPv2 address.")
            return
        try:
            resp = requests.get(f"http://{parsed['host']}:{parsed['port']}/health", timeout=5)
            resp.raise_for_status()
            print(f"Connected to {parsed['host']}:{parsed['port']} - peer healthy.")
        except requests.exceptions.RequestException as e:
            print(f"Address parses, but peer is unreachable: {e}")

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
