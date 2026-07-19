#!/usr/bin/env python3
"""
Basic MCPv2 file transfer smoke test with Provider Support.

This is the simple, original-style smoke test (kept for quick manual runs).
For the full multi-scenario suite (many iterations, many kinds of exchanges,
error paths, security checks) see test_scenarios.py - run that in CI.
"""

import subprocess
import time
import requests
import json
import sys
import os
import signal
import platform
import base64

PEER1_PORT = 8000
PEER2_PORT = 8001
SECRET = "testsecret"
PEER_IP = "127.0.0.1"


def start_peer(port, secret, public_ip, port_file, llm_mode=False):
    python = sys.executable
    script = os.path.join(os.path.dirname(os.path.abspath(__file__)), "mcpv2.py")
    env = os.environ.copy()
    env["MCPV2_LLM_MODE"] = "1" if llm_mode else "0"
    cmd = [
        python, script,
        "--port", str(port),
        "--secret", secret,
        "--bind-host", "0.0.0.0",
        "--public-ip", public_ip,
        "--log-level", "WARNING",
        "--port-file", port_file,
    ]
    log_fh = open(port_file + ".log", "w")
    if platform.system() == "Windows":
        proc = subprocess.Popen(cmd, stdout=log_fh, stderr=subprocess.STDOUT,
                                creationflags=subprocess.CREATE_NEW_PROCESS_GROUP, env=env)
    else:
        proc = subprocess.Popen(cmd, stdout=log_fh, stderr=subprocess.STDOUT,
                                preexec_fn=os.setsid, env=env)

    # Discover the ACTUAL bound port (fixes: this used to just assume the
    # requested port was the bound port, which silently broke if that port
    # was already in use).
    deadline = time.time() + 10
    bound_port = None
    while time.time() < deadline:
        if os.path.exists(port_file):
            content = open(port_file).read().strip()
            if content:
                bound_port = int(content)
                break
        if proc.poll() is not None:
            raise RuntimeError(f"Peer on requested port {port} exited early; see {port_file}.log")
        time.sleep(0.1)
    if bound_port is None:
        raise RuntimeError(f"Peer on requested port {port} never reported its bound port")

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


def stop_peer(proc):
    if platform.system() == "Windows":
        proc.terminate()
    else:
        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)


def send_slot(target_url, session_id, slot):
    headers = {"Content-Type": "application/json", "sessionId": session_id}
    resp = requests.post(target_url, json=[slot], headers=headers)
    resp.raise_for_status()
    data = resp.json()
    return data[0] if data else None


def main():
    sample_md = """# Instructions for AI Agent

1. Greet the user politely.
2. Answer questions concisely.
3. Provide references when available.
"""
    with open("instructions.md", "w") as f:
        f.write(sample_md)

    with open("instructions.md", "r") as f:
        content = f.read()
    content_b64 = base64.b64encode(content.encode()).decode()

    p1_file = os.path.abspath(".port1.txt")
    p2_file = os.path.abspath(".port2.txt")
    for f in (p1_file, p2_file):
        if os.path.exists(f):
            os.remove(f)

    p1, port1 = start_peer(PEER1_PORT, SECRET, PEER_IP, p1_file, llm_mode=False)
    p2, port2 = start_peer(PEER2_PORT, SECRET, PEER_IP, p2_file, llm_mode=True)

    try:
        resp1 = requests.get(f"http://{PEER_IP}:{port1}/mcpv2/session")
        resp1.raise_for_status()
        session_p1 = resp1.json()["sessionId"]

        print("=" * 80)
        print("MCPv2 File Transfer & Execution Test")
        print("=" * 80)

        slot1 = {
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {"name": "upload_file",
                       "arguments": {"filename": "instructions.md", "content_b64": content_b64}},
            "context": {"provider": "claude"}
        }
        print(f"\n[Peer 1 -> Peer 2 (port {port2})] Uploading instructions.md...")
        resp = send_slot(f"http://{PEER_IP}:{port2}/mcpv2", session_p1, slot1)
        print(f"[Peer 2 -> Peer 1] Upload: {resp['result']['content'][0]['text']}")

        slot3 = {
            "jsonrpc": "2.0", "id": 3, "method": "tools/call",
            "params": {"name": "process_instructions", "arguments": {"filename": "instructions.md"}}
        }
        print("\n[Peer 1 -> Peer 2] Processing instructions.md...")
        resp3 = send_slot(f"http://{PEER_IP}:{port2}/mcpv2", session_p1, slot3)
        print("[Peer 2 -> Peer 1] Processed:")
        print(resp3['result']['content'][0]['text'])

        print("\nFile transfer test passed.")

    except Exception as e:
        print(f"Test failed: {e}")
        raise
    finally:
        stop_peer(p1)
        stop_peer(p2)
        for f in (p1_file, p2_file):
            if os.path.exists(f):
                os.remove(f)
        if os.path.exists("instructions.md"):
            os.remove("instructions.md")


if __name__ == "__main__":
    main()
