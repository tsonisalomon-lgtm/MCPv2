#!/usr/bin/env python3
"""
MCPv2 CLI test suite.

Drives mcpv2_cli.py exactly the way a person would - by piping commands
into its interactive prompt via stdin - and asserts on what it prints.
This is deliberately black-box: it doesn't import CLI internals, it runs
the actual `python mcpv2_cli.py` process, because that's the only way to
be sure the interactive loop, argument parsing, and subprocess lifecycle
management all genuinely work together end to end.

Covers every command: help, ReadyTo, StopTo (+ the StopPeer alias, +
both its "by port" and "by address" forms), ConnectTo (fresh-session and
stale-session-in-address paths), SentTo/SendTo (prompt and file upload),
PayTo, PingTo, an unknown command, and exit's automatic peer cleanup -
including confirming a peer stopped via StopTo (or via exit) is actually
dead afterward, not just reported as stopped.
"""

import os
import subprocess
import sys
import time
import socket

import requests

HERE = os.path.dirname(os.path.abspath(__file__))
CLI = os.path.join(HERE, "mcpv2_cli.py")
PYTHON = sys.executable

PASS = []
FAIL = []


def record(name, ok, detail=""):
    (PASS if ok else FAIL).append((name, detail))
    mark = "PASS" if ok else "FAIL"
    print(f"  [{mark}] {name}" + (f" -- {detail}" if detail and not ok else ""))


def free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def run_cli(script_lines, timeout=40):
    """Run mcpv2_cli.py with the given lines fed to stdin, return stdout."""
    stdin_text = "\n".join(script_lines) + "\n"
    proc = subprocess.run([PYTHON, CLI], input=stdin_text, capture_output=True,
                          text=True, timeout=timeout, cwd=HERE)
    return proc.stdout + proc.stderr


def port_is_free(port, host="127.0.0.1"):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind((host, port))
            return True
        except OSError:
            return False


def main():
    upload_target = os.path.join(HERE, "_cli_test_upload.md")
    with open(upload_target, "w") as f:
        f.write("# CLI test upload\nThis file exercises SentTo's upload path.\n")

    # -------------------------------------------------------------
    # Session 1: help + full happy-path command tour on one peer,
    # then StopTo by bare port number.
    # -------------------------------------------------------------
    port1 = free_port()
    addr1 = f"mcpv2://127.0.0.1:{port1}/mcpv2"
    out = run_cli([
        "help",
        f"ReadyTo --port {port1} --secret clitestsecret --public-ip 127.0.0.1",
        f"PingTo {addr1}",
        f"ConnectTo {addr1}",
        f"SentTo \"hello from the cli test\" {addr1}",
        f"SentTo {upload_target} {addr1}",
        f"PayTo 12.5 {addr1}",
        "totally_unknown_command",
        f"StopTo {port1}",
        "exit",
    ])

    record("help lists all commands",
           all(c in out for c in ["ReadyTo", "StopTo", "ConnectTo", "SentTo", "PayTo", "PingTo", "SendTo"]))
    record("ReadyTo starts peer and prints address", "Peer is ready and healthy" in out and addr1 in out)
    record("PingTo returns latency + echo", "Ping latency" in out and "'echo': 'ping'" in out)
    record("ConnectTo succeeds with real auth round trip",
           "ConnectTo SUCCESS" in out and "Skills:" in out and "ping" in out)
    record("SentTo prompt gets an ask response", "Generic response to: hello from the cli test" in out)
    record("SentTo file uploads successfully",
           "Upload response" in out and "'status': 'success'" in out and "_cli_test_upload.md" in out)
    record("PayTo returns stub pending status", "Payment (stub) response" in out and "'pending'" in out)
    record("Unknown command handled gracefully", "Unknown command. Type 'help'." in out)
    record("StopTo (by port) reports stopped", f"Stopped peer on port {port1}." in out)

    # The stop happened mid-session (before exit); confirm the OS port is
    # actually free again, i.e. the process really died, not just that we
    # printed a success message.
    time.sleep(0.5)
    record("StopTo actually kills the process (port free again)", port_is_free(port1))

    # -------------------------------------------------------------
    # Session 2: StopTo by full mcpv2:// address (not just a bare port),
    # and the StopPeer alias.
    # -------------------------------------------------------------
    port2 = free_port()
    addr2 = f"mcpv2://127.0.0.1:{port2}/mcpv2"
    out2 = run_cli([
        f"ReadyTo --port {port2} --secret clitestsecret2 --public-ip 127.0.0.1",
        f"StopTo {addr2}",   # stop by ADDRESS, not port number
        "exit",
    ])
    record("ReadyTo (session 2) starts peer", "Peer is ready and healthy" in out2)
    record("StopTo accepts a full mcpv2:// address (not just a port)",
           f"Stopped peer on port {port2}." in out2)
    time.sleep(0.5)
    record("StopTo-by-address actually kills the process", port_is_free(port2))

    port3 = free_port()
    addr3 = f"mcpv2://127.0.0.1:{port3}/mcpv2"
    out3 = run_cli([
        f"ReadyTo --port {port3} --secret clitestsecret3 --public-ip 127.0.0.1",
        f"StopPeer {port3}",  # backward-compatible alias
        "exit",
    ])
    record("StopPeer alias still works", f"Stopped peer on port {port3}." in out3)
    time.sleep(0.5)
    record("StopPeer-alias actually kills the process", port_is_free(port3))

    # -------------------------------------------------------------
    # Session 3: exit's automatic cleanup, WITHOUT an explicit StopTo -
    # a peer left running should still be killed when the CLI exits.
    # -------------------------------------------------------------
    port4 = free_port()
    out4 = run_cli([
        f"ReadyTo --port {port4} --secret clitestsecret4 --public-ip 127.0.0.1",
        "exit",
    ])
    record("exit reports auto-stopping untracked-by-hand peers",
           "Stopping 1 peer(s) started by ReadyTo" in out4)
    time.sleep(0.5)
    record("exit's automatic cleanup actually kills the process", port_is_free(port4))

    # -------------------------------------------------------------
    # Session 4: ConnectTo against a stale/invalid sessionId embedded in
    # the address - should detect the 401, transparently fetch a fresh
    # session, retry, and still report success.
    # -------------------------------------------------------------
    port5 = free_port()
    addr5 = f"mcpv2://127.0.0.1:{port5}/mcpv2"
    stale_addr5 = f"{addr5}?sessionId=not-a-real-session-id"
    out5 = run_cli([
        f"ReadyTo --port {port5} --secret clitestsecret5 --public-ip 127.0.0.1",
        f"ConnectTo {stale_addr5}",
        f"StopTo {port5}",
        "exit",
    ])
    record("ConnectTo recovers from a stale session in the address",
           "rejected (401); fetching a fresh one and retrying" in out5 and "ConnectTo SUCCESS" in out5)

    # -------------------------------------------------------------
    # Session 5: ConnectTo against nothing listening at all - clear,
    # specific failure message, not a stack trace or a hang.
    # -------------------------------------------------------------
    dead_port = free_port()  # never started
    out6 = run_cli([f"ConnectTo mcpv2://127.0.0.1:{dead_port}/mcpv2", "exit"])
    record("ConnectTo reports a clear failure when nothing is listening",
           "ConnectTo FAILED" in out6 and "unreachable" in out6)

    # -------------------------------------------------------------
    # Session 6: SendTo alias (not SentTo) works identically.
    # -------------------------------------------------------------
    port6 = free_port()
    addr6 = f"mcpv2://127.0.0.1:{port6}/mcpv2"
    out7 = run_cli([
        f"ReadyTo --port {port6} --secret clitestsecret6 --public-ip 127.0.0.1",
        f"SendTo \"alias check\" {addr6}",
        f"StopTo {port6}",
        "exit",
    ])
    record("SendTo alias works the same as SentTo", "Generic response to: alias check" in out7)

    if os.path.exists(upload_target):
        os.remove(upload_target)

    print("=" * 60)
    print(f"TOTAL: {len(PASS)} passed, {len(FAIL)} failed")
    if FAIL:
        print("\nFailures:")
        for name, detail in FAIL:
            print(f"  - {name}: {detail}")
        sys.exit(1)
    else:
        print("All CLI checks passed.")
        sys.exit(0)


if __name__ == "__main__":
    main()
