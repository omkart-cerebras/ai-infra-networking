#!/usr/bin/env python3
"""
Discover hostnames behind console-server ports.

Flow per port:
  ssh root:portNN@<console_ip>
    -> Password:
       send password (from YAML)
       press Enter twice
    -> <hostname> login:
       extract hostname
       terminate session using <Enter>~.

Non-responsive ports are skipped without stopping the script.

The yaml file format should be as follows:


default_password: "your_default_password"
console_servers:
  - name: "your_console_server_name"
    ip: "your_console_server_ip"
    password: "your_console_server_password"
    - name: "another_console_server_name"
      ip: "another_console_server_ip"
      password: "another_console_server_password"



Requirements:
  pip install pyyaml pexpect tabulate
"""

from __future__ import annotations

import argparse
import csv
import logging
import re
import time
from dataclasses import dataclass
from datetime import datetime
from typing import Dict, List

import yaml
import pexpect
from tabulate import tabulate


# Matches: "<hostname> login:"
LOGIN_PROMPT_RE = re.compile(
    r"(?m)^\s*([A-Za-z0-9][A-Za-z0-9._-]{0,62})\s+login:\s*$"
)


@dataclass
class Result:
    console_server: str
    console_ip: str
    port: str
    username: str
    hostname: str
    notes: str


# ---------------- Logging ----------------

def setup_logging(verbosity: int) -> None:
    level = logging.WARNING
    if verbosity == 1:
        level = logging.INFO
    elif verbosity >= 2:
        level = logging.DEBUG

    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(message)s",
    )


# ---------------- YAML ----------------

def load_yaml(path: str) -> List[Dict[str, str]]:
    logging.info("Loading YAML: %s", path)

    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}

    servers = data.get("console_servers", [])
    default_pw = data.get("default_password")

    if not servers:
        raise ValueError("YAML must contain 'console_servers' list")

    out = []
    for s in servers:
        name = s.get("name", s["ip"])
        pw = s.get("password", default_pw)
        if not pw:
            raise ValueError(f"Password missing for console server {name}")

        out.append({
            "name": str(name),
            "ip": str(s["ip"]),
            "password": str(pw),
        })

    logging.info("Loaded %d console servers", len(out))
    return out


# ---------------- Session termination ----------------

def terminate_console_session(child: pexpect.spawn, timeout: int = 2) -> None:
    """
    Terminate SSH session using:
      <Enter>
      ~.
    """
    logging.debug("Terminating console session using <Enter>~.")
    try:
        child.send("\r")
        child.send("~.")
        child.expect(pexpect.EOF, timeout=timeout)
    except Exception:
        try:
            child.close(force=True)
        except Exception:
            pass


# ---------------- Port probe ----------------

def probe_port(
    console_name: str,
    console_ip: str,
    password: str,
    port_num: int,
    *,
    timeout: int,
    term_timeout: int,
    max_steps: int,
    debug_trace: bool = False,
) -> Result:
    """
    Probe a single console port:
      - ssh root:portNN@console_ip
      - handle banners + hostkey prompts
      - send password when prompted
      - AFTER password: press Enter twice to reach "<hostname> login:"
      - extract hostname from "<hostname> login:"
      - terminate session using <Enter>~.
    """
    port = f"{port_num:02d}"
    user = f"root:port{port}"

    # SSH options help avoid interactive known_hosts prompts and speed up failures
    ssh_cmd = (
        f"ssh -o StrictHostKeyChecking=no "
        f"-o UserKnownHostsFile=/dev/null "
        f"-o ConnectTimeout={max(3, min(timeout, 30))} "
        f"{user}@{console_ip}"
    )

    print(f"  • Trying port {port}")
    logging.info("[%s %s] Probing port %s (cmd=%s)", console_name, console_ip, port, ssh_cmd)

    child = pexpect.spawn(ssh_cmd, encoding="utf-8", timeout=timeout, echo=False)

    # If enabled, dump all remote output to stdout (useful for troubleshooting)
    if debug_trace:
        import sys
        child.logfile_read = sys.stdout

    # Robust patterns (banner-friendly, not fragile)
    HOSTKEY_PROMPT_RE = re.compile(r"(?is)(are you sure you want to continue connecting|authenticity of host)")
    YESNO_PROMPT_RE = re.compile(r"(?is)\(yes/no.*\)\s*$")
    PASSWORD_PROMPT_RE = re.compile(r"(?i)(?:\([^)]*\)\s*)?password:\s*")  # matches "(ssh ...) Password:" too
    LOGIN_PROMPT_RE = re.compile(r"(?m)^\s*([A-Za-z0-9][A-Za-z0-9._-]{0,62})\s+login:\s*$")

    patterns = [
        HOSTKEY_PROMPT_RE,                                # 0
        YESNO_PROMPT_RE,                                  # 1
        PASSWORD_PROMPT_RE,                               # 2
        LOGIN_PROMPT_RE,                                  # 3  (captures hostname)
        r"(?i)permission denied",                         # 4
        r"(?i)remote host identification has changed",     # 5
        r"(?i)connection (?:timed out|closed|refused)",    # 6
        r"(?i)no route to host",                           # 7
        r"(?i)could not resolve hostname",                 # 8
        pexpect.TIMEOUT,                                   # 9
        pexpect.EOF,                                       # 10
    ]

    # Track if we already authenticated so we can "nudge" the console again if needed
    password_sent = False

    try:
        for _ in range(max_steps):
            idx = child.expect(patterns, timeout=timeout)

            if idx in (0, 1):
                logging.debug("[%s %s port %s] Hostkey/yes-no prompt -> sending 'yes'", console_name, console_ip, port)
                print(f"  • Port {port} → accepting hostkey")
                child.sendline("yes")
                continue

            if idx == 2:
                logging.debug("[%s %s port %s] Password prompt -> sending password", console_name, console_ip, port)
                print(f"  • Port {port} → sending password")
                child.sendline(password)
                password_sent = True

                # REQUIRED in your environment: press Enter twice after password
                time.sleep(0.3)
                child.send("\r")
                time.sleep(0.2)
                child.send("\r")
                continue
            
            if idx == 3:
                # Try standard "<hostname> login:" match first
                hostname = child.match.group(1)
                print(f"  ✓ Port {port} → device hostname: {hostname}")
                logging.info("[%s %s] SUCCESS port %s -> %s", console_name, console_ip, port, hostname)

                terminate_console_session(child, timeout=term_timeout)
                return Result(console_name, console_ip, port, user, hostname, "ok")

            # Additional pattern: FreeBSD/arm (hostname) (ttyu0)
            # Look for this pattern in the output if not matched above
            after_str = child.after if isinstance(child.after, str) else ""
            output = child.before + after_str
            m = re.search(r"FreeBSD/\w+\s+\(([^)]+)\)\s+\(ttyu\d+\)", output)
            if m:
                hostname = m.group(1)
                print(f"  ✓ Port {port} → device hostname: {hostname}")
                logging.info("[%s %s] SUCCESS port %s -> %s (FreeBSD pattern)", console_name, console_ip, port, hostname)

                terminate_console_session(child, timeout=term_timeout)
                return Result(console_name, console_ip, port, user, hostname, "ok")

            if idx == 4:
                print(f"  ✗ Port {port} → auth failed")
                return Result(console_name, console_ip, port, user, "", "auth_failed")

            if idx == 5:
                print(f"  ✗ Port {port} → hostkey changed")
                return Result(console_name, console_ip, port, user, "", "hostkey_changed")

            if idx in (6, 7, 8):
                print(f"  ✗ Port {port} → unreachable")
                return Result(console_name, console_ip, port, user, "", "unreachable")

            if idx == 9:
                # If we've already sent password, some consoles need extra "Enter" nudges
                if password_sent:
                    logging.warning("[%s %s] TIMEOUT after password on port %s -> sending Enter x2 again",
                                    console_name, console_ip, port)
                    child.send("\r")
                    child.send("\r")
                    continue

                print(f"  ✗ Port {port} → timeout")
                return Result(console_name, console_ip, port, user, "", "timeout")

            if idx == 10:
                print(f"  ✗ Port {port} → EOF")
                return Result(console_name, console_ip, port, user, "", "eof")

        print(f"  ✗ Port {port} → exceeded steps")
        return Result(console_name, console_ip, port, user, "", "steps_exceeded")

    except Exception as e:
        logging.exception("[%s %s] ERROR on port %s: %s", console_name, console_ip, port, type(e).__name__)
        print(f"  ✗ Port {port} → error ({type(e).__name__})")
        return Result(console_name, console_ip, port, user, "", f"error:{type(e).__name__}")

    finally:
        try:
            child.close(force=True)
        except Exception:
            pass



# ---------------- Main ----------------

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("-y", "--yaml", required=True)
    ap.add_argument("--timeout", type=int, default=8)
    ap.add_argument("--term-timeout", type=int, default=10)
    ap.add_argument("--max-port", type=int, default=32)
    ap.add_argument("--steps", type=int, default=3)
    ap.add_argument("--csv", default="")
    ap.add_argument("-v", "--verbose", action="count", default=0)

    args = ap.parse_args()
    setup_logging(args.verbose)

    servers = load_yaml(args.yaml)
    results: List[Result] = []

    for s in servers:
        for p in range(1, args.max_port + 1):
            r = probe_port(
                s["name"],
                s["ip"],
                s["password"],
                p,
                timeout=args.timeout,
                term_timeout=args.term_timeout,
                max_steps=args.steps,
            )
            if r.notes == "ok":
                results.append(r)

    print(tabulate(
        [[r.console_server, r.console_ip, r.port, r.hostname] for r in results],
        headers=["Console Server", "IP", "Port", "Device Hostname"],
        tablefmt="github"
    ))

    out_csv = args.csv or f"console_discovery_{datetime.now():%Y%m%d_%H%M%S}.csv"
    with open(out_csv, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["console_server", "console_ip", "port", "ssh_user", "hostname"])
        for r in results:
            w.writerow([r.console_server, r.console_ip, r.port, r.username, r.hostname])

    print(f"\nSaved CSV: {out_csv}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
