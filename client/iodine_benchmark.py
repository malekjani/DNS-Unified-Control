#!/usr/bin/env python3
"""Iodine DNS tunnel diagnostic benchmark (client side, Python stdlib only).

Runs one iodine client at a time, with no default route or server changes.
The iodine password is read once with no echo and passed on stdin, never argv.
"""

from __future__ import annotations

import datetime as dt
import getpass
import os
import pathlib
import pwd
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass

DOMAIN = os.environ.get("DUC_IODINE_DOMAIN", "").strip()
SERVER_TUN_IP = "10.78.0.1"
INTERFACE = "dnsbench0"
START_TIMEOUT = 75
PING_COUNT = 12
BIG_PING_COUNT = 6
BIG_PING_BYTES = 900

@dataclass(frozen=True)
class Profile:
    label: str
    resolver: str
    args: tuple[str, ...]

PROFILES = [
    Profile("01 CF baseline NULL/auto", "1.1.1.1", ("-Tnull",)),
    Profile("02 CF NULL I1", "1.1.1.1", ("-Tnull", "-I1")),
    Profile("03 CF NULL I1 M200", "1.1.1.1", ("-Tnull", "-I1", "-M200")),
    Profile("04 CF NULL M200 frag900", "1.1.1.1", ("-Tnull", "-I1", "-M200", "-m900")),
    Profile("05 CF NULL M200 frag700", "1.1.1.1", ("-Tnull", "-I1", "-M200", "-m700")),
    Profile("06 CF NULL legacy L0", "1.1.1.1", ("-Tnull", "-L0", "-M200")),
    Profile("07 CF TXT M200 frag700", "1.1.1.1", ("-Ttxt", "-I1", "-M200", "-m700")),
    Profile("08 CF TXT M200 frag900", "1.1.1.1", ("-Ttxt", "-I1", "-M200", "-m900")),
    Profile("09 Google NULL M200 auto", "8.8.8.8", ("-Tnull", "-I1", "-M200")),
    Profile("10 Google NULL M200 frag900", "8.8.8.8", ("-Tnull", "-I1", "-M200", "-m900")),
]

active_process = None


def stop_client():
    global active_process
    p = active_process
    active_process = None
    if p is None:
        return
    if p.poll() is None:
        try:
            os.killpg(p.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            p.wait(timeout=5)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(p.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            p.wait(timeout=5)
    else:
        p.wait()


def on_signal(signum, frame):
    print("\nInterrupted; stopping only the iodine client started by this script.", flush=True)
    stop_client()
    raise SystemExit(128 + signum)


def command_ok(args):
    return subprocess.run(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0


def parse_ping(output):
    m = re.search(r"(\d+)\s+packets? transmitted,\s*(\d+)\s+(?:packets? )?received,\s*([\d.]+)% packet loss", output)
    if not m:
        return {"sent": 0, "received": 0, "loss": None, "avg": None}
    r = re.search(r"(?:rtt|round-trip) min/avg/max/(?:mdev|stddev)\s*=\s*[\d.]+/([\d.]+)/", output)
    return {
        "sent": int(m.group(1)),
        "received": int(m.group(2)),
        "loss": float(m.group(3)),
        "avg": float(r.group(1)) if r else None,
    }


def ping_test(size):
    args = ["ping", "-n", "-I", INTERFACE, "-c", str(PING_COUNT if size == 56 else BIG_PING_COUNT),
            "-i", "1", "-W", "3", "-w", "30", "-s", str(size), SERVER_TUN_IP]
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=35)
        return parse_ping(r.stdout + "\n" + r.stderr)
    except subprocess.TimeoutExpired:
        return {"sent": 0, "received": 0, "loss": None, "avg": None}


def status_line(result):
    return "n/a" if result["loss"] is None else f"{result['loss']:5.1f}% ({result['received']}/{result['sent']})"


def start_client(profile, password, logpath):
    global active_process
    args = ["iodine", "-f", "-r", "-d", INTERFACE, *profile.args, profile.resolver, DOMAIN]
    with open(logpath, "wb") as log:
        p = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=log, stderr=subprocess.STDOUT,
                             start_new_session=True)
    active_process = p
    try:
        # Per iodine manual: without -P, password is read from stdin.
        p.stdin.write(password.encode("utf-8") + b"\n")
        p.stdin.flush()
    except BrokenPipeError:
        pass
    finally:
        p.stdin.close()

    until = time.monotonic() + START_TIMEOUT
    while time.monotonic() < until:
        contents = logpath.read_text(encoding="utf-8", errors="replace")
        if "Connection setup complete" in contents and command_ok(["ip", "link", "show", "dev", INTERFACE]):
            return True, args
        if p.poll() is not None:
            return False, args
        time.sleep(0.5)
    return False, args


def safe_float(x):
    return f"{x:.1f}" if x is not None else "n/a"


def make_report(results, report_path):
    now = dt.datetime.now().isoformat(timespec="seconds")
    lines = [
        "IODINE DNS BENCHMARK — CLIENT SIDE",
        f"Generated: {now}",
        f"Domain: {DOMAIN}, server tunnel IP: {SERVER_TUN_IP}, device: {INTERFACE}",
        f"Sample: {PING_COUNT} small ICMP pings (56 bytes) + {BIG_PING_COUNT} large ICMP pings ({BIG_PING_BYTES} bytes) per profile",
        "Password: NOT STORED. No server configuration or default route changed.",
        "NOTE: Brief pings are screening tests, not long-term reliability/throughput measurements.",
        "",
        "PROFILE | START | SMALL LOSS | BIG LOSS | AVG RTT ms (small) | SERVFAIL | DNS FRAGMENT",
    ]
    for r in results:
        lines.append(f"{r['name']} | {r['state']} | {status_line(r['small'])} | {status_line(r['big'])} | "
                     f"{safe_float(r['small']['avg'])} | {r['servfail']} | {r['fragment']}")
    valid = [r for r in results if r["state"] == "READY" and r["small"]["loss"] is not None
             and r["big"]["loss"] is not None]
    if valid:
        valid.sort(key=lambda r: ((r['small']['loss'] + r['big']['loss']) / 2,
                                  r['servfail'], r['small']['avg'] if r['small']['avg'] is not None else 999999))
        lines.extend(["", "TOP 3 CANDIDATES (lower loss first; confirm with longer repeat tests):"])
        for r in valid[:3]:
            lines.append(f"  {r['name']}: small={r['small']['loss']:.1f}%, "
                         f"big={r['big']['loss']:.1f}%, avg={safe_float(r['small']['avg'])}ms")
    lines.append("")
    lines.append("DETAILS:")
    for r in results:
        lines.extend([f"[{r['name']}]", f"resolver: {r['resolver']}",
                      "args: " + " ".join(r['args']),
                      f"state: {r['state']} | SERVFAIL: {r['servfail']} | fragmentsize: {r['fragment']}"])
        if r['state'] != 'READY':
            lines.extend(["last log lines:", *r['tail']])
        lines.append("")
    report_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    os.chmod(report_path, 0o600)
    sudo_user = os.getenv("SUDO_USER")
    if sudo_user and sudo_user != "root":
        pw = pwd.getpwnam(sudo_user)
        os.chown(report_path, pw.pw_uid, pw.pw_gid)
    return "\n".join(lines)


def main():
    if not DOMAIN or not re.fullmatch(r'[a-z0-9-]+(?:\.[a-z0-9-]+)+', DOMAIN):
        sys.exit('Specify your own tunnel zone: DUC_IODINE_DOMAIN=i.YOUR_DOMAIN sudo -E python3 iodine_benchmark.py')
    if os.geteuid() != 0:
        sys.exit("Run with sudo: sudo python3 iodine_benchmark.py")
    for name in ("iodine", "ping", "ip", "pgrep"):
        if not shutil.which(name):
            sys.exit(f"Missing command: {name}")
    existing = subprocess.run(["pgrep", "-x", "iodine"], capture_output=True, text=True)
    if existing.returncode == 0:
        print("An iodine client is already running. Stop it with Ctrl+C, then rerun this tool.")
        print("Running iodine PID(s):", ", ".join(existing.stdout.split()))
        sys.exit(2)
    if command_ok(["ip", "link", "show", "dev", INTERFACE]):
        sys.exit(f"Device {INTERFACE} already exists; stopping without changes.")
    signal.signal(signal.SIGINT, on_signal)
    signal.signal(signal.SIGTERM, on_signal)
    password = getpass.getpass("Iodine shared password (hidden; never saved): ")
    if not password:
        sys.exit("Empty password. Aborted.")
    try:
        base = pwd.getpwnam(os.environ.get("SUDO_USER") or "root").pw_dir
    except KeyError:
        base = str(pathlib.Path.home())
    report_path = pathlib.Path(base) / f"iodine-benchmark-{dt.datetime.now():%Y%m%d-%H%M%S}.txt"
    results = []
    print(f"\nBenchmarking {len(PROFILES)} profiles. Existing connections and default routes will not be modified.")
    try:
        with tempfile.TemporaryDirectory(prefix="iodine-benchmark-") as t:
            for ix, profile in enumerate(PROFILES, 1):
                print(f"\n[{ix}/{len(PROFILES)}] {profile.label}", flush=True)
                logpath = pathlib.Path(t) / f"{ix:02d}.log"
                state = "START_FAILED"
                small = {"sent": 0, "received": 0, "loss": None, "avg": None}
                big = small.copy()
                try:
                    connected, _ = start_client(profile, password, logpath)
                    if connected:
                        state = "READY"
                        time.sleep(1)
                        small = ping_test(56)
                        big = ping_test(BIG_PING_BYTES)
                    else:
                        state = "START_FAILED_OR_TIMEOUT"
                except Exception as e:
                    state = "ERROR_" + type(e).__name__
                finally:
                    stop_client()
                    # Avoid reusing a disappearing interface across profiles.
                    for _ in range(20):
                        if not command_ok(["ip", "link", "show", "dev", INTERFACE]):
                            break
                        time.sleep(0.25)
                logtext = logpath.read_text(encoding="utf-8", errors="replace") if logpath.exists() else ""
                m = re.search(r"Setting downstream fragment size to max (\d+)", logtext)
                frag = m.group(1) if m else (next((a[2:] for a in profile.args if a.startswith("-m")), "auto/unknown"))
                result = {"name": profile.label, "resolver": profile.resolver, "args": profile.args,
                          "state": state, "small": small, "big": big, "servfail": logtext.count("SERVFAIL"),
                          "fragment": frag, "tail": logtext.strip().splitlines()[-8:]}
                results.append(result)
                print(f"    {state} | small: {status_line(small)} | large: {status_line(big)} "
                      f"| avg: {safe_float(small['avg'])}ms | SERVFAIL: {result['servfail']} | frag: {frag}", flush=True)
    finally:
        stop_client()
    report = make_report(results, report_path)
    print("\n" + "=" * 70 + "\n" + report)
    print(f"Report saved: {report_path}")
    print("You can paste the report contents here; it does not include the iodine password.")


if __name__ == "__main__":
    main()
