#!/usr/bin/env python3
# Copyright (c) 2026 The Innova developers
"""Verify that every harness honours IV5_TEST_PORT_BASE.

A grep for the variable name passes on a tree where nothing reads it, so this
evaluates each harness's port assignments under two different bases and compares
the numbers that come out.

Checks per harness that launches a daemon:
  1. it sources lib/testports.sh
  2. every port-shaped assignment routes through iv5_port
  3. with no base set, the ports are exactly the historical literals
  4. with a base set, every port lands inside that base's window
  5. two different bases produce two disjoint sets of ports
"""
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
TESTS = ROOT / "contrib" / "test"
LIB = TESTS / "lib" / "testports.sh"
WINDOW = 64

# Harnesses that never bind a port.
EXEMPT = {
    "build_staged_index.sh",       # operates on the Git index, starts no node
    "check_privacy_vnext_freshness.sh",
    "run_fuzz_campaign.sh",
    "audit_build_dependencies.sh",
    "v5_release_gate.sh",          # orchestrator; the suites it calls are checked
    "testports_selftest.sh",       # tests the library itself
    "check_port_isolation.sh",
}

ASSIGN = re.compile(
    r'^[ \t]*(?P<name>[A-Za-z_][A-Za-z_0-9]*)='
    r'(?P<rhs>.*)$'
)
# Anchored so IMPORT_OK, MERGE_REPORT and RPCUSER are not ports.
PORTISH = re.compile(r'(?:^|_)(PORT|RPC|IDNS)(?:_|\d|$)')
NOT_A_PORT = re.compile(r'(USER|PASS|WALLET|TIMEOUT|COUNT|WAIT|DIR|ALLOWIP|OFFSET|TPS)')
BARE_LITERAL = re.compile(r'^"?(?:\$\{[A-Za-z_0-9]+:-)?\d{3,5}\}?"?$')
# A port literal buried in arithmetic, e.g. idnsport=$((29200 + i)).
ARITH_LITERAL = re.compile(r'\$\(\(\s*(\d{4,5})\s*\+')
# A port literal in a URL or -rpcport flag, e.g. http://127.0.0.1:19331/.
# quick_test bound the allocated port but polled 19331, so it waited 60s for a
# node that was answering the whole time.
URL_LITERAL = re.compile(r'(?:127\.0\.0\.1|localhost):(\d{4,5})')
FLAG_LITERAL = re.compile(r'-(?:rpc)?port=(\d{4,5})')
# A conf value must not carry quotes: innova.conf takes the value verbatim, so
# rpcport="19331" is not a number.
QUOTED_CONF = re.compile(r'^(rpcport|port|idnsport)="')
# host:port passed as an RPC argument is data the node advertises, not a socket
# this harness binds.
IGNORE_URL = re.compile(r'(registerprivate|addnode\s+["\']?\$|collateralnode)')


def is_port_var(name):
    # Harness variables are upper case; lower-case names on the left of '=' are
    # innova.conf keys inside a heredoc and take their value from a variable.
    if name != name.upper():
        return False
    return bool(PORTISH.search(name)) and not NOT_A_PORT.search(name)


def port_assignments(text):
    """Port variable assignment lines, in file order.

    Only assignments whose right-hand side is a port value: a bare literal
    (not yet wired) or an iv5_port call (wired). Anything else with a
    port-shaped name is a different kind of variable.
    """
    out = []
    for line in text.split("\n"):
        m = ASSIGN.match(line)
        if not m:
            continue
        name = m.group("name")
        if not is_port_var(name):
            continue
        rhs = m.group("rhs").strip()
        if not (BARE_LITERAL.match(rhs) or "iv5_port" in rhs):
            continue
        out.append((name, rhs, line))
    return out


def evaluate(path, assignments, base):
    """Evaluate a harness's port assignments in isolation and return name->port."""
    names = [n for n, _, _ in assignments]
    body = "\n".join(line for _, _, line in assignments)
    script = (
        f'source "{LIB}"\n'
        f'SCRIPT_DIR="{TESTS}"\n'
        f'iv5_ports_init check >/dev/null 2>&1 || exit 9\n'
        f'{body}\n'
        + "\n".join(f'echo "{n}=${{{n}}}"' for n in names)
    )
    env = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "HOME": str(pathlib.Path.home())}
    if base is not None:
        env["IV5_TEST_PORT_BASE"] = str(base)
    proc = subprocess.run(["bash", "-c", script], capture_output=True, text=True, env=env)
    if proc.returncode != 0:
        return None, proc.stderr.strip() or f"exit {proc.returncode}"
    values = {}
    for line in proc.stdout.split("\n"):
        if "=" not in line:
            continue
        k, v = line.split("=", 1)
        v = v.strip()
        if v.isdigit():
            values[k] = int(v)
    return values, None


def main():
    failures = []
    checked = 0

    for path in sorted(TESTS.glob("*.sh")):
        if path.name in EXEMPT:
            continue
        text = path.read_text()
        assignments = port_assignments(text)
        if not assignments:
            continue
        checked += 1
        rel = path.name

        # 1. sources the library
        if "lib/testports.sh" not in text:
            failures.append(f"{rel}: does not source lib/testports.sh")
            continue

        # 2. no bare literals left, in an assignment or in arithmetic
        for name, rhs, line in assignments:
            if BARE_LITERAL.match(rhs):
                failures.append(f"{rel}: {name} is a hardcoded port ({rhs}); route it through iv5_port")
        for lineno, line in enumerate(text.split("\n"), 1):
            stripped = line.strip()
            m = ARITH_LITERAL.search(line)
            if m and "iv5_port" not in line:
                failures.append(
                    f"{rel}:{lineno}: port literal {m.group(1)} in arithmetic "
                    f"({stripped}); derive it from a base that iv5_port set")
            # An address passed *to* an RPC (a collateralnode advertising a
            # host:port) is data, not a socket this harness binds.
            m = URL_LITERAL.search(line)
            if m and not IGNORE_URL.search(line):
                failures.append(
                    f"{rel}:{lineno}: hardcoded {m.group(0)} ({stripped}); "
                    f"the harness would poll a port it did not bind")
            m = FLAG_LITERAL.search(line)
            if m:
                failures.append(
                    f"{rel}:{lineno}: hardcoded {m.group(0)} ({stripped}); "
                    f"use the variable iv5_port set")
            if QUOTED_CONF.match(stripped):
                failures.append(
                    f"{rel}:{lineno}: conf value is quoted ({stripped}); "
                    f"innova.conf takes the value verbatim, so this is not a number")

        # 3/4/5. evaluate under no base, and under two different bases
        legacy, err = evaluate(path, assignments, None)
        if legacy is None:
            failures.append(f"{rel}: could not evaluate port block: {err}")
            continue

        # Historical literals are the second argument to each iv5_port call.
        for name, rhs, line in assignments:
            m = re.search(r'iv5_port\s+(\d+)\s+(\d+)', rhs)
            if not m:
                continue
            want = int(m.group(2))
            got = legacy.get(name)
            if got != want:
                failures.append(
                    f"{rel}: with no base set {name}={got}, but its historical port is {want}; "
                    f"default behaviour changed")

        base_a, base_b = 52000, 52000 + WINDOW
        va, err_a = evaluate(path, assignments, base_a)
        vb, err_b = evaluate(path, assignments, base_b)
        if va is None or vb is None:
            failures.append(f"{rel}: could not evaluate under a base: {err_a or err_b}")
            continue

        for name, port in va.items():
            if not (base_a <= port < base_a + WINDOW):
                failures.append(
                    f"{rel}: {name}={port} is outside the window {base_a}-{base_a + WINDOW - 1}; "
                    f"the base is not honoured")

        overlap = set(va.values()) & set(vb.values())
        if overlap:
            failures.append(
                f"{rel}: bases {base_a} and {base_b} share ports {sorted(overlap)}; "
                f"concurrent runs would collide")

    print(f"[port-isolation] checked {checked} harnesses")
    if failures:
        print(f"[port-isolation] {len(failures)} problem(s):")
        for f in failures:
            print(f"  FAIL {f}")
        return 1
    print("[port-isolation] every harness honours IV5_TEST_PORT_BASE")
    return 0


if __name__ == "__main__":
    sys.exit(main())
