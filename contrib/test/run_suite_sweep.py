#!/usr/bin/env python3
# Copyright (c) 2026 The Innova developers
"""Run the regtest suites named in suites.json, concurrently and isolated.

Reads the manifest rather than globbing contrib/test/*.sh: the glob picks up
build helpers whose non-zero exit is correct behaviour.

Each suite is given its own port window via IV5_TEST_PORT_BASE=auto. A harness
that does not source lib/testports.sh ignores that and binds fixed sockets, so
the manifest marks it fixed_ports and those run serially after the parallel batch.

Output is a JSON record per suite: exit status, wall time, and the PASS/FAIL case
counts scraped from the harness output. Case counts are the comparable quantity
across runs; assertion counts are not, because miner_tests and mruset_tests are
nondeterministic.

  ./run_suite_sweep.py --list
  ./run_suite_sweep.py --jobs 4 --output /var/tmp/sweep.json
  ./run_suite_sweep.py --only iv5 --jobs 2
"""
import argparse
import concurrent.futures
import json
import os
import pathlib
import re
import subprocess
import sys
import time

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parents[1]
MANIFEST = HERE / "suites.json"

PASS_RE = re.compile(r'^\s*(?:\x1b\[[0-9;]*m)?\[PASS\]', re.M)
FAIL_RE = re.compile(r'^\s*(?:\x1b\[[0-9;]*m)?\[FAIL\]', re.M)
# Harness summary lines, e.g. "passed: 17  failed: 0" or "Passed: 16, Failed: 0"
SUMMARY_RE = re.compile(r'passed:\s*(\d+).{0,4}failed:\s*(\d+)', re.I | re.S)


def load_manifest():
    data = json.loads(MANIFEST.read_text())
    return data["suites"]


def runnable(entry, kinds):
    return entry["kind"] in kinds


def run_one(entry, innovad, timeout_scale, log_dir):
    name = entry["name"]
    path = HERE / name
    cmd = ["python3", str(path)] if name.endswith(".py") else ["bash", str(path)]

    env = dict(os.environ)
    # Real isolation: each suite takes its own locked window.
    env["IV5_TEST_PORT_BASE"] = "auto"
    if innovad:
        env["INNOVAD"] = innovad

    budget = int(entry.get("minutes", 15) * 60 * timeout_scale)
    log_path = log_dir / (name.replace("/", "_") + ".log")

    started = time.time()
    timed_out = False
    try:
        proc = subprocess.run(cmd, cwd=str(ROOT), env=env, timeout=budget,
                              stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                              text=True, errors="replace")
        output, code = proc.stdout, proc.returncode
    except subprocess.TimeoutExpired as exc:
        output = (exc.stdout or "") if isinstance(exc.stdout, str) else \
                 (exc.stdout or b"").decode(errors="replace")
        code, timed_out = 124, True

    elapsed = time.time() - started
    log_path.write_text(output)

    cases_pass = len(PASS_RE.findall(output))
    cases_fail = len(FAIL_RE.findall(output))
    summary = SUMMARY_RE.search(output)
    if summary:
        # Prefer the harness's own tally when it prints one.
        cases_pass = max(cases_pass, int(summary.group(1)))
        cases_fail = max(cases_fail, int(summary.group(2)))

    return {
        "name": name,
        "kind": entry["kind"],
        "nodes": entry.get("nodes", 0),
        "nondeterministic": bool(entry.get("nondeterministic")),
        "exit_code": code,
        "timed_out": timed_out,
        "budget_seconds": budget,
        "elapsed_seconds": round(elapsed, 1),
        "cases_passed": cases_pass,
        "cases_failed": cases_fail,
        "cases_total": cases_pass + cases_fail,
        "log": str(log_path),
        # A suite that exits 0 having run zero cases has not demonstrated
        # anything. Scored separately so it cannot hide inside a green sweep.
        "ok": code == 0 and cases_fail == 0 and (cases_pass > 0 or entry["kind"] == "static"),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--jobs", type=int, default=1,
                    help="suites to run concurrently; fixed_ports entries are run "
                         "serially afterwards because they bind fixed sockets")
    ap.add_argument("--only", default="",
                    help="substring filter on suite name")
    ap.add_argument("--kinds", default="suite,selftest,static",
                    help="comma-separated kinds to run; 'helper' is never swept")
    ap.add_argument("--innovad", default=os.environ.get("INNOVAD", ""),
                    help="path to the innovad under test")
    ap.add_argument("--timeout-scale", type=float, default=1.0)
    ap.add_argument("--output", default="")
    ap.add_argument("--log-dir", default="")
    ap.add_argument("--list", action="store_true")
    args = ap.parse_args()

    kinds = {k.strip() for k in args.kinds.split(",") if k.strip()}
    if "helper" in kinds:
        print("refusing to sweep 'helper' entries; they are not tests", file=sys.stderr)
        return 2

    entries = [e for e in load_manifest()
               if runnable(e, kinds) and args.only in e["name"]]

    if args.list:
        for e in entries:
            flag = " (nondeterministic)" if e.get("nondeterministic") else ""
            print(f'{e["kind"]:9s} {e["name"]:45s} nodes={e.get("nodes",0)} '
                  f'budget={e.get("minutes",15)}m{flag}')
        print(f"\n{len(entries)} runnable; "
              f"{sum(1 for e in load_manifest() if e['kind'] == 'helper')} helpers excluded")
        return 0

    if args.innovad and not pathlib.Path(args.innovad).exists():
        print(f"innovad not found: {args.innovad}", file=sys.stderr)
        return 2

    log_dir = pathlib.Path(args.log_dir or (pathlib.Path(os.environ.get("TMPDIR", "/tmp"))
                                            / f"innova-sweep-{int(time.time())}"))
    log_dir.mkdir(parents=True, exist_ok=True)
    print(f"[sweep] {len(entries)} suites, jobs={args.jobs}, logs in {log_dir}")

    # A fixed_ports entry ignores IV5_TEST_PORT_BASE, so two of them can bind the
    # same socket. They run one at a time, after the batch that is safe in parallel.
    parallel = [e for e in entries if not e.get("fixed_ports")]
    serial = [e for e in entries if e.get("fixed_ports")]
    if serial:
        print(f"[sweep] {len(serial)} fixed-port suite(s) deferred to a serial pass: "
              f'{", ".join(e["name"] for e in serial)}')

    results = []

    def report(r):
        results.append(r)
        mark = "ok  " if r["ok"] else "FAIL"
        extra = " TIMEOUT" if r["timed_out"] else ""
        print(f'[{mark}] {r["name"]:45s} '
              f'{r["cases_passed"]:3d}p/{r["cases_failed"]:3d}f '
              f'{r["elapsed_seconds"]:7.1f}s exit={r["exit_code"]}{extra}')

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as pool:
        futures = {pool.submit(run_one, e, args.innovad, args.timeout_scale, log_dir): e
                   for e in parallel}
        for fut in concurrent.futures.as_completed(futures):
            report(fut.result())

    for entry in serial:
        report(run_one(entry, args.innovad, args.timeout_scale, log_dir))

    results.sort(key=lambda r: r["name"])
    failed = [r for r in results if not r["ok"]]
    empty = [r for r in results if r["ok"] and r["cases_total"] == 0 and r["kind"] == "suite"]

    record = {
        "schema": "innova-suite-sweep-v1",
        "generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "innovad": args.innovad,
        "jobs": args.jobs,
        "suites_run": len(results),
        "suites_failed": len(failed),
        "cases_passed": sum(r["cases_passed"] for r in results),
        "cases_failed": sum(r["cases_failed"] for r in results),
        "results": results,
    }
    if args.output:
        pathlib.Path(args.output).write_text(json.dumps(record, indent=2))
        print(f"[sweep] evidence written to {args.output}")

    print(f'\n[sweep] {len(results) - len(failed)}/{len(results)} suites ok, '
          f'{record["cases_passed"]} cases passed, {record["cases_failed"]} failed')
    if empty:
        print(f'[sweep] {len(empty)} suite(s) exited 0 without running a case: '
              f'{", ".join(r["name"] for r in empty)}')
    for r in failed:
        print(f'  FAIL {r["name"]}  exit={r["exit_code"]} '
              f'cases={r["cases_passed"]}p/{r["cases_failed"]}f  log={r["log"]}')
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
