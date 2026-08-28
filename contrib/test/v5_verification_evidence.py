#!/usr/bin/env python3
"""Write, verify and index the evidence behind check_v5_release_policy's verification digests.

One document per field of REQUIRED_VERIFICATION_FIELDS. The SHA-256 of that
document is the value the release manifest carries in verification.<field>, so the
document is the only thing in the bundle that says what run the digest stands for.

The field list is imported, never restated: a field added to the policy is a field
this tool accepts, and nothing here is a second copy of it.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, Mapping

sys.path.insert(0, str(Path(__file__).resolve().parent))

from check_v5_release_policy import REQUIRED_VERIFICATION_FIELDS  # noqa: E402

SCHEMA_VERSION = 1
SUFFIX = "_sha256"
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
RESULTS = ("pass", "fail")
WORKTREE_STATES = ("clean", "dirty")

DOCUMENT_FIELDS = frozenset({
    "schema_version",
    "field",
    "obligation",
    "producer",
    "commit",
    "worktree",
    "host",
    "toolchain",
    "commands",
    "started_at",
    "completed_at",
    "duration_seconds",
    "result",
    "observations",
    "log",
    "log_sha256",
})
HOST_FIELDS = frozenset({"kernel", "release", "machine", "node"})


class EvidenceError(RuntimeError):
    pass


def obligation_of(field: str) -> str:
    if field not in REQUIRED_VERIFICATION_FIELDS:
        raise EvidenceError("%s is not a release verification field" % field)
    if not field.endswith(SUFFIX):
        raise EvidenceError("%s does not end in %s" % (field, SUFFIX))
    return field[: -len(SUFFIX)]


def digest_of(path: Path) -> str:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError as exc:
        raise EvidenceError("cannot hash %s: %s" % (path, exc)) from exc


def parse_timestamp(value: Any, where: str) -> dt.datetime:
    text = str(value or "")
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = dt.datetime.fromisoformat(text)
    except ValueError as exc:
        raise EvidenceError("%s is not an ISO-8601 timestamp: %r" % (where, value)) from exc
    if parsed.tzinfo is None:
        raise EvidenceError("%s carries no UTC offset" % where)
    return parsed.astimezone(dt.timezone.utc)


def load_document(path: Path) -> Dict[str, Any]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise EvidenceError("cannot read evidence %s: %s" % (path, exc)) from exc
    if not isinstance(document, dict):
        raise EvidenceError("%s is not a JSON object" % path)
    return document


def validate(document: Mapping[str, Any], path: Path, field: str = "",
             commit: str = "", allow_dirty: bool = False,
             require_pass: bool = True) -> str:
    """Check one document against the shape, its log and the commit it claims.

    Returns the digest the manifest would carry. Every failure raises: absence is
    never a pass, and a document that records a failed run is never evidence.
    """
    present = set(document)
    if present != DOCUMENT_FIELDS:
        raise EvidenceError(
            "%s fields do not match schema (missing=%s extra=%s)" %
            (path, sorted(DOCUMENT_FIELDS - present), sorted(present - DOCUMENT_FIELDS))
        )
    if document["schema_version"] != SCHEMA_VERSION:
        raise EvidenceError("%s schema_version %r is not %d" %
                            (path, document["schema_version"], SCHEMA_VERSION))

    named = str(document["field"])
    if named not in REQUIRED_VERIFICATION_FIELDS:
        raise EvidenceError("%s names %s, which the release policy does not require" % (path, named))
    if field and named != field:
        raise EvidenceError("%s carries evidence for %s, not %s" % (path, named, field))
    if str(document["obligation"]) != obligation_of(named):
        raise EvidenceError("%s obligation %r does not match its field" %
                            (path, document["obligation"]))
    if not str(document["producer"]).startswith("contrib/"):
        raise EvidenceError("%s producer must be a repository-relative path" % path)

    claimed = str(document["commit"]).lower()
    if not COMMIT_RE.match(claimed):
        raise EvidenceError("%s commit %r is not a 40-hex commit" % (path, document["commit"]))
    if commit and claimed != commit.lower():
        raise EvidenceError("%s was produced at %s, the tree is at %s" % (path, claimed, commit))
    if str(document["worktree"]) not in WORKTREE_STATES:
        raise EvidenceError("%s worktree %r is neither clean nor dirty" % (path, document["worktree"]))
    if document["worktree"] == "dirty" and not allow_dirty:
        raise EvidenceError("%s was produced from a dirty worktree, so it answers for no commit" % path)

    host = document["host"]
    if not isinstance(host, dict) or set(host) != HOST_FIELDS:
        raise EvidenceError("%s host fields do not match schema" % path)
    if not all(isinstance(value, str) and value for value in host.values()):
        raise EvidenceError("%s host values must be non-empty strings" % path)
    if not isinstance(document["toolchain"], str) or not document["toolchain"]:
        raise EvidenceError("%s records no toolchain" % path)

    commands = document["commands"]
    if (not isinstance(commands, list) or not commands or
            any(not isinstance(item, str) or not item for item in commands)):
        raise EvidenceError("%s commands must be a non-empty list of strings" % path)

    started = parse_timestamp(document["started_at"], "%s started_at" % path)
    completed = parse_timestamp(document["completed_at"], "%s completed_at" % path)
    if completed < started:
        raise EvidenceError("%s completed before it started" % path)
    duration = document["duration_seconds"]
    if isinstance(duration, bool) or not isinstance(duration, int) or duration < 0:
        raise EvidenceError("%s duration_seconds must be a non-negative integer" % path)

    observations = document["observations"]
    if not isinstance(observations, dict) or not observations:
        raise EvidenceError("%s must record at least one observation" % path)
    for key, value in observations.items():
        if not isinstance(key, str) or not key:
            raise EvidenceError("%s observation keys must be non-empty strings" % path)
        if isinstance(value, (dict, list)) or value is None:
            raise EvidenceError("%s observation %s must be a scalar" % (path, key))

    result = str(document["result"])
    if result not in RESULTS:
        raise EvidenceError("%s result %r is neither pass nor fail" % (path, result))
    if require_pass and result != "pass":
        raise EvidenceError("%s records a failed run" % path)

    log_name = str(document["log"])
    if "/" in log_name or log_name in ("", ".", ".."):
        raise EvidenceError("%s log must be a bare file name beside the document" % path)
    log_path = path.parent / log_name
    if not log_path.is_file():
        raise EvidenceError("%s names log %s, which is not beside it" % (path, log_name))
    if digest_of(log_path) != str(document["log_sha256"]).lower():
        raise EvidenceError("%s log digest does not match %s" % (path, log_name))

    return digest_of(path)


def document_path(directory: Path, field: str) -> Path:
    return directory / ("%s.json" % obligation_of(field))


def write(args: argparse.Namespace) -> int:
    field = args.field
    obligation = obligation_of(field)
    directory = args.dir
    directory.mkdir(parents=True, exist_ok=True)
    log_path = Path(args.log)
    if not log_path.is_file():
        raise EvidenceError("no log at %s" % log_path)
    if log_path.parent.resolve() != directory.resolve():
        raise EvidenceError("the log must already sit in %s" % directory)

    observations: Dict[str, Any] = {}
    for item in args.observation:
        key, separator, value = item.partition("=")
        if not separator or not key:
            raise EvidenceError("observation %r is not key=value" % item)
        try:
            observations[key] = int(value)
        except ValueError:
            try:
                observations[key] = float(value)
            except ValueError:
                observations[key] = value

    started = parse_timestamp(args.started_at, "--started-at")
    completed = parse_timestamp(args.completed_at, "--completed-at")
    document = {
        "schema_version": SCHEMA_VERSION,
        "field": field,
        "obligation": obligation,
        "producer": args.producer,
        "commit": args.commit.lower(),
        "worktree": args.worktree,
        "host": {
            "kernel": args.host_kernel,
            "release": args.host_release,
            "machine": args.host_machine,
            "node": args.host_node,
        },
        "toolchain": args.toolchain,
        "commands": args.command,
        "started_at": started.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "completed_at": completed.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "duration_seconds": int((completed - started).total_seconds()),
        "result": args.result,
        "observations": observations,
        "log": log_path.name,
        "log_sha256": digest_of(log_path),
    }
    path = document_path(directory, field)
    path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    # Written for a failed run too: the failure is the evidence, and refusing to
    # record it would leave the directory looking merely incomplete.
    validate(document, path, field=field, commit=args.commit,
             allow_dirty=True, require_pass=False)
    print(digest_of(path))
    return 0 if args.result == "pass" else 1


def verify(args: argparse.Namespace) -> int:
    path = document_path(args.dir, args.field)
    if not path.is_file():
        raise EvidenceError("no evidence for %s at %s" % (args.field, path))
    document = load_document(path)
    print(validate(document, path, field=args.field, commit=args.commit or "",
                   allow_dirty=args.allow_dirty))
    return 0


def index(args: argparse.Namespace) -> int:
    """Verify every named field and write the verification block for the manifest."""
    digests: Dict[str, str] = {}
    missing = []
    for field in sorted(set(args.field)):
        path = document_path(args.dir, field)
        if not path.is_file():
            missing.append("%s: no evidence at %s" % (field, path))
            continue
        try:
            digests[field] = validate(load_document(path), path, field=field,
                                      commit=args.commit or "", allow_dirty=args.allow_dirty)
        except EvidenceError as exc:
            missing.append(str(exc))
    for line in missing:
        print("MISSING EVIDENCE: %s" % line, file=sys.stderr)
    out = args.dir / "verification.json"
    out.write_text(json.dumps(digests, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print("%s: %d of %d fields" % (out, len(digests), len(set(args.field))))
    return 1 if missing else 0


def selftest() -> int:
    """Round-trip one document, then prove each tamper is caught."""
    import subprocess
    import tempfile

    commit = "0" * 39 + "1"
    with tempfile.TemporaryDirectory() as raw:
        directory = Path(raw)
        log = directory / "asan_lsan.log"
        log.write_text("synthetic run\n", encoding="utf-8")
        arguments = [
            sys.executable, str(Path(__file__).resolve()), "write",
            "--field", "asan_lsan_sha256", "--dir", str(directory),
            "--producer", "contrib/test/produce_asan_lsan_evidence.sh",
            "--commit", commit, "--worktree", "clean",
            "--host-kernel", "Linux", "--host-release", "6.8.0",
            "--host-machine", "x86_64", "--host-node", "selftest",
            "--toolchain", "g++ (selftest)", "--command", "make -f makefile.unix clean",
            "--started-at", "2026-01-01T00:00:00Z", "--completed-at", "2026-01-01T00:10:00Z",
            "--result", "pass", "--observation", "test_cases=7", "--log", str(log),
        ]
        written = subprocess.run(arguments, capture_output=True, text=True)
        if written.returncode != 0:
            raise EvidenceError("selftest write failed: %s" % written.stderr.strip())
        digest = written.stdout.strip()
        path = document_path(directory, "asan_lsan_sha256")
        if digest != digest_of(path):
            raise EvidenceError("selftest write printed a digest that is not the document's")

        document = load_document(path)
        if validate(document, path, field="asan_lsan_sha256", commit=commit) != digest:
            raise EvidenceError("selftest verify of an intact document failed")

        def rejects(mutation: str, mutate) -> None:
            broken = json.loads(json.dumps(document))
            mutate(broken)
            candidate = directory / "candidate.json"
            candidate.write_text(json.dumps(broken), encoding="utf-8")
            try:
                validate(broken, candidate, field="asan_lsan_sha256", commit=commit)
            except EvidenceError:
                return
            raise EvidenceError("selftest: %s was accepted" % mutation)

        rejects("a failed run", lambda d: d.__setitem__("result", "fail"))
        rejects("another commit", lambda d: d.__setitem__("commit", "f" * 40))
        rejects("a dirty worktree", lambda d: d.__setitem__("worktree", "dirty"))
        rejects("a missing observation", lambda d: d.__setitem__("observations", {}))
        rejects("a dropped field", lambda d: d.pop("toolchain"))
        rejects("an extra field", lambda d: d.__setitem__("extra", 1))
        rejects("a field the policy does not require",
                lambda d: d.__setitem__("field", "not_a_field_sha256"))
        rejects("a log digest that does not match",
                lambda d: d.__setitem__("log_sha256", "0" * 64))
        rejects("a log outside the directory", lambda d: d.__setitem__("log", "../x.log"))
        rejects("completion before the start",
                lambda d: d.__setitem__("completed_at", "2025-01-01T00:00:00Z"))

        # A tampered log is caught by the digest the document carries.
        log.write_text("edited after the fact\n", encoding="utf-8")
        try:
            validate(document, path, field="asan_lsan_sha256", commit=commit)
        except EvidenceError:
            pass
        else:
            raise EvidenceError("selftest: an edited log was accepted")

    print("v5_verification_evidence selftest passed")
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--selftest", action="store_true",
                        help="exercise the writer and every rejection it owes")
    sub = parser.add_subparsers(dest="command")

    writer = sub.add_parser("write", help="write one evidence document and print its digest")
    writer.add_argument("--field", required=True)
    writer.add_argument("--dir", type=Path, required=True)
    writer.add_argument("--producer", required=True)
    writer.add_argument("--commit", required=True)
    writer.add_argument("--worktree", choices=WORKTREE_STATES, required=True)
    writer.add_argument("--host-kernel", required=True)
    writer.add_argument("--host-release", required=True)
    writer.add_argument("--host-machine", required=True)
    writer.add_argument("--host-node", required=True)
    writer.add_argument("--toolchain", required=True)
    writer.add_argument("--command", action="append", default=[], required=True)
    writer.add_argument("--started-at", required=True)
    writer.add_argument("--completed-at", required=True)
    writer.add_argument("--result", choices=RESULTS, required=True)
    writer.add_argument("--observation", action="append", default=[])
    writer.add_argument("--log", required=True)
    writer.set_defaults(handler=write)

    verifier = sub.add_parser("verify", help="verify one document and print its digest")
    verifier.add_argument("--field", required=True)
    verifier.add_argument("--dir", type=Path, required=True)
    verifier.add_argument("--commit", default="")
    verifier.add_argument("--allow-dirty", action="store_true")
    verifier.set_defaults(handler=verify)

    indexer = sub.add_parser("index", help="verify fields and write the manifest verification block")
    indexer.add_argument("--field", action="append", default=[], required=True)
    indexer.add_argument("--dir", type=Path, required=True)
    indexer.add_argument("--commit", default="")
    indexer.add_argument("--allow-dirty", action="store_true")
    indexer.set_defaults(handler=index)

    args = parser.parse_args(argv)
    if args.selftest:
        return selftest()
    if args.command is None:
        parser.error("a subcommand is required")
    return args.handler(args)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except EvidenceError as error:
        print("v5_verification_evidence: %s" % error, file=sys.stderr)
        raise SystemExit(2)
