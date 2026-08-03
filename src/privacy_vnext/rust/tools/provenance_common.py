#!/usr/bin/env python3
"""Deterministic helpers shared by the privacy-vNext provenance tools."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parents[1]
UPSTREAM = ROOT / "upstream"
VENDOR = ROOT / "vendor"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def iter_tree_files(root: Path, excluded: Iterable[str] = ()) -> list[Path]:
    excluded_parts = frozenset(excluded)
    result: list[Path] = []
    for directory, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(
            name for name in dirnames if name not in excluded_parts
        )
        base = Path(directory)
        for filename in sorted(filenames):
            path = base / filename
            if not excluded_parts.intersection(path.relative_to(root).parts):
                result.append(path)
    return result


def tree_sha256(root: Path, excluded: Iterable[str] = ()) -> tuple[str, int]:
    """Hash canonical relative names, file kinds, and file content digests."""
    digest = hashlib.sha256()
    paths = iter_tree_files(root, excluded)
    for path in paths:
        relative = path.relative_to(root).as_posix().encode("utf-8")
        digest.update(len(relative).to_bytes(8, "big"))
        digest.update(relative)
        if path.is_symlink():
            payload = os.readlink(path).encode("utf-8")
            kind = b"L"
        else:
            payload = bytes.fromhex(sha256_file(path))
            kind = b"F"
        digest.update(kind)
        digest.update(len(payload).to_bytes(8, "big"))
        digest.update(payload)
    return digest.hexdigest(), len(paths)


def canonical_json(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


def license_files(root: Path) -> list[str]:
    names = ("license", "copying", "notice")
    return [
        path.relative_to(root).as_posix()
        for path in iter_tree_files(root, ("target",))
        if path.name.lower().startswith(names)
    ]

