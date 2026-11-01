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

# Registry crates for the Nyx messenger (src/nyx_pq.rs) that the pinned upstream lock does not
# resolve. Not a consensus input. Each entry is name, version and the crates.io archive SHA-256;
# adding or bumping one is a reviewed edit here.
MESSENGER_PACKAGES: dict[tuple[str, str], str] = {
    ("aead", "0.5.2"): "d122413f284cf2d62fb1b7db97e02edb8cda96d769b16e443a4f6195e35662b0",
    ("autocfg", "1.5.1"): "f2032f911046de80f0a198e0901378627c33f59ea0ac00e363d481118bd70a53",
    ("block-buffer", "0.12.1"): "d2f6c7dbe95a6ed67ad9f18e57daf93a2f034c524b99fd2b76d18fdfeb6660aa",
    ("chacha20", "0.9.1"): "c3613f74bd2eac03dad61bd53dbe620703d4371614fe0bc3b9f04dd36fe4e818",
    ("chacha20poly1305", "0.10.1"): "10cd79432192d1c0f4e1a0fef9527696cc039165d729fb41b3f4f4f354c2dc35",
    ("cipher", "0.4.4"): "773f3b9af64447d2ce9850330c473515014aa235e6a783b02db81ff39e4a3dad",
    ("cmov", "0.5.4"): "0c9ea0ac24bc397ab3c98583a3c9ba74fa56b09a4449bbe172b9b1ddb016027a",
    ("cpufeatures", "0.3.1"): "5ca28b0ae3115b884660db4118d803791fd6756b6e88f39c0f3f7859060d7566",
    ("crypto-common", "0.2.2"): "ce6e4c961d6cd6c9a86db418387425e8bdeaf05b3c8bc1411e6dca4c252f1453",
    ("ctutils", "0.4.7"): "a2376ffd6f96d8a9db59875b4b6b0237d6900b5baf64279714e05493ce64828a",
    ("digest", "0.11.3"): "f1dd6dbb5841937940781866fa1281a1ff7bd3bf827091440879f9994983d5c2",
    ("hkdf", "0.12.4"): "7b5f8eb2ad728638ea2c7d47a21db23b7b58a72ed6a38256b8a1849f15fbbdf7",
    ("hmac", "0.12.1"): "6c49c37c09c17a53d937dfbb742eb3a961d65a994e6bcdcf37e7399d0cc8ab5e",
    ("hybrid-array", "0.4.15"): "27f864f10dfb56725ce5ce5472bc52252c8f93a4ab86327122cebf62c5f59a17",
    ("inout", "0.1.4"): "879f10e63c20629ecabbb64a8010319738c66a5cd0c29b02d63d272b03751d01",
    ("keccak", "0.2.2"): "d8f198d1db720e4940b5a493201d199d9f24f568f8f746bd13706243a2f71598",
    ("kem", "0.3.0"): "01737161ba802849cfd486b5bd209d38ba4943494c249a8126005170c7621edd",
    ("ml-dsa", "0.1.2"): "6f6d49c3f3f0e10e18ca975ffda66f8da0ec36521c1d911adcbc521bf0743f5c",
    ("ml-kem", "0.3.4"): "84ca78b66f46050d49fa21693ae8adab2081d8101b65d8067316b6b70b64a0d1",
    ("module-lattice", "0.2.4"): "c4a1e412c8ee83a1c678f427806219c49c96b2511b9f07497514f0e43fb26155",
    ("opaque-debug", "0.3.1"): "c08d65885ee38876c4f86fa503fb49d7b507c2b62552df7c70b2fce627e06381",
    ("poly1305", "0.8.0"): "8159bd90725d2df49889a078b54f4f79e87f1f8a8444194cdca81d38f5393abf",
    ("rand_core", "0.10.1"): "63b8176103e19a2643978565ca18b50549f6101881c443590420e4dc998a3c69",
    ("sha3", "0.12.0"): "bc9bad02c26382724b2d2692c6f179285e4b54eeecd7968f52a50059c3c11759",
    ("shake", "0.1.0"): "09057cb2149ad4cbd2da1e26b351f9a4c354219421229c69c3063e6f61947c4a",
    ("signature", "3.0.0"): "28d567dcbaf0049cb8ac2608a76cd95ff9e4412e1899d389ee400918ca7537f5",
    ("sponge-cursor", "0.1.0"): "3a0219bd7d979d58245a4f41f695e1ac9f8befdffadd7f61f1bae9e39abc6620",
    ("typenum", "1.20.1"): "b6f5e870be6c3b371b77fe0ee0bafb859fa4964b4404c27de1d380043c4dda20",
    ("universal-hash", "0.5.1"): "fc1de2c688dc15305988b563c3854064043356019f97a4b46276fe734c4f07ea",
    ("x25519-dalek", "2.0.1"): "c7e468321c81fb07fa7f4c636c3972b9100f0346e5b6a9f2bd0603a52f7ed277",
}


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

