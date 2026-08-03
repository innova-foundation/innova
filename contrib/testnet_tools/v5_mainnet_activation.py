#!/usr/bin/env python3
"""Calculate the one-piece mainnet v5 activation-ladder shift."""

from __future__ import annotations

import argparse
import json
from typing import Optional, Sequence


BASE = 7_800_000
BOUNDARY_B_BASE = 8_060_000
MINIMUM_LEAD = 100_000
SHIFT_GRANULARITY = 10_000


def ceil_to(value: int, granularity: int) -> int:
    return ((value + granularity - 1) // granularity) * granularity


def activation_shift(trusted_tip: int) -> int:
    if trusted_tip < 0:
        raise ValueError("trusted tip must be non-negative")
    return ceil_to(max(0, trusted_tip + MINIMUM_LEAD - BASE), SHIFT_GRANULARITY)


def result(trusted_tip: int, trusted_hash: str) -> dict:
    digest = trusted_hash.lower()
    if len(digest) != 64 or any(ch not in "0123456789abcdef" for ch in digest):
        raise ValueError("trusted hash must be a 64-character hexadecimal block hash")
    shift = activation_shift(trusted_tip)
    return {
        "schema_version": 1,
        "trusted_tip_height": trusted_tip,
        "trusted_tip_hash": digest,
        "minimum_lead_blocks": MINIMUM_LEAD,
        "shift_granularity": SHIFT_GRANULARITY,
        "activation_shift": shift,
        "first_v5_gate": BASE + shift,
        "boundary_b_slot": BOUNDARY_B_BASE + shift,
    }


def selftest() -> None:
    assert activation_shift(7_699_999) == 0
    assert activation_shift(7_700_000) == 0
    assert activation_shift(7_700_001) == 10_000
    assert activation_shift(7_709_999) == 10_000
    assert activation_shift(7_710_001) == 20_000
    payload = result(7_710_001, "ab" * 32)
    assert payload["first_v5_gate"] == 7_820_000
    assert payload["boundary_b_slot"] == 8_080_000


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--trusted-tip", type=int)
    parser.add_argument("--trusted-hash")
    parser.add_argument("--selftest", action="store_true")
    args = parser.parse_args(argv)
    if args.selftest:
        selftest()
        print("v5 mainnet activation selftest passed")
        return 0
    if args.trusted_tip is None or args.trusted_hash is None:
        parser.error("--trusted-tip and --trusted-hash are required")
    try:
        print(json.dumps(result(args.trusted_tip, args.trusted_hash), sort_keys=True))
    except ValueError as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
