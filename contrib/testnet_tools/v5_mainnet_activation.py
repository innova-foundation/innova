#!/usr/bin/env python3
"""Calculate the one-piece mainnet v5 activation-ladder shift."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Optional, Sequence

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "test"))

from v5_release_evidence_schema import (  # noqa: E402
    MAINNET_ACTIVATION_BOUNDARY_B_BASE as BOUNDARY_B_BASE,
    MAINNET_ACTIVATION_DAG_GATE_BASE as DAG_BASE,
    MAINNET_ACTIVATION_FIRST_GATE_BASE as BASE,
    MAINNET_ACTIVATION_MAX_LEAD_BLOCKS as MAXIMUM_LEAD,
    MAINNET_ACTIVATION_MIN_LEAD_BLOCKS as MINIMUM_LEAD,
    MAINNET_ACTIVATION_SHIFT_GRANULARITY as SHIFT_GRANULARITY,
    MAINNET_ACTIVATION_SHIFT_STEP as SHIFT_STEP,
    MAINNET_PRE_DAG_EPOCH_INTERVAL as EPOCH_INTERVAL,
)


def ceil_to(value: int, granularity: int) -> int:
    return ((value + granularity - 1) // granularity) * granularity


def activation_shift(trusted_tip: int) -> int:
    """Smallest policy-valid shift for a tip: the gates clear the minimum lead.

    This is the low edge of an allowed band, not the one required answer. The
    release policy accepts any shift whose first gate leads the trusted tip by
    between MINIMUM_LEAD and MAXIMUM_LEAD blocks, so a tag stays valid while the
    tip advances instead of expiring in about two days.

    Steps by SHIFT_STEP, not SHIFT_GRANULARITY: the DAG gate must also land on a
    pre-DAG epoch boundary, and only multiples of lcm(granularity, epoch) keep
    both true.
    """
    if trusted_tip < 0:
        raise ValueError("trusted tip must be non-negative")
    return ceil_to(max(0, trusted_tip + MINIMUM_LEAD - BASE), SHIFT_STEP)


def lead_bounds(trusted_tip: int) -> tuple:
    """Inclusive (min, max) shift the policy accepts for this tip."""
    lo = activation_shift(trusted_tip)
    hi = (max(0, trusted_tip + MAXIMUM_LEAD - BASE) // SHIFT_STEP) * SHIFT_STEP
    return lo, max(lo, hi)


def result(trusted_tip: int, trusted_hash: str, shift_override: Optional[int] = None) -> dict:
    digest = trusted_hash.lower()
    if len(digest) != 64 or any(ch not in "0123456789abcdef" for ch in digest):
        raise ValueError("trusted hash must be a 64-character hexadecimal block hash")
    shift = activation_shift(trusted_tip) if shift_override is None else shift_override
    if shift < 0 or shift % SHIFT_GRANULARITY != 0:
        raise ValueError("shift must be a non-negative multiple of %d" % SHIFT_GRANULARITY)
    if (DAG_BASE + shift) % EPOCH_INTERVAL != 0:
        raise ValueError(
            "DAG gate %d is not a multiple of the pre-DAG epoch interval %d; use a "
            "shift that is a multiple of %d" % (DAG_BASE + shift, EPOCH_INTERVAL, SHIFT_STEP))
    lead = BASE + shift - trusted_tip
    if not MINIMUM_LEAD <= lead <= MAXIMUM_LEAD:
        raise ValueError(
            "first gate %d leads tip %d by %d blocks, outside the policy band [%d, %d]"
            % (BASE + shift, trusted_tip, lead, MINIMUM_LEAD, MAXIMUM_LEAD))
    lo, hi = lead_bounds(trusted_tip)
    return {
        "schema_version": 1,
        "trusted_tip_height": trusted_tip,
        "trusted_tip_hash": digest,
        "minimum_lead_blocks": MINIMUM_LEAD,
        "maximum_lead_blocks": MAXIMUM_LEAD,
        "shift_granularity": SHIFT_GRANULARITY,
        "shift_step": SHIFT_STEP,
        "activation_shift": shift,
        "activation_shift_min": lo,
        "activation_shift_max": hi,
        "lead_blocks": lead,
        "first_v5_gate": BASE + shift,
        "dag_gate": DAG_BASE + shift,
        "boundary_b_slot": BOUNDARY_B_BASE + shift,
    }


def selftest() -> None:
    # The floor is a minimum, and the step is lcm(granularity, epoch interval).
    assert SHIFT_STEP % SHIFT_GRANULARITY == 0
    assert (DAG_BASE + SHIFT_STEP) % EPOCH_INTERVAL == 0
    assert activation_shift(7_789_999) == 0
    assert activation_shift(7_790_001) == 60
    assert activation_shift(7_790_060) == 60
    assert activation_shift(7_790_061) == 120

    # A band, not one required answer: every shift in it must be accepted.
    tip = 8_135_825
    lo, hi = lead_bounds(tip)
    assert lo == 345_840, lo
    assert hi == 585_780, hi
    for shift in range(lo, hi + 1, SHIFT_STEP):
        payload = result(tip, "ab" * 32, shift_override=shift)
        assert MINIMUM_LEAD <= payload["lead_blocks"] <= MAXIMUM_LEAD
        assert payload["dag_gate"] % EPOCH_INTERVAL == 0

    # The shipped ladder is inside the band for the tip it was set against.
    shipped = result(tip, "ab" * 32, shift_override=350_040)
    assert shipped["first_v5_gate"] == 8_150_040
    assert shipped["dag_gate"] == 8_160_000
    assert shipped["boundary_b_slot"] == 8_410_040
    assert shipped["lead_blocks"] == 14_215

    # Rejected: too short, too long, 600,000, and a shift inside the lead band
    # that puts the DAG gate off an epoch boundary.
    for bad in (0, 345_780, 585_840, 600_000, 350_000):
        try:
            result(tip, "ab" * 32, shift_override=bad)
        except ValueError:
            pass
        else:
            raise AssertionError("shift %d should be rejected for tip %d" % (bad, tip))


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--trusted-tip", type=int)
    parser.add_argument("--trusted-hash")
    parser.add_argument("--shift", type=int,
                        help="Use this shift instead of the smallest valid one; "
                             "must still land inside the policy lead band")
    parser.add_argument("--selftest", action="store_true")
    args = parser.parse_args(argv)
    if args.selftest:
        selftest()
        print("v5 mainnet activation selftest passed")
        return 0
    if args.trusted_tip is None or args.trusted_hash is None:
        parser.error("--trusted-tip and --trusted-hash are required")
    try:
        print(json.dumps(result(args.trusted_tip, args.trusted_hash, args.shift), sort_keys=True))
    except ValueError as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
