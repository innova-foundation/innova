#!/usr/bin/env python3
# Copyright (c) 2026 The Innova developers
# Byte-level readers for the one-chain evidence run: serialized consensus bytes only,
# never RPC fields that echo the wallet's request.

import json
import sys

MARKER = bytes([0xFF]) + b"IV5P"
IV5_TX_VERSION = 2008

# src/dag.h DAG_PARENT_TAG, src/mstimestamp.h MS_TIMESTAMP_TAG.
IDAG_TAG = b"IDAG"
IMTS_TAG = b"IMTS"
MAX_DAG_PARENTS = 32

# The IV5 payload prefix is fixed width up to the two value fields: schema(2),
# operation, profile, authorization, mask, finality object, network, reserved,
# genesis(32), parameter digest(32), finalized root(32), tree size(8).
VB_OFFSET = 113
FEE_OFFSET = 121


def compact(b, o):
    v = b[o]
    o += 1
    if v < 253:
        return v, o
    if v == 253:
        return int.from_bytes(b[o:o + 2], "little"), o + 2
    if v == 254:
        return int.from_bytes(b[o:o + 4], "little"), o + 4
    return int.from_bytes(b[o:o + 8], "little"), o + 8


def parse_tx(raw):
    """Walk a serialized transaction. Returns (version, vouts, scripts, envelope_offset)."""
    b = bytes.fromhex(raw)
    version = int.from_bytes(b[0:4], "little")
    o = 8                       # version(4) + nTime(4)
    n, o = compact(b, o)
    for _ in range(n):
        o += 36                 # prevout
        length, o = compact(b, o)
        o += length + 4         # script + sequence
    nvout, o = compact(b, o)
    scripts = []
    for _ in range(nvout):
        o += 8                  # value
        length, o = compact(b, o)
        scripts.append(b[o:o + length])
        o += length
    o += 4                      # nLockTime
    return b, version, nvout, scripts, o


def read_iv5(raw):
    b, version, nvout, scripts, o = parse_tx(raw)
    if version != IV5_TX_VERSION:
        return {"version": version, "vout_count": nvout, "iv5": False}
    if b[o:o + 5] != MARKER:
        raise ValueError("no IV5 envelope marker at offset %d" % o)
    o += 7                      # marker(5) + envelope version(2)
    size, o = compact(b, o)
    payload = b[o:o + size]
    if len(payload) != size:
        raise ValueError("the envelope declares %d payload bytes and carries %d"
                         % (size, len(payload)))
    # A short payload would otherwise read zero for both value fields instead of failing.
    if size < FEE_OFFSET + 8:
        raise ValueError("a %d-byte payload is shorter than its own value fields" % size)
    return {
        "version": version,
        "vout_count": nvout,
        "vin_count": None,
        "iv5": True,
        "payload_size": size,
        "operation": payload[2],
        "disclosure_mask": payload[5],
        "value_balance": int.from_bytes(payload[VB_OFFSET:VB_OFFSET + 8], "little", signed=True),
        "fee": int.from_bytes(payload[FEE_OFFSET:FEE_OFFSET + 8], "little"),
    }


def bounded_push(script):
    """The single bounded data push after a leading OP_RETURN, or None.

    Mirrors DecodeCanonicalDAGParentScript: IDAG permits 32 hashes (1,029
    payload bytes), so the push is parsed directly rather than through the
    generic 520-byte script-element path.
    """
    if len(script) < 2 or script[0] != 0x6A:     # OP_RETURN
        return None, False
    o = 1
    opcode = script[o]
    o += 1
    if opcode <= 75:
        size = opcode
    elif opcode == 0x4C:                          # OP_PUSHDATA1
        if o + 1 > len(script):
            return None, False
        size = script[o]
        o += 1
    elif opcode == 0x4D:                          # OP_PUSHDATA2
        if o + 2 > len(script):
            return None, False
        size = script[o] | (script[o + 1] << 8)
        o += 2
    else:
        return None, False
    if o + size > len(script):
        return None, False
    data = script[o:o + size]
    trailing = (o + size) != len(script)
    return data, trailing


def read_idag(script):
    data, trailing = bounded_push(script)
    if data is None or len(data) < 5 or data[:4] != IDAG_TAG:
        return None
    out = {"trailing_ops": trailing, "count": data[4], "parents": []}
    count = data[4]
    if count == 0 or count > MAX_DAG_PARENTS:
        out["malformed"] = "count byte %d outside 1..%d" % (count, MAX_DAG_PARENTS)
        return out
    need = 5 + count * 32
    if len(data) < need:
        out["malformed"] = "declares %d parents and carries %d bytes" % (count, len(data))
        return out
    for i in range(count):
        # uint256 is little-endian on the wire; GetHex() prints it reversed.
        out["parents"].append(data[5 + i * 32:5 + (i + 1) * 32][::-1].hex())
    return out


def read_imts(script):
    # 6a 06 "IMTS" <offset little-endian uint16>
    data, trailing = bounded_push(script)
    if data is None or len(data) != 6 or data[:4] != IMTS_TAG:
        return None
    return {"trailing_ops": trailing,
            "offset_ms": data[4] | (data[5] << 8)}


def bit_size(v):
    return v.bit_length()


def poem_entropy(block_hash_hex):
    """GetBlockEntropy(), recomputed. src/finality.cpp.

    comp = ~h; nBitSize = bitSize(comp); result = nBitSize<<32, plus the 32 bits
    below the top bit when nBitSize > 33.
    """
    h = int(block_hash_hex, 16)
    comp = (~h) & ((1 << 256) - 1)
    if comp == 0:
        return "0" * 64
    nbits = bit_size(comp)
    result = nbits << 32
    if nbits > 33:
        shifted = comp >> (nbits - 33)
        result += shifted & 0xFFFFFFFF
    return "%064x" % result


def scan_ip(raw_hex, ip):
    """Is this IPv4 address present in these bytes, as ASCII or as four octets?"""
    b = bytes.fromhex(raw_hex)
    octets = bytes(int(p) for p in ip.split("."))
    return {
        "ascii": ip.encode() in b,
        "octets": octets in b,
        "present": (ip.encode() in b) or (octets in b),
    }


def coinbase_payloads(raw):
    _, version, nvout, scripts, _ = parse_tx(raw)
    rows = []
    for i, s in enumerate(scripts):
        if len(s) < 1 or s[0] != 0x6A:
            continue
        row = {"n": i, "script_hex": s.hex()}
        idag = read_idag(s)
        imts = read_imts(s)
        if idag is not None:
            row["tag"] = "IDAG"
            row.update(idag)
        elif imts is not None:
            row["tag"] = "IMTS"
            row.update(imts)
        else:
            data, _tr = bounded_push(s)
            row["tag"] = (data[:4].decode("latin1") if data and len(data) >= 4
                          else "unknown")
        rows.append(row)
    return {"version": version, "vout_count": nvout, "op_returns": rows}


def main():
    if len(sys.argv) < 2:
        print("usage: iv5_onechain_evidence.py <iv5|idag|imts|entropy|scanip|coinbase> ...",
              file=sys.stderr)
        return 2
    cmd = sys.argv[1]
    try:
        if cmd == "iv5":
            print(json.dumps(read_iv5(sys.argv[2].strip())))
        elif cmd == "idag":
            out = []
            for h in sys.argv[2:]:
                r = read_idag(bytes.fromhex(h.strip()))
                if r is not None:
                    out.append(r)
            print(json.dumps(out))
        elif cmd == "imts":
            out = []
            for h in sys.argv[2:]:
                r = read_imts(bytes.fromhex(h.strip()))
                if r is not None:
                    out.append(r)
            print(json.dumps(out))
        elif cmd == "entropy":
            print(poem_entropy(sys.argv[2].strip()))
        elif cmd == "scanip":
            print(json.dumps(scan_ip(sys.argv[2].strip(), sys.argv[3].strip())))
        elif cmd == "coinbase":
            print(json.dumps(coinbase_payloads(sys.argv[2].strip())))
        else:
            print("unknown subcommand %s" % cmd, file=sys.stderr)
            return 2
    except Exception as e:
        print(json.dumps({"error": str(e)}))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
