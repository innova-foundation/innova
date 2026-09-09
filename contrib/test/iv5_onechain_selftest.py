#!/usr/bin/env python3
# Copyright (c) 2026 The Innova developers
# Negative and positive vectors for the five one-chain evidence decoders; positive
# vectors follow BuildDAGParentScript, MS_TIMESTAMP_TAG and GetBlockEntropy.

import json
import subprocess
import sys
import os

HERE = os.path.dirname(os.path.abspath(__file__))
DECODE = os.path.join(HERE, "iv5_onechain_evidence.py")

PASSED = 0
FAILED = 0


def run(*args):
    r = subprocess.run([sys.executable, DECODE] + list(args),
                       capture_output=True, text=True)
    return r.stdout.strip()


def ok(cond, label):
    global PASSED, FAILED
    if cond:
        PASSED += 1
        print("[PASS] %s" % label)
    else:
        FAILED += 1
        print("[FAIL] %s" % label)


def push(data):
    """CScript << OP_RETURN << data, with the push encoding CScript would use."""
    if len(data) <= 75:
        p = bytes([len(data)])
    elif len(data) <= 255:
        p = b"\x4c" + bytes([len(data)])
    else:
        p = b"\x4d" + len(data).to_bytes(2, "little")
    return (b"\x6a" + p + data).hex()


def idag_script(parents_be):
    d = b"IDAG" + bytes([len(parents_be)])
    for h in parents_be:
        d += bytes.fromhex(h)[::-1]
    return push(d)


def imts_script(off):
    return push(b"IMTS" + off.to_bytes(2, "little"))


P = ["%02x" % i * 32 for i in range(40)]

print("=== IDAG parent commitment ===")
# Accepts what the encoder produces, at both push encodings.
for n in (1, 2, 3, 32):
    r = json.loads(run("idag", idag_script(P[:n])))
    ok(len(r) == 1 and r[0]["count"] == n and r[0]["parents"] == P[:n],
       "accepts a %d-parent commitment and recovers every parent" % n)
# The evidence claim that matters: more than one parent is a merge block.
r = json.loads(run("idag", idag_script(P[:2])))
ok(r[0]["count"] > 1, "reports a 2-parent commitment as more than one parent")
r = json.loads(run("idag", idag_script(P[:1])))
ok(r[0]["count"] == 1, "reports a 1-parent commitment as one parent, not a merge")

# --- mutations it must not accept ---
ok(json.loads(run("idag", push(b"XDAG" + bytes([1]) + b"\x00" * 32))) == [],
   "rejects a commitment whose tag is not IDAG")
ok(json.loads(run("idag", push(b"IDAG" + bytes([0])))) == [] or
   "malformed" in json.loads(run("idag", push(b"IDAG" + bytes([0]))))[0],
   "rejects a count byte of zero")
r = json.loads(run("idag", idag_script(P[:33])))
ok(r and "malformed" in r[0],
   "rejects 33 parents, one past the MAX_DAG_PARENTS bound")
# A count byte that promises more than the payload carries: the one mutation
# that would otherwise read 32 bytes of whatever follows as a parent hash.
short = push(b"IDAG" + bytes([4]) + b"\xaa" * 32)
r = json.loads(run("idag", short))
ok(r and "malformed" in r[0],
   "rejects a count byte promising more parents than the payload holds")
ok(json.loads(run("idag", "6a0455555555")) == [],
   "ignores an unrelated OP_RETURN")
ok(json.loads(run("idag", imts_script(500))) == [],
   "does not read an IMTS commitment as an IDAG one")

print()
print("=== IMTS millisecond offset ===")
for off in (1, 63, 459, 837, 964, 999):
    r = json.loads(run("imts", imts_script(off)))
    ok(len(r) == 1 and r[0]["offset_ms"] == off,
       "recovers a %d ms offset" % off)
# A zero offset decodes, and the CALLER is what must not count it -- the check
# scans for nonzero rows. Both halves are asserted so neither can drift.
r = json.loads(run("imts", imts_script(0)))
ok(len(r) == 1 and r[0]["offset_ms"] == 0,
   "decodes a zero offset rather than hiding it")
ok(json.loads(run("imts", push(b"XMTS" + b"\x00\x00"))) == [],
   "rejects a commitment whose tag is not IMTS")
ok(json.loads(run("imts", push(b"IMTS" + b"\x00"))) == [],
   "rejects a five-byte payload, one short of the fixed width")
ok(json.loads(run("imts", push(b"IMTS" + b"\x00\x00\x00"))) == [],
   "rejects a seven-byte payload, one over the fixed width")
ok(json.loads(run("imts", idag_script(P[:1]))) == [],
   "does not read an IDAG commitment as an IMTS one")

print()
print("=== POEM entropy ===")
# Distinct block hashes must give distinct entropy, or agreement across nodes
# would be agreement on a constant.
h1 = "41c48e81e1d14b774749135f576366d158ae98d923bcce3fd0ba07cfbe463d82"
h2 = "0783447fd328b95374f1a9203b9444ce9608e41742ce7c987f32daeb6d3c7c11"
e1, e2 = run("entropy", h1), run("entropy", h2)
ok(len(e1) == 64 and e1 != e2,
   "two different block hashes give two different entropy values")
ok(run("entropy", h1) == e1, "the same block hash gives the same entropy")
# GetBlockEntropy depends only on the top 33 bits of the block hash.
top = int(h1, 16) ^ (1 << 254)
ok(run("entropy", "%064x" % top) != e1,
   "flipping a bit inside the top 33 of the block hash changes the entropy")
low = int(h1, 16) ^ 1
ok(run("entropy", "%064x" % low) == e1,
   "flipping the lowest bit does not: the entropy reads 33 bits of the hash, "
   "and the other 223 do not reach it")
sensitive = sum(1 for b in range(256)
                if run("entropy", "%064x" % (int(h1, 16) ^ (1 << b))) != e1)
ok(sensitive == 33,
   "exactly 33 of the 256 hash bits change the entropy (measured: %d)" % sensitive)
# The all-ones hash complements to zero, the one input the function special-cases.
ok(run("entropy", "f" * 64) == "0" * 64,
   "an all-ones block hash gives zero, as GetBlockEntropy defines")

print()
print("=== IV5 envelope reader ===")
# A transaction that is not v2008 is not an IV5 transaction, whatever follows.
plain = ("01000000" "00000000" "00" "00" "00000000")
r = json.loads(run("iv5", plain))
ok(r.get("iv5") is False, "reports a non-2008 transaction as carrying no IV5 envelope")
# A v2008 transaction with no envelope marker must fail loudly, not silently
# return zeros that would sum into a pool identity.
nomarker = ("d8070000" "00000000" "00" "00" "00000000")
r = json.loads(run("iv5", nomarker))
ok("error" in r, "refuses a v2008 transaction with no envelope marker")
# A payload shorter than the value fields it declares: the one mutation that
# would otherwise read past the end and yield zero for both.
body = b"\xff" + b"IV5P" + b"\x01\x00" + bytes([10]) + b"\x00" * 10
short_tx = ("d8070000" "00000000" "00" "00" "00000000") + body.hex()
r = json.loads(run("iv5", short_tx))
ok("error" in r, "refuses a payload too short to hold its own value fields")

print()
print("=== IPv4 presence scan (the IDNS positive control) ===")
ip = "192.0.2.44"
present_ascii = ("00" * 4 + ip.encode().hex() + "00" * 4)
r = json.loads(run("scanip", present_ascii, ip))
ok(r["present"] and r["ascii"], "finds an address written as text")
present_octets = ("00" * 4 + bytes([192, 0, 2, 44]).hex() + "00" * 4)
r = json.loads(run("scanip", present_octets, ip))
ok(r["present"] and r["octets"], "finds an address written as four octets")
r = json.loads(run("scanip", "00" * 32, ip))
ok(not r["present"], "reports absent when the address is not there")
# The control must be able to distinguish two different addresses, or "absent"
# would mean nothing.
r = json.loads(run("scanip", present_ascii, "198.51.100.7"))
ok(not r["present"], "does not report a different address as present")

print()
print("=== coinbase payload extraction ===")
# A coinbase with both commitments, the shape every post-DAG block carries.
def cb(scripts):
    tx = "01000000" + "00000000" + "00" + ("%02x" % len(scripts))
    for s in scripts:
        tx += "0000000000000000"
        b = bytes.fromhex(s)
        tx += "%02x" % len(b) + s
    return tx + "00000000"

raw = cb([idag_script(P[:2]), imts_script(459)])
r = json.loads(run("coinbase", raw))
tags = [x["tag"] for x in r["op_returns"]]
ok(tags == ["IDAG", "IMTS"], "finds both commitments in one coinbase")
idag = [x for x in r["op_returns"] if x["tag"] == "IDAG"][0]
imts = [x for x in r["op_returns"] if x["tag"] == "IMTS"][0]
ok(idag["count"] == 2 and imts["offset_ms"] == 459,
   "recovers the parent count and the millisecond offset from the same coinbase")
# A coinbase with only the producer output carries neither.
r = json.loads(run("coinbase", cb([])))
ok(r["op_returns"] == [], "finds no commitment in a coinbase that carries none")

print()
print("checks: %d passed, %d failed" % (PASSED, FAILED))
sys.exit(1 if FAILED else 0)
