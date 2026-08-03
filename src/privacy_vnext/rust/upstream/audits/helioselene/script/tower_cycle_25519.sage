#!/usr/bin/env sage
# -*- coding: utf-8 -*-

# This script finds efficient elliptic curve tower-cycles for Curve25519.
# The algorithm is described in this paper: https://arxiv.org/pdf/0712.2022.pdf

import sys
from multiprocessing import Pool, cpu_count
from traceback import print_exc

p = 2^255 - 19

# https://en.wikipedia.org/wiki/Cornacchia%27s_algorithm
# Finds [x,y] that solves x^2+d*y^2=m

def cornacchia_inner(r, m, d):
    sm = isqrt(m)
    t = m
    while r > sm:
        rn = t % r
        t = r
        r = rn
    s2 = m - r^2
    if s2 % d != 0:
        return (None, "s2 not divisible by d")
    s2 //= d
    s = isqrt(s2)
    if s*s == s2:
        return (r, s)
    return (None, "sqrt(s2) not an integer")

def cornacchia(d, m):
    rall = Mod(-d, m).sqrt(extend=False, all=True)
    if not rall:
        return (None, "No sqrt mod m")
    # test all square roots
    for r in rall:
        (x, y) = cornacchia_inner(int(r), m, d)
        if x:
            break
    return (x, y)

# Find an isomorphism with a specific value of the curve parameter "a".
def get_iso(E, ax):
    a = E.a4()
    b = E.a6()
    f = E.base_field()
    u4 = a / ax
    us = u4.nth_root(4,all=True)
    if not us:
        return None
    # sorting for determinism
    us.sort()
    u = us[0]
    bx = b / u^6
    Eu = EllipticCurve([f(ax), bx])
    assert Eu.is_isomorphic(E)
    return Eu

def check_curve(E):
    # a = -3 for efficient doubling https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html
    iso = get_iso(E, -3)
    if iso is None:
        return (E, "a = -3")
    E = iso
    b = E.a6()
    if b.is_square():
        return (E, "b is non-square")
    try:
        E.lift_x(1)
    except (ValueError):
        return (E, "x=1 on curve")
    return (E, None)

def to_signed(x):
    o = int(x.order())
    i = int(x)
    if i > o - 1000:
        return i - o
    return i

def curve_to_str(E, reason):
    a = to_signed(E.a4())
    b = E.a6()
    estr = "        y^2=x^3"
    if a == 1:
        estr += "+"
    elif a == -1:
        estr += "-"
    else:
        estr += "%+i*" % a
    estr += "x+%i" % b
    if reason:
        estr += ", failed condition: %s" % reason
    return estr + "\n"

def find_curves(d, q):
    H = hilbert_class_polynomial(d)
    Fp = GF(p)
    Fq = GF(q)
    Sp = H.roots(GF(p), False)
    Sq = H.roots(GF(q), False)
    # sorting for determinism
    Sp.sort()
    Sq.sort()
    zp = Fp(2)
    zq = Fq(2)
    # smallest non-squares in the fields
    while zp.is_square():
        zp += 1
    while zq.is_square():
        zq += 1
    output = "    Ep:\n"
    for j0 in Sp:
        ap = 27*j0/(4*(1728-j0))
        Ep = EllipticCurve([ap, -ap])
        rp = Ep.count_points()
        if rp == q:
            (Ep, reason) = check_curve(Ep)
            output += curve_to_str(Ep, reason)
            if not reason:
                break
        # explicit twisting parameter for determinism
        Ep = Ep.quadratic_twist(zp)
        rp = Ep.count_points()
        if rp == q:
            (Ep, reason) = check_curve(Ep)
            output += curve_to_str(Ep, reason)
            if not reason:
                break
    output += "    Eq:\n"
    for j0 in Sq:
        aq = 27*j0/(4*(1728-j0))
        Eq = EllipticCurve([aq, -aq])
        rq = Eq.count_points()
        if rq == p:
            (Eq, reason) = check_curve(Eq)
            output += curve_to_str(Eq, reason)
            if not reason:
                break
        # explicit twisting parameter for determinism
        Eq = Eq.quadratic_twist(zq)
        rq = Eq.count_points()
        if rq == p:
            (Eq, reason) = check_curve(Eq)
            output += curve_to_str(Eq, reason)
            if not reason:
                break
    return output

pi_4 = (pi/4).numerical_approx()

def twist_security(p, q):
    # the number of points of the quadratic twist of Ep
    nt = 2 * (p + 1) - q
    # the largest prime order subgroup
    qt = factor(nt)[-1][0]
    # ECDLP security in bits = log2(sqrt(pi/4 * qt)) = log4(pi/4 * qt)
    return log(pi_4 * qt, 4)

def print_curves(d, q):
    reason = None
    if q % 4 != 3:
        reason = "q = 3 mod 4"
    elif 2^256 - 2*q >= 2^128:
        reason = "2^256 - 2*q < 2^128"
    elif twist_security(p, q) < 100:
        reason = "Ep twist security"
    elif twist_security(q, p) < 100:
        reason = "Eq twist security"
    if reason:
        sys.stdout.write("D = %i, q = %s, failed condition: %s\n" % (d, hex(q), reason))
        sys.stdout.flush()
        return False
    output = "D = %i, q = %s\n" % (d, hex(q))
    output += find_curves(d, q)
    sys.stdout.write(output)
    sys.stdout.flush()
    return True

def get_discriminants(wid, processes):
    # -D must be 3 mod 8
    for d in range(3 + 8 * wid, 1000000000, 8 * processes):
        yield d

def find_primes(wid, processes):
    for d in get_discriminants(wid, processes):
        (x, y) = cornacchia(d, 4*p)
        if x == None:
            continue
        q = p + 1 - x
        if is_prime(q):
            yield (-d, q)

def run_search(wid, processes):
    for (d, q) in find_primes(wid, processes):
        if print_curves(d, q):
            break

def worker(*args):
    try:
        run_search(*args)
    except (KeyboardInterrupt, SystemExit):
        pass
    except:
        print_exc()

processes = 1
print("p = %s" % hex(p))
print("Searching for curves using %i process(es)." % (processes,))

pool = Pool(processes=processes)

try:
    for wid in range(processes):
        pool.apply_async(worker, (wid, processes))

    pool.close()
    pool.join()
except (KeyboardInterrupt, SystemExit):
    pass
finally:
    pool.terminate()
