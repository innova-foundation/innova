#!/usr/bin/env python3
# Independent PQXDH/X3DH combiner and ratchet KDF vectors for nyx_session_tests (pure Python: RFC 5869, RFC 7748).
import hmac, hashlib
def hkdf(salt, ikm, info, n):
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    out=b''; t=b''; i=1
    while len(out)<n:
        t=hmac.new(prk, t+info+bytes([i]), hashlib.sha256).digest(); out+=t; i+=1
    return out[:n]
P=2**255-19; A24=121665
def x25519(k,u):
    k=bytearray(k); k[0]&=248; k[31]&=127; k[31]|=64; k=int.from_bytes(k,'little')
    u=int.from_bytes(u,'little')&((1<<255)-1)
    x1=u; x2,z2,x3,z3=1,0,u,1; sw=0
    for t in reversed(range(255)):
        kt=(k>>t)&1; sw^=kt
        if sw: x2,x3=x3,x2; z2,z3=z3,z2
        sw=kt
        a=(x2+z2)%P; aa=a*a%P; b=(x2-z2)%P; bb=b*b%P; e=(aa-bb)%P; c=(x3+z3)%P; d=(x3-z3)%P
        da=d*a%P; cb=c*b%P; x3=(da+cb)**2%P; z3=x1*(da-cb)**2%P; x2=aa*bb%P; z2=e*(aa+A24*e)%P
    if sw: x2,x3=x3,x2; z2,z3=z3,z2
    return (x2*pow(z2,P-2,P)%P).to_bytes(32,'little')
def pub(sk): return x25519(sk,(9).to_bytes(32,'little'))
def dh(sk,pk): return x25519(sk,pk)
# RFC 7748 6.1 check
a=bytes.fromhex('77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a')
assert pub(a).hex()=='8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a'
ikA=bytes([0x11]*32); ekA=bytes([0x22]*32); ikB=bytes([0x33]*32); spkB=bytes([0x44]*32); opkB=bytes([0x55]*32); ss=bytes([0x66]*32)
d1=dh(ikA,pub(spkB)); d2=dh(ekA,pub(ikB)); d3=dh(ekA,pub(spkB)); d4=dh(ekA,pub(opkB))
F=b'\xff'*32; z=b'\0'*32
pq4=hkdf(z,F+d1+d2+d3+d4+ss,b"NyxPQXDH_CURVE25519_SHA-256_ML-KEM-768",96)
pq3=hkdf(z,F+d1+d2+d3+ss,b"NyxPQXDH_CURVE25519_SHA-256_ML-KEM-768",96)
cl4=hkdf(z,F+d1+d2+d3+d4,b"NyxX3DH_CURVE25519_SHA-256",96)
rk=hkdf(bytes([0x77]*32), bytes([0x88]*32), b"NyxRatchetRK",96)
ck=bytes([0x99]*32)
m=hmac.new(ck,b'\x01',hashlib.sha256).digest(); ck2=hmac.new(ck,b'\x02',hashlib.sha256).digest()
mk=hkdf(z,m,b"NyxMsgKey",32)
for n,v in [("pq4",pq4),("pq3",pq3),("cl4",cl4),("rk",rk),("ck2",ck2),("mk",mk),("dh1",d1)]:
    print(n, v.hex())
