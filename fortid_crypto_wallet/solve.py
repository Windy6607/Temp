#!/usr/bin/env python3
"""FortID "crypto_wallet" solver.

The APK's MainActivity.z() treats the 12-word recovery phrase as four
what3words addresses (///w1.w2.w3, ///w4.w5.w6, ...), each of which must lie
within 900 m of one of four coordinates baked into libwalletverify.so
(any assignment counts - it's a perfect-matching check):

    41.991750, -87.889806   Chicago O'Hare (ORD)
    33.941589, -118.408530  Los Angeles (LAX)
    44.884755, -93.222284   Minneapolis-St Paul (MSP)
    40.641311, -73.778139   New York JFK

The phrase must then be a valid BIP-39 mnemonic whose m/44'/60'/0'/0/0
Ethereum address is 0xdc7d8b278af5f31fed5fe68f50be6d02404fb522. The flag is
AES-GCM-decrypted with key sha256(privkey || "FortID/cryptocurrency-wallet/flag/v1").

Usage: python3 solve.py ///a.b.c ///d.e.f ///g.h.i ///j.k.l
Every ordering of the four groups is tried, so pass them in any order.
"""
import base64
import hashlib
import hmac
import itertools
import os
import sys

from Crypto.Cipher import AES
from Crypto.Hash import keccak

TARGET = "0xdc7d8b278af5f31fed5fe68f50be6d02404fb522"
NONCE = base64.b64decode("NaY6LHeKYbf9abvi")
CT = base64.b64decode("7ue/WCpa19Wp+mKFu1PHsuTknMRzHqRamlwGVXWJCmMw7smZ/9PzoWkhi80Ezgs9tQ==")

P = 2**256 - 2**32 - 977
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)


def ec_add(a, b):
    if a is None:
        return b
    if b is None:
        return a
    if a[0] == b[0] and (a[1] + b[1]) % P == 0:
        return None
    if a == b:
        lam = 3 * a[0] * a[0] * pow(2 * a[1], -1, P) % P
    else:
        lam = (b[1] - a[1]) * pow(b[0] - a[0], -1, P) % P
    x = (lam * lam - a[0] - b[0]) % P
    return x, (lam * (a[0] - x) - a[1]) % P


def ec_mul(k):
    r, q = None, G
    while k:
        if k & 1:
            r = ec_add(r, q)
        q = ec_add(q, q)
        k >>= 1
    return r


def pub(k, compressed):
    x, y = ec_mul(k)
    if compressed:
        return bytes([2 + (y & 1)]) + x.to_bytes(32, "big")
    return b"\x04" + x.to_bytes(32, "big") + y.to_bytes(32, "big")


WORDLIST = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "bip39_english.txt")).read().split()
INDEX = {w: i for i, w in enumerate(WORDLIST)}


def checksum_ok(words):
    if len(words) != 12 or any(w not in INDEX for w in words):
        return False
    bits = int("".join(f"{INDEX[w]:011b}" for w in words), 2)
    entropy = (bits >> 4).to_bytes(16, "big")
    return bits & 0xF == hashlib.sha256(entropy).digest()[0] >> 4


def derive_privkey(words):
    seed = hashlib.pbkdf2_hmac("sha512", " ".join(words).encode(), b"mnemonic", 2048)
    i = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    k, chain = int.from_bytes(i[:32], "big"), i[32:]
    for idx in (0x8000002C, 0x8000003C, 0x80000000, 0, 0):  # m/44'/60'/0'/0/0
        data = (b"\x00" + k.to_bytes(32, "big") if idx & 0x80000000 else pub(k, True)) + idx.to_bytes(4, "big")
        i = hmac.new(chain, data, hashlib.sha512).digest()
        k, chain = (int.from_bytes(i[:32], "big") + k) % N, i[32:]
    return k


def eth_address(k):
    h = keccak.new(digest_bits=256, data=pub(k, False)[1:]).digest()
    return "0x" + h[12:].hex()


def decrypt_flag(k):
    key = hashlib.sha256(k.to_bytes(32, "big") + b"FortID/cryptocurrency-wallet/flag/v1").digest()
    c = AES.new(key, AES.MODE_GCM, nonce=NONCE)
    c.update(b"wallet-recovery")
    return c.decrypt_and_verify(CT[:-16], CT[-16:]).decode()


def main(args):
    groups = [a.strip().lstrip("/").lower().split(".") for a in args]
    if len(groups) != 4 or any(len(g) != 3 for g in groups):
        sys.exit(__doc__)
    for g in groups:
        bad = [w for w in g if w not in INDEX]
        if bad:
            print(f"warning: {'.'.join(g)} has non-BIP39 words {bad}; that can't be a seed group")
    for perm in itertools.permutations(groups):
        words = [w for g in perm for w in g]
        if not checksum_ok(words):
            continue
        k = derive_privkey(words)
        addr = eth_address(k)
        print(f"checksum ok: {' '.join(words)} -> {addr}")
        if addr == TARGET:
            print("FLAG:", decrypt_flag(k))
            return
    print("no ordering produced the target address")


if __name__ == "__main__":
    main(sys.argv[1:])
