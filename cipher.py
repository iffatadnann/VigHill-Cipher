"""
VigHill: a two-stage classical cipher.
  Stage 1: Vigenere cipher  (keyed polyalphabetic substitution, key >= 10 letters)
  Stage 2: Hill cipher 2x2  (keyed digraph diffusion, 4-letter key = matrix [[a,b],[c,d]])
Alphabet: A-Z only (non-letters are stripped, lower case is upper-cased).
If the cleaned plaintext has odd length, 'X' is appended (Hill needs pairs).
"""
import argparse
from math import gcd

M = 26


def clean(text: str) -> str:
    return "".join(c for c in text.upper() if "A" <= c <= "Z")


def modinv(a: int, m: int = M) -> int:
    a %= m
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    raise ValueError(f"{a} has no inverse mod {m}")


# ---------------------------------------------------------------- Hill key
def parse_hill_key(key: str):
    """4 letters -> (a,b,c,d). Must be invertible mod 26 (gcd(det,26)=1)."""
    k = clean(key)
    if len(k) != 4:
        raise ValueError("Hill key must be exactly 4 letters (matrix a b / c d)")
    a, b, c, d = (ord(x) - 65 for x in k)
    if gcd((a * d - b * c) % M, M) != 1:
        raise ValueError("Hill matrix not invertible mod 26; choose another key")
    return a, b, c, d


def hill_inverse(K):
    a, b, c, d = K
    di = modinv(a * d - b * c)
    return (d * di % M, -b * di % M, -c * di % M, a * di % M)


def hill_apply(text: str, K) -> str:
    a, b, c, d = K
    out = []
    for i in range(0, len(text), 2):
        x, y = ord(text[i]) - 65, ord(text[i + 1]) - 65
        out.append(chr((a * x + b * y) % M + 65))
        out.append(chr((c * x + d * y) % M + 65))
    return "".join(out)


# ---------------------------------------------------------------- Vigenere
def vigenere(text: str, key: str, sign: int = 1) -> str:
    k = [ord(c) - 65 for c in key]
    L = len(k)
    return "".join(chr((ord(c) - 65 + sign * k[i % L]) % M + 65) for i, c in enumerate(text))


# ---------------------------------------------------------------- Shift (baseline)
def shift_encrypt(text: str, k: int) -> str:
    return "".join(chr((ord(c) - 65 + k) % M + 65) for c in clean(text))


def shift_decrypt(text: str, k: int) -> str:
    return shift_encrypt(text, -k)


# ---------------------------------------------------------------- VigHill
def check_keys(vkey: str, hkey: str):
    v = clean(vkey)
    if len(v) < 10:
        raise ValueError("Vigenere key must have at least 10 letters")
    return v, parse_hill_key(hkey)


def encrypt(plain: str, vkey: str, hkey: str) -> str:
    v, K = check_keys(vkey, hkey)
    p = clean(plain)
    if len(p) % 2:
        p += "X"
    return hill_apply(vigenere(p, v, +1), K)          # C = H (P + V)


def decrypt(cipher: str, vkey: str, hkey: str) -> str:
    v, K = check_keys(vkey, hkey)
    c = clean(cipher)
    if len(c) % 2:
        raise ValueError("ciphertext length must be even")
    return vigenere(hill_apply(c, hill_inverse(K)), v, -1)   # P = H^-1 C - V


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="VigHill cipher (Vigenere -> Hill 2x2)")
    ap.add_argument("mode", choices=["enc", "dec"])
    ap.add_argument("--vkey", required=True, help="Vigenere key, >=10 letters")
    ap.add_argument("--hkey", required=True, help="Hill key, 4 letters")
    ap.add_argument("text")
    a = ap.parse_args()
    print((encrypt if a.mode == "enc" else decrypt)(a.text, a.vkey, a.hkey))
