"""Attacks: (1) frequency analysis (shift, Vigenere, VigHill), (2) known-plaintext attack on VigHill."""
from math import gcd
from cipher import M, modinv, hill_inverse, hill_apply, vigenere, shift_decrypt
from corpus import ENGLISH_FREQ

EXP = [f / 100 for f in ENGLISH_FREQ]


# ------------------------------------------------------------- statistics
def index_of_coincidence(t: str) -> float:
    n = len(t)
    if n < 2:
        return 0.0
    cnt = [0] * 26
    for c in t:
        cnt[ord(c) - 65] += 1
    return sum(x * (x - 1) for x in cnt) / (n * (n - 1))


def chi2_shift(col: str, s: int) -> float:
    """chi^2 of column decrypted with shift s vs English."""
    n = len(col)
    cnt = [0] * 26
    for c in col:
        cnt[(ord(c) - 65 - s) % 26] += 1
    return sum((cnt[i] - n * EXP[i]) ** 2 / (n * EXP[i]) for i in range(26))


def best_shift(col: str) -> int:
    return min(range(26), key=lambda s: chi2_shift(col, s))


# ------------------------------------------------------------- frequency analysis
def attack_shift(ct: str) -> int:
    return best_shift(ct)


def guess_period(ct: str, max_p: int = 20, thr: float = 0.055) -> int:
    for p in range(1, max_p + 1):
        cols = [ct[i::p] for i in range(p)]
        if sum(index_of_coincidence(c) for c in cols) / p > thr:
            return p
    return 0


def attack_vigenere(ct: str, period: int = 0) -> str:
    """Ciphertext-only: IC to find the period, chi^2 per column to find the key."""
    p = period or guess_period(ct)
    if p == 0:
        return ""
    return "".join(chr(best_shift(ct[i::p]) + 65) for i in range(p))


def attack_vighill_freq(ct: str, key_len: int) -> str:
    """Naive frequency analysis against VigHill: treat it as Vigenere with the true key length.
    Returns the (wrong) 'plaintext' guess, to measure how much of the message is recovered."""
    key = "".join(chr(best_shift(ct[i::key_len]) + 65) for i in range(key_len))
    return vigenere(ct, key, -1)


# ------------------------------------------------------------- known-plaintext attack
def _mat_inv2(m00, m01, m10, m11):
    det = (m00 * m11 - m01 * m10) % M
    if gcd(det, M) != 1:
        return None
    di = modinv(det)
    return (m11 * di % M, -m01 * di % M, -m10 * di % M, m00 * di % M)


def _mul(A, B):
    a, b, c, d = A
    e, f, g, h = B
    return ((a * e + b * g) % M, (a * f + b * h) % M, (c * e + d * g) % M, (c * f + d * h) % M)


def kpa(known_p: str, known_c: str, key_len: int, offset: int = 0):
    """
    Known-plaintext attack on VigHill.
    known_p/known_c : aligned known plaintext / ciphertext (same length, starting at even `offset`).
    Idea: C_d = H (P_d + K_d) with K_d repeating every p digraphs (p = lcm(L,2)/2).
          C_d - C_{d+p} = H (P_d - P_{d+p})  -> the key K cancels, leaving a linear system for H.
          Then K_d = H^-1 C_d - P_d recovers the Vigenere key.
    Returns (H or None, key list of length L with None for unknown letters, number of key letters found).
    """
    L = key_len
    p = L // 2 if L % 2 == 0 else L
    n = len(known_p) // 2
    k0 = offset // 2
    P = [(ord(known_p[2 * i]) - 65, ord(known_p[2 * i + 1]) - 65) for i in range(n)]
    C = [(ord(known_c[2 * i]) - 65, ord(known_c[2 * i + 1]) - 65) for i in range(n)]
    D = [((P[i][0] - P[i + p][0]) % M, (P[i][1] - P[i + p][1]) % M,
          (C[i][0] - C[i + p][0]) % M, (C[i][1] - C[i + p][1]) % M) for i in range(n - p)]
    H = None
    for i in range(len(D)):
        for j in range(i + 1, len(D)):
            inv = _mat_inv2(D[i][0], D[j][0], D[i][1], D[j][1])   # columns = difference vectors
            if inv is None:
                continue
            cand = _mul((D[i][2], D[j][2], D[i][3], D[j][3]), inv)
            if _mat_inv2(*cand) is None:
                continue
            if all((cand[0] * d[0] + cand[1] * d[1]) % M == d[2] and
                   (cand[2] * d[0] + cand[3] * d[1]) % M == d[3] for d in D):
                H = cand
                break
        if H:
            break
    if H is None:
        return None, [None] * L, 0
    Hi = hill_inverse(H)
    key = [None] * L
    for i in range(n):
        x = (Hi[0] * C[i][0] + Hi[1] * C[i][1] - P[i][0]) % M
        y = (Hi[2] * C[i][0] + Hi[3] * C[i][1] - P[i][1]) % M
        d = k0 + i
        key[(2 * d) % L] = x
        key[(2 * d + 1) % L] = y
    return H, key, sum(k is not None for k in key)


def decrypt_with_recovered(ct: str, H, key, offset_unused=0) -> str:
    """Decrypt the whole ciphertext; unknown key letters are shown as '?'."""
    Hi = hill_inverse(H)
    mid = hill_apply(ct, Hi)
    L = len(key)
    return "".join("?" if key[i % L] is None else chr((ord(c) - 65 - key[i % L]) % M + 65)
                   for i, c in enumerate(mid))
