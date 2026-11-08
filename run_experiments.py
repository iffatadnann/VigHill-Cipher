"""Reproduces every number in REPORT.md. Usage: python3 run_experiments.py"""
import random, time, string, json
from cipher import *
from corpus import PLAIN
from attacks import *

random.seed(2026)
rand_key = lambda n: "".join(random.choice(string.ascii_uppercase) for _ in range(n))

def rand_hill():
    while True:
        k = rand_key(4)
        try:
            parse_hill_key(k); return k
        except ValueError:
            pass

def sample(n):
    s = random.randrange(0, len(PLAIN) - n)
    s -= s % 2
    return PLAIN[s:s + n]

R = {}
# ---- 1. correctness
ok = 0
for _ in range(2000):
    n = random.randint(1, 300)
    p = "".join(random.choice(string.ascii_uppercase) for _ in range(n))
    vk, hk = rand_key(random.randint(10, 20)), rand_hill()
    c = encrypt(p, vk, hk)
    ok += decrypt(c, vk, hk).rstrip("X") == p.rstrip("X") if n % 2 else decrypt(c, vk, hk) == p
R["roundtrip_ok_of_2000"] = ok

# ---- 2. KPA vs known length (L=12) and other key lengths
T = 500
kpa_tab = []
for L in (10, 12, 15):
    for known in (12, 16, 20, 24, 28, 32, 40, 60):
        full = fixed = 0; tm = 0
        for _ in range(T):
            vk, hk = rand_key(L), rand_hill()
            p = sample(200); c = encrypt(p, vk, hk)
            off = 2 * random.randint(0, 20)
            t0 = time.perf_counter()
            H, key, found = kpa(p[off:off + known], c[off:off + known], L, off)
            tm += time.perf_counter() - t0
            fixed += H is not None and H == parse_hill_key(hk)
            if found == L and H:
                full += "".join(chr(k + 65) for k in key) == vk
        kpa_tab.append(dict(L=L, known=known, hill_recovered=fixed / T, full_key=full / T, ms=1000 * tm / T))
R["kpa"] = kpa_tab

# ---- 3. frequency analysis vs ciphertext length
fa = []
for n in (50, 100, 200, 400, 800, 1600):
    row = dict(n=n); T2 = 200
    big = (PLAIN * 3)
    def smp(n):
        s = random.randrange(0, len(big) - n); return big[s:s + n]
    # shift
    ok = 0
    for _ in range(T2):
        k = random.randrange(26); p = smp(n); ok += attack_shift(shift_encrypt(p, k)) == k
    row["shift_key"] = ok / T2
    # Vigenere alone (12-letter key), period unknown
    ok = per = 0
    for _ in range(T2):
        vk = rand_key(12); p = smp(n); c = vigenere(p, vk, 1)
        per += guess_period(c) in (12, 6, 4, 3, 2, 1) and guess_period(c) == 12
        ok += attack_vigenere(c, 12) == vk
    row["vig_period_found"] = per / T2; row["vig_key_known_period"] = ok / T2
    # VigHill
    acc = ics = 0.0; exact = 0
    for _ in range(T2):
        vk, hk = rand_key(12), rand_hill(); p = smp(n - n % 2); c = encrypt(p, vk, hk)
        g = attack_vighill_freq(c, 12)
        acc += sum(a == b for a, b in zip(g, p)) / len(p); exact += g == p
        ics += index_of_coincidence(c)
    row["vighill_letters_correct"] = acc / T2; row["vighill_exact"] = exact / T2; row["vighill_IC"] = ics / T2
    fa.append(row)
R["freq"] = fa
R["IC_english"] = index_of_coincidence(PLAIN)

# ---- 4. timing
tim = []
for n in (10**3, 10**4, 10**5, 10**6):
    p = "".join(random.choices(string.ascii_uppercase, k=n)); vk, hk = "SECRETLONGKEY", "DDCF"
    t = time.perf_counter(); c = encrypt(p, vk, hk); te = time.perf_counter() - t
    t = time.perf_counter(); decrypt(c, vk, hk); td = time.perf_counter() - t
    t = time.perf_counter(); s = shift_encrypt(p, 7); ts = time.perf_counter() - t
    t = time.perf_counter(); shift_decrypt(s, 7); tsd = time.perf_counter() - t
    t = time.perf_counter(); vigenere(p, vk, 1); tv = time.perf_counter() - t
    t = time.perf_counter(); kpa(p[:40], c[:40], 13) ; tk = time.perf_counter() - t
    tim.append(dict(n=n, vighill_enc=te, vighill_dec=td, shift_enc=ts, shift_dec=tsd, vig_enc=tv))
R["timing"] = tim
t = time.perf_counter()
for _ in range(1000):
    p = sample(200); c = encrypt(p, "SECRETLONGKE", "DDCF"); kpa(p[:40], c[:40], 12)
R["kpa_total_seconds_for_1000_runs"] = (time.perf_counter() - t)
json.dump(R, open("results.json", "w"), indent=1)
print(json.dumps(R, indent=1))
