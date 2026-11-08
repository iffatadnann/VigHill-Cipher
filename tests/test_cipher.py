import sys, os, random, string
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
import pytest
from cipher import *
from attacks import kpa
from corpus import PLAIN

VK, HK = "SECRETLONGKEY", "DDCF"

def test_roundtrip_even_and_odd():
    for n in (1, 2, 3, 10, 99, 1000):
        p = "".join(random.choice(string.ascii_uppercase) for _ in range(n))
        d = decrypt(encrypt(p, VK, HK), VK, HK)
        assert d[:n] == p and len(d) in (n, n + 1)

def test_cleaning():
    assert decrypt(encrypt("Hello, World!", VK, HK), VK, HK) == "HELLOWORLD"

def test_short_vigenere_key_rejected():
    with pytest.raises(ValueError):
        encrypt("HELLO", "SHORTKEY", HK)

def test_non_invertible_hill_rejected():
    with pytest.raises(ValueError):
        encrypt("HELLO", VK, "GYBN")

def test_kpa_recovers_both_keys():
    p = PLAIN[:200]; c = encrypt(p, VK, HK)
    H, key, found = kpa(p[:40], c[:40], len(VK), 0)
    assert H == parse_hill_key(HK) and found == len(VK)
    assert "".join(chr(k + 65) for k in key) == VK
