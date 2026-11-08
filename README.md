# VigHill – a two-stage classical cipher (Vigenère → Hill 2×2) and its break

```
python3 cipher.py enc --vkey SECRETLONGKEY --hkey DDCF "Attack at dawn"
python3 cipher.py dec --vkey SECRETLONGKEY --hkey DDCF <ciphertext>
python3 run_experiments.py     # regenerates results.json (all numbers in REPORT.md)
python3 -m pytest tests
```
Files: `cipher.py` (encrypt/decrypt + shift/Vigenère baselines), `attacks.py` (frequency analysis + known-plaintext attack),
`run_experiments.py`, `corpus.py` (English sample + letter frequencies), `results.json`, `REPORT.md`.
