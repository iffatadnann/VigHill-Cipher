# VigHill: Design, Attack and Analysis of a Two-Stage Classical Cipher

## 1. Cipher Design and Implementation

### 1.1 Background: the classical building blocks used

| Cipher | What it does | Strength | Weakness |
|---|---|---|---|
| Shift (Caesar) | Adds one fixed number k to every letter (mod 26) | Simple, fast | Only 26 keys; letter frequencies unchanged |
| Vigenère | Adds a *different* number to each letter, taken from a repeating keyword | Flattens single-letter frequencies | Key repeats → period can be found; each column is just a Shift |
| Hill (2×2) | Multiplies each pair of letters by a 2×2 matrix (mod 26) | Mixes two letters together (diffusion); hides single-letter *and* most digraph frequencies | Purely linear → falls to known-plaintext |

**Selected for VigHill:** Vigenère (which is itself a keyed family of Shift ciphers) and Hill. Affine was not needed: its effect (multiply + add) is already contained in Hill-with-an-offset, which is exactly what the combination produces (see 1.4).

### 1.2 Notation and keys

* Letters are numbers: A=0, B=1, … Z=25. All arithmetic is **mod 26**.
* Plaintext P = p₀ p₁ … p_{n−1}. Input is upper-cased, non-letters removed, and if n is odd one `X` is appended so n is even.
* **Key 1 – Vigenère key** Kv = k₀ k₁ … k_{L−1}, **L ≥ 10 letters** (default `SECRETLONGKEY`, L = 13).
* **Key 2 – Hill key** (4 letters a b c d) forming the matrix  H = [[a, b], [c, d]].
  Valid only if **gcd(det H, 26) = 1**, where det H = ad − bc (mod 26). Otherwise H has no inverse and decryption is impossible; the program rejects such keys.
* Total secret = L + 4 ≥ 14 letters.

### 1.3 Algorithms

**Preprocessing** (both directions)
```
1. Convert to upper case; delete everything that is not A–Z.
2. (Encryption only) If length is odd, append 'X'.
```

**Encryption algorithm  Enc(P, Kv, H)**
```
Input : plaintext P (even length n), Vigenère key Kv (length L ≥ 10), Hill matrix H
Output: ciphertext C (length n)

Stage 1 – Vigenère (substitution, position-dependent)
 1. for i = 0 … n−1:
 2.      s[i] = ( p[i] + k[i mod L] ) mod 26

Stage 2 – Hill 2×2 (diffusion on pairs)
 3. for j = 0, 2, 4, … , n−2:
 4.      c[j]   = ( a·s[j] + b·s[j+1] ) mod 26
 5.      c[j+1] = ( c·s[j] + d·s[j+1] ) mod 26
 6. return C
```
In one line:  **C₍pair j₎ = H · ( P₍pair j₎ + Kv₍pair j₎ ) mod 26.**

**Encryption algorithm in words**
1. Take the message. Turn every letter into capitals and throw away spaces, digits and punctuation, so only the letters A to Z remain.
2. Count the letters. If the count is odd, add one extra `X` at the end so the letters can be grouped into pairs.
3. Turn each letter into a number: A is 0, B is 1, and so on up to Z, which is 25.
4. **Stage 1 (Vigenère).** Write the secret keyword (at least 10 letters) under the message and repeat it as many times as needed until every message letter has a key letter beneath it. Turn the key letters into numbers in the same way. For each position, add the key number to the message number. If the total is 26 or more, subtract 26 (wrap around the alphabet). This gives an intermediate list of numbers.
5. **Stage 2 (Hill).** Split the intermediate numbers into consecutive pairs. Take the four Hill key letters, turn them into numbers a, b, c, d, and arrange them as a 2-by-2 grid. For each pair (x, y), make two new numbers: the first is a times x plus b times y; the second is c times x plus d times y. Replace each result by its remainder after dividing by 26.
6. Turn all the resulting numbers back into letters. This string is the ciphertext.

**Decryption algorithm  Dec(C, Kv, H)**  (inverse of each stage, in *reverse order*)
```
Input : ciphertext C (even length n), same Kv and H
Output: plaintext P

Preparation
 1. det = (a·d − b·c) mod 26
 2. det⁻¹ = the number x in 1…25 with det·x ≡ 1 (mod 26)      (exists since gcd(det,26)=1)
 3. H⁻¹ = det⁻¹ · [[ d, −b ], [ −c, a ]]  mod 26   =  [[a', b'], [c', d']]

Undo Stage 2 – inverse Hill
 4. for j = 0, 2, 4, … , n−2:
 5.      s[j]   = ( a'·c[j] + b'·c[j+1] ) mod 26
 6.      s[j+1] = ( c'·c[j] + d'·c[j+1] ) mod 26

Undo Stage 1 – inverse Vigenère
 7. for i = 0 … n−1:
 8.      p[i] = ( s[i] − k[i mod L] ) mod 26
 9. return P   (drop a trailing padding 'X' if the original length was odd)
```
In one line:  **P₍pair j₎ = H⁻¹ · C₍pair j₎ − Kv₍pair j₎ mod 26.**

Why it is correct: H⁻¹·(H·x) = x for the Hill part, and (x + k) − k = x for the Vigenère part; the stages are undone in the opposite order to how they were applied (like taking off socks after shoes).

**Decryption algorithm in words**
1. Take the ciphertext, which always has an even number of letters, and turn each letter into a number (A = 0 … Z = 25).
2. Prepare the reverse of the Hill grid. Work out the determinant of the key grid: a times d minus b times c, remainder after dividing by 26. Find the number that, multiplied by the determinant, leaves remainder 1 when divided by 26 (its modular inverse). Build the inverse grid by swapping a and d, changing the signs of b and c, multiplying all four entries by that inverse number, and taking remainders after dividing by 26.
3. **Undo Stage 2 (Hill).** Split the ciphertext numbers into pairs. Multiply each pair by the inverse grid exactly as in encryption (first new number = a′ times x plus b′ times y; second = c′ times x plus d′ times y, each taken mod 26). This restores the intermediate list produced by the Vigenère stage.
4. **Undo Stage 1 (Vigenère).** Write the same secret keyword under the numbers, repeating it as before. For each position, subtract the key number from the number; if the answer is negative, add 26 (wrap around backwards).
5. Turn the numbers back into letters. If an extra `X` was added during encryption because the message length was odd, remove it. The result is the original message (in capitals, without spaces or punctuation).
6. The order matters: the last step of encryption (Hill) must be the first thing undone, and the first step of encryption (Vigenère) must be the last thing undone.

### 1.4 How the two classical techniques are combined (detailed explanation)

1. **Pipeline (product cipher).** The output of the first cipher is the input of the second. This is the classical idea of a *product cipher* (Shannon): combine **confusion** (making the key–ciphertext relationship complicated) with **diffusion** (spreading each plaintext letter's influence over several ciphertext letters).
   * **Vigenère = confusion / substitution.** It replaces each letter by another one, with the replacement depending on *position* (via the repeating keyword). Result: the same plaintext letter, e.g. `E`, becomes different ciphertext letters at different places, so single-letter frequencies are flattened.
   * **Hill = diffusion.** Each output letter is a mix of **two** input letters (e.g. c₀ = 3·s₀ + 3·s₁). Changing one plaintext letter changes *both* letters of its pair. It also destroys the column structure that a Vigenère break relies on, because the two letters of a pair come from *different* key positions (kᵢ and kᵢ₊₁).
2. **Why the order Vigenère → Hill (and not the reverse).** If Hill were applied first, the Vigenère shifts would be applied to the output, and a Vigenère-style frequency attack on columns would work on the Hill-ed text. With Vigenère first, the final ciphertext letters are mixtures of letters from different shift columns, so column-by-column frequency analysis (the standard attack on Vigenère) gets nothing (measured IC ≈ 0.039 ≈ random).
3. **Key interaction.** The two keys are independent, so the attacker must find both. The combined key space is 26^L × 157 248 (number of invertible 2×2 matrices mod 26) ≈ 2^73.7 for L = 12.
4. **Alignment between the stages.** Hill works on blocks of 2 and Vigenère has period L, so the key pattern seen by the Hill blocks repeats every p = lcm(L, 2)/2 blocks (L/2 if L is even, L if L is odd).
5. **Algebraic form of the combination.** Combining the formulas for one block j gives  
   C_j = H·P_j + H·K_j  (mod 26), where K_j = (k_{2j mod L}, k_{(2j+1) mod L}).  
   That is a **Hill cipher with a periodic, key-dependent offset** (a position-dependent affine Hill cipher). This also explains the main security finding (Section 3.2): the whole cipher is still linear, so subtracting two blocks with the same offset cancels the Vigenère key.

### 1.5 Worked example (by hand; matches the program output)

Keys: Kv = `SECRETLONGKEY` = [18, 4, 2, 17, 4, 19, 11, 14, 13, 6, 10, 4, 24];  Hill key `DDCF` → a=3, b=3, c=2, d=5, H = [[3,3],[2,5]].
Plaintext: `ATTACKATDAWN` = [0, 19, 19, 0, 2, 10, 0, 19, 3, 0, 22, 13].

*Stage 1 (Vigenère), p + k mod 26:*
0+18=18 (S), 19+4=23 (X), 19+2=21 (V), 0+17=17 (R), 2+4=6 (G), 10+19=29→3 (D), 0+11=11 (L), 19+14=33→7 (H), 3+13=16 (Q), 0+6=6 (G), 22+10=32→6 (G), 13+4=17 (R)  
→ intermediate text `SXVRGDLHQGGR`.

*Stage 2 (Hill), first three pairs:*
* (18, 23): 3·18+3·23 = 123 → 123 mod 26 = **19** (T); 2·18+5·23 = 151 → **21** (V)
* (21, 17): 3·21+3·17 = 114 → **10** (K); 2·21+5·17 = 127 → **23** (X)
* (6, 3): 3·6+3·3 = 27 → **1** (B); 2·6+5·3 = 27 → **1** (B)

Full ciphertext: **`TVKXBBCFOKRT`**.

*Decryption:* det H = 3·5 − 3·2 = 9; 9·3 = 27 ≡ 1, so det⁻¹ = 3; H⁻¹ = 3·[[5, −3], [−2, 3]] = [[15, −9], [−6, 9]] ≡ **[[15, 17], [20, 9]]**.
* (19, 21): 15·19+17·21 = 642 → **18**; 20·19+9·21 = 569 → **23**  → (18, 23) = `SX` ✔
* (10, 23): 15·10+17·23 = 541 → **21**; 20·10+9·23 = 407 → **17** → (21, 17) = `VR` ✔
Then subtract the key: 18−18=0 (A), 23−4=19 (T), 21−2=19 (T), 17−17=0 (A) … → `ATTA…` → `ATTACKATDAWN` ✔

### 1.6 Where this is in the code
`cipher.py`: `vigenere()` = Stage 1, `hill_apply()` = Stage 2, `hill_inverse()` = H⁻¹ computation, `encrypt()` / `decrypt()` = the algorithms above, `parse_hill_key()` / `check_keys()` = key validity rules (L ≥ 10, det invertible).

## 2. Security analysis (design level)

* **Key space:** 26¹² · |GL₂(ℤ₂₆)| = 26¹² · 157 248 ≈ 2⁷³·⁷ for L = 12 — far beyond brute force *on paper*.
* **Frequency flattening:** Index of coincidence (IC) of English is 0.068 (our corpus); VigHill ciphertext IC ≈ 0.039 ≈ random (0.0385), for all lengths 50–1600. Classic IC/Kasiski period finding and per-column χ² therefore fail.
* **Structural weakness (the real flaw):** both stages are *linear over ℤ₂₆*. The composite is
  **C_d = H·P_d + H·K_d**, where the digraph key K_d repeats every p = lcm(L,2)/2 digraphs (6 for L = 12). That is a *Hill cipher with a periodic affine offset*. Consequently:
  * it is linear → any known-plaintext attack reduces to solving a small linear system (below);
  * the key length shows up as a period of p digraphs in the structure (this is what the KPA exploits);
  * the effective secret is only 4 + L numbers, and “two stages” adds ≈17 bits (Hill) over Vigenère alone, not a new kind of hardness.

## 3. Attacks

### 3.1 Frequency analysis (ciphertext-only) — implemented in `attacks.py`
Method: IC to guess period, then χ² of each column against English letter frequencies to recover each key shift.
Results (200 trials per cell, 12-letter key; plaintext windows drawn from a 1 668-letter corpus, so absolute numbers are indicative):

| ciphertext length | Shift: key found | Vigenère only: period found / key found (period known) | VigHill: letters correct (key-length known to attacker) | VigHill exact | VigHill IC |
|---|---|---|---|---|---|
| 50 | 100 % | 11.5 % / 0 % | 7.5 % | 0 % | 0.0391 |
| 100 | 100 % | 27 % / 0 % | 6.5 % | 0 % | 0.0392 |
| 200 | 100 % | 56 % / 31.5 % | 5.2 % | 0 % | 0.0391 |
| 400 | 100 % | 68.5 % / 65 % | 5.2 % | 0 % | 0.0390 |
| 800 | 100 % | 80 % / 100 % | 5.2 % | 0 % | 0.0392 |
| 1600 | 100 % | 87 % / 100 % | 5.1 % | 0 % | 0.0390 |

(≈4 % letters correct = chance.) **Frequency analysis breaks Shift always and Vigenère from ~800 letters, but gets nothing out of VigHill**: the Hill stage mixes letters from different Vigenère columns, so no column is a shifted English distribution.

### 3.2 Known-plaintext attack — implemented as `kpa()`
Attacker knows `m` consecutive plaintext letters with their ciphertext (starting at a known even offset) and the key length L (or tries L = 10…20; the work is trivially repeated).
1. Because K_d = K_{d+p}: **C_d − C_{d+p} = H (P_d − P_{d+p})** — the Vigenère key cancels.
2. Take two difference pairs whose plaintext-difference vectors form an invertible 2×2 matrix Dp; then H = Dc · Dp⁻¹ (mod 26). Verify H against all other difference pairs.
3. Recover the key: K_d = H⁻¹C_d − P_d, giving all L Vigenère letters once all p digraph classes are covered.
4. Decrypt the entire ciphertext.

Success rate (500 trials each, random keys, English plaintext, random even offset) — *full recovery of both keys* ( = 100 % plaintext recovery):

| known letters | L = 10 | L = 12 | L = 15 |
|---|---|---|---|
| 12 | 0 % | 0 % | 0 % |
| 16 | 59.8 % | 33.8 % | 0 % |
| 20 | 90.8 % | 82.8 % | 0 % |
| 24 | 97.4 % | 96.8 % | 0 % |
| 28 | 99.2 % | 98.6 % | 0 % |
| 32 | 100 % | 100 % | 0 % |
| 40 | 100 % | 100 % | 86.8 % |
| 60 | 100 % | 100 % | 100 % |

Theoretical minimum: (p+2) digraphs, i.e. 2p+4 letters (16 for L = 12). Odd L is *not* safer: p = L (period doubles) so ≈2L+4 = 34 letters are needed, which the table matches. The failures below 100 % are only cases where no two difference vectors are independent mod 26 (not a limitation of the method).

**Computational effort:** O(m + D²) with D = m/2 − p differences (the pair search stops at the first consistent pair, in practice after a handful of tries). Measured: 0.02 ms (24 letters) to 0.05 ms (60 letters) per attack, independent of the 2⁷³·⁷ key space; whole pipeline (encrypt + attack) ≈ 0.08 ms. Decrypting the rest of the message is O(n).

## 4. Efficiency (Python 3, single thread, `results.json`)

| n (letters) | VigHill enc | VigHill dec | Shift enc | Shift dec | Vigenère enc |
|---|---|---|---|---|---|
| 10³ | 0.28 ms | 0.36 ms | 0.13 ms | 0.13 ms | 0.10 ms |
| 10⁴ | 3.0 ms | 3.2 ms | 1.3 ms | 1.4 ms | 1.1 ms |
| 10⁵ | 32 ms | 62 ms | 25 ms | 26 ms | 13 ms |
| 10⁶ | 291 ms | 336 ms | 143 ms | 157 ms | 123 ms |

* Encryption and decryption are both **Θ(n)** time, O(n) memory (O(1) extra per block): one modular add per letter (stage 1) + four multiplies/two adds per pair (stage 2). Decryption additionally precomputes H⁻¹ once in O(1).
* Versus Shift (also Θ(n), one add per letter) VigHill is the same order and **≈2–2.3× slower in absolute terms** — a constant-factor cost. Shift’s key space is 26 (broken by 26-way brute force, or by frequency analysis from ~50 letters); VigHill’s is 2⁷³·⁷ but, as shown, is reduced to a linear solve by 32 known letters.
* Attack costs: shift break O(26·n) ≈ trivial; VigHill frequency analysis O(L·26·n) (fails); VigHill KPA O(m).

## 5. Improving security cheaply
1. **Break linearity** with one inexpensive non-linear step between stages: a keyed substitution/S-box, or a keyed transposition of the Vigenère output. KPA via differences then no longer applies (cost: O(n)).
2. **Make the Vigenère key non-repeating**: autokey (key = Kv ‖ plaintext) or a key as long as the message (OTP-like limit); removes the period p that the attack exploits.
3. **Larger/dependent Hill blocks**: 3×3 or 4×4 Hill (key ≥ 9–16 letters) raises the known-plaintext need to ≈ (p+n)·n and diffuses more; chain blocks (CBC-like: add previous ciphertext block before Hill) so identical blocks do not repeat.
4. Add an **affine constant** or Hill-then-Vigenère-then-Hill ordering with independent keys only if combined with (1); stacking more linear stages does not help (their product is still linear).
5. Do not reuse keys; never encrypt known headers/boilerplate.

## 6. Limitations / honesty notes
* Plaintexts come from a 1 668-letter corpus (windows overlap), so frequency-attack percentages are indicative, not definitive. The KPA numbers depend only on the maths and plaintext variety.
* The KPA assumes the key length (or a small set of candidates) and contiguous known text at an even offset; an odd offset is not implemented (the attacker would simply drop the first known letter to realign).
* Reproduce everything: `python3 run_experiments.py` (seeded; timings vary by machine).
