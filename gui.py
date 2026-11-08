"""VigHill GUI (Tkinter). Run:  python3 gui.py
Tabs: 1) Encrypt / Decrypt   2) Attack simulation (frequency + known-plaintext)   3) Results & efficiency
Uses cipher.py, attacks.py, corpus.py and results.json from the same folder."""
import json
import os
import random
import string
import time
import tkinter as tk
from tkinter import ttk, messagebox

from cipher import (clean, encrypt, decrypt, parse_hill_key, shift_encrypt,
                    vigenere)
from attacks import (kpa, decrypt_with_recovered, attack_shift, attack_vigenere,
                     attack_vighill_freq, index_of_coincidence, guess_period)
from corpus import PLAIN, ENGLISH_FREQ

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_V, DEFAULT_H = "SECRETLONGKEY", "DDCF"


def rand_key(n):
    return "".join(random.choice(string.ascii_uppercase) for _ in range(n))


def rand_hill():
    while True:
        k = rand_key(4)
        try:
            parse_hill_key(k)
            return k
        except ValueError:
            pass


def text_box(parent, height=5, readonly=False):
    frame = ttk.Frame(parent)
    t = tk.Text(frame, height=height, wrap="word", font=("Consolas", 10))
    sb = ttk.Scrollbar(frame, command=t.yview)
    t.configure(yscrollcommand=sb.set)
    t.pack(side="left", fill="both", expand=True)
    sb.pack(side="right", fill="y")
    return frame, t


def set_text(t, s):
    t.configure(state="normal")
    t.delete("1.0", "end")
    t.insert("1.0", s)


# ======================================================================== tab 1
class CipherTab(ttk.Frame):
    def __init__(self, master):
        super().__init__(master, padding=10)
        self.vkey = tk.StringVar(value=DEFAULT_V)
        self.hkey = tk.StringVar(value=DEFAULT_H)
        self.status = tk.StringVar()

        keys = ttk.LabelFrame(self, text="Keys", padding=8)
        keys.pack(fill="x")
        ttk.Label(keys, text="Vigenère key (≥ 10 letters):").grid(row=0, column=0, sticky="w")
        ttk.Entry(keys, textvariable=self.vkey, width=28).grid(row=0, column=1, padx=6)
        ttk.Label(keys, text="Hill key (4 letters):").grid(row=0, column=2, sticky="w", padx=(12, 0))
        ttk.Entry(keys, textvariable=self.hkey, width=8).grid(row=0, column=3, padx=6)
        ttk.Button(keys, text="Random keys", command=self.random_keys).grid(row=0, column=4, padx=6)
        self.matrix = tk.StringVar()
        ttk.Label(keys, textvariable=self.matrix, foreground="#555").grid(row=1, column=0, columnspan=5, sticky="w", pady=(6, 0))
        self.hkey.trace_add("write", lambda *_: self.update_matrix())
        self.update_matrix()

        ttk.Label(self, text="Input text (plaintext to encrypt, or ciphertext to decrypt):").pack(anchor="w", pady=(10, 2))
        f, self.inp = text_box(self, 6)
        f.pack(fill="both", expand=True)
        self.inp.insert("1.0", "Attack at dawn")

        bar = ttk.Frame(self)
        bar.pack(fill="x", pady=8)
        ttk.Button(bar, text="Encrypt  ▶", command=self.do_enc).pack(side="left")
        ttk.Button(bar, text="◀  Decrypt", command=self.do_dec).pack(side="left", padx=6)
        ttk.Button(bar, text="Use output as input", command=self.swap).pack(side="left", padx=6)
        ttk.Button(bar, text="Copy output", command=self.copy).pack(side="left")

        ttk.Label(self, text="Output:").pack(anchor="w")
        f, self.out = text_box(self, 6)
        f.pack(fill="both", expand=True)

        ttk.Label(self, text="Stage-by-stage (last encryption):").pack(anchor="w", pady=(8, 2))
        f, self.stages = text_box(self, 6)
        f.pack(fill="both", expand=True)
        ttk.Label(self, textvariable=self.status, foreground="#a00").pack(anchor="w")

    def update_matrix(self):
        try:
            a, b, c, d = parse_hill_key(self.hkey.get())
            self.matrix.set(f"Hill matrix H = [[{a}, {b}], [{c}, {d}]]   det = {(a*d-b*c) % 26}  (invertible ✔)")
        except ValueError as e:
            self.matrix.set(f"Hill key problem: {e}")

    def random_keys(self):
        self.vkey.set(rand_key(random.randint(10, 16)))
        self.hkey.set(rand_hill())

    def do_enc(self):
        try:
            p = clean(self.inp.get("1.0", "end"))
            v, h = self.vkey.get(), self.hkey.get()
            c = encrypt(p, v, h)
            padded = p + ("X" if len(p) % 2 else "")
            s1 = vigenere(padded, clean(v), +1)
            set_text(self.out, c)
            set_text(self.stages,
                     f"Cleaned plaintext : {padded}\n"
                     f"After Vigenère    : {s1}\n"
                     f"After Hill (final): {c}\n"
                     f"Length {len(c)} letters")
            self.status.set("")
        except ValueError as e:
            self.status.set(str(e))

    def do_dec(self):
        try:
            p = decrypt(self.inp.get("1.0", "end"), self.vkey.get(), self.hkey.get())
            set_text(self.out, p)
            self.status.set("")
        except ValueError as e:
            self.status.set(str(e))

    def swap(self):
        set_text(self.inp, self.out.get("1.0", "end").strip())

    def copy(self):
        self.clipboard_clear()
        self.clipboard_append(self.out.get("1.0", "end").strip())


# ======================================================================== tab 2
class AttackTab(ttk.Frame):
    def __init__(self, master):
        super().__init__(master, padding=10)
        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True)
        self.kpa_f = self.build_kpa(nb)
        self.fa_f = self.build_freq(nb)
        nb.add(self.kpa_f, text="Known-plaintext attack")
        nb.add(self.fa_f, text="Frequency analysis")

    # ---- KPA
    def build_kpa(self, nb):
        f = ttk.Frame(nb, padding=8)
        self.k_L = tk.IntVar(value=12)
        self.k_known = tk.IntVar(value=40)
        self.k_len = tk.IntVar(value=200)
        row = ttk.Frame(f)
        row.pack(fill="x")
        for lbl, var, lo, hi in (("Key length L", self.k_L, 10, 20),
                                 ("Known letters", self.k_known, 4, 200),
                                 ("Message length", self.k_len, 60, 600)):
            ttk.Label(row, text=lbl).pack(side="left")
            ttk.Spinbox(row, from_=lo, to=hi, textvariable=var, width=5).pack(side="left", padx=(4, 12))
        ttk.Button(row, text="Run attack (random keys)", command=self.run_kpa).pack(side="left")
        ttk.Button(row, text="Success rate (300 trials)", command=self.kpa_rate).pack(side="left", padx=6)
        f2, self.kout = text_box(f, 20)
        f2.pack(fill="both", expand=True, pady=8)
        return f

    def run_kpa(self):
        L, m, n = self.k_L.get(), self.k_known.get() // 2 * 2, self.k_len.get() // 2 * 2
        vk, hk = rand_key(L), rand_hill()
        s = random.randrange(0, (len(PLAIN) - n) // 2) * 2
        p = PLAIN[s:s + n]
        c = encrypt(p, vk, hk)
        off = 2 * random.randint(0, max(0, (n - m) // 2))
        t0 = time.perf_counter()
        H, key, found = kpa(p[off:off + m], c[off:off + m], L, off)
        dt = (time.perf_counter() - t0) * 1000
        out = [f"True Vigenère key : {vk}", f"True Hill key      : {hk}  {parse_hill_key(hk)}",
               f"Attacker knows    : {m} plaintext letters at offset {off}  (key length L={L} assumed known)",
               f"Ciphertext        : {c[:80]}{'…' if len(c) > 80 else ''}", ""]
        if H is None:
            out.append(f"RESULT: attack FAILED in {dt:.3f} ms – not enough independent digraph differences "
                       f"(need ≥ 2p+4 = {2 * (L // 2 if L % 2 == 0 else L) + 4} letters).")
        else:
            rec = "".join("?" if k is None else chr(k + 65) for k in key)
            out += [f"Recovered Hill H  : {H}  {'✔' if H == parse_hill_key(hk) else '✘'}",
                    f"Recovered key     : {rec}  ({found}/{L} letters)  {'✔' if rec == vk else '(partial)'}",
                    f"Time              : {dt:.3f} ms", "",
                    "Full decryption with recovered keys ('?' = unknown key letter):",
                    decrypt_with_recovered(c, H, key)[:400], "",
                    "True plaintext:", p[:400]]
        set_text(self.kout, "\n".join(out))

    def kpa_rate(self):
        L, m, T = self.k_L.get(), self.k_known.get() // 2 * 2, 300
        ok = 0
        t0 = time.perf_counter()
        for _ in range(T):
            vk, hk = rand_key(L), rand_hill()
            s = random.randrange(0, (len(PLAIN) - 200) // 2) * 2
            p = PLAIN[s:s + 200]
            c = encrypt(p, vk, hk)
            off = 2 * random.randint(0, 20)
            H, key, found = kpa(p[off:off + m], c[off:off + m], L, off)
            ok += bool(H) and found == L and "".join(chr(k + 65) for k in key) == vk
        dt = time.perf_counter() - t0
        set_text(self.kout, f"L = {L}, known letters = {m}\nFull-key recovery: {ok}/{T} = {100 * ok / T:.1f} %\n"
                            f"Total time for {T} trials (incl. encryption): {dt * 1000:.1f} ms")

    # ---- Frequency analysis
    def build_freq(self, nb):
        f = ttk.Frame(nb, padding=8)
        self.f_n = tk.IntVar(value=800)
        self.f_cipher = tk.StringVar(value="Shift")
        row = ttk.Frame(f)
        row.pack(fill="x")
        ttk.Label(row, text="Cipher").pack(side="left")
        ttk.Combobox(row, textvariable=self.f_cipher, values=["Shift", "Vigenère (12)", "VigHill (12/Hill)"],
                     state="readonly", width=18).pack(side="left", padx=6)
        ttk.Label(row, text="Ciphertext length").pack(side="left")
        ttk.Spinbox(row, from_=50, to=1600, increment=50, textvariable=self.f_n, width=6).pack(side="left", padx=6)
        ttk.Button(row, text="Run frequency attack", command=self.run_freq).pack(side="left", padx=6)
        self.canvas = tk.Canvas(f, height=230, bg="white", highlightthickness=1, highlightbackground="#ccc")
        self.canvas.pack(fill="x", pady=8)
        f2, self.fout = text_box(f, 12)
        f2.pack(fill="both", expand=True)
        return f

    def draw_hist(self, text):
        c = self.canvas
        c.update_idletasks()
        c.delete("all")
        W, H = max(c.winfo_width(), 600), 230
        cnt = [0] * 26
        for ch in text:
            cnt[ord(ch) - 65] += 1
        n = max(len(text), 1)
        obs = [x / n * 100 for x in cnt]
        top = max(max(obs), max(ENGLISH_FREQ)) * 1.1
        bw = (W - 40) / 26
        for i in range(26):
            x0 = 30 + i * bw
            h = obs[i] / top * (H - 50)
            e = ENGLISH_FREQ[i] / top * (H - 50)
            c.create_rectangle(x0 + 2, H - 25 - h, x0 + bw / 2, H - 25, fill="#4a7fd4", outline="")
            c.create_rectangle(x0 + bw / 2, H - 25 - e, x0 + bw - 2, H - 25, fill="#e0913a", outline="")
            c.create_text(x0 + bw / 2, H - 12, text=chr(65 + i), font=("Consolas", 8))
        c.create_text(36, 10, anchor="w", text="■ ciphertext letter freq (%)", fill="#4a7fd4", font=("Segoe UI", 9))
        c.create_text(220, 10, anchor="w", text="■ expected English (%)", fill="#e0913a", font=("Segoe UI", 9))
        c.create_text(W - 10, 10, anchor="e", text=f"IC = {index_of_coincidence(text):.4f} (English ≈ 0.068, random ≈ 0.038)",
                      font=("Segoe UI", 9))

    def run_freq(self):
        n, kind = self.f_n.get() // 2 * 2, self.f_cipher.get()
        big = PLAIN * 3
        s = random.randrange(0, len(big) - n)
        p = big[s:s + n]
        t0 = time.perf_counter()
        if kind == "Shift":
            k = random.randrange(26)
            c = shift_encrypt(p, k)
            g = attack_shift(c)
            res = f"True shift {k}, recovered shift {g}  →  {'SUCCESS' if g == k else 'FAIL'}"
        elif kind.startswith("Vigenère"):
            vk = rand_key(12)
            c = vigenere(p, vk, 1)
            per = guess_period(c)
            g = attack_vigenere(c, 12)
            res = (f"True key {vk}\nIC-guessed period: {per or 'none found'} (true 12)\n"
                   f"Recovered key (period 12 given): {g}  →  {'SUCCESS' if g == vk else 'FAIL'}\n"
                   f"Letters of key correct: {sum(a == b for a, b in zip(g, vk))}/12")
        else:
            vk, hk = rand_key(12), rand_hill()
            c = encrypt(p, vk, hk)
            g = attack_vighill_freq(c, 12)
            acc = sum(a == b for a, b in zip(g, p)) / len(p)
            res = (f"True keys {vk} / {hk}\nAttacker's 'plaintext' guess (key length 12 given):\n{g[:120]}…\n"
                   f"Letters correct: {100 * acc:.1f} %  (chance ≈ 4 %)  →  FAIL: Hill stage defeats column χ²")
        dt = (time.perf_counter() - t0) * 1000
        self.draw_hist(c)
        set_text(self.fout, f"{kind}, n = {n}\nCiphertext: {c[:100]}…\n\n{res}\n\nAttack time: {dt:.2f} ms")


# ======================================================================== tab 3
class ResultsTab(ttk.Frame):
    def __init__(self, master):
        super().__init__(master, padding=10)
        try:
            with open(os.path.join(HERE, "results.json")) as fh:
                R = json.load(fh)
        except OSError:
            ttk.Label(self, text="results.json not found – run run_experiments.py first").pack()
            return
        ttk.Label(self, text=f"Round-trip correctness: {R['roundtrip_ok_of_2000']}/2000    "
                             f"English IC = {R['IC_english']:.4f}").pack(anchor="w")
        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True, pady=6)
        self.table(nb, "KPA success", ["L", "known letters", "Hill recovered %", "Full key %", "time ms"],
                   [(r["L"], r["known"], f"{100*r['hill_recovered']:.1f}", f"{100*r['full_key']:.1f}",
                     f"{r['ms']:.3f}") for r in R["kpa"]])
        self.table(nb, "Frequency analysis",
                   ["n", "Shift key %", "Vig period %", "Vig key %", "VigHill letters %", "VigHill IC"],
                   [(r["n"], f"{100*r['shift_key']:.0f}", f"{100*r['vig_period_found']:.1f}",
                     f"{100*r['vig_key_known_period']:.1f}", f"{100*r['vighill_letters_correct']:.1f}",
                     f"{r['vighill_IC']:.4f}") for r in R["freq"]])
        self.table(nb, "Timing (ms)", ["n", "VigHill enc", "VigHill dec", "Shift enc", "Shift dec", "Vig enc", "VigHill/Shift"],
                   [(f"{r['n']:,}", f"{1000*r['vighill_enc']:.2f}", f"{1000*r['vighill_dec']:.2f}",
                     f"{1000*r['shift_enc']:.2f}", f"{1000*r['shift_dec']:.2f}", f"{1000*r['vig_enc']:.2f}",
                     f"{r['vighill_enc']/r['shift_enc']:.2f}×") for r in R["timing"]])
        self.timing_plot(nb, R["timing"])
        ttk.Label(self, text=f"1000 × (encrypt + KPA) = {R['kpa_total_seconds_for_1000_runs']:.3f} s").pack(anchor="w")

    def table(self, nb, title, cols, rows):
        f = ttk.Frame(nb, padding=6)
        tv = ttk.Treeview(f, columns=cols, show="headings", height=12)
        for c in cols:
            tv.heading(c, text=c)
            tv.column(c, width=110, anchor="center")
        for r in rows:
            tv.insert("", "end", values=r)
        tv.pack(fill="both", expand=True)
        nb.add(f, text=title)

    def timing_plot(self, nb, tim):
        f = ttk.Frame(nb, padding=6)
        c = tk.Canvas(f, width=640, height=320, bg="white")
        c.pack()
        W, H, ml, mb = 640, 320, 60, 40
        series = [("VigHill enc", "vighill_enc", "#c0392b"), ("VigHill dec", "vighill_dec", "#e67e22"),
                  ("Shift enc", "shift_enc", "#2980b9"), ("Vigenère enc", "vig_enc", "#27ae60")]
        mx = max(r["vighill_dec"] for r in tim) * 1000
        c.create_line(ml, 20, ml, H - mb)
        c.create_line(ml, H - mb, W - 20, H - mb)
        for k, r in enumerate(tim):
            x = ml + k * (W - ml - 40) / (len(tim) - 1)
            c.create_text(x, H - mb + 14, text=f"{r['n']:,}", font=("Segoe UI", 8))
        for y in range(0, 5):
            v = mx * y / 4
            yy = H - mb - (H - mb - 20) * y / 4
            c.create_text(ml - 6, yy, anchor="e", text=f"{v:.0f}", font=("Segoe UI", 8))
        for i, (name, key, col) in enumerate(series):
            pts = []
            for k, r in enumerate(tim):
                x = ml + k * (W - ml - 40) / (len(tim) - 1)
                y = H - mb - (H - mb - 20) * (r[key] * 1000) / mx
                pts += [x, y]
            c.create_line(*pts, fill=col, width=2)
            c.create_text(ml + 10 + i * 140, 10, anchor="w", text="— " + name, fill=col, font=("Segoe UI", 9))
        c.create_text(W // 2, H - 8, text="message length n (letters)   |   y: time in ms   (linear Θ(n))", font=("Segoe UI", 8))
        nb.add(f, text="Timing plot")


# ======================================================================== main
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("VigHill – Vigenère → Hill cipher: encrypt, decrypt & attack")
        self.geometry("980x760")
        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True)
        nb.add(CipherTab(nb), text="Encrypt / Decrypt")
        nb.add(AttackTab(nb), text="Attack simulation")
        nb.add(ResultsTab(nb), text="Results & efficiency")


if __name__ == "__main__":
    App().mainloop()
