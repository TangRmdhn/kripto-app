# Vigenere Cipher
# Enkripsi : Ci = (Pi + Ki) mod 26
# Dekripsi : Pi = (Ci - Ki) mod 26
# Hanya huruf yang diproses, karakter lain dibiarkan.
from .utils import Step, limit, vis


def bersihkan_kunci(key):
    hasil = ""
    for c in key.upper():
        if "A" <= c <= "Z":
            hasil += c
    if hasil == "":
        raise ValueError("Kunci Vigenere harus berisi minimal satu huruf A-Z.")
    return hasil


def penyelarasan(text, k):
    # tampilkan kunci di bawah teks (60 karakter pertama)
    atas = ""
    bawah = ""
    ki = 0
    for ch in text[:60]:
        if ch.isascii() and ch.isalpha():
            atas += ch.upper()
            bawah += k[ki % len(k)]
            ki += 1
        else:
            atas += vis(ch)
            bawah += " "
    return "Teks  : " + atas + "\nKunci : " + bawah


def proses(text, key, enkripsi):
    if text == "":
        raise ValueError("Teks tidak boleh kosong.")
    k = bersihkan_kunci(key)

    if enkripsi:
        tanda = 1
        op = "+"
        nama_in = "Pi"
        nama_out = "Ci"
    else:
        tanda = -1
        op = "-"
        nama_in = "Ci"
        nama_out = "Pi"
    rumus = f"{nama_out} = ({nama_in} {op} Ki) mod 26"

    hasil = ""
    rows = []
    ki = 0
    no = 1
    for ch in text:
        if ch.isascii() and ch.isalpha():
            if ch.isupper():
                base = 65
            else:
                base = 97
            x = ord(ch) - base
            huruf_kunci = k[ki % len(k)]
            nilai_kunci = ord(huruf_kunci) - 65
            r = (x + tanda * nilai_kunci) % 26
            res = chr(r + base)
            rows.append({
                "No": str(no),
                "Karakter": ch,
                "Nilai": str(x),
                "Huruf kunci": f"{huruf_kunci} ({nilai_kunci})",
                "Rumus": f"({x} {op} {nilai_kunci}) mod 26 = {r}",
                "Hasil": res,
            })
            ki += 1
        else:
            res = ch
            rows.append({
                "No": str(no),
                "Karakter": vis(ch),
                "Nilai": "-",
                "Huruf kunci": "-",
                "Rumus": "bukan huruf, dilewati",
                "Hasil": vis(ch),
            })
        hasil += res
        no += 1

    tampil, catatan = limit(rows)
    steps = [
        Step(
            "Persiapan kunci dan rumus",
            f"Kunci dibersihkan (hanya huruf, dijadikan huruf besar): **{k}** (panjang {len(k)}).\n\n"
            "Setiap huruf diberi nilai A=0, B=1, ..., Z=25. Kunci diulang berkali-kali "
            "mengikuti panjang teks. Karakter yang bukan huruf tidak memakai kunci.\n\n"
            f"Rumus: `{rumus}`",
        ),
        Step("Penyelarasan kunci dengan teks", "Kunci diulang di bawah setiap huruf:",
             code=penyelarasan(text, k)),
        Step("Proses per karakter", "Setiap huruf dihitung dengan rumus di atas." + catatan, table=tampil),
        Step("Hasil", code=hasil),
    ]
    return hasil, steps


def encrypt(text, key):
    return proses(text, key, True)


def decrypt(text, key):
    return proses(text, key, False)
