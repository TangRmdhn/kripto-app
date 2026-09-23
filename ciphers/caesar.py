# Caesar Cipher
# Enkripsi : Ci = (Pi + K) mod 26
# Dekripsi : Pi = (Ci - K) mod 26
# Hanya huruf yang digeser, karakter lain dibiarkan.
from .utils import Step, limit, vis


def ambil_kunci(key):
    try:
        return int(str(key).strip()) % 26
    except ValueError:
        raise ValueError("Kunci Caesar harus berupa bilangan bulat (contoh: 3).")


def proses(text, key, enkripsi):
    if text == "":
        raise ValueError("Teks tidak boleh kosong.")
    k = ambil_kunci(key)

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

    hasil = ""
    rows = []
    no = 1
    for ch in text:
        if ch.isascii() and ch.isalpha():
            if ch.isupper():
                base = 65
            else:
                base = 97
            x = ord(ch) - base
            r = (x + tanda * k) % 26
            res = chr(r + base)
            rows.append({
                "No": str(no),
                "Karakter": ch,
                "Nilai": str(x),
                "Rumus": f"({x} {op} {k}) mod 26 = {r}",
                "Hasil": res,
            })
        else:
            res = ch
            rows.append({
                "No": str(no),
                "Karakter": vis(ch),
                "Nilai": "-",
                "Rumus": "bukan huruf, dilewati",
                "Hasil": vis(ch),
            })
        hasil += res
        no += 1

    tampil, catatan = limit(rows)
    steps = [
        Step(
            "Persiapan kunci dan rumus",
            f"Kunci (geser): **{k}** (kunci dimodulo 26).\n\n"
            "Setiap huruf diberi nilai A=0, B=1, ..., Z=25, lalu digeser sejauh kunci. "
            "Karakter yang bukan huruf tidak diubah.\n\n"
            f"Rumus: `{nama_out} = ({nama_in} {op} K) mod 26`",
        ),
        Step("Proses per karakter", "Setiap huruf dihitung dengan rumus di atas." + catatan, table=tampil),
        Step("Hasil", code=hasil),
    ]
    return hasil, steps


def encrypt(text, key):
    return proses(text, key, True)


def decrypt(text, key):
    return proses(text, key, False)
