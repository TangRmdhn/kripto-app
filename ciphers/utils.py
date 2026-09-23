# Fungsi bantu yang dipakai semua algoritma.
# Tiap algoritma mengembalikan (hasil, daftar Step).
from dataclasses import dataclass

# maksimal baris tabel yang ditampilkan
MAX_ROWS = 64


@dataclass
class Step:
    title: str
    detail: str = ""
    table: list = None
    code: str = None
    kind: str = "step"  # "step" atau "header"


def header(title, detail="", code=None):
    return Step(title=title, detail=detail, code=code, kind="header")


def vis(ch):
    # supaya spasi dan enter kelihatan di tabel
    if ch == " ":
        return "␣"
    if ch == "\n":
        return "↵"
    if ch == "\t":
        return "⇥"
    return ch


def to_hex(data):
    return data.hex().upper()


def from_hex(text):
    cleaned = "".join(text.split())
    if cleaned == "":
        raise ValueError("Cipherteks tidak boleh kosong.")
    try:
        return bytes.fromhex(cleaned)
    except ValueError:
        raise ValueError(
            "Cipherteks harus berupa string hex yang valid (karakter 0-9 dan A-F, jumlah genap)."
        )


def group(s, n):
    # pecah string jadi kelompok n karakter, dipisah spasi
    parts = []
    for i in range(0, len(s), n):
        parts.append(s[i:i + n])
    return " ".join(parts)


def limit(rows):
    # potong tabel kalau terlalu panjang
    if len(rows) <= MAX_ROWS:
        return rows, ""
    note = f"\n\n_Tabel dipotong: menampilkan {MAX_ROWS} dari {len(rows)} baris._"
    return rows[:MAX_ROWS], note
