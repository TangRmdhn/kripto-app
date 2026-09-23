# Super enkripsi: gabungan 4 algoritma
#
# Enkripsi:
#   Plainteks -> [1] Vigenere -> [2] Caesar -> [3] LFSR -> [4] Feistel -> hex
# Dekripsi urutannya dibalik: 4 -> 3 -> 2 -> 1
#
# Vigenere dan Caesar bekerja pada teks, LFSR dan Feistel bekerja pada byte.
from . import caesar, feistel, lfsr_stream, vigenere
from .utils import from_hex, header, to_hex


def encrypt(text, key_vig, key_caesar, seed, key_block, mode="ECB"):
    if text == "":
        raise ValueError("Plainteks tidak boleh kosong.")
    steps = []

    t1, s1 = vigenere.encrypt(text, key_vig)
    steps.append(header("TAHAP 1: Vigenere Cipher (klasik, substitusi)",
                        "Plainteks dienkripsi dengan Vigenere.",
                        code=f"Input : {text}\nOutput: {t1}"))
    steps += s1

    t2, s2 = caesar.encrypt(t1, key_caesar)
    steps.append(header("TAHAP 2: Caesar Cipher (klasik, substitusi)",
                        "Keluaran tahap 1 menjadi masukan tahap 2.",
                        code=f"Input : {t1}\nOutput: {t2}"))
    steps += s2

    b3, s3 = lfsr_stream.encrypt_bytes(t2.encode("utf-8"), seed)
    steps.append(header("TAHAP 3: Stream Cipher LFSR (modern)",
                        "Keluaran tahap 2 diubah menjadi byte (UTF-8), lalu di-XOR dengan keystream LFSR.",
                        code=f"Output (hex): {to_hex(b3)}"))
    steps += s3

    b4, s4 = feistel.encrypt_bytes(b3, key_block, mode)
    steps.append(header("TAHAP 4: Block Cipher Feistel (modern)",
                        "Keluaran tahap 3 dienkripsi per blok 64 bit.",
                        code=f"Output (hex): {to_hex(b4)}"))
    steps += s4

    hasil = to_hex(b4)
    steps.append(header("HASIL AKHIR SUPER ENKRIPSI", "Cipherteks akhir dalam heksadesimal:", code=hasil))
    return hasil, steps


def decrypt(hex_text, key_vig, key_caesar, seed, key_block, mode="ECB"):
    data = from_hex(hex_text)
    steps = []

    b3, s4 = feistel.decrypt_bytes(data, key_block, mode)
    steps.append(header("TAHAP 1: Dekripsi Block Cipher Feistel (kebalikan tahap 4)",
                        "Cipherteks akhir didekripsi per blok, lalu padding dibuang.",
                        code=f"Output (hex): {to_hex(b3)}"))
    steps += s4

    b2, s3 = lfsr_stream.decrypt_bytes(b3, seed)
    steps.append(header("TAHAP 2: Dekripsi Stream Cipher LFSR (kebalikan tahap 3)",
                        "Keystream yang sama di-XOR kembali dengan data.",
                        code=f"Output (hex): {to_hex(b2)}"))
    steps += s3

    try:
        t2 = b2.decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError(
            "Hasil dekripsi LFSR bukan teks UTF-8 yang valid. Kemungkinan seed LFSR salah."
        )

    t1, s2 = caesar.decrypt(t2, key_caesar)
    steps.append(header("TAHAP 3: Dekripsi Caesar Cipher (kebalikan tahap 2)",
                        "Teks dikembalikan ke huruf sebelum digeser Caesar.",
                        code=f"Input : {t2}\nOutput: {t1}"))
    steps += s2

    plain, s1 = vigenere.decrypt(t1, key_vig)
    steps.append(header("TAHAP 4: Dekripsi Vigenere Cipher (kebalikan tahap 1)",
                        "Teks dikembalikan menjadi plainteks asli.",
                        code=f"Input : {t1}\nOutput: {plain}"))
    steps += s1

    steps.append(header("HASIL AKHIR DEKRIPSI", "Plainteks:", code=plain))
    return plain, steps
