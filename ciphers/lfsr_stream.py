# Stream Cipher berbasis LFSR
# keystream dibuat dari seed, lalu di-XOR dengan bit data:
#   ci = pi XOR ki   (enkripsi)
#   pi = ci XOR ki   (dekripsi)
#
# Cara kerja LFSR:
#   - register n bit: b1 b2 ... bn
#   - bit keluaran = b1
#   - umpan balik = XOR bit pada posisi tap
#   - register geser kiri, umpan balik masuk jadi bn
from .utils import Step, from_hex, group, limit, to_hex

# posisi tap (1 = b1), semua menghasilkan periode 2^n - 1
TAPS = {4: [1, 4], 8: [1, 3, 4, 5], 16: [1, 3, 4, 6]}
DEFAULT_SEEDS = {4: "1111", 8: "10110001", 16: "1010110011100001"}


def bersihkan_seed(seed):
    seed = "".join(seed.split())
    if len(seed) not in TAPS:
        raise ValueError("Seed harus berupa bit 0/1 dengan panjang tepat 4, 8, atau 16.")
    for c in seed:
        if c != "0" and c != "1":
            raise ValueError("Seed harus berupa bit 0/1 dengan panjang tepat 4, 8, atau 16.")
    if "1" not in seed:
        raise ValueError("Seed tidak boleh semua 0 karena LFSR akan macet di 0.")
    return seed


def keystream(seed, nbits):
    reg = []
    for c in seed:
        reg.append(int(c))
    taps = TAPS[len(seed)]
    hasil = []
    for i in range(nbits):
        hasil.append(reg[0])
        fb = 0
        for t in taps:
            fb = fb ^ reg[t - 1]
        reg = reg[1:] + [fb]
    return hasil


def bits_ke_str(bits):
    s = ""
    for b in bits:
        s += str(b)
    return s


def jejak_lfsr(seed, jumlah):
    # tabel clock demi clock untuk ditampilkan
    reg = []
    for c in seed:
        reg.append(int(c))
    taps = TAPS[len(seed)]
    rows = []
    for clk in range(1, jumlah + 1):
        keluar = reg[0]
        fb = 0
        teks_fb = []
        for t in taps:
            fb = fb ^ reg[t - 1]
            teks_fb.append(f"b{t}={reg[t - 1]}")
        reg_baru = reg[1:] + [fb]
        rows.append({
            "Clock": str(clk),
            "Register (b1..bn)": bits_ke_str(reg),
            "Bit keluaran (b1)": str(keluar),
            "Umpan balik": " ⊕ ".join(teks_fb) + f" = {fb}",
            "Register baru": bits_ke_str(reg_baru),
        })
        reg = reg_baru
    return rows


def proses(data, seed, enkripsi):
    if len(data) == 0:
        raise ValueError("Data tidak boleh kosong.")
    seed = bersihkan_seed(seed)
    n = len(seed)
    taps = TAPS[n]
    ks = keystream(seed, len(data) * 8)

    hasil = bytearray()
    xor_rows = []
    conv_rows = []
    for i in range(len(data)):
        b = data[i]
        kbyte = int(bits_ke_str(ks[i * 8:(i + 1) * 8]), 2)
        r = b ^ kbyte
        hasil.append(r)
        xor_rows.append({
            "Byte ke-": str(i + 1),
            "Data (bit)": f"{b:08b}",
            "Keystream (bit)": f"{kbyte:08b}",
            "Hasil XOR (bit)": f"{r:08b}",
            "Dalam hex": f"{b:02X} ⊕ {kbyte:02X} = {r:02X}",
        })

        # baris tabel konversi byte ke bit
        row = {"Byte ke-": str(i + 1)}
        if enkripsi:
            if b == 32:
                row["Karakter"] = "␣"
            elif 32 < b < 127:
                row["Karakter"] = chr(b)
            else:
                row["Karakter"] = "-"
        row["Hex"] = f"{b:02X}"
        row["Bit"] = f"{b:08b}"
        conv_rows.append(row)
    hasil = bytes(hasil)

    conv_rows, conv_note = limit(conv_rows)
    xor_tampil, xor_note = limit(xor_rows)

    teks_fb = " ⊕ ".join([f"b{t}" for t in taps])
    if enkripsi:
        nama_data = "plainteks"
        nama_hasil = "cipherteks"
        rumus = "ci = pi ⊕ ki"
    else:
        nama_data = "cipherteks"
        nama_hasil = "plainteks"
        rumus = "pi = ci ⊕ ki"

    if enkripsi:
        teks_hasil = "Hasil dalam heksadesimal."
        kode_hasil = to_hex(hasil)
    else:
        teks_hasil = "Byte hasil dikembalikan menjadi teks (UTF-8)."
        kode_hasil = hasil.decode("utf-8", errors="replace")

    steps = [
        Step(
            f"Ubah {nama_data} menjadi bit",
            f"{nama_data.capitalize()} diubah ke byte (UTF-8), lalu setiap byte ditulis sebagai 8 bit. "
            "Cipher aliran bekerja pada aliran bit ini." + conv_note,
            table=conv_rows,
        ),
        Step(
            "Siapkan LFSR dari kunci (seed)",
            f"Seed U = `{seed}` ({n} bit) dimasukkan ke register geser.\n\n"
            f"Fungsi umpan balik: `b{n} = {teks_fb}`\n\n"
            "Setiap clock: bit `b1` dikeluarkan sebagai bit keystream, register digeser ke kiri, "
            f"lalu hasil umpan balik masuk sebagai `b{n}` yang baru.\n\n"
            f"Periode maksimum: 2^{n} - 1 = {2 ** n - 1} bit sebelum keystream berulang.",
        ),
        Step(
            "Jalankan LFSR (16 clock pertama)",
            "Bit keluaran (b1) dari setiap clock membentuk keystream. "
            "Pengirim dan penerima harus memakai seed yang sama agar keystream identik.",
            table=jejak_lfsr(seed, min(16, len(data) * 8)),
            code="Keystream awal: " + group(bits_ke_str(ks[:32]), 8),
        ),
        Step(
            f"XOR {nama_data} dengan keystream",
            f"Setiap bit {nama_data} di-XOR dengan bit keystream pada posisi yang sama ({rumus})." + xor_note,
            table=xor_tampil,
        ),
        Step(f"Hasil ({nama_hasil})", teks_hasil, code=kode_hasil),
    ]
    return hasil, steps


def encrypt_bytes(data, seed):
    return proses(data, seed, True)


def decrypt_bytes(data, seed):
    return proses(data, seed, False)


def encrypt(text, seed):
    # teks -> hex
    if text == "":
        raise ValueError("Teks tidak boleh kosong.")
    hasil, steps = encrypt_bytes(text.encode("utf-8"), seed)
    return to_hex(hasil), steps


def decrypt(hex_text, seed):
    # hex -> teks
    hasil, steps = decrypt_bytes(from_hex(hex_text), seed)
    return hasil.decode("utf-8", errors="replace"), steps
