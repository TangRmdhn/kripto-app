# Block Cipher jaringan Feistel (versi mini)
#
# Parameter:
#   - blok  : 64 bit (8 byte), dibagi L (32 bit) dan R (32 bit)
#   - kunci : 64 bit (8 byte)
#   - ronde : 8
#   - padding : PKCS#7
#   - mode  : ECB atau CBC
#
# Satu ronde:
#   L(i+1) = R(i)
#   R(i+1) = L(i) XOR F(R(i), K(i))
#
# Fungsi F:
#   1. x = R XOR K
#   2. y = S-box(x) per 4 bit
#   3. z = rotasi kiri y 7 bit
#
# Setelah ronde terakhir L dan R ditukar.
# Dekripsi sama saja, hanya urutan kunci ronde dibalik.
import os

from .utils import Step, from_hex, limit, to_hex

BLOCK_SIZE = 8
ROUNDS = 8
# S-box 4 bit (sama dengan cipher PRESENT)
SBOX = [0xC, 0x5, 0x6, 0xB, 0x9, 0x0, 0xA, 0xD, 0x3, 0xE, 0xF, 0x8, 0x4, 0x7, 0x1, 0x2]


def rotasi_kiri(x, n, lebar):
    n = n % lebar
    mask = (1 << lebar) - 1
    return ((x << n) | (x >> (lebar - n))) & mask


def xor_bytes(a, b):
    hasil = bytearray()
    for i in range(len(a)):
        hasil.append(a[i] ^ b[i])
    return bytes(hasil)


def cek_mode(mode):
    mode = mode.upper()
    if mode != "ECB" and mode != "CBC":
        raise ValueError("Mode harus ECB atau CBC.")
    return mode


def siapkan_kunci(key_text):
    raw = key_text.encode("utf-8")
    if len(raw) == 0:
        raise ValueError("Kunci block cipher tidak boleh kosong.")
    if len(raw) < 8:
        # kunci pendek diulang sampai 8 byte
        key8 = (raw * 8)[:8]
        note = f"Kunci {len(raw)} byte kurang dari 8 byte, jadi diulang sampai 8 byte."
    elif len(raw) == 8:
        key8 = raw
        note = "Kunci tepat 8 byte (64 bit)."
    else:
        # kunci panjang dilipat dengan XOR
        lipat = bytearray(8)
        for i in range(len(raw)):
            lipat[i % 8] = lipat[i % 8] ^ raw[i]
        key8 = bytes(lipat)
        note = f"Kunci {len(raw)} byte lebih dari 8 byte, jadi dilipat dengan XOR menjadi 8 byte."
    return key8, note


def buat_kunci_ronde(key8):
    # kunci ronde ke-i = 32 bit kiri dari kunci yang diputar kiri 11*(i-1) bit
    k = int.from_bytes(key8, "big")
    hasil = []
    for i in range(ROUNDS):
        hasil.append(rotasi_kiri(k, 11 * i, 64) >> 32)
    return hasil


def fungsi_f(r, rk):
    x = r ^ rk
    y = 0
    for i in range(8):
        nibble = (x >> (28 - 4 * i)) & 0xF
        y = (y << 4) | SBOX[nibble]
    z = rotasi_kiri(y, 7, 32)
    return x, y, z


def feistel(block, keys, labels, trace=None):
    left = int.from_bytes(block[:4], "big")
    right = int.from_bytes(block[4:], "big")
    ronde = 1
    for i in range(len(keys)):
        rk = keys[i]
        x, y, z = fungsi_f(right, rk)
        right_baru = left ^ z
        if trace is not None:
            trace.append({
                "Ronde": str(ronde),
                "L": f"{left:08X}",
                "R": f"{right:08X}",
                "Kunci ronde": f"K{labels[i]} = {rk:08X}",
                "R ⊕ K": f"{x:08X}",
                "Setelah S-box": f"{y:08X}",
                "F (rotasi 7 bit)": f"{z:08X}",
                "R baru = L ⊕ F": f"{right_baru:08X}",
            })
        left = right
        right = right_baru
        ronde += 1
    # tukar di akhir
    return right.to_bytes(4, "big") + left.to_bytes(4, "big")


def tambah_padding(data):
    n = BLOCK_SIZE - len(data) % BLOCK_SIZE
    return data + bytes([n]) * n, n


def buang_padding(data):
    if len(data) > 0:
        n = data[-1]
    else:
        n = 0
    if n < 1 or n > BLOCK_SIZE or data[-n:] != bytes([n]) * n:
        raise ValueError(
            "Padding tidak valid. Kemungkinan kunci atau mode salah, atau cipherteks rusak."
        )
    return data[:-n], n


def langkah_kunci(key8, note, rks, dekripsi):
    rows = []
    for i in range(len(rks)):
        rows.append({
            "Ronde": str(i + 1),
            "Kunci ronde": f"K{i + 1}",
            "Nilai (32 bit, hex)": f"{rks[i]:08X}",
            "Rumus": f"32 bit kiri dari (kunci diputar kiri {11 * i} bit)",
        })
    urutan = ""
    if dekripsi:
        urutan = "Pada dekripsi, kunci dipakai dengan urutan terbalik (K8 dulu sampai K1)."
    return [
        Step("Siapkan kunci 64 bit", f"{note}\n\nKunci 64 bit (hex): `{key8.hex().upper()}`"),
        Step(
            "Bangkitkan kunci ronde (key schedule)",
            f"Dari kunci 64 bit dibuat {ROUNDS} kunci ronde masing-masing 32 bit. {urutan}",
            table=rows,
        ),
    ]


def penjelasan_ronde():
    return (
        "Setiap ronde:\n\n"
        "- `L(i+1) = R(i)`\n"
        "- `R(i+1) = L(i) ⊕ F(R(i), K(i))`\n\n"
        "Fungsi F: `R ⊕ K`, lalu substitusi S-box 4 bit pada tiap nibble, lalu rotasi kiri 7 bit. "
        "Setelah ronde terakhir, L dan R ditukar."
    )


def pecah_blok(data):
    blocks = []
    for i in range(0, len(data), BLOCK_SIZE):
        blocks.append(data[i:i + BLOCK_SIZE])
    return blocks


def encrypt_bytes(data, key_text, mode="ECB", iv=None):
    mode = cek_mode(mode)
    key8, note = siapkan_kunci(key_text)
    rks = buat_kunci_ronde(key8)
    labels = list(range(1, ROUNDS + 1))
    steps = langkah_kunci(key8, note, rks, False)

    padded, npad = tambah_padding(data)
    blocks = pecah_blok(padded)
    steps.append(Step(
        "Padding dan pembagian blok",
        f"Data {len(data)} byte ditambah **{npad} byte padding** bernilai `{npad:02X}` sehingga panjangnya "
        f"kelipatan {BLOCK_SIZE} byte (64 bit). Hasilnya {len(blocks)} blok.\n\n"
        f"Data setelah padding (hex): `{padded.hex().upper()}`",
    ))

    prev = b""
    if mode == "CBC":
        if iv is None:
            iv = os.urandom(BLOCK_SIZE)
        prev = iv
        steps.append(Step(
            "Mode CBC dan IV",
            "Pada mode CBC setiap blok plainteks di-XOR dulu dengan cipherteks blok sebelumnya "
            "(blok pertama di-XOR dengan IV acak). IV ditaruh di depan cipherteks agar dekripsi bisa dilakukan.\n\n"
            f"IV (hex): `{iv.hex().upper()}`",
        ))
    else:
        steps.append(Step(
            "Mode ECB",
            "Pada mode ECB setiap blok dienkripsi sendiri-sendiri. Blok plainteks yang sama menghasilkan "
            "cipherteks yang sama.",
        ))

    trace = []
    out_blocks = []
    rows = []
    nomor = 1
    for blk in blocks:
        if mode == "CBC":
            inp = xor_bytes(blk, prev)
        else:
            inp = blk
        # jejak ronde hanya untuk blok pertama
        if nomor == 1:
            c = feistel(inp, rks, labels, trace)
        else:
            c = feistel(inp, rks, labels)
        row = {"Blok": str(nomor), "Plainteks (hex)": blk.hex().upper()}
        if mode == "CBC":
            row["Setelah XOR (CBC)"] = inp.hex().upper()
        row["Cipherteks (hex)"] = c.hex().upper()
        rows.append(row)
        out_blocks.append(c)
        prev = c
        nomor += 1

    steps.append(Step("Jaringan Feistel pada blok 1 (8 ronde)", penjelasan_ronde(), table=trace))
    tampil, catatan = limit(rows)
    steps.append(Step("Enkripsi semua blok", "Semua blok diproses dengan cara yang sama." + catatan, table=tampil))

    hasil = b"".join(out_blocks)
    if mode == "CBC":
        hasil = iv + hasil
        ket = "Pada mode CBC, 8 byte pertama adalah IV."
    else:
        ket = ""
    steps.append(Step("Hasil (hex)", ket, code=to_hex(hasil)))
    return hasil, steps


def decrypt_bytes(data, key_text, mode="ECB"):
    mode = cek_mode(mode)
    key8, note = siapkan_kunci(key_text)
    rks = buat_kunci_ronde(key8)
    rks_balik = list(reversed(rks))
    labels = list(range(ROUNDS, 0, -1))
    steps = langkah_kunci(key8, note, rks, True)

    if mode == "CBC":
        if len(data) < 2 * BLOCK_SIZE or len(data) % BLOCK_SIZE != 0:
            raise ValueError("Cipherteks CBC harus berisi IV 8 byte dan minimal satu blok (kelipatan 8 byte).")
        iv = data[:BLOCK_SIZE]
        body = data[BLOCK_SIZE:]
        steps.append(Step(
            "Pisahkan IV (mode CBC)",
            f"8 byte pertama cipherteks adalah IV: `{iv.hex().upper()}`. Sisanya adalah blok cipherteks.",
        ))
        prev = iv
    else:
        if len(data) == 0 or len(data) % BLOCK_SIZE != 0:
            raise ValueError("Cipherteks ECB harus kelipatan 8 byte (16 karakter hex).")
        body = data
        prev = b""

    blocks = pecah_blok(body)
    steps.append(Step(
        "Bagi cipherteks menjadi blok",
        f"Cipherteks {len(body)} byte dibagi menjadi {len(blocks)} blok 64 bit.",
    ))

    trace = []
    plain_blocks = []
    rows = []
    nomor = 1
    for blk in blocks:
        if nomor == 1:
            raw = feistel(blk, rks_balik, labels, trace)
        else:
            raw = feistel(blk, rks_balik, labels)
        if mode == "CBC":
            p = xor_bytes(raw, prev)
        else:
            p = raw
        row = {"Blok": str(nomor), "Cipherteks (hex)": blk.hex().upper()}
        if mode == "CBC":
            row["Setelah Feistel"] = raw.hex().upper()
        row["Plainteks (hex)"] = p.hex().upper()
        rows.append(row)
        plain_blocks.append(p)
        prev = blk
        nomor += 1

    steps.append(Step(
        "Jaringan Feistel pada blok 1 (kunci dibalik)",
        penjelasan_ronde() + "\n\nDekripsi memakai algoritma yang sama, tetapi urutan kunci ronde dibalik.",
        table=trace,
    ))
    tampil, catatan = limit(rows)
    judul = "Dekripsi semua blok"
    if mode == "CBC":
        judul += " dan XOR dengan blok sebelumnya (CBC)"
    steps.append(Step(judul, "Semua blok diproses dengan cara yang sama." + catatan, table=tampil))

    hasil, npad = buang_padding(b"".join(plain_blocks))
    steps.append(Step(
        "Hapus padding",
        f"Byte terakhir bernilai `{npad:02X}`, artinya {npad} byte padding dibuang.",
    ))
    steps.append(Step("Hasil", code=hasil.decode("utf-8", errors="replace")))
    return hasil, steps


def encrypt(text, key_text, mode="ECB"):
    # teks -> hex
    if text == "":
        raise ValueError("Teks tidak boleh kosong.")
    hasil, steps = encrypt_bytes(text.encode("utf-8"), key_text, mode)
    return to_hex(hasil), steps


def decrypt(hex_text, key_text, mode="ECB"):
    # hex -> teks
    hasil, steps = decrypt_bytes(from_hex(hex_text), key_text, mode)
    return hasil.decode("utf-8", errors="replace"), steps
