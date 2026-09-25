# Aplikasi Enkripsi dan Dekripsi (Kriptografi Klasik dan Modern)

Tugas Mata Kuliah Kriptografi (Materi 5: Algoritma Kriptografi Modern).
Aplikasi web berbasis **Streamlit** yang melakukan enkripsi dan dekripsi dengan **5 menu**,
lengkap dengan halaman yang menampilkan **proses algoritma langkah demi langkah**.

Seluruh algoritma ditulis **manual** (tanpa library kriptografi) supaya setiap langkahnya bisa ditampilkan
dan dipelajari.

## Anggota Kelompok

| Nama | NIM |
|------|-----|
| Bintang Ramadhan | 123240073 |
| Fahmi Firdaus | 123240055 |
| Farabian Nabil Alauzi | 123240058 |

## Menu Aplikasi

| Menu | Algoritma | Jenis | Bekerja pada |
|------|-----------|-------|--------------|
| 1 | Vigenere Cipher | Klasik (substitusi) | Huruf |
| 2 | Caesar Cipher | Klasik (substitusi) | Karakter |
| 3 | Stream Cipher LFSR | Modern (cipher aliran) | Bit |
| 4 | Block Cipher Feistel | Modern (cipher blok) | Blok 64 bit |
| 5 | Super Enkripsi | Gabungan menu 1 sampai 4 | Teks lalu bit |

## Cara Menjalankan

Butuh Python 3.9 atau lebih baru.

```bash
# 1. (opsional) buat virtual environment
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate

# 2. pasang dependensi
pip install -r requirements.txt

# 3. jalankan aplikasi
streamlit run app.py
```

Aplikasi terbuka di `http://localhost:8501`.

## Cara Memakai

1. Pilih menu di sidebar.
2. Pilih mode **Enkripsi** atau **Dekripsi**.
3. Isi teks dan kunci, lalu klik tombol **Proses**.
4. Hasil muncul di bagian atas, dan penjelasan **langkah demi langkah** muncul di bawahnya.

Format cipherteks:

- Menu 1 dan 2: teks biasa.
- Menu 3, 4, dan 5: **heksadesimal** (salin dengan ikon salin pada kotak hasil, lalu tempel ke mode Dekripsi).

## Penjelasan Algoritma

### 1. Vigenere Cipher
Setiap huruf digeser sejauh nilai huruf kunci yang diulang (A=0, ..., Z=25).

```
Enkripsi: Ci = (Pi + Ki) mod 26
Dekripsi: Pi = (Ci - Ki) mod 26
```

Karakter selain huruf (spasi, angka, tanda baca) tidak diubah. Huruf besar dan kecil dipertahankan.

### 2. Caesar Cipher
Substitusi monoalfabetik: setiap huruf digeser sejauh kunci (bilangan bulat, dimodulo 26).

```
Enkripsi: Ci = (Pi + K) mod 26
Dekripsi: Pi = (Ci - K) mod 26
```

### 3. Stream Cipher LFSR
Sesuai materi: keystream dibangkitkan oleh LFSR dari seed (kunci U), lalu di-XOR dengan bit data.

```
ci = pi XOR ki        pi = ci XOR ki
```

- Register geser n bit `b1 ... bn`, bit keluaran adalah `b1`.
- Umpan balik adalah XOR dari bit-bit tap, dimasukkan sebagai `bn` yang baru setelah register digeser kiri.
- Pilihan seed 4, 8, atau 16 bit dengan periode maksimum `2^n - 1`.

| n | Tap (posisi bit) |
|---|------------------|
| 4 | b1, b4 (sama dengan contoh di materi) |
| 8 | b1, b3, b4, b5 |
| 16 | b1, b3, b4, b6 |

Contoh materi: seed `1111` menghasilkan `111101011001000` lalu berulang (periode 15). Ini diuji di unit test.

**Catatan keamanan (dari materi):** seed yang sama untuk dua pesan berbeda menghasilkan keystream yang sama,
sehingga rentan terhadap serangan keystream reuse (`C1 XOR C2 = P1 XOR P2`).

### 4. Block Cipher Feistel (versi mini)

| Parameter | Nilai |
|-----------|-------|
| Ukuran blok | 64 bit (L 32 bit dan R 32 bit) |
| Ukuran kunci | 64 bit (kunci teks diulang bila kurang, dilipat dengan XOR bila lebih) |
| Jumlah ronde | 8 |
| Padding | PKCS#7 |
| Mode | ECB atau CBC (IV acak, ditaruh di depan cipherteks) |

Satu ronde:

```
L(i+1) = R(i)
R(i+1) = L(i) XOR F(R(i), K(i))
```

Fungsi F: `R XOR K`, substitusi S-box 4 bit pada tiap nibble (S-box yang sama dengan cipher PRESENT),
lalu rotasi kiri 7 bit. Setelah ronde terakhir, L dan R ditukar. Dekripsi memakai algoritma yang sama dengan
**urutan kunci ronde dibalik**. Kunci ronde ke-i adalah 32 bit kiri dari kunci yang diputar kiri `11 x (i-1)` bit.

### 5. Super Enkripsi

```
Plainteks -> Vigenere -> Caesar -> LFSR -> Feistel -> Cipherteks (hex)
```

Algoritma klasik berjalan lebih dulu pada teks, lalu hasilnya diubah menjadi byte (UTF-8) untuk diproses
algoritma modern. Dekripsi berjalan dengan urutan terbalik. Keempat kunci (Vigenere, Caesar, seed LFSR,
kunci Feistel) harus sama saat dekripsi.

## Struktur Proyek

```
.
├── app.py                  # Antarmuka Streamlit (5 menu)
├── ciphers/
│   ├── utils.py            # Step, konversi bit/hex, helper tabel
│   ├── vigenere.py         # Menu 1
│   ├── caesar.py           # Menu 2
│   ├── lfsr_stream.py      # Menu 3
│   ├── feistel.py          # Menu 4
│   └── super_cipher.py     # Menu 5
├── tests/
│   └── test_ciphers.py     # Unit test
├── requirements.txt
└── README.md
```

Setiap fungsi enkripsi/dekripsi mengembalikan `(hasil, daftar_langkah)`. Daftar langkah itulah yang
ditampilkan `app.py` sebagai halaman proses.

## Menjalankan Unit Test

```bash
python -m unittest discover -s tests -v
```

Test mencakup vektor uji Vigenere klasik (`ATTACKATDAWN` + `LEMON` = `LXFOPVEFRNHR`), contoh LFSR dari materi,
periode maksimum LFSR, round trip semua algoritma (ECB dan CBC), serta penanganan input/kunci yang salah.

## Batasan

- Input berupa teks (UTF-8), bukan file.
- Tabel proses dipotong sampai 64 baris pada teks yang panjang supaya halaman tetap ringan.
