# Aplikasi Enkripsi dan Dekripsi (Streamlit)
#
# Menu:
#   1. Vigenere Cipher     (klasik)
#   2. Caesar Cipher       (klasik)
#   3. Stream Cipher LFSR  (modern)
#   4. Block Cipher Feistel (modern)
#   5. Super Enkripsi      (gabungan 1-4)
#
# Jalankan dengan: streamlit run app.py
import pandas as pd
import streamlit as st

from ciphers import caesar, feistel, lfsr_stream, super_cipher, vigenere

st.set_page_config(page_title="Aplikasi Kriptografi", layout="wide")

MENU = [
    "1. Vigenere Cipher (Klasik)",
    "2. Caesar Cipher (Klasik)",
    "3. Stream Cipher LFSR (Modern)",
    "4. Block Cipher Feistel (Modern)",
    "5. Super Enkripsi (Gabungan 1-4)",
]


# ---------- fungsi bantu tampilan ----------
def tampilkan_steps(steps):
    nomor = 0
    for s in steps:
        if s.kind == "header":
            st.markdown(f"### {s.title}")
            if s.detail:
                st.markdown(s.detail)
            if s.code is not None:
                st.code(s.code, language=None)
            nomor = 0
            continue
        nomor += 1
        with st.expander(f"Langkah {nomor}: {s.title}", expanded=True):
            if s.detail:
                st.markdown(s.detail)
            if s.table:
                st.dataframe(pd.DataFrame(s.table), hide_index=True)
            if s.code is not None:
                st.code(s.code, language=None)


def pilih_mode(key):
    return st.radio("Mode", ["Enkripsi", "Dekripsi"], horizontal=True, key=f"mode_{key}")


def input_teks(mode, key, contoh):
    if mode == "Enkripsi":
        return st.text_area("Plainteks", value=contoh, height=120, key=f"in_{key}_enc")
    return st.text_area(
        "Cipherteks", value="", height=120, key=f"in_{key}_dec",
        placeholder="Tempel cipherteks di sini",
        help="Cipherteks dari menu LFSR, Feistel, dan Super berupa heksadesimal. "
             "Untuk Vigenere dan Caesar berupa teks biasa.",
    )


def tombol_proses(key, mode):
    return st.button(f"Proses {mode.lower()}", type="primary", key=f"btn_{key}_{mode}")


def jalankan(fungsi, mode):
    # panggil fungsi cipher, kalau error tampilkan pesannya
    try:
        hasil, steps = fungsi()
    except ValueError as e:
        st.error(str(e))
        return

    if mode == "Enkripsi":
        label = "Cipherteks"
    else:
        label = "Plainteks"
    st.subheader(f"Hasil {mode.lower()}")
    st.markdown(f"**{label}** (klik ikon salin di kanan atas kotak):")
    st.code(hasil, language=None)
    st.subheader("Proses langkah demi langkah")
    tampilkan_steps(steps)


# ---------- halaman tiap menu ----------
def halaman_vigenere():
    st.header("Menu 1: Vigenere Cipher (Klasik)")
    st.markdown(
        "Substitusi polialfabetik. Setiap huruf digeser sejauh nilai huruf kunci yang berulang.\n\n"
        "`Ci = (Pi + Ki) mod 26` dan `Pi = (Ci - Ki) mod 26` dengan A=0 sampai Z=25."
    )
    mode = pilih_mode("vig")
    teks = input_teks(mode, "vig", "Kriptografi Modern 2026")
    kunci = st.text_input("Kunci (huruf A-Z)", value="KRIPTO", key="key_vig")
    if tombol_proses("vig", mode):
        if mode == "Enkripsi":
            jalankan(lambda: vigenere.encrypt(teks, kunci), mode)
        else:
            jalankan(lambda: vigenere.decrypt(teks, kunci), mode)


def halaman_caesar():
    st.header("Menu 2: Caesar Cipher (Klasik)")
    st.markdown(
        "Substitusi monoalfabetik. Setiap huruf digeser sejauh kunci (bilangan bulat).\n\n"
        "`Ci = (Pi + K) mod 26` dan `Pi = (Ci - K) mod 26` dengan A=0 sampai Z=25."
    )
    mode = pilih_mode("caesar")
    teks = input_teks(mode, "caesar", "Kriptografi itu seru dan menantang")
    kunci = st.number_input("Kunci (geser)", value=3, step=1, key="key_caesar")
    if tombol_proses("caesar", mode):
        if mode == "Enkripsi":
            jalankan(lambda: caesar.encrypt(teks, kunci), mode)
        else:
            jalankan(lambda: caesar.decrypt(teks, kunci), mode)


def halaman_lfsr():
    st.header("Menu 3: Stream Cipher LFSR (Modern)")
    st.markdown(
        "Keystream dibangkitkan oleh LFSR dari seed (kunci U), lalu di-XOR bit demi bit dengan data.\n\n"
        "`ci = pi ⊕ ki` dan `pi = ci ⊕ ki`. Enkripsi dan dekripsi memakai proses yang sama."
    )
    mode = pilih_mode("lfsr")
    teks = input_teks(mode, "lfsr", "Kriptografi Modern")
    n = st.selectbox("Panjang seed (bit)", [4, 8, 16], index=2, key="lfsr_n")
    seed = st.text_input("Seed (bit 0/1, tidak boleh semua 0)", value=lfsr_stream.DEFAULT_SEEDS[n],
                         key=f"seed_{n}")
    if tombol_proses("lfsr", mode):
        if mode == "Enkripsi":
            jalankan(lambda: lfsr_stream.encrypt(teks, seed), mode)
        else:
            jalankan(lambda: lfsr_stream.decrypt(teks, seed), mode)


def halaman_feistel():
    st.header("Menu 4: Block Cipher Feistel (Modern)")
    st.markdown(
        "Data dipecah menjadi blok 64 bit dan diproses oleh jaringan Feistel 8 ronde "
        "(XOR kunci, S-box, rotasi). Padding memakai PKCS#7.\n\n"
        "`L(i+1) = R(i)` dan `R(i+1) = L(i) ⊕ F(R(i), K(i))`."
    )
    mode = pilih_mode("fei")
    teks = input_teks(mode, "fei", "Rahasia kelompok kriptografi")
    kunci = st.text_input("Kunci (teks, diolah menjadi 64 bit)", value="KUNCI123", key="key_fei")
    mode_blok = st.selectbox("Mode operasi blok", ["ECB", "CBC"], key="bmode_fei",
                             help="CBC memakai IV acak yang ditaruh di depan cipherteks.")
    if tombol_proses("fei", mode):
        if mode == "Enkripsi":
            jalankan(lambda: feistel.encrypt(teks, kunci, mode_blok), mode)
        else:
            jalankan(lambda: feistel.decrypt(teks, kunci, mode_blok), mode)


def halaman_super():
    st.header("Menu 5: Super Enkripsi (Gabungan 1-4)")
    st.markdown(
        "Gabungan keempat algoritma. Enkripsi berjalan berurutan:\n\n"
        "`Plainteks -> Vigenere -> Caesar -> LFSR -> Feistel -> Cipherteks (hex)`\n\n"
        "Dekripsi berjalan dengan urutan kebalikannya."
    )
    mode = pilih_mode("sup")
    teks = input_teks(mode, "sup", "Halo Kriptografi, ini super enkripsi!")
    kolom1, kolom2 = st.columns(2)
    with kolom1:
        k_vig = st.text_input("Kunci Vigenere (huruf)", value="KRIPTO", key="sup_vig")
        seed = st.text_input("Seed LFSR 16 bit", value=lfsr_stream.DEFAULT_SEEDS[16], key="sup_seed")
    with kolom2:
        k_caesar = st.number_input("Kunci Caesar (geser)", value=3, step=1, key="sup_caesar")
        k_blok = st.text_input("Kunci Feistel (teks)", value="KUNCI123", key="sup_block")
    mode_blok = st.selectbox("Mode operasi blok Feistel", ["ECB", "CBC"], key="sup_bmode")
    if tombol_proses("sup", mode):
        if mode == "Enkripsi":
            jalankan(lambda: super_cipher.encrypt(teks, k_vig, k_caesar, seed, k_blok, mode_blok), mode)
        else:
            jalankan(lambda: super_cipher.decrypt(teks, k_vig, k_caesar, seed, k_blok, mode_blok), mode)


# ---------- navigasi ----------
st.sidebar.title("Aplikasi Kriptografi")
menu = st.sidebar.radio("Pilih menu", MENU)

if menu == MENU[0]:
    halaman_vigenere()
elif menu == MENU[1]:
    halaman_caesar()
elif menu == MENU[2]:
    halaman_lfsr()
elif menu == MENU[3]:
    halaman_feistel()
else:
    halaman_super()
