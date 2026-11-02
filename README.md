# 💀 SMASH — Web Intelligence & Audit Tool

```
 ███████╗███╗   ███╗ █████╗ ███████╗██╗  ██╗
 ██╔════╝████╗ ████║██╔══██╗██╔════╝██║  ██║
 ███████╗██╔████╔██║███████║███████╗███████║
 ╚════██║██║╚██╔╝██║██╔══██║╚════██║██╔══██║
 ███████║██║ ╚═╝ ██║██║  ██║███████║██║  ██║
 ╚══════╝╚═╝     ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝
```

> Tool audit & intelijen web berbasis Python — crawl, analisis AI, dan recon otomatis.

---

## 📖 Penjelasan

SMASH adalah tool berbasis Python untuk keperluan **audit keamanan web** dan **pengumpulan intelijen**. Tool ini dirancang untuk:

- Mengambil source code HTML halaman utama sebuah website
- Melakukan crawl mendalam hingga ribuan halaman
- Memindai path sensitif (`.env`, `backup.sql`, `/admin`, dll)
- Menganalisis source code menggunakan AI (OpenRouter) untuk menemukan kredensial bocor, struktur database, endpoint tersembunyi, dan celah keamanan
- Menghasilkan file output terorganisir: schema database, laporan recon, daftar aset, dan data yang bocor
- Menyediakan menu serangan lanjutan setelah proses scan selesai

SMASH berjalan sepenuhnya dari terminal, tanpa dependensi eksternal selain Python 3.

---

## ⚠️ Peringatan

```
PERINGATAN HUKUM — BACA SEBELUM MENGGUNAKAN
```

- Tool ini **hanya boleh digunakan pada sistem yang Anda miliki** atau sistem yang telah memberikan izin tertulis secara eksplisit untuk diuji.
- Penggunaan tool ini terhadap sistem tanpa izin adalah **tindakan ilegal** dan dapat dijerat dengan undang-undang kejahatan siber yang berlaku di negara Anda.
- Pembuat dan kontributor **tidak bertanggung jawab** atas segala kerusakan, kehilangan data, atau tuntutan hukum yang timbul akibat penyalahgunaan tool ini.
- Tool ini dibuat untuk tujuan **edukasi, riset keamanan, dan CTF** semata.
- **Gunakan dengan bijak. Gunakan secara etis.**

---

## 🚀 Cara Penggunaan

### Persyaratan & Setup

SMASH tidak membutuhkan library eksternal — semua dependensi sudah bawaan Python. Yang perlu disiapkan hanya Python-nya sendiri.

---

#### 🤖 Android (Termux)

```bash
# 1. Install Termux dari F-Droid (bukan Play Store)
#    https://f-droid.org/packages/com.termux/

# 2. Update paket
pkg update && pkg upgrade -y

# 3. Install Python
pkg install python -y

# 4. Install git
pkg install git -y

# 5. Beri izin akses storage (wajib untuk simpan ZIP ke Download)
termux-setup-storage

# 6. Verifikasi
python --version
git --version
```

---

#### 🐧 Linux (Debian/Ubuntu/Kali)

```bash
# 1. Update sistem
sudo apt update && sudo apt upgrade -y

# 2. Install Python 3 + pip
sudo apt install python3 python3-pip git -y

# 3. Verifikasi
python3 --version
git --version
```

---

#### 🍎 macOS

```
# 1. Install Homebrew (kalau belum ada)
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# 2. Install Python & git
brew install python git

# 3. Verifikasi
python3 --version
git --version
```

---

#### 🪟 Windows

```
# 1. Download Python dari https://python.org/downloads/
#    Centang "Add Python to PATH" saat install

# 2. Install git dari https://git-scm.com/

# 3. Verifikasi di CMD/PowerShell
python --version
git --version
```

---

> **Catatan:** SMASH menggunakan API OpenRouter untuk fitur AI. Pastikan koneksi internet aktif saat scan berlangsung. API key sudah tertanam di dalam script.

### Instalasi

```bash
git clone https://github.com/vsa-html/ddos3.git
cd ddos3
```

### Jalankan

```bash
python main.py
```

### Pilih Level Crawl

| Level | Keterangan |
|-------|-----------|
| `1` | Hanya ambil source code HTML utama — cepat, tanpa crawl |
| `2` | Crawl hingga 5 level (~500 halaman) + AI scan |
| `3` | Crawl penuh domain (~2000 halaman) + AI scan |
| `4` | Tanpa batas sampai semua link habis + AI scan |
| `5` | LEVEL PENUH — crawl habis + 1000 path sensitif + probe paralel + AI scan semua halaman per batch |

### Alur Kerja

```
Input URL
   ↓
Pilih level crawl
   ↓
Sistem crawl + probe path sensitif
   ↓
AI Pass 1 — scan HTML baris per baris (97 baris/chunk)
   ↓
AI download aset (gambar, font, dll)
   ↓
AI Pass 2 — generate file output
   ↓
ZIP otomatis → /storage/emulated/0/Download
   ↓
Menu serangan (DDOS / Hack)
```

### Output yang Dihasilkan

```
webhack_[domain]_[timestamp]/
├── [domain].html          → halaman utama (CSS inline)
├── html/                  → halaman lain yang ter-crawl
├── database/
│   ├── schema.sql         → rekonstruksi schema database
│   ├── query_umum.sql     → query SELECT/INSERT/UPDATE/DELETE
│   ├── koneksi.txt        → kode koneksi PHP/Python/Node.js
│   ├── .env.temuan        → kredensial yang ditemukan
│   └── config_rekonstruksi.php
├── assets/
│   └── daftar_aset.txt    → daftar CSS, JS, gambar, font
└── recon/
    ├── akun_admin_bocor.txt
    ├── data_pengguna_bocor.txt
    ├── laporan_ai.txt
    └── ai_scan_raw.json
```

---

## 📋 Penjelasan Update — Riwayat Versi

| Versi | Perubahan |
|-------|-----------|
| `smash11` | Versi awal — crawl dasar, probe path sensitif, ZIP output |
| `smash13` | Tambah 320 path sensitif, sistem AI pertama (Groq) |
| `smash14` | Perbaikan klasifikasi file database vs HTML |
| `smash15` | Fix model AI dan dekompresi error response |
| `smash17` | Fix file non-HTML masuk folder database |
| `smash18` | Filter konten HTML palsu di folder database |
| `smash19` | AI deteksi akun admin bocor & data pengguna bocor |
| `smash20` | AI download aset, Level 5, auto-download ZIP, menu serangan DDOS/Hack |
| `smash21` | HTML main dibaca per 97 baris, batch 19 halaman acak |
| `smash22` | Ganti provider AI ke OpenRouter |
| `smash25` | HTML main fully self-contained (CSS + JS + font inline) |
| `smash26` | Hemat storage — JS max 500KB, gambar pakai URL absolut |
| `smash27` | Level 1: hanya ambil source code, tanpa crawl & AI |
| `smash29` | Level 1: inline CSS saja, cepat, tidak putih |
| `smash30` | Semua level pakai CSS-only inline — hemat storage |
| `smash31` | Dual model AI untuk Pass 2 |
| `smash32` | 1 model, 2 API key, rotasi otomatis saat error |
| `smash33` | 3 API key + fallback sistem mandiri kalau semua AI gagal |
| `smash34` | Jalur download ZIP → folder Download |

---

## 🔚 Penutup

SMASH dikembangkan sebagai proyek pembelajaran di bidang keamanan web dan otomasi Python. Setiap versi membawa perbaikan nyata — dari kecepatan, akurasi AI, hingga kualitas output.

Jika Anda menemukan bug atau ingin berkontribusi, buka **Issues** atau **Pull Request** di repositori ini.

> *"Kenali sistemmu sebelum orang lain yang mengenalinya."*

---

<p align="center">
Dibuat dengan ☕ dan Python 3
</p>
