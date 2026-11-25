# DDoS Shield - Sistem Deteksi DDoS Berbasis Machine Learning
### Proyek: Deteksi Serangan DDoS dengan Machine Learning Berbasis Dataset CICDDoS2019
**Kelompok: 2 - KSI5B** | Mata Kuliah: **Kecerdasan Buatan untuk Keamanan (Semester 5)**

---

## 📁 Struktur Direktori Proyek

```text
Project_deteksi_DDos_berbasis_machine_learning/
│
├── core/                           # 🧠 Modul Inti Machine Learning
│   ├── __init__.py
│   ├── preprocessing.py           # Pembersihan data & feature selection
│   ├── detector.py                # Inference engine (memuat pipeline & model untuk prediksi)
│   └── trainer.py                 # Skrip pelatihan & evaluasi model ML
│
├── dataset/                        # 📊 Penyimpanan Dataset Trafik Jaringan
│   ├── raw/                       # File asli (CSV dari CICDDoS2019 dsb)
│   ├── processed/                 # Data bersih siap training
│   ├── sample/                    # Sampel dataset kecil untuk pengujian cepat
│   └── README.md
│
├── models/                         # 💾 Tempat Model ML & Pipeline (.joblib / .pkl)
│   ├── preprocessing_pipeline.joblib # Pipeline Scikit-learn untuk transformasi fitur alur
│   ├── Minggu6_XGBoost.pkl        # Model XGBoost (F1: 0.9994)
│   ├── Minggu6_RF.pkl             # Model Random Forest (F1: 0.9976)
│   └── README.md
│
├── notebooks/                      # 📓 Eksperimen & Analisis (Jupyter Notebook)
│   ├── eda.ipynb                  # Exploratory Data Analysis & visualisasi
│   ├── model_training.ipynb       # Pelatihan, tuning parameter & evaluasi metrik
│   └── README.md
│
├── database/                       # 🗄️ Database & Manajemen Log
│   ├── ddos_deteksi.db            # Database SQLite resmi Kelompok 2 - KSI5B
│   ├── schema_ddos_deteksi.sql    # DDL / Skema SQL lengkap (8 tabel)
│   └── db_manager.py              # Konektor Python SQLite & fungsi CRUD
│
├── templates/                      # 🌐 Antarmuka Web Dashboard (HTML Jinja2)
│   ├── base.html                  # Template induk (kerangka HTML umum)
│   ├── layout_app.html            # Layout sidebar & navbar sistem
│   ├── landing.html               # Halaman utama / landing page
│   ├── login.html                 # Autentikasi pengguna
│   ├── register.html              # Pendaftaran akun analis
│   ├── dashboard.html             # Ringkasan statistik & metrik DDoS
│   ├── monitoring.html            # Pemantauan trafik jaringan real-time
│   ├── alert.html                 # Daftar alert & insiden serangan terdeteksi
│   ├── visualisasi.html           # Grafik tren per jam & distribusi tipe serangan
│   ├── performa.html          # Metrik akurasi, precision, recall & F1-score model
│   ├── riwayat.html               # Riwayat log trafik jaringan
│   ├── export.html                # Ekspor laporan insiden (PDF/Excel)
│   ├── notifikasi.html            # Pusat notifikasi analis & admin
│   ├── pengaturan.html            # Pengaturan threshold alert & profil
│   ├── admin_ringkasan.html       # Overview administrator sistem
│   ├── admin_pengguna.html        # Manajemen persetujuan & peran pengguna
│   ├── admin_model.html           # Monitoring & aktivasi versi model ML
│   └── admin_log.html             # Audit trail & system logs
│
├── static/                         # 🎨 File Aset Web Statis
│   ├── css/
│   │   └── style.css              # Styling antarmuka web (Cybersecurity Theme)
│   └── js/
│       └── app.js                 # Logika interaktif frontend & grafik
│
├── app.py                          # 🚀 Server Aplikasi Web Flask (Routing & Controllers)
├── config.py                       # ⚙️ Konfigurasi Path Model, Database & Parameter Global
├── data.py                         # 📦 Data Provider & Simulasi Generator Flow
├── requirements.txt                # 📋 Daftar dependensi library Python
├── .gitignore                      # 🛡️ Mencegah file cache / dataset besar ter-commit ke Git
└── README.md                       # 📖 Dokumentasi proyek
```

---

## 🗄️ Tabel Database (`ddos_deteksi.db`)
1. **`jenis_serangan`**: 12 jenis serangan (NetBIOS, MSSQL, UDP, Syn, Portmap, LDAP, NTP, TFTP, DNS, SNMP, WebDDoS, BENIGN).
2. **`sumber_dataset`**: Metadata dataset CICDDoS2019.
3. **`alur_jaringan`**: 89 kolom fitur ekstraksi jaringan (Flow Duration, Fwd/Bwd Packets, IAT, Flags TCP, dll.).
4. **`model_ml`**: Menyimpan riwayat model (`Minggu6_XGBoost.pkl`, `Minggu6_RF.pkl`).
5. **`sesi_latih`**: Riwayat sesi pelatihan model ML (hyperparameter, rasio split).
6. **`hasil_deteksi`**: Log hasil prediksi real-time model terhadap alur jaringan.
7. **`pengguna`**: Akun pengguna sistem (`admin`, `user`).
8. **`sesi_masuk`**: Audit log aktivitas login/logout.

---

## 🚀 Cara Menjalankan Proyek

### 1. Instal Dependensi
Pastikan koneksi internet aktif di terminal Anda, lalu jalankan:
```bash
pip install -r requirements.txt
```

### 2. Jalankan Aplikasi Web Flask
```bash
python app.py
```
Akses di browser: `http://127.0.0.1:5000`

---

## 👥 Akun Login Bawaan
- **Admin**: `admin@ddos-system.id` (atau `admin@polbeng.ac.id`) | Sandi: `admin123`
- **User / Analis**: `user1@ddos-system.id` | Sandi: `user123`
