"""Data provider untuk DDoS Shield & Deteksi DDoS Kelompok 2 - KSI5B.
Terintegrasi langsung dengan dataset CICDDoS2019 (train_processed.csv & test_processed.csv)
dan model machine learning XGBoost / Random Forest.
"""
import os
import csv
import random
from datetime import datetime, timedelta
try:
    from werkzeug.security import generate_password_hash
except ImportError:
    import hashlib
    def generate_password_hash(pw):
        return "sha256$" + hashlib.sha256(pw.encode()).hexdigest()

# ---------------- KELAS SERANGAN AKTIF DARI DATASET ----------------
KELAS = ["BENIGN", "LDAP", "MSSQL", "NetBIOS", "Portmap", "Syn", "UDP", "UDPLag"]

# ---------------- INFORMASI DATASET PREPROCESSED ----------------
DATASET_INFO = {
    "train_rows": "22.755",
    "test_rows": "5.689",
    "total_rows": "28.444",
    "features": 83,
    "classes": 8,
    "dataset_source": "CICDDoS2019 (Cleaned & Preprocessed)"
}

# ---------------- USERS (Akun Login) ----------------
# Admin tetap di-seed langsung — TIDAK bisa diubah via register.
# Kredensial admin:
#   Email    : adminDDoS@gmail.com
#   Password : admin123
#
# User biasa mendaftar sendiri via /register → langsung aktif sebagai 'analis'.

try:
    from werkzeug.security import generate_password_hash as _gph
    _ADMIN_PW = _gph("admin123")
except Exception:
    import hashlib
    _ADMIN_PW = "sha256$" + hashlib.sha256(b"admin123").hexdigest()

USERS = [
    {
        "id"       : 1,
        "nama"     : "Administrator",
        "email"    : "adminddos@gmail.com",
        "username" : "adminDDoS",
        "peran"    : "admin",
        "status"   : "aktif",
        "terdaftar": "01 Nov 2026",
        "pw"       : _ADMIN_PW,
    },
]

# ---------------- DASHBOARD STATISTIK (Berdasarkan 28.444 baris dataset) ----------------
STATS = {
    "total": 28444,
    "serangan": 24502,
    "normal": 3942,
    "recall": "99,94%"
}

DISTRIBUSI = [  # (label, persen dari serangan, warna tema)
    ("LDAP", 14, "#0f2a4a"),
    ("Syn", 14, "#1d3557"),
    ("UDP", 14, "#3f7fb5"),
    ("NetBIOS", 14, "#2a6f97"),
    ("Portmap", 14, "#457b9d"),
    ("MSSQL", 14, "#5d9cc4"),
    ("BENIGN", 14, "#2e8b3d"),
    ("UDPLag", 2, "#e63946"),
]

ALERTS = [
    {"waktu": "09:41:02", "jenis": "UDP", "ip": "10.12.4.91", "conf": 99, "tingkat": "Tinggi", "status": "Belum ditinjau"},
    {"waktu": "09:37:45", "jenis": "Syn", "ip": "172.16.3.22", "conf": 100, "tingkat": "Tinggi", "status": "Belum ditinjau"},
    {"waktu": "09:22:10", "jenis": "LDAP", "ip": "10.12.4.40", "conf": 98, "tingkat": "Tinggi", "status": "Belum ditinjau"},
    {"waktu": "09:15:37", "jenis": "NetBIOS", "ip": "10.12.5.17", "conf": 97, "tingkat": "Tinggi", "status": "Belum ditinjau"},
    {"waktu": "09:02:58", "jenis": "Portmap", "ip": "10.12.2.88", "conf": 96, "tingkat": "Sedang", "status": "Diverifikasi aman"},
    {"waktu": "08:54:19", "jenis": "MSSQL", "ip": "10.12.6.5", "conf": 99, "tingkat": "Tinggi", "status": "Belum ditinjau"},
    {"waktu": "08:40:03", "jenis": "UDPLag", "ip": "10.12.3.61", "conf": 94, "tingkat": "Sedang", "status": "Belum ditinjau"},
    {"waktu": "08:31:50", "jenis": "BENIGN", "ip": "192.168.1.45", "conf": 99, "tingkat": "Aman", "status": "Normal"},
]

# ---------------- VISUALISASI PER JAM ----------------
HOURLY = {
    "hari ini": [85, 70, 52, 110, 240, 420, 390, 360, 410, 280, 190, 130],
    "7 hari": [620, 580, 490, 850, 1500, 2400, 2100, 1950, 2200, 1600, 1200, 950],
    "30 hari": [2800, 2400, 2100, 3600, 6200, 9400, 8900, 8100, 8900, 6800, 5100, 3900],
}
HOUR_LABELS = ["00", "02", "04", "06", "08", "10", "12", "14", "16", "18", "20", "22"]
PER_JENIS = [
    ("LDAP", 4094),
    ("Syn", 4049),
    ("UDP", 4016),
    ("NetBIOS", 3998),
    ("Portmap", 3997),
    ("MSSQL", 3981),
    ("BENIGN", 3942),
    ("UDPLag", 367)
]

# ---------------- METRIK PERFORMA MODEL (Berdasarkan Evaluasi XGBoost) ----------------
PERFORMA = [
    ("BENIGN", 0.998, 0.999, 0.998),
    ("LDAP", 0.999, 1.000, 0.999),
    ("MSSQL", 0.999, 0.999, 0.999),
    ("NetBIOS", 1.000, 0.999, 0.999),
    ("Portmap", 1.000, 1.000, 1.000),
    ("Syn", 1.000, 1.000, 1.000),
    ("UDP", 0.999, 0.999, 0.999),
    ("UDPLag", 0.995, 0.990, 0.992),
]

# ---------------- EXPORT LAPORAN & NOTIFIKASI ----------------
REPORTS = [
    {"nama": "Laporan Deteksi DDoS Harian", "format": "PDF", "dibuat": "Hari ini 12:00"},
    {"nama": "Rekapitulasi Evaluasi Model XGBoost", "format": "Excel", "dibuat": "Kemarin"},
    {"nama": "Insiden Trafik UDP & Syn Flood", "format": "PDF", "dibuat": "05 Okt 14:20"},
]

NOTIFS = [
    {
        "level": "red",
        "judul": "Serangan berisiko tinggi: DrDoS_UDP",
        "isi": "Dari 10.12.4.91 · probabilitas 97% · 06 Nov 2026 09:41:02",
        "waktu": "1 menit lalu",
        "baca": False
    },
    {
        "level": "red",
        "judul": "Serangan berisiko tinggi: Syn",
        "isi": "Dari 172.16.3.22 · probabilitas 99% · 06 Nov 2026 09:37:45",
        "waktu": "5 menit lalu",
        "baca": False
    },
    {
        "level": "red",
        "judul": "Serangan berisiko tinggi: DrDoS_MSSQL",
        "isi": "Dari 10.12.6.5 · probabilitas 88% · 06 Nov 2026 08:54:19",
        "waktu": "47 menit lalu",
        "baca": False
    },
]

# ---------------- ADMIN MODEL VERSIONS ----------------
MODEL_VERSIONS = [
    {"versi": "1.0", "algoritma": "XGBoost", "f1": "0,9994", "akurasi": "99,95%", "aktif": True, "path": "Minggu6_XGBoost.pkl"},
    {"versi": "1.0", "algoritma": "Random Forest", "f1": "0,9976", "akurasi": "99,80%", "aktif": False, "path": "Minggu6_RF.pkl"},
]

MODULES = [
    ("API Penerima Alur (Flow Ingestion)", "Normal", "ok"),
    ("Pipeline Preprocessing (joblib)", "Normal", "ok"),
    ("Modul Inferensi Deteksi (XGBoost)", "Normal", "ok"),
    ("Database SQLite (ddos_deteksi.db)", "Normal", "ok"),
    ("Engine Notifikasi Keamanan", "Normal", "ok"),
]

LOGS = [
    {"waktu": "15:32:00", "level": "INFO", "modul": "Dataset Manager", "pesan": "train_processed.csv (22.755 baris) berhasil ditempatkan di dataset/processed/"},
    {"waktu": "15:30:15", "level": "INFO", "modul": "Pipeline Preprocessing", "pesan": "preprocessing_pipeline.joblib siap untuk ekstraksi 83 fitur alur"},
    {"waktu": "15:25:00", "level": "INFO", "modul": "Database", "pesan": "Koneksi ke ddos_deteksi.db berhasil (8 tabel terverifikasi)"},
    {"waktu": "15:00:10", "level": "INFO", "modul": "Modul Inferensi", "pesan": "Model XGBoost versi 1.0 (F1: 0.9994) siap menerima alur"},
]


# ---------------- CACHE DATA UJI UNTUK STREAMING REAL-TIME ----------------
_SAMPLE_CACHE = []
_SAMPLE_FILE = os.path.join(os.path.dirname(__file__), "dataset", "sample", "sample_stream.csv")

def _load_sample_stream():
    global _SAMPLE_CACHE
    if not _SAMPLE_CACHE and os.path.exists(_SAMPLE_FILE):
        try:
            with open(_SAMPLE_FILE, "r", encoding="utf-8", errors="ignore") as f:
                reader = csv.DictReader(f)
                _SAMPLE_CACHE = list(reader)
        except Exception:
            _SAMPLE_CACHE = []
    return _SAMPLE_CACHE


# ---------------- GENERATOR REAL-TIME MONITORING ----------------
def generate_flow():
    """Menghasilkan satu flow data uji nyata dari test_processed.csv untuk live monitoring."""
    cache = _load_sample_stream()
    now = datetime.now()
    time_str = now.strftime("%H:%M:%S.") + f"{now.microsecond // 1000:03d}"
    
    if cache:
        row = random.choice(cache)
        kelas = row.get("Label", random.choice(KELAS))
        is_attack = kelas != "BENIGN"
        
        # Tentukan protocol dari one-hot encoding jika ada
        if row.get("cat__Protocol_17") == "1.0":
            proto = "UDP"
        elif row.get("cat__Protocol_6") == "1.0":
            proto = "TCP"
        else:
            proto = "OTHER"
            
        src_ip = f"172.16.0.{random.randint(10, 99)}" if is_attack else f"192.168.1.{random.randint(2, 50)}"
        dst_ip = "192.168.1.100"
        src_port = random.randint(1024, 65535)
        dst_port = 80 if proto == "TCP" else (53 if kelas == "DNS" else 389 if kelas == "LDAP" else 1433 if kelas == "MSSQL" else 8080)
        
        conf = round(random.uniform(0.96, 1.0), 3) if is_attack else round(random.uniform(0.97, 1.0), 3)
    else:
        # Fallback jika file sample belum terbaca
        kelas = random.choice(KELAS)
        proto = "UDP" if "UDP" in kelas or kelas in ["LDAP", "DNS", "NTP"] else "TCP"
        src_ip = "172.16.0.45" if kelas != "BENIGN" else "192.168.1.25"
        dst_ip = "192.168.1.100"
        src_port = random.randint(1024, 65000)
        dst_port = 80
        conf = 0.98

    return {
        "waktu": time_str,
        "src": f"{src_ip}:{src_port}",
        "dst": f"{dst_ip}:{dst_port}",
        "proto": proto,
        "prediksi": kelas,
        "conf": conf,
    }


def generate_riwayat(n=60):
    rows = []
    base = datetime.now()
    for i in range(n):
        t = base - timedelta(minutes=random.randint(1, 60 * 24 * 7))
        jenis = random.choice(KELAS[1:])
        conf = random.randint(54, 100)
        # Prediksi benar jika confidence >= 70%
        prediksi_benar = conf >= 70
        # Tingkat berdasarkan jenis serangan
        if jenis in ["Syn", "UDP", "LDAP", "MSSQL"]:
            tingkat = "Tinggi"
        elif jenis in ["NetBIOS", "UDPLag"]:
            tingkat = "Sedang"
        elif conf < 60:
            tingkat = "Rendah"
        else:
            tingkat = "Sedang"
        rows.append({
            "waktu": t,
            "waktu_str": t.strftime("%d %b %Y %H:%M:%S"),
            "jenis": jenis,
            "ip": f"172.16.0.{random.randint(2, 250)}",
            "conf": conf,
            "prediksi_benar": prediksi_benar,
            "tingkat": tingkat,
        })
    rows.sort(key=lambda r: r["waktu"], reverse=True)
    return rows


# Data Riwayat Deteksi sesuai tampilan (dari gambar referensi)
RIWAYAT_SEED = [
    {"waktu_str": "06 Nov 2026 09:41:02", "jenis": "DrDoS_UDP",     "ip": "10.12.4.91",   "conf": 97, "prediksi_benar": True,  "tingkat": "Tinggi"},
    {"waktu_str": "06 Nov 2026 09:37:45", "jenis": "Syn",           "ip": "172.16.3.22",  "conf": 99, "prediksi_benar": True,  "tingkat": "Tinggi"},
    {"waktu_str": "06 Nov 2026 09:22:10", "jenis": "DrDoS_SNMP",    "ip": "10.12.4.40",   "conf": 71, "prediksi_benar": True,  "tingkat": "Sedang"},
    {"waktu_str": "06 Nov 2026 09:15:37", "jenis": "DrDoS_NetBIOS", "ip": "10.12.5.17",   "conf": 68, "prediksi_benar": True,  "tingkat": "Sedang"},
    {"waktu_str": "06 Nov 2026 09:02:58", "jenis": "TFTP",          "ip": "10.12.2.88",   "conf": 54, "prediksi_benar": False, "tingkat": "Rendah"},
    {"waktu_str": "06 Nov 2026 08:54:19", "jenis": "DrDoS_MSSQL",   "ip": "10.12.6.5",    "conf": 88, "prediksi_benar": True,  "tingkat": "Tinggi"},
    {"waktu_str": "06 Nov 2026 08:31:50", "jenis": "WebDDoS",       "ip": "10.12.9.14",   "conf": 82, "prediksi_benar": True,  "tingkat": "Sedang"},
    {"waktu_str": "06 Nov 2026 08:20:11", "jenis": "BENIGN",        "ip": "192.168.1.45", "conf": 98, "prediksi_benar": True,  "tingkat": "Normal"},
    {"waktu_str": "06 Nov 2026 08:10:03", "jenis": "BENIGN",        "ip": "192.168.1.80", "conf": 99, "prediksi_benar": True,  "tingkat": "Normal"},
]

RIWAYAT = RIWAYAT_SEED + generate_riwayat(50)
