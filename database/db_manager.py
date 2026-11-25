"""Modul Manajemen Database SQLite (ddos_deteksi.db).
Menangani koneksi dan query untuk:
- Pengguna (admin, user)
- Model ML (model_ml)
- Jenis serangan (jenis_serangan)
- Alur jaringan (alur_jaringan)
- Hasil deteksi (hasil_deteksi)
- Sesi audit (sesi_masuk)
"""
import sqlite3
import os
import sys
import hashlib

# Tambahkan direktori root proyek ke sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from config import Config


def get_db_connection():
    """Membuka koneksi ke database SQLite ddos_deteksi.db."""
    conn = sqlite3.connect(Config.DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def get_all_attack_types():
    """Mengambil semua jenis serangan dari tabel jenis_serangan."""
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT id_jenis, nama_serangan, kategori, deskripsi FROM jenis_serangan")
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    return rows


def get_ml_models():
    """Mengambil daftar model ML beserta metrik evaluasinya."""
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT id_model, nama_model, versi, akurasi, presisi, recall, f1_score, path_file_model, keterangan FROM model_ml")
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    return rows


def get_users():
    """Mengambil semua data pengguna."""
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT id_pengguna AS id, nama_lengkap AS nama, email, peran, (CASE WHEN aktif=1 THEN 'aktif' ELSE 'nonaktif' END) AS status, dibuat_pada AS terdaftar, kata_sandi AS pw FROM pengguna")
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    return rows


def add_user(nama: str, email: str, password_hash: str, peran: str = None, aktif: int = 1):
    """Menambahkan pengguna baru ke tabel pengguna SQLite."""
    conn = get_db_connection()
    c = conn.cursor()
    username = email.split("@")[0]
    c.execute("""
        INSERT INTO pengguna (nama_lengkap, username, email, kata_sandi, peran, aktif)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (nama, username, email, password_hash, peran, aktif))
    new_id = c.lastrowid
    conn.commit()
    conn.close()
    return new_id


def verify_user(username: str, password_plain: str):
    """Verifikasi login pengguna menggunakan SHA256 hash."""
    hashed = hashlib.sha256(password_plain.encode("utf-8")).hexdigest()
    conn = get_db_connection()
    c = conn.cursor()
    c.execute(
        "SELECT id_pengguna, nama_lengkap, username, peran, email, aktif FROM pengguna WHERE username = ? AND kata_sandi = ?",
        (username, hashed)
    )
    user = c.fetchone()
    conn.close()
    return dict(user) if user else None


def log_detection(id_model: int, label_prediksi: str, label_aktual: str = None, probabilitas: float = 1.0, benar: int = 1):
    """Menyimpan hasil prediksi ke tabel hasil_deteksi."""
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("""
        INSERT INTO hasil_deteksi (id_model, label_prediksi, label_aktual, probabilitas, benar)
        VALUES (?, ?, ?, ?, ?)
    """, (id_model, label_prediksi, label_aktual, probabilitas, benar))
    conn.commit()
    conn.close()


def get_recent_detections(limit: int = 50):
    """Mengambil riwayat deteksi terbaru."""
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("""
        SELECT h.id_deteksi, m.nama_model, h.label_prediksi, h.label_aktual, h.probabilitas, h.waktu_deteksi
        FROM hasil_deteksi h
        LEFT JOIN model_ml m ON h.id_model = m.id_model
        ORDER BY h.id_deteksi DESC
        LIMIT ?
    """, (limit,))
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    return rows


if __name__ == "__main__":
    print("[INFO] Memeriksa koneksi database ddos_deteksi.db...")
    models = get_ml_models()
    print(f"[INFO] Terdeteksi {len(models)} model ML:")
    for m in models:
        print(f"  - {m['nama_model']} v{m['versi']} (F1: {m['f1_score']}) -> File: {m['path_file_model']}")
    
    users = get_users()
    print(f"[INFO] Terdeteksi {len(users)} pengguna terdaftar:")
    for u in users:
        print(f"  - {u['username']} ({u['nama_lengkap']}) - Peran: {u['peran']}")
