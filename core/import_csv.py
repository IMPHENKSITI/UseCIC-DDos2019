"""Skrip Import Dataset CSV ke Database SQLite (ddos_deteksi.db).
Dapat mengimpor file CSV (seperti dataset CICDDoS2019) ke dalam tabel alur_jaringan.
"""
import os
import sys
import sqlite3
import pandas as pd

# Tambahkan path root
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from config import Config


# Pemetaan nama kolom CIC-DDoS2019 (English) ke nama kolom alur_jaringan (Bahasa Indonesia)
COLUMN_MAPPING = {
    "Flow ID": "flow_id",
    "Source IP": "ip_sumber",
    "Source Port": "port_sumber",
    "Destination IP": "ip_tujuan",
    "Destination Port": "port_tujuan",
    "Protocol": "protokol",
    "Timestamp": "timestamp_alur",
    "Flow Duration": "durasi_alur",
    "Total Fwd Packets": "total_paket_maju",
    "Total Backward Packets": "total_paket_mundur",
    "Total Length of Fwd Packets": "total_panjang_paket_maju",
    "Total Length of Bwd Packets": "total_panjang_paket_mundur",
    "Fwd Packet Length Max": "panjang_paket_maju_maks",
    "Fwd Packet Length Min": "panjang_paket_maju_min",
    "Fwd Packet Length Mean": "panjang_paket_maju_rerata",
    "Fwd Packet Length Std": "panjang_paket_maju_std",
    "Bwd Packet Length Max": "panjang_paket_mundur_maks",
    "Bwd Packet Length Min": "panjang_paket_mundur_min",
    "Bwd Packet Length Mean": "panjang_paket_mundur_rerata",
    "Bwd Packet Length Std": "panjang_paket_mundur_std",
    "Flow Bytes/s": "byte_per_detik",
    "Flow Packets/s": "paket_per_detik",
    "Flow IAT Mean": "iat_alur_rerata",
    "Flow IAT Std": "iat_alur_std",
    "Flow IAT Max": "iat_alur_maks",
    "Flow IAT Min": "iat_alur_min",
    "Fwd IAT Total": "iat_maju_total",
    "Fwd IAT Mean": "iat_maju_rerata",
    "Fwd IAT Std": "iat_maju_std",
    "Fwd IAT Max": "iat_maju_maks",
    "Fwd IAT Min": "iat_maju_min",
    "Bwd IAT Total": "iat_mundur_total",
    "Bwd IAT Mean": "iat_mundur_rerata",
    "Bwd IAT Std": "iat_mundur_std",
    "Bwd IAT Max": "iat_mundur_maks",
    "Bwd IAT Min": "iat_mundur_min",
    "Fwd PSH Flags": "flag_psh_maju",
    "Bwd PSH Flags": "flag_psh_mundur",
    "Fwd URG Flags": "flag_urg_maju",
    "Bwd URG Flags": "flag_urg_mundur",
    "Fwd Header Length": "panjang_header_maju",
    "Bwd Header Length": "panjang_header_mundur",
    "Fwd Packets/s": "paket_per_detik_maju",
    "Bwd Packets/s": "paket_per_detik_mundur",
    "Min Packet Length": "panjang_paket_min",
    "Max Packet Length": "panjang_paket_maks",
    "Packet Length Mean": "panjang_paket_rerata",
    "Packet Length Std": "panjang_paket_std",
    "Packet Length Variance": "panjang_paket_varian",
    "FIN Flag Count": "jumlah_flag_fin",
    "SYN Flag Count": "jumlah_flag_syn",
    "RST Flag Count": "jumlah_flag_rst",
    "PSH Flag Count": "jumlah_flag_psh",
    "ACK Flag Count": "jumlah_flag_ack",
    "URG Flag Count": "jumlah_flag_urg",
    "CWE Flag Count": "jumlah_flag_cwe",
    "ECE Flag Count": "jumlah_flag_ece",
    "Down/Up Ratio": "rasio_unduh_unggah",
    "Average Packet Size": "ukuran_paket_rerata",
    "Avg Fwd Segment Size": "ukuran_segmen_maju_rerata",
    "Avg Bwd Segment Size": "ukuran_segmen_mundur_rerata",
    "Fwd Avg Bytes/Bulk": "rerata_byte_bulk_maju",
    "Fwd Avg Packets/Bulk": "rerata_paket_bulk_maju",
    "Fwd Avg Bulk Rate": "rerata_laju_bulk_maju",
    "Bwd Avg Bytes/Bulk": "rerata_byte_bulk_mundur",
    "Bwd Avg Packets/Bulk": "rerata_paket_bulk_mundur",
    "Bwd Avg Bulk Rate": "rerata_laju_bulk_mundur",
    "Subflow Fwd Packets": "paket_subflow_maju",
    "Subflow Fwd Bytes": "byte_subflow_maju",
    "Subflow Bwd Packets": "paket_subflow_mundur",
    "Subflow Bwd Bytes": "byte_subflow_mundur",
    "Init_Win_bytes_forward": "byte_window_awal_maju",
    "Init_Win_bytes_backward": "byte_window_awal_mundur",
    "act_data_pkt_fwd": "paket_data_aktif_maju",
    "min_seg_size_forward": "ukuran_min_segmen_maju",
    "Active Mean": "aktif_rerata",
    "Active Std": "aktif_std",
    "Active Max": "aktif_maks",
    "Active Min": "aktif_min",
    "Idle Mean": "idle_rerata",
    "Idle Std": "idle_std",
    "Idle Max": "idle_maks",
    "Idle Min": "idle_min",
    "SimilarHTTP": "similar_http",
}


def import_csv_to_db(csv_file_path: str, max_rows: int = 5000):
    """Membaca file CSV dan memasukkannya ke tabel alur_jaringan di ddos_deteksi.db."""
    if not os.path.exists(csv_file_path):
        print(f"[ERROR] File {csv_file_path} tidak ditemukan!")
        return False

    print(f"[INFO] Membaca file CSV: {csv_file_path} (maksimal {max_rows} baris)...")
    try:
        df = pd.read_csv(csv_file_path, nrows=max_rows)
    except Exception as e:
        print(f"[ERROR] Gagal membaca CSV: {e}")
        return False

    df.columns = df.columns.str.strip()
    
    # Rename kolom dari format CIC-DDoS2019 ke format tabel alur_jaringan
    df = df.rename(columns=COLUMN_MAPPING)

    conn = sqlite3.connect(Config.DATABASE_PATH)
    cursor = conn.cursor()

    # Dapatkan kolom yang ada pada tabel alur_jaringan
    cursor.execute("PRAGMA table_info(alur_jaringan)")
    table_cols = [c[1] for c in cursor.fetchall() if c[1] not in ["id_alur", "dibuat_pada"]]

    # Ambil hanya kolom yang cocok
    valid_cols = [c for c in table_cols if c in df.columns]
    df_to_insert = df[valid_cols].copy()

    # Bersihkan NaN dan Inf
    df_to_insert = df_to_insert.replace([float("inf"), float("-inf")], None).fillna(0)

    print(f"[INFO] Menemukan {len(valid_cols)} kolom yang cocok dari 89 kolom tabel alur_jaringan.")
    print(f"[INFO] Memasukkan {len(df_to_insert)} baris ke tabel alur_jaringan...")

    df_to_insert.to_sql("alur_jaringan", conn, if_exists="append", index=False)
    conn.commit()
    conn.close()

    print(f"[SUCCESS] Berhasil mengimpor {len(df_to_insert)} baris ke tabel alur_jaringan!")
    return True


if __name__ == "__main__":
    # Contoh pemanggilan: python core/import_csv.py dataset/sample/sample_traffic.csv
    if len(sys.argv) > 1:
        target_csv = sys.argv[1]
    else:
        target_csv = os.path.join(Config.DATASET_DIR, "sample", "sample.csv")
    import_csv_to_db(target_csv)

