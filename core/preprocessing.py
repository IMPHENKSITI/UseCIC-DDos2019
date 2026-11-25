"""Modul Preprocessing Data Trafik Jaringan.
Digunakan untuk membersihkan, menangani nilai infinity / null,
dan menstandarisasi fitur numerik sebelum diinput ke model Machine Learning.
"""
import numpy as np
import pandas as pd


def clean_network_data(df: pd.DataFrame) -> pd.DataFrame:
    """Membersihkan DataFrame dari spasi nama kolom, inf, dan NaN."""
    # Hilangkan leading/trailing whitespace pada kolom (sering terjadi pada dataset CIC-DDoS)
    df.columns = df.columns.str.strip()
    
    # Ganti infinity dengan NaN lalu bersihkan
    df = df.replace([np.inf, -np.inf], np.nan)
    df = df.dropna()
    
    return df


def extract_features(df: pd.DataFrame, feature_columns: list) -> pd.DataFrame:
    """Mengambil hanya kolom-kolom fitur yang digunakan saat pelatihan model."""
    available_cols = [col for col in feature_columns if col in df.columns]
    return df[available_cols]


def scale_features(features: np.ndarray, scaler) -> np.ndarray:
    """Melakukan scaling fitur menggunakan scaler yang sudah di-load (StandardScaler / MinMaxScaler)."""
    if scaler is not None:
        return scaler.transform(features)
    return features

