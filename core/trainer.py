"""Skrip Pelatihan Model Deteksi DDoS (Machine Learning Trainer).
Membaca dataset CSV (misal: CIC-DDoS2019), melakukan preprocessing,
melatih classifier (Random Forest / XGBoost), dan mengekspor model ke models/.
"""
import os
import sys

# Tambahkan direktori root proyek ke sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
import joblib
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score
from config import Config


def train_model(csv_path: str, target_column: str = "Label"):
    print(f"[INFO] Membaca dataset dari: {csv_path}")
    if not os.path.exists(csv_path):
        print(f"[ERROR] File dataset {csv_path} tidak ditemukan!")
        return False

    df = pd.read_csv(csv_path)
    df.columns = df.columns.str.strip()
    
    # Preprocessing dasar
    df = df.replace([float('inf'), float('-inf')], None).dropna()
    
    X = df.drop(columns=[target_column], errors="ignore")
    # Hanya ambil kolom numerik
    X = X.select_dtypes(include=["float64", "int64"])
    y = df[target_column]

    print(f"[INFO] Ukuran dataset: {X.shape[0]} baris, {X.shape[1]} fitur")
    
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    print("[INFO] Melakukan feature scaling...")
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    print("[INFO] Melatih model Random Forest...")
    clf = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
    clf.fit(X_train_scaled, y_train)

    print("[INFO] Evaluasi model pada test set...")
    y_pred = clf.predict(X_test_scaled)
    acc = accuracy_score(y_test, y_pred)
    print(f"[INFO] Akurasi: {acc * 100:.2f}%")
    print(classification_report(y_test, y_pred))

    # Simpan model dan scaler
    os.makedirs(os.path.dirname(Config.MODEL_PATH), exist_ok=True)
    joblib.dump(clf, Config.MODEL_PATH)
    joblib.dump(scaler, Config.SCALER_PATH)
    print(f"[SUCCESS] Model disimpan ke: {Config.MODEL_PATH}")
    print(f"[SUCCESS] Scaler disimpan ke: {Config.SCALER_PATH}")
    return True


if __name__ == "__main__":
    sample_dataset = os.path.join(Config.DATASET_DIR, "sample", "sample_ddos.csv")
    train_model(sample_dataset)
