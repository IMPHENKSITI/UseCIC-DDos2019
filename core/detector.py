"""Modul Detektor DDoS (Inference Engine).
Memuat Pipeline Preprocessing (preprocessing_pipeline.joblib)
serta Model Machine Learning (Minggu6_XGBoost.pkl / Minggu6_RF.pkl)
untuk mendeteksi dan mengklasifikasikan trafik jaringan secara real-time.
"""
import os
import sys

# Tambahkan direktori root proyek ke sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
try:
    import joblib
    import numpy as np
    JOBLIB_AVAILABLE = True
except ImportError:
    joblib = None
    np = None
    JOBLIB_AVAILABLE = False

from config import Config


class DDoSDetector:
    def __init__(self, model_path=Config.MODEL_XGBOOST_PATH, pipeline_path=Config.PIPELINE_PATH):
        self.model_path = model_path
        self.pipeline_path = pipeline_path
        self.model = None
        self.pipeline = None
        self.is_loaded = False
        self.load_model_and_pipeline()

    def load_model_and_pipeline(self):
        """Memuat pipeline preprocessing dan model klasifikasi."""
        if not JOBLIB_AVAILABLE:
            print("[WARNING] Library 'joblib' atau 'numpy' belum terpasang. Jalankan: pip install -r requirements.txt")
            self.is_loaded = False
            return
        try:
            # 1. Muat Pipeline Preprocessing
            if os.path.exists(self.pipeline_path):
                self.pipeline = joblib.load(self.pipeline_path)
                print(f"[INFO] Preprocessing pipeline dimuat: {self.pipeline_path}")
            else:
                print(f"[WARNING] Pipeline preprocessing belum ditemukan di {self.pipeline_path}")

            # 2. Muat Model ML (XGBoost atau Random Forest)
            if os.path.exists(self.model_path):
                self.model = joblib.load(self.model_path)
                print(f"[INFO] Model ML berhasil dimuat: {self.model_path}")
                self.is_loaded = True
            elif os.path.exists(Config.MODEL_RF_PATH):
                self.model = joblib.load(Config.MODEL_RF_PATH)
                print(f"[INFO] Menggunakan model alternatif: {Config.MODEL_RF_PATH}")
                self.is_loaded = True
            else:
                print(f"[WARNING] File model ({os.path.basename(self.model_path)}) belum ditemukan di folder models/.")
                self.is_loaded = False
        except Exception as e:
            print(f"[ERROR] Gagal memuat model/pipeline: {e}")
            self.is_loaded = False

    def predict_flow(self, flow_data) -> dict:
        """Memprediksi satu rekaman alur jaringan (bisa berupa dict, array, atau DataFrame)."""
        if not self.is_loaded or self.model is None:
            # Fallback simulasi jika model .pkl belum di-upload/di-train
            return {
                "prediksi": "BENIGN",
                "conf": 0.95,
                "is_attack": False,
                "tingkat": "Aman",
                "mode": "simulation"
            }

        try:
            # Transformasi fitur menggunakan pipeline preprocessing
            if self.pipeline is not None:
                transformed_data = self.pipeline.transform(flow_data)
            else:
                transformed_data = flow_data

            # Prediksi label
            pred = self.model.predict(transformed_data)[0]

            # Hitung confidence jika model mendukung predict_proba
            conf = 1.0
            if hasattr(self.model, "predict_proba"):
                probs = self.model.predict_proba(transformed_data)[0]
                conf = float(np.max(probs))

            label_str = str(pred)
            is_attack = label_str.upper() != "BENIGN"

            # Tentukan tingkat ancaman
            if is_attack:
                if conf >= 0.85:
                    tingkat = "Tinggi"
                elif conf >= 0.65:
                    tingkat = "Sedang"
                else:
                    tingkat = "Rendah"
            else:
                tingkat = "Aman"

            return {
                "prediksi": label_str,
                "conf": round(conf, 4),
                "is_attack": is_attack,
                "tingkat": tingkat,
                "mode": "real_ml_model"
            }
        except Exception as e:
            return {
                "prediksi": "ERROR",
                "conf": 0.0,
                "is_attack": False,
                "tingkat": "Unknown",
                "error": str(e)
            }


if __name__ == "__main__":
    detector = DDoSDetector()
    print("[INFO] Status detektor aktif:", detector.is_loaded)
