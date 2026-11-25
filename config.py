import os

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "ddos-shield-secret-key-2026")
    
    # Path Database SQLite (Proyek Kelompok 2 - KSI5B)
    DATABASE_PATH = os.path.join(BASE_DIR, "database", "ddos_deteksi.db")
    
    # Path Model & Pipeline Preprocessing
    PIPELINE_PATH = os.path.join(BASE_DIR, "models", "preprocessing_pipeline.joblib")
    MODEL_XGBOOST_PATH = os.path.join(BASE_DIR, "models", "Minggu6_XGBoost.pkl")
    MODEL_RF_PATH = os.path.join(BASE_DIR, "models", "Minggu6_RF.pkl")
    
    # Default model aktif
    MODEL_PATH = MODEL_XGBOOST_PATH
    
    # Path Dataset
    DATASET_DIR = os.path.join(BASE_DIR, "dataset")
    
    # Daftar 12 Kelas Serangan Resmi dari Database jenis_serangan (CICDDoS2019)
    KELAS_SERANGAN = [
        "BENIGN", "Syn", "UDP", "DNS", "SNMP", "NetBIOS",
        "Portmap", "NTP", "LDAP", "MSSQL", "TFTP", "WebDDoS"
    ]
    
    # Threshold default untuk alert (persen)
    DEFAULT_ALERT_THRESHOLD = 70

