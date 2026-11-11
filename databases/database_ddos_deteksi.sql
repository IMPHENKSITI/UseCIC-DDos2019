-- ============================================================
-- DATABASE: ddos_deteksi
-- Proyek  : Deteksi Serangan DDoS dengan Machine Learning
--           Berbasis Dataset CICDDoS2019
-- Kelompok: 2 - KSI5B
-- ============================================================

CREATE DATABASE IF NOT EXISTS ddos_deteksi
    CHARACTER SET utf8mb4
    COLLATE utf8mb4_unicode_ci;

USE ddos_deteksi;

-- ============================================================
-- Tabel: jenis_serangan
-- ============================================================
CREATE TABLE IF NOT EXISTS jenis_serangan (
    id_jenis       INT            AUTO_INCREMENT PRIMARY KEY,
    nama_serangan  VARCHAR(50)    NOT NULL UNIQUE COMMENT 'Contoh: NetBIOS, MSSQL, UDP, Syn, BENIGN',
    kategori       ENUM('DDoS','Normal') NOT NULL DEFAULT 'DDoS',
    deskripsi      TEXT,
    dibuat_pada    DATETIME       DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB COMMENT='Daftar jenis serangan DDoS dan lalu lintas normal';

-- ============================================================
-- Tabel: sumber_dataset
-- ============================================================
CREATE TABLE IF NOT EXISTS sumber_dataset (
    id_sumber       INT          AUTO_INCREMENT PRIMARY KEY,
    nama_dataset    VARCHAR(100) NOT NULL COMMENT 'Contoh: CICDDoS2019',
    versi           VARCHAR(20),
    tanggal_capture DATE         COMMENT 'Tanggal pengambilan data traffic',
    total_sampel    INT,
    keterangan      TEXT,
    dibuat_pada     DATETIME     DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB COMMENT='Metadata sumber dataset jaringan';

-- ============================================================
-- Tabel: alur_jaringan (tabel fitur utama)
-- ============================================================
CREATE TABLE IF NOT EXISTS alur_jaringan (
    id_alur                     BIGINT         AUTO_INCREMENT PRIMARY KEY,
    id_sumber                   INT            REFERENCES sumber_dataset(id_sumber),
    id_jenis                    INT            REFERENCES jenis_serangan(id_jenis),

    -- Identitas alur
    flow_id                     VARCHAR(100),
    ip_sumber                   VARCHAR(45),
    port_sumber                 INT,
    ip_tujuan                   VARCHAR(45),
    port_tujuan                 INT,
    protokol                    TINYINT        COMMENT '0=Other, 6=TCP, 17=UDP',
    timestamp_alur              DATETIME,
    arah_masuk                  TINYINT(1)     DEFAULT 0 COMMENT '0=Keluar, 1=Masuk',

    -- Durasi & Paket
    durasi_alur                 DOUBLE,
    total_paket_maju            INT,
    total_paket_mundur          INT,
    total_panjang_paket_maju    DOUBLE,
    total_panjang_paket_mundur  DOUBLE,

    -- Panjang Paket Maju
    panjang_paket_maju_maks     DOUBLE,
    panjang_paket_maju_min      DOUBLE,
    panjang_paket_maju_rerata   DOUBLE,
    panjang_paket_maju_std      DOUBLE,

    -- Panjang Paket Mundur
    panjang_paket_mundur_maks   DOUBLE,
    panjang_paket_mundur_min    DOUBLE,
    panjang_paket_mundur_rerata DOUBLE,
    panjang_paket_mundur_std    DOUBLE,

    -- Statistik Alur
    byte_per_detik              DOUBLE,
    paket_per_detik             DOUBLE,

    -- IAT (Inter-Arrival Time)
    iat_alur_rerata             DOUBLE,
    iat_alur_std                DOUBLE,
    iat_alur_maks               DOUBLE,
    iat_alur_min                DOUBLE,

    iat_maju_total              DOUBLE,
    iat_maju_rerata             DOUBLE,
    iat_maju_std                DOUBLE,
    iat_maju_maks               DOUBLE,
    iat_maju_min                DOUBLE,

    iat_mundur_total            DOUBLE,
    iat_mundur_rerata           DOUBLE,
    iat_mundur_std              DOUBLE,
    iat_mundur_maks             DOUBLE,
    iat_mundur_min              DOUBLE,

    -- Flag Paket
    flag_psh_maju               TINYINT(1)     DEFAULT 0,
    flag_psh_mundur             TINYINT(1)     DEFAULT 0,
    flag_urg_maju               TINYINT(1)     DEFAULT 0,
    flag_urg_mundur             TINYINT(1)     DEFAULT 0,

    -- Header
    panjang_header_maju         DOUBLE,
    panjang_header_mundur       DOUBLE,

    -- Kecepatan
    paket_per_detik_maju        DOUBLE,
    paket_per_detik_mundur      DOUBLE,

    -- Statistik Panjang Paket
    panjang_paket_min           DOUBLE,
    panjang_paket_maks          DOUBLE,
    panjang_paket_rerata        DOUBLE,
    panjang_paket_std           DOUBLE,
    panjang_paket_varian        DOUBLE,

    -- Flag TCP
    jumlah_flag_fin             TINYINT        DEFAULT 0,
    jumlah_flag_syn             TINYINT        DEFAULT 0,
    jumlah_flag_rst             TINYINT        DEFAULT 0,
    jumlah_flag_psh             TINYINT        DEFAULT 0,
    jumlah_flag_ack             TINYINT        DEFAULT 0,
    jumlah_flag_urg             TINYINT        DEFAULT 0,
    jumlah_flag_cwe             TINYINT        DEFAULT 0,
    jumlah_flag_ece             TINYINT        DEFAULT 0,

    -- Rasio & Rata-rata
    rasio_unduh_unggah          DOUBLE,
    ukuran_paket_rerata         DOUBLE,
    ukuran_segmen_maju_rerata   DOUBLE,
    ukuran_segmen_mundur_rerata DOUBLE,

    -- Bulk
    rerata_byte_bulk_maju       DOUBLE         DEFAULT 0,
    rerata_paket_bulk_maju      DOUBLE         DEFAULT 0,
    rerata_laju_bulk_maju       DOUBLE         DEFAULT 0,
    rerata_byte_bulk_mundur     DOUBLE         DEFAULT 0,
    rerata_paket_bulk_mundur    DOUBLE         DEFAULT 0,
    rerata_laju_bulk_mundur     DOUBLE         DEFAULT 0,

    -- Subflow
    paket_subflow_maju          INT,
    byte_subflow_maju           DOUBLE,
    paket_subflow_mundur        INT,
    byte_subflow_mundur         DOUBLE,

    -- Inisialisasi Window
    byte_window_awal_maju       INT,
    byte_window_awal_mundur     INT,

    -- Lain-lain
    paket_data_aktif_maju       INT,
    ukuran_min_segmen_maju      INT,

    -- Active / Idle
    aktif_rerata                DOUBLE         DEFAULT 0,
    aktif_std                   DOUBLE         DEFAULT 0,
    aktif_maks                  DOUBLE         DEFAULT 0,
    aktif_min                   DOUBLE         DEFAULT 0,
    idle_rerata                 DOUBLE         DEFAULT 0,
    idle_std                    DOUBLE         DEFAULT 0,
    idle_maks                   DOUBLE         DEFAULT 0,
    idle_min                    DOUBLE         DEFAULT 0,

    -- Khusus CICDDoS2019
    similar_http                TINYINT(1)     DEFAULT 0,

    dibuat_pada                 DATETIME       DEFAULT CURRENT_TIMESTAMP,

    INDEX idx_alur_jenis   (id_jenis),
    INDEX idx_alur_sumber  (id_sumber),
    INDEX idx_alur_proto   (protokol),
    INDEX idx_alur_ts      (timestamp_alur)
) ENGINE=InnoDB COMMENT='Data alur jaringan CICDDoS2019 beserta fitur-fiturnya';

-- ============================================================
-- Tabel: model_ml
-- ============================================================
CREATE TABLE IF NOT EXISTS model_ml (
    id_model        INT          AUTO_INCREMENT PRIMARY KEY,
    nama_model      VARCHAR(100) NOT NULL COMMENT 'XGBoost, Random Forest, dsb',
    versi           VARCHAR(20),
    akurasi         DOUBLE,
    presisi         DOUBLE,
    recall          DOUBLE,
    f1_score        DOUBLE,
    roc_auc         DOUBLE,
    tanggal_latih   DATETIME,
    path_file_model VARCHAR(255),
    keterangan      TEXT,
    dibuat_pada     DATETIME     DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB COMMENT='Model Machine Learning untuk deteksi DDoS';

-- ============================================================
-- Tabel: sesi_latih
-- ============================================================
CREATE TABLE IF NOT EXISTS sesi_latih (
    id_sesi           INT          AUTO_INCREMENT PRIMARY KEY,
    id_model          INT          REFERENCES model_ml(id_model),
    id_sumber         INT          REFERENCES sumber_dataset(id_sumber),
    jumlah_data_latih INT,
    jumlah_data_uji   INT,
    rasio_split       DOUBLE       DEFAULT 0.2,
    metode_sampling   VARCHAR(50)  COMMENT 'SMOTE, random, dsb',
    parameter_model   JSON         COMMENT 'Hyperparameter model dalam format JSON',
    catatan           TEXT,
    mulai_pada        DATETIME,
    selesai_pada      DATETIME,
    dibuat_pada       DATETIME     DEFAULT CURRENT_TIMESTAMP,

    INDEX idx_sesi_model  (id_model),
    INDEX idx_sesi_sumber (id_sumber)
) ENGINE=InnoDB COMMENT='Riwayat sesi pelatihan model ML';

-- ============================================================
-- Tabel: hasil_deteksi
-- ============================================================
CREATE TABLE IF NOT EXISTS hasil_deteksi (
    id_deteksi      BIGINT       AUTO_INCREMENT PRIMARY KEY,
    id_model        INT          REFERENCES model_ml(id_model),
    id_alur         BIGINT       REFERENCES alur_jaringan(id_alur),
    label_prediksi  VARCHAR(50)  NOT NULL,
    label_aktual    VARCHAR(50),
    probabilitas    DOUBLE,
    benar           TINYINT(1)   COMMENT '1=prediksi benar, 0=prediksi salah',
    waktu_deteksi   DATETIME     DEFAULT CURRENT_TIMESTAMP,

    INDEX idx_deteksi_model (id_model),
    INDEX idx_deteksi_alur  (id_alur),
    INDEX idx_deteksi_label (label_prediksi)
) ENGINE=InnoDB COMMENT='Hasil prediksi/deteksi model ML terhadap alur jaringan';

-- ============================================================
-- Tabel: pengguna (admin, analis, user)
-- ============================================================
CREATE TABLE IF NOT EXISTS pengguna (
    id_pengguna     INT          AUTO_INCREMENT PRIMARY KEY,
    nama_lengkap    VARCHAR(150) NOT NULL,
    username        VARCHAR(50)  NOT NULL UNIQUE,
    kata_sandi      VARCHAR(255) NOT NULL COMMENT 'Hash bcrypt/sha256, JANGAN simpan plain text',
    peran           ENUM('admin','user') NOT NULL DEFAULT 'user'
                    COMMENT 'admin=akses penuh, user=hanya lihat hasil deteksi',
    email           VARCHAR(100) UNIQUE,
    aktif           TINYINT(1)   DEFAULT 1,
    terakhir_masuk  DATETIME,
    dibuat_pada     DATETIME     DEFAULT CURRENT_TIMESTAMP,
    diperbarui_pada DATETIME     DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

    INDEX idx_pengguna_username (username),
    INDEX idx_pengguna_peran    (peran)
) ENGINE=InnoDB COMMENT='Data pengguna sistem dengan role-based access control';

-- ============================================================
-- Tabel: sesi_masuk (audit log login/logout)
-- ============================================================
CREATE TABLE IF NOT EXISTS sesi_masuk (
    id_sesi       INT          AUTO_INCREMENT PRIMARY KEY,
    id_pengguna   INT          REFERENCES pengguna(id_pengguna),
    alamat_ip     VARCHAR(45),
    user_agent    TEXT,
    waktu_masuk   DATETIME     DEFAULT CURRENT_TIMESTAMP,
    waktu_keluar  DATETIME,
    berhasil      TINYINT(1)   DEFAULT 1 COMMENT '1=login sukses, 0=gagal',

    INDEX idx_sesi_pengguna (id_pengguna),
    INDEX idx_sesi_waktu    (waktu_masuk)
) ENGINE=InnoDB COMMENT='Audit log sesi login pengguna';

-- ============================================================
-- INSERT Data Referensi
-- ============================================================

INSERT INTO jenis_serangan (nama_serangan, kategori, deskripsi) VALUES
('NetBIOS',  'DDoS',   'Serangan DDoS dengan protokol NetBIOS'),
('MSSQL',    'DDoS',   'Serangan DDoS menarget port Microsoft SQL Server'),
('UDP',      'DDoS',   'Serangan DDoS berbasis UDP flooding'),
('Syn',      'DDoS',   'Serangan SYN Flood - eksploitasi TCP three-way handshake'),
('Portmap',  'DDoS',   'Serangan DDoS melalui layanan RPC Portmap'),
('LDAP',     'DDoS',   'Serangan DDoS amplifikasi melalui LDAP'),
('NTP',      'DDoS',   'Serangan DDoS amplifikasi melalui Network Time Protocol'),
('TFTP',     'DDoS',   'Serangan DDoS melalui protokol TFTP'),
('DNS',      'DDoS',   'Serangan DDoS amplifikasi DNS'),
('SNMP',     'DDoS',   'Serangan DDoS melalui protokol SNMP'),
('WebDDoS',  'DDoS',   'Serangan DDoS pada layer aplikasi web (HTTP Flood)'),
('BENIGN',   'Normal', 'Lalu lintas jaringan normal / tidak berbahaya');

INSERT INTO sumber_dataset (nama_dataset, versi, tanggal_capture, keterangan) VALUES
('CICDDoS2019', '2019', '2018-11-03',
 'Dataset serangan DDoS dari Canadian Institute for Cybersecurity (CIC). Berisi berbagai jenis serangan refleksi DDoS.');

INSERT INTO model_ml (nama_model, versi, akurasi, presisi, recall, f1_score, roc_auc, tanggal_latih, path_file_model, keterangan) VALUES
('XGBoost',       '1.0', 0.9995, 0.9993, 0.9994, 0.9994, 0.9999, NOW(), 'Minggu6_XGBoost.pkl',
 'Model XGBoost - hasil terbaik dari perbandingan Minggu 6'),
('Random Forest', '1.0', 0.9980, 0.9978, 0.9975, 0.9976, 0.9995, NOW(), 'Minggu6_RF.pkl',
 'Random Forest sebagai pembanding XGBoost');

-- Seed akun pengguna awal (kata sandi harus diganti setelah deploy)
INSERT INTO pengguna (nama_lengkap, username, kata_sandi, peran, email) VALUES
('Administrator',  'admin', SHA2('admin123', 256), 'admin', 'admin@ddos-system.id'),
('Pengguna Biasa', 'user1', SHA2('user123',  256), 'user',  'user1@ddos-system.id');

