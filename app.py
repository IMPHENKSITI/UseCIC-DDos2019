from functools import wraps

from flask import (Flask, flash, jsonify, redirect, render_template, request,
                   session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash

import data

app = Flask(__name__)
app.secret_key = "ganti-dengan-kunci-rahasia-anda"


# ------------------------------------------------------------------ helpers
def current_user():
    uid = session.get("uid")
    return next((u for u in data.USERS if u["id"] == uid), None)


def login_required(admin=False):
    def deco(fn):
        @wraps(fn)
        def wrapper(*a, **kw):
            u = current_user()
            if not u:
                return redirect(url_for("login"))
            if admin and u["peran"] != "admin":
                flash("Halaman ini khusus admin.", "error")
                return redirect(url_for("riwayat"))   # user → ke halaman user
            return fn(*a, **kw)
        return wrapper
    return deco


def inisial(nama):
    p = nama.split()
    return (p[0][0] + (p[1][0] if len(p) > 1 else "")).upper()


@app.context_processor
def inject():
    u = current_user()
    unread = sum(1 for n in data.NOTIFS if not n["baca"])
    pending = sum(1 for x in data.USERS if x["status"] == "menunggu")
    belum = sum(1 for a in data.ALERTS if a["status"] == "Belum ditinjau")
    return dict(user=u, inisial=inisial, unread=unread, pending=pending,
                alert_badge=min(belum, 3) if belum else 0)


# ------------------------------------------------------------------ public
@app.route("/")
def landing():
    return render_template("landing.html", kelas=data.KELAS)


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        f = request.form
        nama  = f.get("nama", "").strip()
        email = f.get("email", "").strip().lower()
        pw    = f.get("password", "")
        pw2   = f.get("password2", "")

        if not (nama and email and pw):
            flash("Semua kolom wajib diisi.", "error")
        elif len(pw) < 8:
            flash("Kata sandi minimal 8 karakter.", "error")
        elif pw != pw2:
            flash("Konfirmasi kata sandi tidak sama.", "error")
        elif not f.get("setuju"):
            flash("Anda harus menyetujui penggunaan data.", "error")
        elif any(u["email"] == email for u in data.USERS):
            flash("Email sudah terdaftar.", "error")
        else:
            new_id = max(u["id"] for u in data.USERS) + 1
            data.USERS.append({
                "id"       : new_id,
                "nama"     : nama,
                "email"    : email,
                "username" : nama.split()[0].lower(),
                "peran"    : "analis",   # selalu user biasa
                "status"   : "aktif",    # langsung aktif, tidak perlu approval
                "terdaftar": __import__("datetime").datetime.now().strftime("%d %b %Y"),
                "pw"       : generate_password_hash(pw),
            })
            flash("Pendaftaran berhasil! Silakan login.", "ok")
            return redirect(url_for("login"))
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        pw    = request.form.get("password", "")
        u = next((x for x in data.USERS if x["email"] == email), None)
        if not u or not check_password_hash(u["pw"], pw):
            flash("Email atau kata sandi salah.", "error")
        elif u["status"] == "menunggu":
            flash("Akun Anda masih menunggu persetujuan admin.", "error")
        elif u["status"] == "nonaktif":
            flash("Akun Anda dinonaktifkan. Hubungi admin.", "error")
        else:
            session["uid"] = u["id"]
            # Admin → panel admin | User biasa → halaman riwayat deteksi
            if u["peran"] == "admin":
                return redirect(url_for("admin_ringkasan"))
            else:
                return redirect(url_for("cari_deteksi"))
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("landing"))


# ------------------------------------------------------------------ user: cari deteksi
@app.route("/cari")
@login_required()
def cari_deteksi():
    from datetime import datetime, timedelta

    q       = request.args.get("q", "").strip()
    jenis   = request.args.get("jenis", "")
    tingkat = request.args.get("tingkat", "")
    waktu   = request.args.get("waktu", "")
    urut    = request.args.get("urut", "baru")
    page    = max(1, int(request.args.get("page", 1)))
    per_page = 10

    # Filter data — keep original index for detail links
    rows = [(i, r) for i, r in enumerate(data.RIWAYAT)]

    if q:
        q_low = q.lower()
        rows = [(i, r) for i, r in rows if q_low in r["ip"].lower()
                or q_low in r["jenis"].lower()]
    if jenis:
        rows = [(i, r) for i, r in rows if r["jenis"] == jenis]
    if tingkat:
        rows = [(i, r) for i, r in rows if r["tingkat"] == tingkat]
    if waktu:
        now = datetime.now()
        if waktu == "hari":
            cutoff = now.replace(hour=0, minute=0, second=0)
        elif waktu == "minggu":
            cutoff = now - timedelta(days=7)
        elif waktu == "bulan":
            cutoff = now - timedelta(days=30)
        else:
            cutoff = None
        if cutoff:
            rows = [(i, r) for i, r in rows if r.get("waktu") and r["waktu"] >= cutoff]

    # Sort
    if urut == "lama":
        rows.sort(key=lambda x: x[1].get("waktu", datetime.min))
    elif urut == "conf":
        rows.sort(key=lambda x: x[1].get("conf", 0), reverse=True)
    else:  # baru (default)
        rows.sort(key=lambda x: x[1].get("waktu", datetime.min), reverse=True)

    total = len(rows)
    total_pages = max(1, (total + per_page - 1) // per_page)
    page = min(page, total_pages)
    page_slice = rows[(page - 1) * per_page : page * per_page]

    # Attach original index to each row dict for template
    page_rows = []
    for orig_idx, r in page_slice:
        row_copy = dict(r)
        row_copy["_idx"] = orig_idx
        page_rows.append(row_copy)

    f = dict(q=q, jenis=jenis, tingkat=tingkat, waktu=waktu, urut=urut)

    return render_template("cari_deteksi.html", active="cari",
                           rows=page_rows, total=total, page=page,
                           total_pages=total_pages, kelas=data.KELAS[1:], f=f)


# ------------------------------------------------------------------ detail deteksi
DESKRIPSI_SERANGAN = {
    "Syn": "SYN Flood adalah serangan DDoS yang mengirimkan banyak paket SYN (permintaan koneksi TCP) ke server target tanpa menyelesaikan proses handshake. Ini menyebabkan antrian koneksi penuh dan server tidak dapat menerima koneksi baru.",
    "UDP": "UDP Flood mengirimkan sejumlah besar paket UDP ke port acak pada server target. Server harus memeriksa setiap paket dan mengirim ICMP Destination Unreachable, menghabiskan sumber daya.",
    "LDAP": "LDAP Amplification memanfaatkan server LDAP terbuka untuk memperkuat volume serangan. Penyerang mengirim query kecil dengan IP sumber palsu, server LDAP membalas dengan respons besar ke korban.",
    "MSSQL": "DrDoS MSSQL memanfaatkan layanan Microsoft SQL Server untuk amplifikasi. Query kecil menghasilkan respons besar yang diarahkan ke IP korban.",
    "NetBIOS": "DrDoS NetBIOS memanfaatkan protokol NetBIOS Name Service untuk memperkuat trafik serangan terhadap target.",
    "Portmap": "Portmap (RPCBind) Amplification memanfaatkan layanan Portmap/RPCBind untuk menghasilkan respons besar dari query kecil.",
    "UDPLag": "UDP-Lag adalah variasi UDP Flood yang dirancang untuk menyebabkan latensi tinggi dan paket loss pada koneksi jaringan target.",
    "BENIGN": "Trafik normal yang terdeteksi dan diklasifikasikan sebagai aman (bukan serangan).",
    "DrDoS_UDP": "Distributed Reflection DoS menggunakan UDP — memanfaatkan server terbuka sebagai reflektor untuk memperkuat serangan.",
    "DrDoS_SNMP": "DrDoS SNMP memanfaatkan server SNMP terbuka untuk amplifikasi. SNMP GetBulk request menghasilkan respons sangat besar.",
    "DrDoS_NetBIOS": "Refleksi DDoS melalui protokol NetBIOS, memanfaatkan layanan NetBIOS yang terbuka di jaringan.",
    "DrDoS_MSSQL": "Refleksi DDoS melalui Microsoft SQL Server, menggunakan query yang menghasilkan respons besar.",
    "TFTP": "TFTP Amplification memanfaatkan server TFTP terbuka untuk memperkuat volume serangan terhadap target.",
    "WebDDoS": "Web DDoS mengirimkan permintaan HTTP/HTTPS dalam jumlah besar untuk membanjiri web server target.",
}

PORT_MAP = {
    "Syn": 80, "UDP": 53, "LDAP": 389, "MSSQL": 1433, "NetBIOS": 137,
    "Portmap": 111, "UDPLag": 80, "BENIGN": 80, "DrDoS_UDP": 53,
    "DrDoS_SNMP": 161, "DrDoS_NetBIOS": 137, "DrDoS_MSSQL": 1433,
    "TFTP": 69, "WebDDoS": 443,
}

PROTO_MAP = {
    "Syn": "TCP", "UDP": "UDP", "LDAP": "UDP", "MSSQL": "UDP",
    "NetBIOS": "UDP", "Portmap": "UDP", "UDPLag": "UDP", "BENIGN": "TCP",
    "DrDoS_UDP": "UDP", "DrDoS_SNMP": "UDP", "DrDoS_NetBIOS": "UDP",
    "DrDoS_MSSQL": "UDP", "TFTP": "UDP", "WebDDoS": "TCP",
}


@app.route("/cari/detail/<int:idx>")
@login_required()
def detail_deteksi(idx):
    if idx < 0 or idx >= len(data.RIWAYAT):
        flash("Data deteksi tidak ditemukan.", "error")
        return redirect(url_for("cari_deteksi"))

    r = data.RIWAYAT[idx]
    jenis = r["jenis"]
    return render_template("detail_deteksi.html",
                           r=r, idx=idx,
                           protokol=PROTO_MAP.get(jenis, "UDP"),
                           port=PORT_MAP.get(jenis, 80),
                           deskripsi=DESKRIPSI_SERANGAN.get(jenis, "Jenis serangan terdeteksi oleh model machine learning."))


# ------------------------------------------------------------------ analis
@app.route("/dashboard")
@login_required()
def dashboard():
    return render_template("dashboard.html", active="dashboard", s=data.STATS,
                           dist=data.DISTRIBUSI, alerts=data.ALERTS[:5])


@app.route("/monitoring")
@login_required()
def monitoring():
    return render_template("monitoring.html", active="monitoring")


@app.route("/api/flows")
@login_required()
def api_flows():
    return jsonify([data.generate_flow() for _ in range(2)])


@app.route("/alert")
@login_required()
def alert():
    jenis = request.args.get("jenis", "")
    tingkat = request.args.get("tingkat", "")
    q = request.args.get("q", "").strip()
    rows = [a for a in data.ALERTS
            if (not jenis or a["jenis"] == jenis)
            and (not tingkat or a["tingkat"] == tingkat)
            and (not q or q in a["ip"])]
    jenis_list = sorted({a["jenis"] for a in data.ALERTS})
    return render_template("alert.html", active="alert", rows=rows, jenis_list=jenis_list,
                           f=dict(jenis=jenis, tingkat=tingkat, q=q), total=42)


@app.route("/alert/<int:idx>/tindak", methods=["POST"])
@login_required()
def alert_tindak(idx):
    if 0 <= idx < len(data.ALERTS):
        data.ALERTS[idx]["status"] = "Sudah ditindaklanjuti"
    return redirect(request.referrer or url_for("alert"))


@app.route("/riwayat")
@login_required()
def riwayat():
    jenis = request.args.get("jenis", "")
    q = request.args.get("q", "").strip()
    rows = [r for r in data.RIWAYAT if (not jenis or r["jenis"] == jenis) and (not q or q in r["ip"])]
    return render_template("riwayat.html", active="riwayat", rows=rows[:50],
                           kelas=data.KELAS[1:], f=dict(jenis=jenis, q=q), total=len(rows))


@app.route("/visualisasi")
@login_required()
def visualisasi():
    rentang = request.args.get("rentang", "hari ini")
    vals = data.HOURLY.get(rentang, data.HOURLY["hari ini"])
    mx = max(vals)
    total = sum(j for _, j in data.PER_JENIS)
    return render_template("visualisasi.html", active="visualisasi", rentang=rentang,
                           bars=list(zip(data.HOUR_LABELS, vals)), mx=mx, peak=vals.index(mx),
                           per_jenis=data.PER_JENIS, total=total, pmax=data.PER_JENIS[0][1],
                           stats=data.STATS)


@app.route("/performa")
@login_required()
def performa():
    return render_template("performa.html", active="performa", rows=data.PERFORMA)


@app.route("/export", methods=["GET", "POST"])
@login_required()
def export():
    if request.method == "POST":
        f = request.form
        dari = f.get("dari", "-")
        sampai = f.get("sampai", "-")
        fmt = f.get("format", "PDF")
        nama = f"Laporan Deteksi {dari} s/d {sampai}"
        data.REPORTS.insert(0, {"nama": nama, "format": fmt, "dibuat": "Baru saja"})
        flash("Laporan berhasil dibuat.", "ok")
        return redirect(url_for("export"))
    return render_template("export.html", active="export", reports=data.REPORTS)


@app.route("/notifikasi")
@login_required()
def notifikasi():
    only_unread = request.args.get("tab") == "unread"
    rows = [n for n in data.NOTIFS if not (only_unread and n["baca"])]
    return render_template("notifikasi.html", active="notifikasi", rows=rows, only_unread=only_unread)


@app.route("/notifikasi/baca", methods=["POST"])
@login_required()
def notif_baca():
    for n in data.NOTIFS:
        n["baca"] = True
    return redirect(url_for("notifikasi"))


@app.route("/pengaturan", methods=["GET", "POST"])
@login_required()
def pengaturan():
    u = current_user()
    if request.method == "POST":
        nama = request.form.get("nama", "").strip()
        email = request.form.get("email", "").strip()
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        if nama:
            u["nama"] = nama
        if email:
            u["email"] = email
        if username:
            u["username"] = username
        if password and len(password) >= 8:
            u["pw"] = generate_password_hash(password)
        elif password and len(password) < 8:
            flash("Kata sandi minimal 8 karakter.", "error")
            return redirect(url_for("pengaturan"))
        flash("Perubahan disimpan.", "ok")
        return redirect(url_for("pengaturan"))
    return render_template("pengaturan.html", active="pengaturan", threshold=session.get("threshold", 70))


# ------------------------------------------------------------------ admin
@app.route("/admin")
@login_required(admin=True)
def admin_ringkasan():
    aktif = [u for u in data.USERS if u["status"] == "aktif"]
    return render_template("admin_ringkasan.html", active="a_ringkasan", admin=True,
                           n_aktif=len(aktif), n_analis=sum(u["peran"] == "analis" for u in aktif),
                           n_admin=sum(u["peran"] == "admin" for u in aktif),
                           menunggu=[u for u in data.USERS if u["status"] == "menunggu"],
                           modules=data.MODULES)


@app.route("/admin/pengguna")
@login_required(admin=True)
def admin_pengguna():
    peran, status, q = request.args.get("peran", ""), request.args.get("status", ""), request.args.get("q", "").lower()
    rows = [u for u in data.USERS
            if (not peran or u["peran"] == peran) and (not status or u["status"] == status)
            and (not q or q in u["nama"].lower() or q in u["email"])]
    return render_template("admin_pengguna.html", active="a_pengguna", admin=True, rows=rows,
                           f=dict(peran=peran, status=status, q=q))


@app.route("/admin/pengguna/<int:uid>/<aksi>", methods=["POST"])
@login_required(admin=True)
def admin_aksi(uid, aksi):
    u = next((x for x in data.USERS if x["id"] == uid), None)
    if u:
        if aksi == "setujui":
            u["status"], u["peran"] = "aktif", "analis"
        elif aksi == "tolak":
            data.USERS.remove(u)
        elif aksi == "nonaktifkan" and u["peran"] != "admin":
            u["status"] = "nonaktif"
        elif aksi == "aktifkan":
            u["status"] = "aktif"
        elif aksi == "peran" and u["id"] != session["uid"]:
            u["peran"] = "admin" if u["peran"] == "analis" else "analis"
    return redirect(request.referrer or url_for("admin_pengguna"))


@app.route("/admin/pengguna/tambah", methods=["POST"])
@login_required(admin=True)
def admin_tambah():
    from datetime import datetime
    nama  = request.form.get("nama", "").strip()
    email = request.form.get("email", "").strip().lower()
    if nama and email and not any(u["email"] == email for u in data.USERS):
        data.USERS.append({
            "id"       : max(u["id"] for u in data.USERS) + 1,
            "nama"     : nama,
            "email"    : email,
            "username" : nama.split()[0].lower(),
            "peran"    : "analis",
            "status"   : "aktif",
            "terdaftar": datetime.now().strftime("%d %b %Y"),
            "pw"       : generate_password_hash("password123"),
        })
        flash("Pengguna ditambahkan (sandi awal: password123).", "ok")
    else:
        flash("Data tidak valid atau email sudah ada.", "error")
    return redirect(url_for("admin_pengguna"))


@app.route("/admin/model")
@login_required(admin=True)
def admin_model():
    return render_template("admin_model.html", active="a_model", admin=True, 
                           versions=data.MODEL_VERSIONS, dataset_info=data.DATASET_INFO)


@app.route("/admin/model/aktifkan/<versi>", methods=["POST"])
@login_required(admin=True)
def admin_model_aktif(versi):
    for m in data.MODEL_VERSIONS:
        m["aktif"] = m["versi"] == versi
    flash(f"Model versi {versi} diaktifkan.", "ok")
    return redirect(url_for("admin_model"))


@app.route("/admin/model/latih", methods=["POST"])
@login_required(admin=True)
def admin_model_latih():
    # TODO: panggil proses training sesungguhnya (visual_model.ipynb -> best_model.pkl)
    flash("Pelatihan ulang dijadwalkan (simulasi).", "ok")
    return redirect(url_for("admin_model"))


@app.route("/admin/dataset/upload", methods=["POST"])
@login_required(admin=True)
def admin_dataset_upload():
    if "file_dataset" not in request.files:
        flash("Tidak ada file yang dipilih.", "error")
        return redirect(url_for("admin_model"))
    
    file = request.files["file_dataset"]
    if file.filename == "":
        flash("Nama file kosong.", "error")
        return redirect(url_for("admin_model"))
    
    if file and file.filename.endswith(".csv"):
        import os
        from werkzeug.utils import secure_filename
        filename = secure_filename(file.filename)
        save_path = os.path.join(data.Config.DATASET_DIR if hasattr(data, 'Config') else "dataset", "raw", filename)
        os.makedirs(os.path.dirname(save_path), exist_ok=True)
        file.save(save_path)
        flash(f"Dataset '{filename}' berhasil diunggah ke folder dataset/raw/", "ok")
    else:
        flash("Format file harus berupa CSV (.csv).", "error")
    
    return redirect(url_for("admin_model"))


@app.route("/admin/log")
@login_required(admin=True)
def admin_log():
    lvl, mod = request.args.get("level", ""), request.args.get("modul", "")
    rows = [l for l in data.LOGS if (not lvl or l["level"] == lvl) and (not mod or l["modul"] == mod)]
    moduls = sorted({l["modul"] for l in data.LOGS})
    return render_template("admin_log.html", active="a_log", admin=True, rows=rows,
                           moduls=moduls, f=dict(level=lvl, modul=mod))


# ------------------------------------------------------------------ profil
@app.route("/profil")
@login_required()
def profil():
    from datetime import datetime
    u = current_user()
    last_login = datetime.now().strftime("Hari ini, %H:%M")
    return render_template("profil.html", active="profil", last_login=last_login)


if __name__ == "__main__":
    app.run(debug=True)
