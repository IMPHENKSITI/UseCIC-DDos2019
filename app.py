import os
import sqlite3
import pandas as pd
import pickle
from flask import Flask, render_template, request, jsonify, send_file, flash, redirect
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.svm import SVC
from sklearn.linear_model import LogisticRegression

app = Flask(__name__)
app.secret_key = "super_secret_key"
UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Helper untuk inisialisasi tabel jika belum ada
def init_db():
    conn = sqlite3.connect('database.db')
    conn.execute('''
        CREATE TABLE IF NOT EXISTS warga (
            pendapatan REAL, tanggungan INTEGER, usia INTEGER, kondisi_rumah INTEGER, layak INTEGER
        )
    ''')
    conn.commit()
    conn.close()

def get_db_connection():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn

def load_ml_components():
    try:
        with open('best_model.pkl', 'rb') as m_file, open('scaler.pkl', 'rb') as s_file:
            return pickle.load(m_file), pickle.load(s_file)
    except:
        return None, None

@app.route('/')
def index():
    init_db()
    conn = get_db_connection()
    data = conn.execute('SELECT * FROM warga LIMIT 10').fetchall()
    conn.close()
    model, _ = load_ml_components()
    status_model = "Aktif" if model else "Belum dilatih (Silakan Import Data & Retrain)"
    return render_template('index.html', data=data, status_model=status_model)

@app.route('/predict', methods=['POST'])
def predict():
    try:
        model, scaler = load_ml_components()
        if not model:
            return jsonify({'error': 'Model belum dilatih! Import data dan lakukan Retrain.'})

        pendapatan = float(request.form['pendapatan'])
        tanggungan = float(request.form['tanggungan'])
        usia = float(request.form['usia'])
        kondisi = float(request.form['kondisi'])

        input_data = pd.DataFrame([[pendapatan, tanggungan, usia, kondisi]], 
                                  columns=['pendapatan', 'tanggungan', 'usia', 'kondisi_rumah'])
        input_scaled = scaler.transform(input_data)
        
        pred = model.predict(input_scaled)[0]
        hasil = "Layak Menerima Bantuan" if pred == 1 else "Tidak Layak"
        
        return jsonify({'hasil': hasil})
    except Exception as e:
        return jsonify({'error': str(e)})

@app.route('/settings', methods=['POST'])
def settings():
    algo = request.form.get('algoritma')
    conn = get_db_connection()
    df = pd.read_sql_query("SELECT * FROM warga", conn)
    conn.close()
    
    if df.empty:
        return jsonify({'status': 'Data kosong! Silakan import file Excel/CSV terlebih dahulu.'})

    X = df.drop('layak', axis=1)
    y = df['layak']
    
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    
    if algo == 'rf':
        model = RandomForestClassifier(random_state=42)
    elif algo == 'svm':
        model = SVC(random_state=42)
    else:
        model = LogisticRegression(random_state=42)
        
    model.fit(X_scaled, y)
    
    with open('best_model.pkl', 'wb') as f: pickle.dump(model, f)
    with open('scaler.pkl', 'wb') as f: pickle.dump(scaler, f)
    
    return jsonify({'status': f'Model berhasil dilatih menggunakan {algo.upper()}'})

@app.route('/export')
def export_data():
    conn = get_db_connection()
    df = pd.read_sql_query("SELECT * FROM warga", conn)
    conn.close()
    
    if df.empty:
        return redirect('/')
        
    filepath = os.path.join(UPLOAD_FOLDER, 'export_warga.xlsx')
    df.to_excel(filepath, index=False)
    return send_file(filepath, as_attachment=True)

@app.route('/import', methods=['POST'])
def import_data():
    if 'file' not in request.files:
        return redirect('/')
    
    file = request.files['file']
    if file.filename != '':
        filepath = os.path.join(UPLOAD_FOLDER, file.filename)
        file.save(filepath)
        
        # Dukung baca Excel maupun CSV
        if file.filename.endswith('.csv'):
            df = pd.read_csv(filepath)
        elif file.filename.endswith('.xlsx') or file.filename.endswith('.xls'):
            df = pd.read_excel(filepath)
        else:
            return redirect('/')
            
        conn = get_db_connection()
        # Ganti data lama dengan data baru yang diimpor
        df.to_sql('warga', conn, if_exists='replace', index=False)
        conn.close()
        
    return redirect('/')

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)