from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit
import csv
import io
import json
import sqlite3

import joblib
import pandas as pd
from flask import Flask, jsonify, render_template, request, Response
from ml.features import extract_features, normalize_url

ROOT = Path(__file__).resolve().parent
MODEL_PATH = ROOT / 'ml' / 'model.joblib'
DB_PATH = ROOT / 'scans.db'
app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 32 * 1024

if not MODEL_PATH.exists():
    raise RuntimeError('Model missing. Run python ml/generate_demo_data.py and python ml/train.py first.')
bundle = joblib.load(MODEL_PATH)  # Load only your own trusted model file.
model = bundle['model']
feature_columns = bundle['features']
metrics_path = ROOT / 'ml' / 'metrics.json'
metrics = json.loads(metrics_path.read_text()) if metrics_path.exists() else {}

def connect():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

with connect() as conn:
    conn.execute('CREATE TABLE IF NOT EXISTS scans (id INTEGER PRIMARY KEY AUTOINCREMENT, url TEXT NOT NULL, hostname TEXT NOT NULL, verdict TEXT NOT NULL, risk INTEGER NOT NULL, scanned_at TEXT NOT NULL)')

def get_stats():
    with connect() as conn:
        rows = [dict(r) for r in conn.execute('SELECT * FROM scans ORDER BY id DESC LIMIT 100')]
        counts = dict(conn.execute('SELECT verdict, COUNT(*) FROM scans GROUP BY verdict').fetchall())
        total = conn.execute('SELECT COUNT(*) FROM scans').fetchone()[0]
    return {'total': total, 'phishing': counts.get('Phishing', 0), 'legitimate': counts.get('Legitimate', 0), 'recent': rows}

@app.get('/')
def home():
    return render_template('index.html', metrics=metrics, demo=metrics.get('demo_data', False))

@app.get('/api/stats')
def stats():
    return jsonify(get_stats())

@app.post('/api/scan')
def scan():
    payload = request.get_json(silent=True) or {}
    try:
        url = normalize_url(payload.get('url', ''))
        extracted = extract_features(url)
    except (ValueError, TypeError) as exc:
        return jsonify({'error': str(exc)}), 400
    frame = pd.DataFrame([extracted], columns=feature_columns)
    probabilities = model.predict_proba(frame)[0]
    phishing_index = list(model.classes_).index(1)
    risk = round(float(probabilities[phishing_index]) * 100)
    verdict = 'Phishing' if risk >= 50 else 'Legitimate'
    host = urlsplit(url).hostname or ''
    now = datetime.now(timezone.utc).isoformat(timespec='seconds')
    with connect() as conn:
        conn.execute('INSERT INTO scans(url, hostname, verdict, risk, scanned_at) VALUES (?, ?, ?, ?, ?)', (url, host, verdict, risk, now))
    explanations = []
    if not extracted['uses_https']: explanations.append('Uses HTTP instead of HTTPS')
    if extracted['has_ip_address']: explanations.append('Hostname is an IP address')
    if extracted['suspicious_keyword_count']: explanations.append('Contains account/security-related keywords')
    if extracted['is_shortener']: explanations.append('Uses a URL shortening service')
    if extracted['url_length'] > 100: explanations.append('Unusually long URL')
    if extracted['subdomain_count'] >= 3: explanations.append('Multiple subdomains')
    if not explanations: explanations.append('No selected heuristic warning signs detected')
    return jsonify({'url': url, 'hostname': host, 'verdict': verdict, 'risk': risk, 'confidence': max(risk, 100-risk), 'signals': explanations, 'features': extracted, 'scanned_at': now, 'demo': metrics.get('demo_data', False)})

@app.get('/api/health')
def health():
    try:
        with connect() as conn:
            conn.execute('SELECT 1').fetchone()
        return jsonify({'online': True, 'model_loaded': model is not None, 'database': True})
    except sqlite3.Error:
        return jsonify({'online': False, 'model_loaded': model is not None, 'database': False}), 503

@app.delete('/api/scans/<int:scan_id>')
def delete_scan(scan_id):
    with connect() as conn:
        result = conn.execute('DELETE FROM scans WHERE id = ?', (scan_id,))
    if result.rowcount == 0:
        return jsonify({'error': 'Scan not found'}), 404
    return jsonify({'deleted': scan_id})

@app.delete('/api/scans')
def clear_scans():
    with connect() as conn:
        conn.execute('DELETE FROM scans')
    return jsonify({'cleared': True})

@app.get('/api/export')
def export():
    with connect() as conn:
        rows = conn.execute('SELECT url, hostname, verdict, risk, scanned_at FROM scans ORDER BY id DESC').fetchall()
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(['url', 'hostname', 'verdict', 'risk', 'scanned_at'])
    for row in rows: writer.writerow(list(row))
    return Response(out.getvalue(), mimetype='text/csv', headers={'Content-Disposition': 'attachment; filename=scan_history.csv'})

if __name__ == '__main__':
    app.run(debug=False, host='127.0.0.1', port=5000)
