from flask import Flask, request, jsonify
from dotenv import load_dotenv
import psycopg2
import os

load_dotenv()

app = Flask(__name__)

def get_db():
    conn = psycopg2.connect(
        dbname="sentineldesk",
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASSWORD"),
        host="localhost"
    )
    return conn

@app.route('/')
def index():
    return jsonify({"status": "SentinelDesk running"})

@app.route('/logs', methods=['POST'])
def ingest_log():
    data = request.get_json()
    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO auth_logs (timestamp, username, ip_address, status, raw_log) VALUES (%s, %s, %s, %s, %s)",
        (data['timestamp'], data['username'], data['ip_address'], data['status'], data['raw_log'])
    )
    conn.commit()
    cur.close()
    conn.close()
    return jsonify({"message": "Log ingested"}), 201

@app.route('/alerts', methods=['GET'])
def get_alerts():
    from detectors import detect_brute_force, detect_credential_stuffing, detect_suspicious_login_times
    alerts = detect_brute_force() + detect_credential_stuffing() + detect_suspicious_login_times
    return jsonify({"alerts": alerts})

if __name__ == '__main__':
    app.run(debug=True)
