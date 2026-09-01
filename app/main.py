import os

from dotenv import load_dotenv
from flask import Flask, jsonify, request

from app.db import execute
from app.detectors import run_all_detectors

load_dotenv()

app = Flask(__name__)

REQUIRED_LOG_FIELDS = ("timestamp", "username", "ip_address", "status", "raw_log")


@app.route("/")
def index():
    return jsonify({"status": "SentinelDesk running"})


@app.route("/logs", methods=["POST"])
def ingest_log():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "Request body must be a JSON object"}), 400

    missing = [field for field in REQUIRED_LOG_FIELDS if field not in data]
    if missing:
        return jsonify({"error": f"Missing fields: {', '.join(missing)}"}), 400

    execute(
        """
        INSERT INTO auth_logs (timestamp, username, ip_address, status, raw_log)
        VALUES (%s, %s, %s, %s, %s)
        """,
        tuple(data[field] for field in REQUIRED_LOG_FIELDS),
    )
    return jsonify({"message": "Log ingested"}), 201


@app.route("/alerts", methods=["GET"])
def get_alerts():
    alerts = run_all_detectors()
    return jsonify({"alerts": alerts, "count": len(alerts)})


if __name__ == "__main__":
    debug = os.getenv("FLASK_DEBUG", "0") == "1"
    app.run(debug=debug, port=int(os.getenv("PORT", "5001")), threaded=True)