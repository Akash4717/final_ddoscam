from flask import Flask, render_template, jsonify, request
from flask_cors import CORS
import logging
import requests
import numpy as np
import time
from datetime import datetime
from collections import deque, defaultdict
import threading
import json

# -----------------------------
# EmailJS Configuration
# -----------------------------
EMAILJS_SERVICE_ID = "service_7ltcrrw"
EMAILJS_TEMPLATE_ID = "template_oupoglq"
EMAILJS_PUBLIC_KEY = "zxfidoYvook_dIeac"
EMAILJS_PRIVATE_KEY = "MWHsEdre0TPV-EA7AF-e8"
EMAILJS_URL = "https://api.emailjs.com/api/v1.0/email/send"
ADMIN_EMAIL = "santaclaus19102004@gmail.com"

# -----------------------------
# Victim Firewall Endpoints
# -----------------------------
VICTIM_BLOCK_URLS = {
    "camera1": "http://localhost:8000/api/block_ip",
    "camera2": "http://10.72.9.92:8001/api/block_ip"
}   

# -----------------------------
# Logging Setup
# -----------------------------
logging.basicConfig(level=logging.INFO, format="%(asctime)s [DETECTOR] %(message)s")
log = logging.getLogger("detector")

app = Flask(__name__, template_folder="templates")
CORS(app)

# -----------------------------
# Runtime State - Per Camera
# -----------------------------
MAX_HISTORY = 200

# Camera 1 State
camera1_traffic_history = deque(maxlen=MAX_HISTORY)
camera1_detection_history = deque(maxlen=MAX_HISTORY)
camera1_attack_log = []
camera1_stats = {
    "packets_per_sec": 0,
    "bytes_per_sec": 0,
    "unique_src_ips": 0,
    "src_ip_entropy": 0,
    "status": "Normal",
    "confidence": 0,
    "alerts": 0,
    "malicious_ips": []
}
camera1_blacklisted = {}

# Camera 2 State
camera2_traffic_history = deque(maxlen=MAX_HISTORY)
camera2_detection_history = deque(maxlen=MAX_HISTORY)
camera2_attack_log = []
camera2_stats = {
    "packets_per_sec": 0,
    "bytes_per_sec": 0,
    "unique_src_ips": 0,
    "src_ip_entropy": 0,
    "status": "Normal",
    "confidence": 0,
    "alerts": 0,
    "malicious_ips": []
}
camera2_blacklisted = {}

_blacklist_lock = threading.Lock()

# -----------------------------
# Helper Functions
# -----------------------------
def send_attack_email(camera_id, attack_type, confidence, ips, timestamp):
    payload = {
        "service_id": EMAILJS_SERVICE_ID,
        "template_id": EMAILJS_TEMPLATE_ID,
        "user_id": EMAILJS_PUBLIC_KEY,
        "accessToken": EMAILJS_PRIVATE_KEY,
        "template_params": {
            "admin_email": ADMIN_EMAIL,
            "attack_type": f"[{camera_id.upper()}] {attack_type}",
            "confidence": f"{confidence:.1f}%",
            "malicious_ips": ", ".join(ips) if ips else "Unknown",
            "timestamp": timestamp
        }
    }

    try:
        response = requests.post(EMAILJS_URL, json=payload, timeout=5)
        print(f"[EMAIL RAW {camera_id}]:", response.status_code, response.text)
    except Exception as e:
        print(f"[EMAIL ERROR {camera_id}]", e)


def to_number(v):
    if isinstance(v, (np.float32, np.float64)): return float(v)
    if isinstance(v, (np.int32, np.int64)): return int(v)
    return v

def safe(data, key, default=0.0):
    try: return float(data.get(key, default))
    except: return float(default)

# -----------------------------
# Mitigation Function
# -----------------------------
def block_ip(ip, camera_id):
    try:
        with _blacklist_lock:
            blacklist = camera1_blacklisted if camera_id == "camera1" else camera2_blacklisted
            
            if ip in blacklist:
                return False

            block_url = VICTIM_BLOCK_URLS[camera_id]
            response = requests.post(block_url, json={"ip": ip}, timeout=5)

            if response.status_code == 200:
                blacklist[ip] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                log.warning(f"[MITIGATION {camera_id.upper()}] Blocked IP: {ip}")
                return True

            log.error(f"[MITIGATION ERROR {camera_id.upper()}] Victim refused block: {response.text}")
            return False
    except Exception as e:
        log.error(f"[MITIGATION ERROR {camera_id.upper()}] Failed blocking {ip} -> {str(e)}")
        return False


def auto_mitigate(ips, camera_id):
    for ip in ips:
        block_ip(ip, camera_id)

# -----------------------------
# Detection Logic
# -----------------------------
def detect_attack(f):
    pps = safe(f, "packets_per_sec")
    uniq = int(safe(f, "unique_src_ips"))
    ent = safe(f, "src_ip_entropy")
    bps = safe(f, "bytes_per_sec")
    conr = safe(f, "connection_rate")
    ips = list(f.get("source_ips") or [])

    if pps > 40:
        return True, min(99.9, 40 + pps * 1.1), "HTTP Flood", ips

    if uniq >= 5 or ent > 1.0:
        return True, min(99.9, 50 + uniq * 8 + ent * 12), "Botnet Flood", ips

    if bps > 80000:
        return True, min(99.9, 30 + bps / 2000), "Bandwidth Flood", ips

    if conr > 40:
        return True, min(99.9, 35 + conr * 1.2), "Connection Flood", ips

    return False, 0.0, "Normal", []


# -----------------------------
# API: Telemetry Ingest - Camera 1
# -----------------------------
@app.route("/api/ingest", methods=["POST"])
def ingest_camera1():
    return ingest_camera("camera1")

# -----------------------------
# API: Telemetry Ingest - Camera 2
# -----------------------------
@app.route("/api/ingest/camera2", methods=["POST"])
def ingest_camera2():
    return ingest_camera("camera2")

# -----------------------------
# Generic Ingest Function
# -----------------------------
def ingest_camera(camera_id):
    try:
        # Select the appropriate state based on camera
        if camera_id == "camera1":
            traffic_history = camera1_traffic_history
            detection_history = camera1_detection_history
            attack_log = camera1_attack_log
            current_stats = camera1_stats
            blacklisted = camera1_blacklisted
        else:
            traffic_history = camera2_traffic_history
            detection_history = camera2_detection_history
            attack_log = camera2_attack_log
            current_stats = camera2_stats
            blacklisted = camera2_blacklisted

        data = request.get_json(force=True) or {}
        data = {k: to_number(v) for k, v in data.items()}

        is_attack, conf, atk_type, bad_ips = detect_attack(data)

        current_stats.update({
            "packets_per_sec": data.get("packets_per_sec", 0),
            "bytes_per_sec": data.get("bytes_per_sec", 0),
            "unique_src_ips": data.get("unique_src_ips", 0),
            "src_ip_entropy": data.get("src_ip_entropy", 0),
            "status": atk_type,
            "confidence": conf,
            "malicious_ips": bad_ips
        })

        detection_history.append({
            "timestamp": datetime.now().strftime("%H:%M:%S"),
            "is_attack": is_attack,
            "type": atk_type,
            "confidence": f"{conf:.1f}%",
            "packets_per_sec": int(data.get("packets_per_sec", 0)),
            "ips": bad_ips
        })

        traffic_history.append(float(data.get("packets_per_sec", 0)))

        if is_attack:
            attack_log.append(detection_history[-1])
            current_stats["alerts"] += 1

            log.warning(f"[DETECT {camera_id.upper()}] {atk_type} | {conf:.1f}% | IPs={bad_ips}")

            send_attack_email(camera_id, atk_type, conf, bad_ips, datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

            # AUTO MITIGATION HERE
            auto_mitigate(bad_ips, camera_id)

        return jsonify({"detected": is_attack, "attack_type": atk_type, "confidence": conf, "malicious_ips": bad_ips})

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# -----------------------------
# Manual Mitigation Endpoint
# -----------------------------
@app.route("/api/mitigate", methods=["POST"])
def trigger_mitigation():
    data = request.get_json(force=True) or {}
    camera_id = data.get("camera", "camera1")
    
    current_stats = camera1_stats if camera_id == "camera1" else camera2_stats
    blacklisted = camera1_blacklisted if camera_id == "camera1" else camera2_blacklisted
    
    ips = current_stats.get("malicious_ips", [])

    if not ips:
        return jsonify({"ok": False, "message": "No malicious IPs detected."}), 400

    blocked = []
    already = []

    for ip in ips:
        if ip in blacklisted:
            already.append(ip)
        elif block_ip(ip, camera_id):
            blocked.append(ip)

    return jsonify({
        "ok": True,
        "blocked": blocked,
        "already_blocked": already,
        "total_blacklisted": list(blacklisted.keys())
    })


# -----------------------------
# Stats Endpoint
# -----------------------------
@app.route("/api/stats")
def stats():
    return jsonify({
        "camera1": {
            "current": camera1_stats,
            "traffic_history": list(camera1_traffic_history),
            "detection_history": list(camera1_detection_history),
            "attack_log": list(camera1_attack_log),
            "blacklisted_ips": [{"ip": ip, "blocked_at": ts} for ip, ts in camera1_blacklisted.items()]
        },
        "camera2": {
            "current": camera2_stats,
            "traffic_history": list(camera2_traffic_history),
            "detection_history": list(camera2_detection_history),
            "attack_log": list(camera2_attack_log),
            "blacklisted_ips": [{"ip": ip, "blocked_at": ts} for ip, ts in camera2_blacklisted.items()]
        }
    })


# -----------------------------
# Reset
# -----------------------------
@app.route("/api/reset", methods=["POST"])
def reset_system():
    data = request.get_json(force=True) or {}
    camera_id = data.get("camera", "all")
    
    if camera_id == "all" or camera_id == "camera1":
        camera1_traffic_history.clear()
        camera1_detection_history.clear()
        camera1_attack_log.clear()
        camera1_blacklisted.clear()
        camera1_stats.update({
            "packets_per_sec": 0,
            "bytes_per_sec": 0,
            "unique_src_ips": 0,
            "src_ip_entropy": 0,
            "status": "Normal",
            "confidence": 0,
            "alerts": 0,
            "malicious_ips": []
        })
    
    if camera_id == "all" or camera_id == "camera2":
        camera2_traffic_history.clear()
        camera2_detection_history.clear()
        camera2_attack_log.clear()
        camera2_blacklisted.clear()
        camera2_stats.update({
            "packets_per_sec": 0,
            "bytes_per_sec": 0,
            "unique_src_ips": 0,
            "src_ip_entropy": 0,
            "status": "Normal",
            "confidence": 0,
            "alerts": 0,
            "malicious_ips": []
        })

    log.info(f"[RESET] System reset for {camera_id}")
    return jsonify({"reset": True, "camera": camera_id})


@app.route("/")
def index():
    return render_template("dashboard.html")


if __name__ == "__main__":
    log.info("[START] Multi-Camera Detector Running on :5000")
    app.run(host="0.0.0.0", port=5000, debug=True)