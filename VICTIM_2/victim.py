"""
victim.py — REAL WEBCAM VERSION (WITH PPS + SYN COUNT LOGGING)
--------------------------------------------------------------
This version uses your laptop webcam through OpenCV (cv2.VideoCapture)
and applies disruption (freeze, delay, frame drop) during HTTP attack load.
Now prints PPS & SYN count in terminal.
"""

from flask import Flask, Response, request, send_from_directory, jsonify
from collections import defaultdict, deque
import threading
import time
import requests
import math
import os
import logging
import random
import cv2
import numpy as np
from datetime import datetime

# ---------- CONFIG ----------
DETECTOR_URL = "http://10.35.14.214:5000"
AGG_INTERVAL = 2.0
MAX_HISTORY = 200

LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = 8001
# ----------------------------

app = Flask(__name__)
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

# Thread-safe counters
lock = threading.Lock()
packet_timestamps = deque(maxlen=MAX_HISTORY)
packet_sizes = deque(maxlen=MAX_HISTORY)
src_ip_counts = defaultdict(int)

# ⚠️ REAL BLOCKLIST (from clean victim with mitigation)
blocked_ips = set()
blocked_lock = threading.Lock()

# SYN counter (added)
syn_count = 0

# Camera disruption globals
camera_loss_rate = 0.0
camera_freeze = False
camera_delay = 0.0
last_frame = None

# REAL WEBCAM - Try multiple camera sources
cap = None

def init_camera():
    """Try to open real camera with multiple options"""
    global cap, last_frame
    
    # Suppress OpenCV warnings
    cv2.setLogLevel(0)
    
    # Try different camera indices and backends
    camera_options = [
        (0, cv2.CAP_DSHOW),   # Primary camera with DirectShow
        (1, cv2.CAP_DSHOW),   # Secondary camera with DirectShow
        (0, cv2.CAP_MSMF),    # Primary with MSMF
        (1, cv2.CAP_MSMF),    # Secondary with MSMF
        (0, None),            # Default backend primary
        (1, None),            # Default backend secondary
        (2, None),            # Third camera
    ]
    
    for cam_index, backend in camera_options:
        try:
            logging.info(f"Trying camera index {cam_index} with backend {backend}...")
            
            if backend:
                test_cap = cv2.VideoCapture(cam_index, backend)
            else:
                test_cap = cv2.VideoCapture(cam_index)
            
            if test_cap.isOpened():
                # Configure camera
                test_cap.set(cv2.CAP_PROP_FRAME_WIDTH, 640)
                test_cap.set(cv2.CAP_PROP_FRAME_HEIGHT, 480)
                test_cap.set(cv2.CAP_PROP_BUFFERSIZE, 1)
                test_cap.set(cv2.CAP_PROP_FPS, 30)
                
                # Wait a moment for camera to initialize
                time.sleep(0.5)
                
                # Test if we can actually read frames
                for attempt in range(5):
                    ret, frame = test_cap.read()
                    if ret and frame is not None and frame.size > 0:
                        cap = test_cap
                        last_frame = frame
                        logging.info(f"✅ Camera opened successfully: Index {cam_index}, Backend {backend}")
                        logging.info(f"   Resolution: {frame.shape[1]}x{frame.shape[0]}")
                        return True
                    time.sleep(0.1)
                
                # If we couldn't read frames, release and try next
                test_cap.release()
                logging.warning(f"   Camera {cam_index} opened but couldn't read frames")
                
        except Exception as e:
            logging.error(f"   Failed to open camera {cam_index}: {e}")
            continue
    
    # If all attempts fail
    logging.error("❌ FATAL: No working camera found!")
    logging.error("   Please check:")
    logging.error("   1. Camera is connected")
    logging.error("   2. Camera is not being used by another application")
    logging.error("   3. Camera drivers are installed")
    raise Exception("No camera available. Cannot start victim server.")

# Initialize camera on startup
init_camera()


# --------------------------------------------------------
#  CAMERA STREAM
# --------------------------------------------------------
def camera_stream():
    global last_frame

    frame_count = 0
    error_count = 0
    max_consecutive_errors = 10

    while True:
        try:
            # Frame drop (simulated packet loss)
            if random.random() < camera_loss_rate:
                time.sleep(0.04)
                continue

            # Freeze frame (during attack)
            if camera_freeze:
                frame = last_frame
            else:
                # Try to read from real camera
                ret, frame = cap.read()
                
                if not ret or frame is None or frame.size == 0:
                    error_count += 1
                    
                    if error_count >= max_consecutive_errors:
                        logging.error(f"[CAMERA] Too many read errors ({error_count}). Reinitializing...")
                        cap.release()
                        time.sleep(1)
                        init_camera()
                        error_count = 0
                        continue
                    
                    # Use last good frame if read fails
                    if last_frame is not None:
                        frame = last_frame
                    else:
                        time.sleep(0.1)
                        continue
                else:
                    # Successful read
                    error_count = 0
                    last_frame = frame.copy()
                    frame_count += 1

            # Apply delay (simulated network delay during attack)
            if camera_delay > 0:
                time.sleep(camera_delay)

            # Encode JPEG
            encode_param = [int(cv2.IMWRITE_JPEG_QUALITY), 80]
            ret, jpg = cv2.imencode('.jpg', frame, encode_param)
            
            if not ret:
                logging.warning("[CAMERA] JPEG encoding failed")
                continue

            yield (
                b"--frame\r\n"
                b"Content-Type: image/jpeg\r\n\r\n" +
                jpg.tobytes() +
                b"\r\n"
            )
            
            # Target ~30 FPS when not delayed
            if camera_delay == 0:
                time.sleep(0.033)

        except Exception as e:
            logging.error(f"[CAMERA STREAM ERROR] {e}")
            error_count += 1
            time.sleep(0.1)


@app.route("/camera/stream")
def camera_feed():
    return Response(
        camera_stream(),
        mimetype="multipart/x-mixed-replace; boundary=frame"
    )


# --------------------------------------------------------
#  BLOCKING ENDPOINT (CALLED BY DETECTOR)
# --------------------------------------------------------
@app.route("/api/block_ip", methods=["POST"])
def block_ip():
    data = request.get_json(force=True)
    ip = data.get("ip")

    if not ip:
        return jsonify({"ok": False, "error": "no ip"}), 400

    with blocked_lock:
        blocked_ips.add(ip)

    logging.warning(f"[BLOCK] Now blocking IP: {ip}")

    return jsonify({"ok": True, "blocked": ip})


# --------------------------------------------------------
#  AGGREGATION THREAD
# --------------------------------------------------------
def _current_stats_and_reset():
    global packet_timestamps, packet_sizes, src_ip_counts, syn_count

    with lock:
        packets = len(packet_sizes)
        byte_sum = sum(packet_sizes)
        src_copy = dict(src_ip_counts)
        syn = syn_count

        # Reset
        packet_timestamps.clear()
        packet_sizes.clear()
        src_ip_counts.clear()
        syn_count = 0

    return packets, byte_sum, src_copy, syn


def entropy(counts):
    total = sum(counts.values())
    if total == 0:
        return 0
    ent = 0
    for v in counts.values():
        p = v / total
        ent -= p * math.log(p, 2)
    return ent


def aggregator_loop():
    global camera_loss_rate, camera_delay, camera_freeze

    while True:
        time.sleep(AGG_INTERVAL)

        packets, byte_sum, src, syn = _current_stats_and_reset()
        pps = packets / AGG_INTERVAL

        # Disruption rules
        if pps < 5:
            camera_loss_rate = 0.0
            camera_delay = 0.0
            camera_freeze = False

        elif pps < 20:
            camera_loss_rate = 0.05
            camera_delay = 0.05
            camera_freeze = True

        elif pps < 40:
            camera_loss_rate = 0.15
            camera_delay = 0.10
            camera_freeze = True

        else:
            camera_loss_rate = 0.25
            camera_delay = 0.25
            camera_freeze = True

        # 🔥 PRINT PPS + SYN ON TERMINAL
        logging.info(
            f"[CAMERA] PPS={pps:.1f}  SYN={syn}  loss={camera_loss_rate}  delay={camera_delay}  freeze={camera_freeze}"
        )

        # Send to detector
        data = {
            "packets_per_sec": pps,
            "bytes_per_sec": byte_sum / AGG_INTERVAL,
            "unique_src_ips": len(src),
            "unique_dst_ports": 1,
            "avg_packet_size": (byte_sum / packets) if packets else 0,
            "packet_size_variance": 0,
            "flow_duration": AGG_INTERVAL,
            "syn_count": syn,
            "rst_count": 0,
            "ack_count": 0,
            "connection_rate": pps,
            "src_ip_entropy": entropy(src),
            "source_ips": list(src.keys())

        }

        try:
            requests.post(f"{DETECTOR_URL}/api/ingest/camera2", json=data, timeout=2)
        except:
            pass


threading.Thread(target=aggregator_loop, daemon=True).start()


# --------------------------------------------------------
#  NORMAL ROUTES
# --------------------------------------------------------
@app.route("/")
def index():
    return send_from_directory(".", "victim.html")


@app.route("/<path:p>", methods=["GET", "POST", "HEAD", "OPTIONS"])
@app.route("/", methods=["GET", "POST", "HEAD", "OPTIONS"])
def catch_all(p=None):
    global syn_count

    remote = request.remote_addr or "unknown"

    # ============================
    # REAL BLOCKING HERE
    # ============================
    with blocked_lock:
        if remote in blocked_ips:
            logging.warning(f"[BLOCKED REQUEST] {remote} attempted access")
            return ("FORBIDDEN — IP BLOCKED BY MITIGATION", 403)

    size = int(request.headers.get("Content-Length", 0))

    # Read fake TCP flag (HTTP can't read real SYN)
    flags = request.headers.get("X-Flags", "")

    with lock:
        packet_timestamps.append(time.time())
        packet_sizes.append(size)
        src_ip_counts[remote] += 1

        if flags == "SYN":
            syn_count += 1

    return ("OK", 200)


# --------------------------------------------------------
#  SERVER START
# --------------------------------------------------------
if __name__ == "__main__":
    logging.info(f"✅ Victim running at http://{LISTEN_HOST}:{LISTEN_PORT}")
    logging.info(f"📹 Camera stream available at /camera/stream")
    logging.info(f"🎥 Using REAL WEBCAM - Camera ready!")
    app.run(host=LISTEN_HOST, port=LISTEN_PORT, debug=False, threaded=True)