import os
import sys

# Add project root to Python path so we can import `mitigation` and `ml`
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, PROJECT_ROOT)
# Also add backend/ itself so `services.*` and `routes.*` resolve correctly
sys.path.insert(0, os.path.dirname(__file__))

from flask import Flask, send_from_directory
from flask_cors import CORS

from routes.logs import logs_bp
from routes.detect import detect_bp
from routes.alerts import alerts_bp

app = Flask(__name__)
CORS(app)

# ── API Blueprints ──
app.register_blueprint(logs_bp)
app.register_blueprint(detect_bp)
app.register_blueprint(alerts_bp)

# ── Serve Frontend ──
FRONTEND_DIR = os.path.join(PROJECT_ROOT, "frontend")

@app.route("/")
def serve_index():
    return send_from_directory(FRONTEND_DIR, "index.html")

@app.route("/<path:filename>")
def serve_static(filename):
    if os.path.isfile(os.path.join(FRONTEND_DIR, filename)):
        return send_from_directory(FRONTEND_DIR, filename)
    return "Not Found", 404

if __name__ == "__main__":
    print("🛡️  SkyShield backend starting on http://localhost:8000")
    print(f"📂 Serving frontend from {FRONTEND_DIR}")
    app.run(port=8000, debug=True, use_reloader=False)
