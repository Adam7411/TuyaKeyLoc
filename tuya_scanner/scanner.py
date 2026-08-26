#!/usr/bin/env python3
"""Minimal TuyaKeyLoc scanner placeholder.
This minimal server exists so the addon Docker build can succeed.
Replace with full scanner implementation from your branch when ready.
"""
from flask import Flask, jsonify
import os

app = Flask(__name__, static_folder="/var/www", static_url_path="/")

@app.route("/")
def index():
    return app.send_static_file("index.html")

@app.route("/api/ping")
def ping():
    return jsonify({"ok": True, "name": "TuyaKeyLoc"})

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 7080))
    app.run(host="0.0.0.0", port=port)
