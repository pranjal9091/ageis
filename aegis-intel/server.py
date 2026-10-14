import os
from flask import Flask, request, jsonify
from analyzer import ThreatAnalyzer

app = Flask(__name__)
analyzer = ThreatAnalyzer()

@app.after_request
def add_cors_headers(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    return response

@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "service": "Aegis Threat Intelligence Engine",
        "engine": "Shannon-Entropy & Heuristic Scorer v1.2",
        "status": "ONLINE"
    })

@app.route("/api/analyze", methods=["POST", "OPTIONS"])
def analyze_payload():
    if request.method == "OPTIONS":
        return jsonify({}), 200

    data = request.get_json(silent=True) or {}
    payload = data.get("payload", "")
    path = data.get("path", "")
    method = data.get("method", "GET")
    headers = data.get("headers", {})

    result = analyzer.analyze(payload=payload, path=path, method=method, headers=headers)
    return jsonify(result)

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5050))
    print(f"[AEGIS-INTEL] Starting Threat Intelligence Service on http://0.0.0.0:{port}")
    app.run(host="0.0.0.0", port=port, debug=False)


