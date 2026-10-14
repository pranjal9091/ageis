#!/bin/bash
set -e

PORT=${PORT:-8080}
export PORT

echo "====================================================="
echo "  AEGIS: Booting Cloud Production Gateway on Port $PORT"
echo "====================================================="

# 1. Substitute $PORT into Nginx configuration
envsubst '${PORT}' < /etc/nginx/templates/default.conf.template > /etc/nginx/conf.d/default.conf

# 2. Start Python Threat Intelligence Engine on 127.0.0.1:5050
echo "[1/3] Starting Python Threat Intel Engine (:5050)..."
cd /app/aegis-intel
PORT=5050 python3 server.py &
PY_PID=$!

# 3. Start Go Proxy Core on 127.0.0.1:8082
echo "[2/3] Starting Go Reverse Proxy Core (:8082)..."
cd /app/aegis-proxy
PORT=8082 ./aegis-gateway &
GO_PID=$!

# Graceful cleanup on SIGTERM
cleanup() {
    echo "[AEGIS] Terminating child processes..."
    kill $PY_PID $GO_PID 2>/dev/null || true
    exit 0
}
trap cleanup SIGINT SIGTERM EXIT

# Give internal services 1s to initialize
sleep 1.0

# 4. Start Nginx in foreground (binds to Render's public $PORT)
echo "[3/3] Starting Nginx Edge Router on port $PORT..."
exec nginx -g "daemon off;"
