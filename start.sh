#!/bin/bash
# ==============================================================================
# AEGIS: Zero-Trust Reverse Proxy & Real-Time Security Telemetry Platform
# Unified Start Script
# ==============================================================================

set -e

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$DIR"

echo "======================================================================"
echo "      AEGIS: ZERO-TRUST REVERSE PROXY & TELEMETRY PLATFORM            "
echo "======================================================================"

# Function to kill child processes on exit
cleanup() {
    echo ""
    echo "[AEGIS] Shutting down all microservices..."
    kill $(jobs -p) 2>/dev/null || true
    echo "[AEGIS] All services terminated cleanly."
    exit 0
}
trap cleanup SIGINT SIGTERM EXIT

# 1. Start Go Proxy & Control Plane
echo "[1/3] Starting Aegis Go Core Engine (:8080) & Internal Upstreams (:8081)..."
cd "$DIR/aegis-proxy"
go run . &
GO_PID=$!
sleep 1.5

# 2. Start Python Threat Intelligence Service
echo "[2/3] Starting Python Threat Intelligence & Entropy Service (:5050)..."
cd "$DIR/aegis-intel"
python3 server.py &
PY_PID=$!
sleep 1.0

# 3. Start Frontend Dashboard
echo "[3/3] Starting SOC Observability Dashboard (:5173)..."
cd "$DIR/aegis-ui"
npm run dev -- --host &
UI_PID=$!
sleep 1.5

echo ""
echo "======================================================================"
echo "  AEGIS IS RUNNING LOCALLY"
echo "----------------------------------------------------------------------"
echo "  SOC Dashboard:    http://localhost:5173"
echo "  Go Proxy Gateway: http://localhost:8080"
echo "  WebSocket Stream: ws://localhost:8080/ws/telemetry"
echo "  Python Intel API: http://localhost:5050"
echo "  Internal Upstream: http://localhost:8081"
echo "======================================================================"
echo "Press Ctrl+C to terminate all services."

# Wait indefinitely
wait
