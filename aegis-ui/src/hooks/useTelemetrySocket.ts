import { useState, useEffect, useRef, useCallback } from 'react';
import type { SecurityEvent, MetricsSnapshot } from '../types/telemetry';

const ZERO_METRICS: MetricsSnapshot = {
  totalRequests: 0,
  allowedRequests: 0,
  blockedRequests: 0,
  status2xx: 0,
  status3xx: 0,
  status4xx: 0,
  status5xx: 0,
  threatsBlocked: 0,
  rateLimitsHit: 0,
  zeroTrustDeny: 0,
  currentRps: 0,
  p50LatencyMs: 0,
  p95LatencyMs: 0,
  p99LatencyMs: 0,
  avgLatencyMs: 0,
  activeClients: 0,
  timestamp: Date.now(),
};

import { WS_BASE_URL } from '../config';

export function useTelemetrySocket(wsUrl = WS_BASE_URL) {
  const [connected, setConnected] = useState(false);
  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [metrics, setMetrics] = useState<MetricsSnapshot>(ZERO_METRICS);
  const socketRef = useRef<WebSocket | null>(null);
  const reconnectTimeoutRef = useRef<number | null>(null);

  const connect = useCallback(() => {
    try {
      const ws = new WebSocket(wsUrl);
      socketRef.current = ws;

      ws.onopen = () => {
        setConnected(true);
      };

      ws.onmessage = (msgEvent) => {
        try {
          const data = JSON.parse(msgEvent.data);
          if (data.type === 'INIT_BACKLOG' && Array.isArray(data.events)) {
            setEvents(data.events.reverse());
          } else if (data.type === 'SECURITY_EVENT' && data.event) {
            setEvents((prev) => [data.event, ...prev.slice(0, 99)]);
          } else if (data.type === 'METRICS_UPDATE' && data.stats) {
            setMetrics(data.stats);
          }
        } catch {
          // Silent parse fallback
        }
      };

      ws.onclose = () => {
        setConnected(false);
        reconnectTimeoutRef.current = window.setTimeout(connect, 2000);
      };

      ws.onerror = () => {
        setConnected(false);
        ws.close();
      };
    } catch {
      setConnected(false);
      reconnectTimeoutRef.current = window.setTimeout(connect, 2000);
    }
  }, [wsUrl]);

  useEffect(() => {
    connect();
    return () => {
      if (socketRef.current) {
        socketRef.current.close();
      }
      if (reconnectTimeoutRef.current) {
        clearTimeout(reconnectTimeoutRef.current);
      }
    };
  }, [connect]);

  return { connected, events, metrics, setEvents };
}
