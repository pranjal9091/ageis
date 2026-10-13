export interface SecurityEvent {
  id: string;
  timestamp: string;
  clientIp: string;
  method: string;
  path: string;
  userAgent: string;
  userId: string;
  userRole: string;
  deviceTrust: number;
  status: number;
  verdict: 'ALLOWED' | 'BLOCKED_WAF' | 'BLOCKED_RATE_LIMIT' | 'BLOCKED_ZERO_TRUST';
  reason: string;
  threatType?: string;
  threatSeverity?: string;
  latencyMs: number;
  upstreamTarget: string;
  matchedPolicy?: string;
  payloadSnippet?: string;
}

export interface MetricsSnapshot {
  totalRequests: number;
  allowedRequests: number;
  blockedRequests: number;
  status2xx: number;
  status3xx: number;
  status4xx: number;
  status5xx: number;
  threatsBlocked: number;
  rateLimitsHit: number;
  zeroTrustDeny: number;
  currentRps: number;
  p50LatencyMs: number;
  p95LatencyMs: number;
  p99LatencyMs: number;
  avgLatencyMs: number;
  activeClients: number;
  timestamp: number;
}

export interface PolicyRule {
  id: string;
  name: string;
  pathPrefix: string;
  methods: string[];
  requiredRoles: string[];
  minDeviceTrust: number;
  rateLimitRps: number;
  enforceMfa: boolean;
  enabled: boolean;
  description: string;
}

export interface SimulatorStatus {
  running: boolean;
  uptime_seconds: number;
  total_sent: number;
  allowed_sent: number;
  threats_sent: number;
  rate_bursts_sent: number;
  zero_trust_denies_sent: number;
}

export interface AnomalySignal {
  type: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM';
  details: string;
}

export interface EntropyAnalysisResult {
  risk_score: number;
  shannon_entropy: number;
  classification: string;
  recommended_action: string;
  anomaly_signals: AnomalySignal[];
  inspected_length: number;
}
