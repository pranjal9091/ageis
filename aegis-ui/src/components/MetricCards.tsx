import React from 'react';
import type { MetricsSnapshot } from '../types/telemetry';
import { Activity, ShieldAlert, Clock, Radio, Users } from 'lucide-react';

interface MetricCardsProps {
  metrics: MetricsSnapshot;
}

export const MetricCards: React.FC<MetricCardsProps> = ({ metrics }) => {
  const blockPercentage =
    metrics.totalRequests > 0
      ? ((metrics.blockedRequests / metrics.totalRequests) * 100).toFixed(1)
      : '0.0';

  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3.5">
      {/* 1. Throughput */}
      <div className="light-card rounded-xl p-4 transition-all hover:border-slate-300">
        <div className="flex items-center justify-between text-slate-500 mb-2">
          <span className="text-[11px] font-bold uppercase tracking-wider text-slate-500">Throughput</span>
          <div className="p-1.5 rounded-md bg-blue-50 text-blue-600">
            <Activity className="h-3.5 w-3.5" />
          </div>
        </div>
        <div className="flex items-baseline space-x-1.5">
          <span className="text-2xl font-bold font-mono-code text-slate-900 tracking-tight">
            {metrics.currentRps > 0 ? metrics.currentRps.toFixed(1) : '0.0'}
          </span>
          <span className="text-xs text-slate-500 font-mono-code">req/s</span>
        </div>
        <div className="mt-2 text-[11px] text-slate-500 font-medium">
          <span>Real-time rolling tick</span>
        </div>
      </div>

      {/* 2. Latency */}
      <div className="light-card rounded-xl p-4 transition-all hover:border-slate-300">
        <div className="flex items-center justify-between text-slate-500 mb-2">
          <span className="text-[11px] font-bold uppercase tracking-wider text-slate-500">P99 Latency</span>
          <div className="p-1.5 rounded-md bg-emerald-50 text-emerald-600">
            <Clock className="h-3.5 w-3.5" />
          </div>
        </div>
        <div className="flex items-baseline space-x-1.5">
          <span className="text-2xl font-bold font-mono-code text-slate-900 tracking-tight">
            {metrics.totalRequests > 0 && metrics.p99LatencyMs > 0 ? metrics.p99LatencyMs.toFixed(2) : '—'}
          </span>
          <span className="text-xs text-slate-500 font-mono-code">{metrics.totalRequests > 0 ? 'ms' : ''}</span>
        </div>
        <div className="mt-2 text-[11px] text-slate-500 font-medium">
          <span>Median (P50): {metrics.totalRequests > 0 ? `${metrics.p50LatencyMs.toFixed(2)}ms` : '—'}</span>
        </div>
      </div>

      {/* 3. Total Inspected Packets */}
      <div className="light-card rounded-xl p-4 transition-all hover:border-slate-300">
        <div className="flex items-center justify-between text-slate-500 mb-2">
          <span className="text-[11px] font-bold uppercase tracking-wider text-slate-500">Total Packets</span>
          <div className="p-1.5 rounded-md bg-slate-100 text-slate-700">
            <Radio className="h-3.5 w-3.5" />
          </div>
        </div>
        <div className="flex items-baseline space-x-1.5">
          <span className="text-2xl font-bold font-mono-code text-slate-900 tracking-tight">
            {metrics.totalRequests.toLocaleString()}
          </span>
          <span className="text-xs text-slate-500 font-mono-code">inspected</span>
        </div>
        <div className="mt-2 text-[11px] text-slate-500 flex items-center space-x-1.5 font-medium">
          <span className="text-emerald-700 font-mono-code">{metrics.allowedRequests} passed</span>
          <span className="text-slate-300">•</span>
          <span className="text-slate-600 font-mono-code">{metrics.status2xx} 2xx</span>
        </div>
      </div>

      {/* 4. Security Interceptions */}
      <div className="light-card rounded-xl p-4 transition-all hover:border-slate-300">
        <div className="flex items-center justify-between text-slate-500 mb-2">
          <span className="text-[11px] font-bold uppercase tracking-wider text-slate-500">Interceptions</span>
          <div className="p-1.5 rounded-md bg-rose-50 text-rose-600">
            <ShieldAlert className="h-3.5 w-3.5" />
          </div>
        </div>
        <div className="flex items-baseline space-x-1.5">
          <span className="text-2xl font-bold font-mono-code text-rose-600 tracking-tight">
            {metrics.blockedRequests.toLocaleString()}
          </span>
          <span className="text-xs text-slate-500 font-mono-code">({blockPercentage}%)</span>
        </div>
        <div className="mt-2 text-[11px] text-slate-500 flex items-center space-x-1.5 font-medium">
          <span className="text-rose-700 font-mono-code">{metrics.threatsBlocked} WAF</span>
          <span className="text-slate-300">•</span>
          <span className="text-amber-700 font-mono-code">{metrics.zeroTrustDeny} Policy</span>
        </div>
      </div>

      {/* 5. Active Edge Clients */}
      <div className="light-card rounded-xl p-4 transition-all hover:border-slate-300">
        <div className="flex items-center justify-between text-slate-500 mb-2">
          <span className="text-[11px] font-bold uppercase tracking-wider text-slate-500">Active Clients</span>
          <div className="p-1.5 rounded-md bg-indigo-50 text-indigo-600">
            <Users className="h-3.5 w-3.5" />
          </div>
        </div>
        <div className="flex items-baseline space-x-1.5">
          <span className="text-2xl font-bold font-mono-code text-slate-900 tracking-tight">
            {metrics.activeClients}
          </span>
          <span className="text-xs text-slate-500 font-mono-code">fingerprints</span>
        </div>
        <div className="mt-2 text-[11px] text-slate-500 font-medium">
          <span>Rate limits: <span className="font-mono-code text-slate-800">{metrics.rateLimitsHit}</span></span>
        </div>
      </div>
    </div>
  );
};
