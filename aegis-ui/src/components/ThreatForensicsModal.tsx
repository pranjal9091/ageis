import React from 'react';
import type { SecurityEvent } from '../types/telemetry';
import { X, ShieldAlert, ShieldCheck, Terminal, Key, AlertCircle } from 'lucide-react';

interface ThreatForensicsModalProps {
  event: SecurityEvent | null;
  onClose: () => void;
}

export const ThreatForensicsModal: React.FC<ThreatForensicsModalProps> = ({ event, onClose }) => {
  if (!event) return null;

  const isBlocked = event.verdict !== 'ALLOWED';

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/40 backdrop-blur-xs animate-in fade-in duration-100">
      <div className="bg-white border border-slate-300 rounded-xl w-full max-w-xl overflow-hidden shadow-xl">
        {/* Modal Header */}
        <div className="p-4 border-b border-slate-200 flex items-center justify-between bg-slate-50/70">
          <div className="flex items-center space-x-2.5">
            <div
              className={`p-1.5 rounded-lg border ${
                isBlocked
                  ? 'bg-rose-50 border-rose-200 text-rose-700'
                  : 'bg-emerald-50 border-emerald-200 text-emerald-700'
              }`}
            >
              {isBlocked ? <ShieldAlert className="h-4.5 w-4.5" /> : <ShieldCheck className="h-4.5 w-4.5" />}
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <span className="text-sm font-bold text-slate-900 font-mono-code">{event.id}</span>
                <span
                  className={`text-[10px] font-mono-code px-2 py-0.5 rounded-full font-bold uppercase ${
                    event.verdict === 'ALLOWED'
                      ? 'bg-emerald-100 text-emerald-800 border border-emerald-200'
                      : 'bg-rose-100 text-rose-800 border border-rose-200'
                  }`}
                >
                  {event.verdict}
                </span>
              </div>
              <p className="text-[11px] text-slate-500 font-mono-code mt-0.5">
                {new Date(event.timestamp).toISOString()} • {event.latencyMs.toFixed(2)}ms latency
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="text-slate-400 hover:text-slate-700 p-1.5 rounded-lg hover:bg-slate-100 transition cursor-pointer"
          >
            <X className="h-4.5 w-4.5" />
          </button>
        </div>

        {/* Modal Content */}
        <div className="p-5 space-y-4 max-h-[70vh] overflow-y-auto">
          {/* Reason Alert */}
          <div
            className={`p-3 rounded-lg border text-xs flex items-start space-x-2.5 ${
              isBlocked
                ? 'bg-rose-50 border-rose-200 text-rose-900'
                : 'bg-emerald-50 border-emerald-200 text-emerald-900'
            }`}
          >
            <AlertCircle className="h-4 w-4 shrink-0 mt-0.5" />
            <div>
              <span className="font-bold">Security Decision: </span>
              {event.reason}
            </div>
          </div>

          {/* Grid Metadata */}
          <div className="grid grid-cols-2 gap-2.5 text-xs">
            <div className="p-3 rounded-lg bg-slate-50 border border-slate-200">
              <span className="text-slate-500 block mb-1 font-mono-code uppercase text-[10px] font-bold">Client Address</span>
              <span className="text-slate-900 font-mono-code font-semibold">{event.clientIp}</span>
            </div>

            <div className="p-3 rounded-lg bg-slate-50 border border-slate-200">
              <span className="text-slate-500 block mb-1 font-mono-code uppercase text-[10px] font-bold">Request Target</span>
              <span className="text-slate-900 font-mono-code font-semibold truncate block">
                {event.method} {event.path}
              </span>
            </div>

            <div className="p-3 rounded-lg bg-slate-50 border border-slate-200">
              <span className="text-slate-500 block mb-1 font-mono-code uppercase text-[10px] font-bold">Subject Identity</span>
              <div className="flex items-center space-x-1.5">
                <Key className="h-3.5 w-3.5 text-slate-500" />
                <span className="text-slate-900 font-mono-code font-semibold truncate">{event.userId}</span>
              </div>
            </div>

            <div className="p-3 rounded-lg bg-slate-50 border border-slate-200">
              <span className="text-slate-500 block mb-1 font-mono-code uppercase text-[10px] font-bold">Posture & Role</span>
              <div className="flex items-center space-x-1.5">
                <span className="font-mono-code text-slate-900 font-bold">{event.deviceTrust}/100</span>
                <span className="text-[10px] text-slate-500 font-medium">({event.userRole})</span>
              </div>
            </div>
          </div>

          {/* Malicious Payload Snippet if caught */}
          {event.payloadSnippet && (
            <div>
              <span className="text-xs font-bold text-rose-700 block mb-1.5 flex items-center space-x-1.5">
                <Terminal className="h-3.5 w-3.5 text-rose-600" />
                <span>Extracted Threat Vector ({event.threatType || 'WAF Filter'})</span>
              </span>
              <div className="p-3 rounded-lg bg-slate-950 border border-slate-900 text-rose-400 font-mono-code text-xs overflow-x-auto whitespace-pre-wrap break-all shadow-inner">
                {event.payloadSnippet}
              </div>
            </div>
          )}

          {/* Technical Diagnostics */}
          <div className="p-3.5 rounded-lg bg-slate-50 border border-slate-200 text-xs space-y-1.5 font-mono-code">
            <div className="flex justify-between border-b border-slate-200/80 pb-1">
              <span className="text-slate-500 font-medium">Upstream Destination</span>
              <span className="text-slate-900 font-semibold">{event.upstreamTarget}</span>
            </div>
            <div className="flex justify-between border-b border-slate-200/80 pb-1">
              <span className="text-slate-500 font-medium">Matched Policy</span>
              <span className="text-slate-900 font-semibold">{event.matchedPolicy || 'default-allow'}</span>
            </div>
            <div className="flex justify-between border-b border-slate-200/80 pb-1">
              <span className="text-slate-500 font-medium">HTTP Response Status</span>
              <span className="text-slate-900 font-bold">{event.status}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-500 font-medium">User Agent</span>
              <span className="text-slate-700 truncate max-w-xs">{event.userAgent}</span>
            </div>
          </div>
        </div>

        {/* Modal Footer */}
        <div className="p-3.5 border-t border-slate-200 bg-slate-50/70 flex justify-end">
          <button
            onClick={onClose}
            className="px-4 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-white text-xs font-semibold transition cursor-pointer shadow-2xs"
          >
            Dismiss
          </button>
        </div>
      </div>
    </div>
  );
};
