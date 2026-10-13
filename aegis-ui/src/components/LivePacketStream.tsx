import React, { useState } from 'react';
import type { SecurityEvent } from '../types/telemetry';
import { Filter, Eye, ShieldCheck, ShieldAlert } from 'lucide-react';

interface LivePacketStreamProps {
  events: SecurityEvent[];
  onSelectEvent: (event: SecurityEvent) => void;
}

export const LivePacketStream: React.FC<LivePacketStreamProps> = ({ events, onSelectEvent }) => {
  const [filter, setFilter] = useState<'ALL' | 'BLOCKED' | 'ALLOWED'>('ALL');
  const [searchTerm, setSearchTerm] = useState('');

  const filteredEvents = events.filter((ev) => {
    if (filter === 'BLOCKED' && ev.verdict === 'ALLOWED') return false;
    if (filter === 'ALLOWED' && ev.verdict !== 'ALLOWED') return false;
    if (searchTerm) {
      const q = searchTerm.toLowerCase();
      return (
        ev.path.toLowerCase().includes(q) ||
        ev.clientIp.toLowerCase().includes(q) ||
        ev.userId.toLowerCase().includes(q) ||
        ev.verdict.toLowerCase().includes(q)
      );
    }
    return true;
  });

  return (
    <div className="light-card rounded-xl overflow-hidden">
      {/* Header with Search and Filter Tabs */}
      <div className="p-4 border-b border-slate-200 bg-white flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <div className="text-xs font-bold text-slate-900 flex items-center space-x-2">
            <span>In-Flight Telemetry Feed</span>
            <span className="text-[10px] px-2 py-0.5 rounded-full bg-slate-100 text-slate-700 font-bold font-mono-code border border-slate-200">
              {filteredEvents.length} events
            </span>
          </div>
          <p className="text-[11px] text-slate-500 mt-0.5">
            Streaming network requests inspected across WAF, Rate Limiting, and Zero-Trust policies.
          </p>
        </div>

        <div className="flex items-center space-x-2">
          {/* Search Box */}
          <input
            type="text"
            placeholder="Filter IP, path, user..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="px-3 py-1.5 rounded-lg bg-slate-50 border border-slate-300 text-xs text-slate-900 placeholder-slate-400 focus:outline-none focus:border-slate-500 focus:bg-white w-48 font-mono-code transition"
          />

          {/* Filter Pills */}
          <div className="flex items-center bg-slate-100 p-0.5 rounded-lg border border-slate-200 text-xs">
            <button
              onClick={() => setFilter('ALL')}
              className={`px-2.5 py-1 rounded-md transition text-xs font-semibold ${
                filter === 'ALL' ? 'bg-white text-slate-900 shadow-2xs' : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              All
            </button>
            <button
              onClick={() => setFilter('BLOCKED')}
              className={`px-2.5 py-1 rounded-md transition text-xs font-semibold ${
                filter === 'BLOCKED' ? 'bg-white text-rose-700 shadow-2xs' : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              Blocks
            </button>
            <button
              onClick={() => setFilter('ALLOWED')}
              className={`px-2.5 py-1 rounded-md transition text-xs font-semibold ${
                filter === 'ALLOWED' ? 'bg-white text-emerald-700 shadow-2xs' : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              Passed
            </button>
          </div>
        </div>
      </div>

      {/* Dense Live Table */}
      <div className="overflow-x-auto max-h-[500px]">
        <table className="w-full text-left text-xs border-collapse">
          <thead className="bg-slate-50/90 sticky top-0 z-10 border-b border-slate-200 text-slate-600 font-mono-code text-[11px] uppercase tracking-wider">
            <tr>
              <th className="py-2.5 px-4 font-bold">Time</th>
              <th className="py-2.5 px-3 font-bold">Method</th>
              <th className="py-2.5 px-4 font-bold">Target Path</th>
              <th className="py-2.5 px-4 font-bold">Identity / Role</th>
              <th className="py-2.5 px-3 font-bold text-center">Posture</th>
              <th className="py-2.5 px-4 font-bold">Verdict</th>
              <th className="py-2.5 px-3 font-bold text-right">Status</th>
              <th className="py-2.5 px-3 font-bold text-right">Latency</th>
              <th className="py-2.5 px-3 font-bold text-center">Inspect</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-100 bg-white">
            {filteredEvents.length === 0 ? (
              <tr>
                <td colSpan={9} className="py-16 text-center text-slate-400">
                  <div className="flex flex-col items-center justify-center space-y-1.5">
                    <Filter className="h-6 w-6 text-slate-300" />
                    <span className="text-xs font-medium">Awaiting incoming network traffic. Send real HTTP requests via the Live Sandbox or cURL.</span>
                  </div>
                </td>
              </tr>
            ) : (
              filteredEvents.map((ev, idx) => {
                const isBlocked = ev.verdict !== 'ALLOWED';
                const timeStr = new Date(ev.timestamp).toLocaleTimeString([], {
                  hour12: false,
                  hour: '2-digit',
                  minute: '2-digit',
                  second: '2-digit',
                });

                return (
                  <tr
                    key={`${ev.id}-${idx}`}
                    onClick={() => onSelectEvent(ev)}
                    className="hover:bg-slate-50 cursor-pointer transition-colors duration-100 group"
                  >
                    {/* Timestamp */}
                    <td className="py-2.5 px-4 font-mono-code text-slate-500 whitespace-nowrap text-[11px]">
                      {timeStr}
                    </td>

                    {/* Method */}
                    <td className="py-2.5 px-3 whitespace-nowrap font-mono-code">
                      <span
                        className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                          ev.method === 'GET'
                            ? 'bg-blue-50 text-blue-700 border border-blue-200'
                            : 'bg-emerald-50 text-emerald-700 border border-emerald-200'
                        }`}
                      >
                        {ev.method}
                      </span>
                    </td>

                    {/* Path */}
                    <td className="py-2.5 px-4 font-mono-code text-slate-900 font-medium max-w-xs truncate" title={ev.path}>
                      {ev.path}
                    </td>

                    {/* Identity & Role */}
                    <td className="py-2.5 px-4 whitespace-nowrap">
                      <div className="flex items-center space-x-1.5">
                        <span className="text-slate-800 font-medium truncate max-w-[140px]" title={ev.userId}>
                          {ev.userId}
                        </span>
                        <span className="text-[10px] px-1.5 py-0.2 rounded bg-slate-100 text-slate-600 font-mono-code border border-slate-200">
                          {ev.userRole}
                        </span>
                      </div>
                    </td>

                    {/* Device Trust */}
                    <td className="py-2.5 px-3 text-center whitespace-nowrap font-mono-code text-[11px]">
                      <span
                        className={`px-2 py-0.5 rounded-full text-[10px] font-bold ${
                          ev.deviceTrust >= 80
                            ? 'text-emerald-700 bg-emerald-50 border border-emerald-200'
                            : ev.deviceTrust >= 60
                            ? 'text-amber-700 bg-amber-50 border border-amber-200'
                            : 'text-rose-700 bg-rose-50 border border-rose-200'
                        }`}
                      >
                        {ev.deviceTrust}/100
                      </span>
                    </td>

                    {/* Verdict */}
                    <td className="py-2.5 px-4 whitespace-nowrap">
                      <div className="flex items-center space-x-1.5">
                        {isBlocked ? (
                          <ShieldAlert className="h-3.5 w-3.5 text-rose-600 shrink-0" />
                        ) : (
                          <ShieldCheck className="h-3.5 w-3.5 text-emerald-600 shrink-0" />
                        )}
                        <span
                          className={`font-mono-code text-[11px] font-semibold ${
                            ev.verdict === 'ALLOWED'
                              ? 'text-emerald-700'
                              : 'text-rose-700'
                          }`}
                        >
                          {ev.verdict}
                        </span>
                      </div>
                    </td>

                    {/* Status Code */}
                    <td className="py-2.5 px-3 text-right font-mono-code font-bold">
                      <span
                        className={
                          ev.status < 300
                            ? 'text-emerald-700'
                            : ev.status === 429
                            ? 'text-amber-700'
                            : 'text-rose-700'
                        }
                      >
                        {ev.status}
                      </span>
                    </td>

                    {/* Latency */}
                    <td className="py-2.5 px-3 text-right font-mono-code text-slate-600 font-medium text-[11px]">
                      {ev.latencyMs.toFixed(2)}ms
                    </td>

                    {/* Inspector Icon */}
                    <td className="py-2.5 px-3 text-center text-slate-400 group-hover:text-slate-900 transition">
                      <Eye className="h-3.5 w-3.5 mx-auto" />
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};
