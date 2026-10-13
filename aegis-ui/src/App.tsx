import { useState, useEffect } from 'react';
import { useTelemetrySocket } from './hooks/useTelemetrySocket';
import { Navbar } from './components/Navbar';
import { MetricCards } from './components/MetricCards';
import { LivePacketStream } from './components/LivePacketStream';
import { RequestSandbox } from './components/RequestSandbox';
import { PolicyManager } from './components/PolicyManager';
import { ThreatIntelView } from './components/ThreatIntelView';
import { TopologyGraph } from './components/TopologyGraph';
import { ThreatForensicsModal } from './components/ThreatForensicsModal';
import type { SecurityEvent } from './types/telemetry';

export function App() {
  const [activeTab, setActiveTab] = useState('observability');
  const [selectedEvent, setSelectedEvent] = useState<SecurityEvent | null>(null);
  const [resetLoading, setResetLoading] = useState(false);
  const [currentUpstream, setCurrentUpstream] = useState('https://httpbin.org');

  // Real WebSocket Telemetry Hook
  const { connected, events, metrics } = useTelemetrySocket();

  // Fetch current proxy default upstream
  const fetchUpstream = async () => {
    try {
      const res = await fetch('http://127.0.0.1:8080/api/control/upstream');
      if (res.ok) {
        const data = await res.json();
        if (data.currentUpstream) {
          setCurrentUpstream(data.currentUpstream);
        }
      }
    } catch {
      // Fallback
    }
  };

  useEffect(() => {
    fetchUpstream();
  }, []);

  const handleSetUpstream = async (newTarget: string) => {
    try {
      const res = await fetch('http://127.0.0.1:8080/api/control/upstream', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target: newTarget }),
      });
      if (res.ok) {
        setCurrentUpstream(newTarget);
      }
    } catch {
      // Fallback
    }
  };

  const handleResetTelemetry = async () => {
    setResetLoading(true);
    try {
      await fetch('http://127.0.0.1:8080/api/control/reset', { method: 'POST' });
    } catch {
      // Ignore
    } finally {
      setTimeout(() => setResetLoading(false), 500);
    }
  };

  return (
    <div className="min-h-screen bg-[#f8fafc] text-slate-900 flex flex-col font-sans selection:bg-slate-200 selection:text-slate-900">
      {/* Top Navbar */}
      <Navbar
        activeTab={activeTab}
        setActiveTab={setActiveTab}
        wsConnected={connected}
        onResetTelemetry={handleResetTelemetry}
        resetLoading={resetLoading}
        currentUpstream={currentUpstream}
      />

      {/* Main Container */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-5 space-y-4">
        {/* Metric Ribbon */}
        <MetricCards metrics={metrics} />

        {/* Tab View Switching */}
        <div>
          {activeTab === 'observability' && (
            <LivePacketStream events={events} onSelectEvent={setSelectedEvent} />
          )}

          {activeTab === 'sandbox' && (
            <RequestSandbox
              currentUpstream={currentUpstream}
              onSetUpstream={handleSetUpstream}
            />
          )}

          {activeTab === 'policies' && <PolicyManager />}

          {activeTab === 'intel' && <ThreatIntelView />}

          {activeTab === 'topology' && <TopologyGraph currentUpstream={currentUpstream} />}
        </div>
      </main>

      {/* Deep Forensics Modal */}
      <ThreatForensicsModal
        event={selectedEvent}
        onClose={() => setSelectedEvent(null)}
      />

      {/* Footer */}
      <footer className="border-t border-slate-200 bg-white py-3.5 text-center text-xs text-slate-500 font-mono-code mt-auto">
        <div className="max-w-7xl mx-auto px-4 flex flex-col sm:flex-row items-center justify-between gap-2">
          <span className="font-medium">Aegis Zero-Trust Platform • Distributed Edge & Reverse Proxy Architecture</span>
          <span className="text-slate-600 font-bold">Go 1.26 + Python 3.14 + React 19 + TypeScript</span>
        </div>
      </footer>
    </div>
  );
}

export default App;
