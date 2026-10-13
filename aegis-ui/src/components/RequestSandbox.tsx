import React, { useState } from 'react';
import { Send, Globe, ShieldAlert, CheckCircle2, AlertOctagon, Terminal, Link2, Settings } from 'lucide-react';

interface RequestSandboxProps {
  currentUpstream: string;
  onSetUpstream: (url: string) => Promise<void>;
}

export const RequestSandbox: React.FC<RequestSandboxProps> = ({ currentUpstream, onSetUpstream }) => {
  const [targetServer, setTargetServer] = useState(currentUpstream || 'https://httpbin.org');
  const [method, setMethod] = useState<'GET' | 'POST'>('GET');
  const [path, setPath] = useState('/get');
  const [userId, setUserId] = useState('pranjal.singh@corp.aegis');
  const [userRole, setUserRole] = useState('super_admin');
  const [deviceTrust, setDeviceTrust] = useState(92);
  const [customToken, setCustomToken] = useState('');
  const [requestBody, setRequestBody] = useState('{\n  "query": "active_users",\n  "timestamp": 1728839000\n}');
  
  const [loading, setLoading] = useState(false);
  const [savingUpstream, setSavingUpstream] = useState(false);
  const [response, setResponse] = useState<any>(null);
  const [executionTime, setExecutionTime] = useState<number | null>(null);

  // Real, genuine live internet and zero-trust testing presets
  const realPresets = [
    {
      title: 'Public Httpbin Echo (Live Internet)',
      desc: 'Real live public API showing headers & IP reflected by Aegis',
      target: 'https://httpbin.org',
      method: 'GET' as const,
      path: '/get',
      user: 'pranjal.singh@corp.aegis',
      role: 'devops',
      trust: 90,
      body: '',
    },
    {
      title: 'Live JSONPlaceholder (Live Internet)',
      desc: 'Fetches real live REST resource through the Go proxy',
      target: 'https://jsonplaceholder.typicode.com',
      method: 'GET' as const,
      path: '/todos/1',
      user: 'pranjal.singh@corp.aegis',
      role: 'super_admin',
      trust: 95,
      body: '',
    },
    {
      title: 'SQL Injection Attack (Intercepted by WAF)',
      desc: 'In-flight WAF intercepts and blocks attack before reaching live server',
      target: 'https://httpbin.org',
      method: 'GET' as const,
      path: "/get?search=products' OR '1'='1'--",
      user: 'security.auditor@corp.aegis',
      role: 'super_admin',
      trust: 90,
      body: '',
    },
    {
      title: 'XSS Attack (Intercepted by WAF)',
      desc: 'In-flight script tag injection dropped with 403 Forbidden',
      target: 'https://httpbin.org',
      method: 'GET' as const,
      path: "/get?q=<script>alert(1)</script>",
      user: 'pen.tester@corp.aegis',
      role: 'super_admin',
      trust: 85,
      body: '',
    },
    {
      title: 'Zero-Trust Role Quarantine',
      desc: 'Intern role blocked from /billing (requires finance_lead or super_admin)',
      target: 'http://127.0.0.1:8081',
      method: 'GET' as const,
      path: '/api/v1/billing/ledger',
      user: 'guest.intern@corp.aegis',
      role: 'intern',
      trust: 85,
      body: '',
    },
    {
      title: 'Untrusted Device Quarantine',
      desc: 'Finance user blocked due to low device compliance (<80 threshold)',
      target: 'http://127.0.0.1:8081',
      method: 'GET' as const,
      path: '/api/v1/billing/ledger',
      user: 'neha.sharma@corp.aegis',
      role: 'finance_lead',
      trust: 45,
      body: '',
    },
  ];

  const applyPreset = (preset: typeof realPresets[0]) => {
    setTargetServer(preset.target);
    setMethod(preset.method);
    setPath(preset.path);
    setUserId(preset.user);
    setUserRole(preset.role);
    setDeviceTrust(preset.trust);
    if (preset.body) setRequestBody(preset.body);
  };

  const handleSaveAsDefaultUpstream = async () => {
    try {
      setSavingUpstream(true);
      await onSetUpstream(targetServer);
    } finally {
      setSavingUpstream(false);
    }
  };

  const handleExecute = async () => {
    setLoading(true);
    setResponse(null);
    const start = performance.now();

    try {
      const headers: Record<string, string> = {
        'Content-Type': 'application/json',
        'X-User-Id': userId.trim() || 'anonymous.guest',
        'X-User-Role': userRole,
        'X-Device-Trust': deviceTrust.toString(),
        'X-Aegis-Upstream': targetServer.trim(),
      };

      if (customToken.trim()) {
        headers['Authorization'] = customToken.startsWith('Bearer ') ? customToken : `Bearer ${customToken}`;
      }

      const host = window.location.hostname || 'localhost';
      const proxyUrl = `http://${host}:8080${path.startsWith('/') ? path : '/' + path}`;
      const res = await fetch(proxyUrl, {
        method,
        headers,
        body: method === 'POST' ? requestBody : undefined,
      });

      const elapsed = performance.now() - start;
      setExecutionTime(elapsed);

      const contentType = res.headers.get('content-type') || '';
      let data;
      if (contentType.includes('application/json')) {
        data = await res.json();
      } else {
        data = await res.text();
      }

      setResponse({
        status: res.status,
        statusText: res.statusText,
        verdict: res.headers.get('x-aegis-verdict') || (res.status === 200 ? 'ALLOWED' : 'BLOCKED'),
        headers: Object.fromEntries(res.headers.entries()),
        data,
      });
    } catch (err: any) {
      const elapsed = performance.now() - start;
      setExecutionTime(elapsed);
      setResponse({
        status: 0,
        statusText: 'Connection Error',
        verdict: 'NETWORK_ERROR',
        headers: {},
        data: { error: 'Failed to communicate with Go proxy on :8080', details: err.message },
      });
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-4">
      {/* Target Upstream Server Link Bar */}
      <div className="light-card rounded-xl p-4 flex flex-col md:flex-row md:items-center justify-between gap-3">
        <div className="flex items-center space-x-3">
          <div className="p-2 rounded-lg bg-slate-100 text-slate-700">
            <Globe className="h-4 w-4 shrink-0" />
          </div>
          <div>
            <div className="text-xs font-bold text-slate-900">
              Live Upstream Server Link
            </div>
            <div className="text-[11px] text-slate-500 font-medium">
              Aegis proxies in-flight requests directly to this destination.
            </div>
          </div>
        </div>

        <div className="flex items-center space-x-2 flex-1 max-w-lg">
          <div className="relative flex-1">
            <Link2 className="h-3.5 w-3.5 text-slate-400 absolute left-3 top-2.5" />
            <input
              type="text"
              value={targetServer}
              onChange={(e) => setTargetServer(e.target.value)}
              placeholder="e.g. https://httpbin.org or https://jsonplaceholder.typicode.com"
              className="w-full pl-8 pr-3 py-1.5 rounded-lg bg-slate-50 border border-slate-300 text-xs font-mono-code text-slate-900 focus:outline-none focus:border-slate-500 focus:bg-white transition"
            />
          </div>
          <button
            onClick={handleSaveAsDefaultUpstream}
            disabled={savingUpstream || !targetServer}
            className="px-3 py-1.5 rounded-lg bg-white hover:bg-slate-50 text-slate-700 text-xs font-semibold border border-slate-300 transition shadow-2xs flex items-center space-x-1 shrink-0"
            title="Sets this URL as the default proxy upstream in Go"
          >
            <Settings className="h-3 w-3 text-slate-500" />
            <span>{savingUpstream ? 'Saving...' : 'Set Default'}</span>
          </button>
        </div>
      </div>

      {/* Real Test Presets */}
      <div>
        <div className="text-xs font-bold text-slate-700 mb-2">
          Interactive Test Presets
        </div>
        <div className="grid grid-cols-1 md:grid-cols-3 lg:grid-cols-5 gap-2.5">
          {realPresets.map((p, idx) => (
            <button
              key={idx}
              onClick={() => applyPreset(p)}
              className="text-left p-3 rounded-lg light-card-interactive transition group cursor-pointer"
            >
              <div className="text-xs font-semibold text-slate-900 group-hover:text-blue-600 truncate">
                {p.title}
              </div>
              <div className="text-[11px] text-slate-500 mt-1 line-clamp-2 leading-relaxed">
                {p.desc}
              </div>
            </button>
          ))}
        </div>
      </div>

      {/* Main Sandbox Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
        {/* Left Column: Request Form */}
        <div className="lg:col-span-6 light-card rounded-xl p-5 space-y-4">
          <div className="flex items-center justify-between pb-2 border-b border-slate-100">
            <span className="text-xs font-bold text-slate-900 flex items-center space-x-2">
              <Terminal className="h-4 w-4 text-slate-700" />
              <span>Probe Request Builder</span>
            </span>
            <span className="text-[11px] font-mono-code text-slate-500 bg-slate-100 px-2 py-0.5 rounded">
              Gateway: 127.0.0.1:8080
            </span>
          </div>

          {/* Method & Path */}
          <div>
            <label className="text-[11px] font-bold text-slate-700 block mb-1">
              Method & Path
            </label>
            <div className="flex space-x-2">
              <select
                value={method}
                onChange={(e) => setMethod(e.target.value as any)}
                className="px-3 py-2 rounded-lg bg-slate-50 border border-slate-300 text-xs font-mono-code font-bold text-slate-900 focus:outline-none focus:border-slate-500 focus:bg-white"
              >
                <option value="GET">GET</option>
                <option value="POST">POST</option>
              </select>
              <input
                type="text"
                value={path}
                onChange={(e) => setPath(e.target.value)}
                className="flex-1 px-3 py-2 rounded-lg bg-slate-50 border border-slate-300 text-xs font-mono-code text-slate-900 focus:outline-none focus:border-slate-500 focus:bg-white"
                placeholder="/get or /api/v1/..."
              />
            </div>
          </div>

          {/* Identity & Role Attributes */}
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <div>
              <label className="text-[11px] font-bold text-slate-700 block mb-1">
                Client Identity (X-User-Id)
              </label>
              <input
                type="text"
                value={userId}
                onChange={(e) => setUserId(e.target.value)}
                className="w-full px-3 py-2 rounded-lg bg-slate-50 border border-slate-300 text-xs font-mono-code text-slate-900 focus:outline-none focus:border-slate-500 focus:bg-white"
                placeholder="e.g. pranjal.singh@corp.aegis"
              />
            </div>
            <div>
              <label className="text-[11px] font-bold text-slate-700 block mb-1">
                Zero-Trust Role (X-User-Role)
              </label>
              <select
                value={userRole}
                onChange={(e) => setUserRole(e.target.value)}
                className="w-full px-3 py-2 rounded-lg bg-slate-50 border border-slate-300 text-xs font-mono-code text-slate-900 focus:outline-none focus:border-slate-500 focus:bg-white"
              >
                <option value="super_admin">super_admin (Full Access)</option>
                <option value="devops">devops (Cluster & Workloads)</option>
                <option value="finance_lead">finance_lead (Treasury & Ledger)</option>
                <option value="it_admin">it_admin (Directory Admin)</option>
                <option value="intern">intern (Restricted Role)</option>
                <option value="public">public (Unauthenticated Guest)</option>
              </select>
            </div>
          </div>

          {/* Optional Bearer Token / Claims */}
          <div>
            <label className="text-[11px] font-bold text-slate-700 block mb-1">
              Optional Bearer Token / Claims Header
            </label>
            <input
              type="text"
              value={customToken}
              onChange={(e) => setCustomToken(e.target.value)}
              className="w-full px-3 py-1.5 rounded-lg bg-slate-50 border border-slate-300 text-xs font-mono-code text-slate-800 focus:outline-none focus:border-slate-500 focus:bg-white"
              placeholder="e.g. eyJhbGciOi... or custom bearer string"
            />
          </div>

          {/* Device Posture Slider */}
          <div>
            <div className="flex justify-between text-[11px] mb-1">
              <span className="font-bold text-slate-700">Device Compliance Posture</span>
              <span className="font-mono-code font-bold text-slate-900">{deviceTrust} / 100</span>
            </div>
            <input
              type="range"
              min="0"
              max="100"
              value={deviceTrust}
              onChange={(e) => setDeviceTrust(parseInt(e.target.value))}
              className="w-full h-1.5 bg-slate-200 rounded-lg appearance-none cursor-pointer accent-slate-900"
            />
            <div className="flex justify-between text-[10px] text-slate-400 mt-1">
              <span>0 (Untrusted)</span>
              <span>80 (Strict Policy Threshold)</span>
              <span>100 (Compliant MDM)</span>
            </div>
          </div>

          {/* POST Body Editor */}
          {method === 'POST' && (
            <div>
              <label className="text-[11px] font-bold text-slate-700 block mb-1">
                JSON Request Body
              </label>
              <textarea
                rows={3}
                value={requestBody}
                onChange={(e) => setRequestBody(e.target.value)}
                className="w-full px-3 py-2 rounded-lg bg-slate-50 border border-slate-300 text-xs font-mono-code text-slate-900 focus:outline-none focus:border-slate-500 focus:bg-white"
              />
            </div>
          )}

          {/* Execute Button */}
          <button
            onClick={handleExecute}
            disabled={loading}
            className="w-full py-2.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-white font-semibold text-xs transition flex items-center justify-center space-x-2 shadow-xs cursor-pointer"
          >
            <Send className="h-3.5 w-3.5" />
            <span>{loading ? 'Evaluating in Go Proxy...' : 'Send Request Through Aegis Proxy'}</span>
          </button>
        </div>

        {/* Right Column: Live Response */}
        <div className="lg:col-span-6 light-card rounded-xl p-5 flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between pb-2 border-b border-slate-100">
              <span className="text-xs font-bold text-slate-900">Live Gateway Verdict</span>
              {executionTime !== null && (
                <span className="text-[11px] font-mono-code text-slate-500">
                  Latency: <span className="text-slate-900 font-bold">{executionTime.toFixed(2)}ms</span>
                </span>
              )}
            </div>

            {response ? (
              <div className="mt-4 space-y-3.5">
                {/* Status Pill */}
                <div
                  className={`p-3 rounded-lg border text-xs flex items-center justify-between ${
                    response.status === 200
                      ? 'bg-emerald-50 border-emerald-200 text-emerald-900'
                      : response.status === 429
                      ? 'bg-amber-50 border-amber-200 text-amber-900'
                      : 'bg-rose-50 border-rose-200 text-rose-900'
                  }`}
                >
                  <div className="flex items-center space-x-2.5">
                    {response.status === 200 ? (
                      <CheckCircle2 className="h-4.5 w-4.5 text-emerald-600 shrink-0" />
                    ) : response.status === 429 ? (
                      <AlertOctagon className="h-4.5 w-4.5 text-amber-600 shrink-0" />
                    ) : (
                      <ShieldAlert className="h-4.5 w-4.5 text-rose-600 shrink-0" />
                    )}
                    <div>
                      <span className="font-mono-code font-bold text-sm">{response.status} {response.statusText}</span>
                      <span className="ml-2 font-medium opacity-80">Verdict: {response.verdict}</span>
                    </div>
                  </div>
                </div>

                {/* Response Body Inspector */}
                <div>
                  <div className="text-[11px] font-mono-code text-slate-500 mb-1 font-medium">
                    Live Server Payload ({targetServer})
                  </div>
                  <div className="p-3.5 rounded-lg bg-slate-950 border border-slate-900 text-xs font-mono-code text-emerald-400 max-h-72 overflow-y-auto shadow-inner">
                    <pre className="whitespace-pre-wrap">{JSON.stringify(response.data, null, 2)}</pre>
                  </div>
                </div>
              </div>
            ) : (
              <div className="py-24 text-center text-slate-400 flex flex-col items-center justify-center space-y-2">
                <Terminal className="h-8 w-8 text-slate-300" />
                <span className="text-xs font-medium">
                  Select a preset or enter any live URL above, then click Send Request to inspect.
                </span>
              </div>
            )}
          </div>

          <div className="mt-4 pt-3 border-t border-slate-100 text-[11px] text-slate-400 flex justify-between font-medium">
            <span>Dynamic Upstream Routing</span>
            <span className="font-mono-code text-slate-600">100% Real Live HTTP Proxying</span>
          </div>
        </div>
      </div>
    </div>
  );
};
