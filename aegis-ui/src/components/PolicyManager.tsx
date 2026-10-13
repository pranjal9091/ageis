import React, { useState, useEffect } from 'react';
import type { PolicyRule } from '../types/telemetry';
import { Lock, Plus, ToggleLeft, ToggleRight, Shield, RefreshCw } from 'lucide-react';

export const PolicyManager: React.FC = () => {
  const [policies, setPolicies] = useState<PolicyRule[]>([]);
  const [loading, setLoading] = useState(false);
  const [showAddModal, setShowAddModal] = useState(false);

  const [newRule, setNewRule] = useState<Partial<PolicyRule>>({
    id: '',
    name: '',
    pathPrefix: '/api/v1/custom',
    methods: ['*'],
    requiredRoles: ['super_admin'],
    minDeviceTrust: 75,
    rateLimitRps: 20,
    enforceMfa: false,
    enabled: true,
    description: '',
  });

  const fetchPolicies = async () => {
    try {
      setLoading(true);
      const res = await fetch('http://127.0.0.1:8080/api/control/policies');
      if (res.ok) {
        const data = await res.json();
        setPolicies(data);
      }
    } catch {
      // Ignore
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchPolicies();
  }, []);

  const handleTogglePolicy = async (policy: PolicyRule) => {
    const updated = { ...policy, enabled: !policy.enabled };
    try {
      const res = await fetch('http://127.0.0.1:8080/api/control/policies', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(updated),
      });
      if (res.ok) {
        setPolicies((prev) => prev.map((p) => (p.id === policy.id ? updated : p)));
      }
    } catch {
      // Ignore
    }
  };

  const handleCreatePolicy = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newRule.name || !newRule.pathPrefix) return;

    try {
      const ruleToSave: PolicyRule = {
        id: newRule.id || `pol-${Date.now().toString().slice(-4)}`,
        name: newRule.name || 'Custom Policy',
        pathPrefix: newRule.pathPrefix || '/api/v1',
        methods: newRule.methods || ['*'],
        requiredRoles: newRule.requiredRoles || ['super_admin'],
        minDeviceTrust: Number(newRule.minDeviceTrust) || 70,
        rateLimitRps: Number(newRule.rateLimitRps) || 20,
        enforceMfa: Boolean(newRule.enforceMfa),
        enabled: true,
        description: newRule.description || 'Configured via Zero-Trust Control Plane',
      };

      const res = await fetch('http://127.0.0.1:8080/api/control/policies', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(ruleToSave),
      });

      if (res.ok) {
        setShowAddModal(false);
        fetchPolicies();
      }
    } catch {
      // Ignore
    }
  };

  return (
    <div className="space-y-4">
      {/* Top Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <div className="text-xs font-bold text-slate-900 flex items-center space-x-2">
            <Lock className="h-4 w-4 text-slate-700" />
            <span>Zero-Trust Access Control (ABAC Policies)</span>
          </div>
          <p className="text-[11px] text-slate-500 mt-0.5">
            Rules are evaluated in Go memory with zero-downtime hot reloading. Every incoming request must satisfy role and device compliance.
          </p>
        </div>

        <div className="flex items-center space-x-2">
          <button
            onClick={fetchPolicies}
            className="p-1.5 rounded-lg bg-white hover:bg-slate-50 text-slate-700 border border-slate-300 transition shadow-2xs cursor-pointer"
            title="Reload policies"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${loading ? 'animate-spin' : ''}`} />
          </button>
          <button
            onClick={() => setShowAddModal(true)}
            className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-white text-xs font-semibold transition shadow-xs cursor-pointer"
          >
            <Plus className="h-3.5 w-3.5" />
            <span>New Policy Rule</span>
          </button>
        </div>
      </div>

      {/* Policy Cards Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-3.5">
        {policies.map((p) => (
          <div
            key={p.id}
            className={`p-4 rounded-xl light-card transition-all ${
              p.enabled
                ? 'hover:border-slate-300'
                : 'opacity-60 bg-slate-50/50'
            }`}
          >
            <div className="flex items-start justify-between">
              <div>
                <div className="flex items-center space-x-2">
                  <span className="text-xs font-mono-code font-bold text-blue-700 bg-blue-50 px-1.5 py-0.5 rounded border border-blue-200">{p.id}</span>
                  <span className="text-xs font-bold text-slate-900">{p.name}</span>
                </div>
                <p className="text-[11px] text-slate-600 mt-1 leading-relaxed">{p.description}</p>
              </div>

              {/* Live Toggle */}
              <button
                onClick={() => handleTogglePolicy(p)}
                className="text-slate-400 hover:text-slate-700 transition cursor-pointer"
                title={p.enabled ? 'Disable' : 'Enable'}
              >
                {p.enabled ? (
                  <ToggleRight className="h-6 w-6 text-emerald-600" />
                ) : (
                  <ToggleLeft className="h-6 w-6 text-slate-300" />
                )}
              </button>
            </div>

            {/* Constraints Grid */}
            <div className="mt-3.5 pt-3 border-t border-slate-100 grid grid-cols-2 sm:grid-cols-4 gap-2 text-[11px] font-mono-code">
              <div className="bg-slate-50 p-2 rounded border border-slate-200">
                <span className="text-slate-400 block text-[9px] uppercase font-bold">Path</span>
                <span className="text-slate-900 font-semibold truncate block" title={p.pathPrefix}>
                  {p.pathPrefix}
                </span>
              </div>

              <div className="bg-slate-50 p-2 rounded border border-slate-200">
                <span className="text-slate-400 block text-[9px] uppercase font-bold">Roles</span>
                <span className="text-slate-900 font-semibold truncate block">
                  {p.requiredRoles.join(', ')}
                </span>
              </div>

              <div className="bg-slate-50 p-2 rounded border border-slate-200">
                <span className="text-slate-400 block text-[9px] uppercase font-bold">Min Posture</span>
                <span className="text-slate-900 font-bold">{p.minDeviceTrust}/100</span>
              </div>

              <div className="bg-slate-50 p-2 rounded border border-slate-200">
                <span className="text-slate-400 block text-[9px] uppercase font-bold">Rate Limit</span>
                <span className="text-slate-900 font-semibold">{p.rateLimitRps} rps</span>
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* Modal to add new policy */}
      {showAddModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/40 backdrop-blur-xs animate-in fade-in">
          <div className="bg-white border border-slate-300 rounded-xl w-full max-w-md overflow-hidden p-5 space-y-4 shadow-xl">
            <h3 className="text-sm font-bold text-slate-900 flex items-center space-x-2">
              <Shield className="h-4 w-4 text-slate-700" />
              <span>Define Access Policy Rule</span>
            </h3>

            <form onSubmit={handleCreatePolicy} className="space-y-3 text-xs">
              <div>
                <label className="text-slate-700 font-bold block mb-1">Rule Name</label>
                <input
                  type="text"
                  required
                  placeholder="e.g. Payment Gateway Isolation"
                  value={newRule.name}
                  onChange={(e) => setNewRule({ ...newRule, name: e.target.value })}
                  className="w-full px-3 py-1.5 rounded-lg bg-slate-50 border border-slate-300 text-slate-900 focus:outline-none focus:border-slate-500 focus:bg-white"
                />
              </div>

              <div className="grid grid-cols-2 gap-2.5">
                <div>
                  <label className="text-slate-700 font-bold block mb-1">Path Prefix</label>
                  <input
                    type="text"
                    required
                    placeholder="/api/v1/payments"
                    value={newRule.pathPrefix}
                    onChange={(e) => setNewRule({ ...newRule, pathPrefix: e.target.value })}
                    className="w-full px-3 py-1.5 rounded-lg bg-slate-50 border border-slate-300 text-slate-900 font-mono-code focus:outline-none focus:border-slate-500 focus:bg-white"
                  />
                </div>
                <div>
                  <label className="text-slate-700 font-bold block mb-1">Allowed Roles</label>
                  <input
                    type="text"
                    required
                    placeholder="finance_lead, admin"
                    value={newRule.requiredRoles?.join(', ')}
                    onChange={(e) =>
                      setNewRule({
                        ...newRule,
                        requiredRoles: e.target.value.split(',').map((r) => r.trim()),
                      })
                    }
                    className="w-full px-3 py-1.5 rounded-lg bg-slate-50 border border-slate-300 text-slate-900 font-mono-code focus:outline-none focus:border-slate-500 focus:bg-white"
                  />
                </div>
              </div>

              <div className="grid grid-cols-2 gap-2.5">
                <div>
                  <label className="text-slate-700 font-bold block mb-1">Min Posture (0-100)</label>
                  <input
                    type="number"
                    min="0"
                    max="100"
                    value={newRule.minDeviceTrust}
                    onChange={(e) => setNewRule({ ...newRule, minDeviceTrust: parseInt(e.target.value) })}
                    className="w-full px-3 py-1.5 rounded-lg bg-slate-50 border border-slate-300 text-slate-900 font-mono-code focus:outline-none focus:border-slate-500 focus:bg-white"
                  />
                </div>
                <div>
                  <label className="text-slate-700 font-bold block mb-1">Rate Limit (req/s)</label>
                  <input
                    type="number"
                    min="1"
                    max="1000"
                    value={newRule.rateLimitRps}
                    onChange={(e) => setNewRule({ ...newRule, rateLimitRps: parseInt(e.target.value) })}
                    className="w-full px-3 py-1.5 rounded-lg bg-slate-50 border border-slate-300 text-slate-900 font-mono-code focus:outline-none focus:border-slate-500 focus:bg-white"
                  />
                </div>
              </div>

              <div>
                <label className="text-slate-700 font-bold block mb-1">Description</label>
                <textarea
                  rows={2}
                  placeholder="Enforces strict Zero-Trust checks..."
                  value={newRule.description}
                  onChange={(e) => setNewRule({ ...newRule, description: e.target.value })}
                  className="w-full px-3 py-1.5 rounded-lg bg-slate-50 border border-slate-300 text-slate-900 focus:outline-none focus:border-slate-500 focus:bg-white"
                />
              </div>

              <div className="pt-2 border-t border-slate-200 flex justify-end space-x-2">
                <button
                  type="button"
                  onClick={() => setShowAddModal(false)}
                  className="px-3.5 py-1.5 rounded-lg bg-slate-100 hover:bg-slate-200 text-slate-700 font-semibold cursor-pointer"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-1.5 rounded-lg bg-slate-900 hover:bg-slate-800 text-white font-semibold cursor-pointer shadow-2xs"
                >
                  Save Policy
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};
