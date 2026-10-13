import React from 'react';
import { Shield, Activity, Terminal, Lock, Cpu, Network, RefreshCw, Globe } from 'lucide-react';

interface NavbarProps {
  activeTab: string;
  setActiveTab: (tab: string) => void;
  wsConnected: boolean;
  onResetTelemetry: () => void;
  resetLoading: boolean;
  currentUpstream: string;
}

export const Navbar: React.FC<NavbarProps> = ({
  activeTab,
  setActiveTab,
  wsConnected,
  onResetTelemetry,
  resetLoading,
  currentUpstream,
}) => {
  const tabs = [
    { id: 'observability', label: 'Live Telemetry', icon: Activity },
    { id: 'sandbox', label: 'Live Sandbox', icon: Terminal },
    { id: 'policies', label: 'Access Policies', icon: Lock },
    { id: 'intel', label: 'Threat Intelligence', icon: Cpu },
    { id: 'topology', label: 'Network Mesh', icon: Network },
  ];

  return (
    <header className="border-b border-slate-200 bg-white/95 backdrop-blur-md sticky top-0 z-50 shadow-xs">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">
          {/* Brand Identity - Clean Swiss Minimal Light */}
          <div className="flex items-center space-x-3">
            <div className="h-9 w-9 rounded-lg bg-slate-900 text-white flex items-center justify-center shadow-xs">
              <Shield className="h-4.5 w-4.5" />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <span className="text-base font-bold tracking-tight text-slate-900 font-mono-code">
                  AEGIS
                </span>
                <span className="text-[10px] tracking-wide uppercase px-2 py-0.5 rounded-full bg-slate-100 text-slate-700 border border-slate-200 font-semibold font-mono-code">
                  Zero-Trust Gateway
                </span>
              </div>
              <p className="text-[11px] text-slate-500 font-medium">
                High-Concurrency Go Reverse Proxy & Real-Time Security Telemetry
              </p>
            </div>
          </div>

          {/* Navigation Tabs - Modern Crisp Light Pills */}
          <nav className="flex items-center space-x-1 bg-slate-100/80 p-1 rounded-lg border border-slate-200">
            {tabs.map((tab) => {
              const Icon = tab.icon;
              const isActive = activeTab === tab.id;
              return (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id)}
                  className={`flex items-center space-x-1.5 px-3 py-1.5 rounded-md text-xs font-semibold transition-all duration-150 cursor-pointer ${
                    isActive
                      ? 'bg-white text-slate-900 shadow-xs border border-slate-200/80'
                      : 'text-slate-600 hover:text-slate-900 hover:bg-white/50'
                  }`}
                >
                  <Icon className={`h-3.5 w-3.5 ${isActive ? 'text-slate-900' : 'text-slate-500'}`} />
                  <span>{tab.label}</span>
                </button>
              );
            })}
          </nav>

          {/* Engine Controls & Status */}
          <div className="flex items-center space-x-2.5">
            {/* Live Gateway Pill */}
            <div className="flex items-center space-x-1.5 px-2.5 py-1 rounded-md bg-slate-100 border border-slate-200 text-xs">
              <span
                className={`h-2 w-2 rounded-full ${
                  wsConnected ? 'bg-emerald-500 ring-2 ring-emerald-200' : 'bg-rose-500'
                }`}
              />
              <span className="text-slate-700 font-mono-code text-[11px] font-medium">
                {wsConnected ? 'Proxy :8080' : 'Offline'}
              </span>
            </div>

            {/* Current Target Server */}
            <div className="hidden xl:flex items-center space-x-1 px-2.5 py-1 rounded-md bg-slate-50 border border-slate-200 text-[11px] text-slate-600 font-mono-code max-w-xs truncate" title={currentUpstream}>
              <Globe className="h-3 w-3 text-slate-400 shrink-0" />
              <span className="text-slate-400">Target:</span>
              <span className="text-slate-800 font-medium truncate">{currentUpstream.replace('http://', '').replace('https://', '')}</span>
            </div>

            {/* Reset Telemetry Button */}
            <button
              onClick={onResetTelemetry}
              disabled={resetLoading}
              className="flex items-center space-x-1.5 px-3 py-1.5 rounded-md bg-white hover:bg-slate-50 text-slate-700 text-xs font-semibold border border-slate-300 transition shadow-2xs cursor-pointer"
              title="Reset all live counters and packet feed to zero"
            >
              <RefreshCw className={`h-3 w-3 text-slate-500 ${resetLoading ? 'animate-spin' : ''}`} />
              <span>{resetLoading ? 'Clearing...' : 'Clear Telemetry'}</span>
            </button>
          </div>
        </div>
      </div>
    </header>
  );
};
