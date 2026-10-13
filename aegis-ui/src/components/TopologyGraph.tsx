import { Network, ArrowRight, Shield, Database, Users, Cloud, CheckCircle2, Globe } from 'lucide-react';

interface TopologyGraphProps {
  currentUpstream: string;
}

export const TopologyGraph: React.FC<TopologyGraphProps> = ({ currentUpstream }) => {
  const upstreams = [
    {
      name: 'Dynamic Live Target',
      path: currentUpstream,
      port: currentUpstream.startsWith('https') ? '443' : '80',
      status: 'ACTIVE',
      icon: Globe,
      desc: 'Configured live destination (HTTP/HTTPS public or local)',
      policy: 'Dynamic Upstream Layer (Header / Runtime Config)',
    },
    {
      name: 'Billing & Treasury API',
      path: 'http://127.0.0.1:8081/api/v1/billing',
      port: '8081',
      status: 'ISOLATED',
      icon: Database,
      desc: 'Financial ledger & corporate wire settlement engine',
      policy: 'pol-fin-001 (Strict Isolation • 80 Min Posture)',
    },
    {
      name: 'Identity & Directory Service',
      path: 'http://127.0.0.1:8081/api/v1/identity',
      port: '8081',
      status: 'ISOLATED',
      icon: Users,
      desc: 'Active Directory and credential vault integration',
      policy: 'pol-id-002 (IT Admin & DevOps • 65 Min Posture)',
    },
    {
      name: 'Kubernetes Workload Clusters',
      path: 'http://127.0.0.1:8081/api/v1/workloads',
      port: '8081',
      status: 'ISOLATED',
      icon: Cloud,
      desc: 'Distributed Kubernetes cluster telemetry & pod scheduler',
      policy: 'pol-ops-003 (Cloud Engineers • 70 Min Posture)',
    },
  ];

  return (
    <div className="space-y-4">
      {/* Header */}
      <div>
        <div className="text-xs font-bold text-slate-900 flex items-center space-x-2">
          <Network className="h-4 w-4 text-slate-700" />
          <span>Network Mesh & Upstream Topology</span>
        </div>
        <p className="text-[11px] text-slate-500 mt-0.5">
          Zero-Trust isolation ensures upstream destinations never face the open internet directly. All ingress traffic is negotiated via Go proxy goroutines.
        </p>
      </div>

      {/* Visual Pipeline Layout */}
      <div className="light-card rounded-xl p-5">
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-5 items-center">
          {/* Node 1: Untrusted Ingress */}
          <div className="lg:col-span-3 p-4 rounded-lg bg-slate-50 border border-slate-200 text-center space-y-1.5">
            <span className="text-[10px] font-mono-code uppercase text-slate-500 tracking-wider font-bold">
              Ingress Zone
            </span>
            <div className="text-xs font-bold text-slate-900">Public & Corporate Traffic</div>
            <p className="text-[11px] text-slate-500">
              Users, API clients, remote workers, automated scanners
            </p>
            <div className="pt-1.5 text-[10px] font-mono-code text-slate-500 font-medium">
              HTTP / TLS Ingress
            </div>
          </div>

          {/* Flow Arrow */}
          <div className="hidden lg:flex lg:col-span-1 justify-center text-slate-400">
            <ArrowRight className="h-5 w-5 text-slate-400" />
          </div>

          {/* Node 2: Aegis Core Gateway */}
          <div className="lg:col-span-4 p-4 rounded-lg bg-slate-900 text-white text-center space-y-2.5 shadow-md">
            <div className="h-8 w-8 mx-auto rounded-md bg-white/10 flex items-center justify-center text-white">
              <Shield className="h-4 w-4" />
            </div>
            <div>
              <div className="text-sm font-bold font-mono-code">AEGIS GATEWAY</div>
              <span className="text-[10px] font-mono-code text-slate-300">Port :8080 (Golang Core)</span>
            </div>

            {/* Sub-layers */}
            <div className="grid grid-cols-2 gap-1.5 text-[10px] font-mono-code text-slate-300">
              <div className="bg-white/10 p-1.5 rounded">
                1. Heuristic WAF
              </div>
              <div className="bg-white/10 p-1.5 rounded">
                2. Token Bucket
              </div>
              <div className="bg-white/10 p-1.5 rounded">
                3. Zero-Trust ABAC
              </div>
              <div className="bg-white/10 p-1.5 rounded">
                4. Telemetry Hub
              </div>
            </div>
          </div>

          {/* Flow Arrow */}
          <div className="hidden lg:flex lg:col-span-1 justify-center text-slate-400">
            <ArrowRight className="h-5 w-5 text-slate-400" />
          </div>

          {/* Node 3: Upstream Mesh */}
          <div className="lg:col-span-3 p-4 rounded-lg bg-slate-50 border border-slate-200 text-center space-y-1.5">
            <span className="text-[10px] font-mono-code uppercase text-slate-500 tracking-wider font-bold">
              Protected Egress
            </span>
            <div className="text-xs font-bold text-slate-900">Upstream Destination</div>
            <p className="text-[11px] text-slate-500">
              Live web servers or internal VPC microservices
            </p>
            <div className="pt-1.5 text-[10px] font-mono-code text-emerald-700 flex items-center justify-center space-x-1 font-bold">
              <CheckCircle2 className="h-3.5 w-3.5" />
              <span>Forwarded With Clean Headers</span>
            </div>
          </div>
        </div>
      </div>

      {/* Upstream Microservices List */}
      <div>
        <div className="text-xs font-bold text-slate-700 mb-2">
          Protected Destinations
        </div>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          {upstreams.map((srv, idx) => {
            const Icon = srv.icon;
            return (
              <div
                key={idx}
                className="p-3.5 rounded-lg light-card transition space-y-1.5"
              >
                <div className="flex items-start justify-between">
                  <div className="flex items-center space-x-2.5">
                    <div className="p-1.5 rounded-md bg-slate-100 text-slate-700 border border-slate-200">
                      <Icon className="h-3.5 w-3.5" />
                    </div>
                    <div>
                      <div className="text-xs font-bold text-slate-900">{srv.name}</div>
                      <span className="text-[11px] font-mono-code text-slate-500">{srv.path}</span>
                    </div>
                  </div>
                  <span className="text-[10px] font-mono-code px-2 py-0.5 rounded-full bg-slate-100 text-slate-700 font-bold border border-slate-200">
                    {srv.status}
                  </span>
                </div>

                <p className="text-[11px] text-slate-600 leading-relaxed">{srv.desc}</p>

                <div className="pt-1.5 border-t border-slate-100 flex items-center justify-between text-[10px] font-mono-code text-slate-500 font-medium">
                  <span>Enforcement: {srv.policy}</span>
                  <span>Port :{srv.port}</span>
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
};
