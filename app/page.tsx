'use client';

import { useState, useEffect } from 'react';
import { createClient } from '@supabase/supabase-js';
import { Shield, Terminal, AlertTriangle, CheckCircle, Search, Loader2 } from 'lucide-react';

// Initialize Supabase Client
const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL!;
const supabaseAnonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!;
const supabase = createClient(supabaseUrl, supabaseAnonKey);

interface Log {
  id: string;
  step_name: string;
  log_level: string;
  message: string;
  timestamp: string;
}

interface Vulnerability {
  id: string;
  subdomain: string;
  vuln_type: string;
  severity: string;
  evidence: string;
}

export default function Dashboard() {
  const [domain, setDomain] = useState('');
  const [currentTargetId, setCurrentTargetId] = useState<string | null>(null);
  const [scanning, setScanning] = useState(false);
  const [logs, setLogs] = useState<Log[]>([]);
  const [vulns, setVulns] = useState<Vulnerability[]>([]);

  // Listen for real-time updates when a scan starts
  useEffect(() => {
    if (!currentTargetId) return;

    // 1. Subscribe to Agent Logs
    const logChannel = supabase
      .channel('agent_logs_channel')
      .on(
        'postgres_changes',
        { event: 'INSERT', filter: `target_id=eq.${currentTargetId}`, schema: 'public', table: 'agent_logs' },
        (payload) => {
          setLogs((prev) => [payload.new as Log, ...prev]);
        }
      )
      .subscribe();

    // 2. Subscribe to Vulnerability findings
    const vulnChannel = supabase
      .channel('vulnerabilities_channel')
      .on(
        'postgres_changes',
        { event: 'INSERT', filter: `target_id=eq.${currentTargetId}`, schema: 'public', table: 'vulnerabilities' },
        (payload) => {
          setVulns((prev) => [payload.new as Vulnerability, ...prev]);
        }
      )
      .subscribe();

    return () => {
      supabase.removeChannel(logChannel);
      supabase.removeChannel(vulnChannel);
    };
  }, [currentTargetId]);

  const handleScanSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!domain) return;

    setScanning(true);
    setLogs([]);
    setVulns([]);

    try {
      const response = await fetch(`${process.env.NEXT_PUBLIC_BACKEND_URL}/api/scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domain }),
      });

      const data = await response.json();
      if (data.success) {
        setCurrentTargetId(data.target_id);
      }
    } catch (error) {
      console.error("Failed to start scan:", error);
    }
  };

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 p-8 font-sans">
      {/* Header */}
      <header className="flex items-center justify-between border-b border-slate-800 pb-6 mb-8">
        <div className="flex items-center gap-3">
          <Shield className="w-8 h-8 text-emerald-400" />
          <h1 className="text-2xl font-bold tracking-tight">BountyWire <span className="text-xs bg-emerald-500/10 text-emerald-400 px-2.5 py-1 rounded-full border border-emerald-500/20 ml-2">Agent Active</span></h1>
        </div>
      </header>

      {/* Target Input Section */}
      <form onSubmit={handleScanSubmit} className="max-w-2xl flex gap-3 mb-8">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-3.5 h-5 w-5 text-slate-500" />
          <input
            type="text"
            placeholder="Enter target domain (e.g., example.com)"
            value={domain}
            onChange={(e) => setDomain(e.target.value)}
            disabled={scanning && logs.filter(l => l.step_name === 'Completed').length === 0}
            className="w-full bg-slate-900 border border-slate-800 rounded-lg pl-10 pr-4 py-3 text-slate-200 focus:outline-none focus:border-emerald-500 disabled:opacity-50 transition-colors"
          />
        </div>
        <button
          type="submit"
          disabled={scanning && logs.filter(l => l.step_name === 'Completed').length === 0}
          className="bg-emerald-600 hover:bg-emerald-500 text-white font-medium px-6 py-3 rounded-lg flex items-center gap-2 disabled:opacity-50 transition-colors"
        >
          {scanning && logs.filter(l => l.step_name === 'Completed').length === 0 ? (
            <>
              <Loader2 className="w-5 h-5 animate-spin" />
              Analyzing...
            </>
          ) : (
            'Launch Agent'
          )}
        </button>
      </form>

      {/* Main Panel Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
        {/* Left Column: Realtime Reasoning Terminal */}
        <div className="lg:col-span-2 bg-slate-900 border border-slate-800 rounded-xl p-6 flex flex-col h-[600px]">
          <div className="flex items-center gap-2 border-b border-slate-800 pb-4 mb-4">
            <Terminal className="w-5 h-5 text-slate-400" />
            <h2 className="font-semibold text-slate-200">Agent Reasoning Loop Logs</h2>
          </div>

          <div className="flex-1 overflow-y-auto space-y-3 font-mono text-xs scrollbar-thin">
            {logs.length === 0 && (
              <p className="text-slate-600 italic">Awaiting target submission...</p>
            )}
            {logs.map((log) => (
              <div
                key={log.id}
                className={`p-3 rounded border ${log.log_level === 'warning' ? 'bg-amber-950/20 border-amber-500/20 text-amber-300' :
                    log.log_level === 'critical' ? 'bg-rose-950/20 border-rose-500/20 text-rose-300' :
                      log.step_name === 'Completed' ? 'bg-emerald-950/20 border-emerald-500/20 text-emerald-400' :
                        'bg-slate-950 border-slate-800 text-slate-400'
                  }`}
              >
                <div className="flex justify-between font-bold mb-1">
                  <span>[{log.step_name.toUpperCase()}]</span>
                  <span className="opacity-50">{new Date(log.timestamp).toLocaleTimeString()}</span>
                </div>
                <p className="leading-relaxed">{log.message}</p>
              </div>
            ))}
          </div>
        </div>

        {/* Right Column: Confirmed Vulnerabilities */}
        <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 flex flex-col h-[600px]">
          <div className="flex items-center gap-2 border-b border-slate-800 pb-4 mb-4">
            <AlertTriangle className="w-5 h-5 text-amber-500" />
            <h2 className="font-semibold text-slate-200">Confirmed Vulnerabilities</h2>
          </div>

          <div className="flex-1 overflow-y-auto space-y-4">
            {vulns.length === 0 && (
              <div className="flex flex-col items-center justify-center h-full text-slate-600 gap-2">
                <CheckCircle className="w-8 h-8 text-slate-800" />
                <p className="text-sm italic">No active threats discovered yet.</p>
              </div>
            )}
            {vulns.map((vuln) => (
              <div key={vuln.id} className="bg-rose-950/10 border border-rose-500/30 rounded-lg p-4">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-xs bg-rose-500/20 text-rose-400 font-bold px-2 py-0.5 rounded border border-rose-500/30">
                    {vuln.severity.toUpperCase()}
                  </span>
                  <span className="text-xs text-slate-400 font-mono">{vuln.vuln_type}</span>
                </div>
                <p className="text-sm font-semibold text-rose-200 mb-2">Potential Subdomain Takeover</p>
                <div className="bg-slate-950 p-2.5 rounded font-mono text-[11px] text-slate-400 border border-slate-800 break-all">
                  {vuln.evidence}
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}