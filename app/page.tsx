'use client';

import { useState, useEffect, useCallback } from 'react';
import { createClient } from '@supabase/supabase-js';
import {
  Shield, Terminal, AlertTriangle, CheckCircle, Search,
  Loader2, Clock, ChevronRight, Database, Wifi, WifiOff
} from 'lucide-react';

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
  subdomain_id: string;
  vuln_type: string;
  severity: string;
  evidence: string;
  created_at: string;
}

interface Target {
  id: string;
  domain: string;
  status: string;
  created_at: string;
}

export default function Dashboard() {
  const [domain, setDomain] = useState('');
  const [scanning, setScanning] = useState(false);
  const [logs, setLogs] = useState<Log[]>([]);
  const [vulns, setVulns] = useState<Vulnerability[]>([]);
  const [targets, setTargets] = useState<Target[]>([]);
  const [activeTarget, setActiveTarget] = useState<Target | null>(null);
  const [realtimeStatus, setRealtimeStatus] = useState<'connected' | 'disconnected'>('disconnected');

  // Fetch all past targets on mount
  useEffect(() => {
    fetchTargets();
  }, []);

  const fetchTargets = async () => {
    const { data } = await supabase
      .from('targets')
      .select('*')
      .order('created_at', { ascending: false })
      .limit(10);
    if (data) setTargets(data);
  };

  // Fetch logs + vulns for a given target from DB
  const loadTargetData = useCallback(async (target: Target) => {
    setActiveTarget(target);
    setLogs([]);
    setVulns([]);

    const [logsRes, vulnsRes] = await Promise.all([
      supabase
        .from('agent_logs')
        .select('*')
        .eq('target_id', target.id)
        .order('timestamp', { ascending: true }),
      supabase
        .from('vulnerabilities')
        .select('*')
        .eq('target_id', target.id)
        .order('created_at', { ascending: true }),
    ]);

    if (logsRes.data) setLogs(logsRes.data);
    if (vulnsRes.data) setVulns(vulnsRes.data);
  }, []);

  // Realtime subscription when scanning a new target
  useEffect(() => {
    if (!activeTarget || activeTarget.status !== 'scanning') return;

    const logChannel = supabase
      .channel(`logs-${activeTarget.id}`)
      .on(
        'postgres_changes',
        { event: 'INSERT', schema: 'public', table: 'agent_logs', filter: `target_id=eq.${activeTarget.id}` },
        (payload) => {
          const newLog = payload.new as Log;
          setLogs((prev) => {
            if (prev.find(l => l.id === newLog.id)) return prev;
            return [...prev, newLog];
          });
          if (newLog.step_name === 'Completed' || newLog.step_name === 'Failed') {
            setScanning(false);
            setActiveTarget(prev => prev ? { ...prev, status: newLog.step_name === 'Completed' ? 'completed' : 'failed' } : prev);
            fetchTargets();
          }
        }
      )
      .on(
        'postgres_changes',
        { event: 'INSERT', schema: 'public', table: 'vulnerabilities', filter: `target_id=eq.${activeTarget.id}` },
        (payload) => {
          const newVuln = payload.new as Vulnerability;
          setVulns((prev) => {
            if (prev.find(v => v.id === newVuln.id)) return prev;
            return [...prev, newVuln];
          });
        }
      )
      .subscribe((status) => {
        setRealtimeStatus(status === 'SUBSCRIBED' ? 'connected' : 'disconnected');
      });

    return () => {
      supabase.removeChannel(logChannel);
      setRealtimeStatus('disconnected');
    };
  }, [activeTarget?.id, activeTarget?.status]);

  const handleScanSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!domain.trim() || scanning) return;

    setScanning(true);
    setLogs([]);
    setVulns([]);
    setActiveTarget(null);

    try {
      const response = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domain: domain.trim() }),
      });

      const data = await response.json();
      if (data.success && data.target_id) {
        const newTarget: Target = { id: data.target_id, domain: domain.trim(), status: 'scanning', created_at: new Date().toISOString() };
        setActiveTarget(newTarget);
        setTargets(prev => [newTarget, ...prev]);
      } else {
        console.error('Scan failed:', data.error);
        setScanning(false);
        alert(`Scan failed: ${data.error}`);
      }
    } catch (error: any) {
      console.error('Network error:', error);
      setScanning(false);
      alert(`Network error: ${error.message}`);
    }
  };

  const severityColor = (s: string) => {
    if (s === 'High' || s === 'Critical') return 'bg-rose-500/20 text-rose-400 border-rose-500/30';
    if (s === 'Medium') return 'bg-amber-500/20 text-amber-400 border-amber-500/30';
    return 'bg-sky-500/20 text-sky-400 border-sky-500/30';
  };

  const logRowStyle = (log: Log) => {
    if (log.log_level === 'warning') return 'bg-amber-950/20 border-amber-500/20 text-amber-300';
    if (log.log_level === 'critical') return 'bg-rose-950/20 border-rose-500/20 text-rose-300';
    if (log.step_name === 'Completed') return 'bg-emerald-950/20 border-emerald-500/20 text-emerald-400';
    if (log.step_name === 'Failed') return 'bg-rose-950/30 border-rose-500/30 text-rose-400';
    return 'bg-slate-950 border-slate-800 text-slate-400';
  };

  const statusBadge = (status: string) => {
    if (status === 'completed') return 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30';
    if (status === 'scanning') return 'bg-sky-500/15 text-sky-400 border-sky-500/30 animate-pulse';
    if (status === 'failed') return 'bg-rose-500/15 text-rose-400 border-rose-500/30';
    return 'bg-slate-500/15 text-slate-400 border-slate-500/30';
  };

  const isScanning = scanning && activeTarget?.status === 'scanning';

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 font-sans">
      {/* Top Nav */}
      <header className="sticky top-0 z-10 bg-slate-950/80 backdrop-blur border-b border-slate-800 px-8 py-4 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Shield className="w-7 h-7 text-emerald-400" />
          <span className="text-xl font-bold tracking-tight">BountyWire</span>
          <span className="text-[11px] bg-emerald-500/10 text-emerald-400 px-2.5 py-0.5 rounded-full border border-emerald-500/20 ml-1">
            Agent Active
          </span>
        </div>
        <div className="flex items-center gap-2 text-xs text-slate-500">
          {realtimeStatus === 'connected'
            ? <><Wifi className="w-4 h-4 text-emerald-400" /><span className="text-emerald-400">Realtime Connected</span></>
            : <><WifiOff className="w-4 h-4" /> Realtime Idle</>
          }
        </div>
      </header>

      <div className="flex h-[calc(100vh-65px)]">
        {/* Sidebar: Past Scans */}
        <aside className="w-64 shrink-0 border-r border-slate-800 bg-slate-900/50 flex flex-col">
          <div className="flex items-center gap-2 px-4 py-3 border-b border-slate-800">
            <Database className="w-4 h-4 text-slate-500" />
            <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider">Past Scans</span>
          </div>
          <div className="flex-1 overflow-y-auto">
            {targets.length === 0 ? (
              <p className="text-xs text-slate-600 italic text-center mt-8 px-4">No scans yet.</p>
            ) : (
              targets.map((t) => (
                <button
                  key={t.id}
                  onClick={() => loadTargetData(t)}
                  className={`w-full text-left px-4 py-3 border-b border-slate-800/50 hover:bg-slate-800/50 transition-colors group ${activeTarget?.id === t.id ? 'bg-slate-800' : ''}`}
                >
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-sm text-slate-200 truncate font-medium">{t.domain}</span>
                    <ChevronRight className="w-3.5 h-3.5 text-slate-600 group-hover:text-slate-400 transition-colors shrink-0" />
                  </div>
                  <div className="flex items-center gap-2">
                    <span className={`text-[10px] px-1.5 py-0.5 rounded border font-medium ${statusBadge(t.status)}`}>
                      {t.status}
                    </span>
                    <span className="text-[10px] text-slate-600">
                      {new Date(t.created_at).toLocaleDateString()}
                    </span>
                  </div>
                </button>
              ))
            )}
          </div>
        </aside>

        {/* Main Content */}
        <main className="flex-1 flex flex-col overflow-hidden p-6 gap-5">
          {/* Scan Input */}
          <form onSubmit={handleScanSubmit} className="flex gap-3 max-w-2xl">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-500" />
              <input
                type="text"
                placeholder="Enter target domain (e.g., example.com)"
                value={domain}
                onChange={(e) => setDomain(e.target.value)}
                disabled={isScanning}
                className="w-full bg-slate-900 border border-slate-700 rounded-lg pl-9 pr-4 py-2.5 text-sm text-slate-200 focus:outline-none focus:border-emerald-500 disabled:opacity-50 transition-colors placeholder:text-slate-600"
              />
            </div>
            <button
              type="submit"
              disabled={isScanning || !domain.trim()}
              className="bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 disabled:cursor-not-allowed text-white text-sm font-semibold px-5 py-2.5 rounded-lg flex items-center gap-2 transition-colors"
            >
              {isScanning ? (
                <><Loader2 className="w-4 h-4 animate-spin" /> Analyzing...</>
              ) : (
                'Launch Agent'
              )}
            </button>
          </form>

          {/* Active target banner */}
          {activeTarget && (
            <div className="flex items-center gap-3 text-xs text-slate-400 bg-slate-900 border border-slate-800 rounded-lg px-4 py-2.5">
              <span className="font-mono text-slate-500">Target:</span>
              <span className="font-semibold text-slate-200">{activeTarget.domain}</span>
              <span className={`ml-auto px-2 py-0.5 rounded border text-[10px] font-medium ${statusBadge(activeTarget.status)}`}>
                {activeTarget.status}
              </span>
              <span className="text-slate-600">·</span>
              <span className="text-slate-500">{logs.length} logs · {vulns.length} vulns</span>
            </div>
          )}

          {/* Panels */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-5 flex-1 min-h-0">
            {/* Logs Panel */}
            <div className="lg:col-span-2 bg-slate-900 border border-slate-800 rounded-xl flex flex-col min-h-0">
              <div className="flex items-center gap-2 px-5 py-3.5 border-b border-slate-800">
                <Terminal className="w-4 h-4 text-slate-400" />
                <h2 className="text-sm font-semibold text-slate-200">Agent Reasoning Loop Logs</h2>
                {logs.length > 0 && (
                  <span className="ml-auto text-[10px] bg-slate-800 text-slate-400 px-2 py-0.5 rounded-full">
                    {logs.length} entries
                  </span>
                )}
              </div>

              <div className="flex-1 overflow-y-auto p-4 space-y-2 font-mono text-xs">
                {logs.length === 0 ? (
                  <div className="flex flex-col items-center justify-center h-full text-slate-700 gap-2">
                    <Terminal className="w-8 h-8" />
                    <p className="italic">
                      {activeTarget ? 'Loading logs...' : 'Select a past scan or launch a new one'}
                    </p>
                  </div>
                ) : (
                  [...logs].reverse().map((log) => (
                    <div key={log.id} className={`p-3 rounded border ${logRowStyle(log)}`}>
                      <div className="flex justify-between font-bold mb-1 opacity-80">
                        <span>[{log.step_name.toUpperCase()}]</span>
                        <span className="flex items-center gap-1 opacity-60">
                          <Clock className="w-3 h-3" />
                          {new Date(log.timestamp).toLocaleTimeString()}
                        </span>
                      </div>
                      <p className="leading-relaxed break-words">{log.message}</p>
                    </div>
                  ))
                )}
              </div>
            </div>

            {/* Vulns Panel */}
            <div className="bg-slate-900 border border-slate-800 rounded-xl flex flex-col min-h-0">
              <div className="flex items-center gap-2 px-5 py-3.5 border-b border-slate-800">
                <AlertTriangle className="w-4 h-4 text-amber-500" />
                <h2 className="text-sm font-semibold text-slate-200">Confirmed Vulnerabilities</h2>
                {vulns.length > 0 && (
                  <span className="ml-auto text-[10px] bg-rose-500/20 text-rose-400 px-2 py-0.5 rounded-full border border-rose-500/30">
                    {vulns.length} found
                  </span>
                )}
              </div>

              <div className="flex-1 overflow-y-auto p-4 space-y-3">
                {vulns.length === 0 ? (
                  <div className="flex flex-col items-center justify-center h-full text-slate-700 gap-2">
                    <CheckCircle className="w-8 h-8 text-slate-800" />
                    <p className="text-xs italic text-slate-600">No active threats discovered yet.</p>
                  </div>
                ) : (
                  vulns.map((vuln) => (
                    <div key={vuln.id} className="bg-rose-950/10 border border-rose-500/20 rounded-lg p-3.5">
                      <div className="flex items-center justify-between mb-2">
                        <span className={`text-[10px] px-2 py-0.5 rounded border font-bold ${severityColor(vuln.severity)}`}>
                          {vuln.severity?.toUpperCase()}
                        </span>
                        <span className="text-[10px] text-slate-400 font-mono">{vuln.vuln_type}</span>
                      </div>
                      <p className="text-xs font-semibold text-rose-200 mb-2">Potential Subdomain Takeover</p>
                      <div className="bg-slate-950 p-2 rounded font-mono text-[10px] text-slate-400 border border-slate-800 break-all leading-relaxed">
                        {vuln.evidence}
                      </div>
                    </div>
                  ))
                )}
              </div>
            </div>
          </div>
        </main>
      </div>
    </div>
  );
}