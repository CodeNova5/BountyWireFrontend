'use client';

import { useState, useEffect, useCallback, useRef } from 'react';
import { createClient } from '@supabase/supabase-js';
import {
  Shield, Terminal, AlertTriangle, CheckCircle, Search,
  Loader2, Clock, ChevronRight, Database, Wifi, WifiOff,
  FileText, X, ExternalLink,
} from 'lucide-react';

const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL!;
const supabaseAnonKey = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!;
const supabase = createClient(supabaseUrl, supabaseAnonKey);

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------
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
  evidence: string; // Contains full Markdown remediation report
  created_at: string;
}

interface Target {
  id: string;
  domain: string;
  status: string;
  created_at: string;
}

interface Subdomain {
  id: string;
  subdomain: string;
  cname: string | null;
  http_status: number | null;
  live_status: string;
}

// ---------------------------------------------------------------------------
// Markdown → HTML renderer (no external deps — lightweight inline parser)
// ---------------------------------------------------------------------------
function renderMarkdown(md: string): string {
  return md
    // Headings
    .replace(/^### (.+)$/gm, '<h3 class="text-base font-bold text-rose-300 mt-5 mb-2">$1</h3>')
    .replace(/^## (.+)$/gm, '<h2 class="text-lg font-bold text-rose-200 mt-6 mb-2 border-b border-rose-500/20 pb-1">$1</h2>')
    .replace(/^# (.+)$/gm, '<h1 class="text-xl font-bold text-white mt-4 mb-3">$1</h1>')
    // Bold / italic
    .replace(/\*\*(.+?)\*\*/g, '<strong class="text-slate-200 font-semibold">$1</strong>')
    .replace(/\*(.+?)\*/g, '<em class="text-slate-300 italic">$1</em>')
    // Code (inline)
    .replace(/`([^`]+)`/g, '<code class="bg-slate-800 text-emerald-400 px-1.5 py-0.5 rounded text-xs font-mono">$1</code>')
    // Code blocks
    .replace(/```[\w]*\n([\s\S]+?)```/g, '<pre class="bg-slate-950 border border-slate-700 rounded-lg p-4 overflow-x-auto text-xs font-mono text-emerald-300 my-3 leading-relaxed"><code>$1</code></pre>')
    // Ordered lists
    .replace(/^\d+\. (.+)$/gm, '<li class="ml-5 list-decimal text-slate-300 mb-1">$1</li>')
    // Unordered lists
    .replace(/^[-*] (.+)$/gm, '<li class="ml-5 list-disc text-slate-300 mb-1">$1</li>')
    // Table rows (basic)
    .replace(/^\|(.+)\|$/gm, (match) => {
      const cells = match.split('|').filter((c) => c.trim()).map((c) => c.trim());
      const isHeader = false;
      return `<tr>${cells.map((c) => `<td class="px-3 py-1.5 border border-slate-700 text-slate-300 text-xs">${c}</td>`).join('')}</tr>`;
    })
    .replace(/^-{3,}$/gm, '<hr class="border-slate-700 my-4">')
    // Paragraphs (double newline)
    .replace(/\n\n/g, '</p><p class="text-slate-400 text-sm leading-relaxed mb-3">')
    // Wrap in opening paragraph
    .replace(/^/, '<p class="text-slate-400 text-sm leading-relaxed mb-3">')
    .replace(/$/, '</p>');
}

// ---------------------------------------------------------------------------
// Remediation Report Modal
// ---------------------------------------------------------------------------
function ReportModal({ vuln, onClose }: { vuln: Vulnerability; onClose: () => void }) {
  const isMarkdown =
    vuln.evidence.startsWith('#') || vuln.evidence.includes('##');

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4"
      onClick={onClose}
    >
      <div
        className="relative w-full max-w-4xl max-h-[90vh] bg-slate-900 border border-rose-500/30 rounded-2xl shadow-2xl flex flex-col overflow-hidden"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Modal header */}
        <div className="flex items-center gap-3 px-6 py-4 border-b border-slate-800 bg-rose-950/30 shrink-0">
          <FileText className="w-5 h-5 text-rose-400" />
          <div className="flex-1 min-w-0">
            <h2 className="text-sm font-bold text-rose-200">Remediation Advisory Report</h2>
            <p className="text-xs text-slate-500 truncate">{vuln.vuln_type} · Severity: {vuln.severity}</p>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg hover:bg-slate-700 text-slate-400 hover:text-white transition-colors"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Report body */}
        <div className="flex-1 overflow-y-auto px-6 py-5">
          {isMarkdown ? (
            <div
              className="prose-report"
              dangerouslySetInnerHTML={{ __html: renderMarkdown(vuln.evidence) }}
            />
          ) : (
            <pre className="text-xs font-mono text-slate-300 leading-relaxed whitespace-pre-wrap break-words">
              {vuln.evidence}
            </pre>
          )}
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Main Dashboard
// ---------------------------------------------------------------------------
export default function Dashboard() {
  const [domain, setDomain] = useState('');
  const [scanning, setScanning] = useState(false);
  const [logs, setLogs] = useState<Log[]>([]);
  const [vulns, setVulns] = useState<Vulnerability[]>([]);
  const [targets, setTargets] = useState<Target[]>([]);
  const [subdomains, setSubdomains] = useState<Subdomain[]>([]);
  const [activeTarget, setActiveTarget] = useState<Target | null>(null);
  const [realtimeStatus, setRealtimeStatus] = useState<'connected' | 'disconnected'>('disconnected');
  const [selectedReport, setSelectedReport] = useState<Vulnerability | null>(null);
  const logsEndRef = useRef<HTMLDivElement>(null);

  // Auto-scroll logs to bottom on new entries
  useEffect(() => {
    logsEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [logs]);

  // Fetch all past targets on mount
  useEffect(() => {
    fetchTargets();
  }, []);

  const fetchTargets = async () => {
    const { data } = await supabase
      .from('targets')
      .select('*')
      .order('created_at', { ascending: false })
      .limit(20);
    if (data) setTargets(data as Target[]);
  };

  // Fetch logs + vulns + subdomains for a given target from DB
  const loadTargetData = useCallback(async (target: Target) => {
    setActiveTarget(target);
    setLogs([]);
    setVulns([]);
    setSubdomains([]);

    const [logsRes, vulnsRes, subRes] = await Promise.all([
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
      supabase
        .from('subdomains')
        .select('*')
        .eq('target_id', target.id)
        .order('discovered_at', { ascending: true }),
    ]);

    if (logsRes.data) setLogs(logsRes.data as Log[]);
    if (vulnsRes.data) setVulns(vulnsRes.data as Vulnerability[]);
    if (subRes.data) setSubdomains(subRes.data as Subdomain[]);
  }, []);

  // Realtime subscription — active while the scan is running
  useEffect(() => {
    if (!activeTarget || activeTarget.status !== 'scanning') return;

    const channel = supabase
      .channel(`scan-${activeTarget.id}`)
      .on(
        'postgres_changes',
        {
          event: 'INSERT',
          schema: 'public',
          table: 'agent_logs',
          filter: `target_id=eq.${activeTarget.id}`,
        },
        (payload) => {
          const newLog = payload.new as Log;
          setLogs((prev) => {
            if (prev.find((l) => l.id === newLog.id)) return prev;
            return [...prev, newLog];
          });
          // Terminal step signals — update local state immediately
          if (newLog.step_name === 'Completed' || newLog.step_name === 'Failed') {
            setScanning(false);
            setActiveTarget((prev) =>
              prev
                ? { ...prev, status: newLog.step_name === 'Completed' ? 'completed' : 'failed' }
                : prev
            );
            fetchTargets();
          }
        }
      )
      .on(
        'postgres_changes',
        {
          event: 'INSERT',
          schema: 'public',
          table: 'vulnerabilities',
          filter: `target_id=eq.${activeTarget.id}`,
        },
        (payload) => {
          const newVuln = payload.new as Vulnerability;
          setVulns((prev) => {
            if (prev.find((v) => v.id === newVuln.id)) return prev;
            return [...prev, newVuln];
          });
        }
      )
      .on(
        'postgres_changes',
        {
          event: 'INSERT',
          schema: 'public',
          table: 'subdomains',
          filter: `target_id=eq.${activeTarget.id}`,
        },
        (payload) => {
          const newSub = payload.new as Subdomain;
          setSubdomains((prev) => {
            if (prev.find((s) => s.id === newSub.id)) return prev;
            return [...prev, newSub];
          });
        }
      )
      .subscribe((status) => {
        setRealtimeStatus(status === 'SUBSCRIBED' ? 'connected' : 'disconnected');
      });

    return () => {
      supabase.removeChannel(channel);
      setRealtimeStatus('disconnected');
    };
  }, [activeTarget?.id, activeTarget?.status]);

  const handleScanSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!domain.trim() || scanning) return;

    setScanning(true);
    setLogs([]);
    setVulns([]);
    setSubdomains([]);
    setActiveTarget(null);

    try {
      const response = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domain: domain.trim() }),
      });

      const data = await response.json();

      if (data.success && data.target_id) {
        // The API is synchronous — by the time we get here, the scan is complete.
        // Update local state to reflect completed status.
        const completedTarget: Target = {
          id: data.target_id,
          domain: domain.trim(),
          status: 'completed',
          created_at: new Date().toISOString(),
        };
        setActiveTarget(completedTarget);
        setTargets((prev) => [completedTarget, ...prev.filter((t) => t.id !== data.target_id)]);
        setScanning(false);
        // Load the full dataset now that the scan is done
        await loadTargetData(completedTarget);
      } else {
        console.error('Scan failed:', data.error);
        setScanning(false);
        alert(`Scan failed: ${data.error}`);
      }
    } catch (error: unknown) {
      const msg = error instanceof Error ? error.message : String(error);
      console.error('Network error:', msg);
      setScanning(false);
      alert(`Network error: ${msg}`);
    }
  };

  // ---------------------------------------------------------------------------
  // Style helpers
  // ---------------------------------------------------------------------------
  const severityColor = (s: string) => {
    if (s === 'Critical') return 'bg-rose-600/20 text-rose-300 border-rose-500/40';
    if (s === 'High') return 'bg-rose-500/20 text-rose-400 border-rose-500/30';
    if (s === 'Medium') return 'bg-amber-500/20 text-amber-400 border-amber-500/30';
    return 'bg-sky-500/20 text-sky-400 border-sky-500/30';
  };

  const logRowStyle = (log: Log) => {
    if (log.log_level === 'critical') return 'bg-rose-950/30 border-rose-500/30 text-rose-300';
    if (log.log_level === 'warning') return 'bg-amber-950/20 border-amber-500/20 text-amber-300';
    if (log.step_name === 'Completed') return 'bg-emerald-950/20 border-emerald-500/20 text-emerald-400';
    if (log.step_name === 'Failed') return 'bg-rose-950/30 border-rose-500/30 text-rose-400';
    return 'bg-slate-950/60 border-slate-800 text-slate-400';
  };

  const statusBadge = (status: string) => {
    if (status === 'completed') return 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30';
    if (status === 'scanning') return 'bg-sky-500/15 text-sky-400 border-sky-500/30 animate-pulse';
    if (status === 'failed') return 'bg-rose-500/15 text-rose-400 border-rose-500/30';
    return 'bg-slate-500/15 text-slate-400 border-slate-500/30';
  };

  const httpStatusColor = (status: number | null) => {
    if (!status) return 'text-slate-600';
    if (status < 300) return 'text-emerald-400';
    if (status < 400) return 'text-sky-400';
    if (status === 404 || status === 410) return 'text-rose-400 font-bold';
    if (status >= 500) return 'text-amber-400';
    return 'text-slate-400';
  };

  const isScanning = scanning;

  return (
    <>
      {/* Remediation Report Modal */}
      {selectedReport && (
        <ReportModal vuln={selectedReport} onClose={() => setSelectedReport(null)} />
      )}

      <div className="min-h-screen bg-slate-950 text-slate-100 font-sans">
        {/* Top Nav */}
        <header className="sticky top-0 z-10 bg-slate-950/90 backdrop-blur border-b border-slate-800 px-6 py-3.5 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <Shield className="w-6 h-6 text-emerald-400" />
            <span className="text-lg font-bold tracking-tight">BountyWire</span>
            <span className="text-[10px] bg-emerald-500/10 text-emerald-400 px-2 py-0.5 rounded-full border border-emerald-500/20 ml-1">
              Agent v2
            </span>
          </div>
          <div className="flex items-center gap-2 text-xs text-slate-500">
            {realtimeStatus === 'connected' ? (
              <>
                <Wifi className="w-4 h-4 text-emerald-400" />
                <span className="text-emerald-400">Realtime Live</span>
              </>
            ) : (
              <>
                <WifiOff className="w-4 h-4" />
                <span>Realtime Idle</span>
              </>
            )}
          </div>
        </header>

        <div className="flex h-[calc(100vh-57px)]">
          {/* Sidebar: Past Scans */}
          <aside className="w-60 shrink-0 border-r border-slate-800 bg-slate-900/40 flex flex-col">
            <div className="flex items-center gap-2 px-4 py-2.5 border-b border-slate-800">
              <Database className="w-3.5 h-3.5 text-slate-500" />
              <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">
                Past Scans
              </span>
            </div>
            <div className="flex-1 overflow-y-auto">
              {targets.length === 0 ? (
                <p className="text-xs text-slate-600 italic text-center mt-8 px-4">No scans yet.</p>
              ) : (
                targets.map((t) => (
                  <button
                    key={t.id}
                    onClick={() => loadTargetData(t)}
                    className={`w-full text-left px-4 py-3 border-b border-slate-800/50 hover:bg-slate-800/50 transition-colors group ${
                      activeTarget?.id === t.id ? 'bg-slate-800/70' : ''
                    }`}
                  >
                    <div className="flex items-center justify-between mb-1">
                      <span className="text-xs text-slate-200 truncate font-medium">{t.domain}</span>
                      <ChevronRight className="w-3 h-3 text-slate-600 group-hover:text-slate-400 transition-colors shrink-0" />
                    </div>
                    <div className="flex items-center gap-2">
                      <span className={`text-[9px] px-1.5 py-0.5 rounded border font-medium ${statusBadge(t.status)}`}>
                        {t.status}
                      </span>
                      <span className="text-[9px] text-slate-600">
                        {new Date(t.created_at).toLocaleDateString()}
                      </span>
                    </div>
                  </button>
                ))
              )}
            </div>
          </aside>

          {/* Main Content */}
          <main className="flex-1 flex flex-col overflow-hidden p-5 gap-4">
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
                  <>
                    <Loader2 className="w-4 h-4 animate-spin" />
                    Scanning...
                  </>
                ) : (
                  'Launch Agent'
                )}
              </button>
            </form>

            {/* Active target status banner */}
            {activeTarget && (
              <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-slate-400 bg-slate-900 border border-slate-800 rounded-lg px-4 py-2.5 max-w-4xl">
                <span className="font-mono text-slate-500">Target:</span>
                <span className="font-semibold text-slate-200">{activeTarget.domain}</span>
                <span className={`px-2 py-0.5 rounded border text-[10px] font-medium ${statusBadge(activeTarget.status)}`}>
                  {activeTarget.status}
                </span>
                <span className="text-slate-600 ml-auto">
                  {logs.length} logs · {subdomains.length} subdomains · {vulns.length} vulns
                </span>
              </div>
            )}

            {/* Three-column panel layout */}
            <div className="grid grid-cols-1 lg:grid-cols-5 gap-4 flex-1 min-h-0">

              {/* Agent Logs — 3/5 width */}
              <div className="lg:col-span-3 bg-slate-900 border border-slate-800 rounded-xl flex flex-col min-h-0">
                <div className="flex items-center gap-2 px-5 py-3 border-b border-slate-800 shrink-0">
                  <Terminal className="w-4 h-4 text-slate-400" />
                  <h2 className="text-sm font-semibold text-slate-200">Agent Reasoning Logs</h2>
                  {logs.length > 0 && (
                    <span className="ml-auto text-[10px] bg-slate-800 text-slate-400 px-2 py-0.5 rounded-full">
                      {logs.length} entries
                    </span>
                  )}
                </div>
                <div className="flex-1 overflow-y-auto p-3 space-y-1.5 font-mono text-xs">
                  {logs.length === 0 ? (
                    <div className="flex flex-col items-center justify-center h-full text-slate-700 gap-2">
                      <Terminal className="w-8 h-8" />
                      <p className="italic text-xs">
                        {isScanning
                          ? 'Agent initializing — logs will stream here...'
                          : activeTarget
                          ? 'Loading logs...'
                          : 'Select a past scan or launch a new one'}
                      </p>
                    </div>
                  ) : (
                    logs.map((log) => (
                      <div key={log.id} className={`p-2.5 rounded border ${logRowStyle(log)}`}>
                        <div className="flex justify-between font-bold mb-0.5 opacity-80">
                          <span>[{log.step_name.toUpperCase()}]</span>
                          <span className="flex items-center gap-1 opacity-60 text-[10px]">
                            <Clock className="w-2.5 h-2.5" />
                            {new Date(log.timestamp).toLocaleTimeString()}
                          </span>
                        </div>
                        <p className="leading-relaxed break-words">{log.message}</p>
                      </div>
                    ))
                  )}
                  <div ref={logsEndRef} />
                </div>
              </div>

              {/* Right column: Subdomains + Vulnerabilities — 2/5 */}
              <div className="lg:col-span-2 flex flex-col gap-4 min-h-0">

                {/* Subdomains Panel */}
                <div className="bg-slate-900 border border-slate-800 rounded-xl flex flex-col" style={{ maxHeight: '40%', minHeight: '160px' }}>
                  <div className="flex items-center gap-2 px-4 py-3 border-b border-slate-800 shrink-0">
                    <ExternalLink className="w-3.5 h-3.5 text-sky-400" />
                    <h2 className="text-sm font-semibold text-slate-200">Probed Subdomains</h2>
                    {subdomains.length > 0 && (
                      <span className="ml-auto text-[10px] bg-sky-500/20 text-sky-400 px-2 py-0.5 rounded-full border border-sky-500/30">
                        {subdomains.length}
                      </span>
                    )}
                  </div>
                  <div className="flex-1 overflow-y-auto">
                    {subdomains.length === 0 ? (
                      <div className="flex items-center justify-center h-full text-slate-700">
                        <p className="text-xs italic">No subdomains discovered yet.</p>
                      </div>
                    ) : (
                      <table className="w-full text-[10px]">
                        <thead className="sticky top-0 bg-slate-900">
                          <tr className="border-b border-slate-800 text-slate-500">
                            <th className="text-left px-3 py-1.5 font-medium">Subdomain</th>
                            <th className="text-left px-3 py-1.5 font-medium">CNAME</th>
                            <th className="text-right px-3 py-1.5 font-medium">HTTP</th>
                          </tr>
                        </thead>
                        <tbody>
                          {subdomains.map((sub) => (
                            <tr key={sub.id} className="border-b border-slate-800/50 hover:bg-slate-800/30 transition-colors">
                              <td className="px-3 py-1.5 font-mono text-slate-300 truncate max-w-[120px]" title={sub.subdomain}>
                                {sub.subdomain}
                              </td>
                              <td className="px-3 py-1.5 font-mono text-sky-400/80 truncate max-w-[100px]" title={sub.cname ?? ''}>
                                {sub.cname ?? <span className="text-slate-700">—</span>}
                              </td>
                              <td className={`px-3 py-1.5 text-right font-mono ${httpStatusColor(sub.http_status)}`}>
                                {sub.http_status ?? '—'}
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    )}
                  </div>
                </div>

                {/* Vulnerabilities Panel */}
                <div className="bg-slate-900 border border-slate-800 rounded-xl flex flex-col flex-1 min-h-0">
                  <div className="flex items-center gap-2 px-4 py-3 border-b border-slate-800 shrink-0">
                    <AlertTriangle className="w-4 h-4 text-amber-500" />
                    <h2 className="text-sm font-semibold text-slate-200">Confirmed Vulnerabilities</h2>
                    {vulns.length > 0 && (
                      <span className="ml-auto text-[10px] bg-rose-500/20 text-rose-400 px-2 py-0.5 rounded-full border border-rose-500/30">
                        {vulns.length} found
                      </span>
                    )}
                  </div>
                  <div className="flex-1 overflow-y-auto p-3 space-y-2.5">
                    {vulns.length === 0 ? (
                      <div className="flex flex-col items-center justify-center h-full text-slate-700 gap-2">
                        <CheckCircle className="w-7 h-7 text-slate-800" />
                        <p className="text-xs italic text-slate-600">No active threats discovered yet.</p>
                      </div>
                    ) : (
                      vulns.map((vuln) => (
                        <div key={vuln.id} className="bg-rose-950/10 border border-rose-500/20 rounded-lg p-3">
                          <div className="flex items-center justify-between mb-2">
                            <span className={`text-[9px] px-2 py-0.5 rounded border font-bold ${severityColor(vuln.severity)}`}>
                              {vuln.severity?.toUpperCase()}
                            </span>
                            <span className="text-[9px] text-slate-500 font-mono">{vuln.vuln_type}</span>
                          </div>
                          <p className="text-xs font-semibold text-rose-200 mb-2">Subdomain Takeover Detected</p>
                          {/* Show first 3 lines of the report as preview */}
                          <div className="bg-slate-950 p-2 rounded font-mono text-[9px] text-slate-500 border border-slate-800 leading-relaxed mb-2 line-clamp-3 overflow-hidden">
                            {vuln.evidence.substring(0, 200)}
                            {vuln.evidence.length > 200 ? '...' : ''}
                          </div>
                          <button
                            onClick={() => setSelectedReport(vuln)}
                            className="w-full flex items-center justify-center gap-1.5 text-[10px] text-rose-400 hover:text-rose-300 border border-rose-500/20 hover:border-rose-500/40 rounded py-1.5 transition-colors bg-rose-950/20 hover:bg-rose-950/40"
                          >
                            <FileText className="w-3 h-3" />
                            View Full Remediation Report
                          </button>
                        </div>
                      ))
                    )}
                  </div>
                </div>

              </div>
            </div>
          </main>
        </div>
      </div>
    </>
  );
}