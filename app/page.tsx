'use client';

import { useState, useEffect, useCallback, useRef } from 'react';
import { createClient } from '@supabase/supabase-js';
import { Shield, Terminal, TriangleAlert as AlertTriangle, CircleCheck as CheckCircle, Search, Loader as Loader2, Clock, ChevronRight, Database, Wifi, WifiOff, FileText, X, ExternalLink, Brain, Wrench, Zap, Activity, Cpu, Eye, Sparkles, ShieldCheck, Download, Radar, Scan, Target, Bug, OctagonAlert as AlertOctagon } from 'lucide-react';

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
  evidence: string;
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
// Animated Radar Sweep Component
// ---------------------------------------------------------------------------
function RadarSweep() {
  return (
    <div className="relative w-24 h-24">
      <div className="absolute inset-0 rounded-full border border-slate-700" />
      <div className="absolute inset-4 rounded-full border border-slate-700/50" />
      <div className="absolute inset-8 rounded-full border border-slate-700/30" />
      <div className="absolute inset-0 rounded-full overflow-hidden">
        <div
          className="absolute inset-0 origin-center animate-spin"
          style={{ animationDuration: '3s' }}
        >
          <div
            className="absolute top-1/2 left-1/2 w-1/2 h-0.5 origin-left"
            style={{
              background: 'linear-gradient(90deg, rgba(139, 92, 246, 0.8), transparent)',
              transform: 'translateY(-50%)',
            }}
          />
          <div
            className="absolute top-1/2 left-1/2 w-1/2 h-24 origin-left -translate-y-1/2"
            style={{
              background: 'linear-gradient(90deg, rgba(139, 92, 246, 0.15), transparent)',
              clipPath: 'polygon(0 50%, 100% 0, 100% 100%)',
            }}
          />
        </div>
      </div>
      <div className="absolute inset-0 flex items-center justify-center">
        <Target className="w-5 h-5 text-violet-400" />
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Skeleton Loader Components
// ---------------------------------------------------------------------------
function LogSkeleton() {
  return (
    <div className="p-3 rounded-lg bg-slate-900/50 border border-slate-800 animate-pulse">
      <div className="flex items-center gap-2 mb-2">
        <div className="w-3.5 h-3.5 rounded bg-slate-700" />
        <div className="h-3 w-24 bg-slate-700 rounded" />
        <div className="ml-auto h-2.5 w-16 bg-slate-800 rounded" />
      </div>
      <div className="pl-5 space-y-1.5">
        <div className="h-2.5 bg-slate-700 rounded w-full" />
        <div className="h-2.5 bg-slate-700 rounded w-4/5" />
      </div>
    </div>
  );
}

function SubdomainTableSkeleton() {
  return (
    <div className="space-y-1.5 p-2">
      {[...Array(5)].map((_, i) => (
        <div key={i} className="flex items-center gap-3 px-3 py-2 animate-pulse">
          <div className="h-3 w-28 bg-slate-700 rounded" />
          <div className="h-3 w-24 bg-slate-700/70 rounded" />
          <div className="ml-auto h-3 w-10 bg-slate-700/50 rounded" />
        </div>
      ))}
    </div>
  );
}

function VulnerabilityCardSkeleton() {
  return (
    <div className="p-3 rounded-lg bg-slate-900/50 border border-slate-800 animate-pulse space-y-2">
      <div className="flex items-center justify-between">
        <div className="h-4 w-16 bg-slate-700 rounded" />
        <div className="h-3 w-20 bg-slate-700/70 rounded" />
      </div>
      <div className="h-3 w-32 bg-slate-700 rounded" />
      <div className="space-y-1.5 mt-2">
        <div className="h-2.5 bg-slate-700 rounded w-full" />
        <div className="h-2.5 bg-slate-700 rounded w-3/4" />
      </div>
      <div className="h-7 bg-slate-700/50 rounded mt-2" />
    </div>
  );
}

// ---------------------------------------------------------------------------
// Animated Progress Bar
// ---------------------------------------------------------------------------
function GlobalProgressBar({ isScanning }: { isScanning: boolean }) {
  if (!isScanning) return null;

  return (
    <div className="absolute top-0 left-0 right-0 h-1 bg-slate-800 overflow-hidden z-20">
      <div
        className="h-full bg-gradient-to-r from-violet-500 via-cyan-400 to-violet-500 animate-shimmer"
        style={{
          width: '30%',
          animation: 'shimmer 1.5s ease-in-out infinite',
        }}
      />
      <style jsx global>{`
        @keyframes shimmer {
          0% { transform: translateX(-100%); }
          100% { transform: translateX(400%); }
        }
      `}</style>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Scanning Diagnostics Panel
// ---------------------------------------------------------------------------
function ScanningDiagnostics({ domain }: { domain: string }) {
  const [counter, setCounter] = useState(0);
  const [phase, setPhase] = useState(0);

  const phases = [
    'Initializing ReAct Agent...',
    'Enumerating Certificate Logs...',
    'Probing DNS Records...',
    'Executing Security Tools...',
    'Analyzing Takeover Surface...',
    'Generating Vulnerability Reports...',
  ];

  useEffect(() => {
    const counterInterval = setInterval(() => {
      setCounter((c) => c + 1);
    }, 100);

    const phaseInterval = setInterval(() => {
      setPhase((p) => (p + 1) % phases.length);
    }, 2500);

    return () => {
      clearInterval(counterInterval);
      clearInterval(phaseInterval);
    };
  }, []);

  return (
    <div className="flex flex-col items-center justify-center h-full gap-6 py-8">
      <RadarSweep />
      <div className="text-center space-y-2">
        <p className="text-xs font-mono text-violet-400 uppercase tracking-widest">
          Autonomous Scan Active
        </p>
        <p className="text-sm text-slate-400 font-medium">{phases[phase]}</p>
        <p className="font-mono text-slate-600 text-xs">
          Target: <span className="text-slate-400">{domain}</span>
        </p>
      </div>
      <div className="flex items-center gap-4 text-[10px] font-mono text-slate-600">
        <span className="flex items-center gap-1.5">
          <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
          DNS Queries: {Math.floor(counter / 3)}
        </span>
        <span className="flex items-center gap-1.5">
          <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-pulse" />
          HTTP Probes: {Math.floor(counter / 5)}
        </span>
        <span className="flex items-center gap-1.5">
          <span className="w-1.5 h-1.5 rounded-full bg-violet-400 animate-pulse" />
          Elapsed: {Math.floor(counter / 10)}s
        </span>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Log entry icon component with precise mappings
// ---------------------------------------------------------------------------
function LogEntryIcon({ stepName }: { stepName: string }) {
  const iconClass = "w-3.5 h-3.5 shrink-0";

  if (stepName === 'Agent Reasoning') {
    return <Brain className={`${iconClass} text-violet-400`} />;
  }
  if (stepName === 'Tool Execution') {
    return <Cpu className={`${iconClass} text-cyan-400`} />;
  }
  if (stepName === 'Tool Result') {
    return <Zap className={`${iconClass} text-emerald-400`} />;
  }
  if (stepName === 'Initialization' || stepName === 'Agent Start') {
    return <Scan className={`${iconClass} text-sky-400`} />;
  }
  if (stepName === 'Discovery') {
    return <Radar className={`${iconClass} text-amber-400`} />;
  }
  if (stepName === 'Completed') {
    return <ShieldCheck className={`${iconClass} text-emerald-400`} />;
  }
  if (stepName === 'Failed') {
    return <AlertOctagon className={`${iconClass} text-rose-400`} />;
  }
  if (stepName === 'Agent Error') {
    return <AlertTriangle className={`${iconClass} text-rose-400`} />;
  }
  if (stepName.includes('Verification')) {
    return <ShieldCheck className={`${iconClass} text-purple-400`} />;
  }
  if (stepName.includes('Analysis')) {
    return <Sparkles className={`${iconClass} text-purple-400`} />;
  }
  return <Terminal className={`${iconClass} text-slate-400`} />;
}

// ---------------------------------------------------------------------------
// Agent activity indicator component
// ---------------------------------------------------------------------------
function AgentActivityIndicator({ isScanning, logs }: { isScanning: boolean; logs: Log[] }) {
  if (!isScanning) return null;

  const stepName = logs[logs.length - 1]?.step_name ?? '';

  let activityText = 'Agent thinking...';
  let activityIcon = <Brain className="w-3.5 h-3.5 animate-pulse" />;
  let activityColor = 'text-violet-400';
  let bgColor = 'bg-violet-500/10 border-violet-500/30';

  if (stepName === 'Tool Execution') {
    activityText = 'Executing tool...';
    activityIcon = <Cpu className="w-3.5 h-3.5 animate-spin" />;
    activityColor = 'text-cyan-400';
    bgColor = 'bg-cyan-500/10 border-cyan-500/30';
  } else if (stepName === 'Tool Result') {
    activityText = 'Analyzing result...';
    activityIcon = <Activity className="w-3.5 h-3.5 animate-pulse" />;
    activityColor = 'text-emerald-400';
    bgColor = 'bg-emerald-500/10 border-emerald-500/30';
  } else if (stepName === 'Discovery') {
    activityText = 'Enumerating assets...';
    activityIcon = <Radar className="w-3.5 h-3.5 animate-pulse" />;
    activityColor = 'text-amber-400';
    bgColor = 'bg-amber-500/10 border-amber-500/30';
  } else if (stepName === 'Agent Reasoning') {
    activityText = 'Planning next action...';
    activityIcon = <Brain className="w-3.5 h-3.5 animate-pulse" />;
    activityColor = 'text-violet-400';
    bgColor = 'bg-violet-500/10 border-violet-500/30';
  }

  return (
    <div className={`flex items-center gap-2 px-3 py-1.5 rounded-lg border text-xs ${activityColor} ${bgColor}`}>
      {activityIcon}
      <span className="font-medium">{activityText}</span>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Markdown - HTML renderer
// ---------------------------------------------------------------------------
function renderMarkdown(md: string): string {
  return md
    .replace(/^### (.+)$/gm, '<h3 class="text-base font-bold text-rose-300 mt-5 mb-2">$1</h3>')
    .replace(/^## (.+)$/gm, '<h2 class="text-lg font-bold text-rose-200 mt-6 mb-2 border-b border-rose-500/20 pb-1">$1</h2>')
    .replace(/^# (.+)$/gm, '<h1 class="text-xl font-bold text-white mt-4 mb-3">$1</h1>')
    .replace(/\*\*(.+?)\*\*/g, '<strong class="text-slate-200 font-semibold">$1</strong>')
    .replace(/\*(.+?)\*/g, '<em class="text-slate-300 italic">$1</em>')
    .replace(/`([^`]+)`/g, '<code class="bg-slate-800 text-emerald-400 px-1.5 py-0.5 rounded text-xs font-mono">$1</code>')
    .replace(/```[\w]*\n([\s\S]+?)```/g, '<pre class="bg-slate-950 border border-slate-700 rounded-lg p-4 overflow-x-auto text-xs font-mono text-emerald-300 my-3 leading-relaxed shadow-lg"><code>$1</code></pre>')
    .replace(/^\d+\. (.+)$/gm, '<li class="ml-5 list-decimal text-slate-300 mb-1">$1</li>')
    .replace(/^[-*] (.+)$/gm, '<li class="ml-5 list-disc text-slate-300 mb-1">$1</li>')
    .replace(/\n\n/g, '</p><p class="text-slate-400 text-sm leading-relaxed mb-3">')
    .replace(/^/, '<p class="text-slate-400 text-sm leading-relaxed mb-3">')
    .replace(/$/, '</p>');
}

// ---------------------------------------------------------------------------
// Premium Remediation Report Modal
// ---------------------------------------------------------------------------
function ReportModal({ vuln, onClose }: { vuln: Vulnerability; onClose: () => void }) {
  const isMarkdown = vuln.evidence.startsWith('#') || vuln.evidence.includes('##');

  const handleExport = () => {
    const blob = new Blob([vuln.evidence], { type: 'text/markdown' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `security-report-${vuln.id}.md`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-md p-6"
      onClick={onClose}
    >
      <div
        className="relative w-full max-w-5xl max-h-[90vh] bg-gradient-to-b from-slate-900 to-slate-950 border border-slate-700 rounded-2xl shadow-2xl flex flex-col overflow-hidden"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header with Export Action */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-slate-700 bg-slate-800/50 shrink-0">
          <div className="flex items-center gap-4">
            <div className="p-2 rounded-lg bg-rose-500/10 border border-rose-500/30">
              <AlertOctagon className="w-5 h-5 text-rose-400" />
            </div>
            <div>
              <h2 className="text-base font-bold text-white">Security Advisory Report</h2>
              <p className="text-xs text-slate-400">{vuln.vuln_type} - Severity: {vuln.severity}</p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={handleExport}
              className="flex items-center gap-2 px-4 py-2 bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-semibold rounded-lg transition-colors"
            >
              <Download className="w-3.5 h-3.5" />
              Export Report
            </button>
            <button
              onClick={onClose}
              className="p-2 rounded-lg hover:bg-slate-700 text-slate-400 hover:text-white transition-colors"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* Asset Meta Information - Dual Column */}
        <div className="px-6 py-4 border-b border-slate-800 bg-slate-900/50 shrink-0">
          <div className="grid grid-cols-2 gap-4">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-slate-800">
                <Bug className="w-4 h-4 text-rose-400" />
              </div>
              <div>
                <p className="text-[10px] uppercase tracking-wider text-slate-500">Vulnerability Type</p>
                <p className="text-sm font-medium text-slate-200">{vuln.vuln_type}</p>
              </div>
            </div>
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-slate-800">
                <AlertTriangle className="w-4 h-4 text-amber-400" />
              </div>
              <div>
                <p className="text-[10px] uppercase tracking-wider text-slate-500">Severity Level</p>
                <p className={`text-sm font-medium ${vuln.severity === 'Critical' ? 'text-rose-400' : vuln.severity === 'High' ? 'text-amber-400' : 'text-sky-400'}`}>
                  {vuln.severity}
                </p>
              </div>
            </div>
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-slate-800">
                <Clock className="w-4 h-4 text-slate-400" />
              </div>
              <div>
                <p className="text-[10px] uppercase tracking-wider text-slate-500">Discovered</p>
                <p className="text-sm font-medium text-slate-200">{new Date(vuln.created_at).toLocaleString()}</p>
              </div>
            </div>
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-slate-800">
                <FileText className="w-4 h-4 text-slate-400" />
              </div>
              <div>
                <p className="text-[10px] uppercase tracking-wider text-slate-500">Report ID</p>
                <p className="text-sm font-mono text-slate-400 truncate">{vuln.id.substring(0, 8)}...</p>
              </div>
            </div>
          </div>
        </div>

        {/* Report Body with Card Container */}
        <div className="flex-1 overflow-y-auto p-6">
          <div className="bg-slate-950 border border-slate-800 rounded-xl shadow-xl p-6">
            {isMarkdown ? (
              <div
                className="prose-report prose-invert max-w-none"
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
    </div>
  );
}

// ---------------------------------------------------------------------------
// HTTP Status Badge with Pulsing Animation for 404/410
// ---------------------------------------------------------------------------
function HttpStatusBadge({ status }: { status: number | null }) {
  if (!status) {
    return <span className="text-slate-600 font-mono">-</span>;
  }

  const isError = status === 404 || status === 410;
  const baseClass = "px-1.5 py-0.5 rounded text-[10px] font-mono font-medium";

  if (isError) {
    return (
      <span className={`${baseClass} bg-rose-500/20 text-rose-400 border border-rose-500/30 animate-pulse`}>
        {status}
      </span>
    );
  }

  if (status < 300) {
    return <span className={`${baseClass} text-emerald-400`}>{status}</span>;
  }
  if (status < 400) {
    return <span className={`${baseClass} text-sky-400`}>{status}</span>;
  }
  if (status >= 500) {
    return <span className={`${baseClass} text-amber-400`}>{status}</span>;
  }
  return <span className={`${baseClass} text-slate-400`}>{status}</span>;
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

  useEffect(() => {
    logsEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [logs]);

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
        const completedTarget: Target = {
          id: data.target_id,
          domain: domain.trim(),
          status: 'completed',
          created_at: new Date().toISOString(),
        };
        setActiveTarget(completedTarget);
        setTargets((prev) => [completedTarget, ...prev.filter((t) => t.id !== data.target_id)]);
        setScanning(false);
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

  const logRowLeftAccent = (log: Log): string => {
    if (log.log_level === 'critical') return 'border-l-rose-500';
    if (log.log_level === 'warning') return 'border-l-amber-500';
    if (log.step_name === 'Completed') return 'border-l-emerald-500';
    if (log.step_name === 'Failed') return 'border-l-rose-500';
    if (log.step_name === 'Agent Reasoning') return 'border-l-violet-500';
    if (log.step_name === 'Tool Execution') return 'border-l-cyan-500';
    if (log.step_name === 'Tool Result') return 'border-l-emerald-500';
    if (log.step_name === 'Discovery') return 'border-l-amber-500';
    if (log.step_name === 'Agent Error') return 'border-l-rose-500';
    return 'border-l-slate-600';
  };

  const logRowBg = (log: Log): string => {
    if (log.log_level === 'critical') return 'bg-rose-950/30';
    if (log.log_level === 'warning') return 'bg-amber-950/20';
    if (log.step_name === 'Completed') return 'bg-emerald-950/20';
    if (log.step_name === 'Failed') return 'bg-rose-950/30';
    if (log.step_name === 'Agent Reasoning') return 'bg-violet-950/20';
    if (log.step_name === 'Tool Execution') return 'bg-cyan-950/20';
    if (log.step_name === 'Tool Result') return 'bg-emerald-950/10';
    if (log.step_name === 'Discovery') return 'bg-amber-950/10';
    if (log.step_name === 'Agent Error') return 'bg-rose-950/20';
    return 'bg-slate-900/50';
  };

  const logRowText = (log: Log): string => {
    if (log.log_level === 'critical') return 'text-rose-200';
    if (log.log_level === 'warning') return 'text-amber-200';
    if (log.step_name === 'Completed') return 'text-emerald-300';
    if (log.step_name === 'Failed') return 'text-rose-300';
    if (log.step_name === 'Agent Reasoning') return 'text-violet-200';
    if (log.step_name === 'Tool Execution') return 'text-cyan-200';
    if (log.step_name === 'Tool Result') return 'text-emerald-300';
    if (log.step_name === 'Discovery') return 'text-amber-300';
    if (log.step_name === 'Agent Error') return 'text-rose-300';
    return 'text-slate-300';
  };

  const statusBadge = (status: string): string => {
    if (status === 'completed') return 'bg-emerald-500/15 text-emerald-400 border-emerald-500/30';
    if (status === 'scanning') return 'bg-violet-500/15 text-violet-400 border-violet-500/30 animate-pulse';
    if (status === 'failed') return 'bg-rose-500/15 text-rose-400 border-rose-500/30';
    return 'bg-slate-500/15 text-slate-400 border-slate-500/30';
  };

  const isScanning = scanning;

  return (
    <>
      {selectedReport && (
        <ReportModal vuln={selectedReport} onClose={() => setSelectedReport(null)} />
      )}

      <div className="min-h-screen bg-slate-950 text-slate-100 font-sans antialiased">
        {/* Top Nav */}
        <header className="sticky top-0 z-10 bg-slate-950/95 backdrop-blur border-b border-slate-800 px-6 py-3.5 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="relative">
              <Shield className="w-6 h-6 text-emerald-400" />
              {isScanning && (
                <span className="absolute -top-0.5 -right-0.5 w-2.5 h-2.5 bg-violet-500 rounded-full animate-ping" />
              )}
            </div>
            <span className="text-lg font-bold tracking-tight text-white">BountyWire</span>
            <span className="text-[10px] bg-violet-500/10 text-violet-400 px-2.5 py-0.5 rounded-full border border-violet-500/30 ml-1 font-bold tracking-wide">
              ReAct Agent
            </span>
          </div>
          <div className="flex items-center gap-4">
            {isScanning && <AgentActivityIndicator isScanning={isScanning} logs={logs} />}
            <div className="flex items-center gap-2 text-xs text-slate-500">
              {realtimeStatus === 'connected' ? (
                <>
                  <Wifi className="w-4 h-4 text-emerald-400" />
                  <span className="text-emerald-400 font-medium">Realtime Live</span>
                </>
              ) : (
                <>
                  <WifiOff className="w-4 h-4" />
                  <span>Realtime Idle</span>
                </>
              )}
            </div>
          </div>
        </header>

        <div className="flex h-[calc(100vh-57px)]">
          {/* Sidebar: Past Scans */}
          <aside className="w-64 shrink-0 border-r border-slate-800 bg-slate-900/30 flex flex-col">
            <div className="flex items-center gap-2 px-4 py-2.5 border-b border-slate-800">
              <Database className="w-3.5 h-3.5 text-slate-500" />
              <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">
                Scan History
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
                      activeTarget?.id === t.id ? 'bg-slate-800/70 border-l-2 border-l-emerald-500' : ''
                    }`}
                  >
                    <div className="flex items-center justify-between mb-1">
                      <span className="text-xs font-medium text-slate-200 truncate">{t.domain}</span>
                      <ChevronRight className="w-3 h-3 text-slate-600 group-hover:text-slate-400 transition-colors shrink-0" />
                    </div>
                    <div className="flex items-center gap-2">
                      <span className={`text-[9px] px-1.5 py-0.5 rounded border font-medium ${statusBadge(t.status)}`}>
                        {t.status}
                      </span>
                      <span className="text-[9px] text-slate-600 font-mono">
                        {new Date(t.created_at).toLocaleDateString()}
                      </span>
                    </div>
                  </button>
                ))
              )}
            </div>
          </aside>

          {/* Main Content */}
          <main className="flex-1 flex flex-col overflow-hidden p-5 gap-4 relative">
            {/* Global Progress Bar */}
            <GlobalProgressBar isScanning={isScanning} />

            {/* Scan Input */}
            <form onSubmit={handleScanSubmit} className="flex gap-3 max-w-2xl">
              <div className="relative flex-1">
                <Search className="absolute left-3.5 top-1/2 -translate-y-1/2 h-4 w-4 text-slate-500" />
                <input
                  type="text"
                  placeholder="Enter target domain (e.g., example.com)"
                  value={domain}
                  onChange={(e) => setDomain(e.target.value)}
                  disabled={isScanning}
                  className="w-full bg-slate-900 border border-slate-700 rounded-xl pl-10 pr-4 py-3 text-sm text-slate-200 focus:outline-none focus:ring-2 focus:ring-violet-500/50 focus:border-violet-500 disabled:opacity-50 transition-all placeholder:text-slate-600"
                />
              </div>
              <button
                type="submit"
                disabled={isScanning || !domain.trim()}
                className="bg-violet-600 hover:bg-violet-500 disabled:opacity-50 disabled:cursor-not-allowed text-white text-sm font-semibold px-6 py-3 rounded-xl flex items-center gap-2.5 transition-colors shadow-lg shadow-violet-500/20"
              >
                {isScanning ? (
                  <>
                    <Loader2 className="w-4 h-4 animate-spin" />
                    Agent Running...
                  </>
                ) : (
                  <>
                    <Cpu className="w-4 h-4" />
                    Launch Agent
                  </>
                )}
              </button>
            </form>

            {/* Active target status banner */}
            {activeTarget && (
              <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-slate-400 bg-slate-900/80 border border-slate-800 rounded-xl px-4 py-3 max-w-4xl">
                <span className="text-slate-500 font-medium">Target:</span>
                <span className="font-semibold text-slate-200 font-mono">{activeTarget.domain}</span>
                <span className={`px-2.5 py-1 rounded-lg border text-[10px] font-bold uppercase tracking-wide ${statusBadge(activeTarget.status)}`}>
                  {activeTarget.status === 'scanning' ? 'Autonomous Reasoning' : activeTarget.status}
                </span>
                <span className="text-slate-600 ml-auto flex items-center gap-2 font-mono">
                  <span className="flex items-center gap-1">
                    <Cpu className="w-3 h-3 text-cyan-400" />
                    {logs.filter(l => l.step_name === 'Tool Execution').length}
                  </span>
                  <span className="flex items-center gap-1">
                    <Brain className="w-3 h-3 text-violet-400" />
                    {logs.filter(l => l.step_name === 'Agent Reasoning').length}
                  </span>
                  <span className="flex items-center gap-1">
                    <Target className="w-3 h-3 text-sky-400" />
                    {subdomains.length}
                  </span>
                  <span className="flex items-center gap-1">
                    <Bug className="w-3 h-3 text-rose-400" />
                    {vulns.length}
                  </span>
                </span>
              </div>
            )}

            {/* Three-column panel layout */}
            <div className="grid grid-cols-1 lg:grid-cols-5 gap-4 flex-1 min-h-0">

              {/* Agent Logs - 3/5 width */}
              <div className="lg:col-span-3 bg-slate-900/50 border border-slate-800 rounded-xl flex flex-col min-h-0 overflow-hidden">
                <div className="flex items-center gap-2 px-5 py-3 border-b border-slate-800 shrink-0 bg-slate-900/80">
                  <Brain className="w-4 h-4 text-violet-400" />
                  <h2 className="text-sm font-semibold text-slate-200">Autonomous Agent Reasoning</h2>
                  {logs.length > 0 && (
                    <span className="ml-auto text-[10px] bg-violet-500/20 text-violet-400 px-2 py-0.5 rounded-full border border-violet-500/30 font-mono">
                      {logs.length} steps
                    </span>
                  )}
                </div>
                <div className="flex-1 overflow-y-auto p-3 space-y-2">
                  {isScanning && logs.length === 0 ? (
                    <ScanningDiagnostics domain={domain} />
                  ) : logs.length === 0 ? (
                    <div className="flex flex-col items-center justify-center h-full text-slate-700 gap-3">
                      <Terminal className="w-10 h-10 text-slate-700" />
                      <p className="text-xs text-center text-slate-600">
                        {activeTarget
                          ? 'Loading agent trace...'
                          : 'Launch a new scan to watch the autonomous agent reasoning in real-time'}
                      </p>
                    </div>
                  ) : (
                    logs.map((log) => (
                      <div
                        key={log.id}
                        className={`p-3 rounded-lg border-l-[3px] border border-slate-800/50 ${logRowLeftAccent(log)} ${logRowBg(log)} ${logRowText(log)} transition-all`}
                      >
                        <div className="flex items-center gap-2 mb-1.5">
                          <LogEntryIcon stepName={log.step_name} />
                          <span className="font-bold text-[11px] uppercase tracking-wide">
                            {log.step_name}
                          </span>
                          <span className="flex items-center gap-1 ml-auto opacity-50 text-[10px] font-mono">
                            <Clock className="w-2.5 h-2.5" />
                            {new Date(log.timestamp).toLocaleTimeString()}
                          </span>
                        </div>
                        <p className="leading-relaxed break-words text-xs pl-5 font-mono">
                          {log.message}
                        </p>
                      </div>
                    ))
                  )}
                  <div ref={logsEndRef} />
                </div>
              </div>

              {/* Right column: Subdomains + Vulnerabilities - 2/5 */}
              <div className="lg:col-span-2 flex flex-col gap-4 min-h-0">

                {/* Subdomains Panel - Fixed height ratio */}
                <div className="bg-slate-900/50 border border-slate-800 rounded-xl flex flex-col min-h-[200px] max-h-[45%] overflow-hidden">
                  <div className="flex items-center gap-2 px-4 py-3 border-b border-slate-800 shrink-0 bg-slate-900/80">
                    <ExternalLink className="w-3.5 h-3.5 text-sky-400" />
                    <h2 className="text-sm font-semibold text-slate-200">Discovered Assets</h2>
                    {subdomains.length > 0 && (
                      <span className="ml-auto text-[10px] bg-sky-500/20 text-sky-400 px-2 py-0.5 rounded-full border border-sky-500/30 font-mono">
                        {subdomains.length}
                      </span>
                    )}
                  </div>
                  <div className="flex-1 overflow-y-auto">
                    {isScanning && subdomains.length === 0 ? (
                      <SubdomainTableSkeleton />
                    ) : subdomains.length === 0 ? (
                      <div className="flex items-center justify-center h-full text-slate-700 py-8">
                        <p className="text-xs italic text-slate-600">No assets enumerated yet.</p>
                      </div>
                    ) : (
                      <table className="w-full text-[11px]">
                        <thead className="sticky top-0 bg-slate-900">
                          <tr className="border-b border-slate-800 text-slate-500 uppercase tracking-wider">
                            <th className="text-left px-3 py-2 font-semibold text-[9px]">Subdomain</th>
                            <th className="text-left px-3 py-2 font-semibold text-[9px]">CNAME</th>
                            <th className="text-right px-3 py-2 font-semibold text-[9px]">HTTP</th>
                          </tr>
                        </thead>
                        <tbody>
                          {subdomains.map((sub) => (
                            <tr key={sub.id} className="border-b border-slate-800/30 hover:bg-slate-800/30 transition-colors">
                              <td className="px-3 py-2 font-mono text-slate-300 truncate max-w-[140px]" title={sub.subdomain}>
                                {sub.subdomain}
                              </td>
                              <td className="px-3 py-2 font-mono text-sky-400/80 truncate max-w-[110px]" title={sub.cname ?? ''}>
                                {sub.cname ?? <span className="text-slate-700">-</span>}
                              </td>
                              <td className="px-3 py-2 text-right">
                                <HttpStatusBadge status={sub.http_status} />
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    )}
                  </div>
                </div>

                {/* Vulnerabilities Panel - Remaining space */}
                <div className="bg-slate-900/50 border border-slate-800 rounded-xl flex flex-col flex-1 min-h-0 overflow-hidden">
                  <div className="flex items-center gap-2 px-4 py-3 border-b border-slate-800 shrink-0 bg-slate-900/80">
                    <AlertTriangle className="w-4 h-4 text-amber-500" />
                    <h2 className="text-sm font-semibold text-slate-200">Confirmed Vulnerabilities</h2>
                    {vulns.length > 0 && (
                      <span className="ml-auto text-[10px] bg-rose-500/20 text-rose-400 px-2 py-0.5 rounded-full border border-rose-500/30 font-mono font-bold">
                        {vulns.length} found
                      </span>
                    )}
                  </div>
                  <div className="flex-1 overflow-y-auto p-3 space-y-3">
                    {isScanning && vulns.length === 0 ? (
                      <>
                        <VulnerabilityCardSkeleton />
                        <VulnerabilityCardSkeleton />
                      </>
                    ) : vulns.length === 0 ? (
                      <div className="flex flex-col items-center justify-center h-full text-slate-700 gap-3 py-8">
                        <ShieldCheck className="w-10 h-10 text-slate-700" />
                        <p className="text-xs italic text-slate-600 text-center">No active threats discovered yet.</p>
                      </div>
                    ) : (
                      vulns.map((vuln) => (
                        <div key={vuln.id} className="bg-rose-950/10 border border-rose-500/20 rounded-xl p-4 hover:border-rose-500/40 transition-colors">
                          <div className="flex items-center justify-between mb-2">
                            <span className={`text-[10px] px-2 py-1 rounded-lg border font-bold uppercase tracking-wider ${severityColor(vuln.severity)}`}>
                              {vuln.severity}
                            </span>
                            <span className="text-[10px] text-slate-500 font-mono">{vuln.vuln_type}</span>
                          </div>
                          <p className="text-xs font-semibold text-rose-200 mb-2">Subdomain Takeover Detected</p>
                          <div className="bg-slate-950 p-3 rounded-lg font-mono text-[10px] text-slate-500 border border-slate-800 leading-relaxed mb-3 line-clamp-3 overflow-hidden">
                            {vuln.evidence.substring(0, 180)}
                            {vuln.evidence.length > 180 ? '...' : ''}
                          </div>
                          <button
                            onClick={() => setSelectedReport(vuln)}
                            className="w-full flex items-center justify-center gap-2 text-[11px] text-rose-400 hover:text-rose-300 border border-rose-500/20 hover:border-rose-500/40 rounded-lg py-2 transition-colors bg-rose-950/20 hover:bg-rose-950/40 font-medium"
                          >
                            <FileText className="w-3.5 h-3.5" />
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
