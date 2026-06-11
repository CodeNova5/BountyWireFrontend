'use client';

import { useState, useEffect, useCallback, useRef } from 'react';
import { createClient } from '@supabase/supabase-js';
import { Shield, Terminal, TriangleAlert as AlertTriangle, CircleCheck as CheckCircle, Search, Loader as Loader2, Clock, ChevronRight, Database, Wifi, WifiOff, FileText, X, ExternalLink, Brain, Wrench, Zap, Activity, Cpu, Eye, Sparkles, ShieldCheck, Download, Radar, Scan, Target, Bug, OctagonAlert as AlertOctagon, TrendingUp, Zap as Lightning, Gauge, ArrowUp, ArrowDown } from 'lucide-react';

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
// Animated Threat Gauge Component
// ---------------------------------------------------------------------------
function ThreatGauge({ vulnerabilityCount, isScanning }: { vulnerabilityCount: number; isScanning: boolean }) {
  const [displayCount, setDisplayCount] = useState(0);

  useEffect(() => {
    if (vulnerabilityCount > displayCount) {
      const interval = setInterval(() => {
        setDisplayCount((prev) => Math.min(prev + 1, vulnerabilityCount));
      }, 100);
      return () => clearInterval(interval);
    }
  }, [vulnerabilityCount, displayCount]);

  const threatLevel = Math.min(100, (displayCount / 10) * 100);
  const threatColor = displayCount === 0 ? 'from-emerald-500 to-cyan-500' : displayCount < 3 ? 'from-amber-500 to-orange-500' : 'from-rose-500 to-red-600';

  return (
    <div className="relative w-32 h-32 flex items-center justify-center">
      <svg className="absolute w-full h-full" viewBox="0 0 120 120">
        {/* Background circle */}
        <circle cx="60" cy="60" r="50" fill="none" stroke="rgba(100, 116, 139, 0.2)" strokeWidth="8" />
        {/* Progress circle */}
        <circle
          cx="60"
          cy="60"
          r="50"
          fill="none"
          stroke="url(#threatGradient)"
          strokeWidth="8"
          strokeDasharray={`${(threatLevel / 100) * 314.159} 314.159`}
          strokeLinecap="round"
          style={{ transition: 'stroke-dasharray 0.3s ease' }}
          transform="rotate(-90 60 60)"
        />
        <defs>
          <linearGradient id="threatGradient" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" stopColor={displayCount === 0 ? '#10b981' : displayCount < 3 ? '#f59e0b' : '#ef4444'} />
            <stop offset="100%" stopColor={displayCount === 0 ? '#06b6d4' : displayCount < 3 ? '#f97316' : '#dc2626'} />
          </linearGradient>
        </defs>
      </svg>

      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <div className={`text-4xl font-black bg-gradient-to-r ${threatColor} bg-clip-text text-transparent`}>
          {displayCount}
        </div>
        <div className="text-xs text-slate-500 font-semibold">THREATS</div>
      </div>

      {isScanning && (
        <div className="absolute inset-0 rounded-full border-2 border-transparent border-t-violet-500 animate-spin" style={{ animationDuration: '2s' }} />
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Animated Progress Bar
// ---------------------------------------------------------------------------
function GlobalStyles() {
  return (
    <style dangerouslySetInnerHTML={{ __html: `
      @keyframes shimmer {
        0% { transform: translateX(-100%); }
        100% { transform: translateX(400%); }
      }
      @keyframes float {
        0%, 100% { transform: translateY(0px); }
        50% { transform: translateY(-8px); }
      }
      @keyframes pulse-glow {
        0%, 100% { filter: drop-shadow(0 0 20px rgba(6, 182, 212, 0.3)); }
        50% { filter: drop-shadow(0 0 40px rgba(6, 182, 212, 0.6)); }
      }
      ::-webkit-scrollbar { width: 6px; }
      ::-webkit-scrollbar-track { background: transparent; }
      ::-webkit-scrollbar-thumb { background: rgba(71, 85, 105, 0.5); border-radius: 3px; }
      ::-webkit-scrollbar-thumb:hover { background: rgba(71, 85, 105, 0.7); }
    ` }} />
  );
}

function GlobalProgressBar({ isScanning }: { isScanning: boolean }) {
  if (!isScanning) return null;

  return (
    <div className="absolute top-0 left-0 right-0 h-1 bg-slate-800 overflow-hidden z-20">
      <div
        className="h-full bg-gradient-to-r from-cyan-500 via-violet-500 to-cyan-500"
        style={{
          width: '30%',
          animation: 'shimmer 1.5s ease-in-out infinite',
        }}
      />
    </div>
  );
}

// ---------------------------------------------------------------------------
// Scan Status Badge
// ---------------------------------------------------------------------------
function ScanStatusBadge({ status, count }: { status: string; count: number }) {
  const badges = {
    assets: { icon: ExternalLink, label: 'Assets', color: 'from-cyan-400 to-blue-500', bg: 'bg-cyan-500/10' },
    vulnerabilities: { icon: AlertTriangle, label: 'Vulns', color: 'from-rose-400 to-red-500', bg: 'bg-rose-500/10' },
    secure: { icon: CheckCircle, label: 'Secure', color: 'from-emerald-400 to-green-500', bg: 'bg-emerald-500/10' },
  };

  const badge = badges[status as keyof typeof badges];
  if (!badge) return null;

  const Icon = badge.icon;

  return (
    <div className={`${badge.bg} border border-${status === 'vulnerabilities' ? 'rose' : status === 'secure' ? 'emerald' : 'cyan'}-500/30 rounded-xl px-4 py-3 backdrop-blur-md`}>
      <div className="flex items-center gap-2 mb-1">
        <Icon className="w-4 h-4 text-slate-400" />
        <span className="text-xs font-semibold text-slate-400">{badge.label}</span>
      </div>
      <div className={`text-2xl font-black bg-gradient-to-r ${badge.color} bg-clip-text text-transparent`}>{count}</div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Skeleton Loader Components
// ---------------------------------------------------------------------------
function LogSkeleton() {
  return (
    <div className="p-3 rounded-lg bg-slate-800/20 border border-slate-700/30 animate-pulse backdrop-blur-sm">
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
    <div className="p-3 rounded-lg bg-slate-800/20 border border-slate-700/30 animate-pulse space-y-2 backdrop-blur-sm">
      <div className="flex items-center justify-between">
        <div className="h-4 w-16 bg-slate-700 rounded" />
        <div className="h-3 w-20 bg-slate-700/70 rounded" />
      </div>
      <div className="h-3 w-32 bg-slate-700 rounded" />
      <div className="space-y-1.5 mt-2">
        <div className="h-2.5 bg-slate-700 rounded w-full" />
        <div className="h-2.5 bg-slate-700 rounded w-3/4" />
      </div>
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
    'Analyzing WHOIS Data...',
    'Scanning HTTP Endpoints...',
    'Correlating Findings...',
    'Generating Report...',
  ];

  useEffect(() => {
    const counterInterval = setInterval(() => setCounter((c) => c + 1), 200);
    const phaseInterval = setInterval(() => setPhase((p) => (p + 1) % phases.length), 3000);
    return () => {
      clearInterval(counterInterval);
      clearInterval(phaseInterval);
    };
  }, []);

  return (
    <div className="flex flex-col items-center justify-center h-full gap-6 py-12">
      <div className="relative">
        <div className="absolute inset-0 bg-gradient-to-r from-cyan-500 to-violet-500 rounded-full blur-xl opacity-20 animate-pulse" />
        <div className="relative w-20 h-20 rounded-full border-2 border-transparent border-t-cyan-400 border-r-violet-400 animate-spin" style={{ animationDuration: '1.5s' }} />
      </div>
      <div className="text-center">
        <p className="text-sm font-semibold text-cyan-400 mb-1">{phases[phase]}</p>
        <p className="text-xs text-slate-500 font-mono">{counter} operations in progress</p>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Icon Components
// ---------------------------------------------------------------------------
function LogEntryIcon({ stepName }: { stepName: string }) {
  const icons: Record<string, any> = {
    'CERT_LOG': Sparkles,
    'DNS_PROBE': Radar,
    'HTTP_SCAN': Activity,
    'ANALYSIS': Brain,
    'REPORT': FileText,
  };
  const IconComponent = icons[stepName] || Terminal;
  return <IconComponent className="w-3.5 h-3.5 text-violet-400" />;
}

function HttpStatusBadge({ status }: { status: number | null }) {
  if (status === null) return <span className="text-slate-600 text-[10px]">N/A</span>;
  const isSuccess = status >= 200 && status < 300;
  return <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded ${isSuccess ? 'text-emerald-400 bg-emerald-400/10' : 'text-orange-400 bg-orange-400/10'}`}>{status}</span>;
}

function severityColor(severity: string) {
  const colors: Record<string, string> = {
    CRITICAL: 'bg-red-950/40 border-red-500/60 text-red-300',
    HIGH: 'bg-orange-950/40 border-orange-500/60 text-orange-300',
    MEDIUM: 'bg-amber-950/40 border-amber-500/60 text-amber-300',
    LOW: 'bg-yellow-950/40 border-yellow-500/60 text-yellow-300',
  };
  return colors[severity] || colors.MEDIUM;
}

function logRowBg(log: Log) {
  const baseClasses = 'bg-slate-800/20 hover:bg-slate-800/40';
  if (log.log_level === 'ERROR') return `${baseClasses} border-rose-500/20`;
  if (log.log_level === 'WARNING') return `${baseClasses} border-amber-500/20`;
  return `${baseClasses} border-slate-700/30`;
}

function logRowText(log: Log) {
  if (log.log_level === 'ERROR') return 'text-rose-300';
  if (log.log_level === 'WARNING') return 'text-amber-300';
  return 'text-slate-300';
}

function logRowLeftAccent(log: Log) {
  if (log.log_level === 'ERROR') return 'border-l-rose-500';
  if (log.log_level === 'WARNING') return 'border-l-amber-500';
  return 'border-l-violet-500';
}

// ---------------------------------------------------------------------------
// Main Page Component
// ---------------------------------------------------------------------------
export default function SecurityDashboard() {
  const [domain, setDomain] = useState('');
  const [isScanning, setIsScanning] = useState(false);
  const [activeTarget, setActiveTarget] = useState<Target | null>(null);
  const [targets, setTargets] = useState<Target[]>([]);
  const [logs, setLogs] = useState<Log[]>([]);
  const [subdomains, setSubdomains] = useState<Subdomain[]>([]);
  const [vulns, setVulns] = useState<Vulnerability[]>([]);
  const [selectedReport, setSelectedReport] = useState<Vulnerability | null>(null);
  const logsEndRef = useRef<HTMLDivElement>(null);

  const scrollToBottom = () => {
    logsEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  useEffect(() => {
    scrollToBottom();
  }, [logs]);

  const fetchTargets = useCallback(async () => {
    try {
      const { data } = await supabase.from('targets').select('*').order('created_at', { ascending: false });
      setTargets(data as Target[]);
    } catch (error) {
      console.error('Error fetching targets:', error);
    }
  }, []);

  const fetchLogs = useCallback(async (targetId: string) => {
    try {
      const { data } = await supabase.from('logs').select('*').eq('target_id', targetId).order('timestamp', { ascending: true });
      setLogs(data as Log[]);
    } catch (error) {
      console.error('Error fetching logs:', error);
    }
  }, []);

  const fetchSubdomains = useCallback(async (targetId: string) => {
    try {
      const { data } = await supabase.from('subdomains').select('*').eq('target_id', targetId).order('subdomain', { ascending: true });
      setSubdomains(data as Subdomain[]);
    } catch (error) {
      console.error('Error fetching subdomains:', error);
    }
  }, []);

  const fetchVulnerabilities = useCallback(async (targetId: string) => {
    try {
      const { data } = await supabase.from('vulnerabilities').select('*').eq('target_id', targetId);
      setVulns(data as Vulnerability[]);
    } catch (error) {
      console.error('Error fetching vulnerabilities:', error);
    }
  }, []);

  const subscribeToUpdates = (targetId: string) => {
    const logsChannel = supabase
      .channel(`logs:${targetId}`)
      .on('postgres_changes', { event: 'INSERT', schema: 'public', table: 'logs', filter: `target_id=eq.${targetId}` }, (payload) => {
        setLogs((prev) => [...prev, payload.new as Log]);
      })
      .subscribe();

    const subdomainsChannel = supabase
      .channel(`subdomains:${targetId}`)
      .on('postgres_changes', { event: 'INSERT', schema: 'public', table: 'subdomains', filter: `target_id=eq.${targetId}` }, (payload) => {
        setSubdomains((prev) => [...prev, payload.new as Subdomain]);
      })
      .subscribe();

    const vulnsChannel = supabase
      .channel(`vulns:${targetId}`)
      .on('postgres_changes', { event: 'INSERT', schema: 'public', table: 'vulnerabilities', filter: `target_id=eq.${targetId}` }, (payload) => {
        setVulns((prev) => [...prev, payload.new as Vulnerability]);
      })
      .subscribe();

    const targetsChannel = supabase
      .channel(`targets:${targetId}`)
      .on('postgres_changes', { event: 'UPDATE', schema: 'public', table: 'targets', filter: `id=eq.${targetId}` }, (payload) => {
        const updatedTarget = payload.new as Target;
        if (updatedTarget.status === 'complete') {
          setIsScanning(false);
        }
      })
      .subscribe();

    return () => {
      supabase.removeChannel(logsChannel);
      supabase.removeChannel(subdomainsChannel);
      supabase.removeChannel(vulnsChannel);
      supabase.removeChannel(targetsChannel);
    };
  };

  const handleScan = async () => {
    if (!domain.trim()) return;

    try {
      const response = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domain: domain.trim() }),
      });

      const { target_id } = await response.json();
      setIsScanning(true);
      setLogs([]);
      setSubdomains([]);
      setVulns([]);

      const newTarget = { id: target_id, domain: domain.trim(), status: 'scanning', created_at: new Date().toISOString() };
      setActiveTarget(newTarget);
      setTargets((prev) => [newTarget, ...prev]);

      const unsubscribe = subscribeToUpdates(target_id);

      setTimeout(() => {
        fetchLogs(target_id);
        fetchSubdomains(target_id);
        fetchVulnerabilities(target_id);
      }, 1000);

      return () => unsubscribe();
    } catch (error) {
      console.error('Error starting scan:', error);
    }
  };

  const handleTargetSelect = async (target: Target) => {
    setActiveTarget(target);
    setLogs([]);
    setSubdomains([]);
    setVulns([]);
    await Promise.all([fetchLogs(target.id), fetchSubdomains(target.id), fetchVulnerabilities(target.id)]);
  };

  useEffect(() => {
    fetchTargets();
  }, [fetchTargets]);

  return (
    <>
      <GlobalStyles />
      <GlobalProgressBar isScanning={isScanning} />

      <div className="relative w-full h-screen bg-gradient-to-br from-slate-950 via-slate-900 to-slate-950 overflow-hidden">
        {/* Animated background elements */}
        <div className="absolute top-0 right-1/4 w-96 h-96 bg-gradient-to-r from-cyan-500/10 to-violet-500/10 rounded-full blur-3xl animate-pulse" style={{ animationDuration: '4s' }} />
        <div className="absolute bottom-1/4 left-1/3 w-80 h-80 bg-gradient-to-r from-violet-500/10 to-rose-500/10 rounded-full blur-3xl animate-pulse" style={{ animationDuration: '3s', animationDelay: '1s' }} />

        <div className="relative h-full flex flex-col">
          {/* Hero Header with Scan Input */}
          <div className="bg-gradient-to-b from-slate-900/80 to-slate-900/40 backdrop-blur-md border-b border-slate-800/50 px-8 py-8">
            <div className="max-w-7xl mx-auto">
              {/* Title */}
              <div className="mb-8">
                <div className="flex items-center gap-3 mb-2">
                  <div className="p-2 rounded-lg bg-gradient-to-br from-cyan-500/20 to-violet-500/20 backdrop-blur-md border border-cyan-500/30">
                    <Shield className="w-5 h-5 text-cyan-400" />
                  </div>
                  <h1 className="text-4xl font-black bg-gradient-to-r from-cyan-400 via-violet-400 to-rose-400 bg-clip-text text-transparent">
                    Threat Intelligence
                  </h1>
                </div>
                <p className="text-sm text-slate-400 ml-11">Real-time vulnerability scanning & asset discovery powered by AI</p>
              </div>

              {/* Search Input */}
              <div className="flex gap-3 mb-6">
                <div className="flex-1 relative group">
                  <input
                    type="text"
                    placeholder="Enter domain to scan (e.g., example.com)"
                    value={domain}
                    onChange={(e) => setDomain(e.target.value)}
                    onKeyPress={(e) => e.key === 'Enter' && handleScan()}
                    className="w-full px-5 py-3 bg-slate-800/50 border border-slate-700/50 hover:border-slate-700 focus:border-cyan-500/50 rounded-lg text-slate-100 placeholder-slate-500 outline-none transition-all backdrop-blur-md focus:bg-slate-800/70"
                  />
                  <Search className="absolute right-4 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500 pointer-events-none" />
                </div>
                <button
                  onClick={handleScan}
                  disabled={isScanning || !domain.trim()}
                  className="px-6 py-3 bg-gradient-to-r from-cyan-500 to-violet-500 hover:from-cyan-600 hover:to-violet-600 disabled:from-slate-700 disabled:to-slate-700 text-white font-semibold rounded-lg transition-all duration-300 flex items-center gap-2 group"
                >
                  {isScanning ? (
                    <>
                      <Loader2 className="w-4 h-4 animate-spin" />
                      <span>Scanning</span>
                    </>
                  ) : (
                    <>
                      <Scan className="w-4 h-4 group-hover:scale-110 transition-transform" />
                      <span>Launch Scan</span>
                    </>
                  )}
                </button>
              </div>

              {/* Quick Stats */}
              {activeTarget && (
                <div className="grid grid-cols-3 gap-4">
                  <ScanStatusBadge status="assets" count={subdomains.length} />
                  <ScanStatusBadge status="vulnerabilities" count={vulns.length} />
                  <ScanStatusBadge status="secure" count={Math.max(0, subdomains.length - vulns.length)} />
                </div>
              )}
            </div>
          </div>

          {/* Main Content */}
          {activeTarget ? (
            <main className="flex-1 overflow-hidden flex">
              {/* Left Panel - Scan History Sidebar */}
              <div className="w-64 border-r border-slate-800/50 bg-slate-900/30 backdrop-blur-sm overflow-y-auto">
                <div className="p-4 border-b border-slate-800/50">
                  <h3 className="text-xs font-bold text-slate-400 uppercase tracking-widest mb-3">Scan History</h3>
                  <div className="space-y-2">
                    {targets.map((target) => (
                      <button
                        key={target.id}
                        onClick={() => handleTargetSelect(target)}
                        className={`w-full text-left px-3 py-2.5 rounded-lg transition-all text-sm font-medium ${activeTarget.id === target.id
                            ? 'bg-gradient-to-r from-cyan-500/30 to-violet-500/30 border border-cyan-500/50 text-cyan-300'
                            : 'text-slate-400 hover:bg-slate-800/50 border border-slate-800/30'
                          }`}
                      >
                        <div className="truncate">{target.domain}</div>
                        <div className="text-[10px] text-slate-600 mt-0.5">{new Date(target.created_at).toLocaleDateString()}</div>
                      </button>
                    ))}
                  </div>
                </div>
              </div>

              {/* Right Panel - Dashboard Grid */}
              <div className="flex-1 overflow-hidden flex flex-col">
                <div className="grid grid-cols-12 gap-4 flex-1 overflow-hidden p-6">
                  {/* Left - Threat Gauge & Logs */}
                  <div className="col-span-3 flex flex-col gap-4 min-h-0">
                    {/* Threat Gauge Card */}
                    <div className="bg-slate-800/30 border border-slate-700/50 rounded-2xl p-6 backdrop-blur-md flex flex-col items-center justify-center">
                      <ThreatGauge vulnerabilityCount={vulns.length} isScanning={isScanning} />
                    </div>

                    {/* Quick Actions */}
                    <div className="bg-slate-800/30 border border-slate-700/50 rounded-2xl p-4 backdrop-blur-md space-y-2">
                      <button className="w-full px-4 py-2.5 bg-gradient-to-r from-emerald-500/20 to-cyan-500/20 hover:from-emerald-500/30 hover:to-cyan-500/30 border border-emerald-500/30 rounded-lg text-sm font-semibold text-emerald-300 transition-all flex items-center gap-2">
                        <Download className="w-4 h-4" />
                        Export Report
                      </button>
                      <button className="w-full px-4 py-2.5 bg-gradient-to-r from-violet-500/20 to-rose-500/20 hover:from-violet-500/30 hover:to-rose-500/30 border border-violet-500/30 rounded-lg text-sm font-semibold text-violet-300 transition-all flex items-center gap-2">
                        <Share2 className="w-4 h-4" />
                        Share Findings
                      </button>
                    </div>
                  </div>

                  {/* Center - Agent Logs */}
                  <div className="col-span-5 bg-slate-800/30 border border-slate-700/50 rounded-2xl flex flex-col min-h-0 overflow-hidden backdrop-blur-md">
                    <div className="flex items-center gap-2 px-5 py-4 border-b border-slate-700/50 shrink-0 bg-slate-900/40">
                      <Brain className="w-4 h-4 text-violet-400" />
                      <h2 className="text-sm font-bold text-slate-200">Agent Reasoning</h2>
                      {logs.length > 0 && (
                        <span className="ml-auto text-[10px] bg-violet-500/20 text-violet-400 px-2.5 py-1 rounded-full border border-violet-500/30 font-mono font-bold">
                          {logs.length} steps
                        </span>
                      )}
                    </div>
                    <div className="flex-1 overflow-y-auto p-4 space-y-2.5">
                      {isScanning && logs.length === 0 ? (
                        <ScanningDiagnostics domain={activeTarget.domain} />
                      ) : logs.length === 0 ? (
                        <div className="flex flex-col items-center justify-center h-full text-slate-600 gap-3">
                          <Terminal className="w-12 h-12 opacity-40" />
                          <p className="text-xs text-center">Waiting for scan to begin...</p>
                        </div>
                      ) : (
                        logs.map((log) => (
                          <div
                            key={log.id}
                            className={`p-3 rounded-lg border-l-[3px] border ${logRowLeftAccent(log)} ${logRowBg(log)} ${logRowText(log)} transition-all backdrop-blur-sm`}
                          >
                            <div className="flex items-center gap-2 mb-1">
                              <LogEntryIcon stepName={log.step_name} />
                              <span className="font-bold text-[10px] uppercase tracking-wide">{log.step_name}</span>
                              <span className="flex items-center gap-1 ml-auto opacity-60 text-[9px] font-mono">
                                <Clock className="w-2.5 h-2.5" />
                                {new Date(log.timestamp).toLocaleTimeString()}
                              </span>
                            </div>
                            <p className="leading-relaxed text-xs pl-5 font-mono opacity-90 break-words">{log.message}</p>
                          </div>
                        ))
                      )}
                      <div ref={logsEndRef} />
                    </div>
                  </div>

                  {/* Right - Assets & Vulns */}
                  <div className="col-span-4 flex flex-col gap-4 min-h-0">
                    {/* Discovered Assets */}
                    <div className="bg-slate-800/30 border border-slate-700/50 rounded-2xl flex flex-col min-h-[250px] overflow-hidden backdrop-blur-md">
                      <div className="flex items-center gap-2 px-5 py-4 border-b border-slate-700/50 shrink-0 bg-slate-900/40">
                        <ExternalLink className="w-4 h-4 text-cyan-400" />
                        <h2 className="text-sm font-bold text-slate-200">Discovered Assets</h2>
                        {subdomains.length > 0 && (
                          <span className="ml-auto text-[10px] bg-cyan-500/20 text-cyan-400 px-2.5 py-1 rounded-full border border-cyan-500/30 font-mono font-bold">
                            {subdomains.length}
                          </span>
                        )}
                      </div>
                      <div className="flex-1 overflow-y-auto">
                        {isScanning && subdomains.length === 0 ? (
                          <SubdomainTableSkeleton />
                        ) : subdomains.length === 0 ? (
                          <div className="flex items-center justify-center h-full text-slate-600">
                            <p className="text-xs">No assets yet</p>
                          </div>
                        ) : (
                          <table className="w-full text-[10px]">
                            <tbody>
                              {subdomains.slice(0, 8).map((sub) => (
                                <tr key={sub.id} className="border-b border-slate-700/30 hover:bg-slate-700/20 transition-colors">
                                  <td className="px-3 py-2 font-mono text-slate-300 truncate text-[9px]" title={sub.subdomain}>
                                    {sub.subdomain.split('.').slice(-2).join('.')}
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
                      {subdomains.length > 8 && (
                        <div className="px-4 py-2 text-center text-[10px] text-slate-500 border-t border-slate-700/30 bg-slate-900/20">
                          +{subdomains.length - 8} more assets
                        </div>
                      )}
                    </div>

                    {/* Vulnerabilities */}
                    <div className="bg-slate-800/30 border border-slate-700/50 rounded-2xl flex flex-col flex-1 min-h-0 overflow-hidden backdrop-blur-md">
                      <div className="flex items-center gap-2 px-5 py-4 border-b border-slate-700/50 shrink-0 bg-slate-900/40">
                        <AlertTriangle className="w-4 h-4 text-rose-400" />
                        <h2 className="text-sm font-bold text-slate-200">Threats Found</h2>
                        {vulns.length > 0 && (
                          <span className="ml-auto text-[10px] bg-rose-500/20 text-rose-400 px-2.5 py-1 rounded-full border border-rose-500/30 font-mono font-bold">
                            {vulns.length}
                          </span>
                        )}
                      </div>
                      <div className="flex-1 overflow-y-auto p-3 space-y-2.5">
                        {isScanning && vulns.length === 0 ? (
                          <>
                            <VulnerabilityCardSkeleton />
                            <VulnerabilityCardSkeleton />
                          </>
                        ) : vulns.length === 0 ? (
                          <div className="flex flex-col items-center justify-center h-full text-slate-600 gap-2">
                            <ShieldCheck className="w-8 h-8 opacity-40" />
                            <p className="text-xs text-center">No threats detected</p>
                          </div>
                        ) : (
                          vulns.map((vuln) => (
                            <div key={vuln.id} className="bg-rose-950/20 border border-rose-500/30 hover:border-rose-500/50 rounded-lg p-3 transition-all backdrop-blur-sm group cursor-pointer">
                              <div className="flex items-center justify-between mb-1.5">
                                <span className={`text-[9px] px-1.5 py-0.5 rounded font-bold uppercase tracking-wider ${severityColor(vuln.severity)}`}>
                                  {vuln.severity}
                                </span>
                                <span className="text-[9px] text-slate-500 font-mono">{vuln.vuln_type}</span>
                              </div>
                              <p className="text-[11px] font-semibold text-rose-300 mb-1.5 line-clamp-2">Subdomain Takeover</p>
                              <button
                                onClick={() => setSelectedReport(vuln)}
                                className="w-full text-[10px] text-rose-400 hover:text-rose-300 border border-rose-500/30 hover:border-rose-500/50 rounded px-2 py-1.5 transition-colors bg-rose-950/20 hover:bg-rose-950/40 font-medium"
                              >
                                View Details →
                              </button>
                            </div>
                          ))
                        )}
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </main>
          ) : (
            <div className="flex-1 flex items-center justify-center">
              <div className="text-center">
                <div className="mb-6 flex justify-center">
                  <div className="relative">
                    <div className="absolute inset-0 bg-gradient-to-r from-cyan-500 to-violet-500 rounded-3xl blur-2xl opacity-30 animate-pulse" />
                    <div className="relative p-4 bg-gradient-to-br from-slate-800 to-slate-900 rounded-3xl border border-slate-700">
                      <Radar className="w-16 h-16 text-gradient animate-pulse" style={{ animation: 'pulse-glow 2s ease-in-out infinite' }} />
                    </div>
                  </div>
                </div>
                <h2 className="text-2xl font-bold text-slate-200 mb-2">Ready to scan</h2>
                <p className="text-slate-400 text-sm">Enter a domain above and launch a scan to discover vulnerabilities</p>
              </div>
            </div>
          )}

          {/* Report Modal */}
          {selectedReport && (
            <div className="fixed inset-0 bg-black/50 backdrop-blur-sm flex items-center justify-center z-50 p-4">
              <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-2xl w-full max-h-[90vh] overflow-y-auto">
                <div className="sticky top-0 flex items-center justify-between px-6 py-4 border-b border-slate-800 bg-slate-900/95 backdrop-blur">
                  <h3 className="text-lg font-bold text-slate-100">Vulnerability Report</h3>
                  <button onClick={() => setSelectedReport(null)} className="p-1 hover:bg-slate-800 rounded-lg transition-colors">
                    <X className="w-5 h-5 text-slate-400" />
                  </button>
                </div>
                <div className="p-6 space-y-4">
                  <div className="bg-slate-800/30 rounded-lg p-4 border border-slate-700/50">
                    <div className="flex items-start justify-between mb-3">
                      <div>
                        <h4 className="font-bold text-slate-100 mb-1">Subdomain Takeover Detected</h4>
                        <p className="text-sm text-slate-400">{selectedReport.vuln_type}</p>
                      </div>
                      <span className={`text-xs px-3 py-1 rounded-lg font-bold ${severityColor(selectedReport.severity)}`}>{selectedReport.severity}</span>
                    </div>
                  </div>

                  <div className="bg-slate-800/30 rounded-lg p-4 border border-slate-700/50">
                    <h5 className="text-sm font-semibold text-slate-300 mb-3">Evidence</h5>
                    <pre className="text-xs font-mono text-slate-400 overflow-x-auto bg-slate-950 p-3 rounded border border-slate-800 max-h-48 overflow-y-auto">
                      {selectedReport.evidence}
                    </pre>
                  </div>

                  <div className="bg-gradient-to-r from-rose-950/20 to-orange-950/20 rounded-lg p-4 border border-rose-500/20">
                    <h5 className="text-sm font-semibold text-rose-300 mb-2">Recommended Actions</h5>
                    <ul className="text-xs text-slate-300 space-y-1.5">
                      <li>• Verify the CNAME record configuration</li>
                      <li>• Update DNS records to point to owned infrastructure</li>
                      <li>• Implement DNSSEC to prevent DNS hijacking</li>
                      <li>• Monitor for unauthorized access attempts</li>
                    </ul>
                  </div>

                  <button className="w-full px-4 py-2.5 bg-gradient-to-r from-cyan-500 to-violet-500 hover:from-cyan-600 hover:to-violet-600 text-white font-semibold rounded-lg transition-all">
                    Generate Full Remediation Plan
                  </button>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>


    </>
  );
}

// Add missing Share2 icon
function Share2(props: any) {
  return (
    <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" {...props}>
      <circle cx="18" cy="5" r="3" />
      <circle cx="6" cy="12" r="3" />
      <circle cx="18" cy="19" r="3" />
      <line x1="8.59" y1="13.51" x2="15.42" y2="17.49" />
      <line x1="15.41" y1="6.51" x2="8.59" y2="10.49" />
    </svg>
  );
}