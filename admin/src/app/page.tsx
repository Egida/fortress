'use client';

import { useState, useEffect, useCallback } from 'react';
import { fortressGet, fortressPost } from '@/lib/api';
import {
  FortressStatus,
  FortressMetrics,
  MetricsHistoryResponse,
  SecondSnapshot,
  ThreatSummary,
  ManagedRule,
  FortressSettings,
} from '@/lib/types';
import { PROTECTION_LEVELS, PROTECTION_LEVELS_LIST, formatUptime, formatNumber } from '@/lib/constants';
import {
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
} from 'recharts';
import {
  Shield,
  ShieldAlert,
  ShieldCheck,
  ShieldBan,
  Zap,
  Activity,
  Radio,
  Ban,
  Eye,
  Crosshair,
  Fingerprint,
  Cpu,
  Radar,
  BookOpen,
  AlertTriangle,
  Flame,
  Server,
  Gauge,
  ChevronRight,
  RotateCcw,
  Siren,
  BotOff,
  Check,
  Loader2,
} from 'lucide-react';

/* ------------------------------------------------------------------ */
/*  Threat score helpers (same logic as threat-map)                    */
/* ------------------------------------------------------------------ */
const LEVEL_KEY_MAP: Record<string, string> = {
  L0: 'Normal', L1: 'High', L2: 'UnderAttack', L3: 'Severe', L4: 'Emergency',
  Normal: 'Normal', High: 'High', UnderAttack: 'UnderAttack', Severe: 'Severe', Emergency: 'Emergency',
};

function threatScore(s: ThreatSummary): number {
  let score = 0;
  const mappedKey = LEVEL_KEY_MAP[s.protection_level] ?? s.protection_level;
  const lvl = PROTECTION_LEVELS[mappedKey]?.level ?? 0;
  score += lvl * 18;
  if (s.block_rate > 50) score += 25;
  else if (s.block_rate > 30) score += 15;
  else if (s.block_rate > 10) score += 5;
  if (s.distributed_attack_active) score += 20;
  if (s.auto_ban_count > 50) score += 10;
  else if (s.auto_ban_count > 10) score += 5;
  if (s.distributed_unique_ips > 500) score += 8;
  return Math.min(100, Math.max(0, score));
}

function scoreLabel(v: number): string {
  if (v >= 80) return 'CRITICAL';
  if (v >= 60) return 'HIGH';
  if (v >= 40) return 'ELEVATED';
  if (v >= 20) return 'GUARDED';
  return 'LOW';
}

function scoreFill(v: number): string {
  if (v >= 80) return '#ef4444';
  if (v >= 60) return '#f97316';
  if (v >= 40) return '#eab308';
  if (v >= 20) return '#3b82f6';
  return '#22c55e';
}

function scoreTextColor(v: number): string {
  if (v >= 80) return 'text-red-400';
  if (v >= 60) return 'text-orange-400';
  if (v >= 40) return 'text-yellow-400';
  if (v >= 20) return 'text-blue-400';
  return 'text-green-400';
}

/* DEFCON mapping from protection level */
function defconFromLevel(levelKey: string): { level: number; label: string; color: string; bgClass: string; borderClass: string } {
  const lvl = PROTECTION_LEVELS[levelKey]?.level ?? 0;
  switch (lvl) {
    case 4: return { level: 1, label: 'DEFCON 1', color: 'text-red-300', bgClass: 'bg-red-950/80', borderClass: 'border-red-700' };
    case 3: return { level: 2, label: 'DEFCON 2', color: 'text-red-400', bgClass: 'bg-red-950/50', borderClass: 'border-red-800' };
    case 2: return { level: 3, label: 'DEFCON 3', color: 'text-orange-400', bgClass: 'bg-orange-950/40', borderClass: 'border-orange-800' };
    case 1: return { level: 4, label: 'DEFCON 4', color: 'text-yellow-400', bgClass: 'bg-yellow-950/30', borderClass: 'border-yellow-900' };
    default: return { level: 5, label: 'DEFCON 5', color: 'text-green-400', bgClass: 'bg-green-950/20', borderClass: 'border-green-900' };
  }
}

/* ------------------------------------------------------------------ */
/*  Main Component                                                    */
/* ------------------------------------------------------------------ */
export default function DashboardPage() {
  const [status, setStatus] = useState<FortressStatus | null>(null);
  const [metrics, setMetrics] = useState<FortressMetrics | null>(null);
  const [history, setHistory] = useState<SecondSnapshot[]>([]);
  const [threatSummary, setThreatSummary] = useState<ThreatSummary | null>(null);
  const [managedRules, setManagedRules] = useState<ManagedRule[]>([]);
  const [settings, setSettings] = useState<FortressSettings | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [switchingLevel, setSwitchingLevel] = useState<string | null>(null);
  const [switchSuccess, setSwitchSuccess] = useState<string | null>(null);

  const fetchData = useCallback(async () => {
    try {
      const [s, m, h, ts, mr, st] = await Promise.all([
        fortressGet<FortressStatus>('/api/fortress/status'),
        fortressGet<FortressMetrics>('/api/fortress/metrics'),
        fortressGet<MetricsHistoryResponse>('/api/fortress/metrics/history?granularity=second'),
        fortressGet<ThreatSummary>('/api/fortress/threat-summary'),
        fortressGet<{ rules: ManagedRule[] } | ManagedRule[]>('/api/fortress/managed-rules'),
        fortressGet<FortressSettings>('/api/fortress/settings').catch(() => null),
      ]);
      setStatus(s);
      setMetrics(m);
      setHistory(h.data || []);
      setThreatSummary(ts);
      const rulesArray = Array.isArray(mr) ? mr : (mr && 'rules' in mr ? mr.rules : []);
      setManagedRules(Array.isArray(rulesArray) ? rulesArray : []);
      if (st) setSettings(st);
      setError(null);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to fetch data');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchData();
    const timer = setInterval(fetchData, 2000);
    return () => clearInterval(timer);
  }, [fetchData]);

  const formatTime = (ts: number) => {
    const d = new Date(ts * 1000);
    return d.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false });
  };

  /* ---------------------------------------------------------------- */
  /*  Protection level switching                                      */
  /* ---------------------------------------------------------------- */
  const handleSwitchLevel = useCallback(async (level: string) => {
    setSwitchingLevel(level);
    setSwitchSuccess(null);
    try {
      await fortressPost('/api/fortress/level', { level });
      setSwitchSuccess(level);
      setTimeout(() => setSwitchSuccess(null), 3000);
      fetchData();
    } catch {
      setError('Failed to change protection level');
    } finally {
      setSwitchingLevel(null);
    }
  }, [fetchData]);

  /* ---------------------------------------------------------------- */
  /*  Quick Response level definitions                                */
  /* ---------------------------------------------------------------- */
  const qrLevels = [
    { key: 'Normal', label: 'DEFCON 5', shortLabel: '5', color: 'emerald', desc: 'Passive Monitoring' },
    { key: 'High', label: 'DEFCON 4', shortLabel: '4', color: 'blue', desc: 'Active Defense' },
    { key: 'UnderAttack', label: 'DEFCON 3', shortLabel: '3', color: 'yellow', desc: 'Threat Engagement' },
    { key: 'Severe', label: 'DEFCON 2', shortLabel: '2', color: 'orange', desc: 'Maximum Defense' },
    { key: 'Emergency', label: 'DEFCON 1', shortLabel: '1', color: 'red', desc: 'Full Lockdown' },
  ];

  /* ---------------------------------------------------------------- */
  /*  Loading skeleton                                                */
  /* ---------------------------------------------------------------- */
  if (loading) {
    return (
      <div className="space-y-6">
        {/* Status banner skeleton */}
        <div className="rounded-xl border border-zinc-800 bg-zinc-900 px-6 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-4">
              <div className="h-7 w-56 animate-pulse rounded bg-zinc-800" />
              <div className="h-6 w-28 animate-pulse rounded-full bg-zinc-800" />
            </div>
            <div className="flex gap-6">
              <div className="h-4 w-28 animate-pulse rounded bg-zinc-800" />
              <div className="h-4 w-20 animate-pulse rounded bg-zinc-800" />
            </div>
          </div>
        </div>

        {/* Threat score + primary stats skeleton */}
        <div className="grid gap-6 lg:grid-cols-4">
          <div className="rounded-xl border border-zinc-800 bg-zinc-900 p-6">
            <div className="h-4 w-32 animate-pulse rounded bg-zinc-800 mb-6" />
            <div className="mx-auto h-40 w-40 animate-pulse rounded-full bg-zinc-800" />
          </div>
          <div className="lg:col-span-3">
            <div className="grid grid-cols-2 gap-4 lg:grid-cols-3">
              {Array.from({ length: 6 }).map((_, i) => (
                <div key={i} className="rounded-xl border border-zinc-800 bg-zinc-900 p-5">
                  <div className="h-3 w-24 animate-pulse rounded bg-zinc-800" />
                  <div className="mt-3 h-8 w-20 animate-pulse rounded bg-zinc-800" />
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Secondary stats skeleton */}
        <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
          {Array.from({ length: 4 }).map((_, i) => (
            <div key={i} className="rounded-xl border border-zinc-800 bg-zinc-900 p-5">
              <div className="h-3 w-28 animate-pulse rounded bg-zinc-800" />
              <div className="mt-3 h-8 w-16 animate-pulse rounded bg-zinc-800" />
            </div>
          ))}
        </div>

        {/* Chart skeleton */}
        <div className="rounded-xl border border-zinc-800 bg-zinc-900 p-5">
          <div className="h-4 w-48 animate-pulse rounded bg-zinc-800 mb-4" />
          <div className="h-72 w-full animate-pulse rounded bg-zinc-800/50" />
        </div>

        {/* Defense summary skeleton */}
        <div className="rounded-xl border border-zinc-800 bg-zinc-900 p-5">
          <div className="h-4 w-40 animate-pulse rounded bg-zinc-800 mb-4" />
          <div className="flex flex-wrap gap-3">
            {Array.from({ length: 6 }).map((_, i) => (
              <div key={i} className="h-7 w-36 animate-pulse rounded-full bg-zinc-800" />
            ))}
          </div>
        </div>
      </div>
    );
  }

  if (!status || !metrics) {
    return (
      <div className="flex items-center justify-center min-h-[60vh]">
        <div className="text-zinc-400 text-lg">
          {error ? <span className="text-red-400">{error}</span> : 'Initializing Command Center...'}
        </div>
      </div>
    );
  }

  /* ---------------------------------------------------------------- */
  /*  Derived values                                                  */
  /* ---------------------------------------------------------------- */
  const levelKey = status?.protection_level ?? 'Normal';
  const levelMeta = PROTECTION_LEVELS[levelKey] ?? PROTECTION_LEVELS['Normal'];
  const defcon = defconFromLevel(levelKey);

  // Threat score
  const score = threatSummary ? threatScore(threatSummary) : 0;
  const fill = scoreFill(score);

  // Primary stat cards
  const totalBlocked = metrics.total_blocked ?? 0;
  const totalRequests = metrics.total_requests ?? 0;
  const challengedPerSec = metrics.challenged_per_sec ?? 0;
  const passedPerSec = metrics.passed_per_sec ?? 0;
  const blockedPerSec = metrics.blocked_per_sec ?? 0;
  const rps = metrics.rps ?? 0;
  const interceptionRate = totalRequests > 0 ? ((totalBlocked / totalRequests) * 100) : 0;

  const primaryStats = [
    {
      label: 'Processed Requests',
      value: formatNumber(totalRequests),
      icon: Server,
      bg: 'bg-cyan-500/10',
      text: 'text-cyan-400',
      border: 'border-cyan-900/50',
    },
    {
      label: 'Threats Neutralized',
      value: formatNumber(totalBlocked),
      icon: ShieldBan,
      bg: 'bg-red-500/10',
      text: 'text-red-400',
      border: 'border-red-900/50',
    },
    {
      label: 'PoW Challenges Issued',
      value: formatNumber(challengedPerSec) + '/s',
      icon: Crosshair,
      bg: 'bg-yellow-500/10',
      text: 'text-yellow-400',
      border: 'border-yellow-900/50',
    },
    {
      label: 'Legitimate Traffic',
      value: formatNumber(passedPerSec) + '/s',
      icon: ShieldCheck,
      bg: 'bg-green-500/10',
      text: 'text-green-400',
      border: 'border-green-900/50',
    },
    {
      label: 'Threat Interception Rate',
      value: interceptionRate.toFixed(1) + '%',
      icon: Gauge,
      bg: interceptionRate > 30 ? 'bg-red-500/10' : interceptionRate > 10 ? 'bg-yellow-500/10' : 'bg-green-500/10',
      text: interceptionRate > 30 ? 'text-red-400' : interceptionRate > 10 ? 'text-yellow-400' : 'text-green-400',
      border: interceptionRate > 30 ? 'border-red-900/50' : interceptionRate > 10 ? 'border-yellow-900/50' : 'border-green-900/50',
    },
    {
      label: 'Throughput (req/s)',
      value: formatNumber(rps),
      icon: Activity,
      bg: 'bg-blue-500/10',
      text: 'text-blue-400',
      border: 'border-blue-900/50',
    },
  ];

  // Secondary threat cards
  const autoBanCount = threatSummary?.auto_ban_count ?? 0;
  const ipReputationTracked = threatSummary?.ip_reputation_tracked ?? 0;
  const distributedActive = threatSummary?.distributed_attack_active ?? false;
  const blockRate = threatSummary?.block_rate ?? 0;

  const secondaryStats = [
    {
      label: 'Active Containment',
      sublabel: 'Auto-banned IPs',
      value: formatNumber(autoBanCount),
      icon: Ban,
      bg: autoBanCount > 0 ? 'bg-red-500/10' : 'bg-green-500/10',
      text: autoBanCount > 0 ? 'text-red-400' : 'text-green-400',
      border: autoBanCount > 0 ? 'border-red-900/50' : 'border-green-900/50',
      pulse: autoBanCount > 10,
    },
    {
      label: 'Flagged Endpoints',
      sublabel: 'IPs with reputation > 50',
      value: formatNumber(ipReputationTracked),
      icon: Eye,
      bg: 'bg-purple-500/10',
      text: 'text-purple-400',
      border: 'border-purple-900/50',
      pulse: false,
    },
    {
      label: 'Coordinated Attack Status',
      sublabel: 'Distributed detection',
      value: distributedActive ? 'ACTIVE' : 'INACTIVE',
      icon: Radar,
      bg: distributedActive ? 'bg-red-500/10' : 'bg-green-500/10',
      text: distributedActive ? 'text-red-400' : 'text-green-400',
      border: distributedActive ? 'border-red-900/50' : 'border-green-900/50',
      pulse: distributedActive,
    },
    {
      label: 'Defense Efficacy',
      sublabel: 'Current block rate',
      value: blockRate.toFixed(1) + '%',
      icon: Shield,
      bg: blockRate > 30 ? 'bg-red-500/10' : blockRate > 10 ? 'bg-yellow-500/10' : 'bg-green-500/10',
      text: blockRate > 30 ? 'text-red-400' : blockRate > 10 ? 'text-yellow-400' : 'text-green-400',
      border: blockRate > 30 ? 'border-red-900/50' : blockRate > 10 ? 'border-yellow-900/50' : 'border-green-900/50',
      pulse: false,
    },
  ];

  // Chart data
  const chartData = history.slice(-60).map((snap) => ({
    time: formatTime(snap.timestamp),
    passed: snap.passed ?? 0,
    challenged: snap.challenged ?? 0,
    blocked: snap.blocked ?? 0,
  }));

  // Managed rules count
  const enabledRulesCount = managedRules.filter(r => r.enabled).length;
  const totalRulesCount = managedRules.length || 20;

  // Defense systems badges
  const defenseBadges = [
    { label: 'JA3 Engine', status: 'ACTIVE', icon: Fingerprint, color: 'text-green-400', bgColor: 'bg-green-500/10', borderColor: 'border-green-800/50' },
    { label: 'PoW System', status: 'ARMED', icon: Crosshair, color: 'text-green-400', bgColor: 'bg-green-500/10', borderColor: 'border-green-800/50' },
    { label: 'Behavioral Analysis', status: 'SCANNING', icon: Cpu, color: 'text-blue-400', bgColor: 'bg-blue-500/10', borderColor: 'border-blue-800/50' },
    { label: 'Auto-Ban', status: 'ENFORCING', icon: Ban, color: 'text-orange-400', bgColor: 'bg-orange-500/10', borderColor: 'border-orange-800/50' },
    { label: 'IP Reputation', status: 'TRACKING', icon: Eye, color: 'text-purple-400', bgColor: 'bg-purple-500/10', borderColor: 'border-purple-800/50' },
    { label: 'Managed Rules', status: `${enabledRulesCount}/${totalRulesCount} ACTIVE`, icon: BookOpen, color: 'text-cyan-400', bgColor: 'bg-cyan-500/10', borderColor: 'border-cyan-800/50' },
  ];

  /* ---------------------------------------------------------------- */
  /*  Render                                                          */
  /* ---------------------------------------------------------------- */
  return (
    <div className="space-y-6">
      {/* Pulse animation keyframes */}
      <style jsx>{`
        @keyframes pulse-glow {
          0%, 100% { opacity: 1; }
          50% { opacity: 0.5; }
        }
        .animate-pulse-glow {
          animation: pulse-glow 1.5s ease-in-out infinite;
        }
        @keyframes sweep {
          0% { transform: rotate(0deg); }
          100% { transform: rotate(360deg); }
        }
        .animate-sweep {
          animation: sweep 3s linear infinite;
        }
      `}</style>

      {/* ===== STATUS BANNER + QUICK RESPONSE ===== */}
      <div className={`rounded-xl border-2 ${defcon.borderClass} ${defcon.bgClass} overflow-hidden`}>
        {/* Top bar */}
        <div className="px-6 py-4 flex flex-wrap items-center justify-between gap-4">
          <div className="flex items-center gap-4">
            <div className="flex items-center gap-3">
              <ShieldAlert className={`h-6 w-6 ${defcon.color}`} />
              <div>
                <h1 className="text-xl font-bold tracking-tight text-zinc-100">Command Center</h1>
                <p className="text-xs text-zinc-500">Real-time threat monitoring and defense coordination</p>
              </div>
            </div>
            <div className="flex items-center gap-2">
              <span className="relative flex h-2.5 w-2.5">
                <span className={`absolute inline-flex h-full w-full animate-ping rounded-full opacity-75 ${
                  defcon.level <= 2 ? 'bg-red-400' : defcon.level <= 3 ? 'bg-orange-400' : defcon.level <= 4 ? 'bg-yellow-400' : 'bg-green-400'
                }`} />
                <span className={`relative inline-flex h-2.5 w-2.5 rounded-full ${
                  defcon.level <= 2 ? 'bg-red-500' : defcon.level <= 3 ? 'bg-orange-500' : defcon.level <= 4 ? 'bg-yellow-500' : 'bg-green-500'
                }`} />
              </span>
              <span className={`rounded-full px-3 py-1 text-xs font-bold tracking-wider ${levelMeta.color} ${levelMeta.textColor}`}>
                {defcon.label}
              </span>
            </div>
          </div>
          <div className="flex items-center gap-6 text-xs text-zinc-500 font-mono">
            <span>UPTIME <span className="text-zinc-300">{formatUptime(status.uptime_secs)}</span></span>
            <span>CONN <span className="text-zinc-300">{formatNumber(status.active_connections)}</span></span>
            <span>VER <span className="text-zinc-300">{status.version}</span></span>
            <span className="flex items-center gap-1.5">
              <span className="relative flex h-1.5 w-1.5">
                <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-green-400 opacity-75" />
                <span className="relative inline-flex h-1.5 w-1.5 rounded-full bg-green-500" />
              </span>
              <span className="text-green-400">LIVE</span>
            </span>
          </div>
        </div>

        {/* Quick Response Section - integrated into banner */}
        <div className="border-t border-zinc-800/50 bg-black/30 px-6 py-4">
          <div className="flex items-center justify-between mb-3">
            <div className="flex items-center gap-3">
              <Siren className="h-4 w-4 text-yellow-500" />
              <span className="text-[11px] font-bold text-zinc-300 uppercase tracking-widest">
                Quick Response
              </span>
              {switchSuccess && (
                <span className="flex items-center gap-1.5 text-xs text-green-400 font-mono">
                  <Check className="h-3.5 w-3.5" />
                  OK
                </span>
              )}
            </div>
            <div className="flex items-center gap-3">
              {settings?.protection?.auto_escalation && (
                <span className="text-[10px] font-mono text-cyan-400 bg-cyan-500/10 border border-cyan-800/50 rounded-full px-2.5 py-0.5">
                  AUTO-ESCALATION
                </span>
              )}
              {/* PANIC + RESET buttons */}
              <button
                onClick={() => handleSwitchLevel('Emergency')}
                disabled={levelKey === 'Emergency' || !!switchingLevel}
                className={`flex items-center gap-1.5 rounded-lg border px-4 py-2 text-[11px] font-black tracking-wider transition-all duration-200 ${
                  levelKey === 'Emergency'
                    ? 'border-red-900/50 bg-red-500/5 text-red-800 cursor-not-allowed'
                    : 'border-red-500/40 bg-red-500/15 text-red-400 hover:bg-red-500/30 hover:border-red-400 hover:shadow-lg hover:shadow-red-500/10 cursor-pointer'
                }`}
              >
                {switchingLevel === 'Emergency' ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Siren className="h-3.5 w-3.5" />}
                PANIC
              </button>
              <button
                onClick={() => handleSwitchLevel('Normal')}
                disabled={levelKey === 'Normal' || !!switchingLevel}
                className={`flex items-center gap-1.5 rounded-lg border px-4 py-2 text-[11px] font-black tracking-wider transition-all duration-200 ${
                  levelKey === 'Normal'
                    ? 'border-emerald-900/50 bg-emerald-500/5 text-emerald-800 cursor-not-allowed'
                    : 'border-emerald-500/40 bg-emerald-500/15 text-emerald-400 hover:bg-emerald-500/30 hover:border-emerald-400 hover:shadow-lg hover:shadow-emerald-500/10 cursor-pointer'
                }`}
              >
                {switchingLevel === 'Normal' ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <RotateCcw className="h-3.5 w-3.5" />}
                RESET
              </button>
            </div>
          </div>

          {/* DEFCON Level Buttons - wider, more visible */}
          <div className="grid grid-cols-5 gap-2">
            {qrLevels.map((lvl) => {
              const isActive = levelKey === lvl.key;
              const isSwitching = switchingLevel === lvl.key;
              const colorMap: Record<string, { bg: string; hoverBg: string; border: string; text: string; activeBg: string; activeBorder: string; dot: string; ring: string }> = {
                emerald: { bg: 'bg-emerald-950/30', hoverBg: 'hover:bg-emerald-500/20', border: 'border-zinc-800/70 hover:border-emerald-500/50', text: 'text-emerald-400', activeBg: 'bg-emerald-500/25', activeBorder: 'border-emerald-400/60', dot: 'bg-emerald-400', ring: 'ring-emerald-500/30' },
                blue: { bg: 'bg-blue-950/30', hoverBg: 'hover:bg-blue-500/20', border: 'border-zinc-800/70 hover:border-blue-500/50', text: 'text-blue-400', activeBg: 'bg-blue-500/25', activeBorder: 'border-blue-400/60', dot: 'bg-blue-400', ring: 'ring-blue-500/30' },
                yellow: { bg: 'bg-yellow-950/30', hoverBg: 'hover:bg-yellow-500/20', border: 'border-zinc-800/70 hover:border-yellow-500/50', text: 'text-yellow-400', activeBg: 'bg-yellow-500/25', activeBorder: 'border-yellow-400/60', dot: 'bg-yellow-400', ring: 'ring-yellow-500/30' },
                orange: { bg: 'bg-orange-950/30', hoverBg: 'hover:bg-orange-500/20', border: 'border-zinc-800/70 hover:border-orange-500/50', text: 'text-orange-400', activeBg: 'bg-orange-500/25', activeBorder: 'border-orange-400/60', dot: 'bg-orange-400', ring: 'ring-orange-500/30' },
                red: { bg: 'bg-red-950/30', hoverBg: 'hover:bg-red-500/20', border: 'border-zinc-800/70 hover:border-red-500/50', text: 'text-red-400', activeBg: 'bg-red-500/25', activeBorder: 'border-red-400/60', dot: 'bg-red-400', ring: 'ring-red-500/30' },
              };
              const c = colorMap[lvl.color];
              return (
                <button
                  key={lvl.key}
                  onClick={() => !isActive && !isSwitching && handleSwitchLevel(lvl.key)}
                  disabled={isActive || !!switchingLevel}
                  className={`relative flex items-center gap-3 rounded-lg border px-4 py-3 transition-all duration-200 ${
                    isActive
                      ? `${c.activeBg} ${c.activeBorder} ring-2 ${c.ring} shadow-lg`
                      : `${c.bg} ${c.hoverBg} ${c.border} cursor-pointer`
                  } ${switchingLevel && !isSwitching ? 'opacity-30' : ''}`}
                >
                  {isActive && (
                    <span className={`absolute top-2 right-2 w-2.5 h-2.5 rounded-full ${c.dot} animate-pulse`} />
                  )}
                  <div className="flex flex-col items-start">
                    {isSwitching ? (
                      <Loader2 className={`h-5 w-5 ${c.text} animate-spin`} />
                    ) : (
                      <>
                        <span className={`text-base font-black font-mono leading-none ${isActive ? c.text : 'text-zinc-500'}`}>
                          {lvl.label}
                        </span>
                        <span className={`text-[10px] mt-1 ${isActive ? c.text + ' opacity-80' : 'text-zinc-600'}`}>
                          {lvl.desc}
                        </span>
                      </>
                    )}
                  </div>
                </button>
              );
            })}
          </div>
        </div>
      </div>

      {error && (
        <div className="rounded-lg border border-red-800 bg-red-900/30 px-4 py-2 text-sm text-red-300 flex items-center gap-2">
          <AlertTriangle className="h-4 w-4 shrink-0" />
          {error}
        </div>
      )}

      {/* ===== COORDINATED ATTACK ALERT ===== */}
      {distributedActive && (
        <div className="animate-pulse-glow rounded-xl border-2 border-red-500 bg-red-950/60 px-6 py-4">
          <div className="flex items-center gap-4">
            <div className="relative">
              <AlertTriangle className="h-6 w-6 text-red-400" />
              <Flame className="absolute -top-1 -right-1 h-3 w-3 text-red-500 animate-bounce" />
            </div>
            <div className="flex-1">
              <p className="text-sm font-bold text-red-200 tracking-wide">
                COORDINATED ATTACK DETECTED
              </p>
              <p className="text-xs text-red-400/80 mt-0.5 font-mono">
                {formatNumber(threatSummary?.distributed_unique_ips ?? 0)} unique source IPs |{' '}
                {formatNumber(threatSummary?.distributed_window_requests ?? 0)} requests in window |{' '}
                Pattern: Multi-vector distributed | Status: Active countermeasures engaged
              </p>
            </div>
            <div className="flex items-center gap-2">
              <span className="relative flex h-3 w-3">
                <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-red-400 opacity-75" />
                <span className="relative inline-flex h-3 w-3 rounded-full bg-red-500" />
              </span>
              <span className="text-xs font-bold text-red-400 tracking-widest">ALERT</span>
            </div>
          </div>
        </div>
      )}

      {/* ===== THREAT SCORE + PRIMARY STATS ===== */}
      <div className="grid gap-6 lg:grid-cols-4">
        {/* Threat Score Gauge */}
        <div className="rounded-xl border border-zinc-800 bg-zinc-900 p-6">
          <h2 className="text-xs font-semibold text-zinc-500 uppercase tracking-widest mb-4">Threat Posture</h2>

          <div className="flex justify-center mb-3">
            <svg viewBox="0 0 200 120" className="w-full max-w-[200px] h-auto">
              {/* background arc */}
              <path
                d="M 20 100 A 80 80 0 0 1 180 100"
                fill="none"
                stroke="#27272a"
                strokeWidth="14"
                strokeLinecap="round"
              />
              {/* value arc */}
              <path
                d="M 20 100 A 80 80 0 0 1 180 100"
                fill="none"
                stroke={fill}
                strokeWidth="14"
                strokeLinecap="round"
                strokeDasharray={`${(score / 100) * 251.2} 251.2`}
                className="transition-all duration-700"
              />
              {/* score value */}
              <text
                x="100"
                y="82"
                textAnchor="middle"
                fill={fill}
                fontSize="36"
                fontWeight="bold"
                fontFamily="monospace"
              >
                {score}
              </text>
              {/* label */}
              <text
                x="100"
                y="102"
                textAnchor="middle"
                fill="#71717a"
                fontSize="11"
                fontWeight="600"
                letterSpacing="0.1em"
              >
                {scoreLabel(score)}
              </text>
              {/* scale labels */}
              <text x="14" y="116" fill="#52525b" fontSize="9" fontFamily="monospace">0</text>
              <text x="172" y="116" fill="#52525b" fontSize="9" fontFamily="monospace">100</text>
            </svg>
          </div>

          {/* Scale legend */}
          <div className="flex justify-center gap-1.5 mb-3">
            {[
              { label: 'LOW', color: 'bg-green-500' },
              { label: 'GRD', color: 'bg-blue-500' },
              { label: 'ELV', color: 'bg-yellow-500' },
              { label: 'HI', color: 'bg-orange-500' },
              { label: 'CRT', color: 'bg-red-500' },
            ].map((s) => (
              <div key={s.label} className="flex items-center gap-1 text-[9px] text-zinc-600 font-mono">
                <span className={`inline-block h-1.5 w-3 rounded-sm ${s.color}`} />
                {s.label}
              </div>
            ))}
          </div>

          {/* Protection level display */}
          <div className="text-center pt-2 border-t border-zinc-800">
            <span className="text-[10px] text-zinc-600 uppercase tracking-widest">Protection Level</span>
            <p className={`text-sm font-bold ${levelMeta.textColor}`}>{levelMeta.label}</p>
          </div>
        </div>

        {/* Primary Stat Cards Grid */}
        <div className="lg:col-span-3">
          <div className="grid grid-cols-2 gap-4 lg:grid-cols-3">
            {primaryStats.map((card) => {
              const Icon = card.icon;
              return (
                <div
                  key={card.label}
                  className={`group rounded-xl border ${card.border} bg-zinc-900 p-5 transition hover:border-zinc-600 ${card.bg}`}
                >
                  <div className="flex items-center justify-between">
                    <p className="text-[10px] font-semibold text-zinc-500 uppercase tracking-wider">{card.label}</p>
                    <Icon className="h-4 w-4 text-zinc-700 group-hover:text-zinc-500 transition" />
                  </div>
                  <p className={`mt-2 text-2xl font-bold tabular-nums font-mono ${card.text}`}>{card.value}</p>
                </div>
              );
            })}
          </div>
        </div>
      </div>

      {/* ===== SECONDARY THREAT CARDS ===== */}
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        {secondaryStats.map((card) => {
          const Icon = card.icon;
          return (
            <div
              key={card.label}
              className={`group rounded-xl border ${card.border} bg-zinc-900 p-5 transition hover:border-zinc-600 ${card.bg} ${card.pulse ? 'animate-pulse-glow' : ''}`}
            >
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-[10px] font-semibold text-zinc-500 uppercase tracking-wider">{card.label}</p>
                  <p className="text-[9px] text-zinc-600 mt-0.5">{card.sublabel}</p>
                </div>
                <Icon className="h-4 w-4 text-zinc-700 group-hover:text-zinc-500 transition" />
              </div>
              <p className={`mt-2 text-2xl font-bold tabular-nums font-mono ${card.text}`}>{card.value}</p>
            </div>
          );
        })}
      </div>

      {/* ===== TRAFFIC ANALYSIS CHART ===== */}
      <div className="rounded-xl border border-zinc-800 bg-zinc-900 p-5">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-xs font-semibold text-zinc-400 uppercase tracking-widest">
            Traffic Analysis &mdash; 60s Window
          </h2>
          <div className="flex items-center gap-4 text-[10px] text-zinc-600 font-mono">
            <span className="flex items-center gap-1.5">
              <span className="inline-block h-2 w-2 rounded-full bg-green-500" /> Legitimate
            </span>
            <span className="flex items-center gap-1.5">
              <span className="inline-block h-2 w-2 rounded-full bg-yellow-500" /> Challenged
            </span>
            <span className="flex items-center gap-1.5">
              <span className="inline-block h-2 w-2 rounded-full bg-red-500" /> Blocked
            </span>
          </div>
        </div>
        <div className="h-72 w-full">
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={chartData} margin={{ top: 5, right: 20, left: 0, bottom: 5 }}>
              <defs>
                <linearGradient id="gP" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#22c55e" stopOpacity={0.4} />
                  <stop offset="95%" stopColor="#22c55e" stopOpacity={0} />
                </linearGradient>
                <linearGradient id="gC" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#eab308" stopOpacity={0.4} />
                  <stop offset="95%" stopColor="#eab308" stopOpacity={0} />
                </linearGradient>
                <linearGradient id="gB" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#ef4444" stopOpacity={0.4} />
                  <stop offset="95%" stopColor="#ef4444" stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="#1c1c1e" />
              <XAxis
                dataKey="time"
                tick={{ fill: '#52525b', fontSize: 10, fontFamily: 'monospace' }}
                axisLine={{ stroke: '#27272a' }}
                tickLine={false}
              />
              <YAxis
                tick={{ fill: '#52525b', fontSize: 10, fontFamily: 'monospace' }}
                axisLine={false}
                tickLine={false}
              />
              <Tooltip
                contentStyle={{
                  backgroundColor: '#0a0a0a',
                  border: '1px solid #27272a',
                  borderRadius: '0.5rem',
                  color: '#e4e4e7',
                  fontSize: '11px',
                  fontFamily: 'monospace',
                }}
              />
              <Area type="monotone" dataKey="passed" stackId="1" stroke="#22c55e" fill="url(#gP)" name="Legitimate" />
              <Area type="monotone" dataKey="challenged" stackId="1" stroke="#eab308" fill="url(#gC)" name="Challenged" />
              <Area type="monotone" dataKey="blocked" stackId="1" stroke="#ef4444" fill="url(#gB)" name="Blocked" />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* ===== ACTIVE DEFENSE SUMMARY ===== */}
      <div className="rounded-xl border border-zinc-800 bg-zinc-900 p-5">
        <h2 className="text-xs font-semibold text-zinc-400 uppercase tracking-widest mb-4">
          Active Defense Systems
        </h2>
        <div className="flex flex-wrap gap-3">
          {defenseBadges.map((badge) => {
            const Icon = badge.icon;
            return (
              <div
                key={badge.label}
                className={`inline-flex items-center gap-2 rounded-full border ${badge.borderColor} ${badge.bgColor} px-3.5 py-1.5`}
              >
                <Icon className={`h-3 w-3 ${badge.color}`} />
                <span className="text-[10px] font-bold text-zinc-400 uppercase tracking-wider">
                  {badge.label}:
                </span>
                <span className={`text-[10px] font-bold uppercase tracking-wider ${badge.color}`}>
                  {badge.status}
                </span>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
