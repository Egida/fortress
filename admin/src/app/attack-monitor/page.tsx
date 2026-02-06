'use client';

import { useEffect, useState, useCallback, useRef } from 'react';
import { fortressGet } from '@/lib/api';
import { formatNumber, PROTECTION_LEVELS } from '@/lib/constants';
import {
  AlertTriangle,
  ShieldCheck,
  ShieldAlert,
  ShieldOff,
  Zap,
  Radio,
  Activity,
  Eye,
  Ban,
  Clock,
  Globe,
  Target,
  Cpu,
  Wifi,
  WifiOff,
  Volume2,
  VolumeX,
  ChevronDown,
  ChevronUp,
  Crosshair,
  Skull,
  Siren,
  MonitorDot,
} from 'lucide-react';
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  ReferenceLine,
} from 'recharts';
import { CountryFlag } from '@/components/country-flag';

/* -------------------------------------------------------------------------- */
/*  Types                                                                     */
/* -------------------------------------------------------------------------- */

interface Metrics {
  rps: number;
  blocked_per_sec: number;
  challenged_per_sec: number;
  passed_per_sec: number;
  unique_ips: number;
  avg_latency_ms: number;
  total_requests: number;
  total_blocked: number;
  uptime_secs: number;
}

interface ThreatSummary {
  protection_level: string;
  rps: number;
  block_rate: number;
  active_connections: number;
  auto_ban_count: number;
  ip_reputation_tracked: number;
  distributed_attack_active: boolean;
  distributed_unique_ips: number;
  distributed_window_requests: number;
}

interface DistributedAttack {
  current_window: {
    total_requests: number;
    unique_ips: number;
    new_ips: number;
    attack_active: boolean;
  };
  last_attack?: {
    request_count: number;
    unique_ips: number;
    new_ip_ratio: number;
    top_path: string;
    signals: string[];
  };
}

interface Threat {
  id: number;
  severity: string;
  started_at: string;
  ended_at: string | null;
  total_requests: number;
  unique_ips: number;
  peak_rps: number;
  max_level: number;
  top_ips_json: string;
  top_countries_json: string;
}

interface AutoBan {
  ip: string;
  reason: string;
  banned_at: string;
  expires_at: string;
  ban_count: number;
}

interface TopIp {
  ip: string;
  count: number;
  country?: string;
  threat_score?: number;
}

interface HistoryPoint {
  timestamp: number;
  requests: number;
  blocked: number;
  challenged: number;
  passed: number;
}

/* -------------------------------------------------------------------------- */
/*  Helpers                                                                   */
/* -------------------------------------------------------------------------- */

function severityColor(severity: string): string {
  switch (severity) {
    case 'critical': return 'text-red-400 bg-red-500/10 border-red-500/20';
    case 'high': return 'text-orange-400 bg-orange-500/10 border-orange-500/20';
    case 'medium': return 'text-yellow-400 bg-yellow-500/10 border-yellow-500/20';
    default: return 'text-blue-400 bg-blue-500/10 border-blue-500/20';
  }
}

function levelToDefcon(level: string): { label: string; color: string; textColor: string; dotColor: string } {
  const map: Record<string, string> = { L0: 'Normal', L1: 'High', L2: 'UnderAttack', L3: 'Severe', L4: 'Critical' };
  const key = map[level] || 'Normal';
  const pl = PROTECTION_LEVELS[key] || PROTECTION_LEVELS.Normal;
  return { label: pl.label, color: pl.color, textColor: pl.textColor, dotColor: pl.dotColor };
}

function timeAgo(dateStr: string): string {
  const diff = Date.now() - new Date(dateStr).getTime();
  if (diff < 60000) return `${Math.floor(diff / 1000)}s ago`;
  if (diff < 3600000) return `${Math.floor(diff / 60000)}m ago`;
  if (diff < 86400000) return `${Math.floor(diff / 3600000)}h ago`;
  return `${Math.floor(diff / 86400000)}d ago`;
}

function formatTime(ts: number): string {
  const d = new Date(ts * 1000);
  return d.toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

/* -------------------------------------------------------------------------- */
/*  Custom Tooltip                                                            */
/* -------------------------------------------------------------------------- */

function ChartTooltip({ active, payload, label }: { active?: boolean; payload?: Array<{ name: string; value: number; color: string }>; label?: number }) {
  if (!active || !payload || !label) return null;
  return (
    <div className="rounded-lg border border-zinc-700 bg-zinc-900 px-3 py-2 text-xs shadow-xl">
      <p className="font-mono text-zinc-400 mb-1">{formatTime(label)}</p>
      {payload.map((p) => (
        <div key={p.name} className="flex items-center gap-2">
          <span className="w-2 h-2 rounded-full" style={{ backgroundColor: p.color }} />
          <span className="text-zinc-300">{p.name}:</span>
          <span className="font-mono text-white">{formatNumber(p.value)}</span>
        </div>
      ))}
    </div>
  );
}

/* -------------------------------------------------------------------------- */
/*  Attack Status Banner                                                      */
/* -------------------------------------------------------------------------- */

function AttackBanner({ threatSummary, distributed }: { threatSummary: ThreatSummary | null; distributed: DistributedAttack | null }) {
  const isAttack = threatSummary?.distributed_attack_active || distributed?.current_window?.attack_active;
  const level = threatSummary?.protection_level || 'L0';
  const defcon = levelToDefcon(level);

  if (isAttack) {
    return (
      <div className="relative overflow-hidden rounded-xl border border-red-500/40 bg-gradient-to-r from-red-950/80 via-red-900/40 to-red-950/80 p-5 mb-6">
        <div className="absolute inset-0 bg-red-500/5 animate-pulse" />
        <div className="relative flex items-center justify-between">
          <div className="flex items-center gap-4">
            <div className="relative">
              <Siren className="h-10 w-10 text-red-400 animate-pulse" />
              <span className="absolute -top-1 -right-1 w-3 h-3 rounded-full bg-red-500 animate-ping" />
            </div>
            <div>
              <h2 className="text-xl font-bold text-red-300 tracking-wider">ATTACK DETECTED</h2>
              <p className="text-sm text-red-400/80 mt-0.5">
                Distributed attack in progress &mdash; {formatNumber(distributed?.current_window?.unique_ips || 0)} unique sources &mdash; {formatNumber(distributed?.current_window?.total_requests || 0)} req/window
              </p>
            </div>
          </div>
          <div className="flex items-center gap-3">
            <div className={`px-3 py-1.5 rounded-lg border ${defcon.color} ${defcon.textColor} text-sm font-mono font-bold`}>
              {defcon.label}
            </div>
            <div className="text-right">
              <div className="text-2xl font-bold font-mono text-red-300">{formatNumber(threatSummary?.rps || 0)}</div>
              <div className="text-xs text-red-400/70">req/sec</div>
            </div>
          </div>
        </div>
        {distributed?.last_attack?.signals && distributed.last_attack.signals.length > 0 && (
          <div className="relative mt-3 flex flex-wrap gap-2">
            {distributed.last_attack.signals.map((sig, i) => (
              <span key={i} className="inline-flex items-center gap-1.5 rounded-full border border-red-500/30 bg-red-500/10 px-2.5 py-0.5 text-xs font-mono text-red-300">
                <AlertTriangle className="h-3 w-3" />
                {sig}
              </span>
            ))}
          </div>
        )}
      </div>
    );
  }

  const levelNum = parseInt(level.replace('L', '')) || 0;
  if (levelNum >= 2) {
    return (
      <div className="rounded-xl border border-yellow-500/30 bg-gradient-to-r from-yellow-950/50 via-yellow-900/20 to-yellow-950/50 p-5 mb-6">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-4">
            <ShieldAlert className="h-8 w-8 text-yellow-400" />
            <div>
              <h2 className="text-lg font-bold text-yellow-300 tracking-wide">ELEVATED THREAT POSTURE</h2>
              <p className="text-sm text-yellow-400/70 mt-0.5">
                Protection level elevated to {defcon.label} &mdash; Enhanced monitoring active
              </p>
            </div>
          </div>
          <div className={`px-3 py-1.5 rounded-lg border ${defcon.color} ${defcon.textColor} text-sm font-mono font-bold`}>
            {defcon.label}
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="rounded-xl border border-emerald-500/20 bg-gradient-to-r from-emerald-950/30 via-emerald-900/10 to-emerald-950/30 p-5 mb-6">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4">
          <ShieldCheck className="h-8 w-8 text-emerald-400" />
          <div>
            <h2 className="text-lg font-bold text-emerald-300 tracking-wide">ALL SYSTEMS NOMINAL</h2>
            <p className="text-sm text-emerald-400/60 mt-0.5">
              No active threats detected &mdash; {defcon.label} ({PROTECTION_LEVELS[levelToDefcon(level).label === 'DEFCON 5' ? 'Normal' : 'Normal']?.codename || 'GREENFIELD'})
            </p>
          </div>
        </div>
        <div className="flex items-center gap-3">
          <div className={`px-3 py-1.5 rounded-lg border border-emerald-500/30 bg-emerald-500/10 text-emerald-400 text-sm font-mono font-bold`}>
            {defcon.label}
          </div>
          <div className="text-right">
            <div className="text-2xl font-bold font-mono text-emerald-300">{formatNumber(threatSummary?.rps || 0)}</div>
            <div className="text-xs text-emerald-400/60">req/sec</div>
          </div>
        </div>
      </div>
    </div>
  );
}

/* -------------------------------------------------------------------------- */
/*  Main Page                                                                 */
/* -------------------------------------------------------------------------- */

export default function AttackMonitorPage() {
  /* ---- state ---- */
  const [metrics, setMetrics] = useState<Metrics | null>(null);
  const [threatSummary, setThreatSummary] = useState<ThreatSummary | null>(null);
  const [distributed, setDistributed] = useState<DistributedAttack | null>(null);
  const [threats, setThreats] = useState<Threat[]>([]);
  const [autoBans, setAutoBans] = useState<AutoBan[]>([]);
  const [topIps, setTopIps] = useState<TopIp[]>([]);
  const [chartData, setChartData] = useState<HistoryPoint[]>([]);
  const [soundEnabled, setSoundEnabled] = useState(false);
  const [showAllThreats, setShowAllThreats] = useState(false);
  const [connected, setConnected] = useState(true);
  const [lastUpdate, setLastUpdate] = useState<Date>(new Date());

  /* Track previous attack state for alert */
  const prevAttackRef = useRef(false);
  const audioRef = useRef<HTMLAudioElement | null>(null);

  /* ---- data fetchers ---- */

  const fetchAll = useCallback(async () => {
    try {
      const [m, ts, da, th, ab, ips, hist] = await Promise.all([
        fortressGet<Metrics>('/api/fortress/metrics'),
        fortressGet<ThreatSummary>('/api/fortress/threat-summary'),
        fortressGet<DistributedAttack>('/api/fortress/distributed-attacks'),
        fortressGet<{ threats: Threat[] }>('/api/fortress/threats'),
        fortressGet<{ bans: AutoBan[]; active_count: number }>('/api/fortress/auto-bans'),
        fortressGet<{ top_ips: TopIp[] }>('/api/fortress/top-ips?limit=20'),
        fortressGet<{ data: HistoryPoint[] }>('/api/fortress/metrics/history?granularity=second'),
      ]);

      setMetrics(m);
      setThreatSummary(ts);
      setDistributed(da);
      setThreats(th.threats?.slice(0, 20) || []);
      setAutoBans(ab.bans || []);
      setTopIps(ips.top_ips || []);

      // Keep last 120 seconds of chart data
      const histData = (hist.data || []).slice(-120);
      setChartData(histData);

      setConnected(true);
      setLastUpdate(new Date());

      // Alert on new attack
      const isAttack = ts.distributed_attack_active || da.current_window?.attack_active;
      if (isAttack && !prevAttackRef.current && soundEnabled && audioRef.current) {
        audioRef.current.play().catch(() => {});
      }
      prevAttackRef.current = !!isAttack;
    } catch {
      setConnected(false);
    }
  }, [soundEnabled]);

  /* ---- polling ---- */

  useEffect(() => {
    fetchAll();
    const interval = setInterval(fetchAll, 2000);
    return () => clearInterval(interval);
  }, [fetchAll]);

  /* ---- computed ---- */

  const isAttack = threatSummary?.distributed_attack_active || distributed?.current_window?.attack_active;
  const activeThreats = threats.filter((t) => !t.ended_at);
  const recentThreats = showAllThreats ? threats : threats.slice(0, 8);

  /* ---- render ---- */

  return (
    <div className="min-h-screen bg-black text-zinc-100">
      {/* Hidden audio element for alerts */}
      <audio ref={audioRef} preload="auto">
        <source src="data:audio/wav;base64,UklGRnoGAABXQVZFZm10IBAAAAABAAEAQB8AAEAfAAABAAgAZGF0YQoGAACBhYqFbF1lbGx3fnmEgoF6dXN4gIeNkZGMh4J9eHd6gYmRlpeUjoeCfHh4fIKKkpaYlZCJg356eHqAh46TlpWRi4WAfHl6fYOJjpGSkI2IhIF+fH1/g4iMjpCPjIiEgX9+fn+ChoeJi4uKiIWDgYB/f4CDhYeIiYiHhYOBgIB/gIGDhQaFhYaFhIKBgICAgoSD" type="audio/wav" />
      </audio>

      <div className="mx-auto max-w-7xl px-4 py-6 sm:px-6 lg:px-8">
        {/* ---- Header ---- */}
        <div className="mb-6 flex items-center justify-between">
          <div>
            <div className="flex items-center gap-3">
              <Crosshair className="h-6 w-6 text-red-400" />
              <h1 className="text-2xl font-bold tracking-tight text-white">
                Attack Monitor
              </h1>
              <span className="relative flex h-2.5 w-2.5 ml-1">
                <span className={`absolute inline-flex h-full w-full animate-ping rounded-full ${isAttack ? 'bg-red-400' : 'bg-green-400'} opacity-75`} />
                <span className={`relative inline-flex h-2.5 w-2.5 rounded-full ${isAttack ? 'bg-red-500' : 'bg-green-500'}`} />
              </span>
              <span className={`rounded-md px-2 py-0.5 text-xs font-medium border ${
                isAttack
                  ? 'bg-red-500/10 text-red-400 border-red-500/20'
                  : 'bg-green-500/10 text-green-400 border-green-500/20'
              }`}>
                {isAttack ? 'UNDER ATTACK' : 'NOMINAL'}
              </span>
            </div>
            <p className="mt-1 text-sm text-zinc-500 ml-9">
              Real-time threat detection and incident response
            </p>
          </div>
          <div className="flex items-center gap-3">
            {/* Connection status */}
            <div className={`flex items-center gap-1.5 text-xs ${connected ? 'text-zinc-500' : 'text-red-400'}`}>
              {connected ? <Wifi className="h-3.5 w-3.5" /> : <WifiOff className="h-3.5 w-3.5" />}
              <span className="font-mono">{connected ? `Updated ${lastUpdate.toLocaleTimeString('en-US', { hour12: false })}` : 'Disconnected'}</span>
            </div>
            {/* Sound toggle */}
            <button
              onClick={() => setSoundEnabled(!soundEnabled)}
              className={`flex items-center gap-1.5 rounded-lg border px-3 py-1.5 text-xs transition-colors ${
                soundEnabled
                  ? 'border-blue-500/30 bg-blue-500/10 text-blue-400'
                  : 'border-zinc-700 bg-zinc-900 text-zinc-500 hover:text-zinc-300'
              }`}
            >
              {soundEnabled ? <Volume2 className="h-3.5 w-3.5" /> : <VolumeX className="h-3.5 w-3.5" />}
              {soundEnabled ? 'Alerts ON' : 'Alerts OFF'}
            </button>
          </div>
        </div>

        {/* ---- Attack Status Banner ---- */}
        <AttackBanner threatSummary={threatSummary} distributed={distributed} />

        {/* ---- Stat Cards ---- */}
        <div className="mb-6 grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-6">
          {[
            {
              label: 'Throughput',
              value: metrics ? `${formatNumber(metrics.rps)}/s` : '--',
              icon: <Activity className="h-4 w-4" />,
              accent: 'text-blue-400',
            },
            {
              label: 'Blocked',
              value: metrics ? `${formatNumber(metrics.blocked_per_sec)}/s` : '--',
              icon: <ShieldOff className="h-4 w-4" />,
              accent: metrics && metrics.blocked_per_sec > 10 ? 'text-red-400' : 'text-orange-400',
            },
            {
              label: 'Challenged',
              value: metrics ? `${formatNumber(metrics.challenged_per_sec)}/s` : '--',
              icon: <Cpu className="h-4 w-4" />,
              accent: 'text-yellow-400',
            },
            {
              label: 'Passed',
              value: metrics ? `${formatNumber(metrics.passed_per_sec)}/s` : '--',
              icon: <ShieldCheck className="h-4 w-4" />,
              accent: 'text-emerald-400',
            },
            {
              label: 'Unique IPs',
              value: metrics ? formatNumber(metrics.unique_ips) : '--',
              icon: <Globe className="h-4 w-4" />,
              accent: 'text-purple-400',
            },
            {
              label: 'Latency',
              value: metrics ? `${metrics.avg_latency_ms.toFixed(1)}ms` : '--',
              icon: <Zap className="h-4 w-4" />,
              accent: metrics && metrics.avg_latency_ms > 100 ? 'text-red-400' : 'text-cyan-400',
            },
          ].map((card) => (
            <div key={card.label} className="rounded-xl border border-zinc-800 bg-zinc-900/80 p-4">
              <div className="flex items-center justify-between mb-2">
                <span className="text-[10px] font-medium uppercase tracking-wider text-zinc-500">{card.label}</span>
                <span className={card.accent}>{card.icon}</span>
              </div>
              <p className="text-xl font-bold font-mono text-white">{card.value}</p>
            </div>
          ))}
        </div>

        {/* ---- Live Traffic Chart ---- */}
        <div className="mb-6 rounded-xl border border-zinc-800 bg-zinc-900/80 p-5">
          <div className="mb-4 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Radio className="h-4 w-4 text-blue-400" />
              <h2 className="text-lg font-semibold text-white">Live Traffic Stream</h2>
              <span className="relative flex h-2 w-2 ml-1">
                <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-blue-400 opacity-75" />
                <span className="relative inline-flex h-2 w-2 rounded-full bg-blue-500" />
              </span>
            </div>
            <div className="flex items-center gap-4 text-xs">
              <span className="flex items-center gap-1.5"><span className="w-2.5 h-2.5 rounded-full bg-blue-500" /> Requests</span>
              <span className="flex items-center gap-1.5"><span className="w-2.5 h-2.5 rounded-full bg-red-500" /> Blocked</span>
              <span className="flex items-center gap-1.5"><span className="w-2.5 h-2.5 rounded-full bg-yellow-500" /> Challenged</span>
              <span className="flex items-center gap-1.5"><span className="w-2.5 h-2.5 rounded-full bg-emerald-500" /> Passed</span>
            </div>
          </div>
          <div className="h-[280px]">
            {chartData.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={chartData} margin={{ top: 5, right: 10, left: 0, bottom: 5 }}>
                  <defs>
                    <linearGradient id="colorRequests" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.3} />
                      <stop offset="95%" stopColor="#3b82f6" stopOpacity={0} />
                    </linearGradient>
                    <linearGradient id="colorBlocked" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#ef4444" stopOpacity={0.4} />
                      <stop offset="95%" stopColor="#ef4444" stopOpacity={0} />
                    </linearGradient>
                    <linearGradient id="colorChallenged" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#eab308" stopOpacity={0.3} />
                      <stop offset="95%" stopColor="#eab308" stopOpacity={0} />
                    </linearGradient>
                    <linearGradient id="colorPassed" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#10b981" stopOpacity={0.2} />
                      <stop offset="95%" stopColor="#10b981" stopOpacity={0} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="#27272a" />
                  <XAxis
                    dataKey="timestamp"
                    tickFormatter={formatTime}
                    stroke="#52525b"
                    fontSize={10}
                    tickLine={false}
                    interval="preserveStartEnd"
                    minTickGap={60}
                  />
                  <YAxis stroke="#52525b" fontSize={10} tickLine={false} axisLine={false} />
                  <Tooltip content={<ChartTooltip />} />
                  <Area
                    type="monotone"
                    dataKey="requests"
                    name="Requests"
                    stroke="#3b82f6"
                    strokeWidth={2}
                    fill="url(#colorRequests)"
                    dot={false}
                    isAnimationActive={false}
                  />
                  <Area
                    type="monotone"
                    dataKey="blocked"
                    name="Blocked"
                    stroke="#ef4444"
                    strokeWidth={2}
                    fill="url(#colorBlocked)"
                    dot={false}
                    isAnimationActive={false}
                  />
                  <Area
                    type="monotone"
                    dataKey="challenged"
                    name="Challenged"
                    stroke="#eab308"
                    strokeWidth={1.5}
                    fill="url(#colorChallenged)"
                    dot={false}
                    isAnimationActive={false}
                  />
                  <Area
                    type="monotone"
                    dataKey="passed"
                    name="Passed"
                    stroke="#10b981"
                    strokeWidth={1.5}
                    fill="url(#colorPassed)"
                    dot={false}
                    isAnimationActive={false}
                  />
                </AreaChart>
              </ResponsiveContainer>
            ) : (
              <div className="flex items-center justify-center h-full text-zinc-600">
                <div className="flex flex-col items-center gap-2">
                  <Radio className="h-6 w-6 animate-pulse" />
                  <span className="text-sm">Acquiring telemetry data...</span>
                </div>
              </div>
            )}
          </div>
        </div>

        {/* ---- Two-column: Threats + Top IPs ---- */}
        <div className="mb-6 grid grid-cols-1 gap-6 lg:grid-cols-2">
          {/* ---- Recent Attack Events ---- */}
          <div className="rounded-xl border border-zinc-800 bg-zinc-900/80 p-5">
            <div className="mb-4 flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Skull className="h-4 w-4 text-red-400" />
                <h2 className="text-lg font-semibold text-white">Attack Timeline</h2>
                {activeThreats.length > 0 && (
                  <span className="rounded-full bg-red-500/10 border border-red-500/20 px-2 py-0.5 text-xs font-mono text-red-400">
                    {activeThreats.length} ACTIVE
                  </span>
                )}
              </div>
              {threats.length > 8 && (
                <button
                  onClick={() => setShowAllThreats(!showAllThreats)}
                  className="flex items-center gap-1 text-xs text-zinc-500 hover:text-zinc-300 transition-colors"
                >
                  {showAllThreats ? 'Show less' : `Show all (${threats.length})`}
                  {showAllThreats ? <ChevronUp className="h-3 w-3" /> : <ChevronDown className="h-3 w-3" />}
                </button>
              )}
            </div>

            <div className="space-y-2 max-h-[400px] overflow-y-auto pr-1">
              {recentThreats.length === 0 && (
                <div className="py-8 text-center text-zinc-600">
                  <ShieldCheck className="h-6 w-6 mx-auto mb-2 text-zinc-700" />
                  <span className="text-sm">No recent attack events</span>
                </div>
              )}
              {recentThreats.map((threat) => {
                const isActive = !threat.ended_at;
                const topIpsArr: [string, number][] = (() => {
                  try { return JSON.parse(threat.top_ips_json || '[]'); } catch { return []; }
                })();
                const topCountriesArr: [string, number][] = (() => {
                  try { return JSON.parse(threat.top_countries_json || '[]'); } catch { return []; }
                })();

                return (
                  <div
                    key={threat.id}
                    className={`rounded-lg border p-3 transition-colors ${
                      isActive
                        ? 'border-red-500/30 bg-red-500/5'
                        : 'border-zinc-800 bg-zinc-800/30 hover:bg-zinc-800/50'
                    }`}
                  >
                    <div className="flex items-center justify-between mb-2">
                      <div className="flex items-center gap-2">
                        {isActive && <span className="w-2 h-2 rounded-full bg-red-500 animate-pulse" />}
                        <span className={`text-xs font-mono font-bold px-1.5 py-0.5 rounded border ${severityColor(threat.severity)}`}>
                          {threat.severity.toUpperCase()}
                        </span>
                        <span className="text-xs text-zinc-500 font-mono">#{threat.id}</span>
                      </div>
                      <div className="flex items-center gap-2 text-xs text-zinc-500">
                        <Clock className="h-3 w-3" />
                        {timeAgo(threat.started_at)}
                        {isActive && <span className="text-red-400 font-medium">ONGOING</span>}
                      </div>
                    </div>
                    <div className="grid grid-cols-3 gap-3 text-xs">
                      <div>
                        <span className="text-zinc-500">Requests</span>
                        <p className="font-mono text-white">{formatNumber(threat.total_requests)}</p>
                      </div>
                      <div>
                        <span className="text-zinc-500">Sources</span>
                        <p className="font-mono text-white">{formatNumber(threat.unique_ips)} IPs</p>
                      </div>
                      <div>
                        <span className="text-zinc-500">Peak</span>
                        <p className="font-mono text-white">{formatNumber(threat.peak_rps)} rps</p>
                      </div>
                    </div>
                    {topCountriesArr.length > 0 && (
                      <div className="mt-2 flex flex-wrap gap-1">
                        {topCountriesArr.slice(0, 6).map(([code, count]) => (
                          <span key={code} className="inline-flex items-center gap-1 rounded-full bg-zinc-800 px-2 py-0.5 text-[10px] text-zinc-400">
                            <CountryFlag code={code} size={12} className="inline-block align-middle" /> {code}
                            <span className="font-mono text-zinc-500">{count}</span>
                          </span>
                        ))}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          </div>

          {/* ---- Top Threat Sources ---- */}
          <div className="rounded-xl border border-zinc-800 bg-zinc-900/80 p-5">
            <div className="mb-4 flex items-center gap-2">
              <Target className="h-4 w-4 text-orange-400" />
              <h2 className="text-lg font-semibold text-white">Top Threat Sources</h2>
              {topIps.length > 0 && (
                <span className="ml-auto rounded-full bg-zinc-800 px-2.5 py-0.5 text-xs font-medium tabular-nums text-zinc-400">
                  {topIps.length}
                </span>
              )}
            </div>

            <div className="max-h-[400px] overflow-y-auto pr-1">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-zinc-800 text-left text-zinc-500 text-xs">
                    <th className="pb-2 pr-3 font-medium">#</th>
                    <th className="pb-2 pr-3 font-medium">Source IP</th>
                    <th className="pb-2 pr-3 text-center font-medium">Score</th>
                    <th className="pb-2 text-right font-medium">Requests</th>
                  </tr>
                </thead>
                <tbody>
                  {topIps.length === 0 && (
                    <tr>
                      <td colSpan={4} className="py-8 text-center text-zinc-600">
                        <MonitorDot className="h-5 w-5 mx-auto mb-1 text-zinc-700" />
                        <span className="text-sm">Awaiting source data...</span>
                      </td>
                    </tr>
                  )}
                  {topIps.map((ip, idx) => {
                    const maxCount = topIps[0]?.count || 1;
                    const pct = (ip.count / maxCount) * 100;
                    return (
                      <tr key={ip.ip} className="border-b border-zinc-800/50 hover:bg-zinc-800/30 transition-colors">
                        <td className="py-2 pr-3 text-zinc-600 tabular-nums text-xs">{idx + 1}</td>
                        <td className="py-2 pr-3">
                          <div className="flex items-center gap-1.5">
                            {ip.country && <span title={ip.country}><CountryFlag code={ip.country} size={14} /></span>}
                            <span className="font-mono text-xs text-zinc-300">{ip.ip}</span>
                          </div>
                          {/* Request bar */}
                          <div className="mt-1 h-1 w-full rounded-full bg-zinc-800 overflow-hidden">
                            <div
                              className={`h-full rounded-full transition-all duration-500 ${
                                (ip.threat_score || 0) >= 50 ? 'bg-red-500' : (ip.threat_score || 0) >= 25 ? 'bg-orange-500' : 'bg-blue-500'
                              }`}
                              style={{ width: `${pct}%` }}
                            />
                          </div>
                        </td>
                        <td className="py-2 pr-3 text-center">
                          {ip.threat_score !== undefined && ip.threat_score !== null ? (
                            <span className={`inline-block rounded-full px-2 py-0.5 text-xs font-medium tabular-nums bg-zinc-800 ${
                              ip.threat_score >= 80 ? 'text-red-400' :
                              ip.threat_score >= 50 ? 'text-orange-400' :
                              ip.threat_score >= 25 ? 'text-yellow-400' :
                              'text-green-400'
                            }`}>
                              {ip.threat_score}
                            </span>
                          ) : (
                            <span className="text-zinc-700 text-xs">--</span>
                          )}
                        </td>
                        <td className="py-2 text-right tabular-nums text-xs text-zinc-300 font-mono">
                          {formatNumber(ip.count)}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>
        </div>

        {/* ---- Two-column: Distributed Detection + Auto-Bans ---- */}
        <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
          {/* ---- Distributed Attack Detection ---- */}
          <div className="rounded-xl border border-zinc-800 bg-zinc-900/80 p-5">
            <div className="mb-4 flex items-center gap-2">
              <Eye className="h-4 w-4 text-purple-400" />
              <h2 className="text-lg font-semibold text-white">Distributed Detection Engine</h2>
            </div>

            {distributed ? (
              <div className="space-y-4">
                {/* Current window */}
                <div className={`rounded-lg border p-4 ${
                  distributed.current_window.attack_active
                    ? 'border-red-500/30 bg-red-500/5'
                    : 'border-zinc-800 bg-zinc-800/30'
                }`}>
                  <div className="flex items-center justify-between mb-3">
                    <span className="text-xs font-medium uppercase tracking-wider text-zinc-500">Current Analysis Window</span>
                    <span className={`text-xs font-mono font-bold px-2 py-0.5 rounded ${
                      distributed.current_window.attack_active
                        ? 'bg-red-500/10 text-red-400 border border-red-500/20'
                        : 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                    }`}>
                      {distributed.current_window.attack_active ? 'ATTACK' : 'CLEAR'}
                    </span>
                  </div>
                  <div className="grid grid-cols-3 gap-4">
                    <div>
                      <span className="text-[10px] text-zinc-500 uppercase">Requests</span>
                      <p className="text-lg font-bold font-mono text-white">{formatNumber(distributed.current_window.total_requests)}</p>
                    </div>
                    <div>
                      <span className="text-[10px] text-zinc-500 uppercase">Unique IPs</span>
                      <p className="text-lg font-bold font-mono text-white">{formatNumber(distributed.current_window.unique_ips)}</p>
                    </div>
                    <div>
                      <span className="text-[10px] text-zinc-500 uppercase">New IPs</span>
                      <p className="text-lg font-bold font-mono text-white">{formatNumber(distributed.current_window.new_ips)}</p>
                    </div>
                  </div>
                </div>

                {/* Last attack */}
                {distributed.last_attack && (
                  <div className="rounded-lg border border-zinc-800 bg-zinc-800/30 p-4">
                    <span className="text-xs font-medium uppercase tracking-wider text-zinc-500 mb-3 block">Last Detected Pattern</span>
                    <div className="grid grid-cols-2 gap-3 text-xs mb-3">
                      <div>
                        <span className="text-zinc-500">Request Count</span>
                        <p className="font-mono text-white">{formatNumber(distributed.last_attack.request_count)}</p>
                      </div>
                      <div>
                        <span className="text-zinc-500">Unique Sources</span>
                        <p className="font-mono text-white">{distributed.last_attack.unique_ips}</p>
                      </div>
                      <div>
                        <span className="text-zinc-500">New IP Ratio</span>
                        <p className="font-mono text-white">{(distributed.last_attack.new_ip_ratio * 100).toFixed(1)}%</p>
                      </div>
                      <div>
                        <span className="text-zinc-500">Target Path</span>
                        <p className="font-mono text-white truncate">{distributed.last_attack.top_path}</p>
                      </div>
                    </div>
                    {distributed.last_attack.signals.length > 0 && (
                      <div className="flex flex-wrap gap-1.5">
                        {distributed.last_attack.signals.map((sig, i) => (
                          <span key={i} className="inline-flex items-center gap-1 rounded-full border border-yellow-500/20 bg-yellow-500/10 px-2 py-0.5 text-[10px] font-mono text-yellow-300">
                            <AlertTriangle className="h-2.5 w-2.5" />
                            {sig}
                          </span>
                        ))}
                      </div>
                    )}
                  </div>
                )}
              </div>
            ) : (
              <div className="py-8 text-center text-zinc-600">
                <Eye className="h-6 w-6 mx-auto mb-2 text-zinc-700 animate-pulse" />
                <span className="text-sm">Initializing detection engine...</span>
              </div>
            )}
          </div>

          {/* ---- Active Auto-Bans ---- */}
          <div className="rounded-xl border border-zinc-800 bg-zinc-900/80 p-5">
            <div className="mb-4 flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Ban className="h-4 w-4 text-red-400" />
                <h2 className="text-lg font-semibold text-white">Active Containment</h2>
              </div>
              <span className={`rounded-full px-2.5 py-0.5 text-xs font-mono font-medium ${
                autoBans.length > 0
                  ? 'bg-red-500/10 text-red-400 border border-red-500/20'
                  : 'bg-zinc-800 text-zinc-500'
              }`}>
                {autoBans.length} {autoBans.length === 1 ? 'BAN' : 'BANS'}
              </span>
            </div>

            {autoBans.length === 0 ? (
              <div className="py-8 text-center text-zinc-600">
                <ShieldCheck className="h-6 w-6 mx-auto mb-2 text-zinc-700" />
                <span className="text-sm">No active containment actions</span>
              </div>
            ) : (
              <div className="space-y-2 max-h-[300px] overflow-y-auto pr-1">
                {autoBans.map((ban) => {
                  const expiresIn = Math.max(0, new Date(ban.expires_at).getTime() - Date.now());
                  const mins = Math.floor(expiresIn / 60000);
                  const secs = Math.floor((expiresIn % 60000) / 1000);
                  return (
                    <div key={ban.ip} className="rounded-lg border border-red-500/20 bg-red-500/5 p-3">
                      <div className="flex items-center justify-between mb-1">
                        <span className="font-mono text-sm text-red-300">{ban.ip}</span>
                        <span className="text-xs font-mono text-red-400">
                          <Clock className="h-3 w-3 inline mr-1" />
                          {mins}m {secs}s remaining
                        </span>
                      </div>
                      <div className="flex items-center justify-between text-xs text-zinc-500">
                        <span>{ban.reason}</span>
                        <span>Strike #{ban.ban_count}</span>
                      </div>
                    </div>
                  );
                })}
              </div>
            )}

            {/* Threat summary footer */}
            {threatSummary && (
              <div className="mt-4 pt-4 border-t border-zinc-800">
                <div className="grid grid-cols-3 gap-3 text-xs">
                  <div>
                    <span className="text-zinc-500">Block Rate</span>
                    <p className="font-mono text-white">{(threatSummary.block_rate * 100).toFixed(2)}%</p>
                  </div>
                  <div>
                    <span className="text-zinc-500">Connections</span>
                    <p className="font-mono text-white">{formatNumber(threatSummary.active_connections)}</p>
                  </div>
                  <div>
                    <span className="text-zinc-500">Rep. Tracked</span>
                    <p className="font-mono text-white">{formatNumber(threatSummary.ip_reputation_tracked)}</p>
                  </div>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
