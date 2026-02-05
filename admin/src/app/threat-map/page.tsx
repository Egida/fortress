"use client";

import { useState, useEffect, useCallback } from "react";
import { fetchApi, fortressPost } from "@/lib/api";
import { PROTECTION_LEVELS, formatNumber } from "@/lib/constants";
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
} from "recharts";
import {
  Shield,
  Zap,
  ShieldBan,
  Radio,
  Ban,
  Eye,
  Globe,
  Users,
  AlertTriangle,
  ArrowUpCircle,
  CheckCircle2,
  XCircle,
  Flame,
} from "lucide-react";
import { CountryFlag } from "@/components/country-flag";

/* ---------- types ---------- */
interface ThreatSummary {
  protection_level: string;
  rps: number;
  block_rate: number;
  active_connections: number;
  auto_ban_count: number;
  ip_reputation_tracked: number;
  distributed_attack_active: boolean;
  distributed_window_requests: number;
  distributed_unique_ips: number;
}

interface CountryRow {
  country: string;
  requests: number;
  blocked: number;
  blocked_pct: number;
}

/* ---------- helpers ---------- */
const levelColors: Record<string, { dot: string; ring: string; text: string; bg: string }> = {
  Normal:      { dot: "bg-green-400",  ring: "ring-green-400/30",  text: "text-green-400",  bg: "bg-green-500/10" },
  High:        { dot: "bg-yellow-400", ring: "ring-yellow-400/30", text: "text-yellow-400", bg: "bg-yellow-500/10" },
  UnderAttack: { dot: "bg-orange-400", ring: "ring-orange-400/30", text: "text-orange-400", bg: "bg-orange-500/10" },
  Severe:      { dot: "bg-red-500",    ring: "ring-red-500/30",    text: "text-red-400",    bg: "bg-red-500/10" },
  Emergency:   { dot: "bg-red-700",    ring: "ring-red-700/30",    text: "text-red-300",    bg: "bg-red-800/20" },
};

function threatScore(s: ThreatSummary): number {
  let score = 0;
  const lvl = PROTECTION_LEVELS[s.protection_level]?.level ?? 0;
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
  if (v >= 80) return "Critical";
  if (v >= 60) return "High";
  if (v >= 40) return "Elevated";
  if (v >= 20) return "Guarded";
  return "Low";
}

function scoreColor(v: number): string {
  if (v >= 80) return "text-red-400";
  if (v >= 60) return "text-orange-400";
  if (v >= 40) return "text-yellow-400";
  if (v >= 20) return "text-blue-400";
  return "text-green-400";
}

function scoreFill(v: number): string {
  if (v >= 80) return "#ef4444";
  if (v >= 60) return "#f97316";
  if (v >= 40) return "#eab308";
  if (v >= 20) return "#3b82f6";
  return "#22c55e";
}

/* ---------- component ---------- */
export default function ThreatMapPage() {
  const [summary, setSummary] = useState<ThreatSummary | null>(null);
  const [countries, setCountries] = useState<CountryRow[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [escalating, setEscalating] = useState<string | null>(null);
  const [tick, setTick] = useState(0);

  const loadData = useCallback(async () => {
    try {
      const [sumRes, countryRes] = await Promise.all([
        fetchApi<ThreatSummary>("/api/fortress/threat-summary"),
        fetchApi("/api/fortress/top-countries?limit=30"),
      ]);
      setSummary(sumRes);
      setCountries((countryRes as any).countries || []);
      setError(null);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "Failed to fetch threat data");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadData();
    const interval = setInterval(() => {
      loadData();
      setTick((t) => t + 1);
    }, 5000);
    return () => clearInterval(interval);
  }, [loadData]);

  const handleEscalate = async (level: string) => {
    setEscalating(level);
    try {
      await fortressPost("/api/fortress/level", { level });
      await loadData();
    } catch {
      /* silently fail - next refresh will show state */
    } finally {
      setEscalating(null);
    }
  };

  /* ---------- loading skeleton ---------- */
  if (loading) {
    return (
      <div className="space-y-6">
        {/* header skeleton */}
        <div className="flex items-center justify-between rounded-xl border border-zinc-800 bg-zinc-900 px-6 py-4">
          <div className="flex items-center gap-4">
            <div className="h-10 w-10 animate-pulse rounded-lg bg-zinc-800" />
            <div>
              <div className="h-6 w-48 animate-pulse rounded bg-zinc-800" />
              <div className="mt-1 h-3 w-72 animate-pulse rounded bg-zinc-800" />
            </div>
          </div>
          <div className="h-4 w-20 animate-pulse rounded bg-zinc-800" />
        </div>
        {/* stat card skeletons */}
        <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
          {Array.from({ length: 8 }).map((_, i) => (
            <div key={i} className="rounded-xl border border-zinc-800 bg-zinc-900 p-5">
              <div className="h-3 w-24 animate-pulse rounded bg-zinc-800" />
              <div className="mt-3 h-7 w-20 animate-pulse rounded bg-zinc-800" />
            </div>
          ))}
        </div>
        {/* two-column skeleton */}
        <div className="grid gap-6 lg:grid-cols-5">
          <div className="lg:col-span-3 rounded-xl border border-zinc-800 bg-zinc-900 p-5">
            <div className="h-4 w-40 animate-pulse rounded bg-zinc-800 mb-4" />
            {Array.from({ length: 6 }).map((_, i) => (
              <div key={i} className="flex gap-4 py-3">
                <div className="h-4 w-24 animate-pulse rounded bg-zinc-800" />
                <div className="h-4 w-16 animate-pulse rounded bg-zinc-800" />
                <div className="h-4 w-16 animate-pulse rounded bg-zinc-800" />
                <div className="h-4 flex-1 animate-pulse rounded bg-zinc-800" />
              </div>
            ))}
          </div>
          <div className="lg:col-span-2 rounded-xl border border-zinc-800 bg-zinc-900 p-5">
            <div className="h-4 w-32 animate-pulse rounded bg-zinc-800 mb-6" />
            <div className="mx-auto h-40 w-40 animate-pulse rounded-full bg-zinc-800" />
          </div>
        </div>
      </div>
    );
  }

  if (!summary) {
    return (
      <div className="flex items-center justify-center min-h-[60vh]">
        <span className="text-red-400">{error || "No data available"}</span>
      </div>
    );
  }

  /* ---------- derived values ---------- */
  const levelKey = summary.protection_level ?? "Normal";
  const levelMeta = PROTECTION_LEVELS[levelKey] ?? PROTECTION_LEVELS["Normal"];
  const lc = levelColors[levelKey] ?? levelColors["Normal"];
  const score = threatScore(summary);
  const topCountries = countries.slice(0, 20);

  const signals: { label: string; active: boolean; severity: "red" | "yellow" | "green" }[] = [
    {
      label: "DDoS vector detected: coordinated distributed flood in progress",
      active: summary.distributed_attack_active,
      severity: "red",
    },
    {
      label: `Anomalous block ratio: ${summary.block_rate.toFixed(1)}% of inbound traffic rejected`,
      active: summary.block_rate > 30,
      severity: summary.block_rate > 50 ? "red" : "yellow",
    },
    {
      label: `Automated threat response: ${summary.auto_ban_count} source IPs quarantined`,
      active: summary.auto_ban_count > 0,
      severity: summary.auto_ban_count > 50 ? "red" : "yellow",
    },
    {
      label: `Source IP dispersion anomaly: ${formatNumber(summary.distributed_unique_ips)} unique origins observed`,
      active: summary.distributed_unique_ips > 200,
      severity: summary.distributed_unique_ips > 500 ? "red" : "yellow",
    },
    {
      label: `Elevated defense posture: protection level at ${levelMeta.label}`,
      active: (PROTECTION_LEVELS[levelKey]?.level ?? 0) >= 2,
      severity: (PROTECTION_LEVELS[levelKey]?.level ?? 0) >= 3 ? "red" : "yellow",
    },
    {
      label: "All systems nominal -- no active threat indicators",
      active:
        !summary.distributed_attack_active &&
        summary.block_rate <= 30 &&
        summary.auto_ban_count === 0 &&
        (PROTECTION_LEVELS[levelKey]?.level ?? 0) < 2,
      severity: "green",
    },
  ];

  /* stat card defs */
  const statCards = [
    {
      label: "Protection Level",
      value: levelMeta.label,
      icon: Shield,
      color: lc.text,
      bg: lc.bg,
    },
    {
      label: "Requests / sec",
      value: summary.rps.toFixed(1),
      icon: Zap,
      color: "text-blue-400",
      bg: "bg-blue-500/10",
    },
    {
      label: "Block Rate",
      value: `${summary.block_rate.toFixed(1)}%`,
      icon: ShieldBan,
      color: summary.block_rate > 30 ? "text-red-400" : "text-green-400",
      bg: summary.block_rate > 30 ? "bg-red-500/10" : "bg-green-500/10",
    },
    {
      label: "Active Connections",
      value: formatNumber(summary.active_connections),
      icon: Radio,
      color: "text-cyan-400",
      bg: "bg-cyan-500/10",
    },
    {
      label: "Auto-Banned IPs",
      value: formatNumber(summary.auto_ban_count),
      icon: Ban,
      color: summary.auto_ban_count > 0 ? "text-red-400" : "text-green-400",
      bg: summary.auto_ban_count > 0 ? "bg-red-500/10" : "bg-green-500/10",
    },
    {
      label: "IP Reputation Tracked",
      value: formatNumber(summary.ip_reputation_tracked),
      icon: Eye,
      color: "text-purple-400",
      bg: "bg-purple-500/10",
    },
    {
      label: "Distributed Window Reqs",
      value: formatNumber(summary.distributed_window_requests),
      icon: Globe,
      color: summary.distributed_attack_active ? "text-red-400" : "text-zinc-300",
      bg: summary.distributed_attack_active ? "bg-red-500/10" : "bg-zinc-800/50",
    },
    {
      label: "Distributed Unique IPs",
      value: formatNumber(summary.distributed_unique_ips),
      icon: Users,
      color: summary.distributed_unique_ips > 200 ? "text-yellow-400" : "text-zinc-300",
      bg: summary.distributed_unique_ips > 200 ? "bg-yellow-500/10" : "bg-zinc-800/50",
    },
  ];

  /* country bar chart data (top 10) */
  const barData = countries.slice(0, 10).map((c) => ({
    name: `${c.country?.length > 12 ? c.country.slice(0, 12) + ".." : c.country}`,
    code: c.country,
    blocked: c.blocked,
    passed: Math.max(0, c.requests - c.blocked),
  }));

  /* ---------- render ---------- */
  return (
    <div className="space-y-6">
      {/* ===== HEADER ===== */}
      <div className="flex flex-wrap items-center justify-between gap-4 rounded-xl border border-zinc-800 bg-zinc-900 px-6 py-4">
        <div className="flex items-center gap-4">
          <div className="flex items-center justify-center h-10 w-10 rounded-lg bg-purple-500/10 border border-purple-500/20">
            <Globe className="h-5 w-5 text-purple-400" />
          </div>
          <div>
            <div className="flex items-center gap-3">
              <h1 className="text-xl font-bold tracking-tight">Threat Intelligence</h1>
              <span
                className={`inline-flex items-center gap-2 rounded-full px-3 py-1 text-xs font-semibold ${levelMeta.color} ${levelMeta.textColor}`}
              >
                <span className={`inline-block h-2 w-2 rounded-full ${lc.dot}`} />
                {levelMeta.label}
              </span>
            </div>
            <p className="text-xs text-zinc-500 mt-0.5">
              Multi-vector threat assessment and strategic defense posture
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2 text-xs text-zinc-500">
          <span className="relative flex h-2.5 w-2.5">
            <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-green-400 opacity-75" />
            <span className="relative inline-flex h-2.5 w-2.5 rounded-full bg-green-500" />
          </span>
          Live &mdash; refreshing every 5s
        </div>
      </div>

      {/* ===== DISTRIBUTED ATTACK ALERT ===== */}
      {summary.distributed_attack_active && (
        <div className="flex items-center gap-4 rounded-xl border border-red-800 bg-red-950/60 px-6 py-4 animate-pulse">
          <AlertTriangle className="h-6 w-6 text-red-400 shrink-0" />
          <div className="flex-1">
            <p className="text-sm font-semibold text-red-300">
              Distributed Attack Detected
            </p>
            <p className="text-xs text-red-400/80 mt-0.5">
              {formatNumber(summary.distributed_window_requests)} requests from{" "}
              {formatNumber(summary.distributed_unique_ips)} unique IPs in the
              current window
            </p>
          </div>
          <Flame className="h-5 w-5 text-red-500 animate-bounce" />
        </div>
      )}

      {/* ===== ERROR BANNER ===== */}
      {error && (
        <div className="rounded-lg border border-red-800 bg-red-900/30 px-4 py-2 text-sm text-red-300">
          {error}
        </div>
      )}

      {/* ===== STAT CARDS (2 rows x 4) ===== */}
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        {statCards.map((card) => {
          const Icon = card.icon;
          return (
            <div
              key={card.label}
              className={`group rounded-xl border border-zinc-800 bg-zinc-900 p-5 transition hover:border-zinc-700 ${card.bg}`}
            >
              <div className="flex items-center justify-between">
                <p className="text-xs font-medium text-zinc-500 uppercase tracking-wider">
                  {card.label}
                </p>
                <Icon className="h-4 w-4 text-zinc-600 group-hover:text-zinc-400 transition" />
              </div>
              <p className={`mt-2 text-2xl font-bold tabular-nums ${card.color}`}>
                {card.value}
              </p>
            </div>
          );
        })}
      </div>

      {/* ===== TWO COLUMN LAYOUT ===== */}
      <div className="grid gap-6 lg:grid-cols-5">
        {/* --- Left: Country Threat Table + Bar Chart --- */}
        <div className="lg:col-span-3 space-y-6">
          {/* Bar Chart */}
          <div className="rounded-xl border border-zinc-800 bg-zinc-900 p-5">
            <h2 className="text-sm font-semibold text-zinc-400 mb-4">
              Top 10 Countries &mdash; Request Distribution
            </h2>
            <div className="h-56">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart
                  data={barData}
                  margin={{ top: 5, right: 10, left: 0, bottom: 5 }}
                >
                  <XAxis
                    dataKey="name"
                    tick={{ fill: "#71717a", fontSize: 11 }}
                    axisLine={{ stroke: "#3f3f46" }}
                    tickLine={false}
                  />
                  <YAxis
                    tick={{ fill: "#71717a", fontSize: 11 }}
                    axisLine={false}
                    tickLine={false}
                  />
                  <Tooltip
                    contentStyle={{
                      backgroundColor: "#18181b",
                      border: "1px solid #3f3f46",
                      borderRadius: "0.5rem",
                      color: "#e4e4e7",
                      fontSize: "12px",
                    }}
                  />
                  <Bar dataKey="passed" stackId="a" name="Passed" fill="#22c55e" radius={[0, 0, 0, 0]} />
                  <Bar dataKey="blocked" stackId="a" name="Blocked" fill="#ef4444" radius={[4, 4, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>

          {/* Geographic Threat Matrix */}
          <div className="rounded-xl border border-zinc-800 bg-zinc-900 overflow-hidden">
            <div className="px-5 pt-5 pb-3">
              <h2 className="text-sm font-semibold text-zinc-400">
                Geographic Threat Matrix
              </h2>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-zinc-800 text-zinc-500 text-xs uppercase tracking-wider">
                    <th className="px-5 py-3 text-left font-medium">Country</th>
                    <th className="px-5 py-3 text-right font-medium">Requests</th>
                    <th className="px-5 py-3 text-right font-medium">Blocked</th>
                    <th className="px-5 py-3 text-left font-medium w-48">Block %</th>
                  </tr>
                </thead>
                <tbody>
                  {topCountries.map((c, i) => {
                    const pct = c.blocked_pct ?? 0;
                    const barColor =
                      pct > 50
                        ? "bg-red-500"
                        : pct > 25
                        ? "bg-yellow-500"
                        : "bg-green-500";
                    return (
                      <tr
                        key={i}
                        className="border-b border-zinc-800/50 hover:bg-zinc-800/30 transition"
                      >
                        <td className="px-5 py-2.5 text-white font-medium">
                          <CountryFlag code={c.country} size={16} className="mr-1 inline-block align-middle" /> {c.country || "Unknown"}
                        </td>
                        <td className="px-5 py-2.5 text-right text-zinc-300 font-mono text-xs">
                          {formatNumber(c.requests || 0)}
                        </td>
                        <td className="px-5 py-2.5 text-right text-zinc-300 font-mono text-xs">
                          {formatNumber(c.blocked || 0)}
                        </td>
                        <td className="px-5 py-2.5">
                          <div className="flex items-center gap-2">
                            <div className="flex-1 h-2 rounded-full bg-zinc-800 overflow-hidden">
                              <div
                                className={`h-full rounded-full ${barColor} transition-all duration-500`}
                                style={{ width: `${Math.min(100, pct)}%` }}
                              />
                            </div>
                            <span
                              className={`text-xs font-mono w-12 text-right ${
                                pct > 50
                                  ? "text-red-400"
                                  : pct > 25
                                  ? "text-yellow-400"
                                  : "text-zinc-400"
                              }`}
                            >
                              {pct.toFixed(1)}%
                            </span>
                          </div>
                        </td>
                      </tr>
                    );
                  })}
                  {topCountries.length === 0 && (
                    <tr>
                      <td
                        colSpan={4}
                        className="px-5 py-10 text-center text-zinc-600"
                      >
                        No country data available
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>

        {/* --- Right: Threat Gauge + Signals + Actions --- */}
        <div className="lg:col-span-2 space-y-6">
          {/* Global Threat Posture */}
          <div className="rounded-xl border border-zinc-800 bg-zinc-900 p-5">
            <h2 className="text-sm font-semibold text-zinc-400 mb-6">
              Global Threat Posture
            </h2>

            {/* Semicircle Gauge */}
            <div className="flex justify-center mb-4">
              <svg viewBox="0 0 200 120" className="w-56 h-auto">
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
                  stroke={scoreFill(score)}
                  strokeWidth="14"
                  strokeLinecap="round"
                  strokeDasharray={`${(score / 100) * 251.2} 251.2`}
                  className="transition-all duration-700"
                />
                {/* center label */}
                <text
                  x="100"
                  y="85"
                  textAnchor="middle"
                  className="text-3xl font-bold"
                  fill={scoreFill(score)}
                  fontSize="32"
                  fontWeight="bold"
                >
                  {score}
                </text>
                <text
                  x="100"
                  y="105"
                  textAnchor="middle"
                  fill="#71717a"
                  fontSize="12"
                >
                  {scoreLabel(score)}
                </text>
                {/* scale labels */}
                <text x="16" y="116" fill="#52525b" fontSize="9">
                  0
                </text>
                <text x="176" y="116" fill="#52525b" fontSize="9">
                  100
                </text>
              </svg>
            </div>

            {/* Scale Legend */}
            <div className="flex justify-center gap-1 mb-6">
              {[
                { label: "Low", color: "bg-green-500" },
                { label: "Guarded", color: "bg-blue-500" },
                { label: "Elevated", color: "bg-yellow-500" },
                { label: "High", color: "bg-orange-500" },
                { label: "Critical", color: "bg-red-500" },
              ].map((s) => (
                <div key={s.label} className="flex items-center gap-1 text-[10px] text-zinc-500">
                  <span className={`inline-block h-1.5 w-3 rounded-full ${s.color}`} />
                  {s.label}
                </div>
              ))}
            </div>

            {/* Active Threat Indicators */}
            <h3 className="text-xs font-semibold text-zinc-500 uppercase tracking-wider mb-3">
              Active Threat Indicators
            </h3>
            <div className="space-y-2">
              {signals
                .filter((s) => s.active)
                .map((s, i) => {
                  const Icon =
                    s.severity === "red"
                      ? XCircle
                      : s.severity === "yellow"
                      ? AlertTriangle
                      : CheckCircle2;
                  const clr =
                    s.severity === "red"
                      ? "text-red-400 bg-red-500/10 border-red-900/50"
                      : s.severity === "yellow"
                      ? "text-yellow-400 bg-yellow-500/10 border-yellow-900/50"
                      : "text-green-400 bg-green-500/10 border-green-900/50";
                  return (
                    <div
                      key={i}
                      className={`flex items-center gap-3 rounded-lg border px-3 py-2 text-xs ${clr}`}
                    >
                      <Icon className="h-3.5 w-3.5 shrink-0" />
                      <span>{s.label}</span>
                    </div>
                  );
                })}
            </div>
          </div>

          {/* Tactical Response Options */}
          <div className="rounded-xl border border-zinc-800 bg-zinc-900 p-5">
            <h2 className="text-sm font-semibold text-zinc-400 mb-4">
              Tactical Response Options
            </h2>
            <p className="text-xs text-zinc-600 mb-3">Quick Escalation</p>
            <div className="space-y-2">
              {[
                {
                  label: "Escalate to L1 (High)",
                  level: "High",
                  color: "border-yellow-800 bg-yellow-900/20 text-yellow-400 hover:bg-yellow-900/40",
                  icon: ArrowUpCircle,
                },
                {
                  label: "Escalate to L2 (Under Attack)",
                  level: "UnderAttack",
                  color: "border-orange-800 bg-orange-900/20 text-orange-400 hover:bg-orange-900/40",
                  icon: ArrowUpCircle,
                },
                {
                  label: "Escalate to L3 (Severe)",
                  level: "Severe",
                  color: "border-red-800 bg-red-900/20 text-red-400 hover:bg-red-900/40",
                  icon: AlertTriangle,
                },
                {
                  label: "De-escalate to Normal",
                  level: "Normal",
                  color: "border-green-800 bg-green-900/20 text-green-400 hover:bg-green-900/40",
                  icon: CheckCircle2,
                },
              ].map((action) => {
                const BtnIcon = action.icon;
                const isActive = escalating === action.level;
                const isCurrent = levelKey === action.level;
                return (
                  <button
                    key={action.level}
                    onClick={() => handleEscalate(action.level)}
                    disabled={isActive || isCurrent}
                    className={`w-full flex items-center gap-3 rounded-lg border px-4 py-3 text-xs font-medium transition disabled:opacity-40 disabled:cursor-not-allowed ${action.color}`}
                  >
                    <BtnIcon className="h-4 w-4 shrink-0" />
                    <span className="flex-1 text-left">
                      {isActive ? "Applying..." : action.label}
                    </span>
                    {isCurrent && (
                      <span className="text-[10px] uppercase tracking-wider opacity-60">
                        Current
                      </span>
                    )}
                  </button>
                );
              })}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
