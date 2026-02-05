'use client';

import { useEffect, useState, useCallback, useRef, useMemo } from 'react';
import { fortressGet } from '@/lib/api';
import { AnalyticsData } from '@/lib/types';
import { formatNumber } from '@/lib/constants';
import {
  Activity, ShieldBan, ShieldCheck, Zap, Fingerprint,
  Globe, Network, Radio, Clock, TrendingUp,
  BarChart3, Shield, Target,
} from 'lucide-react';
import { CountryFlag } from '@/components/country-flag';

/* ───────────────────── TYPES ───────────────────── */

type TimeRange = '1h' | '6h' | '24h' | '7d';

interface HistoryEntry {
  timestamp: number;
  data: AnalyticsData;
}

/* ───────────────────── COMPONENTS ───────────────────── */

function SkeletonCard() {
  return (
    <div className="rounded-xl border border-zinc-800 bg-zinc-900/80 p-5 animate-pulse">
      <div className="h-3 w-20 bg-zinc-800 rounded mb-3" />
      <div className="h-7 w-28 bg-zinc-800/60 rounded" />
    </div>
  );
}

function SkeletonTable() {
  return (
    <div className="rounded-xl border border-zinc-800 bg-zinc-900/80 p-5 animate-pulse">
      <div className="h-4 w-40 bg-zinc-800 rounded mb-5" />
      <div className="space-y-3">
        {Array.from({ length: 5 }).map((_, i) => (
          <div key={i} className="flex items-center gap-3">
            <div className="h-3 w-32 bg-zinc-800/40 rounded" />
            <div className="h-2 flex-1 bg-zinc-800/30 rounded-full" />
          </div>
        ))}
      </div>
    </div>
  );
}

interface StatCardProps {
  label: string;
  value: string;
  icon: React.ElementType;
  color: string;
  iconColor: string;
  subtext?: string;
}

function StatCard({ label, value, icon: Icon, color, iconColor, subtext }: StatCardProps) {
  return (
    <div className="rounded-xl border border-zinc-800 bg-zinc-900/80 backdrop-blur-sm p-5 transition-all hover:border-zinc-700">
      <div className="flex items-start justify-between mb-3">
        <span className="text-xs font-medium text-zinc-500 uppercase tracking-wider">{label}</span>
        <div className={`p-1.5 rounded-lg bg-zinc-800/80`}>
          <Icon className={`w-4 h-4 ${iconColor}`} />
        </div>
      </div>
      <div className={`text-2xl font-bold tabular-nums ${color}`}>{value}</div>
      {subtext && <div className="text-[11px] text-zinc-600 mt-1">{subtext}</div>}
    </div>
  );
}

interface PercentBarProps {
  count: number;
  total: number;
  max: number;
  color: string;
}

function PercentBar({ count, total, max, color }: PercentBarProps) {
  const pct = max > 0 ? (count / max) * 100 : 0;
  const pctOfTotal = total > 0 ? ((count / total) * 100).toFixed(1) : '0.0';
  return (
    <div className="flex items-center gap-3">
      <span className="text-sm text-zinc-300 tabular-nums w-16 text-right font-mono">
        {formatNumber(count)}
      </span>
      <div className="flex-1 h-2 bg-zinc-800 rounded-full overflow-hidden">
        <div
          className={`h-full rounded-full ${color} transition-all duration-500`}
          style={{ width: `${pct}%` }}
        />
      </div>
      <span className="text-[11px] text-zinc-500 tabular-nums w-14 text-right">
        {pctOfTotal}%
      </span>
    </div>
  );
}

interface DataTableProps<T> {
  title: string;
  icon: React.ElementType;
  data: T[];
  columns: { key: keyof T; label: string; render?: (val: T[keyof T], row: T) => React.ReactNode }[];
  countKey: keyof T;
  barColor: string;
  totalRequests: number;
}

function DataTable<T>({ title, icon: Icon, data, columns, countKey, barColor, totalRequests }: DataTableProps<T>) {
  const maxCount = data.reduce((m, row) => Math.max(m, Number(row[countKey]) || 0), 0);

  return (
    <div className="rounded-xl border border-zinc-800 bg-zinc-900/80 backdrop-blur-sm p-5">
      <div className="flex items-center gap-2.5 mb-4">
        <Icon className="w-4 h-4 text-zinc-500" />
        <h3 className="text-sm font-semibold text-zinc-200">{title}</h3>
        <span className="ml-auto text-[10px] text-zinc-600 font-mono">{data.length} entries</span>
      </div>
      <div className="space-y-0">
        {/* Table Header */}
        <div
          className="grid gap-3 text-[10px] text-zinc-500 uppercase tracking-wider pb-2 border-b border-zinc-800 font-medium"
          style={{ gridTemplateColumns: `1fr minmax(200px, 1.5fr)` }}
        >
          {columns.map((col) => (
            <div key={String(col.key)}>{col.label}</div>
          ))}
        </div>

        {/* Table Rows */}
        {data.length === 0 ? (
          <div className="py-8 text-center text-sm text-zinc-600">No data available</div>
        ) : (
          data.map((row, i) => (
            <div
              key={i}
              className="grid gap-3 py-2.5 border-b border-zinc-800/30 last:border-b-0 items-center hover:bg-zinc-800/20 transition-colors rounded"
              style={{ gridTemplateColumns: `1fr minmax(200px, 1.5fr)` }}
            >
              {columns.map((col) => {
                if (col.key === countKey) {
                  return (
                    <div key={String(col.key)}>
                      <PercentBar
                        count={Number(row[countKey]) || 0}
                        total={totalRequests}
                        max={maxCount}
                        color={barColor}
                      />
                    </div>
                  );
                }
                const val = col.render
                  ? col.render(row[col.key], row)
                  : String(row[col.key] ?? '');
                return (
                  <div key={String(col.key)} className="text-sm text-zinc-300 truncate font-mono">
                    {val}
                  </div>
                );
              })}
            </div>
          ))
        )}
      </div>
    </div>
  );
}

function TimeRangeSelector({ value, onChange }: { value: TimeRange; onChange: (v: TimeRange) => void }) {
  const ranges: { key: TimeRange; label: string }[] = [
    { key: '1h', label: '1H' },
    { key: '6h', label: '6H' },
    { key: '24h', label: '24H' },
    { key: '7d', label: '7D' },
  ];

  return (
    <div className="flex items-center bg-zinc-900 border border-zinc-800 rounded-lg p-0.5">
      {ranges.map((r) => (
        <button
          key={r.key}
          onClick={() => onChange(r.key)}
          className={`px-3.5 py-1.5 text-xs font-medium rounded-md transition-all ${
            value === r.key
              ? 'bg-blue-600 text-white shadow-sm'
              : 'text-zinc-500 hover:text-zinc-300 hover:bg-zinc-800/50'
          }`}
        >
          {r.label}
        </button>
      ))}
    </div>
  );
}

/* ───────────────────── ATTACK VECTOR SECTION ───────────────────── */

interface AttackVectorBarProps {
  label: string;
  count: number;
  total: number;
  color: string;
}

function AttackVectorBar({ label, count, total, color }: AttackVectorBarProps) {
  const pct = total > 0 ? (count / total) * 100 : 0;
  return (
    <div className="space-y-1.5">
      <div className="flex items-center justify-between text-sm">
        <span className="text-zinc-400">{label}</span>
        <div className="flex items-center gap-2">
          <span className="text-zinc-300 font-mono tabular-nums">{formatNumber(count)}</span>
          <span className="text-zinc-500 text-xs w-12 text-right">{pct.toFixed(1)}%</span>
        </div>
      </div>
      <div className="h-2 bg-zinc-800 rounded-full overflow-hidden">
        <div
          className={`h-full rounded-full ${color} transition-all duration-700`}
          style={{ width: `${Math.max(pct, 0.5)}%` }}
        />
      </div>
    </div>
  );
}

/* ───────────────────── MAIN PAGE ───────────────────── */

export default function ThreatAnalyticsPage() {
  const [analytics, setAnalytics] = useState<AnalyticsData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [timeRange, setTimeRange] = useState<TimeRange>('24h');
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const [history, setHistory] = useState<HistoryEntry[]>([]);

  const fetchAnalytics = useCallback(async () => {
    try {
      const data = await fortressGet<AnalyticsData>('/api/fortress/analytics');
      setAnalytics(data);
      setError(null);
      setHistory((prev) => {
        const entry: HistoryEntry = { timestamp: Date.now(), data };
        const cutoff = Date.now() - 7 * 24 * 60 * 60 * 1000;
        return [...prev.filter((h) => h.timestamp > cutoff), entry];
      });
    } catch {
      setError('Failed to load threat analytics data.');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchAnalytics();
    intervalRef.current = setInterval(fetchAnalytics, 5000);
    return () => {
      if (intervalRef.current) clearInterval(intervalRef.current);
    };
  }, [fetchAnalytics]);

  const filteredAnalytics = useMemo(() => {
    if (!analytics) return null;

    if (history.length < 2) return analytics;

    const rangeMs: Record<TimeRange, number> = {
      '1h': 60 * 60 * 1000,
      '6h': 6 * 60 * 60 * 1000,
      '24h': 24 * 60 * 60 * 1000,
      '7d': 7 * 24 * 60 * 60 * 1000,
    };
    const cutoff = Date.now() - rangeMs[timeRange];
    const inRange = history.filter((h) => h.timestamp >= cutoff);

    if (inRange.length === 0) return analytics;

    const latest = inRange[inRange.length - 1].data;
    return latest;
  }, [analytics, timeRange, history]);

  if (loading) {
    return (
      <div className="min-h-screen bg-black text-zinc-100">
        <div className="max-w-7xl mx-auto px-6 py-10">
          <div className="mb-10">
            <div className="h-7 w-48 bg-zinc-800 rounded animate-pulse" />
            <div className="h-4 w-72 bg-zinc-800/50 rounded mt-3 animate-pulse" />
          </div>
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
            {Array.from({ length: 4 }).map((_, i) => <SkeletonCard key={i} />)}
          </div>
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            {Array.from({ length: 4 }).map((_, i) => <SkeletonTable key={i} />)}
          </div>
        </div>
      </div>
    );
  }

  if (error && !analytics) {
    return (
      <div className="min-h-screen bg-black flex items-center justify-center">
        <div className="text-center">
          <ShieldBan className="w-10 h-10 text-red-500 mx-auto mb-3" />
          <div className="text-red-400 text-sm">{error}</div>
        </div>
      </div>
    );
  }

  const snap = filteredAnalytics?.snapshot;
  const totalReqs = snap?.total_requests ?? 0;
  const totalBlocked = snap?.total_blocked ?? 0;
  const blockRate = totalReqs > 0 ? ((totalBlocked / totalReqs) * 100).toFixed(1) : '0.0';

  return (
    <div className="min-h-screen bg-black text-zinc-100">
      <div className="max-w-7xl mx-auto px-6 py-10">
        {/* Header */}
        <div className="flex items-start justify-between mb-8">
          <div>
            <h1 className="text-2xl font-bold text-zinc-100 flex items-center gap-3">
              <BarChart3 className="w-7 h-7 text-blue-400" />
              Threat Analytics
            </h1>
            <p className="text-sm text-zinc-500 mt-2 ml-10">Deep traffic analysis and pattern recognition</p>
          </div>
          <div className="flex items-center gap-4">
            <TimeRangeSelector value={timeRange} onChange={setTimeRange} />
            <div className="flex items-center gap-2 bg-zinc-900 border border-zinc-800 rounded-lg px-3 py-2">
              <span className="inline-block h-2 w-2 rounded-full bg-green-500 animate-pulse" />
              <span className="text-xs text-zinc-400 font-medium">Live Feed</span>
            </div>
          </div>
        </div>

        {error && (
          <div className="mb-6 rounded-lg px-4 py-3 text-sm font-medium bg-red-900/30 text-red-300 border border-red-800/50 flex items-center gap-2">
            <ShieldBan className="w-4 h-4" />
            {error}
          </div>
        )}

        {/* Stat Cards */}
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
          <StatCard
            label="Total Processed"
            value={formatNumber(totalReqs)}
            icon={Activity}
            color="text-blue-400"
            iconColor="text-blue-400"
            subtext={`${snap?.rps?.toFixed(0) ?? 0} req/s current`}
          />
          <StatCard
            label="Threats Blocked"
            value={formatNumber(totalBlocked)}
            icon={ShieldBan}
            color="text-red-400"
            iconColor="text-red-400"
            subtext={`${blockRate}% block rate`}
          />
          <StatCard
            label="PoW Verified"
            value={formatNumber(snap?.unique_ips ?? 0)}
            icon={ShieldCheck}
            color="text-amber-400"
            iconColor="text-amber-400"
            subtext="Unique verified clients"
          />
          <StatCard
            label="Clean Traffic"
            value={`${snap?.avg_latency_ms?.toFixed(1) ?? '0.0'} ms`}
            icon={Zap}
            color="text-emerald-400"
            iconColor="text-emerald-400"
            subtext="Average response latency"
          />
        </div>

        {/* Traffic Summary */}
        {totalReqs > 0 && (
          <div className="rounded-xl border border-zinc-800 bg-zinc-900/80 backdrop-blur-sm p-6 mb-8">
            <div className="flex items-center gap-2.5 mb-5">
              <Target className="w-5 h-5 text-zinc-500" />
              <h2 className="text-base font-semibold text-zinc-200">Traffic Summary</h2>
              <span className="ml-auto text-[10px] text-zinc-600 font-mono">
                {formatNumber(totalReqs)} total requests
              </span>
            </div>
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-x-8 gap-y-4">
              <AttackVectorBar
                label="Passed (Clean Traffic)"
                count={Math.max(0, totalReqs - totalBlocked)}
                total={totalReqs}
                color="bg-emerald-500"
              />
              <AttackVectorBar
                label="Blocked (Threats)"
                count={totalBlocked}
                total={totalReqs}
                color="bg-red-500"
              />
            </div>
          </div>
        )}

        {/* Data Tables - 2x2 Grid */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          {/* Top Threat Sources */}
          <DataTable
            title="Top Threat Sources (IP)"
            icon={Shield}
            data={filteredAnalytics?.top_ips ?? []}
            columns={[
              {
                key: 'ip',
                label: 'IP Address',
                render: (val) => (
                  <span className="font-mono text-sm text-zinc-300">{String(val)}</span>
                ),
              },
              { key: 'count', label: 'Requests / Distribution' },
            ]}
            countKey="count"
            barColor="bg-blue-500"
            totalRequests={totalReqs}
          />

          {/* Geographic Distribution */}
          <DataTable
            title="Geographic Distribution"
            icon={Globe}
            data={filteredAnalytics?.top_countries ?? []}
            columns={[
              {
                key: 'country',
                label: 'Country',
                render: (val) => (
                  <span className="text-sm text-zinc-300 inline-flex items-center gap-1"><CountryFlag code={String(val)} size={16} /> {String(val)}</span>
                ),
              },
              { key: 'count', label: 'Requests / Distribution' },
            ]}
            countKey="count"
            barColor="bg-emerald-500"
            totalRequests={totalReqs}
          />

          {/* Network Origin Analysis */}
          <DataTable
            title="Network Origin Analysis (ASN)"
            icon={Network}
            data={filteredAnalytics?.top_asns ?? []}
            columns={[
              {
                key: 'asn',
                label: 'Autonomous System',
                render: (val) => (
                  <span className="font-mono text-sm text-zinc-300">
                    <span className="text-zinc-500">AS</span>{String(val)}
                  </span>
                ),
              },
              { key: 'count', label: 'Requests / Distribution' },
            ]}
            countKey="count"
            barColor="bg-amber-500"
            totalRequests={totalReqs}
          />

          {/* TLS Fingerprint Analysis */}
          <DataTable
            title="TLS Fingerprint Analysis (JA3)"
            icon={Fingerprint}
            data={filteredAnalytics?.top_fingerprints ?? []}
            columns={[
              {
                key: 'fingerprint',
                label: 'JA3 Hash',
                render: (val) => (
                  <span className="font-mono text-sm text-zinc-300" title={String(val)}>
                    {String(val).length > 20 ? `${String(val).slice(0, 20)}...` : String(val)}
                  </span>
                ),
              },
              { key: 'count', label: 'Requests / Distribution' },
            ]}
            countKey="count"
            barColor="bg-purple-500"
            totalRequests={totalReqs}
          />
        </div>

        {/* Footer timestamp */}
        <div className="mt-6 flex items-center justify-end gap-2 text-[11px] text-zinc-600">
          <Clock className="w-3 h-3" />
          Last updated: {new Date().toLocaleTimeString()} | Refreshing every 5s
        </div>
      </div>
    </div>
  );
}
