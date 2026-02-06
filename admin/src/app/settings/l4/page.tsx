'use client';

import { useEffect, useState, useCallback, useRef } from 'react';
import { fortressGet } from '@/lib/api';
import { L4Metrics, L4Event } from '@/lib/types';
import { formatNumber } from '@/lib/constants';
import { Network, ShieldCheck, ShieldOff, Anchor, Activity } from 'lucide-react';

/* ---------- stat card ---------- */
interface StatCardProps {
  label: string;
  value: string;
  color: string;
  icon: React.ElementType;
  bg: string;
}

function StatCard({ label, value, color, icon: Icon, bg }: StatCardProps) {
  return (
    <div className={`group rounded-xl border border-zinc-800 bg-zinc-900 p-5 transition hover:border-zinc-700 ${bg}`}>
      <div className="flex items-center justify-between">
        <p className="text-xs font-medium text-zinc-500 uppercase tracking-wider">{label}</p>
        <Icon className="h-4 w-4 text-zinc-600 group-hover:text-zinc-400 transition" />
      </div>
      <p className={`mt-2 text-2xl font-bold tabular-nums ${color}`}>{value}</p>
    </div>
  );
}

/* ---------- action badges ---------- */
const ACTION_BADGE_STYLES: Record<string, string> = {
  Allow: 'bg-green-900/60 text-green-300 border-green-800',
  Drop: 'bg-red-900/60 text-red-300 border-red-800',
  Tarpit: 'bg-yellow-900/60 text-yellow-300 border-yellow-800',
};

const ACTION_DISPLAY: Record<string, string> = {
  Allow: 'ALLOW',
  Drop: 'DROP',
  Tarpit: 'TARPIT',
};

function ActionBadge({ action }: { action: string }) {
  const style = ACTION_BADGE_STYLES[action] ?? 'bg-zinc-800 text-zinc-400 border-zinc-700';
  const display = ACTION_DISPLAY[action] ?? action;
  return (
    <span className={`inline-flex items-center rounded-md border px-2 py-0.5 text-xs font-semibold tracking-wide ${style}`}>
      {display}
    </span>
  );
}

/* ---------- timestamp formatting ---------- */
function formatTimestamp(ts: string): string {
  try {
    const d = new Date(ts);
    return d.toLocaleTimeString('en-US', {
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      hour12: false,
    });
  } catch {
    return ts;
  }
}

/* ---------- skeleton loader ---------- */
function LoadingSkeleton() {
  return (
    <div className="min-h-screen bg-black">
      <div className="max-w-7xl mx-auto px-6 py-10">
        {/* Header skeleton */}
        <div className="flex items-center gap-4 mb-8">
          <div className="h-7 w-56 animate-pulse rounded bg-zinc-800" />
          <div className="h-5 w-20 animate-pulse rounded-full bg-zinc-800" />
        </div>
        {/* Stat card skeletons */}
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
          {Array.from({ length: 4 }).map((_, i) => (
            <div key={i} className="rounded-xl border border-zinc-800 bg-zinc-900 p-5">
              <div className="h-3 w-32 animate-pulse rounded bg-zinc-800" />
              <div className="mt-3 h-7 w-20 animate-pulse rounded bg-zinc-800" />
            </div>
          ))}
        </div>
        {/* Table skeleton */}
        <div className="rounded-xl border border-zinc-800 bg-zinc-900 p-5">
          <div className="h-5 w-48 animate-pulse rounded bg-zinc-800 mb-6" />
          {Array.from({ length: 6 }).map((_, i) => (
            <div key={i} className="flex gap-4 py-3">
              <div className="h-4 w-20 animate-pulse rounded bg-zinc-800" />
              <div className="h-4 w-28 animate-pulse rounded bg-zinc-800" />
              <div className="h-4 w-16 animate-pulse rounded bg-zinc-800" />
              <div className="h-4 flex-1 animate-pulse rounded bg-zinc-800" />
              <div className="h-4 w-16 animate-pulse rounded bg-zinc-800" />
              <div className="h-4 w-16 animate-pulse rounded bg-zinc-800" />
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

/* ========== main page ========== */
export default function L4Page() {
  const [metrics, setMetrics] = useState<L4Metrics | null>(null);
  const [events, setEvents] = useState<L4Event[]>([]);
  const [loadingMetrics, setLoadingMetrics] = useState(true);
  const [loadingEvents, setLoadingEvents] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const metricsIntervalRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const eventsIntervalRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const fetchMetrics = useCallback(async () => {
    try {
      const data = await fortressGet<L4Metrics>('/api/fortress/l4/metrics');
      setMetrics(data);
      setError(null);
    } catch {
      setError('Failed to load L4 metrics. Retrying...');
    } finally {
      setLoadingMetrics(false);
    }
  }, []);

  const fetchEvents = useCallback(async () => {
    try {
      const data = await fortressGet<L4Event[]>('/api/fortress/l4/events?limit=50');
      setEvents(data);
    } catch {
      // Silently handle event fetch errors since metrics error is shown
    } finally {
      setLoadingEvents(false);
    }
  }, []);

  useEffect(() => {
    fetchMetrics();
    metricsIntervalRef.current = setInterval(fetchMetrics, 3000);
    return () => {
      if (metricsIntervalRef.current) clearInterval(metricsIntervalRef.current);
    };
  }, [fetchMetrics]);

  useEffect(() => {
    fetchEvents();
    eventsIntervalRef.current = setInterval(fetchEvents, 5000);
    return () => {
      if (eventsIntervalRef.current) clearInterval(eventsIntervalRef.current);
    };
  }, [fetchEvents]);

  const loading = loadingMetrics && loadingEvents;

  if (loading) {
    return <LoadingSkeleton />;
  }

  return (
    <div className="min-h-screen bg-black text-zinc-100">
      <div className="max-w-7xl mx-auto px-6 py-10">
        {/* ===== HEADER ===== */}
        <div className="flex items-center justify-between mb-8">
          <div className="flex items-center gap-3">
            <div className="flex items-center justify-center h-10 w-10 rounded-lg bg-blue-500/10 border border-blue-500/20">
              <Network className="h-5 w-5 text-blue-400" />
            </div>
            <div>
              <h1 className="text-2xl font-bold text-zinc-100">L4 TCP Shield</h1>
              <p className="text-xs text-zinc-500 mt-0.5">
                Layer 4 TCP/SYN flood protection and connection management
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <span className="relative flex h-2.5 w-2.5">
              <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-green-400 opacity-75" />
              <span className="relative inline-flex h-2.5 w-2.5 rounded-full bg-green-500" />
            </span>
            <span className="text-xs text-zinc-500">Live</span>
          </div>
        </div>

        {/* ===== ERROR BANNER ===== */}
        {error && (
          <div className="mb-6 rounded-lg px-4 py-3 text-sm font-medium bg-red-900/50 text-red-300 border border-red-800">
            {error}
          </div>
        )}

        {/* ===== STAT CARDS ===== */}
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
          <StatCard
            label="Total Connections Processed"
            value={formatNumber(metrics?.total_allowed ?? 0)}
            color="text-green-400"
            icon={ShieldCheck}
            bg="bg-green-500/5"
          />
          <StatCard
            label="SYN Floods Blocked"
            value={formatNumber(metrics?.total_dropped ?? 0)}
            color="text-red-400"
            icon={ShieldOff}
            bg="bg-red-500/5"
          />
          <StatCard
            label="Active Tarpit Sessions"
            value={formatNumber(metrics?.total_tarpitted ?? 0)}
            color="text-yellow-400"
            icon={Anchor}
            bg="bg-yellow-500/5"
          />
          <StatCard
            label="Connection Rate (conn/s)"
            value={formatNumber(metrics?.tracked_ips ?? 0)}
            color="text-amber-400"
            icon={Activity}
            bg="bg-amber-500/5"
          />
        </div>

        {/* ===== EVENTS TABLE ===== */}
        <div className="rounded-xl border border-zinc-800 bg-zinc-900 p-5">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-lg font-semibold text-zinc-100">L4 Security Event Log</h2>
            <span className="text-xs text-zinc-600 tabular-nums">
              {events.length} event{events.length !== 1 ? 's' : ''}
            </span>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-zinc-800">
                  <th className="text-left text-xs font-medium text-zinc-500 uppercase tracking-wider pb-3 pr-4">
                    Timestamp
                  </th>
                  <th className="text-left text-xs font-medium text-zinc-500 uppercase tracking-wider pb-3 pr-4">
                    Source IP
                  </th>
                  <th className="text-left text-xs font-medium text-zinc-500 uppercase tracking-wider pb-3 pr-4">
                    Action
                  </th>
                  <th className="text-left text-xs font-medium text-zinc-500 uppercase tracking-wider pb-3 pr-4">
                    Reason
                  </th>
                  <th className="text-right text-xs font-medium text-zinc-500 uppercase tracking-wider pb-3 pr-4">
                    Concurrent Conn.
                  </th>
                  <th className="text-right text-xs font-medium text-zinc-500 uppercase tracking-wider pb-3">
                    Conn. Rate
                  </th>
                </tr>
              </thead>
              <tbody>
                {events.length === 0 ? (
                  <tr>
                    <td colSpan={6} className="py-8 text-center text-sm text-zinc-600">
                      No events recorded yet
                    </td>
                  </tr>
                ) : (
                  events.map((event) => (
                    <tr
                      key={event.id}
                      className="border-b border-zinc-800/50 last:border-b-0 hover:bg-zinc-800/30 transition-colors"
                    >
                      <td className="py-2.5 pr-4">
                        <span className="text-sm text-zinc-400 font-mono">
                          {formatTimestamp(event.timestamp)}
                        </span>
                      </td>
                      <td className="py-2.5 pr-4">
                        <span className="text-sm text-zinc-300 font-mono">
                          {event.client_ip}
                        </span>
                      </td>
                      <td className="py-2.5 pr-4">
                        <ActionBadge action={event.action} />
                      </td>
                      <td className="py-2.5 pr-4">
                        <span className="text-sm text-zinc-400">
                          {event.reason ?? '-'}
                        </span>
                      </td>
                      <td className="py-2.5 pr-4 text-right">
                        <span className="text-sm text-zinc-300 tabular-nums">
                          {event.concurrent_connections != null
                            ? formatNumber(event.concurrent_connections)
                            : '-'}
                        </span>
                      </td>
                      <td className="py-2.5 text-right">
                        <span className="text-sm text-zinc-300 tabular-nums">
                          {event.connection_rate != null
                            ? `${formatNumber(event.connection_rate)}/s`
                            : '-'}
                        </span>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
}
