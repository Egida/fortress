'use client';

import { useEffect, useState, useCallback, useRef } from 'react';
import { fortressGet } from '@/lib/api';
import { formatNumber } from '@/lib/constants';
import {
  Activity,
  Radio,
  ShieldCheck,
  Zap,
  Gauge,
  Globe,
  MonitorDot,
  Hash,
} from 'lucide-react';
import { CountryFlag } from '@/components/country-flag';

/* -------------------------------------------------------------------------- */
/*  Types                                                                     */
/* -------------------------------------------------------------------------- */

interface Metrics {
  rps: number;
  blocked_per_sec: number;
  unique_ips: number;
  avg_latency_ms: number;
}

interface TopIp {
  ip: string;
  count: number;
  country?: string;
  threat_score?: number;
}

interface TopCountry {
  country: string;
  count: number;
}

interface TopIpsResponse {
  top_ips: TopIp[];
}

interface TopCountriesResponse {
  top_countries: TopCountry[];
}

/* -------------------------------------------------------------------------- */
/*  Helpers                                                                   */
/* -------------------------------------------------------------------------- */

/** Return a colour class based on threat score (0-100). */
function threatColor(score: number | undefined): string {
  if (score === undefined || score === null) return 'text-zinc-600';
  if (score >= 80) return 'text-red-400';
  if (score >= 50) return 'text-orange-400';
  if (score >= 25) return 'text-yellow-400';
  return 'text-green-400';
}

/* -------------------------------------------------------------------------- */
/*  Component                                                                 */
/* -------------------------------------------------------------------------- */

export default function LiveTrafficPage() {
  /* ---- state ---- */
  const [metrics, setMetrics] = useState<Metrics | null>(null);
  const [topIps, setTopIps] = useState<TopIp[]>([]);
  const [topCountries, setTopCountries] = useState<TopCountry[]>([]);
  const [metricsError, setMetricsError] = useState<string | null>(null);
  const [ipsError, setIpsError] = useState<string | null>(null);
  const [countriesError, setCountriesError] = useState<string | null>(null);

  /* refs so we can clear intervals on unmount */
  const metricsInterval = useRef<ReturnType<typeof setInterval> | null>(null);
  const ipsInterval = useRef<ReturnType<typeof setInterval> | null>(null);
  const countriesInterval = useRef<ReturnType<typeof setInterval> | null>(null);

  /* ---- data fetchers ---- */

  const fetchMetrics = useCallback(async () => {
    try {
      const data = await fortressGet<Metrics>('/api/fortress/metrics');
      setMetrics(data);
      setMetricsError(null);
    } catch {
      setMetricsError('Failed to load traffic metrics');
    }
  }, []);

  const fetchTopIps = useCallback(async () => {
    try {
      const data = await fortressGet<TopIpsResponse>('/api/fortress/top-ips?limit=30');
      setTopIps(data.top_ips ?? []);
      setIpsError(null);
    } catch {
      setIpsError('Failed to load endpoint data');
    }
  }, []);

  const fetchTopCountries = useCallback(async () => {
    try {
      const data = await fortressGet<TopCountriesResponse>('/api/fortress/top-countries');
      setTopCountries(data.top_countries ?? []);
      setCountriesError(null);
    } catch {
      setCountriesError('Failed to load geographic data');
    }
  }, []);

  /* ---- polling setup ---- */

  useEffect(() => {
    /* initial fetches */
    fetchMetrics();
    fetchTopIps();
    fetchTopCountries();

    /* metrics + top-ips: every 2 s */
    metricsInterval.current = setInterval(fetchMetrics, 2000);
    ipsInterval.current = setInterval(fetchTopIps, 2000);

    /* top-countries: every 4 s */
    countriesInterval.current = setInterval(fetchTopCountries, 4000);

    return () => {
      if (metricsInterval.current) clearInterval(metricsInterval.current);
      if (ipsInterval.current) clearInterval(ipsInterval.current);
      if (countriesInterval.current) clearInterval(countriesInterval.current);
    };
  }, [fetchMetrics, fetchTopIps, fetchTopCountries]);

  /* ---- stat cards config ---- */

  const statCards: {
    label: string;
    value: string;
    icon: React.ReactNode;
    accent: string;
  }[] = metrics
    ? [
        {
          label: 'Request Throughput',
          value: `${formatNumber(metrics.rps)} req/s`,
          icon: <Zap className="h-4 w-4" />,
          accent: 'text-blue-400',
        },
        {
          label: 'Active Sessions',
          value: formatNumber(metrics.unique_ips),
          icon: <MonitorDot className="h-4 w-4" />,
          accent: 'text-emerald-400',
        },
        {
          label: 'Interception Rate',
          value: `${formatNumber(metrics.blocked_per_sec)}/s`,
          icon: <ShieldCheck className="h-4 w-4" />,
          accent: 'text-orange-400',
        },
        {
          label: 'PoW Challenges',
          value: `${metrics.avg_latency_ms.toFixed(1)} ms avg`,
          icon: <Gauge className="h-4 w-4" />,
          accent: 'text-purple-400',
        },
      ]
    : [];

  /* ---- render ---- */

  return (
    <div className="min-h-screen bg-black text-zinc-100">
      <div className="mx-auto max-w-7xl px-4 py-8 sm:px-6 lg:px-8">
        {/* ---- Header ---- */}
        <div className="mb-8">
          <div className="flex items-center gap-3">
            <Activity className="h-6 w-6 text-blue-400" />
            <h1 className="text-2xl font-bold tracking-tight text-white">
              Traffic Intelligence
            </h1>
            <span className="relative flex h-2.5 w-2.5 ml-1">
              <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-green-400 opacity-75" />
              <span className="relative inline-flex h-2.5 w-2.5 rounded-full bg-green-500" />
            </span>
            <span className="rounded-md bg-green-500/10 px-2 py-0.5 text-xs font-medium text-green-400 border border-green-500/20">
              LIVE
            </span>
          </div>
          <p className="mt-1 text-sm text-zinc-500 ml-9">
            Real-time network traffic analysis
          </p>
        </div>

        {/* ---- Stat cards ---- */}
        {metricsError && (
          <div className="mb-4 flex items-center gap-2 rounded-lg border border-red-500/20 bg-red-500/5 px-4 py-2 text-sm text-red-400">
            <Radio className="h-4 w-4 shrink-0" />
            {metricsError}
          </div>
        )}

        <div className="mb-8 grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
          {metrics ? (
            statCards.map((card) => (
              <div
                key={card.label}
                className="rounded-xl border border-zinc-800 bg-zinc-900/80 p-5 transition-colors hover:border-zinc-700"
              >
                <div className="flex items-center justify-between">
                  <p className="text-xs font-medium uppercase tracking-wider text-zinc-500">
                    {card.label}
                  </p>
                  <span className={card.accent}>{card.icon}</span>
                </div>
                <p className="mt-3 text-2xl font-semibold text-white tabular-nums">
                  {card.value}
                </p>
              </div>
            ))
          ) : (
            /* skeleton placeholders while loading */
            Array.from({ length: 4 }).map((_, i) => (
              <div
                key={i}
                className="animate-pulse rounded-xl border border-zinc-800 bg-zinc-900 p-5"
              >
                <div className="flex items-center justify-between">
                  <div className="h-3 w-28 rounded bg-zinc-800" />
                  <div className="h-4 w-4 rounded bg-zinc-800" />
                </div>
                <div className="mt-4 h-7 w-24 rounded bg-zinc-800" />
              </div>
            ))
          )}
        </div>

        {/* ---- Two-column layout ---- */}
        <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
          {/* ---- Active Endpoint Analysis ---- */}
          <div className="rounded-xl border border-zinc-800 bg-zinc-900/80 p-5">
            <div className="mb-4 flex items-center gap-2">
              <Hash className="h-4 w-4 text-blue-400" />
              <h2 className="text-lg font-semibold text-white">
                Active Endpoint Analysis
              </h2>
              {topIps.length > 0 && (
                <span className="ml-auto rounded-full bg-zinc-800 px-2.5 py-0.5 text-xs font-medium tabular-nums text-zinc-400">
                  {topIps.length}
                </span>
              )}
            </div>

            {ipsError && (
              <div className="mb-3 flex items-center gap-2 rounded-lg border border-red-500/20 bg-red-500/5 px-3 py-2 text-sm text-red-400">
                <Radio className="h-3.5 w-3.5 shrink-0" />
                {ipsError}
              </div>
            )}

            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-zinc-800 text-left text-zinc-500">
                    <th className="pb-2 pr-4 font-medium">#</th>
                    <th className="pb-2 pr-4 font-medium">Endpoint IP</th>
                    <th className="pb-2 pr-4 font-medium text-center">Threat</th>
                    <th className="pb-2 text-right font-medium">Requests</th>
                  </tr>
                </thead>
                <tbody>
                  {topIps.length === 0 && !ipsError && (
                    <tr>
                      <td
                        colSpan={4}
                        className="py-8 text-center text-zinc-600"
                      >
                        <div className="flex flex-col items-center gap-1">
                          <MonitorDot className="h-5 w-5 text-zinc-700" />
                          <span>Awaiting endpoint data...</span>
                        </div>
                      </td>
                    </tr>
                  )}
                  {topIps.map((entry, idx) => (
                    <tr
                      key={entry.ip}
                      className="border-b border-zinc-800/50 transition-colors hover:bg-zinc-800/30"
                    >
                      <td className="py-2 pr-4 text-zinc-600 tabular-nums">
                        {idx + 1}
                      </td>
                      <td className="py-2 pr-4 font-mono text-zinc-300">
                        {entry.country && (
                          <span className="mr-1.5 inline-flex items-center">
                            <CountryFlag code={entry.country} size={16} />
                          </span>
                        )}
                        {entry.ip}
                        {entry.country && (
                          <span className="ml-1.5 text-xs text-zinc-600">
                            {entry.country}
                          </span>
                        )}
                      </td>
                      <td className="py-2 pr-4 text-center">
                        {entry.threat_score !== undefined && entry.threat_score !== null ? (
                          <span
                            className={`inline-block rounded-full px-2 py-0.5 text-xs font-medium tabular-nums ${threatColor(entry.threat_score)} bg-zinc-800`}
                          >
                            {entry.threat_score}
                          </span>
                        ) : (
                          <span className="text-zinc-700">--</span>
                        )}
                      </td>
                      <td className="py-2 text-right tabular-nums text-zinc-300">
                        {formatNumber(entry.count)}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {/* ---- Geographic Traffic Distribution ---- */}
          <div className="rounded-xl border border-zinc-800 bg-zinc-900/80 p-5">
            <div className="mb-4 flex items-center gap-2">
              <Globe className="h-4 w-4 text-emerald-400" />
              <h2 className="text-lg font-semibold text-white">
                Geographic Traffic Distribution
              </h2>
              {topCountries.length > 0 && (
                <span className="ml-auto rounded-full bg-zinc-800 px-2.5 py-0.5 text-xs font-medium tabular-nums text-zinc-400">
                  {topCountries.length}
                </span>
              )}
            </div>

            {countriesError && (
              <div className="mb-3 flex items-center gap-2 rounded-lg border border-red-500/20 bg-red-500/5 px-3 py-2 text-sm text-red-400">
                <Radio className="h-3.5 w-3.5 shrink-0" />
                {countriesError}
              </div>
            )}

            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-zinc-800 text-left text-zinc-500">
                    <th className="pb-2 pr-4 font-medium">#</th>
                    <th className="pb-2 pr-4 font-medium">Country</th>
                    <th className="pb-2 text-right font-medium">Requests</th>
                    <th className="pb-2 text-right font-medium">Share</th>
                  </tr>
                </thead>
                <tbody>
                  {topCountries.length === 0 && !countriesError && (
                    <tr>
                      <td
                        colSpan={4}
                        className="py-8 text-center text-zinc-600"
                      >
                        <div className="flex flex-col items-center gap-1">
                          <Globe className="h-5 w-5 text-zinc-700" />
                          <span>Awaiting geographic data...</span>
                        </div>
                      </td>
                    </tr>
                  )}
                  {(() => {
                    const total = topCountries.reduce((s, c) => s + c.count, 0);
                    return topCountries.map((entry, idx) => {
                      const pct = total > 0 ? ((entry.count / total) * 100).toFixed(1) : '0.0';
                      return (
                        <tr
                          key={entry.country}
                          className="border-b border-zinc-800/50 transition-colors hover:bg-zinc-800/30"
                        >
                          <td className="py-2 pr-4 text-zinc-600 tabular-nums">
                            {idx + 1}
                          </td>
                          <td className="py-2 pr-4 text-zinc-300">
                            <span className="mr-1.5 inline-flex items-center align-middle">
                              <CountryFlag code={entry.country} size={16} />
                            </span>
                            {entry.country}
                          </td>
                          <td className="py-2 text-right tabular-nums text-zinc-300">
                            {formatNumber(entry.count)}
                          </td>
                          <td className="py-2 text-right tabular-nums text-zinc-500">
                            {pct}%
                          </td>
                        </tr>
                      );
                    });
                  })()}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
