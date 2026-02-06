'use client';

import { Fragment, useEffect, useState, useCallback } from 'react';
import { fortressGet } from '@/lib/api';
import { formatNumber } from '@/lib/constants';
import type { Attack } from '@/lib/types';
import {
  Crosshair,
  RefreshCw,
  ShieldAlert,
  ChevronDown,
  Clock,
  Zap,
  ShieldOff,
  Fingerprint,
  Globe,
  Server,
  ShieldCheck,
} from 'lucide-react';
import { CountryFlag } from '@/components/country-flag';

/* -------------------------------------------------------------------------- */
/*  Helpers                                                                   */
/* -------------------------------------------------------------------------- */

interface ThreatsResponse {
  threats: Attack[];
}

/** Map raw severity to a professional technical label. */
const SEVERITY_MAP: Record<string, { label: string; cls: string }> = {
  low: { label: 'Advisory', cls: 'bg-green-500/10 text-green-400 border-green-500/20' },
  medium: { label: 'Elevated', cls: 'bg-yellow-500/10 text-yellow-400 border-yellow-500/20' },
  high: { label: 'Critical', cls: 'bg-orange-500/10 text-orange-400 border-orange-500/20' },
  critical: { label: 'Severe', cls: 'bg-red-500/10 text-red-400 border-red-500/20' },
};

function severityBadge(severity: string) {
  const entry =
    SEVERITY_MAP[severity.toLowerCase()] ?? {
      label: severity,
      cls: 'bg-zinc-700 text-zinc-300 border-zinc-600',
    };
  return (
    <span
      className={`inline-block rounded-md border px-2 py-0.5 text-xs font-semibold uppercase tracking-wide ${entry.cls}`}
    >
      {entry.label}
    </span>
  );
}

/** Classify attack type based on heuristics. */
function classifyAttack(attack: Attack): string {
  if (attack.unique_ips > 500) return 'Distributed Botnet';
  if (attack.peak_rps > 10000) return 'L7 HTTP Flood';
  if (attack.unique_ips > 100) return 'Coordinated L7 Attack';
  if (attack.peak_rps > 1000) return 'Volumetric HTTP Flood';
  return 'L7 HTTP Flood';
}

/** Compute duration string from start/end ISO dates. */
function attackDuration(start: string | null, end: string | null): string {
  if (!start) return '\u2014';
  if (!end) return 'Ongoing';
  try {
    const ms = new Date(end).getTime() - new Date(start).getTime();
    if (ms < 0) return '\u2014';
    const totalSecs = Math.floor(ms / 1000);
    const h = Math.floor(totalSecs / 3600);
    const m = Math.floor((totalSecs % 3600) / 60);
    const s = totalSecs % 60;
    if (h > 0) return `${h}h ${m}m ${s}s`;
    if (m > 0) return `${m}m ${s}s`;
    return `${s}s`;
  } catch {
    return '\u2014';
  }
}

function formatDate(iso: string | null): string {
  if (!iso) return '\u2014';
  try {
    const d = new Date(iso);
    return d.toLocaleString('en-US', {
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      hour12: false,
    });
  } catch {
    return iso;
  }
}

function parseJsonField(
  raw: string | null,
): { label: string; value: number }[] {
  if (!raw) return [];
  try {
    const parsed = JSON.parse(raw);
    if (Array.isArray(parsed)) {
      return parsed
        .map((item) => {
          // Handle tuple arrays from Rust: ["US", 100] or ["1.2.3.4", 500]
          if (Array.isArray(item) && item.length >= 2) {
            return { label: String(item[0]), value: Number(item[1]) };
          }
          // Handle object arrays: {country: "US", count: 100}
          if (typeof item === 'object' && item !== null) {
            return {
              label:
                item.country ??
                item.ip ??
                String(item.key ?? item.label ?? ''),
              value: Number(item.count ?? item.value ?? item.requests ?? 0),
            };
          }
          return { label: String(item), value: 0 };
        })
        .filter((e) => e.label && e.value > 0);
    }
    if (typeof parsed === 'object' && parsed !== null) {
      return Object.entries(parsed).map(([key, val]) => ({
        label: key,
        value: Number(val),
      }));
    }
    return [];
  } catch {
    return [];
  }
}

/* -------------------------------------------------------------------------- */
/*  Component                                                                 */
/* -------------------------------------------------------------------------- */

export default function AttacksPage() {
  const [attacks, setAttacks] = useState<Attack[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [expandedId, setExpandedId] = useState<number | null>(null);

  const fetchAttacks = useCallback(async () => {
    try {
      const data = await fortressGet<ThreatsResponse>(
        '/api/fortress/threats',
      );
      setAttacks(data.threats ?? []);
      setError(null);
    } catch {
      setError('Failed to retrieve attack vector data');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchAttacks();
  }, [fetchAttacks]);

  const toggleExpand = (id: number) => {
    setExpandedId((prev) => (prev === id ? null : id));
  };

  /* ---- render ---- */

  return (
    <div className="min-h-screen bg-black text-zinc-100">
      <div className="mx-auto max-w-7xl px-4 py-8 sm:px-6 lg:px-8">
        {/* ---- Header ---- */}
        <div className="mb-8 flex items-center justify-between">
          <div>
            <div className="flex items-center gap-3">
              <Crosshair className="h-6 w-6 text-red-400" />
              <h1 className="text-2xl font-bold tracking-tight text-white">
                Attack Vector Analysis
              </h1>
            </div>
            <p className="mt-1 text-sm text-zinc-500 ml-9">
              Historical attack pattern recognition and forensics
            </p>
          </div>
          <button
            onClick={() => {
              setLoading(true);
              fetchAttacks();
            }}
            className="flex items-center gap-2 rounded-lg border border-zinc-700 bg-zinc-800 px-4 py-2 text-sm font-medium text-zinc-300 transition-colors hover:bg-zinc-700 hover:text-white"
          >
            <RefreshCw className="h-3.5 w-3.5" />
            Refresh
          </button>
        </div>

        {/* ---- Error ---- */}
        {error && (
          <div className="mb-6 flex items-center gap-2 rounded-xl border border-red-500/20 bg-red-500/5 p-4 text-sm text-red-400">
            <ShieldAlert className="h-4 w-4 shrink-0" />
            {error}
          </div>
        )}

        {/* ---- Table card ---- */}
        <div className="rounded-xl border border-zinc-800 bg-zinc-900/80 p-5">
          {loading ? (
            /* skeleton rows */
            <div className="space-y-3">
              {Array.from({ length: 5 }).map((_, i) => (
                <div
                  key={i}
                  className="h-12 animate-pulse rounded-lg bg-zinc-800"
                />
              ))}
            </div>
          ) : attacks.length === 0 ? (
            /* empty state */
            <div className="flex flex-col items-center justify-center py-20 text-zinc-600">
              <ShieldCheck className="mb-4 h-14 w-14 text-zinc-700" />
              <p className="text-lg font-medium text-zinc-400">
                No attack vectors detected in monitoring window
              </p>
              <p className="mt-1 text-sm text-zinc-600">
                Detected threats and attack patterns will appear here.
              </p>
            </div>
          ) : (
            /* data table */
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-zinc-800 text-left text-zinc-500">
                    <th className="pb-3 pr-4 font-medium">ID</th>
                    <th className="pb-3 pr-4 font-medium">Vector Type</th>
                    <th className="pb-3 pr-4 font-medium">Started</th>
                    <th className="pb-3 pr-4 font-medium">Attack Duration</th>
                    <th className="pb-3 pr-4 text-right font-medium">
                      Peak Request Rate
                    </th>
                    <th className="pb-3 pr-4 text-right font-medium">
                      Threats Neutralized
                    </th>
                    <th className="pb-3 pr-4 text-right font-medium">
                      Unique Source IPs
                    </th>
                    <th className="pb-3 font-medium">Severity</th>
                    <th className="pb-3 font-medium" />
                  </tr>
                </thead>
                <tbody>
                  {attacks.map((attack) => {
                    const isExpanded = expandedId === attack.id;
                    const topCountries = parseJsonField(
                      attack.top_countries_json,
                    );
                    const topIps = parseJsonField(attack.top_ips_json);
                    const hasDetails = true;

                    return (
                      <Fragment key={attack.id}>
                        {/* ---- Main data row ---- */}
                        <tr
                          className={`border-b border-zinc-800/50 transition-colors hover:bg-zinc-800/30 ${
                            hasDetails ? 'cursor-pointer' : ''
                          }`}
                          onClick={() =>
                            hasDetails && toggleExpand(attack.id)
                          }
                        >
                          <td className="py-3 pr-4 font-mono text-zinc-500">
                            #{attack.id}
                          </td>
                          <td className="py-3 pr-4">
                            <span className="inline-flex items-center gap-1.5 rounded-md bg-zinc-800 border border-zinc-700 px-2 py-0.5 text-xs font-medium text-zinc-300">
                              <Zap className="h-3 w-3 text-yellow-400" />
                              {classifyAttack(attack)}
                            </span>
                          </td>
                          <td className="py-3 pr-4 text-zinc-300 tabular-nums">
                            {formatDate(attack.started_at)}
                          </td>
                          <td className="py-3 pr-4">
                            {attack.ended_at ? (
                              <span className="inline-flex items-center gap-1 text-zinc-300">
                                <Clock className="h-3 w-3 text-zinc-500" />
                                {attackDuration(attack.started_at, attack.ended_at)}
                              </span>
                            ) : (
                              <span className="inline-flex items-center gap-1 rounded-md bg-red-500/10 border border-red-500/20 px-2 py-0.5 text-xs font-medium text-red-400">
                                <span className="relative flex h-1.5 w-1.5">
                                  <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-red-400 opacity-75" />
                                  <span className="relative inline-flex h-1.5 w-1.5 rounded-full bg-red-500" />
                                </span>
                                Active
                              </span>
                            )}
                          </td>
                          <td className="py-3 pr-4 text-right tabular-nums text-zinc-300">
                            {formatNumber(attack.peak_rps)} req/s
                          </td>
                          <td className="py-3 pr-4 text-right tabular-nums text-zinc-300">
                            {formatNumber(attack.total_requests)}
                          </td>
                          <td className="py-3 pr-4 text-right tabular-nums text-zinc-300">
                            {formatNumber(attack.unique_ips)}
                          </td>
                          <td className="py-3 pr-4">
                            {severityBadge(attack.severity)}
                          </td>
                          <td className="py-3 pl-2 text-zinc-600">
                            {hasDetails && (
                              <ChevronDown
                                className={`h-4 w-4 transition-transform ${
                                  isExpanded ? 'rotate-180' : ''
                                }`}
                              />
                            )}
                          </td>
                        </tr>

                        {/* ---- Expanded detail row ---- */}
                        {isExpanded && hasDetails && (
                          <tr className="border-b border-zinc-800/50 bg-zinc-950/60">
                            <td colSpan={9} className="px-4 py-5">
                              {/* Attack summary stats */}
                              <div className="mb-5 grid grid-cols-2 gap-3 sm:grid-cols-4">
                                <div className="rounded-lg border border-zinc-800 bg-zinc-900 p-3">
                                  <div className="flex items-center gap-1.5 text-xs text-zinc-500 mb-1">
                                    <Clock className="h-3 w-3" />
                                    Attack Duration
                                  </div>
                                  <p className="text-sm font-medium text-zinc-200 tabular-nums">
                                    {attackDuration(attack.started_at, attack.ended_at)}
                                  </p>
                                </div>
                                <div className="rounded-lg border border-zinc-800 bg-zinc-900 p-3">
                                  <div className="flex items-center gap-1.5 text-xs text-zinc-500 mb-1">
                                    <Zap className="h-3 w-3" />
                                    Peak Request Rate
                                  </div>
                                  <p className="text-sm font-medium text-zinc-200 tabular-nums">
                                    {formatNumber(attack.peak_rps)} req/s
                                  </p>
                                </div>
                                <div className="rounded-lg border border-zinc-800 bg-zinc-900 p-3">
                                  <div className="flex items-center gap-1.5 text-xs text-zinc-500 mb-1">
                                    <ShieldOff className="h-3 w-3" />
                                    Threats Neutralized
                                  </div>
                                  <p className="text-sm font-medium text-zinc-200 tabular-nums">
                                    {formatNumber(attack.total_requests)}
                                  </p>
                                </div>
                                <div className="rounded-lg border border-zinc-800 bg-zinc-900 p-3">
                                  <div className="flex items-center gap-1.5 text-xs text-zinc-500 mb-1">
                                    <Fingerprint className="h-3 w-3" />
                                    Unique Source IPs
                                  </div>
                                  <p className="text-sm font-medium text-zinc-200 tabular-nums">
                                    {formatNumber(attack.unique_ips)}
                                  </p>
                                </div>
                              </div>

                              <div className="grid grid-cols-1 gap-6 md:grid-cols-2">
                                {/* Top Attack Sources */}
                                <div>
                                  <div className="mb-3 flex items-center gap-2">
                                    <Server className="h-3.5 w-3.5 text-blue-400" />
                                    <h4 className="text-xs font-semibold uppercase tracking-wider text-zinc-500">
                                      Top Attack Sources
                                    </h4>
                                  </div>
                                  {topIps.length > 0 ? (
                                    <div className="space-y-1">
                                      {topIps.map((entry, idx) => (
                                        <div
                                          key={idx}
                                          className="flex items-center justify-between rounded-md px-2.5 py-1.5 text-sm hover:bg-zinc-800/40 transition-colors"
                                        >
                                          <span className="flex items-center gap-2">
                                            <span className="text-xs text-zinc-600 tabular-nums w-4">
                                              {idx + 1}
                                            </span>
                                            <span className="font-mono text-zinc-300">
                                              {entry.label}
                                            </span>
                                          </span>
                                          <span className="tabular-nums text-zinc-500">
                                            {formatNumber(entry.value)}
                                          </span>
                                        </div>
                                      ))}
                                    </div>
                                  ) : (
                                    <p className="text-xs text-zinc-600 px-2.5 py-4">
                                      IP source data not available for this attack
                                    </p>
                                  )}
                                </div>

                                {/* Geographic Origin */}
                                <div>
                                  <div className="mb-3 flex items-center gap-2">
                                    <Globe className="h-3.5 w-3.5 text-emerald-400" />
                                    <h4 className="text-xs font-semibold uppercase tracking-wider text-zinc-500">
                                      Geographic Origin
                                    </h4>
                                  </div>
                                  {topCountries.length > 0 ? (
                                    <div className="space-y-1">
                                      {topCountries.map((entry, idx) => (
                                        <div
                                          key={idx}
                                          className="flex items-center justify-between rounded-md px-2.5 py-1.5 text-sm hover:bg-zinc-800/40 transition-colors"
                                        >
                                          <span className="flex items-center gap-2">
                                            <span className="text-xs text-zinc-600 tabular-nums w-4">
                                              {idx + 1}
                                            </span>
                                            <span className="text-zinc-300 inline-flex items-center gap-1">
                                              <CountryFlag code={entry.label} size={16} />
                                              {entry.label}
                                            </span>
                                          </span>
                                          <span className="tabular-nums text-zinc-500">
                                            {formatNumber(entry.value)}
                                          </span>
                                        </div>
                                      ))}
                                    </div>
                                  ) : (
                                    <p className="text-xs text-zinc-600 px-2.5 py-4">
                                      Geographic data not available for this attack
                                    </p>
                                  )}
                                </div>
                              </div>
                            </td>
                          </tr>
                        )}
                      </Fragment>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
