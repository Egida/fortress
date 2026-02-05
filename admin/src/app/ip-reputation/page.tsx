"use client";

import { Fragment, useState, useEffect, useCallback, useMemo } from "react";
import { fetchApi, fortressPost } from "@/lib/api";
import { formatNumber } from "@/lib/constants";
import {
  RefreshCw,
  Search,
  ShieldAlert,
  ShieldCheck,
  ShieldX,
  Activity,
  ChevronDown,
  Ban,
  Globe,
  Fingerprint,
} from "lucide-react";
import { CountryFlag } from "@/components/country-flag";

/* -------------------------------------------------------------------------- */
/*  Types                                                                     */
/* -------------------------------------------------------------------------- */

interface IpEntry {
  ip: string;
  score: number;
  total_requests: number;
  blocked_count: number;
  categories: string[];
  country?: string | null;
  city?: string | null;
  asn?: number | null;
  asn_org?: string | null;
}

interface ReputationResponse {
  ips: IpEntry[];
  tracked_count: number;
}

type SortField = "score" | "total_requests" | "blocked_count" | "block_rate";
type SortDir = "asc" | "desc";

/* -------------------------------------------------------------------------- */
/*  Category badge colors                                                     */
/* -------------------------------------------------------------------------- */

const CATEGORY_STYLES: Record<string, string> = {
  TorExit: "bg-purple-500/15 text-purple-400 border-purple-500/20",
  Scanner: "bg-red-500/15 text-red-400 border-red-500/20",
  BruteForce: "bg-orange-500/15 text-orange-400 border-orange-500/20",
  DDoS: "bg-red-500/15 text-red-400 border-red-500/20",
  KnownProxy: "bg-blue-500/15 text-blue-400 border-blue-500/20",
};

function categoryBadge(cat: string) {
  const cls =
    CATEGORY_STYLES[cat] ?? "bg-zinc-700/40 text-zinc-400 border-zinc-600/30";
  return (
    <span
      key={cat}
      className={`inline-flex items-center rounded-full border px-2 py-0.5 text-xs font-medium ${cls}`}
    >
      {cat}
    </span>
  );
}

/* -------------------------------------------------------------------------- */
/*  Helpers                                                                   */
/* -------------------------------------------------------------------------- */

function scoreColor(score: number) {
  if (score >= 80) return { text: "text-red-400", bar: "bg-red-500", ring: "ring-red-500/20" };
  if (score >= 50) return { text: "text-yellow-400", bar: "bg-yellow-500", ring: "ring-yellow-500/20" };
  return { text: "text-green-400", bar: "bg-green-500", ring: "ring-green-500/20" };
}

function blockRate(entry: IpEntry): number {
  if (entry.total_requests === 0) return 0;
  return (entry.blocked_count / entry.total_requests) * 100;
}

/* -------------------------------------------------------------------------- */
/*  Skeleton row                                                              */
/* -------------------------------------------------------------------------- */

function SkeletonRow() {
  return (
    <tr className="border-b border-zinc-800/50">
      <td className="px-4 py-3"><div className="h-4 w-28 animate-pulse rounded bg-zinc-800" /></td>
      <td className="px-4 py-3"><div className="h-4 w-24 animate-pulse rounded bg-zinc-800" /></td>
      <td className="px-4 py-3"><div className="h-4 w-14 animate-pulse rounded bg-zinc-800" /></td>
      <td className="px-4 py-3"><div className="h-4 w-14 animate-pulse rounded bg-zinc-800" /></td>
      <td className="px-4 py-3"><div className="h-4 w-12 animate-pulse rounded bg-zinc-800" /></td>
      <td className="px-4 py-3"><div className="flex gap-1"><div className="h-5 w-16 animate-pulse rounded-full bg-zinc-800" /><div className="h-5 w-14 animate-pulse rounded-full bg-zinc-800" /></div></td>
      <td className="px-4 py-3"><div className="h-7 w-16 animate-pulse rounded bg-zinc-800" /></td>
    </tr>
  );
}

/* -------------------------------------------------------------------------- */
/*  Component                                                                 */
/* -------------------------------------------------------------------------- */

export default function IpReputationPage() {
  const [data, setData] = useState<ReputationResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [search, setSearch] = useState("");
  const [sortField, setSortField] = useState<SortField>("score");
  const [sortDir, setSortDir] = useState<SortDir>("desc");
  const [expandedIp, setExpandedIp] = useState<string | null>(null);
  const [banningIp, setBanningIp] = useState<string | null>(null);

  /* ---- Data fetching ---- */

  const loadData = useCallback(async (isRefresh = false) => {
    if (isRefresh) setRefreshing(true);
    try {
      const res = await fetchApi<ReputationResponse>(
        "/api/fortress/ip-reputation?limit=100",
      );
      setData(res);
    } catch (e) {
      console.error("Failed to load IP reputation data:", e);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, []);

  useEffect(() => {
    loadData();
    const interval = setInterval(() => loadData(), 10_000);
    return () => clearInterval(interval);
  }, [loadData]);

  /* ---- Ban action ---- */

  const handleBan = useCallback(
    async (ip: string) => {
      setBanningIp(ip);
      try {
        await fortressPost("/api/fortress/blocklist", {
          value: ip,
          type: "ip",
          reason: "IP reputation ban",
        });
        await loadData(true);
      } catch (e) {
        console.error("Failed to ban IP:", e);
      } finally {
        setBanningIp(null);
      }
    },
    [loadData],
  );

  /* ---- Computed data ---- */

  const ips = data?.ips ?? [];

  const stats = useMemo(() => {
    const total = ips.length;
    const high = ips.filter((e) => e.score >= 80).length;
    const medium = ips.filter((e) => e.score >= 50 && e.score < 80).length;
    const clean = ips.filter((e) => e.score < 50).length;
    return { total, high, medium, clean };
  }, [ips]);

  const filtered = useMemo(() => {
    let list = [...ips];

    if (search.trim()) {
      const q = search.trim().toLowerCase();
      list = list.filter((e) => e.ip.toLowerCase().includes(q));
    }

    list.sort((a, b) => {
      let av: number, bv: number;
      switch (sortField) {
        case "score":
          av = a.score;
          bv = b.score;
          break;
        case "total_requests":
          av = a.total_requests;
          bv = b.total_requests;
          break;
        case "blocked_count":
          av = a.blocked_count;
          bv = b.blocked_count;
          break;
        case "block_rate":
          av = blockRate(a);
          bv = blockRate(b);
          break;
        default:
          av = a.score;
          bv = b.score;
      }
      return sortDir === "desc" ? bv - av : av - bv;
    });

    return list;
  }, [ips, search, sortField, sortDir]);

  /* ---- Sort handler ---- */

  const handleSort = (field: SortField) => {
    if (sortField === field) {
      setSortDir((d) => (d === "desc" ? "asc" : "desc"));
    } else {
      setSortField(field);
      setSortDir("desc");
    }
  };

  const sortIndicator = (field: SortField) => {
    if (sortField !== field) return null;
    return (
      <ChevronDown
        className={`ml-1 inline h-3 w-3 transition-transform ${
          sortDir === "asc" ? "rotate-180" : ""
        }`}
      />
    );
  };

  /* ---- Render ---- */

  return (
    <div className="min-h-screen bg-black text-zinc-100">
      <div className="mx-auto max-w-7xl px-4 py-8 sm:px-6 lg:px-8">
        {/* ---------------------------------------------------------------- */}
        {/*  Header                                                          */}
        {/* ---------------------------------------------------------------- */}
        <div className="mb-8 flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <div className="flex items-center gap-3">
              <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-orange-500/10 ring-1 ring-orange-500/20">
                <Fingerprint className="h-5 w-5 text-orange-400" />
              </div>
              <div>
                <h1 className="text-2xl font-bold tracking-tight text-white">
                  IP Reputation Matrix
                </h1>
                <p className="text-sm text-zinc-500">
                  Endpoint threat scoring and behavioral profiling
                </p>
              </div>
            </div>
            {data && (
              <div className="mt-3 flex items-center gap-2">
                <span className="inline-flex items-center gap-1.5 rounded-full bg-zinc-800 px-3 py-1 text-xs font-medium text-zinc-300 ring-1 ring-zinc-700">
                  <Globe className="h-3 w-3 text-zinc-500" />
                  {formatNumber(data.tracked_count)} endpoints tracked
                </span>
              </div>
            )}
          </div>
          <button
            onClick={() => loadData(true)}
            disabled={refreshing}
            className="inline-flex items-center gap-2 rounded-lg border border-zinc-700 bg-zinc-900 px-4 py-2 text-sm font-medium text-zinc-300 transition-colors hover:bg-zinc-800 hover:text-white disabled:opacity-50"
          >
            <RefreshCw
              className={`h-4 w-4 ${refreshing ? "animate-spin" : ""}`}
            />
            Refresh
          </button>
        </div>

        {/* ---------------------------------------------------------------- */}
        {/*  Stat Cards                                                      */}
        {/* ---------------------------------------------------------------- */}
        <div className="mb-6 grid grid-cols-2 gap-4 lg:grid-cols-4">
          <div className="rounded-xl border border-zinc-800 bg-zinc-900 p-4">
            <div className="flex items-center gap-3">
              <div className="rounded-lg bg-zinc-800 p-2">
                <Activity className="h-5 w-5 text-zinc-400" />
              </div>
              <div>
                <p className="text-xs font-medium uppercase tracking-wider text-zinc-500">
                  Total Tracked
                </p>
                <p className="text-2xl font-bold tabular-nums text-white">
                  {loading ? "--" : formatNumber(stats.total)}
                </p>
              </div>
            </div>
          </div>

          <div className="rounded-xl border border-red-500/10 bg-zinc-900 p-4">
            <div className="flex items-center gap-3">
              <div className="rounded-lg bg-red-500/10 p-2">
                <ShieldX className="h-5 w-5 text-red-400" />
              </div>
              <div>
                <p className="text-xs font-medium uppercase tracking-wider text-zinc-500">
                  Critical Threat
                </p>
                <p className="text-2xl font-bold tabular-nums text-red-400">
                  {loading ? "--" : stats.high}
                </p>
              </div>
            </div>
          </div>

          <div className="rounded-xl border border-yellow-500/10 bg-zinc-900 p-4">
            <div className="flex items-center gap-3">
              <div className="rounded-lg bg-yellow-500/10 p-2">
                <ShieldAlert className="h-5 w-5 text-yellow-400" />
              </div>
              <div>
                <p className="text-xs font-medium uppercase tracking-wider text-zinc-500">
                  Elevated Risk
                </p>
                <p className="text-2xl font-bold tabular-nums text-yellow-400">
                  {loading ? "--" : stats.medium}
                </p>
              </div>
            </div>
          </div>

          <div className="rounded-xl border border-green-500/10 bg-zinc-900 p-4">
            <div className="flex items-center gap-3">
              <div className="rounded-lg bg-green-500/10 p-2">
                <ShieldCheck className="h-5 w-5 text-green-400" />
              </div>
              <div>
                <p className="text-xs font-medium uppercase tracking-wider text-zinc-500">
                  Nominal
                </p>
                <p className="text-2xl font-bold tabular-nums text-green-400">
                  {loading ? "--" : stats.clean}
                </p>
              </div>
            </div>
          </div>
        </div>

        {/* ---------------------------------------------------------------- */}
        {/*  Search & Sort Controls                                          */}
        {/* ---------------------------------------------------------------- */}
        <div className="mb-4 flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
          <div className="relative max-w-sm flex-1">
            <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-zinc-500" />
            <input
              type="text"
              placeholder="Search endpoints..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="w-full rounded-lg border border-zinc-700 bg-zinc-900 py-2 pl-10 pr-4 text-sm text-zinc-100 placeholder-zinc-500 outline-none transition-colors focus:border-zinc-500 focus:ring-1 focus:ring-zinc-500"
            />
          </div>

          <div className="flex items-center gap-2">
            <span className="text-xs text-zinc-500">Sort by:</span>
            {(
              [
                ["score", "Threat Score"],
                ["total_requests", "Requests"],
                ["blocked_count", "Blocked"],
                ["block_rate", "Block Rate"],
              ] as [SortField, string][]
            ).map(([field, label]) => (
              <button
                key={field}
                onClick={() => handleSort(field)}
                className={`inline-flex items-center rounded-md px-2.5 py-1.5 text-xs font-medium transition-colors ${
                  sortField === field
                    ? "bg-zinc-700 text-white"
                    : "bg-zinc-800/60 text-zinc-400 hover:bg-zinc-700 hover:text-zinc-200"
                }`}
              >
                {label}
                {sortIndicator(field)}
              </button>
            ))}
          </div>
        </div>

        {/* ---------------------------------------------------------------- */}
        {/*  Table                                                           */}
        {/* ---------------------------------------------------------------- */}
        <div className="rounded-xl border border-zinc-800 bg-zinc-900">
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-zinc-800 text-left text-xs font-medium uppercase tracking-wider text-zinc-500">
                  <th className="px-4 py-3">Endpoint</th>
                  <th className="px-4 py-3">Threat Score</th>
                  <th className="px-4 py-3 text-right">Requests</th>
                  <th className="px-4 py-3 text-right">Blocked</th>
                  <th className="px-4 py-3 text-right">Block Rate</th>
                  <th className="px-4 py-3">Classifications</th>
                  <th className="px-4 py-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody>
                {/* Loading skeleton */}
                {loading &&
                  Array.from({ length: 5 }).map((_, i) => (
                    <SkeletonRow key={`skel-${i}`} />
                  ))}

                {/* Empty state */}
                {!loading && filtered.length === 0 && (
                  <tr>
                    <td colSpan={7} className="px-4 py-20 text-center">
                      <div className="flex flex-col items-center text-zinc-600">
                        <Fingerprint className="mb-3 h-12 w-12 text-zinc-700" />
                        <p className="text-lg font-medium text-zinc-400">
                          {search
                            ? "No endpoints match your query"
                            : "No reputation data collected"}
                        </p>
                        <p className="mt-1 text-sm text-zinc-600">
                          {search
                            ? "Try a different search filter."
                            : "Endpoint profiling data will populate as traffic is analyzed."}
                        </p>
                      </div>
                    </td>
                  </tr>
                )}

                {/* Data rows */}
                {!loading &&
                  filtered.map((entry) => {
                    const isExpanded = expandedIp === entry.ip;
                    const colors = scoreColor(entry.score);
                    const rate = blockRate(entry);

                    return (
                      <Fragment key={entry.ip}>
                        <tr
                          className={`border-b border-zinc-800/50 transition-colors hover:bg-zinc-800/30 ${
                            isExpanded ? "bg-zinc-800/20" : ""
                          }`}
                        >
                          {/* IP Address */}
                          <td className="px-4 py-3">
                            <button
                              onClick={() =>
                                setExpandedIp(isExpanded ? null : entry.ip)
                              }
                              className="inline-flex items-center gap-1.5 font-mono text-xs text-white transition-colors hover:text-blue-400"
                            >
                              <ChevronDown
                                className={`h-3.5 w-3.5 text-zinc-500 transition-transform ${
                                  isExpanded ? "rotate-0" : "-rotate-90"
                                }`}
                              />
                              {entry.country && (
                                <CountryFlag code={entry.country} size={14} />
                              )}
                              {entry.ip}
                            </button>
                          </td>

                          {/* Score bar */}
                          <td className="px-4 py-3">
                            <div className="flex items-center gap-2">
                              <div className="h-1.5 w-16 overflow-hidden rounded-full bg-zinc-800">
                                <div
                                  className={`h-full rounded-full ${colors.bar} transition-all`}
                                  style={{
                                    width: `${Math.min(entry.score, 100)}%`,
                                  }}
                                />
                              </div>
                              <span
                                className={`font-mono text-xs font-semibold tabular-nums ${colors.text}`}
                              >
                                {entry.score.toFixed(1)}
                              </span>
                            </div>
                          </td>

                          {/* Total Requests */}
                          <td className="px-4 py-3 text-right tabular-nums text-zinc-300">
                            {formatNumber(entry.total_requests)}
                          </td>

                          {/* Blocked Count */}
                          <td className="px-4 py-3 text-right tabular-nums text-zinc-300">
                            {formatNumber(entry.blocked_count)}
                          </td>

                          {/* Block Rate */}
                          <td className="px-4 py-3 text-right">
                            <span
                              className={`font-mono text-xs tabular-nums ${
                                rate >= 50
                                  ? "text-red-400"
                                  : rate >= 20
                                    ? "text-yellow-400"
                                    : "text-zinc-400"
                              }`}
                            >
                              {rate.toFixed(1)}%
                            </span>
                          </td>

                          {/* Categories */}
                          <td className="px-4 py-3">
                            <div className="flex flex-wrap gap-1">
                              {entry.categories.length > 0 ? (
                                entry.categories.map((c) => categoryBadge(c))
                              ) : (
                                <span className="text-xs text-zinc-600">
                                  --
                                </span>
                              )}
                            </div>
                          </td>

                          {/* Actions */}
                          <td className="px-4 py-3 text-right">
                            <button
                              onClick={(e) => {
                                e.stopPropagation();
                                handleBan(entry.ip);
                              }}
                              disabled={banningIp === entry.ip}
                              className="inline-flex items-center gap-1 rounded-md bg-red-500/10 px-2.5 py-1 text-xs font-medium text-red-400 transition-colors hover:bg-red-500/20 disabled:opacity-50"
                            >
                              <Ban className="h-3 w-3" />
                              {banningIp === entry.ip ? "Containing..." : "Contain"}
                            </button>
                          </td>
                        </tr>

                        {/* Expanded detail row */}
                        {isExpanded && (
                          <tr className="border-b border-zinc-800/50 bg-zinc-950/50">
                            <td colSpan={7} className="px-6 py-5">
                              <div className="grid grid-cols-1 gap-6 md:grid-cols-3">
                                {/* Details */}
                                <div className="space-y-3">
                                  <h4 className="text-xs font-semibold uppercase tracking-wider text-zinc-500">
                                    Endpoint Profile
                                  </h4>
                                  <dl className="space-y-2 text-sm">
                                    <div className="flex justify-between">
                                      <dt className="text-zinc-500">
                                        IP Address
                                      </dt>
                                      <dd className="font-mono text-white">
                                        {entry.ip}
                                      </dd>
                                    </div>
                                    {entry.country && (
                                      <div className="flex justify-between items-center">
                                        <dt className="text-zinc-500">
                                          Country
                                        </dt>
                                        <dd className="text-zinc-200 inline-flex items-center gap-1.5">
                                          <CountryFlag code={entry.country} size={16} />
                                          {entry.country}
                                        </dd>
                                      </div>
                                    )}
                                    {entry.city && (
                                      <div className="flex justify-between">
                                        <dt className="text-zinc-500">City</dt>
                                        <dd className="text-zinc-200">{entry.city}</dd>
                                      </div>
                                    )}
                                    {entry.asn && (
                                      <div className="flex justify-between">
                                        <dt className="text-zinc-500">ASN</dt>
                                        <dd className="font-mono text-zinc-200">AS{entry.asn}</dd>
                                      </div>
                                    )}
                                    {entry.asn_org && (
                                      <div className="flex justify-between">
                                        <dt className="text-zinc-500">Organization</dt>
                                        <dd className="text-zinc-200 text-right max-w-[180px] truncate">{entry.asn_org}</dd>
                                      </div>
                                    )}
                                    <div className="flex justify-between">
                                      <dt className="text-zinc-500">
                                        Threat Score
                                      </dt>
                                      <dd className={`font-mono font-bold ${colors.text}`}>
                                        {entry.score.toFixed(1)} / 100
                                      </dd>
                                    </div>
                                    <div className="flex justify-between">
                                      <dt className="text-zinc-500">
                                        Total Requests
                                      </dt>
                                      <dd className="tabular-nums text-zinc-200">
                                        {entry.total_requests.toLocaleString()}
                                      </dd>
                                    </div>
                                    <div className="flex justify-between">
                                      <dt className="text-zinc-500">
                                        Blocked Requests
                                      </dt>
                                      <dd className="tabular-nums text-zinc-200">
                                        {entry.blocked_count.toLocaleString()}
                                      </dd>
                                    </div>
                                    <div className="flex justify-between">
                                      <dt className="text-zinc-500">
                                        Block Rate
                                      </dt>
                                      <dd className="tabular-nums text-zinc-200">
                                        {rate.toFixed(2)}%
                                      </dd>
                                    </div>
                                  </dl>
                                </div>

                                {/* Score visualization */}
                                <div className="space-y-3">
                                  <h4 className="text-xs font-semibold uppercase tracking-wider text-zinc-500">
                                    Threat Assessment
                                  </h4>
                                  <div className="flex flex-col items-center rounded-lg border border-zinc-800 bg-zinc-900 p-4">
                                    <div
                                      className={`mb-2 text-4xl font-bold tabular-nums ${colors.text}`}
                                    >
                                      {entry.score.toFixed(0)}
                                    </div>
                                    <div className="h-2 w-full overflow-hidden rounded-full bg-zinc-800">
                                      <div
                                        className={`h-full rounded-full ${colors.bar}`}
                                        style={{
                                          width: `${Math.min(entry.score, 100)}%`,
                                        }}
                                      />
                                    </div>
                                    <p className="mt-2 text-xs text-zinc-500">
                                      {entry.score >= 80
                                        ? "CRITICAL -- immediate containment recommended"
                                        : entry.score >= 50
                                          ? "ELEVATED -- active monitoring required"
                                          : "NOMINAL -- standard traffic pattern"}
                                    </p>
                                  </div>
                                </div>

                                {/* Categories & Actions */}
                                <div className="space-y-3">
                                  <h4 className="text-xs font-semibold uppercase tracking-wider text-zinc-500">
                                    Threat Classifications
                                  </h4>
                                  <div className="flex flex-wrap gap-1.5">
                                    {entry.categories.length > 0 ? (
                                      entry.categories.map((c) =>
                                        categoryBadge(c),
                                      )
                                    ) : (
                                      <span className="text-sm text-zinc-600">
                                        No classifications assigned
                                      </span>
                                    )}
                                  </div>

                                  <h4 className="mt-4 text-xs font-semibold uppercase tracking-wider text-zinc-500">
                                    Response Actions
                                  </h4>
                                  <button
                                    onClick={() => handleBan(entry.ip)}
                                    disabled={banningIp === entry.ip}
                                    className="inline-flex items-center gap-2 rounded-lg bg-red-600 px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-red-700 disabled:opacity-50"
                                  >
                                    <Ban className="h-4 w-4" />
                                    {banningIp === entry.ip
                                      ? "Containing..."
                                      : "Confirm Containment"}
                                  </button>
                                  <p className="text-xs text-zinc-600">
                                    This will add the endpoint to the global blocklist
                                    with reason &quot;IP reputation ban&quot;.
                                  </p>
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

          {/* Footer summary */}
          {!loading && filtered.length > 0 && (
            <div className="border-t border-zinc-800 px-4 py-3 text-xs text-zinc-500">
              Showing {filtered.length} of {ips.length} tracked endpoints
              {search && ` matching "${search}"`}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
