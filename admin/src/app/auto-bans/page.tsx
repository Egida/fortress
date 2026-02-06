"use client";

import { useState, useEffect, useCallback, useRef } from "react";
import { fortressGet, fortressPost, fortressDelete } from "@/lib/api";
import { CountryFlag } from "@/components/country-flag";
import { countryName } from "@/lib/i18n";
import {
  ShieldCheck,
  RefreshCw,
  Search,
  Plus,
  Ban,
  Clock,
  Timer,
  ChevronDown,
  ChevronRight,
  X,
  Zap,
  Globe,
  Server,
  MapPin,
  Network,
} from "lucide-react";

/* -------------------------------------------------------------------------- */
/*  Types                                                                      */
/* -------------------------------------------------------------------------- */

interface BanEntry {
  ip: string;
  reason: string;
  remaining_secs: number;
  total_duration_secs: number;
  country?: string | null;
  city?: string | null;
  asn?: number | null;
  asn_org?: string | null;
}

interface BansResponse {
  bans: BanEntry[];
  active_count: number;
}

/* -------------------------------------------------------------------------- */
/*  Helpers                                                                    */
/* -------------------------------------------------------------------------- */

const formatTime = (secs: number) => {
  if (secs >= 3600)
    return `${Math.floor(secs / 3600)}h ${Math.floor((secs % 3600) / 60)}m`;
  if (secs >= 60) return `${Math.floor(secs / 60)}m ${Math.floor(secs % 60)}s`;
  return `${Math.floor(secs)}s`;
};

const DURATION_OPTIONS = [
  { label: "5 minutes", value: 300 },
  { label: "30 minutes", value: 1800 },
  { label: "2 hours", value: 7200 },
  { label: "24 hours", value: 86400 },
] as const;

function reasonLabel(reason: string): { text: string; color: string } {
  if (reason.includes("1h_threshold"))
    return { text: "1h Threshold", color: "text-red-400 bg-red-500/10 ring-red-500/20" };
  if (reason.includes("15m_threshold"))
    return { text: "15m Threshold", color: "text-orange-400 bg-orange-500/10 ring-orange-500/20" };
  if (reason.includes("5m_threshold"))
    return { text: "5m Threshold", color: "text-yellow-400 bg-yellow-500/10 ring-yellow-500/20" };
  if (reason.includes("repeat"))
    return { text: "Repeat Offender", color: "text-red-400 bg-red-500/10 ring-red-500/20" };
  return { text: reason, color: "text-zinc-400 bg-zinc-800 ring-zinc-700" };
}

/* -------------------------------------------------------------------------- */
/*  Component                                                                  */
/* -------------------------------------------------------------------------- */

export default function AutoBansPage() {
  const [data, setData] = useState<BansResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState("");
  const [showForm, setShowForm] = useState(false);
  const [confirmIp, setConfirmIp] = useState<string | null>(null);
  const [refreshing, setRefreshing] = useState(false);
  const [expandedIp, setExpandedIp] = useState<string | null>(null);

  // Manual containment form state
  const [banIp, setBanIp] = useState("");
  const [banReason, setBanReason] = useState("");
  const [banDuration, setBanDuration] = useState<number>(DURATION_OPTIONS[0].value);
  const [banSubmitting, setBanSubmitting] = useState(false);

  const confirmTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  /* ---- Data fetching ---- */

  const loadData = useCallback(async (silent = false) => {
    if (!silent) setLoading(true);
    try {
      const res = await fortressGet<BansResponse>("/api/fortress/auto-bans");
      setData(res);
    } catch (e) {
      console.error("Failed to load auto-response data:", e);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, []);

  useEffect(() => {
    loadData();
    const interval = setInterval(() => loadData(true), 5000);
    return () => clearInterval(interval);
  }, [loadData]);

  /* ---- Actions ---- */

  const handleRefresh = () => {
    setRefreshing(true);
    loadData();
  };

  const handleUnban = async (ip: string) => {
    if (confirmIp !== ip) {
      setConfirmIp(ip);
      if (confirmTimer.current) clearTimeout(confirmTimer.current);
      confirmTimer.current = setTimeout(() => setConfirmIp(null), 3000);
      return;
    }
    setConfirmIp(null);
    if (confirmTimer.current) clearTimeout(confirmTimer.current);
    try {
      await fortressDelete(`/api/fortress/auto-bans/${encodeURIComponent(ip)}`);
      loadData(true);
    } catch (e) {
      console.error("Failed to release containment:", e);
    }
  };

  const handleManualBan = async () => {
    if (!banIp.trim()) return;
    setBanSubmitting(true);
    try {
      await fortressPost("/api/fortress/blocklist", {
        type: "ip",
        value: banIp.trim(),
        reason: banReason.trim() || "Manual containment",
        ttl_secs: banDuration,
      });
      setBanIp("");
      setBanReason("");
      setBanDuration(DURATION_OPTIONS[0].value);
      setShowForm(false);
      loadData(true);
    } catch (e) {
      console.error("Failed to add manual containment:", e);
    } finally {
      setBanSubmitting(false);
    }
  };

  const toggleExpand = (ip: string) => {
    setExpandedIp((prev) => (prev === ip ? null : ip));
  };

  /* ---- Computed values ---- */

  const bans = data?.bans ?? [];
  const activeCount = data?.active_count ?? 0;

  const filtered = bans.filter(
    (b) =>
      b.ip.toLowerCase().includes(search.toLowerCase()) ||
      b.reason.toLowerCase().includes(search.toLowerCase()) ||
      (b.country && b.country.toLowerCase().includes(search.toLowerCase())) ||
      (b.city && b.city.toLowerCase().includes(search.toLowerCase())) ||
      (b.asn_org && b.asn_org.toLowerCase().includes(search.toLowerCase())),
  );

  const longestRemaining =
    bans.length > 0 ? Math.max(...bans.map((b) => b.remaining_secs)) : 0;
  const avgDuration =
    bans.length > 0
      ? Math.round(
          bans.reduce((sum, b) => sum + b.total_duration_secs, 0) / bans.length,
        )
      : 0;

  // Count unique countries
  const uniqueCountries = new Set(bans.map((b) => b.country).filter(Boolean)).size;

  /* ---- Skeleton loading ---- */

  if (loading && !data) {
    return (
      <div className="min-h-screen bg-black p-6 space-y-6">
        <div className="flex items-center justify-between">
          <div className="space-y-2">
            <div className="h-8 w-64 animate-pulse rounded-lg bg-zinc-800" />
            <div className="h-4 w-96 animate-pulse rounded bg-zinc-800/60" />
          </div>
          <div className="h-9 w-24 animate-pulse rounded-lg bg-zinc-800" />
        </div>
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          {Array.from({ length: 4 }).map((_, i) => (
            <div
              key={i}
              className="h-24 animate-pulse rounded-xl border border-zinc-800 bg-zinc-900"
            />
          ))}
        </div>
        <div className="rounded-xl border border-zinc-800 bg-zinc-900 p-5 space-y-3">
          {Array.from({ length: 6 }).map((_, i) => (
            <div
              key={i}
              className="h-10 animate-pulse rounded bg-zinc-800"
            />
          ))}
        </div>
      </div>
    );
  }

  /* ---- Main render ---- */

  return (
    <div className="min-h-screen bg-black p-6 space-y-6">
      {/* ------------------------------------------------------------------ */}
      {/*  Header                                                             */}
      {/* ------------------------------------------------------------------ */}
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-yellow-500/10 ring-1 ring-yellow-500/20">
              <Zap className="h-5 w-5 text-yellow-400" />
            </div>
            <div>
              <h1 className="text-2xl font-bold tracking-tight text-white">
                Auto-Response System
              </h1>
              <p className="text-sm text-zinc-500">
                Automated threat containment and progressive ban escalation
              </p>
            </div>
          </div>
          {activeCount > 0 ? (
            <div className="mt-3">
              <span className="relative inline-flex items-center gap-1.5 px-3 py-1 bg-red-500/15 text-red-400 rounded-full text-xs font-medium ring-1 ring-red-500/20">
                <span className="relative flex h-2 w-2">
                  <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-red-400 opacity-75" />
                  <span className="relative inline-flex h-2 w-2 rounded-full bg-red-500" />
                </span>
                {activeCount} active containment{activeCount !== 1 ? "s" : ""}
              </span>
            </div>
          ) : (
            <div className="mt-3">
              <span className="inline-flex items-center gap-1.5 px-3 py-1 bg-zinc-800 text-zinc-500 rounded-full text-xs font-medium ring-1 ring-zinc-700">
                0 active
              </span>
            </div>
          )}
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => setShowForm((v) => !v)}
            className="flex items-center gap-1.5 rounded-lg border border-zinc-700 bg-zinc-900 px-3 py-2 text-sm font-medium text-zinc-300 transition-colors hover:bg-zinc-800 hover:text-white"
          >
            {showForm ? <X className="h-4 w-4" /> : <Plus className="h-4 w-4" />}
            {showForm ? "Cancel" : "Manual Containment"}
          </button>
          <button
            onClick={handleRefresh}
            disabled={refreshing}
            className="flex items-center gap-1.5 rounded-lg border border-zinc-700 bg-zinc-900 px-3 py-2 text-sm font-medium text-zinc-300 transition-colors hover:bg-zinc-800 hover:text-white disabled:opacity-50"
          >
            <RefreshCw
              className={`h-4 w-4 ${refreshing ? "animate-spin" : ""}`}
            />
            Refresh
          </button>
        </div>
      </div>

      {/* ------------------------------------------------------------------ */}
      {/*  Stat Cards                                                         */}
      {/* ------------------------------------------------------------------ */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        {/* Active Containment */}
        <div className="rounded-xl border border-zinc-800 bg-zinc-900 p-4">
          <div className="flex items-center gap-2 text-zinc-400 text-xs font-medium uppercase tracking-wider mb-2">
            <Ban className="h-3.5 w-3.5 text-red-400" />
            Active Containment
          </div>
          <p className="text-3xl font-bold tabular-nums text-red-400">
            {activeCount}
          </p>
        </div>

        {/* Unique Countries */}
        <div className="rounded-xl border border-zinc-800 bg-zinc-900 p-4">
          <div className="flex items-center gap-2 text-zinc-400 text-xs font-medium uppercase tracking-wider mb-2">
            <Globe className="h-3.5 w-3.5 text-orange-400" />
            Unique Countries
          </div>
          <p className="text-3xl font-bold tabular-nums text-orange-400">
            {uniqueCountries}
          </p>
        </div>

        {/* Longest Remaining */}
        <div className="rounded-xl border border-zinc-800 bg-zinc-900 p-4">
          <div className="flex items-center gap-2 text-zinc-400 text-xs font-medium uppercase tracking-wider mb-2">
            <Clock className="h-3.5 w-3.5 text-yellow-400" />
            Longest Remaining
          </div>
          <p className="text-3xl font-bold tabular-nums text-yellow-400">
            {longestRemaining > 0 ? formatTime(longestRemaining) : "--"}
          </p>
        </div>

        {/* Average Containment Duration */}
        <div className="rounded-xl border border-zinc-800 bg-zinc-900 p-4">
          <div className="flex items-center gap-2 text-zinc-400 text-xs font-medium uppercase tracking-wider mb-2">
            <Timer className="h-3.5 w-3.5 text-blue-400" />
            Avg. Duration
          </div>
          <p className="text-3xl font-bold tabular-nums text-blue-400">
            {avgDuration > 0 ? formatTime(avgDuration) : "--"}
          </p>
        </div>
      </div>

      {/* ------------------------------------------------------------------ */}
      {/*  Manual Containment Form                                             */}
      {/* ------------------------------------------------------------------ */}
      {showForm && (
        <div className="rounded-xl border border-zinc-800 bg-zinc-900 p-5">
          <h2 className="text-sm font-semibold text-zinc-100 mb-4">
            Manual Containment Entry
          </h2>
          <div className="grid grid-cols-1 md:grid-cols-4 gap-3">
            <div>
              <label className="block text-xs text-zinc-400 mb-1">
                Target IP Address
              </label>
              <input
                type="text"
                placeholder="192.168.1.100"
                value={banIp}
                onChange={(e) => setBanIp(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && handleManualBan()}
                className="w-full rounded-lg border border-zinc-700 bg-zinc-800 px-3 py-2 text-sm text-zinc-100 font-mono placeholder-zinc-600 focus:outline-none focus:border-zinc-500 transition-colors"
              />
            </div>
            <div>
              <label className="block text-xs text-zinc-400 mb-1">Reason</label>
              <input
                type="text"
                placeholder="Manual containment"
                value={banReason}
                onChange={(e) => setBanReason(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && handleManualBan()}
                className="w-full rounded-lg border border-zinc-700 bg-zinc-800 px-3 py-2 text-sm text-zinc-100 placeholder-zinc-600 focus:outline-none focus:border-zinc-500 transition-colors"
              />
            </div>
            <div>
              <label className="block text-xs text-zinc-400 mb-1">
                Containment Duration
              </label>
              <div className="relative">
                <select
                  value={banDuration}
                  onChange={(e) => setBanDuration(Number(e.target.value))}
                  className="w-full appearance-none rounded-lg border border-zinc-700 bg-zinc-800 px-3 py-2 pr-8 text-sm text-zinc-100 focus:outline-none focus:border-zinc-500 transition-colors"
                >
                  {DURATION_OPTIONS.map((opt) => (
                    <option key={opt.value} value={opt.value}>
                      {opt.label}
                    </option>
                  ))}
                </select>
                <ChevronDown className="absolute right-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-zinc-500 pointer-events-none" />
              </div>
            </div>
            <div className="flex items-end">
              <button
                onClick={handleManualBan}
                disabled={!banIp.trim() || banSubmitting}
                className="w-full flex items-center justify-center gap-1.5 rounded-lg bg-red-600 px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-red-700 disabled:opacity-40 disabled:cursor-not-allowed"
              >
                <Ban className="h-3.5 w-3.5" />
                {banSubmitting ? "Containing..." : "Contain IP"}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ------------------------------------------------------------------ */}
      {/*  Search                                                             */}
      {/* ------------------------------------------------------------------ */}
      {bans.length > 0 && (
        <div className="relative">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-zinc-500" />
          <input
            type="text"
            placeholder="Filter by IP, country, city, ASN or reason..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full rounded-lg border border-zinc-800 bg-zinc-900 py-2.5 pl-10 pr-4 text-sm text-zinc-100 placeholder-zinc-600 focus:outline-none focus:border-zinc-600 transition-colors"
          />
          {search && (
            <button
              onClick={() => setSearch("")}
              className="absolute right-3 top-1/2 -translate-y-1/2 text-zinc-500 hover:text-zinc-300 transition-colors"
            >
              <X className="h-4 w-4" />
            </button>
          )}
        </div>
      )}

      {/* ------------------------------------------------------------------ */}
      {/*  Table                                                              */}
      {/* ------------------------------------------------------------------ */}
      <div className="rounded-xl border border-zinc-800 bg-zinc-900 overflow-hidden">
        {filtered.length === 0 && bans.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-20 text-zinc-600">
            <ShieldCheck className="h-12 w-12 mb-4 text-green-500/60" />
            <p className="text-lg font-medium text-green-400/80">
              No active containments
            </p>
            <p className="mt-1 text-sm text-zinc-600">
              All clear. No endpoints are currently contained.
            </p>
          </div>
        ) : filtered.length === 0 && search ? (
          <div className="flex flex-col items-center justify-center py-16 text-zinc-600">
            <Search className="h-8 w-8 mb-3 text-zinc-700" />
            <p className="text-sm text-zinc-500">
              No containments matching &ldquo;{search}&rdquo;
            </p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-zinc-800 text-left">
                  <th className="px-4 py-3 text-xs font-medium text-zinc-400 uppercase tracking-wider w-8" />
                  <th className="px-4 py-3 text-xs font-medium text-zinc-400 uppercase tracking-wider">
                    Target Endpoint
                  </th>
                  <th className="px-4 py-3 text-xs font-medium text-zinc-400 uppercase tracking-wider">
                    Location
                  </th>
                  <th className="px-4 py-3 text-xs font-medium text-zinc-400 uppercase tracking-wider">
                    Trigger
                  </th>
                  <th className="px-4 py-3 text-xs font-medium text-zinc-400 uppercase tracking-wider">
                    Remaining
                  </th>
                  <th className="px-4 py-3 text-xs font-medium text-zinc-400 uppercase tracking-wider min-w-[140px]">
                    Progress
                  </th>
                  <th className="px-4 py-3 text-xs font-medium text-zinc-400 uppercase tracking-wider text-right">
                    Actions
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-zinc-800/50">
                {filtered.map((ban) => {
                  const elapsed =
                    ban.total_duration_secs - ban.remaining_secs;
                  const progress =
                    ban.total_duration_secs > 0
                      ? (elapsed / ban.total_duration_secs) * 100
                      : 0;
                  const isConfirming = confirmIp === ban.ip;
                  const isExpanded = expandedIp === ban.ip;
                  const rl = reasonLabel(ban.reason);

                  return (
                    <tr
                      key={ban.ip}
                      className="group"
                    >
                      <td colSpan={7} className="p-0">
                        {/* Main row */}
                        <div
                          className={`flex items-center cursor-pointer transition-colors hover:bg-zinc-800/40 ${isExpanded ? "bg-zinc-800/30" : ""}`}
                          onClick={() => toggleExpand(ban.ip)}
                        >
                          {/* Expand icon */}
                          <div className="px-4 py-3 flex-shrink-0">
                            <ChevronRight
                              className={`h-3.5 w-3.5 text-zinc-600 transition-transform duration-200 ${isExpanded ? "rotate-90" : ""}`}
                            />
                          </div>

                          {/* IP */}
                          <div className="px-4 py-3 flex-1 min-w-[160px]">
                            <span className="font-mono text-xs text-white bg-zinc-800 rounded px-2 py-0.5">
                              {ban.ip}
                            </span>
                          </div>

                          {/* Location */}
                          <div className="px-4 py-3 flex-1 min-w-[140px]">
                            {ban.country ? (
                              <span className="inline-flex items-center gap-1.5">
                                <CountryFlag code={ban.country} size={18} />
                                <span className="text-zinc-300 text-xs">
                                  {countryName(ban.country)}
                                </span>
                              </span>
                            ) : (
                              <span className="text-zinc-600 text-xs">--</span>
                            )}
                          </div>

                          {/* Reason */}
                          <div className="px-4 py-3 flex-1 min-w-[120px]">
                            <span
                              className={`inline-flex items-center px-2 py-0.5 rounded-full text-[11px] font-medium ring-1 ${rl.color}`}
                            >
                              {rl.text}
                            </span>
                          </div>

                          {/* Time Remaining */}
                          <div className="px-4 py-3 flex-shrink-0 w-[100px]">
                            <span className="font-mono text-yellow-400 tabular-nums text-xs">
                              {formatTime(ban.remaining_secs)}
                            </span>
                          </div>

                          {/* Progress Bar */}
                          <div className="px-4 py-3 flex-shrink-0 w-[160px]">
                            <div className="flex items-center gap-2">
                              <div className="flex-1 h-1.5 rounded-full bg-zinc-800 overflow-hidden">
                                <div
                                  className="h-full rounded-full bg-yellow-500/80 transition-all duration-500"
                                  style={{ width: `${Math.min(progress, 100)}%` }}
                                />
                              </div>
                              <span className="text-xs text-zinc-500 tabular-nums w-10 text-right">
                                {Math.round(progress)}%
                              </span>
                            </div>
                          </div>

                          {/* Actions */}
                          <div className="px-4 py-3 flex-shrink-0 text-right min-w-[120px]">
                            <button
                              onClick={(e) => {
                                e.stopPropagation();
                                handleUnban(ban.ip);
                              }}
                              className={`rounded-lg px-3 py-1.5 text-xs font-medium transition-all duration-150 ${
                                isConfirming
                                  ? "bg-red-600 text-white hover:bg-red-700 shadow-lg shadow-red-900/20"
                                  : "bg-zinc-800 text-zinc-400 hover:bg-zinc-700 hover:text-zinc-200"
                              }`}
                            >
                              {isConfirming ? "Confirm?" : "Release"}
                            </button>
                          </div>
                        </div>

                        {/* Expanded detail panel */}
                        {isExpanded && (
                          <div className="border-t border-zinc-800/50 bg-zinc-950/50 px-6 py-4">
                            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                              {/* IP Info */}
                              <div className="space-y-3">
                                <h4 className="text-[11px] font-semibold text-zinc-500 uppercase tracking-wider flex items-center gap-1.5">
                                  <Server className="h-3 w-3" />
                                  Network Info
                                </h4>
                                <div className="space-y-2">
                                  <div>
                                    <span className="text-[10px] text-zinc-600 uppercase tracking-wider block">IP Address</span>
                                    <span className="font-mono text-sm text-white">{ban.ip}</span>
                                  </div>
                                  {ban.asn && (
                                    <div>
                                      <span className="text-[10px] text-zinc-600 uppercase tracking-wider block">ASN</span>
                                      <span className="font-mono text-sm text-zinc-300">AS{ban.asn}</span>
                                    </div>
                                  )}
                                  {ban.asn_org && (
                                    <div>
                                      <span className="text-[10px] text-zinc-600 uppercase tracking-wider block">Organization</span>
                                      <span className="text-sm text-zinc-300">{ban.asn_org}</span>
                                    </div>
                                  )}
                                </div>
                              </div>

                              {/* Location */}
                              <div className="space-y-3">
                                <h4 className="text-[11px] font-semibold text-zinc-500 uppercase tracking-wider flex items-center gap-1.5">
                                  <MapPin className="h-3 w-3" />
                                  Location
                                </h4>
                                <div className="space-y-2">
                                  {ban.country ? (
                                    <div className="flex items-center gap-2">
                                      <CountryFlag code={ban.country} size={28} />
                                      <div>
                                        <span className="text-sm text-white block">{countryName(ban.country)}</span>
                                        <span className="text-[10px] text-zinc-500 font-mono">{ban.country}</span>
                                      </div>
                                    </div>
                                  ) : (
                                    <span className="text-sm text-zinc-600">Unknown</span>
                                  )}
                                  {ban.city && (
                                    <div>
                                      <span className="text-[10px] text-zinc-600 uppercase tracking-wider block">City</span>
                                      <span className="text-sm text-zinc-300">{ban.city}</span>
                                    </div>
                                  )}
                                </div>
                              </div>

                              {/* Containment Info */}
                              <div className="space-y-3">
                                <h4 className="text-[11px] font-semibold text-zinc-500 uppercase tracking-wider flex items-center gap-1.5">
                                  <Ban className="h-3 w-3" />
                                  Containment
                                </h4>
                                <div className="space-y-2">
                                  <div>
                                    <span className="text-[10px] text-zinc-600 uppercase tracking-wider block">Reason</span>
                                    <span className="text-sm text-zinc-300">{ban.reason}</span>
                                  </div>
                                  <div>
                                    <span className="text-[10px] text-zinc-600 uppercase tracking-wider block">Total Duration</span>
                                    <span className="font-mono text-sm text-zinc-300">{formatTime(ban.total_duration_secs)}</span>
                                  </div>
                                </div>
                              </div>

                              {/* Timing */}
                              <div className="space-y-3">
                                <h4 className="text-[11px] font-semibold text-zinc-500 uppercase tracking-wider flex items-center gap-1.5">
                                  <Network className="h-3 w-3" />
                                  Timing
                                </h4>
                                <div className="space-y-2">
                                  <div>
                                    <span className="text-[10px] text-zinc-600 uppercase tracking-wider block">Time Remaining</span>
                                    <span className="font-mono text-sm text-yellow-400">{formatTime(ban.remaining_secs)}</span>
                                  </div>
                                  <div>
                                    <span className="text-[10px] text-zinc-600 uppercase tracking-wider block">Elapsed</span>
                                    <span className="font-mono text-sm text-zinc-300">{formatTime(elapsed)}</span>
                                  </div>
                                  <div>
                                    <span className="text-[10px] text-zinc-600 uppercase tracking-wider block">Progress</span>
                                    <div className="flex items-center gap-2 mt-1">
                                      <div className="flex-1 h-2 rounded-full bg-zinc-800 overflow-hidden max-w-[120px]">
                                        <div
                                          className="h-full rounded-full bg-yellow-500/80 transition-all duration-500"
                                          style={{ width: `${Math.min(progress, 100)}%` }}
                                        />
                                      </div>
                                      <span className="text-xs text-zinc-400 tabular-nums">
                                        {Math.round(progress)}%
                                      </span>
                                    </div>
                                  </div>
                                </div>
                              </div>
                            </div>
                          </div>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* ---- Footer summary ---- */}
      {bans.length > 0 && (
        <div className="flex items-center justify-between text-xs text-zinc-600 px-1">
          <span>
            Showing {filtered.length} of {bans.length} containment
            {bans.length !== 1 ? "s" : ""}
            {search ? ` matching "${search}"` : ""}
          </span>
          <span>Auto-refreshes every 5s</span>
        </div>
      )}
    </div>
  );
}
