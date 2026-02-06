"use client";

import { useState, useEffect, useCallback } from "react";
import { fetchApi } from "@/lib/api";
import {
  Shield,
  Clock,
  FileWarning,
  Bot,
  Lock,
  Waves,
  Globe,
  Search,
  ShieldCheck,
  ShieldOff,
  CheckCircle,
} from "lucide-react";

// --------------- Types ---------------

interface ManagedRule {
  id: number;
  name: string;
  description: string;
  enabled: boolean;
}

// --------------- Constants ---------------

const ICON_MAP: Record<string, React.ComponentType<{ className?: string }>> = {
  Shield,
  Clock,
  FileWarning,
  Bot,
  Lock,
  Waves,
  Globe,
};

const RULE_CATEGORIES: Record<
  string,
  { name: string; icon: string; rules: number[] }
> = {
  security: { name: "Injection & XSS Prevention", icon: "Shield", rules: [1, 2, 3, 4] },
  rate_limiting: { name: "Rate Limiting Engine", icon: "Clock", rules: [5, 6, 7] },
  payload: {
    name: "Payload & Header Inspection",
    icon: "FileWarning",
    rules: [8, 9, 10],
  },
  bot_detection: { name: "Bot Detection & Verification", icon: "Bot", rules: [11, 12] },
  protocol: {
    name: "Protocol Enforcement",
    icon: "Lock",
    rules: [13, 14, 15],
  },
  flood: { name: "Flood Mitigation", icon: "Waves", rules: [16, 17, 18] },
  api: { name: "API & File Access Protection", icon: "Globe", rules: [19, 20] },
};

const RULE_ACTIONS: Record<number, string> = {
  1: "block",
  2: "block",
  3: "block",
  4: "block",
  5: "challenge",
  6: "challenge",
  7: "challenge",
  8: "block",
  9: "score",
  10: "block",
  11: "block",
  12: "block",
  13: "block",
  14: "block",
  15: "block",
  16: "block",
  17: "score",
  18: "block",
  19: "block",
  20: "block",
};

const ACTION_STYLES: Record<string, string> = {
  block: "bg-red-600/15 text-red-400 border border-red-500/20",
  challenge: "bg-yellow-600/15 text-yellow-400 border border-yellow-500/20",
  score: "bg-blue-600/15 text-blue-400 border border-blue-500/20",
};

const ACTION_LABELS: Record<string, string> = {
  block: "Block",
  challenge: "Challenge",
  score: "Score",
};

// --------------- Helpers ---------------

function formatRuleName(name: string): string {
  return name
    .replace(/_/g, " ")
    .replace(/\b\w/g, (c) => c.toUpperCase());
}

function getRuleAction(id: number): string {
  return RULE_ACTIONS[id] ?? "block";
}

// --------------- Component ---------------

export default function ManagedRulesPage() {
  const [rules, setRules] = useState<ManagedRule[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState("");
  const [togglingIds, setTogglingIds] = useState<Set<number>>(new Set());
  const [toast, setToast] = useState<string | null>(null);
  const [bulkLoading, setBulkLoading] = useState(false);

  // --------------- Data fetching ---------------

  const loadRules = useCallback(async () => {
    try {
      const res = await fetchApi<{ rules: ManagedRule[] }>(
        "/api/fortress/managed-rules"
      );
      setRules(res.rules);
    } catch (e) {
      console.error("Failed to load managed rules", e);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadRules();
  }, [loadRules]);

  // --------------- Toast ---------------

  const showToast = (message: string) => {
    setToast(message);
    setTimeout(() => setToast(null), 2000);
  };

  // --------------- Toggle single rule ---------------

  const toggleRule = async (id: number, currentEnabled: boolean) => {
    setTogglingIds((prev) => new Set(prev).add(id));
    try {
      await fetchApi(`/api/fortress/managed-rules/${id}`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ enabled: !currentEnabled }),
      });
      setRules((prev) =>
        prev.map((r) => (r.id === id ? { ...r, enabled: !r.enabled } : r))
      );
      showToast(`Policy ${!currentEnabled ? "enabled" : "disabled"}`);
    } catch (e) {
      console.error("Failed to toggle rule", e);
    } finally {
      setTogglingIds((prev) => {
        const next = new Set(prev);
        next.delete(id);
        return next;
      });
    }
  };

  // --------------- Bulk toggle ---------------

  const bulkToggle = async (enabled: boolean) => {
    setBulkLoading(true);
    try {
      await Promise.all(
        rules
          .filter((r) => r.enabled !== enabled)
          .map((r) =>
            fetchApi(`/api/fortress/managed-rules/${r.id}`, {
              method: "PUT",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({ enabled }),
            })
          )
      );
      setRules((prev) => prev.map((r) => ({ ...r, enabled })));
      showToast(enabled ? "All policies enabled" : "All policies disabled");
    } catch (e) {
      console.error("Bulk toggle failed", e);
    } finally {
      setBulkLoading(false);
    }
  };

  // --------------- Derived data ---------------

  const enabledCount = rules.filter((r) => r.enabled).length;
  const blockCount = rules.filter(
    (r) => getRuleAction(r.id) === "block"
  ).length;
  const challengeCount = rules.filter(
    (r) => getRuleAction(r.id) === "challenge"
  ).length;
  const scoreCount = rules.filter(
    (r) => getRuleAction(r.id) === "score"
  ).length;

  const filteredRules = rules.filter((r) => {
    if (!search.trim()) return true;
    const q = search.toLowerCase();
    return (
      r.name.toLowerCase().includes(q) ||
      r.description.toLowerCase().includes(q) ||
      formatRuleName(r.name).toLowerCase().includes(q)
    );
  });

  const filteredRuleIds = new Set(filteredRules.map((r) => r.id));

  // --------------- Loading skeleton ---------------

  if (loading) {
    return (
      <div className="min-h-screen bg-black text-zinc-100 p-6 space-y-6">
        {/* Header skeleton */}
        <div className="flex items-center justify-between">
          <div className="space-y-2">
            <div className="h-7 w-48 bg-zinc-800 rounded-lg animate-pulse" />
            <div className="h-4 w-72 bg-zinc-800/60 rounded animate-pulse" />
          </div>
          <div className="flex gap-2">
            <div className="h-9 w-24 bg-zinc-800 rounded-lg animate-pulse" />
            <div className="h-9 w-24 bg-zinc-800 rounded-lg animate-pulse" />
          </div>
        </div>
        {/* Stat cards skeleton */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          {[1, 2, 3].map((i) => (
            <div
              key={i}
              className="rounded-xl border border-zinc-800 bg-zinc-900 p-5 space-y-3"
            >
              <div className="h-4 w-24 bg-zinc-800 rounded animate-pulse" />
              <div className="h-8 w-16 bg-zinc-800 rounded animate-pulse" />
            </div>
          ))}
        </div>
        {/* Search skeleton */}
        <div className="h-10 bg-zinc-900 border border-zinc-800 rounded-lg animate-pulse" />
        {/* Rule cards skeleton */}
        {[1, 2, 3].map((s) => (
          <div key={s} className="space-y-3">
            <div className="h-5 w-40 bg-zinc-800 rounded animate-pulse" />
            {[1, 2, 3].map((c) => (
              <div
                key={c}
                className="rounded-xl border border-zinc-800 bg-zinc-900 p-4 h-20 animate-pulse"
              />
            ))}
          </div>
        ))}
      </div>
    );
  }

  // --------------- Main render ---------------

  return (
    <div className="min-h-screen bg-black text-zinc-100 p-6 space-y-6">
      {/* Toast notification */}
      {toast && (
        <div className="fixed top-6 right-6 z-50 flex items-center gap-2 bg-zinc-800 border border-zinc-700 text-zinc-100 px-4 py-2.5 rounded-lg shadow-lg animate-[fadeIn_0.2s_ease-out]">
          <CheckCircle className="w-4 h-4 text-green-400 shrink-0" />
          <span className="text-sm">{toast}</span>
        </div>
      )}

      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-blue-500/10 ring-1 ring-blue-500/20">
              <ShieldCheck className="h-5 w-5 text-blue-400" />
            </div>
            <div>
              <h1 className="text-2xl font-bold tracking-tight text-white">
                Security Policies
              </h1>
              <p className="text-sm text-zinc-500">
                Pre-built rule sets and signature-based threat detection
              </p>
            </div>
          </div>
          <div className="mt-3">
            <span className="inline-flex items-center gap-1.5 bg-zinc-800 border border-zinc-700 text-zinc-300 rounded-full px-3 py-0.5 text-xs font-medium">
              <span className="w-1.5 h-1.5 rounded-full bg-green-400" />
              {enabledCount}/{rules.length} active
            </span>
          </div>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          <button
            onClick={() => bulkToggle(true)}
            disabled={bulkLoading || enabledCount === rules.length}
            className="flex items-center gap-1.5 bg-green-600/15 text-green-400 border border-green-500/20 hover:bg-green-600/25 disabled:opacity-40 disabled:cursor-not-allowed rounded-lg px-3.5 py-2 text-sm font-medium transition-colors"
          >
            <ShieldCheck className="w-4 h-4" />
            Enable All
          </button>
          <button
            onClick={() => bulkToggle(false)}
            disabled={bulkLoading || enabledCount === 0}
            className="flex items-center gap-1.5 bg-zinc-800 text-zinc-400 border border-zinc-700 hover:bg-zinc-700 hover:text-zinc-300 disabled:opacity-40 disabled:cursor-not-allowed rounded-lg px-3.5 py-2 text-sm font-medium transition-colors"
          >
            <ShieldOff className="w-4 h-4" />
            Disable All
          </button>
        </div>
      </div>

      {/* Stat cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="rounded-xl border border-zinc-800 bg-zinc-900 p-5">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-zinc-500 uppercase tracking-wider">
              Active Policies
            </span>
            <ShieldCheck className="w-4 h-4 text-green-400" />
          </div>
          <p className="text-2xl font-bold text-green-400 mt-2">
            {enabledCount}
          </p>
          <p className="text-xs text-zinc-600 mt-1">
            of {rules.length} total policies
          </p>
        </div>
        <div className="rounded-xl border border-zinc-800 bg-zinc-900 p-5">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-zinc-500 uppercase tracking-wider">
              Block Actions
            </span>
            <Shield className="w-4 h-4 text-red-400" />
          </div>
          <p className="text-2xl font-bold text-red-400 mt-2">{blockCount}</p>
          <p className="text-xs text-zinc-600 mt-1">policies that block traffic</p>
        </div>
        <div className="rounded-xl border border-zinc-800 bg-zinc-900 p-5">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-zinc-500 uppercase tracking-wider">
              Challenge & Score
            </span>
            <Clock className="w-4 h-4 text-yellow-400" />
          </div>
          <p className="text-2xl font-bold text-yellow-400 mt-2">
            {challengeCount + scoreCount}
          </p>
          <p className="text-xs text-zinc-600 mt-1">
            {challengeCount} challenge, {scoreCount} score modifier
          </p>
        </div>
      </div>

      {/* Search */}
      <div className="relative">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-zinc-500" />
        <input
          type="text"
          placeholder="Search policies by name or description..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="w-full bg-zinc-900 border border-zinc-800 rounded-lg pl-10 pr-4 py-2.5 text-sm text-zinc-100 placeholder:text-zinc-600 focus:outline-none focus:border-zinc-600 transition-colors"
        />
        {search && (
          <button
            onClick={() => setSearch("")}
            className="absolute right-3 top-1/2 -translate-y-1/2 text-zinc-500 hover:text-zinc-300 text-xs"
          >
            Clear
          </button>
        )}
      </div>

      {/* Category sections */}
      {Object.entries(RULE_CATEGORIES).map(([key, category]) => {
        const categoryRules = category.rules.filter((id) =>
          filteredRuleIds.has(id)
        );
        if (categoryRules.length === 0) return null;

        const Icon = ICON_MAP[category.icon];
        const enabledInCategory = categoryRules.filter((id) =>
          rules.find((r) => r.id === id && r.enabled)
        ).length;

        return (
          <div key={key} className="space-y-3">
            {/* Category header */}
            <div className="flex items-center gap-2.5 px-1">
              {Icon && <Icon className="w-4 h-4 text-zinc-400" />}
              <h2 className="text-sm font-semibold text-zinc-300 uppercase tracking-wider">
                {category.name}
              </h2>
              <span className="text-xs text-zinc-600">
                {enabledInCategory}/{categoryRules.length} active
              </span>
            </div>

            {/* Rule cards */}
            <div className="grid gap-2">
              {categoryRules.map((ruleId) => {
                const rule = rules.find((r) => r.id === ruleId);
                if (!rule) return null;

                const action = getRuleAction(rule.id);
                const isToggling = togglingIds.has(rule.id);

                return (
                  <div
                    key={rule.id}
                    className={`group relative flex items-center justify-between gap-4 rounded-xl border p-4 transition-all duration-200 ${
                      rule.enabled
                        ? "bg-zinc-900 border-zinc-700/60 hover:border-zinc-600"
                        : "bg-zinc-900/40 border-zinc-800/50 opacity-60 hover:opacity-80"
                    }`}
                  >
                    <div className="flex items-center gap-4 min-w-0">
                      {/* Rule ID badge */}
                      <span className="shrink-0 flex items-center justify-center w-8 h-8 rounded-lg bg-zinc-800 border border-zinc-700/50 text-xs font-mono text-zinc-400">
                        #{rule.id}
                      </span>

                      {/* Rule info */}
                      <div className="min-w-0">
                        <div className="flex items-center gap-2.5 flex-wrap">
                          <span className="text-sm font-medium text-zinc-100">
                            {formatRuleName(rule.name)}
                          </span>
                          <span
                            className={`inline-flex items-center rounded-md px-2 py-0.5 text-[11px] font-medium ${ACTION_STYLES[action]}`}
                          >
                            {ACTION_LABELS[action]}
                          </span>
                        </div>
                        <p className="text-xs text-zinc-500 mt-0.5 truncate">
                          {rule.description}
                        </p>
                      </div>
                    </div>

                    {/* Toggle switch */}
                    <button
                      onClick={() => toggleRule(rule.id, rule.enabled)}
                      disabled={isToggling}
                      aria-label={`Toggle ${rule.name}`}
                      className={`relative shrink-0 w-11 h-6 rounded-full transition-colors duration-200 focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 focus-visible:ring-offset-2 focus-visible:ring-offset-zinc-900 disabled:cursor-wait ${
                        rule.enabled ? "bg-blue-600" : "bg-zinc-700"
                      }`}
                    >
                      <span
                        className={`absolute top-0.5 left-0.5 w-5 h-5 rounded-full bg-white shadow-sm transition-transform duration-200 ${
                          rule.enabled ? "translate-x-5" : "translate-x-0"
                        } ${isToggling ? "opacity-70" : ""}`}
                      />
                    </button>
                  </div>
                );
              })}
            </div>
          </div>
        );
      })}

      {/* Empty search state */}
      {filteredRules.length === 0 && !loading && (
        <div className="flex flex-col items-center justify-center py-16 text-zinc-600">
          <Search className="w-8 h-8 mb-3 text-zinc-700" />
          <p className="text-sm">No policies match your search.</p>
          <button
            onClick={() => setSearch("")}
            className="mt-2 text-xs text-zinc-500 hover:text-zinc-300 transition-colors"
          >
            Clear search
          </button>
        </div>
      )}
    </div>
  );
}
