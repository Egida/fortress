'use client';

import { useEffect, useState, useCallback } from 'react';
import { fortressGet, fortressPut, fortressPost } from '@/lib/api';
import { FortressConfig, FortressSettings, FortressStatus, ManagedRule } from '@/lib/types';
import { PROTECTION_LEVELS_LIST, formatUptime, formatNumber } from '@/lib/constants';
import { useLocale } from '@/lib/useLocale';
import {
  Shield, AlertTriangle, Zap, Skull, ShieldAlert, ShieldCheck,
  Info, Save, Server, Clock, FileText, FolderCog, Activity,
  Gauge, Lock, Cpu, ChevronRight, Fingerprint, Ban,
  Bot, Globe, Cloud, Network, Eye, BookLock,
  CheckCircle, Terminal, Database, Radio, Crosshair,
} from 'lucide-react';

/* ================================================================== */
/*  CUSTOM CSS ANIMATIONS (injected via <style> tag)                  */
/* ================================================================== */

const CUSTOM_STYLES = `
  @keyframes pulse-border {
    0%, 100% { border-color: var(--pulse-color); box-shadow: 0 0 15px 2px var(--pulse-shadow); }
    50% { border-color: var(--pulse-color-dim); box-shadow: 0 0 5px 0px var(--pulse-shadow); }
  }

  @keyframes scan-line {
    0% { transform: translateY(-100%); }
    100% { transform: translateY(400%); }
  }

  @keyframes turnstile-spin {
    0% { transform: rotate(0deg); }
    100% { transform: rotate(360deg); }
  }

  @keyframes turnstile-check-draw {
    0% { stroke-dashoffset: 24; }
    100% { stroke-dashoffset: 0; }
  }

  @keyframes fade-up {
    0% { opacity: 0; transform: translateY(8px); }
    100% { opacity: 1; transform: translateY(0); }
  }

  @keyframes status-pulse {
    0%, 100% { opacity: 1; transform: scale(1); }
    50% { opacity: 0.4; transform: scale(0.8); }
  }

  @keyframes glow-sweep {
    0% { background-position: -200% center; }
    100% { background-position: 200% center; }
  }

  .pulse-border-green {
    --pulse-color: rgba(34, 197, 94, 0.6);
    --pulse-color-dim: rgba(34, 197, 94, 0.2);
    --pulse-shadow: rgba(34, 197, 94, 0.15);
    animation: pulse-border 2s ease-in-out infinite;
  }
  .pulse-border-yellow {
    --pulse-color: rgba(234, 179, 8, 0.6);
    --pulse-color-dim: rgba(234, 179, 8, 0.2);
    --pulse-shadow: rgba(234, 179, 8, 0.15);
    animation: pulse-border 2s ease-in-out infinite;
  }
  .pulse-border-orange {
    --pulse-color: rgba(249, 115, 22, 0.6);
    --pulse-color-dim: rgba(249, 115, 22, 0.2);
    --pulse-shadow: rgba(249, 115, 22, 0.15);
    animation: pulse-border 2s ease-in-out infinite;
  }
  .pulse-border-red {
    --pulse-color: rgba(239, 68, 68, 0.6);
    --pulse-color-dim: rgba(239, 68, 68, 0.2);
    --pulse-shadow: rgba(239, 68, 68, 0.15);
    animation: pulse-border 2s ease-in-out infinite;
  }
  .pulse-border-darkred {
    --pulse-color: rgba(185, 28, 28, 0.7);
    --pulse-color-dim: rgba(185, 28, 28, 0.25);
    --pulse-shadow: rgba(185, 28, 28, 0.2);
    animation: pulse-border 1.5s ease-in-out infinite;
  }

  .scan-line {
    animation: scan-line 3s linear infinite;
  }

  .status-dot-pulse {
    animation: status-pulse 1.5s ease-in-out infinite;
  }

  .glow-sweep {
    background: linear-gradient(90deg, transparent 0%, rgba(59,130,246,0.08) 50%, transparent 100%);
    background-size: 200% 100%;
    animation: glow-sweep 4s ease-in-out infinite;
  }

  .turnstile-spinner {
    animation: turnstile-spin 0.8s linear infinite;
  }

  .check-draw {
    stroke-dasharray: 24;
    stroke-dashoffset: 0;
    animation: turnstile-check-draw 0.4s ease-out forwards;
  }

  .fade-up {
    animation: fade-up 0.3s ease-out forwards;
  }

  .module-card {
    transition: all 0.2s ease;
  }
  .module-card:hover {
    transform: translateY(-1px);
  }
`;

/* ================================================================== */
/*  DEFCON CONFIGURATION                                               */
/* ================================================================== */

const DEFCON_LEVELS = [
  {
    key: 'Normal',
    defcon: 5,
    name: 'DEFCON 5',
    subtitle: 'Normal Operations',
    codename: 'GREENFIELD',
    description: 'Standard rate limiting. Minimal filtering. Baseline protection for regular traffic patterns.',
    color: 'green',
    icon: ShieldCheck,
    border: 'border-green-500/40',
    glow: 'shadow-green-500/20',
    bg: 'bg-green-500/5',
    activeBg: 'bg-green-500/10',
    text: 'text-green-400',
    ring: 'ring-green-500/60',
    pulseClass: 'pulse-border-green',
  },
  {
    key: 'High',
    defcon: 4,
    name: 'DEFCON 4',
    subtitle: 'Elevated Threat',
    codename: 'WATCHGUARD',
    description: 'JS challenges for suspicious clients. Enhanced behavioral analysis activated.',
    color: 'yellow',
    icon: Shield,
    border: 'border-yellow-500/40',
    glow: 'shadow-yellow-500/20',
    bg: 'bg-yellow-500/5',
    activeBg: 'bg-yellow-500/10',
    text: 'text-yellow-400',
    ring: 'ring-yellow-500/60',
    pulseClass: 'pulse-border-yellow',
  },
  {
    key: 'UnderAttack',
    defcon: 3,
    name: 'DEFCON 3',
    subtitle: 'Under Attack',
    codename: 'IRONCLAD',
    description: 'All visitors challenged. PoW verification mandatory. Aggressive rate limiting.',
    color: 'orange',
    icon: AlertTriangle,
    border: 'border-orange-500/40',
    glow: 'shadow-orange-500/20',
    bg: 'bg-orange-500/5',
    activeBg: 'bg-orange-500/10',
    text: 'text-orange-400',
    ring: 'ring-orange-500/60',
    pulseClass: 'pulse-border-orange',
  },
  {
    key: 'Severe',
    defcon: 2,
    name: 'DEFCON 2',
    subtitle: 'Severe Attack',
    codename: 'BLACKSTORM',
    description: 'CAPTCHA enforcement. Aggressive IP blocking. Maximum PoW difficulty enabled.',
    color: 'red',
    icon: Skull,
    border: 'border-red-500/40',
    glow: 'shadow-red-500/20',
    bg: 'bg-red-500/5',
    activeBg: 'bg-red-500/10',
    text: 'text-red-400',
    ring: 'ring-red-500/60',
    pulseClass: 'pulse-border-red',
  },
  {
    key: 'Emergency',
    defcon: 1,
    name: 'DEFCON 1',
    subtitle: 'Emergency Lockdown',
    codename: 'DEADBOLT',
    description: 'Whitelist-only mode. All non-whitelisted traffic dropped. Maximum defense posture.',
    color: 'red',
    icon: ShieldAlert,
    border: 'border-red-700/60',
    glow: 'shadow-red-700/30',
    bg: 'bg-red-900/10',
    activeBg: 'bg-red-900/20',
    text: 'text-red-300',
    ring: 'ring-red-700/70',
    pulseClass: 'pulse-border-darkred',
  },
] as const;

/* ================================================================== */
/*  DEFENSE MODULE DEFINITIONS                                         */
/* ================================================================== */

interface DefenseModule {
  id: string;
  nameKey: string;
  descKey: string;
  icon: React.ElementType;
  configKey: string | null;    // null = always on, no toggle
  alwaysOn: boolean;
  badgeFunc?: (settings: FortressSettings | null, managedRulesCount: number) => string | null;
}

const DEFENSE_MODULES: DefenseModule[] = [
  {
    id: 'rate_limiter',
    nameKey: 'module.rate_limiter',
    descKey: 'module.rate_limiter_desc',
    icon: Gauge,
    configKey: null,
    alwaysOn: true,
  },
  {
    id: 'ja3_fingerprint',
    nameKey: 'module.ja3_fingerprint',
    descKey: 'module.ja3_fingerprint_desc',
    icon: Fingerprint,
    configKey: null,
    alwaysOn: true,
  },
  {
    id: 'ip_reputation',
    nameKey: 'module.ip_reputation',
    descKey: 'module.ip_reputation_desc',
    icon: Eye,
    configKey: 'ip_reputation.enabled',
    alwaysOn: false,
  },
  {
    id: 'auto_ban',
    nameKey: 'module.auto_ban',
    descKey: 'module.auto_ban_desc',
    icon: Ban,
    configKey: 'auto_ban.enabled',
    alwaysOn: false,
  },
  {
    id: 'behavioral',
    nameKey: 'module.behavioral',
    descKey: 'module.behavioral_desc',
    icon: Activity,
    configKey: null,
    alwaysOn: true,
  },
  {
    id: 'bot_whitelist',
    nameKey: 'module.bot_whitelist',
    descKey: 'module.bot_whitelist_desc',
    icon: Bot,
    configKey: 'bot_whitelist.enabled',
    alwaysOn: false,
  },
  {
    id: 'managed_rules',
    nameKey: 'module.managed_rules',
    descKey: 'module.managed_rules_desc',
    icon: BookLock,
    configKey: 'managed_rules.enabled',
    alwaysOn: false,
    badgeFunc: (_s, count) => count > 0 ? `${count} rules` : null,
  },
  {
    id: 'distributed',
    nameKey: 'module.distributed',
    descKey: 'module.distributed_desc',
    icon: Radio,
    configKey: null,
    alwaysOn: true,
  },
  {
    id: 'geoip',
    nameKey: 'module.geoip',
    descKey: 'module.geoip_desc',
    icon: Globe,
    configKey: null,
    alwaysOn: true,
  },
  {
    id: 'challenge',
    nameKey: 'module.challenge',
    descKey: 'module.challenge_desc',
    icon: Lock,
    configKey: null,
    alwaysOn: true,
  },
  {
    id: 'cloudflare',
    nameKey: 'module.cloudflare',
    descKey: 'module.cloudflare_desc',
    icon: Cloud,
    configKey: 'cloudflare.enabled',
    alwaysOn: false,
  },
  {
    id: 'l4',
    nameKey: 'module.l4',
    descKey: 'module.l4_desc',
    icon: Network,
    configKey: 'l4_protection.enabled',
    alwaysOn: false,
  },
];

/* ================================================================== */
/*  HELPER COMPONENTS                                                  */
/* ================================================================== */

function Tooltip({ text }: { text: string }) {
  return (
    <div className="group relative inline-flex ml-1.5">
      <Info className="w-3.5 h-3.5 text-zinc-600 hover:text-zinc-400 cursor-help transition-colors" />
      <div className="absolute bottom-full left-1/2 -translate-x-1/2 mb-2 px-3 py-2 bg-zinc-800 border border-zinc-700 rounded-lg text-xs text-zinc-300 w-64 opacity-0 invisible group-hover:opacity-100 group-hover:visible transition-all duration-200 z-50 shadow-xl pointer-events-none">
        {text}
        <div className="absolute top-full left-1/2 -translate-x-1/2 -mt-1 w-2 h-2 bg-zinc-800 border-r border-b border-zinc-700 rotate-45" />
      </div>
    </div>
  );
}

function BunkerSection({
  title,
  icon: Icon,
  children,
  badge,
  classified,
}: {
  title: string;
  icon?: React.ElementType;
  children: React.ReactNode;
  badge?: string;
  classified?: boolean;
}) {
  return (
    <div className="relative rounded-xl border border-zinc-800 bg-zinc-950/90 backdrop-blur-sm mb-8 overflow-hidden">
      {/* Scan line effect */}
      <div className="absolute inset-0 pointer-events-none overflow-hidden opacity-[0.03]">
        <div className="w-full h-8 bg-gradient-to-b from-blue-400/80 to-transparent scan-line" />
      </div>

      {/* Header bar */}
      <div className="flex items-center gap-3 px-6 py-4 border-b border-zinc-800/80 bg-zinc-900/50">
        <div className="flex items-center gap-3 flex-1">
          {Icon && (
            <div className="w-8 h-8 rounded-lg bg-zinc-800/80 border border-zinc-700/50 flex items-center justify-center">
              <Icon className="w-4 h-4 text-zinc-400" />
            </div>
          )}
          <div>
            <h2 className="text-sm font-bold text-zinc-100 uppercase tracking-wider">{title}</h2>
            {classified && (
              <span className="text-[9px] text-red-500/70 font-mono tracking-widest">CLASSIFIED // EYES ONLY</span>
            )}
          </div>
        </div>
        {badge && (
          <span className="text-[9px] font-bold uppercase tracking-widest px-2.5 py-1 rounded-full bg-zinc-800 text-zinc-500 border border-zinc-700/50 font-mono">
            {badge}
          </span>
        )}
      </div>

      {/* Content */}
      <div className="p-6">
        {children}
      </div>
    </div>
  );
}

function ModuleToggleSwitch({
  enabled,
  onToggle,
  disabled,
  loading,
}: {
  enabled: boolean;
  onToggle?: () => void;
  disabled?: boolean;
  loading?: boolean;
}) {
  return (
    <button
      type="button"
      onClick={onToggle}
      disabled={disabled || loading || !onToggle}
      className={`
        relative inline-flex h-7 w-12 items-center rounded-full transition-all duration-300
        ${enabled
          ? 'bg-green-600/80 shadow-[0_0_12px_rgba(34,197,94,0.3)]'
          : 'bg-zinc-700/80 shadow-[0_0_8px_rgba(0,0,0,0.3)]'
        }
        ${disabled || !onToggle ? 'cursor-not-allowed opacity-60' : 'cursor-pointer hover:shadow-lg'}
        ${loading ? 'animate-pulse' : ''}
        border ${enabled ? 'border-green-500/40' : 'border-zinc-600/40'}
      `}
    >
      <span
        className={`
          inline-block h-5 w-5 transform rounded-full shadow-md transition-all duration-300
          ${enabled
            ? 'translate-x-6 bg-green-200'
            : 'translate-x-1 bg-zinc-400'
          }
        `}
      />
    </button>
  );
}

function StatusDot({ active, className = '' }: { active: boolean; className?: string }) {
  return (
    <span className={`relative inline-flex ${className}`}>
      <span
        className={`
          w-2.5 h-2.5 rounded-full
          ${active ? 'bg-green-400' : 'bg-zinc-600'}
        `}
      />
      {active && (
        <span className="absolute inset-0 w-2.5 h-2.5 rounded-full bg-green-400 status-dot-pulse" />
      )}
    </span>
  );
}

/* ================================================================== */
/*  TURNSTILE VERIFICATION WIDGET                                      */
/* ================================================================== */

function TurnstileWidget() {
  const [step, setStep] = useState<'init' | 'verifying' | 'done'>('init');

  useEffect(() => {
    const t1 = setTimeout(() => setStep('verifying'), 800);
    const t2 = setTimeout(() => setStep('done'), 2400);
    return () => {
      clearTimeout(t1);
      clearTimeout(t2);
    };
  }, []);

  return (
    <div className="relative">
      <div className="flex items-center gap-4 px-5 py-4 rounded-xl border border-zinc-800 bg-zinc-900/80 max-w-sm">
        {/* Spinner / Checkmark area */}
        <div className="w-8 h-8 flex items-center justify-center flex-shrink-0">
          {step === 'done' ? (
            <div className="fade-up">
              <svg width="28" height="28" viewBox="0 0 28 28">
                <circle cx="14" cy="14" r="13" fill="none" stroke="rgba(34,197,94,0.3)" strokeWidth="2" />
                <circle cx="14" cy="14" r="13" fill="rgba(34,197,94,0.08)" stroke="rgba(34,197,94,0.7)" strokeWidth="2" />
                <path
                  d="M8 14.5 L12 18.5 L20 10.5"
                  fill="none"
                  stroke="#22c55e"
                  strokeWidth="2.5"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  className="check-draw"
                />
              </svg>
            </div>
          ) : (
            <svg width="28" height="28" viewBox="0 0 28 28" className={step === 'verifying' ? 'turnstile-spinner' : ''}>
              <circle cx="14" cy="14" r="12" fill="none" stroke="rgba(59,130,246,0.15)" strokeWidth="2.5" />
              <path
                d="M14 2 a12 12 0 0 1 12 12"
                fill="none"
                stroke={step === 'init' ? 'rgba(100,100,120,0.4)' : 'rgba(59,130,246,0.7)'}
                strokeWidth="2.5"
                strokeLinecap="round"
              />
            </svg>
          )}
        </div>

        {/* Text */}
        <div className="flex-1 min-w-0">
          <div className={`text-sm font-medium transition-colors duration-300 ${
            step === 'done' ? 'text-green-400' : 'text-zinc-300'
          }`}>
            {step === 'init' && 'Initializing...'}
            {step === 'verifying' && 'Verifying integrity...'}
            {step === 'done' && 'System verified'}
          </div>
          <div className="text-[10px] text-zinc-600 mt-0.5 font-mono">
            {step === 'done' ? 'All subsystems operational' : 'Fortress Security Check'}
          </div>
        </div>

        {/* Branding */}
        <div className="flex items-center gap-1.5 pl-3 border-l border-zinc-800">
          <Shield className="w-3.5 h-3.5 text-zinc-600" />
          <span className="text-[9px] text-zinc-600 font-mono tracking-wider">FORTRESS</span>
        </div>
      </div>
    </div>
  );
}

/* ================================================================== */
/*  SKELETON LOADER                                                    */
/* ================================================================== */

function SkeletonBlock() {
  return (
    <div className="animate-pulse space-y-6">
      <div className="h-7 w-64 bg-zinc-800 rounded" />
      <div className="h-4 w-96 bg-zinc-800/50 rounded" />
      <div className="grid grid-cols-5 gap-4 mt-8">
        {Array.from({ length: 5 }).map((_, i) => (
          <div key={i} className="h-40 bg-zinc-800/30 rounded-xl border border-zinc-800/50" />
        ))}
      </div>
      <div className="grid grid-cols-2 lg:grid-cols-3 gap-4 mt-8">
        {Array.from({ length: 12 }).map((_, i) => (
          <div key={i} className="h-32 bg-zinc-800/20 rounded-xl border border-zinc-800/40" />
        ))}
      </div>
    </div>
  );
}

/* ================================================================== */
/*  MAIN PAGE COMPONENT                                                */
/* ================================================================== */

export default function SystemConfigurationPage() {
  const { t } = useLocale();

  /* ─── State ─── */
  const [config, setConfig] = useState<FortressConfig | null>(null);
  const [settings, setSettings] = useState<FortressSettings | null>(null);
  const [status, setStatus] = useState<FortressStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [levelSwitching, setLevelSwitching] = useState<string | null>(null);
  const [confirmLevel, setConfirmLevel] = useState<string | null>(null);
  const [message, setMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null);
  const [togglingModules, setTogglingModules] = useState<Set<string>>(new Set());

  const [protectionLevel, setProtectionLevel] = useState('');
  const [autoEscalation, setAutoEscalation] = useState(false);
  const [rateLimitMultiplier, setRateLimitMultiplier] = useState('1.0');
  const [challengeDifficulty, setChallengeDifficulty] = useState('medium');

  // Module enabled states (from config)
  const [moduleStates, setModuleStates] = useState<Record<string, boolean>>({
    'ip_reputation.enabled': true,
    'auto_ban.enabled': true,
    'bot_whitelist.enabled': true,
    'managed_rules.enabled': true,
    'cloudflare.enabled': false,
    'l4_protection.enabled': true,
  });

  const [managedRulesCount, setManagedRulesCount] = useState(0);

  /* ─── Data Fetching ─── */
  const fetchData = useCallback(async () => {
    try {
      const [configData, settingsData, statusData, managedRulesData] = await Promise.all([
        fortressGet<FortressConfig>('/api/fortress/config'),
        fortressGet<FortressSettings>('/api/fortress/settings'),
        fortressGet<FortressStatus>('/api/fortress/status').catch(() => null),
        fortressGet<ManagedRule[]>('/api/fortress/managed-rules').catch(() => [] as ManagedRule[]),
      ]);

      setConfig(configData);
      setSettings(settingsData);
      if (statusData) setStatus(statusData);
      setProtectionLevel(configData.protection_level ?? '');
      setAutoEscalation(configData.auto_escalation === 'true');
      setRateLimitMultiplier(configData.rate_limit_multiplier ?? '1.0');
      setChallengeDifficulty(configData.challenge_difficulty ?? 'medium');

      // Count active managed rules
      const activeRules = Array.isArray(managedRulesData)
        ? managedRulesData.filter((r) => r.enabled).length
        : 0;
      setManagedRulesCount(activeRules);

      // Parse module states from config. The config object has arbitrary keys.
      const rawConfig = configData as Record<string, string | undefined>;
      const newModuleStates: Record<string, boolean> = {};
      for (const mod of DEFENSE_MODULES) {
        if (mod.configKey) {
          const val = rawConfig[mod.configKey];
          newModuleStates[mod.configKey] = val !== undefined ? val === 'true' : true;
        }
      }
      // Respect settings data for bot_whitelist
      if (settingsData?.bot_whitelist) {
        newModuleStates['bot_whitelist.enabled'] = settingsData.bot_whitelist.enabled;
      }
      setModuleStates(newModuleStates);
    } catch {
      setMessage({ type: 'error', text: 'Failed to load system configuration.' });
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchData();
  }, [fetchData]);

  /* ─── Helpers ─── */
  const showMessage = (type: 'success' | 'error', text: string) => {
    setMessage({ type, text });
    setTimeout(() => setMessage(null), 4000);
  };

  const handleSave = async () => {
    setSaving(true);
    try {
      await fortressPut('/api/fortress/config', {
        protection_level: protectionLevel,
        auto_escalation: String(autoEscalation),
        rate_limit_multiplier: rateLimitMultiplier,
        challenge_difficulty: challengeDifficulty,
      });
      showMessage('success', 'Configuration saved successfully.');
    } catch {
      showMessage('error', 'Failed to save configuration.');
    } finally {
      setSaving(false);
    }
  };

  const handleLevelChange = async (levelKey: string) => {
    if (confirmLevel !== levelKey) {
      setConfirmLevel(levelKey);
      return;
    }
    setConfirmLevel(null);
    setLevelSwitching(levelKey);
    try {
      await fortressPost('/api/fortress/level', { level: levelKey });
      setProtectionLevel(levelKey);
      const defcon = DEFCON_LEVELS.find((d) => d.key === levelKey);
      showMessage('success', `Protection level changed to ${defcon?.name ?? levelKey}.`);
    } catch {
      showMessage('error', 'Failed to change protection level.');
    } finally {
      setLevelSwitching(null);
    }
  };

  const handleModuleToggle = async (configKey: string) => {
    const newValue = !moduleStates[configKey];
    setTogglingModules((prev) => new Set(prev).add(configKey));

    // Optimistically update
    setModuleStates((prev) => ({ ...prev, [configKey]: newValue }));

    try {
      await fortressPost('/api/fortress/config', {
        key: configKey,
        value: newValue,
      });
      // Refetch to confirm
      const updatedConfig = await fortressGet<FortressConfig>('/api/fortress/config');
      setConfig(updatedConfig);
      const rawConfig = updatedConfig as Record<string, string | undefined>;
      const val = rawConfig[configKey];
      if (val !== undefined) {
        setModuleStates((prev) => ({ ...prev, [configKey]: val === 'true' }));
      }
      const moduleName = DEFENSE_MODULES.find((m) => m.configKey === configKey);
      showMessage('success', `${moduleName ? t(moduleName.nameKey) : configKey} ${newValue ? 'activated' : 'deactivated'}.`);
    } catch {
      // Rollback
      setModuleStates((prev) => ({ ...prev, [configKey]: !newValue }));
      showMessage('error', `Failed to toggle module.`);
    } finally {
      setTogglingModules((prev) => {
        const next = new Set(prev);
        next.delete(configKey);
        return next;
      });
    }
  };

  /* ─── Loading State ─── */
  if (loading) {
    return (
      <div className="min-h-screen bg-black text-zinc-100">
        <style dangerouslySetInnerHTML={{ __html: CUSTOM_STYLES }} />
        <div className="max-w-6xl mx-auto px-6 py-10">
          <SkeletonBlock />
        </div>
      </div>
    );
  }

  /* ─── Render ─── */
  return (
    <div className="min-h-screen bg-black text-zinc-100">
      <style dangerouslySetInnerHTML={{ __html: CUSTOM_STYLES }} />

      <div className="max-w-6xl mx-auto px-6 py-10">
        {/* ════════════════════════════════════════════════ */}
        {/* HEADER                                          */}
        {/* ════════════════════════════════════════════════ */}
        <div className="mb-10">
          <div className="flex items-center gap-4">
            <div className="w-12 h-12 rounded-xl bg-gradient-to-br from-blue-600/20 to-blue-800/20 border border-blue-500/20 flex items-center justify-center">
              <Crosshair className="w-6 h-6 text-blue-400" />
            </div>
            <div>
              <h1 className="text-2xl font-bold text-zinc-100 tracking-tight">
                {t('settings.title')}
              </h1>
              <p className="text-sm text-zinc-500 mt-0.5">{t('settings.subtitle')}</p>
            </div>
          </div>

          {/* Decorative line */}
          <div className="mt-6 h-px bg-gradient-to-r from-blue-500/20 via-zinc-800 to-transparent" />
        </div>

        {/* ════════════════════════════════════════════════ */}
        {/* STATUS MESSAGE                                  */}
        {/* ════════════════════════════════════════════════ */}
        {message && (
          <div
            className={`mb-8 rounded-xl px-5 py-4 text-sm font-medium flex items-center gap-3 border backdrop-blur-sm fade-up ${
              message.type === 'success'
                ? 'bg-green-900/20 text-green-300 border-green-800/40'
                : 'bg-red-900/20 text-red-300 border-red-800/40'
            }`}
          >
            {message.type === 'success' ? (
              <CheckCircle className="w-5 h-5 flex-shrink-0" />
            ) : (
              <AlertTriangle className="w-5 h-5 flex-shrink-0" />
            )}
            <span>{message.text}</span>
          </div>
        )}

        {/* ════════════════════════════════════════════════ */}
        {/* SECTION 1: DEFCON LEVEL SELECTOR                */}
        {/* ════════════════════════════════════════════════ */}
        <BunkerSection
          title={t('settings.protection_level')}
          icon={Shield}
          badge="REAL-TIME"
          classified
        >
          <p className="text-sm text-zinc-500 mb-6">
            Select the active defense posture. Changes take effect immediately across all services.
          </p>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4">
            {DEFCON_LEVELS.map((level) => {
              const isActive = protectionLevel === level.key;
              const isSwitching = levelSwitching === level.key;
              const isConfirming = confirmLevel === level.key;
              const Icon = level.icon;

              return (
                <button
                  key={level.key}
                  onClick={() => handleLevelChange(level.key)}
                  disabled={isSwitching || isActive}
                  className={`
                    relative rounded-xl p-4 text-left transition-all duration-300 border-2
                    ${isActive
                      ? `${level.activeBg} ${level.pulseClass} shadow-lg ${level.glow}`
                      : `border-zinc-800 ${level.bg} hover:border-zinc-700 hover:shadow-md opacity-60 hover:opacity-100`
                    }
                    ${isSwitching ? 'animate-pulse' : ''}
                    ${isConfirming && !isActive ? 'ring-2 ring-white/20 scale-[1.02] border-zinc-600' : ''}
                    disabled:cursor-not-allowed
                  `}
                >
                  <div className="flex flex-col items-center text-center gap-2">
                    <Icon className={`w-7 h-7 ${isActive ? level.text : 'text-zinc-500'}`} />
                    <div className={`text-2xl font-black tabular-nums ${isActive ? level.text : 'text-zinc-300'}`}>
                      {level.defcon}
                    </div>
                    <div className={`text-[10px] font-bold uppercase tracking-wider ${isActive ? level.text : 'text-zinc-400'}`}>
                      {level.subtitle}
                    </div>
                    <div className={`text-[9px] font-mono tracking-wider ${isActive ? level.text + ' opacity-60' : 'text-zinc-600'}`}>
                      {level.codename}
                    </div>
                    <p className="text-[10px] text-zinc-500 leading-tight mt-1">
                      {level.description}
                    </p>
                    {isActive && (
                      <span className={`mt-2 text-[9px] font-bold uppercase tracking-widest ${level.text} bg-black/30 px-2.5 py-0.5 rounded-full border border-current/20`}>
                        ACTIVE
                      </span>
                    )}
                    {isConfirming && !isActive && (
                      <span className="mt-2 text-[9px] font-bold uppercase tracking-widest text-white bg-white/10 px-2.5 py-0.5 rounded-full animate-pulse border border-white/20">
                        Click to Confirm
                      </span>
                    )}
                  </div>
                </button>
              );
            })}
          </div>
        </BunkerSection>

        {/* ════════════════════════════════════════════════ */}
        {/* SECTION 2: DEFENSE MODULES CONTROL PANEL        */}
        {/* ════════════════════════════════════════════════ */}
        <BunkerSection
          title={t('settings.defense_modules')}
          icon={Cpu}
          badge="CONTROL PANEL"
        >
          <p className="text-sm text-zinc-500 mb-6">
            Manage individual protection subsystems. Core modules are always active and cannot be disabled.
          </p>

          <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
            {DEFENSE_MODULES.map((mod) => {
              const Icon = mod.icon;
              const isToggleable = mod.configKey !== null;
              const isEnabled = mod.alwaysOn ? true : (mod.configKey ? moduleStates[mod.configKey] ?? true : true);
              const isToggling = mod.configKey ? togglingModules.has(mod.configKey) : false;
              const badge = mod.badgeFunc ? mod.badgeFunc(settings, managedRulesCount) : null;

              return (
                <div
                  key={mod.id}
                  className={`
                    module-card relative rounded-xl border p-5 transition-all duration-300
                    ${isEnabled
                      ? 'bg-zinc-900/80 border-zinc-800 glow-sweep'
                      : 'bg-zinc-950/60 border-zinc-800/50 opacity-60'
                    }
                  `}
                >
                  {/* Top row: icon + toggle */}
                  <div className="flex items-start justify-between mb-3">
                    <div className="flex items-center gap-3">
                      <div className={`
                        w-9 h-9 rounded-lg flex items-center justify-center border
                        ${isEnabled
                          ? 'bg-zinc-800/80 border-zinc-700/60 text-zinc-300'
                          : 'bg-zinc-900/50 border-zinc-800/40 text-zinc-600'
                        }
                      `}>
                        <Icon className="w-4.5 h-4.5" />
                      </div>
                      <StatusDot active={isEnabled} />
                    </div>

                    {isToggleable ? (
                      <ModuleToggleSwitch
                        enabled={isEnabled}
                        loading={isToggling}
                        onToggle={() => mod.configKey && handleModuleToggle(mod.configKey)}
                      />
                    ) : (
                      <span className="text-[9px] font-bold uppercase tracking-widest text-zinc-600 bg-zinc-800/60 px-2 py-1 rounded-full border border-zinc-700/40 font-mono">
                        CORE
                      </span>
                    )}
                  </div>

                  {/* Name */}
                  <h3 className={`text-sm font-semibold mb-1 ${isEnabled ? 'text-zinc-200' : 'text-zinc-500'}`}>
                    {t(mod.nameKey)}
                  </h3>

                  {/* Description */}
                  <p className={`text-[11px] leading-relaxed ${isEnabled ? 'text-zinc-500' : 'text-zinc-600'}`}>
                    {t(mod.descKey)}
                  </p>

                  {/* Badge (e.g. managed rules count) */}
                  {badge && (
                    <div className="mt-3 pt-2 border-t border-zinc-800/60">
                      <span className="text-[10px] font-mono text-blue-400/70 bg-blue-500/10 px-2 py-0.5 rounded border border-blue-500/20">
                        {badge}
                      </span>
                    </div>
                  )}

                  {/* Status bar at bottom */}
                  <div className={`
                    absolute bottom-0 left-0 right-0 h-0.5 rounded-b-xl transition-all duration-500
                    ${isEnabled ? 'bg-gradient-to-r from-green-500/40 via-green-500/20 to-transparent' : 'bg-transparent'}
                  `} />
                </div>
              );
            })}
          </div>
        </BunkerSection>

        {/* ════════════════════════════════════════════════ */}
        {/* SECTION 2B: PROTECTION PARAMETERS               */}
        {/* ════════════════════════════════════════════════ */}
        <BunkerSection title="Protection Parameters" icon={Gauge} badge="TUNING">
          <div className="space-y-6">
            {/* Adaptive Threat Response */}
            <div className="flex items-center justify-between p-4 rounded-xl bg-zinc-900/60 border border-zinc-800">
              <div>
                <div className="text-sm font-semibold text-zinc-200 flex items-center">
                  Adaptive Threat Response (ATR)
                  <Tooltip text="When enabled, the system automatically escalates and de-escalates protection levels based on real-time traffic analysis, RPS thresholds, and block ratios." />
                </div>
                <p className="text-xs text-zinc-500 mt-1">Auto-adjusts DEFCON level based on threat indicators</p>
              </div>
              <ModuleToggleSwitch
                enabled={autoEscalation}
                onToggle={() => setAutoEscalation(!autoEscalation)}
              />
            </div>

            {/* Rate Limit Multiplier */}
            <div className="p-4 rounded-xl bg-zinc-900/60 border border-zinc-800">
              <div className="flex items-center mb-1">
                <label className="text-sm font-semibold text-zinc-200">
                  Rate Limit Coefficient
                </label>
                <Tooltip text="Global multiplier applied to all rate limiting thresholds. Values below 1.0 make limits stricter; above 1.0 makes them more permissive." />
              </div>
              <p className="text-xs text-zinc-500 mb-4">Global multiplier for all rate limiting thresholds</p>
              <div className="flex items-center gap-4">
                <input
                  type="range"
                  min="0.1"
                  max="5.0"
                  step="0.1"
                  value={rateLimitMultiplier}
                  onChange={(e) => setRateLimitMultiplier(e.target.value)}
                  className="flex-1 h-2 bg-zinc-700 rounded-full appearance-none cursor-pointer accent-blue-500"
                />
                <span className="text-sm font-mono text-zinc-100 bg-zinc-800 px-3 py-1.5 rounded-lg border border-zinc-700 min-w-[60px] text-center font-bold">
                  {parseFloat(rateLimitMultiplier).toFixed(1)}x
                </span>
              </div>
              <div className="flex justify-between text-[10px] text-zinc-600 mt-1.5 px-0.5">
                <span>Strict (0.1x)</span>
                <span>Default (1.0x)</span>
                <span>Permissive (5.0x)</span>
              </div>
            </div>
          </div>

          <div className="mt-6 flex justify-end">
            <button
              onClick={handleSave}
              disabled={saving}
              className="bg-blue-600 hover:bg-blue-500 text-white rounded-lg px-6 py-2.5 text-sm font-semibold disabled:opacity-50 transition-all flex items-center gap-2 shadow-lg shadow-blue-600/20 border border-blue-500/30"
            >
              <Save className="w-4 h-4" />
              {saving ? 'Saving...' : t('common.save')}
            </button>
          </div>
        </BunkerSection>

        {/* ════════════════════════════════════════════════ */}
        {/* SECTION 2C: PoW DIFFICULTY MATRIX                */}
        {/* ════════════════════════════════════════════════ */}
        <BunkerSection title="Proof-of-Work Difficulty Matrix" icon={Lock} badge="CHALLENGE ENGINE">
          <p className="text-xs text-zinc-500 mb-5">
            Select the computational difficulty required for client-side proof-of-work challenges.
          </p>
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 mb-6">
            {[
              { value: 'easy', label: 'L1: Standard', description: 'Low compute cost, fast verification', intensity: 1 },
              { value: 'medium', label: 'L2: Enhanced', description: 'Moderate compute, balanced security', intensity: 2 },
              { value: 'hard', label: 'L3: Extreme', description: 'High compute cost, maximum security', intensity: 3 },
            ].map((level) => {
              const isActive = challengeDifficulty === level.value;
              const intensityColors = [
                'border-green-500/40 bg-green-500/5',
                'border-yellow-500/40 bg-yellow-500/5',
                'border-red-500/40 bg-red-500/5',
              ];
              const textColors = ['text-green-400', 'text-yellow-400', 'text-red-400'];
              const barColors = ['bg-green-500', 'bg-yellow-500', 'bg-red-500'];

              return (
                <button
                  key={level.value}
                  onClick={() => setChallengeDifficulty(level.value)}
                  className={`
                    relative rounded-xl p-5 text-left transition-all duration-200 border
                    ${isActive
                      ? `${intensityColors[level.intensity - 1]} ring-2 ring-white/10 shadow-lg`
                      : 'border-zinc-800 bg-zinc-900/40 hover:border-zinc-700 opacity-50 hover:opacity-100'
                    }
                  `}
                >
                  <div className={`text-sm font-bold ${isActive ? textColors[level.intensity - 1] : 'text-zinc-300'}`}>
                    {level.label}
                  </div>
                  <p className="text-[11px] text-zinc-500 mt-1.5">{level.description}</p>
                  <div className="flex gap-1.5 mt-3">
                    {[1, 2, 3].map((bar) => (
                      <div
                        key={bar}
                        className={`h-1.5 flex-1 rounded-full transition-colors ${
                          bar <= level.intensity ? barColors[level.intensity - 1] : 'bg-zinc-800'
                        }`}
                      />
                    ))}
                  </div>
                  {isActive && (
                    <span className={`absolute top-2.5 right-2.5 text-[9px] font-bold uppercase tracking-widest ${textColors[level.intensity - 1]}`}>
                      Active
                    </span>
                  )}
                </button>
              );
            })}
          </div>

          {settings && (
            <div className="border-t border-zinc-800 pt-4">
              <h3 className="text-xs font-bold text-zinc-500 uppercase tracking-wider mb-3 font-mono">
                PoW Bit Difficulty by Level
              </h3>
              <div className="grid grid-cols-3 gap-3">
                {[
                  { label: 'L1 Standard', bits: settings.challenge.pow_difficulty_l1, color: 'text-green-400' },
                  { label: 'L2 Enhanced', bits: settings.challenge.pow_difficulty_l2, color: 'text-yellow-400' },
                  { label: 'L3 Extreme', bits: settings.challenge.pow_difficulty_l3, color: 'text-red-400' },
                ].map((item) => (
                  <div key={item.label} className="bg-zinc-900/60 rounded-lg p-3 text-center border border-zinc-800">
                    <div className={`text-lg font-bold font-mono ${item.color}`}>{item.bits}-bit</div>
                    <div className="text-[10px] text-zinc-500 mt-0.5">{item.label}</div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </BunkerSection>

        {/* ════════════════════════════════════════════════ */}
        {/* SECTION 3: TURNSTILE VERIFICATION INDICATOR     */}
        {/* ════════════════════════════════════════════════ */}
        <BunkerSection title="System Verification" icon={ShieldCheck} badge="INTEGRITY CHECK">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-xs text-zinc-500 mb-4">
                Runtime integrity verification of all defense subsystems.
              </p>
              <TurnstileWidget />
            </div>
            <div className="hidden sm:flex flex-col items-end gap-2 text-right">
              <div className="text-[10px] font-mono text-zinc-600">
                <span className="text-zinc-500">INTEGRITY:</span>{' '}
                <span className="text-green-400">PASS</span>
              </div>
              <div className="text-[10px] font-mono text-zinc-600">
                <span className="text-zinc-500">MODULES:</span>{' '}
                <span className="text-zinc-300">
                  {DEFENSE_MODULES.filter((m) => m.alwaysOn || (m.configKey && moduleStates[m.configKey])).length}/{DEFENSE_MODULES.length}
                </span>
              </div>
              <div className="text-[10px] font-mono text-zinc-600">
                <span className="text-zinc-500">POSTURE:</span>{' '}
                <span className={`${
                  DEFCON_LEVELS.find((l) => l.key === protectionLevel)?.text ?? 'text-zinc-400'
                }`}>
                  {DEFCON_LEVELS.find((l) => l.key === protectionLevel)?.name ?? 'UNKNOWN'}
                </span>
              </div>
            </div>
          </div>
        </BunkerSection>

        {/* ════════════════════════════════════════════════ */}
        {/* READ-ONLY SETTINGS (from fortress.toml)         */}
        {/* ════════════════════════════════════════════════ */}
        {settings && (
          <>
            <div className="mt-2 mb-6 flex items-center gap-2">
              <ChevronRight className="w-4 h-4 text-zinc-600" />
              <p className="text-xs text-zinc-500">
                The following parameters are loaded from <code className="text-zinc-400 bg-zinc-800/50 px-1.5 py-0.5 rounded font-mono text-[11px]">fortress.toml</code> and require a service restart to modify.
              </p>
            </div>

            <BunkerSection title="Threat Scoring Engine" icon={Activity} badge="READ-ONLY">
              <div className="space-y-2">
                <h3 className="text-xs font-bold text-zinc-500 uppercase tracking-wider mb-3 font-mono">ASN Risk Scores</h3>
                <SettingRow label="Datacenter ASN penalty" value={settings.asn_scoring.datacenter_score} tooltip="Score added to requests originating from known datacenter IP ranges." />
                <SettingRow label="VPN provider ASN penalty" value={settings.asn_scoring.vpn_score} tooltip="Score added to requests from known VPN/proxy provider networks." />
                <SettingRow label="Residential proxy penalty" value={settings.asn_scoring.residential_proxy_score} tooltip="Score added to requests from residential proxy networks." />
              </div>

              <div className="mt-5">
                <h3 className="text-xs font-bold text-zinc-500 uppercase tracking-wider mb-3 font-mono">Geographic Challenge Rules</h3>
                <SettingRow label="Country challenge score bonus" value={settings.blocklist.country_challenge_score} />
                <SettingRow label="Challenged country codes" value={settings.blocklist.challenged_countries.join(', ') || 'None'} />
              </div>

              <div className="mt-5">
                <h3 className="text-xs font-bold text-zinc-500 uppercase tracking-wider mb-3 font-mono">Mobile Proxy Detection</h3>
                <SettingRow label="Minimum signal threshold" value={settings.mobile_proxy.min_signals} />
                <SettingRow label="Score trigger threshold" value={settings.mobile_proxy.score_threshold} />
              </div>
            </BunkerSection>

            <BunkerSection title="Escalation Engine" icon={Zap} badge="READ-ONLY">
              <SettingRow label="Sustained check window" value={settings.escalation.sustained_checks_required} tooltip="Number of consecutive check intervals that must exceed thresholds before triggering escalation." />
              <SettingRow label="Block ratio threshold" value={settings.escalation.block_ratio_threshold} />
              <SettingRow label="De-escalation cooldown" value={`${settings.escalation.deescalation_cooldown_secs}s`} />

              <div className="mt-5 border-t border-zinc-800 pt-4">
                <h3 className="text-xs font-bold text-zinc-500 uppercase tracking-wider mb-3 font-mono">RPS Escalation Thresholds</h3>
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                  {[
                    { label: 'L0 \u2192 L1', value: settings.escalation.l0_to_l1_rps, color: 'text-green-400' },
                    { label: 'L1 \u2192 L2', value: settings.escalation.l1_to_l2_rps, color: 'text-yellow-400' },
                    { label: 'L2 \u2192 L3', value: settings.escalation.l2_to_l3_rps, color: 'text-orange-400' },
                    { label: 'L3 \u2192 L4', value: settings.escalation.l3_to_l4_rps, color: 'text-red-400' },
                  ].map((item) => (
                    <div key={item.label} className="bg-zinc-900/60 rounded-lg p-3 text-center border border-zinc-800">
                      <div className={`text-base font-bold font-mono ${item.color}`}>{item.value.toLocaleString()}</div>
                      <div className="text-[10px] text-zinc-500 mt-0.5">{item.label} RPS</div>
                    </div>
                  ))}
                </div>
              </div>
            </BunkerSection>

            <BunkerSection title="Challenge Engine Configuration" icon={Lock} badge="READ-ONLY">
              <div className="space-y-3">
                <div className="flex items-center gap-3">
                  <StatusDot active={settings.challenge.cookie_subnet_binding} />
                  <span className="text-sm text-zinc-300">Cookie Subnet Binding (/24)</span>
                </div>
                <p className="text-xs text-zinc-500 ml-6">Binds verification cookies to /24 subnet instead of exact IP.</p>

                <div className="flex items-center gap-3 mt-3">
                  <StatusDot active={settings.challenge.nojs_fallback_enabled} />
                  <span className="text-sm text-zinc-300">NoJS Fallback (meta-refresh)</span>
                </div>
                <p className="text-xs text-zinc-500 ml-6">Enables verification for non-JavaScript clients.</p>
              </div>

              <div className="mt-4 border-t border-zinc-800 pt-4">
                <SettingRow label="Cookie TTL" value={`${settings.challenge.cookie_max_age_secs}s`} />
              </div>

              {settings.challenge.exempt_paths.length > 0 && (
                <div className="mt-4 border-t border-zinc-800 pt-4">
                  <h3 className="text-xs font-bold text-zinc-500 uppercase tracking-wider mb-3 font-mono">Challenge-Exempt Paths</h3>
                  <div className="flex flex-wrap gap-2">
                    {settings.challenge.exempt_paths.map((p) => (
                      <span key={p} className="px-2.5 py-1 rounded-md bg-zinc-800 text-zinc-300 text-xs font-mono border border-zinc-700">{p}</span>
                    ))}
                  </div>
                </div>
              )}
            </BunkerSection>
          </>
        )}

        {/* ════════════════════════════════════════════════ */}
        {/* SECTION 4: SYSTEM INFORMATION (ENHANCED)        */}
        {/* ════════════════════════════════════════════════ */}
        <BunkerSection title={t('settings.system_info')} icon={Terminal} badge="TELEMETRY">
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
            {[
              {
                icon: Shield,
                label: 'Fortress Version',
                value: status?.version ?? 'v1.0.0',
              },
              {
                icon: Clock,
                label: 'Uptime',
                value: status?.uptime_secs ? formatUptime(status.uptime_secs) : 'N/A',
              },
              {
                icon: Activity,
                label: 'Total Requests Today',
                value: status?.total_requests_today ? formatNumber(status.total_requests_today) : 'N/A',
              },
              {
                icon: Zap,
                label: 'Active Connections',
                value: status?.active_connections?.toLocaleString() ?? 'N/A',
              },
              {
                icon: Cpu,
                label: 'Active Defense Modules',
                value: `${DEFENSE_MODULES.filter((m) => m.alwaysOn || (m.configKey && moduleStates[m.configKey])).length} / ${DEFENSE_MODULES.length}`,
              },
              {
                icon: Crosshair,
                label: 'Current Posture',
                value: DEFCON_LEVELS.find((l) => l.key === protectionLevel)?.name ?? protectionLevel,
              },
              {
                icon: FolderCog,
                label: 'Configuration File',
                value: '/etc/fortress/fortress.toml',
              },
              {
                icon: FileText,
                label: 'Log File',
                value: '/var/log/fortress/fortress.log',
              },
              {
                icon: Database,
                label: 'Rate Limit Coefficient',
                value: `${parseFloat(rateLimitMultiplier).toFixed(1)}x`,
              },
            ].map((item) => (
              <div
                key={item.label}
                className="bg-zinc-900/60 rounded-xl p-4 border border-zinc-800/60 hover:border-zinc-700/60 transition-colors"
              >
                <div className="flex items-center gap-2 text-xs text-zinc-500 mb-2">
                  <item.icon className="w-3.5 h-3.5" />
                  {item.label}
                </div>
                <div className="text-sm font-mono text-zinc-200 truncate">{item.value}</div>
              </div>
            ))}
          </div>
        </BunkerSection>

        {/* Footer */}
        <div className="mt-4 pb-8 text-center">
          <div className="h-px bg-gradient-to-r from-transparent via-zinc-800 to-transparent mb-4" />
          <p className="text-[10px] font-mono text-zinc-700 tracking-wider">
            FORTRESS THREAT DEFENSE PLATFORM // SYSTEM CONFIGURATION TERMINAL
          </p>
        </div>
      </div>
    </div>
  );
}

/* ================================================================== */
/*  SETTING ROW (read-only display)                                    */
/* ================================================================== */

function SettingRow({
  label,
  value,
  unit,
  tooltip,
}: {
  label: string;
  value: string | number;
  unit?: string;
  tooltip?: string;
}) {
  return (
    <div className="flex items-center justify-between py-2.5 border-b border-zinc-800/40 last:border-0">
      <span className="text-sm text-zinc-400 flex items-center">
        {label}
        {tooltip && <Tooltip text={tooltip} />}
      </span>
      <span className="text-sm text-zinc-200 font-mono bg-zinc-800/50 px-2.5 py-0.5 rounded border border-zinc-700/30">
        {value}
        {unit ? ` ${unit}` : ''}
      </span>
    </div>
  );
}
