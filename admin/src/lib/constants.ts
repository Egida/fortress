// ============================================================================
// FORTRESS - Core Constants & Utility Functions
// Classification: INTERNAL USE ONLY
// ============================================================================

// ---------------------------------------------------------------------------
// Protection Level Definitions (DEFCON-style threat posture)
// ---------------------------------------------------------------------------

export const PROTECTION_LEVELS: Record<string, {
  level: number;
  name: string;
  label: string;
  codename: string;
  color: string;
  textColor: string;
  bg: string;
  borderColor: string;
  dotColor: string;
  description: string;
}> = {
  Normal: {
    level: 0,
    name: 'Passive Monitoring',
    label: 'DEFCON 5',
    codename: 'GREENFIELD',
    color: 'bg-emerald-500/20',
    textColor: 'text-emerald-400',
    bg: '#10b98120',
    borderColor: 'border-emerald-500/30',
    dotColor: 'bg-emerald-400',
    description: 'Baseline traffic analysis. Standard rate limiting. Minimal intervention.',
  },
  High: {
    level: 1,
    name: 'Active Defense',
    label: 'DEFCON 4',
    codename: 'WATCHGUARD',
    color: 'bg-blue-500/20',
    textColor: 'text-blue-400',
    bg: '#3b82f620',
    borderColor: 'border-blue-500/30',
    dotColor: 'bg-blue-400',
    description: 'JS challenge for anomalous fingerprints. Elevated behavioral analysis.',
  },
  UnderAttack: {
    level: 2,
    name: 'Threat Engagement',
    label: 'DEFCON 3',
    codename: 'IRONCLAD',
    color: 'bg-yellow-500/20',
    textColor: 'text-yellow-400',
    bg: '#eab30820',
    borderColor: 'border-yellow-500/30',
    dotColor: 'bg-yellow-400',
    description: 'Mandatory PoW challenge. Aggressive rate limiting. ASN scoring active.',
  },
  Severe: {
    level: 3,
    name: 'Maximum Defense',
    label: 'DEFCON 2',
    codename: 'BLACKSTORM',
    color: 'bg-orange-500/20',
    textColor: 'text-orange-400',
    bg: '#f9731620',
    borderColor: 'border-orange-500/30',
    dotColor: 'bg-orange-400',
    description: 'High-difficulty PoW. Auto-ban escalation. Distributed attack countermeasures.',
  },
  Emergency: {
    level: 4,
    name: 'Full Lockdown',
    label: 'DEFCON 1',
    codename: 'DEADBOLT',
    color: 'bg-red-500/20',
    textColor: 'text-red-400',
    bg: '#ef444420',
    borderColor: 'border-red-500/30',
    dotColor: 'bg-red-500',
    description: 'Emergency mode. All traffic challenged. Only whitelisted IPs pass.',
  },
};

export const PROTECTION_LEVELS_LIST = Object.values(PROTECTION_LEVELS).sort((a, b) => a.level - b.level);

// ---------------------------------------------------------------------------
// Action Colors
// ---------------------------------------------------------------------------

export const ACTION_COLORS: Record<string, string> = {
  Pass: '#22c55e',
  Challenge: '#f59e0b',
  Block: '#ef4444',
  Tarpit: '#a855f7',
  RateLimit: '#f97316',
  Captcha: '#06b6d4',
  Drop: '#dc2626',
};

// ---------------------------------------------------------------------------
// Threat Categories
// ---------------------------------------------------------------------------

export const THREAT_CATEGORIES: Record<string, {
  id: string;
  name: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  color: string;
  description: string;
}> = {
  VOLUMETRIC: {
    id: 'VOLUMETRIC',
    name: 'Volumetric Flood',
    severity: 'high',
    color: '#ef4444',
    description: 'High-bandwidth attacks designed to saturate network capacity (UDP flood, ICMP flood, amplification).',
  },
  PROTOCOL: {
    id: 'PROTOCOL',
    name: 'Protocol Exploitation',
    severity: 'high',
    color: '#f97316',
    description: 'Attacks targeting protocol weaknesses (SYN flood, fragmented packets, Ping of Death).',
  },
  APPLICATION: {
    id: 'APPLICATION',
    name: 'Application Layer',
    severity: 'critical',
    color: '#dc2626',
    description: 'Layer 7 attacks targeting application logic (HTTP flood, Slowloris, API abuse).',
  },
  CREDENTIAL: {
    id: 'CREDENTIAL',
    name: 'Credential Stuffing',
    severity: 'medium',
    color: '#eab308',
    description: 'Automated login attempts using leaked credential databases.',
  },
  SCRAPING: {
    id: 'SCRAPING',
    name: 'Automated Scraping',
    severity: 'low',
    color: '#3b82f6',
    description: 'Bot-driven content extraction bypassing rate limits and access controls.',
  },
  RECONNAISSANCE: {
    id: 'RECONNAISSANCE',
    name: 'Reconnaissance',
    severity: 'medium',
    color: '#a855f7',
    description: 'Port scanning, vulnerability probing, and fingerprinting activity.',
  },
  ZERO_DAY: {
    id: 'ZERO_DAY',
    name: 'Zero-Day Exploit',
    severity: 'critical',
    color: '#991b1b',
    description: 'Unpatched vulnerability exploitation attempts detected via behavioral heuristics.',
  },
  BOT_NETWORK: {
    id: 'BOT_NETWORK',
    name: 'Botnet Activity',
    severity: 'high',
    color: '#b91c1c',
    description: 'Coordinated traffic from known botnet infrastructure (Mirai, Meris variants).',
  },
};

// ---------------------------------------------------------------------------
// Attack Vectors
// ---------------------------------------------------------------------------

export const ATTACK_VECTORS: readonly string[] = [
  'HTTP GET Flood',
  'HTTP POST Flood',
  'Slowloris',
  'RUDY (R-U-Dead-Yet)',
  'SYN Flood',
  'UDP Amplification',
  'DNS Reflection',
  'NTP Amplification',
  'SSDP Amplification',
  'Memcached Reflection',
  'TCP RST Flood',
  'ACK Flood',
  'GRE Flood',
  'ICMP Flood',
  'Fragmentation Attack',
  'SSL/TLS Exhaustion',
  'WebSocket Abuse',
  'API Enumeration',
  'Credential Stuffing',
  'Cache Poisoning',
  'Request Smuggling',
  'Path Traversal Probe',
  'XML-RPC Pingback',
  'WordPress Amplification',
  'Layer 7 Randomized',
  'Browser Impersonation',
  'Headless Chrome Flood',
  'Distributed Slow Read',
] as const;

// ---------------------------------------------------------------------------
// Response Actions
// ---------------------------------------------------------------------------

export const RESPONSE_ACTIONS: Record<string, {
  id: string;
  name: string;
  description: string;
  severity: 'passive' | 'moderate' | 'aggressive' | 'nuclear';
  icon: string;
}> = {
  MONITOR: {
    id: 'MONITOR',
    name: 'Silent Monitor',
    description: 'Log and track without intervention. Feed data to behavioral analysis engine.',
    severity: 'passive',
    icon: 'eye',
  },
  RATE_LIMIT: {
    id: 'RATE_LIMIT',
    name: 'Rate Limiter',
    description: 'Enforce per-IP and per-subnet request quotas with sliding window algorithm.',
    severity: 'moderate',
    icon: 'gauge',
  },
  JS_CHALLENGE: {
    id: 'JS_CHALLENGE',
    name: 'JavaScript Challenge',
    description: 'Deploy client-side JS computation challenge to verify browser authenticity.',
    severity: 'moderate',
    icon: 'code',
  },
  POW_CHALLENGE: {
    id: 'POW_CHALLENGE',
    name: 'Proof-of-Work Challenge',
    description: 'Require computational proof-of-work (Hashcash variant) before granting access.',
    severity: 'aggressive',
    icon: 'cpu',
  },
  CAPTCHA: {
    id: 'CAPTCHA',
    name: 'CAPTCHA Verification',
    description: 'Present visual or interactive CAPTCHA challenge to filter automated traffic.',
    severity: 'aggressive',
    icon: 'shield-question',
  },
  TARPIT: {
    id: 'TARPIT',
    name: 'Connection Tarpit',
    description: 'Deliberately slow response to waste attacker resources and TCP connections.',
    severity: 'aggressive',
    icon: 'hourglass',
  },
  BLOCK: {
    id: 'BLOCK',
    name: 'IP Block',
    description: 'Immediately drop all connections from source IP. Add to temporary blocklist.',
    severity: 'aggressive',
    icon: 'ban',
  },
  SUBNET_BAN: {
    id: 'SUBNET_BAN',
    name: 'Subnet-Level Ban',
    description: 'Block entire /24 or /48 subnet when distributed patterns detected from same range.',
    severity: 'nuclear',
    icon: 'network',
  },
  ASN_BLOCK: {
    id: 'ASN_BLOCK',
    name: 'ASN Block',
    description: 'Block all traffic originating from identified autonomous system number.',
    severity: 'nuclear',
    icon: 'globe',
  },
  GEO_FENCE: {
    id: 'GEO_FENCE',
    name: 'Geofence Enforcement',
    description: 'Restrict or challenge traffic based on geographic origin using MaxMind GeoIP.',
    severity: 'nuclear',
    icon: 'map-pin',
  },
};

// ---------------------------------------------------------------------------
// Utility Functions
// ---------------------------------------------------------------------------

export function formatUptime(secs: number): string {
  const d = Math.floor(secs / 86400);
  const h = Math.floor((secs % 86400) / 3600);
  const m = Math.floor((secs % 3600) / 60);
  if (d > 0) return `${d}d ${h}h ${m}m`;
  if (h > 0) return `${h}h ${m}m`;
  return `${m}m`;
}

export function formatNumber(n: number): string {
  if (n >= 1_000_000_000) return (n / 1_000_000_000).toFixed(1) + 'B';
  if (n >= 1_000_000) return (n / 1_000_000).toFixed(1) + 'M';
  if (n >= 1_000) return (n / 1_000).toFixed(1) + 'K';
  return n.toFixed(0);
}

export function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
  const exponent = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
  const value = bytes / Math.pow(1024, exponent);
  return `${value >= 100 ? value.toFixed(0) : value >= 10 ? value.toFixed(1) : value.toFixed(2)} ${units[exponent]}`;
}

export function formatDuration(seconds: number): string {
  if (seconds < 0) return '0s';
  if (seconds < 60) return `${Math.round(seconds)}s`;

  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  const secs = Math.round(seconds % 60);

  const parts: string[] = [];
  if (days > 0) parts.push(`${days}d`);
  if (hours > 0) parts.push(`${hours}h`);
  if (minutes > 0) parts.push(`${minutes}m`);
  if (secs > 0 && days === 0) parts.push(`${secs}s`);

  return parts.join(' ');
}

export function getRelativeTime(timestamp: string | number | Date): string {
  const now = Date.now();
  const then = typeof timestamp === 'string'
    ? new Date(timestamp).getTime()
    : typeof timestamp === 'number'
      ? timestamp
      : timestamp.getTime();

  const diffMs = now - then;
  const diffSecs = Math.floor(diffMs / 1000);

  if (diffSecs < 5) return 'just now';
  if (diffSecs < 60) return `${diffSecs}s ago`;

  const diffMins = Math.floor(diffSecs / 60);
  if (diffMins < 60) return `${diffMins}m ago`;

  const diffHours = Math.floor(diffMins / 60);
  if (diffHours < 24) return `${diffHours}h ago`;

  const diffDays = Math.floor(diffHours / 24);
  if (diffDays < 7) return `${diffDays}d ago`;

  const diffWeeks = Math.floor(diffDays / 7);
  if (diffWeeks < 4) return `${diffWeeks}w ago`;

  const diffMonths = Math.floor(diffDays / 30);
  if (diffMonths < 12) return `${diffMonths}mo ago`;

  const diffYears = Math.floor(diffDays / 365);
  return `${diffYears}y ago`;
}
