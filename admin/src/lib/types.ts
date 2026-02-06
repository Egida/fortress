// FORTRESS - Type Definitions
// Classification: INTERNAL USE ONLY

// ---------------------------------------------------------------------------
// Core Status & Metrics
// ---------------------------------------------------------------------------

export interface FortressStatus {
  active_connections: number;
  protection_level: string;
  total_requests_today: number;
  uptime_secs: number;
  version: string;
}

export interface FortressMetrics {
  rps: number;
  blocked_per_sec: number;
  challenged_per_sec: number;
  passed_per_sec: number;
  unique_ips: number;
  avg_latency_ms: number;
  total_requests: number;
  total_blocked: number;
  uptime_secs: number;
}

export interface SecondSnapshot {
  timestamp: number;
  requests: number;
  passed: number;
  blocked: number;
  challenged: number;
}

// ---------------------------------------------------------------------------
// Traffic & Threat Data
// ---------------------------------------------------------------------------

export interface TopCountryEntry {
  country: string;
  requests: number;
  blocked: number;
}

export interface ThreatEntry {
  ip: string;
  type: string;
  country?: string;
  timestamp?: string;
}

export interface LiveTrafficEvent {
  timestamp: string;
  client_ip: string;
  country_code: string;
  asn: number;
  method: string;
  path: string;
  host: string;
  status_code: number;
  action: string;
  reason: string | null;
  latency_ms: number;
  user_agent: string;
  ja3_hash: string | null;
  behavioral_score: number;
}

// ---------------------------------------------------------------------------
// Blocklist Entities
// ---------------------------------------------------------------------------

export interface BlockedIp {
  id: number;
  ip: string;
  cidr: string | null;
  reason: string;
  source: string;
  created_at: string;
  expires_at: string | null;
}

export interface BlockedAsn {
  id: number;
  asn: number;
  name: string | null;
  action: string;
  reason: string | null;
  created_at: string;
}

export interface BlockedCountry {
  id: number;
  country_code: string;
  country_name: string | null;
  action: string;
  reason: string | null;
  created_at: string;
}

// ---------------------------------------------------------------------------
// Rules & Policies
// ---------------------------------------------------------------------------

export interface ProtectionRule {
  id: number;
  name: string;
  priority: number;
  conditions_json: string;
  action: string;
  enabled: boolean;
  created_at: string;
}

export interface ManagedRule {
  id: number;
  name: string;
  description: string;
  enabled: boolean;
}

// ---------------------------------------------------------------------------
// Attacks
// ---------------------------------------------------------------------------

export interface Attack {
  id: number;
  started_at: string;
  ended_at: string | null;
  peak_rps: number;
  total_requests: number;
  unique_ips: number;
  max_level: number;
  severity: string;
  top_countries_json: string | null;
  top_ips_json: string | null;
}

// ---------------------------------------------------------------------------
// Service Configuration
// ---------------------------------------------------------------------------

export interface ServiceConfig {
  id: string;
  name: string;
  domains: string[];
  upstream_address: string;
  enabled: boolean;
  protection_level_override: number | null;
  always_challenge: boolean;
  rate_limit_multiplier: number;
  max_connections: number;
  connect_timeout_ms: number;
  response_timeout_ms: number;
}

// ---------------------------------------------------------------------------
// Layer 4 Protection
// ---------------------------------------------------------------------------

export interface L4Metrics {
  total_allowed: number;
  total_dropped: number;
  total_tarpitted: number;
  tracked_ips: number;
}

export interface L4Event {
  id: number;
  timestamp: string;
  client_ip: string;
  action: string;
  reason: string | null;
  concurrent_connections: number | null;
  connection_rate: number | null;
}

// ---------------------------------------------------------------------------
// Analytics
// ---------------------------------------------------------------------------

export interface AnalyticsData {
  snapshot: FortressMetrics;
  top_ips: { ip: string; count: number }[];
  top_countries: { country: string; count: number }[];
  top_asns: { asn: number; count: number }[];
  top_fingerprints: { fingerprint: string; count: number }[];
}

export interface MetricsHistoryResponse {
  granularity: string;
  data: SecondSnapshot[];
}

// ---------------------------------------------------------------------------
// Configuration & Settings
// ---------------------------------------------------------------------------

export interface FortressConfig {
  protection_level?: string;
  auto_escalation?: string;
  rate_limit_multiplier?: string;
  challenge_difficulty?: string;
}

export interface FortressSettings {
  bot_whitelist: {
    enabled: boolean;
    verify_ip: boolean;
  };
  mobile_proxy: {
    min_signals: number;
    score_threshold: number;
  };
  asn_scoring: {
    datacenter_score: number;
    vpn_score: number;
    residential_proxy_score: number;
  };
  escalation: {
    sustained_checks_required: number;
    block_ratio_threshold: number;
    deescalation_cooldown_secs: number;
    l0_to_l1_rps: number;
    l1_to_l2_rps: number;
    l2_to_l3_rps: number;
    l3_to_l4_rps: number;
  };
  challenge: {
    cookie_subnet_binding: boolean;
    nojs_fallback_enabled: boolean;
    pow_difficulty_l1: number;
    pow_difficulty_l2: number;
    pow_difficulty_l3: number;
    cookie_max_age_secs: number;
    exempt_paths: string[];
  };
  blocklist: {
    country_challenge_score: number;
    challenged_countries: string[];
    blocked_countries: string[];
  };
  protection: {
    default_level: number;
    auto_escalation: boolean;
    ipv4_subnet_mask: number;
  };
}

// ---------------------------------------------------------------------------
// IP Reputation & Auto-Ban
// ---------------------------------------------------------------------------

export interface IpReputationEntry {
  ip: string;
  score: number;
  total_requests: number;
  blocked_count: number;
  categories: string[];
}

export interface AutoBanEntry {
  ip: string;
  reason: string;
  remaining_secs: number;
  total_duration_secs: number;
}

// ---------------------------------------------------------------------------
// Threat Summary
// ---------------------------------------------------------------------------

export interface ThreatSummary {
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

// NEW INTERFACES - Threat Intelligence & Security Operations

// ---------------------------------------------------------------------------
// Threat Intelligence
// ---------------------------------------------------------------------------

export interface ThreatIntelligence {
  /** Unique identifier for the threat intel record */
  id: string;
  /** Source feed (e.g., 'abuse-ipdb', 'emerging-threats', 'fortress-internal') */
  source: string;
  /** Indicator of Compromise type */
  ioc_type: 'ip' | 'cidr' | 'asn' | 'ja3' | 'user_agent' | 'domain';
  /** The actual IOC value */
  ioc_value: string;
  /** Threat category classification */
  threat_category: string;
  /** Confidence score from 0 to 100 */
  confidence_score: number;
  /** Severity level */
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
  /** First seen timestamp (ISO 8601) */
  first_seen: string;
  /** Last seen timestamp (ISO 8601) */
  last_seen: string;
  /** Number of times this IOC has been observed */
  sighting_count: number;
  /** Associated tags for categorization */
  tags: string[];
  /** Geographic origin (ISO country code) */
  origin_country: string | null;
  /** Associated autonomous system number */
  origin_asn: number | null;
  /** Whether this IOC is actively being used in the blocklist */
  is_active: boolean;
  /** Time-to-live in seconds before the record expires */
  ttl_secs: number;
  /** Raw feed metadata */
  metadata: Record<string, unknown>;
}

// ---------------------------------------------------------------------------
// Security Event
// ---------------------------------------------------------------------------

export interface SecurityEvent {
  /** Unique event identifier */
  id: string;
  /** Event timestamp (ISO 8601) */
  timestamp: string;
  /** Event classification */
  event_type:
    | 'intrusion_attempt'
    | 'brute_force'
    | 'rate_limit_exceeded'
    | 'challenge_failed'
    | 'anomaly_detected'
    | 'policy_violation'
    | 'escalation_triggered'
    | 'deescalation_triggered'
    | 'auto_ban_applied'
    | 'auto_ban_expired'
    | 'config_change'
    | 'certificate_event';
  /** Severity of the event */
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
  /** Source IP address (if applicable) */
  source_ip: string | null;
  /** Source country code */
  source_country: string | null;
  /** Source ASN */
  source_asn: number | null;
  /** Target service or domain */
  target_service: string | null;
  /** Human-readable event description */
  description: string;
  /** Action taken in response */
  action_taken: string;
  /** Whether the event was resolved or is ongoing */
  resolved: boolean;
  /** The protection level at the time of the event */
  protection_level: string;
  /** Request method if HTTP-related */
  request_method: string | null;
  /** Request path if HTTP-related */
  request_path: string | null;
  /** JA3 fingerprint hash */
  ja3_hash: string | null;
  /** Behavioral analysis score (0-100, higher = more suspicious) */
  behavioral_score: number | null;
  /** Related event IDs for correlation */
  related_events: string[];
  /** Additional contextual data */
  context: Record<string, unknown>;
}

// ---------------------------------------------------------------------------
// SSL/TLS Certificate
// ---------------------------------------------------------------------------

export interface SSLCertificate {
  /** Certificate unique identifier */
  id: string;
  /** Associated domain(s) */
  domains: string[];
  /** Certificate issuer (e.g., 'Let\'s Encrypt', 'Cloudflare') */
  issuer: string;
  /** Certificate serial number */
  serial_number: string;
  /** SHA-256 fingerprint of the certificate */
  fingerprint_sha256: string;
  /** Certificate validity start (ISO 8601) */
  valid_from: string;
  /** Certificate validity end (ISO 8601) */
  valid_to: string;
  /** Whether the certificate is currently active */
  is_active: boolean;
  /** Whether auto-renewal is enabled */
  auto_renew: boolean;
  /** Days until expiration */
  days_until_expiry: number;
  /** Certificate status */
  status: 'valid' | 'expiring_soon' | 'expired' | 'revoked' | 'pending_issuance';
  /** Key algorithm (e.g., 'RSA-2048', 'ECDSA-P256') */
  key_algorithm: string;
  /** TLS protocol versions supported */
  tls_versions: string[];
  /** Last renewal attempt timestamp */
  last_renewal_attempt: string | null;
  /** Last renewal error message */
  last_renewal_error: string | null;
}

// ---------------------------------------------------------------------------
// Firewall Event
// ---------------------------------------------------------------------------

export interface FirewallEvent {
  /** Event unique identifier */
  id: string;
  /** Event timestamp (ISO 8601) */
  timestamp: string;
  /** Firewall rule that triggered */
  rule_id: string;
  /** Rule name */
  rule_name: string;
  /** Action executed */
  action: 'allow' | 'block' | 'challenge' | 'rate_limit' | 'tarpit' | 'log';
  /** Network layer (L3, L4, L7) */
  layer: 'L3' | 'L4' | 'L7';
  /** Source IP address */
  source_ip: string;
  /** Source port */
  source_port: number;
  /** Destination IP address */
  destination_ip: string;
  /** Destination port */
  destination_port: number;
  /** Network protocol */
  protocol: 'TCP' | 'UDP' | 'ICMP' | 'HTTP' | 'HTTPS' | 'DNS';
  /** Packet size in bytes */
  packet_size: number;
  /** Country of origin */
  country_code: string | null;
  /** ASN of origin */
  asn: number | null;
  /** JA3/JA3S fingerprint (for TLS connections) */
  tls_fingerprint: string | null;
  /** Request details for L7 events */
  http_request: {
    method: string;
    path: string;
    host: string;
    user_agent: string;
    headers: Record<string, string>;
  } | null;
  /** Matched threat signatures */
  matched_signatures: string[];
  /** Whether this event was part of a detected attack */
  attack_correlation_id: string | null;
}

// ---------------------------------------------------------------------------
// System Health
// ---------------------------------------------------------------------------

export interface SystemHealth {
  /** Overall system status */
  status: 'healthy' | 'degraded' | 'critical' | 'maintenance';
  /** Timestamp of this health check */
  timestamp: string;
  /** System uptime in seconds */
  uptime_secs: number;
  /** Fortress version */
  version: string;
  /** CPU utilization metrics */
  cpu: {
    usage_percent: number;
    load_average_1m: number;
    load_average_5m: number;
    load_average_15m: number;
    core_count: number;
  };
  /** Memory utilization metrics */
  memory: {
    total_bytes: number;
    used_bytes: number;
    available_bytes: number;
    usage_percent: number;
    swap_total_bytes: number;
    swap_used_bytes: number;
  };
  /** Disk utilization metrics */
  disk: {
    total_bytes: number;
    used_bytes: number;
    available_bytes: number;
    usage_percent: number;
    iops_read: number;
    iops_write: number;
  };
  /** Network interface metrics */
  network: {
    rx_bytes_per_sec: number;
    tx_bytes_per_sec: number;
    rx_packets_per_sec: number;
    tx_packets_per_sec: number;
    active_connections: number;
    connection_errors: number;
  };
  /** Worker/process pool status */
  workers: {
    total: number;
    active: number;
    idle: number;
    max_capacity: number;
  };
  /** Component health checks */
  components: {
    proxy_engine: 'up' | 'down' | 'degraded';
    challenge_server: 'up' | 'down' | 'degraded';
    database: 'up' | 'down' | 'degraded';
    threat_intel_feed: 'up' | 'down' | 'degraded';
    geoip_database: 'up' | 'down' | 'degraded';
    ssl_manager: 'up' | 'down' | 'degraded';
  };
  /** Recent error counts by category */
  error_counts: {
    last_1m: number;
    last_5m: number;
    last_15m: number;
    last_1h: number;
  };
}
