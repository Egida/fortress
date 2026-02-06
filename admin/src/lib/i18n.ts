export type Locale = 'en' | 'tr';

export const translations: Record<Locale, Record<string, string>> = {
  en: {
    // Navigation
    'nav.command_center': 'Command Center',
    'nav.attack_monitor': 'Attack Monitor',
    'nav.services': 'Protected Services',
    'nav.live': 'Traffic Intelligence',
    'nav.attacks': 'Attack Vectors',
    'nav.blocklist': 'Blocklist Engine',
    'nav.rules': 'Rule Engine',
    'nav.analytics': 'Threat Analytics',
    'nav.ip_reputation': 'IP Reputation Matrix',
    'nav.auto_bans': 'Auto-Response System',
    'nav.managed_rules': 'Security Policies',
    'nav.threat_map': 'Threat Intelligence',
    'nav.knowledge_base': 'Knowledge Base',
    'nav.settings': 'System Configuration',
    'nav.l4': 'L4 TCP Shield',
    'nav.disconnect': 'Disconnect',

    // Common
    'common.loading': 'Loading...',
    'common.save': 'Save Changes',
    'common.cancel': 'Cancel',
    'common.delete': 'Delete',
    'common.edit': 'Edit',
    'common.add': 'Add',
    'common.search': 'Search',
    'common.filter': 'Filter',
    'common.export': 'Export',
    'common.refresh': 'Refresh',
    'common.enabled': 'Enabled',
    'common.disabled': 'Disabled',
    'common.active': 'Active',
    'common.inactive': 'Inactive',
    'common.status': 'Status',
    'common.actions': 'Actions',
    'common.confirm': 'Confirm',
    'common.back': 'Back',
    'common.ip_address': 'IP Address',
    'common.country': 'Country',
    'common.requests': 'Requests',
    'common.blocked': 'Blocked',
    'common.passed': 'Passed',
    'common.challenged': 'Challenged',
    'common.score': 'Score',
    'common.reason': 'Reason',
    'common.time': 'Time',
    'common.duration': 'Duration',
    'common.type': 'Type',
    'common.value': 'Value',
    'common.no_data': 'No data available',
    'common.error': 'An error occurred',

    // Protection Levels (DEFCON)
    'level.defcon5': 'DEFCON 5 - Passive Monitoring',
    'level.defcon4': 'DEFCON 4 - Active Defense',
    'level.defcon3': 'DEFCON 3 - Threat Engagement',
    'level.defcon2': 'DEFCON 2 - Maximum Defense',
    'level.defcon1': 'DEFCON 1 - Full Lockdown',

    // Dashboard
    'dashboard.title': 'Command Center',
    'dashboard.subtitle': 'Real-time threat defense operations overview',
    'dashboard.threat_posture': 'Threat Posture',
    'dashboard.processed': 'Processed Requests',
    'dashboard.neutralized': 'Threats Neutralized',
    'dashboard.challenges': 'PoW Challenges Issued',
    'dashboard.legitimate': 'Legitimate Traffic',
    'dashboard.interception': 'Threat Interception Rate',
    'dashboard.throughput': 'Throughput',
    'dashboard.active_defenses': 'Active Defense Systems',
    'dashboard.traffic_overview': 'Traffic Overview',

    // Attack Monitor
    'monitor.title': 'Attack Monitor',
    'monitor.subtitle': 'Real-time threat detection and incident response',
    'monitor.all_clear': 'ALL SYSTEMS NOMINAL',
    'monitor.under_attack': 'ATTACK DETECTED',
    'monitor.elevated': 'ELEVATED THREAT POSTURE',
    'monitor.throughput': 'Throughput',
    'monitor.blocked': 'Blocked',
    'monitor.challenged': 'Challenged',
    'monitor.passed': 'Passed',
    'monitor.unique_ips': 'Unique IPs',
    'monitor.latency': 'Latency',
    'monitor.live_stream': 'Live Traffic Stream',
    'monitor.attack_timeline': 'Attack Timeline',
    'monitor.threat_sources': 'Top Threat Sources',
    'monitor.distributed': 'Distributed Detection Engine',
    'monitor.containment': 'Active Containment',
    'monitor.alerts_on': 'Alerts ON',
    'monitor.alerts_off': 'Alerts OFF',
    'monitor.nominal': 'NOMINAL',

    // Settings
    'settings.title': 'System Configuration',
    'settings.subtitle': 'Core defense parameters and protection modules',
    'settings.protection_level': 'Protection Level',
    'settings.defense_modules': 'Defense Modules',
    'settings.module_status': 'Module Status',
    'settings.system_info': 'System Information',
    'settings.advanced': 'Advanced Configuration',

    // Protection Modules
    'module.rate_limiter': 'Rate Limiter',
    'module.rate_limiter_desc': 'Sliding window rate limiting per IP, subnet, ASN, and country',
    'module.ja3_fingerprint': 'JA3 Fingerprint Engine',
    'module.ja3_fingerprint_desc': 'TLS client fingerprint analysis for bot detection',
    'module.ip_reputation': 'IP Reputation System',
    'module.ip_reputation_desc': 'Progressive scoring with time decay for repeat offenders',
    'module.auto_ban': 'Auto-Ban System',
    'module.auto_ban_desc': 'Automatic containment for IPs exceeding block thresholds',
    'module.behavioral': 'Behavioral Analysis',
    'module.behavioral_desc': 'Request pattern and timing anomaly detection',
    'module.bot_whitelist': 'Bot Whitelist',
    'module.bot_whitelist_desc': 'Allow verified search engine crawlers (Google, Bing, etc.)',
    'module.managed_rules': 'Managed Rules',
    'module.managed_rules_desc': 'Pre-built security rules for common attack patterns',
    'module.distributed': 'Distributed Detection',
    'module.distributed_desc': 'Coordinated attack pattern recognition across IP ranges',
    'module.geoip': 'GeoIP Filtering',
    'module.geoip_desc': 'Country and ASN based access control and scoring',
    'module.challenge': 'PoW Challenge System',
    'module.challenge_desc': 'SHA-256 proof-of-work verification with headless detection',
    'module.cloudflare': 'Cloudflare Compatibility',
    'module.cloudflare_desc': 'Trust CF-Connecting-IP headers from Cloudflare proxy ranges',
    'module.l4': 'L4 TCP Protection',
    'module.l4_desc': 'Kernel-level SYN flood and connection rate protection',

    // Services
    'services.title': 'Protected Services',
    'services.add': 'Register Service',
    'services.domains': 'Domains',
    'services.upstream': 'Upstream Address',
    'services.deploy': 'Deploy Service',

    // Quick Response
    'qr.title': 'Quick Response',
    'qr.subtitle': 'Instant protection level switching',
    'qr.current': 'CURRENT',
    'qr.switch_confirm': 'Switch to',
    'qr.switching': 'Switching...',
    'qr.panic': 'PANIC MODE',
    'qr.panic_desc': 'Immediately activate DEFCON 1 - Full Lockdown',
    'qr.reset': 'RESET',
    'qr.reset_desc': 'Return to DEFCON 5 - Normal monitoring',
    'qr.auto': 'AUTO',
    'qr.auto_desc': 'Let Fortress decide the protection level automatically',
    'qr.auto_enabled': 'Auto-escalation is active',
    'qr.auto_disabled': 'Auto-escalation is disabled',
    'qr.success': 'Protection level changed successfully',
    'qr.error': 'Failed to change protection level',

    // Login
    'login.title': 'FORTRESS',
    'login.subtitle': 'Threat Defense Platform',
    'login.credential': 'Access Credential',
    'login.authenticate': 'AUTHENTICATE',
    'login.failed': 'Authentication failed',
  },
  tr: {
    // Navigation
    'nav.command_center': 'Komuta Merkezi',
    'nav.attack_monitor': 'Saldiri Monitoru',
    'nav.services': 'Korumali Servisler',
    'nav.live': 'Trafik Istihbarati',
    'nav.attacks': 'Saldiri Vektorleri',
    'nav.blocklist': 'Engelleme Motoru',
    'nav.rules': 'Kural Motoru',
    'nav.analytics': 'Tehdit Analitigi',
    'nav.ip_reputation': 'IP Itibar Matrisi',
    'nav.auto_bans': 'Otomatik Mudahale',
    'nav.managed_rules': 'Guvenlik Politikalari',
    'nav.threat_map': 'Tehdit Istihbarati',
    'nav.knowledge_base': 'Bilgi Deposu',
    'nav.settings': 'Sistem Yapilandirmasi',
    'nav.l4': 'L4 TCP Kalkani',
    'nav.disconnect': 'Cikis Yap',

    // Common
    'common.loading': 'Yukleniyor...',
    'common.save': 'Degisiklikleri Kaydet',
    'common.cancel': 'Iptal',
    'common.delete': 'Sil',
    'common.edit': 'Duzenle',
    'common.add': 'Ekle',
    'common.search': 'Ara',
    'common.filter': 'Filtrele',
    'common.export': 'Disari Aktar',
    'common.refresh': 'Yenile',
    'common.enabled': 'Aktif',
    'common.disabled': 'Devre Disi',
    'common.active': 'Aktif',
    'common.inactive': 'Pasif',
    'common.status': 'Durum',
    'common.actions': 'Islemler',
    'common.confirm': 'Onayla',
    'common.back': 'Geri',
    'common.ip_address': 'IP Adresi',
    'common.country': 'Ulke',
    'common.requests': 'Istekler',
    'common.blocked': 'Engellenen',
    'common.passed': 'Gecen',
    'common.challenged': 'Dogrulanan',
    'common.score': 'Skor',
    'common.reason': 'Sebep',
    'common.time': 'Zaman',
    'common.duration': 'Sure',
    'common.type': 'Tur',
    'common.value': 'Deger',
    'common.no_data': 'Veri bulunamadi',
    'common.error': 'Bir hata olustu',

    // Protection Levels (DEFCON)
    'level.defcon5': 'DEFCON 5 - Pasif Izleme',
    'level.defcon4': 'DEFCON 4 - Aktif Savunma',
    'level.defcon3': 'DEFCON 3 - Tehdit Mukavelesi',
    'level.defcon2': 'DEFCON 2 - Maksimum Savunma',
    'level.defcon1': 'DEFCON 1 - Tam Kilit',

    // Dashboard
    'dashboard.title': 'Komuta Merkezi',
    'dashboard.subtitle': 'Anlik tehdit savunma operasyonlari',
    'dashboard.threat_posture': 'Tehdit Durusu',
    'dashboard.processed': 'Islenen Istekler',
    'dashboard.neutralized': 'Etkisizlestirilen Tehditler',
    'dashboard.challenges': 'PoW Dogrulama Sayisi',
    'dashboard.legitimate': 'Me\u015Fru Trafik',
    'dashboard.interception': 'Tehdit Yakalama Orani',
    'dashboard.throughput': 'Islem Hacmi',
    'dashboard.active_defenses': 'Aktif Savunma Sistemleri',
    'dashboard.traffic_overview': 'Trafik Genel Bakis',

    // Attack Monitor
    'monitor.title': 'Saldiri Monitoru',
    'monitor.subtitle': 'Anlik tehdit algilama ve olay mudahalesi',
    'monitor.all_clear': 'TUM SISTEMLER NORMAL',
    'monitor.under_attack': 'SALDIRI TESPIT EDILDI',
    'monitor.elevated': 'YUKSEK TEHDIT DURUSU',
    'monitor.throughput': 'Islem Hacmi',
    'monitor.blocked': 'Engellenen',
    'monitor.challenged': 'Dogrulanan',
    'monitor.passed': 'Gecen',
    'monitor.unique_ips': 'Benzersiz IP',
    'monitor.latency': 'Gecikme',
    'monitor.live_stream': 'Canli Trafik Akisi',
    'monitor.attack_timeline': 'Saldiri Zaman Cigizi',
    'monitor.threat_sources': 'En Buyuk Tehdit Kaynaklari',
    'monitor.distributed': 'Dagitik Algilama Motoru',
    'monitor.containment': 'Aktif Karantina',
    'monitor.alerts_on': 'Uyarilar ACIK',
    'monitor.alerts_off': 'Uyarilar KAPALI',
    'monitor.nominal': 'NORMAL',

    // Settings
    'settings.title': 'Sistem Yapilandirmasi',
    'settings.subtitle': 'Cekirdek savunma parametreleri ve koruma modulleri',
    'settings.protection_level': 'Koruma Seviyesi',
    'settings.defense_modules': 'Savunma Modulleri',
    'settings.module_status': 'Modul Durumu',
    'settings.system_info': 'Sistem Bilgileri',
    'settings.advanced': 'Gelismis Yapilandirma',

    // Protection Modules
    'module.rate_limiter': 'Hiz Sinirlandirici',
    'module.rate_limiter_desc': 'IP, altag, ASN ve ulke bazli kayan pencere hiz sinirlamasi',
    'module.ja3_fingerprint': 'JA3 Parmak Izi Motoru',
    'module.ja3_fingerprint_desc': 'Bot tespiti icin TLS istemci parmak izi analizi',
    'module.ip_reputation': 'IP Itibar Sistemi',
    'module.ip_reputation_desc': 'Tekrarlayan ihlalciler icin zaman azalmali puanlama',
    'module.auto_ban': 'Otomatik Yasaklama',
    'module.auto_ban_desc': 'Engelleme esigini asan IP\'ler icin otomatik karantina',
    'module.behavioral': 'Davranissal Analiz',
    'module.behavioral_desc': 'Istek deseni ve zamanlama anomali tespiti',
    'module.bot_whitelist': 'Bot Beyaz Listesi',
    'module.bot_whitelist_desc': 'Dogrulanmis arama motoru botlarina izin ver (Google, Bing, vb.)',
    'module.managed_rules': 'Yonetilen Kurallar',
    'module.managed_rules_desc': 'Yaygin saldiri desenleri icin hazir guvenlik kurallari',
    'module.distributed': 'Dagitik Algilama',
    'module.distributed_desc': 'IP araliklari uzerinde koordineli saldiri deseni tanima',
    'module.geoip': 'GeoIP Filtreleme',
    'module.geoip_desc': 'Ulke ve ASN bazli erisim kontrolu ve puanlama',
    'module.challenge': 'PoW Dogrulama Sistemi',
    'module.challenge_desc': 'Headless tarayici tespiti ile SHA-256 is ispati dogrulamasi',
    'module.cloudflare': 'Cloudflare Uyumlulugu',
    'module.cloudflare_desc': 'Cloudflare proxy araligindaki CF-Connecting-IP basliklarini guvenirlestir',
    'module.l4': 'L4 TCP Korumasi',
    'module.l4_desc': 'Cekirdek seviyesi SYN flood ve baglanti hizi korumasi',

    // Services
    'services.title': 'Korumali Servisler',
    'services.add': 'Servis Kaydet',
    'services.domains': 'Alan Adlari',
    'services.upstream': 'Upstream Adresi',
    'services.deploy': 'Servisi Devreye Al',

    // Quick Response
    'qr.title': 'Hizli Mudahale',
    'qr.subtitle': 'Anlik koruma seviyesi degistirme',
    'qr.current': 'AKTIF',
    'qr.switch_confirm': 'Gecis yap:',
    'qr.switching': 'Degistiriliyor...',
    'qr.panic': 'PANIK MODU',
    'qr.panic_desc': 'Hemen DEFCON 1 - Tam Kilitlemeyi etkinlestir',
    'qr.reset': 'SIFIRLA',
    'qr.reset_desc': 'DEFCON 5 - Normal izlemeye don',
    'qr.auto': 'OTOMATIK',
    'qr.auto_desc': 'Fortress koruma seviyesini otomatik belirlesin',
    'qr.auto_enabled': 'Otomatik eskalasyon aktif',
    'qr.auto_disabled': 'Otomatik eskalasyon devre disi',
    'qr.success': 'Koruma seviyesi basariyla degistirildi',
    'qr.error': 'Koruma seviyesi degistirilemedi',

    // Login
    'login.title': 'FORTRESS',
    'login.subtitle': 'Tehdit Savunma Platformu',
    'login.credential': 'Erisim Anahtari',
    'login.authenticate': 'GIRIS YAP',
    'login.failed': 'Kimlik dogrulama basarisiz',
  },
};

// Get stored locale or default to English
export function getStoredLocale(): Locale {
  if (typeof window === 'undefined') return 'en';
  return (localStorage.getItem('fortress_locale') as Locale) || 'en';
}

export function setStoredLocale(locale: Locale): void {
  if (typeof window !== 'undefined') {
    localStorage.setItem('fortress_locale', locale);
  }
}

// Translation function
export function t(key: string, locale: Locale): string {
  return translations[locale][key] || translations.en[key] || key;
}

// Country code to flag emoji
export function countryFlag(code: string | undefined): string {
  if (!code || code.length !== 2) return '';
  const upper = code.toUpperCase();
  const cp1 = 0x1f1e6 + upper.charCodeAt(0) - 65;
  const cp2 = 0x1f1e6 + upper.charCodeAt(1) - 65;
  return String.fromCodePoint(cp1, cp2);
}

// Country code to full name
export function countryName(code: string, locale: Locale = 'en'): string {
  try {
    const displayNames = new Intl.DisplayNames([locale === 'tr' ? 'tr' : 'en'], { type: 'region' });
    return displayNames.of(code.toUpperCase()) || code;
  } catch {
    return code;
  }
}
