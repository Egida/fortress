'use client';

import { useState, useMemo } from 'react';
import {
  BookOpen,
  Search,
  ChevronDown,
  Shield,
  Server,
  Globe,
  Zap,
  AlertTriangle,
  Terminal,
  Settings,
} from 'lucide-react';

interface Section {
  id: string;
  title: string;
  icon: React.ElementType;
  content: ContentBlock[];
}

interface ContentBlock {
  heading?: string;
  text?: string;
  items?: string[];
  code?: string;
}

const sections: Section[] = [
  {
    id: 'overview',
    title: 'Genel Bakis',
    icon: Shield,
    content: [
      {
        heading: 'Fortress Nedir?',
        text: 'Fortress, Rust tabanli yuksek performansli bir anti-DDoS reverse proxy sistemidir. Modern tehdit ortamina karsi katmanli koruma saglayarak web uygulamalarinizi ve API\'lerinizi korur.',
      },
      {
        heading: 'Mimari',
        text: 'Trafik akisi asagidaki sekilde gerceklesir:',
        items: [
          'Istemci (Kullanici/Bot) \u2192 Cloudflare (opsiyonel CDN/Proxy) \u2192 Fortress (Anti-DDoS Katmani) \u2192 LiteSpeed/Backend (Uygulamaniz)',
          'Fortress, tum katmanlarda trafigi analiz eder ve tehditleri backend\'e ulasmadan once filtreler.',
        ],
      },
      {
        heading: 'Koruma Katmanlari',
        items: [
          'L4 TCP Korumasi: Cekirdek seviyesinde SYN flood ve baglanti hizi sinirlamasi',
          'L7 HTTP Korumasi: Uygulama katmaninda istek analizi ve filtreleme',
          'Davranissal Analiz: Istek desenleri ve zamanlama anomali tespiti',
          'JavaScript Challenge (PoW): SHA-256 tabanli is ispati dogrulamasi ile bot filtreleme',
        ],
      },
    ],
  },
  {
    id: 'protection-levels',
    title: 'Koruma Seviyeleri',
    icon: Shield,
    content: [
      {
        heading: 'DEFCON 5 \u2014 Normal',
        text: 'Pasif izleme modu. Minimum engelleme uygulanir ve tum trafik gecislidir. Gunluk operasyonlar icin uygundur. Sistem tehditleri kayit altina alir ancak agresif mudahale yapmaz.',
      },
      {
        heading: 'DEFCON 4 \u2014 High',
        text: 'Aktif savunma modu. Hiz sinirlandirma sikilasmasi uygulanir. Supheli trafige JavaScript challenge gonderilir. Artan tehdit aktivitesi tespit edildiginde onerilir.',
      },
      {
        heading: 'DEFCON 3 \u2014 Under Attack',
        text: 'Tehdit mukavelesi modu. Agresif rate limiting devreye girer. Tum yeni IP adreslerine otomatik olarak challenge gonderilir. Aktif saldiri altindayken kullanilir.',
      },
      {
        heading: 'DEFCON 2 \u2014 Severe',
        text: 'Maksimum savunma modu. Cok dusuk istek limitleri uygulanir. Supheli trafik aninda engellenir. Yogun ve koordineli saldirilar sirasinda kullanilir.',
      },
      {
        heading: 'DEFCON 1 \u2014 Emergency',
        text: 'Tam kilit modu. Sadece beyaz listedeki IP adresleri erisim saglayabilir. Diger tum trafik engellenir. Kritik durumlarda son care olarak kullanilir.',
      },
    ],
  },
  {
    id: 'defense-modules',
    title: 'Savunma Modulleri',
    icon: Zap,
    content: [
      {
        heading: 'Hiz Sinirlandirici (Rate Limiter)',
        text: 'IP basina saniyedeki istek limitini kontrol eder. Her koruma seviyesinde farkli limitler uygulanir:',
        items: [
          'DEFCON 5 (Normal): 100 istek/saniye',
          'DEFCON 4 (High): 50 istek/saniye',
          'DEFCON 3 (Under Attack): 30 istek/saniye',
          'DEFCON 2 (Severe): 10 istek/saniye',
          'DEFCON 1 (Emergency): 5 istek/saniye',
          'Ne zaman aktif etmeli: Her zaman aktif olmalidir. Temel koruma katmanidir.',
        ],
      },
      {
        heading: 'JA3 Parmak Izi Motoru',
        text: 'TLS el sikisma ozelliklerini analiz ederek istemcilerin parmak izini cikarir. Bilinen bot ve saldiri araci imzalarini tespit ederek engeller.',
        items: [
          'TLS surum, sifreleme paketleri ve uzantilari analiz eder',
          'Bilinen zararli bot imzalarini otomatik engeller',
          'Ne zaman aktif etmeli: Her zaman. Dusuk performans etkisi ile yuksek tespit orani saglar.',
        ],
      },
      {
        heading: 'IP Itibar Sistemi',
        text: 'Her IP adresi icin 0-100 arasi bir tehdit puani hesaplar. Puanlama zaman gecislidir; belirli bir sure ihlal yapilmazsa puan duser.',
        items: [
          'Yeni IP\'ler 0 puanla baslar',
          'Her ihlalde puan artar (ornegin: rate limit asilma +10, WAF tetikleme +20)',
          'Zaman gecisi: Puan her saat basina yaklasik 5 puan azalir',
          'Ne zaman aktif etmeli: Her zaman. Tekrarlayan saldirganlari otomatik tespit eder.',
        ],
      },
      {
        heading: 'Otomatik Yasaklama (Auto-Ban)',
        text: 'IP itibar puani belirli bir esigi asginda IP adreslerini otomatik olarak engeller.',
        items: [
          'Varsayilan esik: Skor > 80 olan IP\'ler otomatik yasaklanir',
          'Yasaklama suresi yapilandirilabilir (varsayilan: 1 saat)',
          'Ne zaman aktif etmeli: Her zaman. IP itibar sistemi ile birlikte calisir.',
        ],
      },
      {
        heading: 'Davranissal Analiz',
        text: 'Istemcilerin davranis desenlerini analiz ederek anormal aktiviteleri tespit eder.',
        items: [
          'Istek zamanlama desenleri: Cok duzgun araliklarla gelen istekler bot gostergesidir',
          'Path erisim desenleri: Rastgele veya sirali path taramasi tespit edilir',
          'Header tutarliligi: User-Agent ve diger headerlardaki tutarsizliklar analiz edilir',
          'Ne zaman aktif etmeli: Her zaman. Gelismis bot tespiti icin kritik oneme sahiptir.',
        ],
      },
      {
        heading: 'Bot Beyaz Listesi',
        text: 'Google, Bing, Yandex gibi mesru arama motoru botlarina otomatik olarak erisim izni verir.',
        items: [
          'Botlar reverse DNS dogrulamasi ile teyit edilir',
          'Sahte bot User-Agent\'lari otomatik tespit edilir',
          'Ne zaman aktif etmeli: SEO onemli ise her zaman aktif olmali. Kapatilirsa arama motorlari engellenebilir.',
        ],
      },
      {
        heading: 'Yonetilen Kurallar (Managed Rules)',
        text: 'OWASP standartlarina dayali hazir guvenlik kurallari seti.',
        items: [
          'SQL Injection (SQLi) tespiti ve engelleme',
          'Cross-Site Scripting (XSS) korumasi',
          'Path Traversal saldirisi onleme',
          'Remote File Inclusion (RFI) engelleme',
          'Ne zaman aktif etmeli: Her zaman. Web uygulama guvenligi icin temel gereksinimdir.',
        ],
      },
      {
        heading: 'Dagitik Algilama (Distributed Detection)',
        text: 'Farkli IP adreslerinden gelen koordineli saldiri desenlerini tespit eder.',
        items: [
          'Ayni anda birden fazla IP\'den gelen benzer istekleri iliskilendirir',
          'Botnet saldirilarina karsi etkili savunma saglar',
          'ASN ve subnet bazli korelasyon analizi yapar',
          'Ne zaman aktif etmeli: Ozellikle DDoS saldirisi altindayken kritik oneme sahiptir.',
        ],
      },
      {
        heading: 'GeoIP Filtreleme',
        text: 'Ulke bazli erisim kontrolu ve ek puanlama saglar.',
        items: [
          'Belirli ulkelerden gelen trafigi tamamen engelleyebilir',
          'Yuksek riskli ulkelerden gelen trafige ek puan ekleyebilir',
          'Ne zaman aktif etmeli: Hedef kitleniz belirli bolgelerdeyse ve diger bolgelerden saldiri aliyorsaniz.',
        ],
      },
      {
        heading: 'PoW Challenge (JavaScript Challenge)',
        text: 'JavaScript tabanli SHA-256 is ispati dogrulamasi. Istemcinin gercek bir tarayici oldugunu dogrular.',
        items: [
          'Istemci tarayicisinda kriptografik bulmaca cozdurur',
          'Headless tarayici tespiti icin ek kontroller icerir',
          'Basarili dogrulamada clearance cookie verilir',
          'Ne zaman aktif etmeli: Koruma seviyesi yukseltildiginde otomatik devreye girer. Manuel olarak da aktif edilebilir.',
        ],
      },
      {
        heading: 'Cloudflare Modu',
        text: 'Cloudflare proxy arkasinda calisirken gercek istemci IP adresini dogru sekilde alir.',
        items: [
          'CF-Connecting-IP headerindan gercek IP adresi alinir',
          'Cloudflare IP araliklari otomatik olarak taninir ve guvenilir',
          'Ne zaman aktif etmeli: Cloudflare kullaniyorsaniz mutlaka aktif edilmelidir. Aksi halde tum istekler Cloudflare IP\'si olarak gorunur.',
        ],
      },
      {
        heading: 'L4 TCP Korumasi',
        text: 'Cekirdek (kernel) seviyesinde TCP korumasi saglar. iptables kurallari ile SYN flood saldirilarini engeller.',
        items: [
          'SYN cookie mekanizmasi ile SYN flood korumasi',
          'Baglanti hizi sinirlamasi (connection rate limiting)',
          'Anormal TCP bayrak kombinasyonlarini engeller',
          'Ne zaman aktif etmeli: Her zaman. Ag katmaninda temel koruma saglar.',
        ],
      },
    ],
  },
  {
    id: 'service-management',
    title: 'Servis Yonetimi',
    icon: Server,
    content: [
      {
        heading: 'Yeni Servis Ekleme',
        text: 'Fortress uzerinden korumak istediginiz her web servisi icin bir kayit olusturmaniz gerekir.',
        items: [
          'Domain: Korumak istediginiz alan adi (ornegin: example.com)',
          'Upstream Adresi: Backend sunucunuzun adresi (ornegin: 127.0.0.1:8080 veya backend.local:443)',
          'Her servis bagimsiz olarak aktif/deaktif edilebilir',
        ],
      },
      {
        heading: 'Wildcard Domain Destegi',
        text: 'Alt alan adlarinin tamamini tek bir kayitla koruyabilirsiniz.',
        items: [
          'Ornek: *.example.com tum alt alan adlarini kapsar',
          'www.example.com, api.example.com, admin.example.com hepsi korunur',
          'Hem wildcard hem de spesifik domain ayni anda tanimlanabilir',
        ],
      },
      {
        heading: 'Upstream Saglik Kontrolu',
        text: 'Fortress, backend sunucunuzun erisilebiligini duzeli olarak kontrol eder.',
        items: [
          'Varsayilan timeout: 5 saniye',
          'Basarisiz isteklerde otomatik retry mekanizmasi',
          'Backend erisielemez ise 502 Bad Gateway hatasi dondurulur',
        ],
      },
    ],
  },
  {
    id: 'attack-types',
    title: 'Saldiri Tipleri ve Mudahale',
    icon: AlertTriangle,
    content: [
      {
        heading: 'HTTP Flood',
        text: 'Yuksek hacimli GET veya POST istekleri gondererek sunucuyu mesgul etmeye calisan saldiri tipi.',
        items: [
          'Belirtiler: Ani trafik artisi, yuksek CPU kullanimi',
          'Mudahale: Hiz sinirlandirma + PoW Challenge aktif edin',
          'Koruma seviyesini en az DEFCON 3\'e yukseltin',
        ],
      },
      {
        heading: 'Slowloris',
        text: 'Cok sayida yavas HTTP baglantisi acarak sunucu kaynaklarini tuketen saldiri tipi.',
        items: [
          'Belirtiler: Dusuk bant genisligi kullanimi ancak yuksek baglanti sayisi',
          'Mudahale: Baglanti timeout degerlerini dusurun + L4 TCP korumasi aktif edin',
          'Fortress otomatik olarak yavas baglantilari kapatir',
        ],
      },
      {
        heading: 'SYN Flood',
        text: 'TCP el sikisma surecini istismar ederek sunucunun baglanti tablosunu dolduran saldiri tipi.',
        items: [
          'Belirtiler: Yuksek SYN_RECV durumundaki baglanti sayisi',
          'Mudahale: L4 TCP korumasindaki SYN cookie mekanizmasi otomatik devreye girer',
          'iptables kurallari ile cekirdek seviyesinde engelleme yapilir',
        ],
      },
      {
        heading: 'Application Layer Saldirisi',
        text: 'Belirli endpoint\'leri hedef alan sofistike saldiri tipi. Normal trafige benzer gorunur.',
        items: [
          'Belirtiler: Belirli sayfalarda anormal trafik artisi',
          'Mudahale: WAF kurallari + Davranissal analiz aktif edin',
          'Ozel kurallar ile hedeflenen endpoint\'leri koruma altina alin',
        ],
      },
      {
        heading: 'Credential Stuffing',
        text: 'Sizdirilmis kullanici adi ve sifre kombinasyonlari ile toplu giris denemesi.',
        items: [
          'Belirtiler: Login endpoint\'ine yuksek hacimli POST istekleri',
          'Mudahale: Login sayfasina ozel rate limit + PoW Challenge uygulayin',
          'Basarisiz giris denemelerinde IP itibar puanini artirin',
        ],
      },
      {
        heading: 'Bot Saldirisi',
        text: 'Otomatik tarayicilar (headless browser) ile gerceklestirilen saldirilar.',
        items: [
          'Belirtiler: Yuksek hacimli istekler, tutarli User-Agent, duzgun zamanlama',
          'Mudahale: JA3 parmak izi + Headless tarayici algilama + PoW Challenge',
          'Davranissal analiz ile bot desenlerini otomatik tespit edin',
        ],
      },
    ],
  },
  {
    id: 'cloudflare',
    title: 'Cloudflare Entegrasyonu',
    icon: Globe,
    content: [
      {
        heading: 'Genel Bilgi',
        text: 'Fortress, Cloudflare\'in turuncu bulut (proxy) modu ile tam uyumlu calisir. Cloudflare onunde proxy olarak kullanildiginda ozel yapilandirma gerektirir.',
      },
      {
        heading: 'IP Adresi Algilama',
        items: [
          'Fortress otomatik olarak Cloudflare IP araligini tanir',
          'CF-Connecting-IP headeri ile gercek istemci IP adresi alinir',
          'CF-IPCountry headeri ile istemcinin ulke bilgisi kullanilir',
          'Cloudflare modu aktif degilse tum istekler CF sunucu IP\'si olarak gorunur',
        ],
      },
      {
        heading: 'Header Yonetimi',
        items: [
          'X-Forwarded-Proto gibi Cloudflare headerlari backend\'e iletilmez (uyumluluk icin)',
          'Bu durum bazi uygulamalarda mixed content veya redirect sorunlarina yol acabilir',
          'Gerekirse backend uygulamanizda bu headerlari ayri olarak yapilandirin',
        ],
      },
      {
        heading: 'Onerilen SSL Yapilandirmasi',
        text: 'Cloudflare SSL ayarlarinda Full (Strict) modu onerilir.',
        items: [
          'Cloudflare \u2192 Fortress arasi HTTPS (gecerli sertifika gerekli)',
          'Fortress \u2192 Backend arasi yapilandirmaniza bagli (HTTP veya HTTPS)',
          'Flexible mod kullanmayin; 400 hatasi veya sonsuz redirect dongusu olusabilir',
        ],
      },
    ],
  },
  {
    id: 'admin-panel',
    title: 'Admin Panel Kullanimi',
    icon: Settings,
    content: [
      {
        heading: 'Komuta Merkezi',
        text: 'Genel sistem durumu, anlik metrikler ve tehdit durusu. Tum savunma sistemlerinin ozet gorunumu.',
      },
      {
        heading: 'Saldiri Monitoru',
        text: 'Canli saldiri algilama ve olay mudahalesi. Ses uyarisi ozelligi ile anlik bildirim. Saldiri zaman cigizi ve tehdit kaynaklari gorunumu.',
      },
      {
        heading: 'Trafik Istihbarati',
        text: 'Anlik istek akisi izleme. Her istegin detayli bilgisi: IP, ulke, path, durum kodu, engelleme nedeni.',
      },
      {
        heading: 'Engelleme Motoru',
        text: 'Manuel engelleme yonetimi. IP adresi, CIDR blogu, ASN numarasi veya ulke bazli engelleme kurallari tanimlanabilir.',
      },
      {
        heading: 'Kural Motoru',
        text: 'Ozel guvenlik kurallari tanimlama. Path, header, query string ve IP bazli kosullar ile esnek kural yapisi.',
      },
      {
        heading: 'Ayarlar',
        text: 'Koruma seviyesi degistirme ve savunma modullerini yonetme. Her modul bagimsiz olarak aktif/deaktif edilebilir.',
      },
    ],
  },
  {
    id: 'troubleshooting',
    title: 'Sorun Giderme',
    icon: AlertTriangle,
    content: [
      {
        heading: 'Site 400 Hatasi Veriyor',
        items: [
          'En yaygin neden: X-Forwarded-Proto header sorunu',
          'Cloudflare kullaniyorsaniz Cloudflare modunun aktif oldugunu kontrol edin',
          'SSL ayarlarinizi dogrulayin (Cloudflare\'de Full Strict oneriliyor)',
          'Backend uygulamanizin HTTPS beklentilerini kontrol edin',
        ],
      },
      {
        heading: 'Mesru Kullanicilar Engelleniyor',
        items: [
          'Koruma seviyesini bir kademe dusurun (ornegin DEFCON 3\'den DEFCON 4\'e)',
          'Engellenen IP adreslerini beyaz listeye ekleyin',
          'IP itibar sistemindeki esik degerini yuksestin (ornegin 80\'den 90\'a)',
          'Hiz sinirlandirici limitlerini kontrol edin; cok dusuk olabilir',
        ],
      },
      {
        heading: 'API/Webhook Istekleri Basarisiz',
        items: [
          'Fortress, /api/* yollarini otomatik olarak algilar ve challenge\'dan muaf tutar',
          'Ozel API yollari icin kural motoru uzerinden muafiyet tanimlayin',
          'Webhook gonderici IP adreslerini beyaz listeye ekleyin',
          'Rate limiter\'in API isteklerini engellemediginden emin olun',
        ],
      },
      {
        heading: 'Yuksek Latency (Gecikme)',
        items: [
          'Backend saglik kontrolunu dogrulayin; upstream sunucu yavas yanit veriyor olabilir',
          'Baglanti havuzu (connection pool) ayarlarini kontrol edin',
          'Fortress kaynaklarini (CPU/RAM) izleyin',
          'Cok fazla aktif modul performansi etkileyebilir; gereksiz modulleri devre disi birakin',
        ],
      },
      {
        heading: 'Challenge Sayfasi Gorunuyor',
        text: 'Bu normal bir davranistir. Fortress supheli trafige JavaScript challenge gonderir.',
        items: [
          'Kullanici PoW bulmacasini cozduungde clearance cookie verilir',
          'Cookie suresi boyunca tekrar challenge gosterilmez',
          'Eger tum kullanicilara challenge gosteriliyorsa koruma seviyesini dusurun',
          'Beyaz listedeki IP\'lere challenge gosterilmez',
        ],
      },
    ],
  },
  {
    id: 'api-reference',
    title: 'API Referansi',
    icon: Terminal,
    content: [
      {
        heading: 'Sistem Durumu',
        code: 'GET /api/fortress/status',
        text: 'Fortress sisteminin genel durumunu, aktif koruma seviyesini ve modul durumlarini dondurur.',
      },
      {
        heading: 'Anlik Metrikler',
        code: 'GET /api/fortress/metrics',
        text: 'Istek sayilari, engelleme oranlari, ortalama yanit suresi gibi anlik performans metriklerini dondurur.',
      },
      {
        heading: 'Tehdit Listesi',
        code: 'GET /api/fortress/threats',
        text: 'Aktif tehditleri, saldiri vektorlerini ve kaynak IP adreslerini listeler.',
      },
      {
        heading: 'Servis Listesi',
        code: 'GET /api/fortress/services',
        text: 'Kayitli tum servislerin listesini, durumlarini ve yapilandirmalarini dondurur.',
      },
      {
        heading: 'Yeni Servis Ekle',
        code: 'POST /api/fortress/services',
        text: 'Yeni bir korumali servis kaydeder. Body: { domains: string[], upstream: string }',
      },
      {
        heading: 'IP Itibar Verileri',
        code: 'GET /api/fortress/ip-reputation',
        text: 'IP adreslerinin itibar puanlarini, ihlal gecmislerini ve durumlarini listeler.',
      },
      {
        heading: 'Otomatik Yasaklar',
        code: 'GET /api/fortress/auto-bans',
        text: 'Otomatik olarak yasaklanan IP adreslerini, yasaklama nedenlerini ve surelerini listeler.',
      },
      {
        heading: 'Engelleme Ekle',
        code: 'POST /api/fortress/blocklist',
        text: 'Yeni bir engelleme kurali ekler. Body: { type: "ip"|"cidr"|"asn"|"country", value: string, reason?: string }',
      },
      {
        heading: 'Yapilandirma Guncelle',
        code: 'PUT /api/fortress/config',
        text: 'Sistem yapilandirmasini gunceller. Koruma seviyesi, modul ayarlari ve genel parametreleri icerir.',
      },
    ],
  },
];

export default function KnowledgeBasePage() {
  const [searchQuery, setSearchQuery] = useState('');
  const [openSections, setOpenSections] = useState<Set<string>>(new Set());

  const toggleSection = (id: string) => {
    setOpenSections((prev) => {
      const next = new Set(prev);
      if (next.has(id)) {
        next.delete(id);
      } else {
        next.add(id);
      }
      return next;
    });
  };

  const filteredSections = useMemo(() => {
    if (!searchQuery.trim()) return sections;
    const query = searchQuery.toLowerCase();
    return sections.filter((section) => {
      if (section.title.toLowerCase().includes(query)) return true;
      return section.content.some((block) => {
        if (block.heading?.toLowerCase().includes(query)) return true;
        if (block.text?.toLowerCase().includes(query)) return true;
        if (block.code?.toLowerCase().includes(query)) return true;
        if (block.items?.some((item) => item.toLowerCase().includes(query))) return true;
        return false;
      });
    });
  }, [searchQuery]);

  // Auto-open sections when searching
  const effectiveOpenSections = useMemo(() => {
    if (searchQuery.trim()) {
      return new Set(filteredSections.map((s) => s.id));
    }
    return openSections;
  }, [searchQuery, filteredSections, openSections]);

  return (
    <div className="min-h-screen bg-black text-zinc-100">
      {/* Header */}
      <div className="border-b border-zinc-800 bg-zinc-950/50">
        <div className="max-w-5xl mx-auto px-6 py-8">
          <div className="flex items-center gap-3 mb-2">
            <div className="w-10 h-10 rounded-lg bg-blue-600/20 border border-blue-500/20 flex items-center justify-center">
              <BookOpen className="w-5 h-5 text-blue-400" />
            </div>
            <div>
              <h1 className="text-2xl font-bold text-zinc-100 tracking-tight">
                Bilgi Deposu
              </h1>
              <p className="text-sm text-zinc-500">Knowledge Base</p>
            </div>
          </div>
          <p className="text-zinc-400 text-sm mt-3 max-w-2xl">
            Fortress anti-DDoS platformunun kapsamli dokumantasyonu. Koruma seviyeleri,
            savunma modulleri, saldiri tipleri ve sistem yonetimi hakkinda detayli bilgi.
          </p>

          {/* Search */}
          <div className="mt-6 relative max-w-xl">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-zinc-500" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Dokumantasyonda ara..."
              className="w-full bg-zinc-900 border border-zinc-800 rounded-lg pl-10 pr-4 py-2.5 text-sm text-zinc-200 placeholder-zinc-600 focus:outline-none focus:border-blue-500/50 focus:ring-1 focus:ring-blue-500/20 transition-colors"
            />
            {searchQuery && (
              <button
                onClick={() => setSearchQuery('')}
                className="absolute right-3 top-1/2 -translate-y-1/2 text-zinc-500 hover:text-zinc-300 text-xs"
              >
                Temizle
              </button>
            )}
          </div>

          {searchQuery && (
            <p className="text-xs text-zinc-500 mt-2">
              {filteredSections.length} bolum bulundu
            </p>
          )}
        </div>
      </div>

      {/* Content */}
      <div className="max-w-5xl mx-auto px-6 py-8 space-y-3">
        {filteredSections.length === 0 ? (
          <div className="text-center py-16">
            <Search className="w-10 h-10 text-zinc-700 mx-auto mb-4" />
            <p className="text-zinc-500 text-sm">
              &quot;{searchQuery}&quot; ile eslesen icerik bulunamadi.
            </p>
          </div>
        ) : (
          filteredSections.map((section) => {
            const isOpen = effectiveOpenSections.has(section.id);
            const Icon = section.icon;
            return (
              <div
                key={section.id}
                className="bg-zinc-900 border border-zinc-800 rounded-xl overflow-hidden"
              >
                {/* Section Header */}
                <button
                  onClick={() => toggleSection(section.id)}
                  className="w-full flex items-center gap-3 px-5 py-4 text-left hover:bg-zinc-800/50 transition-colors"
                >
                  <div className="w-8 h-8 rounded-lg bg-zinc-800 border border-zinc-700 flex items-center justify-center flex-shrink-0">
                    <Icon className="w-4 h-4 text-zinc-400" />
                  </div>
                  <span className="text-sm font-semibold text-zinc-100 flex-1">
                    {section.title}
                  </span>
                  <ChevronDown
                    className={`w-4 h-4 text-zinc-500 transition-transform duration-200 ${
                      isOpen ? 'rotate-180' : ''
                    }`}
                  />
                </button>

                {/* Section Content */}
                {isOpen && (
                  <div className="px-5 pb-5 space-y-5 border-t border-zinc-800/50">
                    {section.content.map((block, idx) => (
                      <div key={idx} className="pt-4">
                        {block.heading && (
                          <h3 className="text-sm font-semibold text-zinc-200 mb-2">
                            {block.heading}
                          </h3>
                        )}
                        {block.code && (
                          <code className="inline-block bg-zinc-800 border border-zinc-700 text-blue-400 text-xs font-mono px-2.5 py-1 rounded mb-2">
                            {block.code}
                          </code>
                        )}
                        {block.text && (
                          <p className="text-sm text-zinc-400 leading-relaxed">
                            {block.text}
                          </p>
                        )}
                        {block.items && (
                          <ul className="mt-2 space-y-1.5">
                            {block.items.map((item, iIdx) => (
                              <li
                                key={iIdx}
                                className="flex items-start gap-2 text-sm text-zinc-400"
                              >
                                <span className="w-1 h-1 rounded-full bg-zinc-600 mt-2 flex-shrink-0" />
                                <span className="leading-relaxed">{item}</span>
                              </li>
                            ))}
                          </ul>
                        )}
                      </div>
                    ))}
                  </div>
                )}
              </div>
            );
          })
        )}

        {/* Footer */}
        <div className="text-center pt-8 pb-4">
          <p className="text-xs text-zinc-600">
            Fortress Threat Defense Platform &mdash; Dokumantasyon
          </p>
        </div>
      </div>
    </div>
  );
}
