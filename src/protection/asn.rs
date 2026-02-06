use std::collections::HashSet;

use crate::config::settings::AsnScoringConfig;

/// ASN classification for datacenter, residential proxy, VPN, and mobile
/// carrier identification.
///
/// This module maintains curated sets of known ASNs for different network
/// types. During request processing, the ASN classification helps determine
/// the likelihood that traffic is automated or proxied.
pub struct AsnClassifier {
    datacenter_asns: HashSet<u32>,
    residential_proxy_asns: HashSet<u32>,
    vpn_asns: HashSet<u32>,
    mobile_carrier_asns: HashSet<u32>,
}

/// Classification of an ASN's network type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AsnType {
    /// Standard residential ISP
    Residential,
    /// Cloud provider / hosting / datacenter
    Datacenter,
    /// Residential proxy network (Bright Data, IPXO, etc.)
    ResidentialProxy,
    /// Known VPN provider
    VPN,
    /// Mobile carrier network
    MobileCarrier,
    /// Unclassified ASN
    Unknown,
}

impl AsnClassifier {
    /// Create a new AsnClassifier with comprehensive known ASN databases.
    pub fn new() -> Self {
        let mut classifier = Self {
            datacenter_asns: HashSet::new(),
            residential_proxy_asns: HashSet::new(),
            vpn_asns: HashSet::new(),
            mobile_carrier_asns: HashSet::new(),
        };
        classifier.populate_known_asns();
        classifier
    }

    /// Classify an ASN into a network type.
    pub fn classify(&self, asn: u32) -> AsnType {
        if self.residential_proxy_asns.contains(&asn) {
            AsnType::ResidentialProxy
        } else if self.vpn_asns.contains(&asn) {
            AsnType::VPN
        } else if self.datacenter_asns.contains(&asn) {
            AsnType::Datacenter
        } else if self.mobile_carrier_asns.contains(&asn) {
            AsnType::MobileCarrier
        } else {
            AsnType::Unknown
        }
    }

    /// Check if an ASN is suspicious (datacenter or proxy).
    pub fn is_suspicious(&self, asn: u32) -> bool {
        self.residential_proxy_asns.contains(&asn)
    }

    /// Get a graduated suspicion score based on ASN type.
    ///
    /// Residential proxies get high scores (truly suspicious).
    /// Datacenters and VPNs get low scores (legitimate use is common).
    pub fn suspicion_score(&self, asn: u32, config: &AsnScoringConfig) -> f64 {
        match self.classify(asn) {
            AsnType::ResidentialProxy => config.residential_proxy_score,
            AsnType::VPN => config.vpn_score,
            AsnType::Datacenter => config.datacenter_score,
            AsnType::MobileCarrier => 0.0,
            AsnType::Residential => 0.0,
            AsnType::Unknown => 0.0,
        }
    }

    /// Populate all known ASN databases.
    fn populate_known_asns(&mut self) {
        self.populate_datacenter_asns();
        self.populate_residential_proxy_asns();
        self.populate_vpn_asns();
        self.populate_mobile_carrier_asns();
    }

    /// Known datacenter / cloud provider / hosting ASNs (50+).
    fn populate_datacenter_asns(&mut self) {
        let asns: &[u32] = &[
            // Amazon Web Services (AWS)
            14618,  // Amazon.com
            16509,  // Amazon Data Services
            7224,   // Amazon.com
            8987,   // Amazon EU
            38895,  // Amazon Japan
            // Google Cloud Platform
            15169,  // Google LLC
            396982, // Google Cloud
            36040,  // Google (YouTube)
            // Microsoft Azure
            8075,   // Microsoft Corporation
            8068,   // Microsoft Corp
            3598,   // Microsoft Corp (legacy)
            // DigitalOcean
            14061,  // DigitalOcean LLC
            393406, // DigitalOcean
            202018, // DigitalOcean (EU)
            // Hetzner
            24940,  // Hetzner Online GmbH
            213230, // Hetzner Finland
            // OVH / OVHcloud
            16276,  // OVH SAS
            35540,  // OVH Hosting
            // Vultr / Choopa
            20473,  // The Constant Company (Vultr)
            // Linode / Akamai Connected Cloud
            63949,  // Akamai Connected Cloud (Linode)
            // Oracle Cloud
            31898,  // Oracle Corporation
            // IBM Cloud / SoftLayer
            36351,  // SoftLayer Technologies
            // Alibaba Cloud
            45102,  // Alibaba US Technology
            37963,  // Alibaba (China)
            // Tencent Cloud
            45090,  // Tencent Cloud
            132203, // Tencent Building
            // Cloudflare
            13335,  // Cloudflare Inc
            // Fastly
            54113,  // Fastly Inc
            // Akamai
            20940,  // Akamai International
            16625,  // Akamai Technologies
            // Scaleway / Online SAS
            12876,  // Online S.a.s.
            // Contabo
            51167,  // Contabo GmbH
            // Hostinger
            47583,  // Hostinger International
            // GoDaddy
            26496,  // GoDaddy.com
            // DreamHost
            26347,  // DreamHost LLC
            // Rackspace
            33070,  // Rackspace Hosting
            19994,  // Rackspace Cloud
            // UpCloud
            202053, // UpCloud Ltd
            // Kamatera
            36007,  // Kamatera Inc
            // LeaseWeb
            60781,  // LeaseWeb Netherlands
            28753,  // LeaseWeb Deutschland
            // Hostwinds
            54290,  // Hostwinds LLC
            // OVH subsidiaries
            35540,  // OVH Hosting
            // NetCup
            197540, // netcup GmbH
            // Psychz Networks
            40676,  // Psychz Networks
            // QuadraNet
            8100,   // QuadraNet
            // ColoCrossing
            36352,  // ColoCrossing
            // BuyVM / FranTech
            53667,  // FranTech Solutions
            // Ionos (1&1)
            8560,   // Ionos SE
            // Cherry Servers
            59642,  // Cherry Servers
            // Servers.com
            209102, // Servers.com
            // Zenlayer
            21859,  // Zenlayer Inc
        ];

        for asn in asns {
            self.datacenter_asns.insert(*asn);
        }
    }

    /// Known residential proxy network ASNs (10+).
    fn populate_residential_proxy_asns(&mut self) {
        let asns: &[u32] = &[
            // Bright Data (formerly Luminati Networks)
            9009,   // M247 Ltd (commonly used by Bright Data)
            202425, // Bright Data Ltd
            62240,  // Clouvider (residential proxy infrastructure)
            // IPXO
            // (IPXO operates through leased IP space, hard to pin to single ASN)
            208258, // IPXO related
            // NetNut
            44724,  // NetNut Ltd related
            // Oxylabs
            62282,  // Oxylabs related infrastructure
            // Smartproxy
            47764,  // Smartproxy related
            // GeoSurf
            200019, // GeoSurf related
            // PacketStream
            399486, // PacketStream related
            // IPRoyal
            210037, // IPRoyal related
            // Storm Proxies
            46844,  // Storm Proxies related
            // Proxy-Seller
            211298, // Proxy-Seller related
            // Shifter (formerly Microleaves)
            35916,  // Multacom (commonly used by proxy services)
        ];

        for asn in asns {
            self.residential_proxy_asns.insert(*asn);
        }
    }

    /// Known VPN provider ASNs.
    fn populate_vpn_asns(&mut self) {
        let asns: &[u32] = &[
            // NordVPN / Nord Security
            212238, // Nord Security
            // ExpressVPN
            // ExpressVPN uses various hosting ASNs, these are dedicated ranges
            209854, // Express VPN International
            // Mullvad VPN
            198093, // Mullvad VPN AB
            // Private Internet Access (PIA)
            55286,  // Private Internet Access
            // Surfshark
            209611, // Surfshark Ltd
            // ProtonVPN
            209641, // Proton AG
            // CyberGhost
            206264, // CyberGhost related
            // IPVanish
            33438,  // IPVanish (StackPath/Highwinds)
            // Windscribe
            204957, // Windscribe Limited
            // TunnelBear
            394536, // TunnelBear related
        ];

        for asn in asns {
            self.vpn_asns.insert(*asn);
        }
    }

    /// Known mobile carrier ASNs (global, with focus on Turkey).
    fn populate_mobile_carrier_asns(&mut self) {
        let asns: &[u32] = &[
            // Turkey
            9121,   // Turkcell Iletisim Hizmetleri A.S.
            15897,  // Vodafone Turkey
            47331,  // Turk Telekom (TTNET mobile)
            34984,  // Superonline (Turkcell subsidiary)
            // United States
            7018,   // AT&T
            22394,  // Verizon Wireless (Cellco)
            21928,  // T-Mobile USA
            // United Kingdom
            12576,  // EE (BT Mobile)
            25135,  // Vodafone UK
            23415,  // Three UK (Hutchison)
            // Germany
            31334,  // Vodafone Germany (mobile)
            16232,  // Telekom Deutschland
            // India
            55836,  // Reliance Jio
            45609,  // Bharti Airtel (mobile)
            24560,  // Airtel broadband
            // Brazil
            26599,  // Telefonica Brasil (Vivo)
            28573,  // Claro Brasil
            // Indonesia
            17974,  // Telkomsel
            // Russia
            25159,  // MTS (Mobile TeleSystems)
            // Japan
            17676,  // SoftBank Mobile
            // South Korea
            3786,   // LG Uplus
            // Global mobile
            6167,   // Verizon Business
        ];

        for asn in asns {
            self.mobile_carrier_asns.insert(*asn);
        }
    }
}

impl Default for AsnClassifier {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_classify_datacenter() {
        let classifier = AsnClassifier::new();
        assert_eq!(classifier.classify(14618), AsnType::Datacenter); // AWS
        assert_eq!(classifier.classify(15169), AsnType::Datacenter); // Google
        assert_eq!(classifier.classify(8075), AsnType::Datacenter);  // Azure
    }

    #[test]
    fn test_classify_mobile() {
        let classifier = AsnClassifier::new();
        assert_eq!(classifier.classify(9121), AsnType::MobileCarrier);  // Turkcell
        assert_eq!(classifier.classify(15897), AsnType::MobileCarrier); // Vodafone TR
    }

    #[test]
    fn test_classify_unknown() {
        let classifier = AsnClassifier::new();
        assert_eq!(classifier.classify(99999), AsnType::Unknown);
    }

    #[test]
    fn test_is_suspicious() {
        let classifier = AsnClassifier::new();
        assert!(classifier.is_suspicious(14618));  // AWS - datacenter
        assert!(classifier.is_suspicious(9009));   // Bright Data - proxy
        assert!(!classifier.is_suspicious(99999)); // Unknown - not suspicious
    }
}
