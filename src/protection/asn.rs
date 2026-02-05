use std::collections::HashSet;

use crate::config::settings::AsnScoringConfig;

/
/
///
/
/
/
pub struct AsnClassifier {
    datacenter_asns: HashSet<u32>,
    residential_proxy_asns: HashSet<u32>,
    vpn_asns: HashSet<u32>,
    mobile_carrier_asns: HashSet<u32>,
}

/
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AsnType {
    /
    Residential,
    /
    Datacenter,
    /
    ResidentialProxy,
    /
    VPN,
    /
    MobileCarrier,
    /
    Unknown,
}

impl AsnClassifier {
    /
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

    /
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

    /
    pub fn is_suspicious(&self, asn: u32) -> bool {
        self.residential_proxy_asns.contains(&asn)
    }

    /
    ///
    /
    /
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

    /
    fn populate_known_asns(&mut self) {
        self.populate_datacenter_asns();
        self.populate_residential_proxy_asns();
        self.populate_vpn_asns();
        self.populate_mobile_carrier_asns();
    }

    /
    fn populate_datacenter_asns(&mut self) {
        let asns: &[u32] = &[
            14618,
            16509,
            7224,
            8987,
            38895,
            15169,
            396982,
            36040,
            8075,
            8068,
            3598,
            14061,
            393406,
            202018,
            24940,
            213230,
            16276,
            35540,
            20473,
            63949,
            31898,
            36351,
            45102,
            37963,
            45090,
            132203,
            13335,
            54113,
            20940,
            16625,
            12876,
            51167,
            47583,
            26496,
            26347,
            33070,
            19994,
            202053,
            36007,
            60781,
            28753,
            54290,
            35540,
            197540,
            40676,
            8100,
            36352,
            53667,
            8560,
            59642,
            209102,
            21859,
        ];

        for asn in asns {
            self.datacenter_asns.insert(*asn);
        }
    }

    /
    fn populate_residential_proxy_asns(&mut self) {
        let asns: &[u32] = &[
            9009,
            202425,
            62240,
            208258,
            44724,
            62282,
            47764,
            200019,
            399486,
            210037,
            46844,
            211298,
            35916,
        ];

        for asn in asns {
            self.residential_proxy_asns.insert(*asn);
        }
    }

    /
    fn populate_vpn_asns(&mut self) {
        let asns: &[u32] = &[
            212238,
            209854,
            198093,
            55286,
            209611,
            209641,
            206264,
            33438,
            204957,
            394536,
        ];

        for asn in asns {
            self.vpn_asns.insert(*asn);
        }
    }

    /
    fn populate_mobile_carrier_asns(&mut self) {
        let asns: &[u32] = &[
            9121,
            15897,
            47331,
            34984,
            7018,
            22394,
            21928,
            12576,
            25135,
            23415,
            31334,
            16232,
            55836,
            45609,
            24560,
            26599,
            28573,
            17974,
            25159,
            17676,
            3786,
            6167,
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
        assert_eq!(classifier.classify(14618), AsnType::Datacenter);
        assert_eq!(classifier.classify(15169), AsnType::Datacenter);
        assert_eq!(classifier.classify(8075), AsnType::Datacenter);
    }

    #[test]
    fn test_classify_mobile() {
        let classifier = AsnClassifier::new();
        assert_eq!(classifier.classify(9121), AsnType::MobileCarrier);
        assert_eq!(classifier.classify(15897), AsnType::MobileCarrier);
    }

    #[test]
    fn test_classify_unknown() {
        let classifier = AsnClassifier::new();
        assert_eq!(classifier.classify(99999), AsnType::Unknown);
    }

    #[test]
    fn test_is_suspicious() {
        let classifier = AsnClassifier::new();
        assert!(classifier.is_suspicious(14618));
        assert!(classifier.is_suspicious(9009));
        assert!(!classifier.is_suspicious(99999));
    }
}
