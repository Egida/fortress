use std::net::IpAddr;
use std::path::Path;

use tracing::{info, warn};

/// GeoIP lookup using MaxMind databases.
///
/// Provides country, ASN, and city lookups for IP addresses. Gracefully
/// degrades if database files are not available - lookups simply return None.
pub struct GeoIpLookup {
    city_reader: Option<maxminddb::Reader<Vec<u8>>>,
    asn_reader: Option<maxminddb::Reader<Vec<u8>>>,
}

/// Minimal struct for deserializing country data from MaxMind GeoIP2/GeoLite2.
#[derive(serde::Deserialize, Debug)]
struct GeoIpCountry {
    country: Option<CountryRecord>,
}

#[derive(serde::Deserialize, Debug)]
struct CountryRecord {
    iso_code: Option<String>,
}

/// Minimal struct for deserializing city data from MaxMind GeoIP2/GeoLite2.
#[derive(serde::Deserialize, Debug)]
struct GeoIpCity {
    city: Option<CityRecord>,
    country: Option<CountryRecord>,
}

#[derive(serde::Deserialize, Debug)]
struct CityRecord {
    names: Option<std::collections::HashMap<String, String>>,
}

/// Minimal struct for deserializing ASN data from MaxMind GeoLite2-ASN.
#[derive(serde::Deserialize, Debug)]
struct GeoIpAsn {
    autonomous_system_number: Option<u32>,
    autonomous_system_organization: Option<String>,
}

impl GeoIpLookup {
    /// Create a new GeoIpLookup, loading MaxMind database files.
    ///
    /// If a database file is not found or fails to load, the corresponding
    /// lookups will return None (graceful degradation). This allows Fortress
    /// to run without GeoIP databases, just with reduced functionality.
    pub fn new(city_db: &str, asn_db: &str) -> Self {
        let city_reader = if Path::new(city_db).exists() {
            match maxminddb::Reader::open_readfile(city_db) {
                Ok(reader) => {
                    info!(path = city_db, "GeoIP city database loaded successfully");
                    Some(reader)
                }
                Err(e) => {
                    warn!(path = city_db, error = %e, "Failed to load GeoIP city database");
                    None
                }
            }
        } else {
            warn!(path = city_db, "GeoIP city database file not found");
            None
        };

        let asn_reader = if Path::new(asn_db).exists() {
            match maxminddb::Reader::open_readfile(asn_db) {
                Ok(reader) => {
                    info!(path = asn_db, "GeoIP ASN database loaded successfully");
                    Some(reader)
                }
                Err(e) => {
                    warn!(path = asn_db, error = %e, "Failed to load GeoIP ASN database");
                    None
                }
            }
        } else {
            warn!(path = asn_db, "GeoIP ASN database file not found");
            None
        };

        Self {
            city_reader,
            asn_reader,
        }
    }

    /// Look up the 2-letter ISO country code for an IP address.
    ///
    /// Returns None if the database is not loaded or the IP is not found.
    pub fn lookup_country(&self, ip: IpAddr) -> Option<String> {
        let reader = self.city_reader.as_ref()?;

        match reader.lookup::<GeoIpCountry>(ip) {
            Ok(result) => result
                .country
                .and_then(|c| c.iso_code)
                .map(|code| code.to_uppercase()),
            Err(e) => {
                // NotFound errors are expected for private/reserved IPs
                if !matches!(e, maxminddb::MaxMindDBError::AddressNotFoundError(_)) {
                    warn!(ip = %ip, error = %e, "GeoIP country lookup error");
                }
                None
            }
        }
    }

    /// Look up the ASN number and organization name for an IP address.
    ///
    /// Returns None if the ASN database is not loaded or the IP is not found.
    pub fn lookup_asn(&self, ip: IpAddr) -> Option<(u32, String)> {
        let reader = self.asn_reader.as_ref()?;

        match reader.lookup::<GeoIpAsn>(ip) {
            Ok(result) => {
                let asn = result.autonomous_system_number?;
                let org = result
                    .autonomous_system_organization
                    .unwrap_or_else(|| "Unknown".to_string());
                Some((asn, org))
            }
            Err(e) => {
                if !matches!(e, maxminddb::MaxMindDBError::AddressNotFoundError(_)) {
                    warn!(ip = %ip, error = %e, "GeoIP ASN lookup error");
                }
                None
            }
        }
    }

    /// Look up the city name for an IP address.
    ///
    /// Returns the English city name if available, None otherwise.
    pub fn lookup_city(&self, ip: IpAddr) -> Option<String> {
        let reader = self.city_reader.as_ref()?;

        match reader.lookup::<GeoIpCity>(ip) {
            Ok(result) => result
                .city
                .and_then(|c| c.names)
                .and_then(|names| names.get("en").cloned()),
            Err(e) => {
                if !matches!(e, maxminddb::MaxMindDBError::AddressNotFoundError(_)) {
                    warn!(ip = %ip, error = %e, "GeoIP city lookup error");
                }
                None
            }
        }
    }

    /// Check if the GeoIP city database is loaded.
    pub fn has_city_db(&self) -> bool {
        self.city_reader.is_some()
    }

    /// Check if the GeoIP ASN database is loaded.
    pub fn has_asn_db(&self) -> bool {
        self.asn_reader.is_some()
    }
}
