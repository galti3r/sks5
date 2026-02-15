use std::net::IpAddr;
use std::path::Path;
use tracing::warn;

/// GeoIP lookup service
pub struct GeoIpService {
    reader: Option<maxminddb::Reader<Vec<u8>>>,
    allowed_countries: Vec<String>,
    denied_countries: Vec<String>,
    fail_closed: bool,
}

impl GeoIpService {
    pub fn new(
        enabled: bool,
        db_path: Option<&Path>,
        allowed: Vec<String>,
        denied: Vec<String>,
        fail_closed: bool,
    ) -> Self {
        let reader = if enabled {
            if let Some(path) = db_path {
                match maxminddb::Reader::open_readfile(path) {
                    Ok(r) => Some(r),
                    Err(e) => {
                        warn!(path = %path.display(), error = %e, "Failed to open GeoIP database");
                        None
                    }
                }
            } else {
                warn!("GeoIP enabled but no database_path configured");
                None
            }
        } else {
            None
        };

        Self {
            reader,
            allowed_countries: allowed,
            denied_countries: denied,
            fail_closed,
        }
    }

    /// Check if an IP is allowed by GeoIP rules. Returns true if no GeoIP filtering is active.
    pub fn is_allowed(&self, ip: &IpAddr) -> bool {
        if self.reader.is_none() {
            return !self.fail_closed;
        }

        if self.allowed_countries.is_empty() && self.denied_countries.is_empty() {
            return true;
        }

        let country_code = match self.lookup_country(ip) {
            Some(c) => c,
            None => return !self.fail_closed,
        };

        if !self.denied_countries.is_empty() && self.denied_countries.contains(&country_code) {
            return false;
        }

        if !self.allowed_countries.is_empty() {
            return self.allowed_countries.contains(&country_code);
        }

        true
    }

    fn lookup_country(&self, ip: &IpAddr) -> Option<String> {
        let reader = self.reader.as_ref()?;
        let lookup = reader.lookup(*ip).ok()?;
        let result: maxminddb::geoip2::Country = lookup.decode().ok()??;
        result.country.iso_code.map(|s| s.to_string())
    }
}
