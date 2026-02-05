use std::collections::HashMap;
use std::fs;
use std::io::BufReader;
use std::sync::Arc;

use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls::version::{TLS12, TLS13};
use tracing::{debug, error, info, warn};

/
struct ClientHelloInfo {
    tls_version: u16,
    cipher_suites: Vec<u16>,
    extensions: Vec<u16>,
    elliptic_curves: Vec<u16>,
    ec_point_formats: Vec<u8>,
}

/
///
/
/
/
#[derive(Debug)]
pub struct FortressCertResolver {
    certs: HashMap<String, Arc<CertifiedKey>>,
    default_cert: Option<Arc<CertifiedKey>>,
}

impl FortressCertResolver {
    /
    /
    ///
    /
    /
    pub fn load_certs(cert_dir: &str) -> Self {
        let mut certs: HashMap<String, Arc<CertifiedKey>> = HashMap::new();
        let mut default_cert: Option<Arc<CertifiedKey>> = None;

        let entries = match fs::read_dir(cert_dir) {
            Ok(e) => e,
            Err(err) => {
                error!(
                    "Failed to read certificate directory {}: {}",
                    cert_dir, err
                );
                return Self {
                    certs,
                    default_cert,
                };
            }
        };

        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }

            let domain = match path.file_name().and_then(|n| n.to_str()) {
                Some(name) => name.to_string(),
                None => continue,
            };

            let cert_path = path.join("fullchain.pem");
            let key_path = path.join("privkey.pem");

            if !cert_path.exists() || !key_path.exists() {
                warn!(
                    "Skipping directory {} - missing fullchain.pem or privkey.pem",
                    path.display()
                );
                continue;
            }

            match load_certified_key(&cert_path, &key_path) {
                Ok(certified_key) => {
                    let ck = Arc::new(certified_key);
                    if default_cert.is_none() {
                        default_cert = Some(Arc::clone(&ck));
                    }
                    info!("Loaded TLS certificate for domain: {}", domain);
                    certs.insert(domain, ck);
                }
                Err(err) => {
                    error!(
                        "Failed to load certificate for {}: {}",
                        domain, err
                    );
                }
            }
        }

        info!(
            "TLS certificate resolver initialised: {} domain(s) loaded",
            certs.len()
        );

        Self {
            certs,
            default_cert,
        }
    }
}

impl ResolvesServerCert for FortressCertResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let sni = client_hello.server_name();

        if let Some(hostname) = sni {
            debug!("TLS SNI hostname: {}", hostname);

            if let Some(ck) = self.certs.get(hostname) {
                return Some(Arc::clone(ck));
            }

            if let Some(dot_pos) = hostname.find('.') {
                let parent = &hostname[dot_pos + 1..];
                if let Some(ck) = self.certs.get(parent) {
                    return Some(Arc::clone(ck));
                }
            }

            warn!(
                "No certificate matched SNI hostname '{}', falling back to default",
                hostname
            );
        } else {
            warn!("Client did not provide SNI hostname, using default certificate");
        }

        self.default_cert.clone()
    }
}

/
fn load_certified_key(
    cert_path: &std::path::Path,
    key_path: &std::path::Path,
) -> Result<CertifiedKey, Box<dyn std::error::Error>> {
    let cert_file = fs::File::open(cert_path)?;
    let mut cert_reader = BufReader::new(cert_file);
    let certs: Vec<rustls::pki_types::CertificateDer<'static>> =
        rustls_pemfile::certs(&mut cert_reader)
            .filter_map(|r| r.ok())
            .collect();

    if certs.is_empty() {
        return Err(format!("No certificates found in {}", cert_path.display()).into());
    }

    let key_file = fs::File::open(key_path)?;
    let mut key_reader = BufReader::new(key_file);

    let private_key = rustls_pemfile::private_key(&mut key_reader)?
        .ok_or_else(|| format!("No private key found in {}", key_path.display()))?;

    let signing_key = rustls::crypto::ring::sign::any_supported_type(&private_key)?;

    Ok(CertifiedKey::new(certs, signing_key))
}


/
///
/
/
/
pub fn build_tls_config(
    cert_dir: &str,
) -> Result<rustls::ServerConfig, Box<dyn std::error::Error>> {
    let resolver = FortressCertResolver::load_certs(cert_dir);

    let mut config = rustls::ServerConfig::builder_with_protocol_versions(&[&TLS13, &TLS12])
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(resolver));

    config.alpn_protocols = vec![b"http/1.1".to_vec()];

    Ok(config)
}


/
/
///
/
/
pub fn extract_ja3_from_client_hello(buf: &[u8]) -> Option<String> {
    let info = parse_client_hello(buf)?;


    let ciphers: String = info
        .cipher_suites
        .iter()
        .map(|c| c.to_string())
        .collect::<Vec<_>>()
        .join("-");

    let is_grease = |v: u16| -> bool {
        (v & 0x0f0f) == 0x0a0a && ((v >> 8) == (v & 0xff))
    };

    let extensions: String = info
        .extensions
        .iter()
        .copied()
        .filter(|e| !is_grease(*e))
        .map(|e| e.to_string())
        .collect::<Vec<_>>()
        .join("-");

    let curves: String = info
        .elliptic_curves
        .iter()
        .copied()
        .filter(|c| !is_grease(*c))
        .map(|c| c.to_string())
        .collect::<Vec<_>>()
        .join("-");

    let point_formats: String = info
        .ec_point_formats
        .iter()
        .map(|p| p.to_string())
        .collect::<Vec<_>>()
        .join("-");

    let ciphers_filtered: String = info
        .cipher_suites
        .iter()
        .copied()
        .filter(|c| !is_grease(*c))
        .map(|c| c.to_string())
        .collect::<Vec<_>>()
        .join("-");

    let ja3_string = format!(
        "{},{},{},{},{}",
        info.tls_version, ciphers_filtered, extensions, curves, point_formats
    );

    debug!("JA3 raw string: {}", ja3_string);

    let digest = md5_hex(ja3_string.as_bytes());
    Some(digest)
}

/
/
/
fn md5_hex(data: &[u8]) -> String {

    const S: [u32; 64] = [
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
        5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
        4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
        6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
    ];

    const K: [u32; 64] = [
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
        0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
        0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
        0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
        0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
        0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
        0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
        0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
        0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
        0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
        0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
        0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
        0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
        0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
        0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
        0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
    ];

    let mut a0: u32 = 0x67452301;
    let mut b0: u32 = 0xefcdab89;
    let mut c0: u32 = 0x98badcfe;
    let mut d0: u32 = 0x10325476;

    let orig_len_bits = (data.len() as u64) * 8;
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0x00);
    }
    msg.extend_from_slice(&orig_len_bits.to_le_bytes());

    for chunk in msg.chunks_exact(64) {
        let mut m = [0u32; 16];
        for (i, word) in m.iter_mut().enumerate() {
            *word = u32::from_le_bytes([
                chunk[4 * i],
                chunk[4 * i + 1],
                chunk[4 * i + 2],
                chunk[4 * i + 3],
            ]);
        }

        let (mut a, mut b, mut c, mut d) = (a0, b0, c0, d0);

        for i in 0..64u32 {
            let (f, g) = match i {
                0..=15 => ((b & c) | ((!b) & d), i as usize),
                16..=31 => ((d & b) | ((!d) & c), (5 * i as usize + 1) % 16),
                32..=47 => (b ^ c ^ d, (3 * i as usize + 5) % 16),
                _ => (c ^ (b | (!d)), (7 * i as usize) % 16),
            };

            let f = f
                .wrapping_add(a)
                .wrapping_add(K[i as usize])
                .wrapping_add(m[g]);
            a = d;
            d = c;
            c = b;
            b = b.wrapping_add(f.rotate_left(S[i as usize]));
        }

        a0 = a0.wrapping_add(a);
        b0 = b0.wrapping_add(b);
        c0 = c0.wrapping_add(c);
        d0 = d0.wrapping_add(d);
    }

    let digest = [
        a0.to_le_bytes(),
        b0.to_le_bytes(),
        c0.to_le_bytes(),
        d0.to_le_bytes(),
    ]
    .concat();

    hex_encode(&digest)
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}


/
///
/
///
/
/
/
/
/
/
/
/
///
/
fn parse_client_hello(data: &[u8]) -> Option<ClientHelloInfo> {
    let mut pos: usize = 0;

    if data.len() < 5 {
        return None;
    }
    let content_type = data[pos];
    pos += 1;
    if content_type != 0x16 {
        return None;
    }
    pos += 2;
    let record_len = read_u16(data, &mut pos)? as usize;
    if data.len() < pos + record_len {
        return None;
    }

    let handshake_type = read_u8(data, &mut pos)?;
    if handshake_type != 0x01 {
        return None;
    }
    let _handshake_len = read_u24(data, &mut pos)?;

    let tls_version = read_u16(data, &mut pos)?;

    if pos + 32 > data.len() {
        return None;
    }
    pos += 32;

    let session_id_len = read_u8(data, &mut pos)? as usize;
    if pos + session_id_len > data.len() {
        return None;
    }
    pos += session_id_len;

    let cs_len = read_u16(data, &mut pos)? as usize;
    if pos + cs_len > data.len() || cs_len % 2 != 0 {
        return None;
    }
    let mut cipher_suites = Vec::with_capacity(cs_len / 2);
    let cs_end = pos + cs_len;
    while pos < cs_end {
        cipher_suites.push(read_u16(data, &mut pos)?);
    }

    let comp_len = read_u8(data, &mut pos)? as usize;
    if pos + comp_len > data.len() {
        return None;
    }
    pos += comp_len;

    let mut extensions: Vec<u16> = Vec::new();
    let mut elliptic_curves: Vec<u16> = Vec::new();
    let mut ec_point_formats: Vec<u8> = Vec::new();

    if pos + 2 <= data.len() {
        let ext_total_len = read_u16(data, &mut pos)? as usize;
        let ext_end = pos + ext_total_len;
        if ext_end > data.len() {
            return None;
        }

        while pos + 4 <= ext_end {
            let ext_type = read_u16(data, &mut pos)?;
            let ext_data_len = read_u16(data, &mut pos)? as usize;
            if pos + ext_data_len > ext_end {
                return None;
            }
            let ext_data_start = pos;
            pos += ext_data_len;

            extensions.push(ext_type);

            match ext_type {
                0x000a => {
                    let mut epos = ext_data_start;
                    if epos + 2 <= pos {
                        let list_len = read_u16(data, &mut epos)? as usize;
                        let list_end = epos + list_len;
                        while epos + 2 <= list_end && epos + 2 <= data.len() {
                            elliptic_curves.push(read_u16(data, &mut epos)?);
                        }
                    }
                }
                0x000b => {
                    let mut epos = ext_data_start;
                    if epos + 1 <= pos {
                        let fmt_len = read_u8(data, &mut epos)? as usize;
                        let fmt_end = epos + fmt_len;
                        while epos < fmt_end && epos < data.len() {
                            ec_point_formats.push(read_u8(data, &mut epos)?);
                        }
                    }
                }
                _ => {}
            }
        }
    }

    Some(ClientHelloInfo {
        tls_version,
        cipher_suites,
        extensions,
        elliptic_curves,
        ec_point_formats,
    })
}


#[inline]
fn read_u8(data: &[u8], pos: &mut usize) -> Option<u8> {
    if *pos >= data.len() {
        return None;
    }
    let v = data[*pos];
    *pos += 1;
    Some(v)
}

#[inline]
fn read_u16(data: &[u8], pos: &mut usize) -> Option<u16> {
    if *pos + 2 > data.len() {
        return None;
    }
    let v = u16::from_be_bytes([data[*pos], data[*pos + 1]]);
    *pos += 2;
    Some(v)
}

#[inline]
fn read_u24(data: &[u8], pos: &mut usize) -> Option<u32> {
    if *pos + 3 > data.len() {
        return None;
    }
    let v = (data[*pos] as u32) << 16 | (data[*pos + 1] as u32) << 8 | (data[*pos + 2] as u32);
    *pos += 3;
    Some(v)
}
