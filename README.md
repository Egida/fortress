<p align="center">
  <img src="https://readme-typing-svg.herokuapp.com?font=JetBrains+Mono&weight=700&size=24&duration=3000&pause=1000&color=00FF00&center=true&vCenter=true&width=200&lines=Tron" alt="Tron" />
</p>

# Fortress

Enterprise-grade anti-DDoS reverse proxy. L3/L4/L7 koruma, real-time traffic analysis, otomatik tehdit tespiti.

![Dashboard](https://files.catbox.moe/6au5t6.png)

## Özellikler

- **L7 Koruma**: Rate limiting, behavioral analysis, fingerprint detection
- **L4 Koruma**: SYN flood, connection exhaustion, slowloris tespiti
- **Challenge System**: PoW (Proof of Work) ve JS challenge
- **GeoIP**: Ülke bazlı bloklama/challenge
- **IP Reputation**: Otomatik skor sistemi
- **Auto-Ban**: Threshold bazlı otomatik yasaklama
- **Bot Detection**: JA3 fingerprint, header analysis
- **Distributed Attack Detection**: Koordineli saldırı tespiti
- **Real-time Analytics**: Live traffic monitoring

## Kurulum

```bash
# Rust gerekli
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Build
cargo build --release

# Config
cp config/fortress.example.toml config/fortress.toml
nano config/fortress.toml

# Çalıştır
./target/release/fortress --config config/fortress.toml
```

## Admin Panel

![Login](https://files.catbox.moe/veb1o3.png)

Admin panel varsayılan olarak `http://localhost:9090` adresinde çalışır.

## Services

![Services](https://files.catbox.moe/gay9oq.png)

Her domain için ayrı upstream ve koruma ayarları tanımlanabilir.

## Ayarlar

![Settings](https://files.catbox.moe/nvcidb.png)

Tüm koruma modülleri granüler şekilde yapılandırılabilir.

## Config Örneği

```toml
[server]
http_bind = "0.0.0.0:80"
https_bind = "0.0.0.0:443"

[upstream]
address = "127.0.0.1:8080"

[protection]
default_level = 1

[rate_limit]
requests_per_second = 50
burst_size = 100

[challenge]
pow_difficulty = 18
js_challenge_enabled = true
```

## API

```bash
# Status
curl -H "X-Fortress-Key: YOUR_KEY" http://localhost:9090/api/status

# Block IP
curl -X POST -H "X-Fortress-Key: YOUR_KEY" \
  -d '{"ip":"1.2.3.4","reason":"manual"}' \
  http://localhost:9090/api/blocklist

# Services
curl -H "X-Fortress-Key: YOUR_KEY" http://localhost:9090/api/fortress/services
```

## Tech Stack

- Rust + Tokio (async runtime)
- Hyper (HTTP)
- Rustls (TLS)
- Axum (Admin API)
- SQLite (persistence)
- MaxMindDB (GeoIP)

## Lisans

MIT
