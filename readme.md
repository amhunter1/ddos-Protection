# DDoS Protection System for Node.js

[![npm version](https://badge.fury.io/js/ddos-protection-system.svg)](https://badge.fury.io/js/ddos-protection-system)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A comprehensive, production-ready DDoS protection middleware for Node.js applications with advanced detection capabilities, rate limiting, geographic filtering, and behavioral analysis.

## Özellikler (Features)

- **Rate Limiting**: Dakika, saat ve gün bazlı istek sınırlandırma
- **Burst Protection**: Ani trafik artışlarının tespiti
- **Geographic Filtering**: Ülke bazlı erişim kontrolü
- **User Agent Filtering**: Şüpheli user agent'ların engellenmesi
- **IP Whitelisting/Blacklisting**: IP bazlı erişim yönetimi
- **Heuristic Analysis**: URL pattern analizi ve header kontrolü
- **Behavioral Analysis**: Kullanıcı davranış pattern analizi
- **Redis Integration**: Yüksek performanslı dağıtık önbellekleme
- **Graceful Degradation**: Redis down olduğunda kesintisiz çalışma
- **Comprehensive Logging**: Detaylı loglama sistemi
- **Framework Support**: Express, Koa ve Fastify entegrasyonu
- **Configuration Validation**: Kapsamlı konfigürasyon doğrulama
- **Security Headers**: Otomatik güvenlik header'ları
- **CLI Management Tool**: Kolay yönetim için komut satırı aracı

## Kurulum (Installation)

```bash
npm install ddos-protection-system
```

## Hızlı Başlangıç (Quick Start)

### Express.js ile Kullanım

```javascript
const express = require('express');
const { createDDoSProtection } = require('ddos-protection-system');

const app = express();

// DDoS koruması ekle
app.use(createDDoSProtection({
  maxRequestsPerMinute: 100,
  maxRequestsPerHour: 1000,
  blockedCountries: ['CN', 'RU'],
  logLevel: 'info'
}));

app.get('/', (req, res) => {
  res.json({
    message: 'Güvenli!',
    timestamp: new Date().toISOString(),
    clientIP: req.ip
  });
});

app.listen(3000, () => {
  console.log('Server 3000 portunda çalışıyor');
});
```

### Koa.js ile Kullanım

```javascript
const Koa = require('koa');
const { createKoaMiddleware } = require('ddos-protection-system');

const app = new Koa();

// DDoS koruması ekle
app.use(createKoaMiddleware({
  maxRequestsPerMinute: 100,
  blockedCountries: ['CN']
}));

app.use(async ctx => {
  ctx.body = { message: 'Güvenli!' };
});

app.listen(3000);
```

### Fastify ile Kullanım

```javascript
const fastify = require('fastify');
const { createFastifyMiddleware } = require('ddos-protection-system');

const app = fastify();

// Express uyumluluğu için kayıt
await app.register(require('fastify-express'));

// DDoS koruması ekle
app.use(createFastifyMiddleware({
  maxRequestsPerMinute: 100
}));

app.get('/', (req, reply) => {
  reply.send({ message: 'Güvenli!' });
});

app.listen(3000);
```

## Konfigürasyon Seçenekleri (Configuration Options)

### Rate Limiting

```javascript
{
  maxRequestsPerMinute: 100,    // Dakikada maksimum istek
  maxRequestsPerHour: 1000,     // Saatte maksimum istek
  maxRequestsPerDay: 5000       // Günde maksimum istek
}
```

### Burst Protection

```javascript
{
  burstThreshold: 20,           // Burst eşiği
  burstWindow: 1000             // Burst penceresi (milisaniye)
}
```

### Geographic Filtering

```javascript
{
  blockedCountries: ['CN', 'RU', 'KP'],  // Engellenen ülkeler
  allowedCountries: ['US', 'CA', 'GB']   // İzin verilen ülkeler (boş bırakılırsa engellenenler hariç hepsi)
}
```

### User Agent Filtering

```javascript
{
  blockedUserAgents: ['masscan', 'nmap', 'sqlmap'],
  suspiciousUserAgents: ['curl', 'wget']
}
```

### IP Management

```javascript
{
  blockDuration: 3600000,       // Blok süresi (milisaniye)
  maxFailedAttempts: 5,         // Maksimum başarısız deneme
  maxConnectionsPerIP: 20       // IP başına maksimum bağlantı
}
```

### Request Limits

```javascript
{
  maxRequestSize: '10mb',       // Maksimum istek boyutu
  maxURILength: 2048            // Maksimum URI uzunluğu
}
```

### Redis Configuration

```javascript
{
  redis: {
    host: 'localhost',
    port: 6379,
    password: null,
    db: 0
  }
}
```

### Logging

```javascript
{
  logLevel: 'info',             // debug, info, warn, error
  logToFile: true,              // Dosya loglama
  logFilePath: './logs/ddos.log' // Log dosyası yolu
}
```

### Whitelisting

```javascript
{
  whitelistedIPs: ['127.0.0.1', '192.168.1.1'],
  whitelistedUserAgents: ['Googlebot', 'Bingbot']
}
```

### Advanced Features

```javascript
{
  enableHeuristicAnalysis: true,    // Heuristik analiz
  enableBehavioralAnalysis: true,   // Davranışsal analiz
  enableCaptcha: false,             // CAPTCHA challenge
  enableJSChallenge: false          // JavaScript challenge
}
```

### Response Configuration

```javascript
{
  blockResponseCode: 429,           // Blok yanıtı HTTP kodu
  blockMessage: 'Too Many Requests' // Blok mesajı
}
```

### System Settings

```javascript
{
  cleanupInterval: 300000,          // Temizlik aralığı (milisaniye)
  dataRetention: 86400000           // Veri saklama süresi (milisaniye)
}
```

## Konfigürasyon Dosyaları (Configuration Files)

Sistem otomatik olarak JSON konfigürasyon dosyalarını yükler:

### `src/config/blocklist.json`

```json
{
  "countries": ["CN", "RU", "KP", "IR", "SY"],
  "userAgents": ["masscan", "nmap", "sqlmap", "nikto"],
  "ipRanges": ["1.10.16.0/20", "5.34.242.0/23"]
}
```

### `src/config/whitelist.json`

```json
{
  "ips": ["127.0.0.1", "::1", "10.0.0.1"],
  "userAgents": ["Googlebot", "Bingbot", "Slurp"]
}
```

## API Metodları (API Methods)

### İstatistikleri Al (Get Statistics)

```javascript
const protection = new DDoSProtection(options);
const stats = await protection.getStats();

console.log(stats);
// {
//   blockedIPs: 5,
//   activeConnections: 23,
//   totalRequests: 15432,
//   inMemoryBlocked: 3,
//   inMemoryConnections: 12,
//   suspiciousActivities: 8,
//   userAgentStats: 45,
//   geoStats: 12,
//   redisAvailable: true
// }
```

### Engellenen IP'leri Al (Get Blocked IPs)

```javascript
const blockedIPs = await protection.getBlockedIPs();
console.log(blockedIPs);
// [
//   {
//     ip: '192.168.1.100',
//     reason: 'RATE_LIMIT_EXCEEDED',
//     timestamp: 1638360000000,
//     expires: 1638363600000
//   }
// ]
```

### IP Engellemesini Kaldır (Unblock IP)

```javascript
await protection.unblockIP('192.168.1.100');
```

### Bağlantıyı Kapat (Close Connection)

```javascript
await protection.close();
```

## CLI Yönetim Aracı (CLI Management Tool)

### Kullanım (Usage)

```bash
node cli.js <command> [options]
```

### Komutlar (Commands)

```bash
# İstatistikleri göster
node cli.js stats

# Engellenen IP'leri listele
node cli.js blocked

# IP engellemesini kaldır
node cli.js unblock 192.168.1.100

# Konfigürasyonu göster
node cli.js config

# Yardım göster
node cli.js help
```

## Ortam Değişkenleri (Environment Variables)

```bash
# Redis Konfigürasyonu
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=mypassword

# Uygulama Konfigürasyonu
NODE_ENV=production
PORT=3000
```

## Tespit Mekanizmaları (Detection Mechanisms)

### 1. Rate Limiting
- Dakika, saat ve gün bazlı istek takibi
- Otomatik bloklama limiti aşılınca
- Hassas rate hesaplama için sliding window algoritması

### 2. Burst Detection
- Trafik pattern'lerinde ani artış tespiti
- Konfigüre edilebilir burst eşikleri ve pencereleri
- Flash attack ve ani trafik dalgalarının önüne geçme

### 3. Geographic Filtering
- MaxMind GeoIP veritabanı kullanarak IP coğrafi konumlandırma
- Ülke bazlı bloklama ve whitelist desteği
- Otomatik coğrafi istatistik güncellemeleri

### 4. User Agent Analysis
- Bilinen kötü niyetli user agent'ların bloklanması
- Şüpheli user agent pattern tespiti
- User agent istatistiklerinin tutulması

### 5. Heuristic Analysis
- Bot'ların sıklıkla eksik header göndermesi tespiti
- Şüpheli URL pattern analizi
- Parameter sayısı izleme

### 6. Behavioral Analysis
- İstek zamanlama pattern analizi
- Anormal davranış sequence tespiti
- Analiz için davranış geçmişinin saklanması

## Performans (Performance)

- **Redis Entegrasyonu**: Dağıtık sistemlerde yüksek performans
- **In-Memory Fallback**: Redis down olduğunda kesintisiz çalışma
- **Verimli Veri Yapıları**: O(1) lookup süreleri
- **Otomatik Temizlik**: Düzenli veri temizliği ve optimizasyon
- **Bağlantı Havuzu**: Verimli Redis bağlantı yönetimi

## Güvenlik Özellikleri (Security Features)

- **Çok Katmanlı Koruma**: Rate limiting, geographic filtering, behavioral analysis
- **Gerçek Zamanlı İzleme**: Sürekli trafik analizi ve tehdit tespiti
- **Otomatik Engelleme**: Şüpheli aktivitelerin otomatik bloklanması
- **Whitelist/Blacklist**: Esnek erişim kontrolü
- **Loglama**: Detaylı güvenlik olayları loglama
- **Request Validation**: İstek yapısı ve boyut validasyonu
- **Header Injection Protection**: Kötü niyetli header injection önleme
- **SQL Injection Detection**: SQL injection pattern tespiti
- **XSS Protection**: Otomatik güvenlik header'ları
- **CSRF Protection**: Request origin validasyonu

## Loglama ve İzleme (Logging and Monitoring)

Sistem kapsamlı loglama sağlar:

```javascript
// Debug seviyesi - detaylı istek bilgisi
[DEBUG] Allowed request from 192.168.1.100

// Info seviyesi - önemli olaylar
[INFO] Blocked IP 192.168.1.100 for reason: RATE_LIMIT_EXCEEDED

// Warning seviyesi - potansiyel sorunlar
[WARN] Redis connection error: Connection timeout

// Error seviyesi - kritik sorunlar
[ERROR] Failed to initialize Redis: Connection refused
```

## Production Deployment

### Docker Konfigürasyonu

```dockerfile
FROM node:16-alpine

WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production

COPY . .
EXPOSE 3000

CMD ["npm", "start"]
```

### Kubernetes Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ddos-protected-app
spec:
  replicas: 3
  template:
    spec:
      containers:
      - name: app
        image: your-app:latest
        env:
        - name: REDIS_HOST
          value: "redis-service"
        - name: REDIS_PORT
          value: "6379"
```

### Load Balancer Konfigürasyonu

```nginx
upstream app_backend {
    server app1:3000;
    server app2:3000;
    server app3:3000;
}

server {
    listen 80;
    server_name your-domain.com;

    location / {
        proxy_pass http://app_backend;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header Host $host;
    }
}
```

## Sorun Giderme (Troubleshooting)

### Yaygın Sorunlar (Common Issues)

1. **Redis Bağlantısı Başarısız**
   - Redis sunucusunun çalıştığından emin olun
   - Bağlantı kimlik bilgilerini kontrol edin
   - Firewall'un bağlantılara izin verdiğini kontrol edin

2. **Yüksek Bellek Kullanımı**
   - Temizlik aralığını ayarlayın
   - Veri saklama süresini azaltın
   - Bellek içi veri yapılarını izleyin

3. **False Positives (Yanlış Pozitif)**
   - Trafik pattern'lerine göre rate limit'leri ayarlayın
   - Meşru IP'leri whitelist'e ekleyin
   - Engellenen IP listesini düzenli olarak inceleyin

4. **Performans Sorunları**
   - Redis'in düzgün konfigüre edildiğinden emin olun
   - Sistem kaynaklarını izleyin
   - Gerekirse horizontal scaling yapın

### Debug Modu

Sorun giderme için debug loglamayı etkinleştirin:

```javascript
const protection = new DDoSProtection({
  logLevel: 'debug',
  logToFile: true
});
```

## Katkıda Bulunma (Contributing)

1. Repository'yi fork edin
2. Feature branch oluşturun
3. Değişikliklerinizi yapın
4. Yeni özellikler için test ekleyin
5. Pull request gönderin

## Lisans (License)

MIT License - LICENSE dosyasını inceleyin

## Destek (Support)

Destek ve sorularınız için:
- GitHub Issues: [Issue açın](https://github.com/amhunter1/ddos-Protection/issues)
- Email: gfwilliamtr@gmail.com
- Discord: gfwilliam
