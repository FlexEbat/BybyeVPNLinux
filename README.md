# ByebyeVPNLinux

**[English](#english)** | **[Русский](#русский)**

---

<a id="english"></a>
## English

**Note:** This project is a Linux/Python fork of the original [ByeByeVPN](https://github.com/pwnnex/ByeByeVPN) tool. It has been rewritten for Linux environments using raw sockets, `scapy` for network-level manipulation, `asyncio` for the concurrent probe pipeline, and a hand-rolled byte-accurate Chrome 131 TLS ClientHello builder for TLS-fingerprint spoofing (no `curl_cffi` dependency).

ByebyeVPNLinux is a low-level network diagnostic toolkit. Its purpose is to evaluate the detectability of circumvention protocols, proxies, and VPNs (Xray/Reality, Trojan, Shadowsocks, WireGuard, AmneziaWG, Hysteria2, SSTP) against the kind of passive and active Deep Packet Inspection (DPI) checks used by state-level middleboxes such as the Russian TSPU. It produces a 0–100 exposure score plus a separate 3-tier TSPU-style verdict (BLOCK / THROTTLE / ALLOW).

**Honesty note:** this README describes what the current script actually does. A few techniques that are common in this space (PMTUD-based MTU fingerprinting, BGP-prefix analysis, reverse-DNS/PTR checks, entropy analysis, replay-attack simulation, domain-fronting checks, `--html`/`--compare` reporting) are **not implemented yet** — see [Roadmap](#roadmap-not-yet-implemented) below instead of assuming they run.

### Core Checking Strategies & Technical Mechanics

The scanner executes eight phases, from Layer 3 (network) up to Layer 7 (application).

#### 1. DNS Resolution
Resolves the target host to both an IPv4 (A) and IPv6 (AAAA) address via `getaddrinfo`, preferring IPv4 for all subsequent probing. This establishes the baseline IP independent of any local DoH/DoT configuration.

#### 2. GeoIP Aggregation
Queries 5 HTTPS-only GeoIP providers (`ipapi.is`, `iplocate.io`, `ipwho.is`, `ipinfo.io`, `freeipapi.com`) in parallel via `asyncio.gather`. Flags the target as "hosting ASN" (Hetzner/OVH/AWS/DigitalOcean/etc.) if any provider's ASN/org string matches known hosting keywords — a soft signal, since state censors treat commercial-ASN traffic with more suspicion than residential/mobile traffic.

#### 3. TCP Stealth SYN-Scan & Stack Fingerprint
* **SYN-scan:** uses `scapy` to send raw SYN packets across the full **1–65535** range by default (or a curated ~210-port list with `--fast`), immediately sending RST on SYN-ACK to tear down the half-open connection without touching the application layer.
* **TCP_INFO fingerprint:** on the first open port, opens 6 real connections, measures handshake RTT (median/stddev — a large stddev is a soft signal for a userspace TUN/tunnel), and reads `TCP_INFO` (`snd_mss`/`rcv_mss`) from the socket where the kernel exposes it.
* **Closed-port behavior:** connects to a port known to be closed and records whether it gets an immediate RST (normal) or silent drop (filtered), as an informational signal.

#### 4. UDP Probes
Sends real handshake-shaped payloads and records which ones get a reply:
* WireGuard `MessageInitiation` on `:51820`.
* AmneziaWG Sx=8 dual-probe (junk-prefixed) on `:51820` and on the dedicated `:55555`.
* AmneziaWG S1-obfuscation sweep across 12 junk-prefix sizes on `:51820`.
* Hysteria2 QUIC v1 Initial packets on `:36712` and `:443`.

#### 5. Service Fingerprint + Certificate Transparency
* SSH banner grab, SOCKS5 greeting probe, a Shadowsocks-AEAD-consistent "silent immediate drop" heuristic on random bytes, an open HTTP `CONNECT` proxy check, an RKN 302-redirect check, and a check for leaked `Via`/`X-Forwarded-For` proxy headers.
* **crt.sh Certificate Transparency lookup:** for domain targets, queries `crt.sh`'s JSON API. Zero CT-log entries for an otherwise-valid cert is a strong signal of a certificate generated/served outside the normal public-CA flow.

#### 5b. uTLS Dual-Probe + JA4 / JA4S
Opens two TLS connections to each TLS port: one plain `ssl.create_default_context()` handshake, one using a byte-accurate hand-built Chrome 131 ClientHello (GREASE + padding to 512 bytes). If one succeeds and the other doesn't, that's an active Reality/XTLS-style discriminator. The tool also computes a **JA4** fingerprint for the ClientHello it sent and a **JA4S** fingerprint for the parsed ServerHello, plus a heuristic best-effort guess at the underlying TLS stack (Reality-style minimal-extension server vs. Go `crypto/tls` default vs. OpenSSL default).
> These JA4/JA4S values are a simplified, spec-shaped approximation (sorted cipher/extension SHA-256 truncated to 12 hex chars) — useful for relative comparison between scans, not guaranteed to match the canonical JA4 reference implementation byte-for-byte.

#### 6. J3 / TSPU Active Probing
Sends a fixed set of 8 probes to every open TLS port: empty TCP connection, `GET /` with a real `Host`, `CONNECT example.com:443`, a plausible SSH banner, 512 random bytes, a TLS ClientHello with a random `.invalid` SNI, an HTTP absolute-URI request, and `0xFF × 128`. A server that silently drops nearly all of these while only answering valid TLS is flagged as Reality/XTLS-consistent. A server that returns byte-identical HTTP responses to unrelated garbage payloads is flagged as a canned proxy fallback.

#### 7. SNITCH + Traceroute + SSTP
* **SNITCH:** compares the measured TCP handshake RTT against a coarse per-country expected-latency bucket derived from the GeoIP result, flagging RTTs that are implausibly low (edge/anycast node masquerading as the claimed location) or implausibly high (extra tunnel hop). This is a heuristic bucket table, **not** a real speed-of-light/Haversine distance calculation.
* **Traceroute:** ICMP traceroute via `scapy`, using the same 32-byte payload as Windows `ping.exe` (`abcdefghi...`) so the probe itself doesn't stand out on the wire. Flags `10.X.Y.Z`-range intermediate hops as informational (TSPU management-subnet pattern).
* **SSTP probe:** sends an `SSTP_DUPLEX_POST` negotiation request on `:443` to detect a Microsoft SSTP endpoint.

#### 8. Verdict
Produces two separate outputs:
* A **0–100 score** with 4 labels (`CLEAN` > 84, `NOISY` > 69, `SUSPICIOUS` > 49, `OBVIOUSLY VPN` below), built from weighted "strong" signals (named-protocol/proxy detections) and "soft" signals (uTLS mismatch, hosting ASN, SNITCH mismatch, timing anomalies).
* A **3-tier TSPU-style verdict** — `IMMEDIATE BLOCK` (≥1 strong signal), `BLOCK (cumulative)` (≥2 soft signals), `THROTTLE / QoS` (1 soft signal), or `PASS / ALLOW` (none) — modeling how a real classifier would likely act rather than just scoring exposure.

Results can be exported as JSON (`--json`) and/or a saved Markdown transcript (`--save`).

### Installation

This tool operates at the network-interface layer and requires Linux with root privileges.

```bash
git clone https://github.com/FlexEbat/ByebyeVPNLinux.git
cd ByebyeVPNLinux

python3 -m venv env
source env/bin/activate

pip install scapy
```

### Usage

Root (`sudo`) is required for ICMP traceroute and the `scapy` SYN scan.

```bash
# Full scan: all 65535 TCP ports + full 8-phase pipeline
sudo ./env/bin/python3 byebyevpnlinux.py scan <IP_OR_DOMAIN>

# Fast scan: ~210 curated VPN/proxy/TLS/admin ports
sudo ./env/bin/python3 byebyevpnlinux.py scan <IP_OR_DOMAIN> --fast

# Export JSON report and/or a saved Markdown transcript
sudo ./env/bin/python3 byebyevpnlinux.py scan <IP_OR_DOMAIN> --json --save

# Passive mode: skip UDP / service-fuzzer / J3 (TCP scan + GeoIP + traceroute only)
sudo ./env/bin/python3 byebyevpnlinux.py scan <IP_OR_DOMAIN> --passive

# Add jittered delays between probes (lower footprint, slower scan)
sudo ./env/bin/python3 byebyevpnlinux.py scan <IP_OR_DOMAIN> --stealth

# Standalone modules
sudo ./env/bin/python3 byebyevpnlinux.py dpi <IP_OR_DOMAIN>            # SNI-RST injection probe only
sudo ./env/bin/python3 byebyevpnlinux.py ech <DOMAIN>                  # DNS HTTPS-RR / ECH probe only
sudo ./env/bin/python3 byebyevpnlinux.py audit-config <PATH>           # offline WireGuard/Xray config audit
sudo ./env/bin/python3 byebyevpnlinux.py sweep <CIDR>                  # /24-max subnet sweep with JA4S per host
```

### Roadmap (not yet implemented)

These are described in earlier drafts of this README / the upstream project's ambitions but are **not** in the current codebase. Contributions welcome:

* PMTUD-based MTU fingerprinting (VPN encapsulation detection via DF-flag ICMP probing)
* BGP-prefix / routing-anomaly analysis
* Reverse-DNS (PTR) consistency check against the TLS certificate's domain
* FakeDNS leak detection (V2Ray-style private-IP DNS hijack)
* Domain-fronting check (benign SNI + mismatched HTTP `Host`)
* Slowloris-style timing attack (partial request, measure server timeout aggressiveness)
* Shannon-entropy analysis of raw responses
* TLS ClientHello replay-attack simulation (Shadowsocks-AEAD/XTLS nonce tracking)
* `--html` visual report generation and `--compare` diffing against a prior JSON report
* TTL-based middlebox detection (differential TTL between open/closed ports)
* Additional UDP signatures: OpenVPN `HARD_RESET`, TUIC v5, L2TP, IKEv2

---

<a id="русский"></a>
## Русский

**Примечание:** Проект — Linux/Python-форк оригинального инструмента [ByeByeVPN](https://github.com/pwnnex/ByeByeVPN). Переписан для Linux с использованием сырых сокетов, `scapy` для низкоуровневых манипуляций с пакетами, `asyncio` для параллельного пайплайна проверок, и собственного побайтового билдера Chrome 131 TLS ClientHello для подделки TLS-фингерпринта (без зависимости от `curl_cffi`).

ByebyeVPNLinux — низкоуровневый инструмент сетевой диагностики. Задача — оценить обнаруживаемость протоколов обхода блокировок, прокси и VPN (Xray/Reality, Trojan, Shadowsocks, WireGuard, AmneziaWG, Hysteria2, SSTP) для тех же пассивных и активных DPI-проверок, что использует ТСПУ. На выходе — score 0–100 и отдельный 3-tier ТСПУ-вердикт (BLOCK / THROTTLE / ALLOW).

**Важно:** этот README описывает то, что реально делает текущий скрипт. Часть техник, распространённых в этой области (PMTUD-фингерпринтинг MTU, анализ BGP-префиксов, reverse-DNS/PTR, анализ энтропии, replay-атаки, domain fronting, отчёты `--html`/`--compare`), **пока не реализована** — см. [Roadmap](#roadmap-нереализовано) ниже, не рассчитывайте, что они уже работают.

### Стратегии проверок и техническая реализация

Сканер выполняет восемь фаз — от L3 (сеть) до L7 (приложение).

#### 1. Разрешение DNS
Резолвит хост в IPv4 (A) и IPv6 (AAAA) через `getaddrinfo`, с приоритетом IPv4 для всех дальнейших проверок.

#### 2. GeoIP-агрегация
Опрашивает 5 HTTPS-провайдеров (`ipapi.is`, `iplocate.io`, `ipwho.is`, `ipinfo.io`, `freeipapi.com`) параллельно через `asyncio.gather`. Помечает IP как "hosting ASN", если ASN/org совпадает с ключевыми словами хостинг-провайдеров — это мягкий (soft) сигнал.

#### 3. TCP Stealth SYN-scan и фингерпринт стека
* **SYN-scan:** через `scapy`, по умолчанию весь диапазон **1–65535** (или ~210 curated-портов с `--fast`), с немедленным RST на SYN-ACK.
* **TCP_INFO фингерпринт:** на первом открытом порту — 6 реальных подключений, медиана/стандартное отклонение RTT (большой разброс — мягкий сигнал userspace-туннеля) и чтение `TCP_INFO` (`snd_mss`/`rcv_mss`) там, где ядро это отдаёт.
* **Поведение закрытого порта:** проверка — приходит ли немедленный RST (норма) или соединение тихо дропается (фильтрация).

#### 4. UDP-пробы
Реальные handshake-подобные payload'ы:
* WireGuard `MessageInitiation` на `:51820`.
* AmneziaWG Sx=8 dual-probe на `:51820` и на выделенном `:55555`.
* AmneziaWG S1-sweep по 12 размерам junk-префикса на `:51820`.
* Hysteria2 QUIC v1 Initial на `:36712` и `:443`.

#### 5. Фингерпринт сервиса + Certificate Transparency
SSH-баннер, SOCKS5-greeting, эвристика "мгновенный тихий дроп" в духе Shadowsocks-AEAD, проверка открытого HTTP `CONNECT`-прокси, проверка RKN-редиректа, проверка утечки заголовков `Via`/`X-Forwarded-For`.
**crt.sh:** для доменных целей — запрос к JSON API `crt.sh`. Ноль записей в CT-логах при валидном сертификате — сильный сигнал того, что сертификат генерируется/подставляется не через обычный публичный CA-флоу.

#### 5b. uTLS dual-probe + JA4 / JA4S
Два TLS-соединения на каждый TLS-порт: обычный `ssl`-хэндшейк и побайтовый Chrome 131 ClientHello (GREASE + паддинг до 512 байт). Расхождение результатов — активный Reality/XTLS-дискриминатор. Считаются **JA4** (по отправленному ClientHello) и **JA4S** (по разобранному ServerHello), плюс эвристическая (best-effort) догадка о стеке — Reality-стиль минимальных extensions, Go `crypto/tls` дефолт, или OpenSSL дефолт.
> Это упрощённая, по духу спеки, реализация JA4/JA4S (SHA-256 от отсортированных списков шифров/extensions, обрезанный до 12 hex-символов) — полезна для сравнения между сканами, но не гарантированно совпадает побайтово с эталонной реализацией JA4.

#### 6. J3 / активное зондирование ТСПУ
Фиксированный набор из 8 проб на каждый открытый TLS-порт: пустое TCP-соединение, `GET /` с реальным `Host`, `CONNECT example.com:443`, правдоподобный SSH-баннер, 512 случайных байт, TLS ClientHello со случайным `.invalid` SNI, HTTP absolute-URI, `0xFF × 128`. Сервер, молча дропающий почти всё кроме валидного TLS — паттерн Reality/XTLS. Идентичные HTTP-ответы на разный мусор — сигнатура canned-fallback прокси.

#### 7. SNITCH + Traceroute + SSTP
* **SNITCH:** сравнивает измеренный RTT с грубой таблицей ожидаемой задержки по стране из GeoIP, помечая неправдоподобно низкий (edge/anycast-нода под видом целевой локации) или неправдоподобно высокий (лишний хоп-туннель) RTT. Это эвристическая таблица бакетов, **не** расчёт по формуле гаверсинуса/скорости света.
* **Traceroute:** ICMP через `scapy` с тем же 32-байтным payload'ом, что и у `ping.exe` (`abcdefghi...`), чтобы сам пробник не выделялся на проводе. Хопы `10.X.Y.Z` — информационный сигнал паттерна управляющей подсети ТСПУ.
* **SSTP-проба:** отправка `SSTP_DUPLEX_POST` на `:443` для обнаружения Microsoft SSTP endpoint'а.

#### 8. Вердикт
Два отдельных результата:
* **Score 0–100** с 4 лейблами (`CLEAN` > 84, `NOISY` > 69, `SUSPICIOUS` > 49, `OBVIOUSLY VPN` ниже) на основе весов "сильных" (named-протокол/прокси) и "мягких" (uTLS-mismatch, hosting ASN, SNITCH-несоответствие, тайминг-аномалии) сигналов.
* **3-tier ТСПУ-вердикт** — `IMMEDIATE BLOCK` (≥1 сильный сигнал), `BLOCK (cumulative)` (≥2 мягких сигнала), `THROTTLE / QoS` (1 мягкий сигнал), `PASS / ALLOW` (ничего) — моделирует, как реально поведёт себя классификатор, а не просто считает score.

Результаты можно экспортировать в JSON (`--json`) и/или сохранить как Markdown-транскрипт (`--save`).

### Установка

Инструмент работает на уровне сетевых интерфейсов, нужен Linux с правами root.

```bash
git clone https://github.com/FlexEbat/ByebyeVPNLinux.git
cd ByebyeVPNLinux

python3 -m venv env
source env/bin/activate

pip install scapy
```

### Использование

`sudo` обязателен для ICMP traceroute и `scapy` SYN-скана.

```bash
# Полный скан: все 65535 портов + полный 8-фазный пайплайн
sudo ./env/bin/python3 byebyevpnlinux.py scan <IP_ИЛИ_ДОМЕН>

# Быстрый скан: ~210 curated VPN/proxy/TLS/admin портов
sudo ./env/bin/python3 byebyevpnlinux.py scan <IP_ИЛИ_ДОМЕН> --fast

# Экспорт JSON-отчёта и/или сохранённого Markdown-транскрипта
sudo ./env/bin/python3 byebyevpnlinux.py scan <IP_ИЛИ_ДОМЕН> --json --save

# Пассивный режим: только TCP-скан + GeoIP + traceroute (без UDP/fuzzer/J3)
sudo ./env/bin/python3 byebyevpnlinux.py scan <IP_ИЛИ_ДОМЕН> --passive

# С джиттер-задержками между пробами (менее заметно, дольше)
sudo ./env/bin/python3 byebyevpnlinux.py scan <IP_ИЛИ_ДОМЕН> --stealth

# Отдельные модули
sudo ./env/bin/python3 byebyevpnlinux.py dpi <IP_ИЛИ_ДОМЕН>            # только SNI-RST проба
sudo ./env/bin/python3 byebyevpnlinux.py ech <ДОМЕН>                   # только DNS HTTPS-RR / ECH проба
sudo ./env/bin/python3 byebyevpnlinux.py audit-config <ПУТЬ>           # офлайн-аудит WireGuard/Xray конфига
sudo ./env/bin/python3 byebyevpnlinux.py sweep <CIDR>                  # sweep подсети (до /24) с JA4S на хост
```

### Roadmap (нереализовано)

Описано в более ранних черновиках README / амбициях апстрим-проекта, но **отсутствует** в текущем коде. PR приветствуются:

* PMTUD-фингерпринтинг MTU (детект VPN-инкапсуляции через ICMP с флагом DF)
* Анализ BGP-префиксов / аномалий маршрутизации
* Проверка reverse-DNS (PTR) на соответствие домену TLS-сертификата
* Обнаружение утечки FakeDNS (V2Ray-style DNS-хайджек в приватный IP)
* Проверка domain fronting (нейтральный SNI + несовпадающий HTTP `Host`)
* Тайминг-атака в духе Slowloris (частичный запрос, измерение агрессивности таймаута сервера)
* Анализ энтропии по Шеннону для сырых ответов
* Симуляция replay-атаки TLS ClientHello (отслеживание nonce у Shadowsocks-AEAD/XTLS)
* Генерация `--html`-отчёта и diff-сравнение `--compare` с прошлым JSON
* TTL-детект middlebox (разница TTL между открытым и закрытым портом)
* Дополнительные UDP-сигнатуры: OpenVPN `HARD_RESET`, TUIC v5, L2TP, IKEv2

---

**Отказ от ответственности:**
Данный инструмент предназначен исключительно для образовательных целей, анализа защиты сетей и оценки OPSEC собственных инфраструктур. Автор не несёт ответственности за любое неправомерное использование инструмента.

