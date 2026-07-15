# ByebyeVPNLinux

**[English](#english)** | **[Русский](#русский)**

---

<a id="english"></a>
## English

**Note:** This project is a Linux/Python fork of the original [ByeByeVPN](https://github.com/pwnnex/ByeByeVPN) tool. It has been rewritten for Linux environments using raw sockets, `scapy` for network-level manipulation, `asyncio` for the concurrent probe pipeline, and a hand-rolled byte-accurate Chrome 131 TLS ClientHello builder for TLS-fingerprint spoofing (no `curl_cffi` dependency).

ByebyeVPNLinux is a low-level network diagnostic toolkit. Its purpose is to evaluate the detectability of circumvention protocols, proxies, and VPNs (Xray/Reality, Trojan, Shadowsocks, WireGuard, AmneziaWG, Hysteria2, SSTP) against the kind of passive and active Deep Packet Inspection (DPI) checks used by state-level middleboxes such as the Russian TSPU. It produces a 0–100 exposure score plus a separate 3-tier TSPU-style verdict (BLOCK / THROTTLE / ALLOW).

**Honesty note:** this README describes what the current script actually does. The core pipeline below runs eight phases (L3→L7); a further set of independent modules (PMTUD MTU fingerprinting, BGP-anomaly check, PTR/certificate consistency, FakeDNS-leak detection, domain-fronting check, Slowloris-style timing probe, Shannon-entropy scoring, TLS replay simulation, TTL middlebox detection, extra UDP signatures, HTML report, JSON diffing) runs alongside it and feeds the same verdict. All of it is on by default except `--slowloris`, which is opt-in since it adds ~12s per scan.

### Core Checking Strategies & Technical Mechanics

The scanner executes eight core phases, from Layer 3 (network) up to Layer 7 (application), plus a set of additional independent modules described in the section right after.

#### 1. DNS Resolution
Resolves the target host to both an IPv4 (A) and IPv6 (AAAA) address via `getaddrinfo`, preferring IPv4 for all subsequent probing. This establishes the baseline IP independent of any local DoH/DoT configuration.

#### 2. GeoIP Aggregation
Queries 5 HTTPS-only GeoIP providers (`ipapi.is`, `iplocate.io`, `ipwho.is`, `ipinfo.io`, `freeipapi.com`) in parallel via `asyncio.gather`. Flags the target as "hosting ASN" (Hetzner/OVH/AWS/DigitalOcean/etc.) if any provider's ASN/org string matches known hosting keywords — a soft signal, since state censors treat commercial-ASN traffic with more suspicion than residential/mobile traffic. The aggregated ASN string is also handed to the BGP-anomaly module (see below).

#### 3. TCP Stealth SYN-Scan & Stack Fingerprint
* **SYN-scan:** uses `scapy` to send raw SYN packets across the full **1–65535** range by default (or a curated ~210-port list with `--fast`), immediately sending RST on SYN-ACK to tear down the half-open connection without touching the application layer.
* **TCP_INFO fingerprint:** on the first open port, opens 6 real connections, measures handshake RTT (median/stddev — a large stddev is a soft signal for a userspace TUN/tunnel), and reads `TCP_INFO` (`snd_mss`/`rcv_mss`) from the socket where the kernel exposes it.
* **Closed-port behavior:** connects to a port known to be closed and records whether it gets an immediate RST (normal) or silent drop (filtered), as an informational signal. The same open/closed port pair is reused by the **TTL middlebox** module below.

#### 4. UDP Probes
Sends real handshake-shaped payloads and records which ones get a reply:
* WireGuard `MessageInitiation` on `:51820`.
* AmneziaWG Sx=8 dual-probe (junk-prefixed) on `:51820` and on the dedicated `:55555`.
* AmneziaWG S1-obfuscation sweep across 12 junk-prefix sizes on `:51820`.
* Hysteria2 QUIC v1 Initial packets on `:36712` and `:443`.
* OpenVPN `P_CONTROL_HARD_RESET_CLIENT_V2` (opcode `0x38`) on `:1194`.
* TUIC v5-shaped QUIC v1 Initial on `:443` and `:8443`.
* L2TP `SCCRQ` (Start-Control-Connection-Request) on `:1701`.
* IKEv2 `IKE_SA_INIT` on `:500` and `:4500` (NAT-T).

#### 5. Service Fingerprint + Certificate Transparency
* SSH banner grab, SOCKS5 greeting probe, a Shadowsocks-AEAD-consistent "silent immediate drop" heuristic on random bytes, an open HTTP `CONNECT` proxy check, an RKN 302-redirect check, and a check for leaked `Via`/`X-Forwarded-For` proxy headers.
* **crt.sh Certificate Transparency lookup:** for domain targets, queries `crt.sh`'s JSON API. Zero CT-log entries for an otherwise-valid cert is a strong signal of a certificate generated/served outside the normal public-CA flow.

#### 5b. uTLS Dual-Probe + JA4 / JA4S
Opens two TLS connections to each TLS port: one plain `ssl.create_default_context()` handshake, one using a byte-accurate hand-built Chrome 131 ClientHello (GREASE + padding to 512 bytes). If one succeeds and the other doesn't, that's an active Reality/XTLS-style discriminator. The tool also computes a **JA4** fingerprint for the ClientHello it sent and a **JA4S** fingerprint for the parsed ServerHello, plus a heuristic best-effort guess at the underlying TLS stack (Reality-style minimal-extension server vs. Go `crypto/tls` default vs. OpenSSL default).
> These JA4/JA4S values are a simplified, spec-shaped approximation (sorted cipher/extension SHA-256 truncated to 12 hex chars) — useful for relative comparison between scans, not guaranteed to match the canonical JA4 reference implementation byte-for-byte.

#### 6. J3 / TSPU Active Probing
Sends a fixed set of 8 probes to every open TLS port: empty TCP connection, `GET /` with a real `Host`, `CONNECT example.com:443`, a plausible SSH banner, 512 random bytes, a TLS ClientHello with a random `.invalid` SNI, an HTTP absolute-URI request, and `0xFF × 128`. A server that silently drops nearly all of these while only answering valid TLS is flagged as Reality/XTLS-consistent. A server that returns byte-identical HTTP responses to unrelated garbage payloads is flagged as a canned proxy fallback. Every raw response is additionally scored with **Shannon entropy** (bits/byte) and bucketed (text-like / structured-binary / mixed / ciphertext-like), which helps distinguish plaintext fallback pages from padded/encrypted tunnel traffic at a glance.

#### 7. SNITCH + Traceroute + SSTP
* **SNITCH:** compares the measured TCP handshake RTT against a coarse per-country expected-latency bucket derived from the GeoIP result, flagging RTTs that are implausibly low (edge/anycast node masquerading as the claimed location) or implausibly high (extra tunnel hop). This is a heuristic bucket table, **not** a real speed-of-light/Haversine distance calculation.
* **Traceroute:** ICMP traceroute via `scapy`, using the same 32-byte payload as Windows `ping.exe` (`abcdefghi...`) so the probe itself doesn't stand out on the wire. Flags `10.X.Y.Z`-range intermediate hops as informational (TSPU management-subnet pattern).
* **SSTP probe:** sends an `SSTP_DUPLEX_POST` negotiation request on `:443` to detect a Microsoft SSTP endpoint.

#### 8. Verdict
Produces two separate outputs:
* A **0–100 score** with 4 labels (`CLEAN` > 84, `NOISY` > 69, `SUSPICIOUS` > 49, `OBVIOUSLY VPN` below), built from weighted "strong" signals (named-protocol/proxy detections, FakeDNS leaks) and "soft" signals (uTLS mismatch, hosting ASN, SNITCH mismatch, timing anomalies, PTR/cert mismatch, PMTUD encapsulation, TTL middlebox, BGP anomalies, domain fronting, missing TLS anti-replay).
* A **3-tier TSPU-style verdict** — `IMMEDIATE BLOCK` (≥1 strong signal), `BLOCK (cumulative)` (≥2 soft signals), `THROTTLE / QoS` (1 soft signal), or `PASS / ALLOW` (none) — modeling how a real classifier would likely act rather than just scoring exposure.

Results can be exported as JSON (`--json`) and/or a saved Markdown transcript (`--save`), plus an optional standalone HTML report (`--html`, see below).

### Additional independent modules

These run alongside the 8-phase pipeline above (all on by default unless noted) and feed their findings into the same score/TSPU verdict and the same JSON report.

* **PMTUD MTU fingerprint** — binary-searches the path MTU using ICMP Echo with the `DF` (Don't Fragment) bit set. A discovered MTU below 1500 is matched against a table of known tunnel overheads (WireGuard/AmneziaWG ≈1420, OpenVPN/L2TP-over-UDP ≈1400, Hysteria2/QUIC ≈1350, IPv6-minimum/aggressive tunnels ≈1280) to flag likely VPN encapsulation. Disable with `--no-pmtud`.
* **BGP-prefix / routing-anomaly analysis** — queries RIPEstat's `network-info`, `as-overview`, and `rpki-validation` APIs (HTTPS-only) for the target's announcing AS, prefix, and RPKI status. Flags MOAS (Multiple Origin AS) announcements, an AS holder name that doesn't match the GeoIP-reported organization, and non-`valid` RPKI status. Disable with `--no-bgp`.
* **Reverse-DNS (PTR) vs. certificate check** — resolves the PTR record for the target IP and compares it against the Subject/SAN names on the TLS certificate served on the first open TLS port. A generic hosting-provider PTR (e.g. `123-45-67-89.customer.example-hoster.net`) that doesn't match any certificate name is flagged — typical of VPS/hosting setups fronting an unrelated domain's certificate.
* **FakeDNS leak detection** — if the target exposes `:53/udp`, a hand-rolled minimal DNS client sends an A query for a random, guaranteed-nonexistent `.invalid` hostname. A real, non-hijacking resolver returns `NXDOMAIN`/nothing; an answer landing in `198.18.0.0/15` (common V2Ray/Xray FakeDNS pool), `240.0.0.0/4` (Clash-style fake-ip pool), CGNAT (`100.64.0.0/10`) or RFC1918 space is flagged as a FakeDNS-style hijack — a strong signal.
* **Domain fronting check** — opens a TLS session using a neutral, unrelated SNI (randomly chosen from a small set of well-known CDN/cloud hostnames) but sends an HTTP request with the real target hostname in the `Host` header. If the server still answers with a valid response instead of rejecting the SNI/Host mismatch, fronting through that endpoint is flagged as possible.
* **Slowloris-style timing probe** *(opt-in via `--slowloris`)* — opens a **single** connection, sends a partial HTTP request, then drips one extra header line every few seconds. It measures how long the server tolerates the incomplete request before closing it, giving a rough read on timeout aggressiveness / presence of anti-slowloris protection. This is a single-connection timing measurement, not a resource-exhaustion attack — it never opens multiple concurrent connections.
* **Shannon-entropy analysis** — computed for every raw byte response collected during the J3 probing phase (see Phase 6 above) and reported per-probe, plus available as a standalone helper for any captured payload.
* **TLS ClientHello replay simulation** — sends the exact same byte-for-byte ClientHello (same `ClientRandom`) to a TLS port twice in a row. If both attempts get a valid, matching `ServerHello`, the endpoint doesn't appear to enforce any replay/nonce-reuse protection at the TLS layer — relevant for auditing Shadowsocks-AEAD/XTLS-style deployments for nonce handling issues. Disable with `--no-replay`.
* **TTL-based middlebox detection** — compares the IP TTL on the SYN-ACK from a known-open port against the TTL on the RST from a known-closed port. A difference of 2+ hops suggests the two paths aren't answered by the same host/interface — a common middlebox/MITM signature. Disable with `--no-ttl`.
* **`--html` report** — renders a single dark-themed standalone HTML page (score, TSPU verdict, all strong/soft/info signals, and the results of every module above) next to the usual JSON/Markdown outputs.
* **`--compare OLD.json`** — diffs the current scan's score, label, and full signal set against a previously saved `--json` report, printing which signals newly appeared, which disappeared, and the score delta. Useful for tracking whether a hardening change actually reduced detectability over time.

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

Root (`sudo`) is required for ICMP traceroute, the `scapy` SYN scan, and the PMTUD/TTL-middlebox modules.

```bash
# Full scan: all 65535 TCP ports + full pipeline + all additional modules
sudo ./env/bin/python3 byebyevpnlinux.py scan <IP_OR_DOMAIN>

# Fast scan: ~210 curated VPN/proxy/TLS/admin ports
sudo ./env/bin/python3 byebyevpnlinux.py scan <IP_OR_DOMAIN> --fast

# Export JSON report, a saved Markdown transcript, and a standalone HTML report
sudo ./env/bin/python3 byebyevpnlinux.py scan <IP_OR_DOMAIN> --json --save --html

# Diff this scan against a previous JSON report (score/label/signal delta)
sudo ./env/bin/python3 byebyevpnlinux.py scan <IP_OR_DOMAIN> --json --compare old_report.json

# Include the Slowloris-style timing probe (opt-in, adds ~12s)
sudo ./env/bin/python3 byebyevpnlinux.py scan <IP_OR_DOMAIN> --slowloris

# Skip specific additional modules
sudo ./env/bin/python3 byebyevpnlinux.py scan <IP_OR_DOMAIN> --no-pmtud --no-bgp --no-ttl --no-fronting --no-replay

# Passive mode: skip UDP / service-fuzzer / J3 / FakeDNS / fronting / replay / slowloris
# (TCP scan + GeoIP + traceroute + PMTUD + BGP + PTR + TTL-middlebox only)
sudo ./env/bin/python3 byebyevpnlinux.py scan <IP_OR_DOMAIN> --passive

# Add jittered delays between probes (lower footprint, slower scan)
sudo ./env/bin/python3 byebyevpnlinux.py scan <IP_OR_DOMAIN> --stealth

# Standalone modules
sudo ./env/bin/python3 byebyevpnlinux.py dpi <IP_OR_DOMAIN>            # SNI-RST injection probe only
sudo ./env/bin/python3 byebyevpnlinux.py ech <DOMAIN>                  # DNS HTTPS-RR / ECH probe only
sudo ./env/bin/python3 byebyevpnlinux.py audit-config <PATH>           # offline WireGuard/Xray config audit
sudo ./env/bin/python3 byebyevpnlinux.py sweep <CIDR>                  # /24-max subnet sweep with JA4S per host
```

#### `scan` flags reference

| Flag | Effect |
|---|---|
| `--fast` | curated ~210 ports instead of full 1–65535 |
| `--json` | export `<host>_report.json` |
| `--save [PATH]` | save a Markdown transcript of the run |
| `--stealth` | jittered delays between probes |
| `--passive` | skip UDP / fuzzer / J3 / FakeDNS / fronting / replay / slowloris |
| `--j3-subset N` | run only J3 probe #N (1–8) |
| `--html [PATH]` | write a standalone HTML report (default `<host>_report.html`) |
| `--compare OLD.json` | diff this scan against a prior JSON report |
| `--slowloris` | enable the Slowloris-style timing probe (opt-in, +~12s) |
| `--no-pmtud` | skip PMTUD MTU fingerprinting |
| `--no-bgp` | skip BGP-anomaly analysis (RIPEstat) |
| `--no-ttl` | skip TTL middlebox detection |
| `--no-fronting` | skip domain-fronting check |
| `--no-replay` | skip TLS ClientHello replay simulation |

---

<a id="русский"></a>
## Русский

**Примечание:** Проект — Linux/Python-форк оригинального инструмента [ByeByeVPN](https://github.com/pwnnex/ByeByeVPN). Переписан для Linux с использованием сырых сокетов, `scapy` для низкоуровневых манипуляций с пакетами, `asyncio` для параллельного пайплайна проверок, и собственного побайтового билдера Chrome 131 TLS ClientHello для подделки TLS-фингерпринта (без зависимости от `curl_cffi`).

ByebyeVPNLinux — низкоуровневый инструмент сетевой диагностики. Задача — оценить обнаруживаемость протоколов обхода блокировок, прокси и VPN (Xray/Reality, Trojan, Shadowsocks, WireGuard, AmneziaWG, Hysteria2, SSTP) для тех же пассивных и активных DPI-проверок, что использует ТСПУ. На выходе — score 0–100 и отдельный 3-tier ТСПУ-вердикт (BLOCK / THROTTLE / ALLOW).

**Важно:** этот README описывает то, что реально делает текущий скрипт. Основной пайплайн ниже выполняет восемь фаз (L3→L7); параллельно с ним работает набор независимых модулей (PMTUD-фингерпринт MTU, BGP-анализ аномалий, сверка PTR/сертификата, детект утечки FakeDNS, проверка domain fronting, Slowloris-style тайминг-проба, скоринг энтропии Шеннона, симуляция TLS replay, TTL-детект middlebox, доп. UDP-сигнатуры, HTML-отчёт, diff JSON-отчётов), результаты которых идут в тот же вердикт. Всё включено по умолчанию, кроме `--slowloris` — она опциональна, так как добавляет ~12с к скану.

### Стратегии проверок и техническая реализация

Сканер выполняет восемь основных фаз — от L3 (сеть) до L7 (приложение), плюс набор дополнительных независимых модулей, описанных в разделе сразу после.

#### 1. Разрешение DNS
Резолвит хост в IPv4 (A) и IPv6 (AAAA) через `getaddrinfo`, с приоритетом IPv4 для всех дальнейших проверок.

#### 2. GeoIP-агрегация
Опрашивает 5 HTTPS-провайдеров (`ipapi.is`, `iplocate.io`, `ipwho.is`, `ipinfo.io`, `freeipapi.com`) параллельно через `asyncio.gather`. Помечает IP как "hosting ASN", если ASN/org совпадает с ключевыми словами хостинг-провайдеров — это мягкий (soft) сигнал. Агрегированная строка ASN также передаётся в модуль BGP-анализа (см. ниже).

#### 3. TCP Stealth SYN-scan и фингерпринт стека
* **SYN-scan:** через `scapy`, по умолчанию весь диапазон **1–65535** (или ~210 curated-портов с `--fast`), с немедленным RST на SYN-ACK.
* **TCP_INFO фингерпринт:** на первом открытом порту — 6 реальных подключений, медиана/стандартное отклонение RTT (большой разброс — мягкий сигнал userspace-туннеля) и чтение `TCP_INFO` (`snd_mss`/`rcv_mss`) там, где ядро это отдаёт.
* **Поведение закрытого порта:** проверка — приходит ли немедленный RST (норма) или соединение тихо дропается (фильтрация). Та же пара открытый/закрытый порт переиспользуется модулем **TTL middlebox** ниже.

#### 4. UDP-пробы
Реальные handshake-подобные payload'ы:
* WireGuard `MessageInitiation` на `:51820`.
* AmneziaWG Sx=8 dual-probe на `:51820` и на выделенном `:55555`.
* AmneziaWG S1-sweep по 12 размерам junk-префикса на `:51820`.
* Hysteria2 QUIC v1 Initial на `:36712` и `:443`.
* OpenVPN `P_CONTROL_HARD_RESET_CLIENT_V2` (opcode `0x38`) на `:1194`.
* TUIC v5-подобный QUIC v1 Initial на `:443` и `:8443`.
* L2TP `SCCRQ` (Start-Control-Connection-Request) на `:1701`.
* IKEv2 `IKE_SA_INIT` на `:500` и `:4500` (NAT-T).

#### 5. Фингерпринт сервиса + Certificate Transparency
SSH-баннер, SOCKS5-greeting, эвристика "мгновенный тихий дроп" в духе Shadowsocks-AEAD, проверка открытого HTTP `CONNECT`-прокси, проверка RKN-редиректа, проверка утечки заголовков `Via`/`X-Forwarded-For`.
**crt.sh:** для доменных целей — запрос к JSON API `crt.sh`. Ноль записей в CT-логах при валидном сертификате — сильный сигнал того, что сертификат генерируется/подставляется не через обычный публичный CA-флоу.

#### 5b. uTLS dual-probe + JA4 / JA4S
Два TLS-соединения на каждый TLS-порт: обычный `ssl`-хэндшейк и побайтовый Chrome 131 ClientHello (GREASE + паддинг до 512 байт). Расхождение результатов — активный Reality/XTLS-дискриминатор. Считаются **JA4** (по отправленному ClientHello) и **JA4S** (по разобранному ServerHello), плюс эвристическая (best-effort) догадка о стеке — Reality-стиль минимальных extensions, Go `crypto/tls` дефолт, или OpenSSL дефолт.
> Это упрощённая, по духу спеки, реализация JA4/JA4S (SHA-256 от отсортированных списков шифров/extensions, обрезанный до 12 hex-символов) — полезна для сравнения между сканами, но не гарантированно совпадает побайтово с эталонной реализацией JA4.

#### 6. J3 / активное зондирование ТСПУ
Фиксированный набор из 8 проб на каждый открытый TLS-порт: пустое TCP-соединение, `GET /` с реальным `Host`, `CONNECT example.com:443`, правдоподобный SSH-баннер, 512 случайных байт, TLS ClientHello со случайным `.invalid` SNI, HTTP absolute-URI, `0xFF × 128`. Сервер, молча дропающий почти всё кроме валидного TLS — паттерн Reality/XTLS. Идентичные HTTP-ответы на разный мусор — сигнатура canned-fallback прокси. Каждый сырой ответ дополнительно оценивается по **энтропии Шеннона** (бит/байт) и классифицируется (текстоподобный / структурированный бинарный / смешанный / похожий на шифртекст) — это помогает на глаз отличить plaintext-заглушку от паддинга/шифрованного туннельного трафика.

#### 7. SNITCH + Traceroute + SSTP
* **SNITCH:** сравнивает измеренный RTT с грубой таблицей ожидаемой задержки по стране из GeoIP, помечая неправдоподобно низкий (edge/anycast-нода под видом целевой локации) или неправдоподобно высокий (лишний хоп-туннель) RTT. Это эвристическая таблица бакетов, **не** расчёт по формуле гаверсинуса/скорости света.
* **Traceroute:** ICMP через `scapy` с тем же 32-байтным payload'ом, что и у `ping.exe` (`abcdefghi...`), чтобы сам пробник не выделялся на проводе. Хопы `10.X.Y.Z` — информационный сигнал паттерна управляющей подсети ТСПУ.
* **SSTP-проба:** отправка `SSTP_DUPLEX_POST` на `:443` для обнаружения Microsoft SSTP endpoint'а.

#### 8. Вердикт
Два отдельных результата:
* **Score 0–100** с 4 лейблами (`CLEAN` > 84, `NOISY` > 69, `SUSPICIOUS` > 49, `OBVIOUSLY VPN` ниже) на основе весов "сильных" (named-протокол/прокси, утечка FakeDNS) и "мягких" (uTLS-mismatch, hosting ASN, SNITCH-несоответствие, тайминг-аномалии, PTR/сертификат mismatch, PMTUD-инкапсуляция, TTL middlebox, BGP-аномалии, domain fronting, отсутствие TLS anti-replay) сигналов.
* **3-tier ТСПУ-вердикт** — `IMMEDIATE BLOCK` (≥1 сильный сигнал), `BLOCK (cumulative)` (≥2 мягких сигнала), `THROTTLE / QoS` (1 мягкий сигнал), `PASS / ALLOW` (ничего) — моделирует, как реально поведёт себя классификатор, а не просто считает score.

Результаты можно экспортировать в JSON (`--json`) и/или сохранить как Markdown-транскрипт (`--save`), а также получить отдельный HTML-отчёт (`--html`, см. ниже).

### Дополнительные независимые модули

Работают параллельно с основным 8-фазным пайплайном (все включены по умолчанию, если не указано иное) и передают результаты в тот же score/ТСПУ-вердикт и тот же JSON-отчёт.

* **PMTUD-фингерпринт MTU** — двоичный поиск path MTU через ICMP Echo с битом `DF` (Don't Fragment). Найденный MTU ниже 1500 сверяется с таблицей типичных туннельных оверхедов (WireGuard/AmneziaWG ≈1420, OpenVPN/L2TP-over-UDP ≈1400, Hysteria2/QUIC ≈1350, IPv6-минимум/агрессивные туннели ≈1280), чтобы пометить вероятную VPN-инкапсуляцию. Отключается через `--no-pmtud`.
* **Анализ BGP-префиксов / аномалий маршрутизации** — запрашивает API RIPEstat `network-info`, `as-overview` и `rpki-validation` (только HTTPS) для анонсирующей AS, префикса и RPKI-статуса цели. Помечает MOAS-анонсы (несколько origin AS), несовпадение имени держателя AS с организацией из GeoIP, и не-`valid` RPKI-статус. Отключается через `--no-bgp`.
* **Проверка reverse-DNS (PTR) против сертификата** — резолвит PTR-запись целевого IP и сравнивает её с именами Subject/SAN сертификата на первом открытом TLS-порту. Generic PTR хостинг-провайдера (например `123-45-67-89.customer.example-hoster.net`), не совпадающая ни с одним именем сертификата, помечается — типично для VPS/хостинга, отдающего сертификат постороннего домена.
* **Детект утечки FakeDNS** — если у цели открыт `:53/udp`, собственный минимальный DNS-клиент шлёт A-запрос на случайное, заведомо несуществующее `.invalid`-имя. Нормальный, не подменяющий резолвер вернёт `NXDOMAIN`/ничего; ответ, попадающий в `198.18.0.0/15` (типичный пул V2Ray/Xray FakeDNS), `240.0.0.0/4` (fake-ip пул в духе Clash), CGNAT (`100.64.0.0/10`) или адресное пространство RFC1918, помечается как FakeDNS-style хайджек — сильный сигнал.
* **Проверка domain fronting** — открывает TLS-сессию с нейтральным, посторонним SNI (случайно выбранным из небольшого набора известных CDN/облачных хостов), но шлёт HTTP-запрос с реальным целевым доменом в заголовке `Host`. Если сервер всё равно отвечает валидным ответом вместо отказа из-за несовпадения SNI/Host, фронтинг через этот узел помечается как возможный.
* **Slowloris-style тайминг-проба** *(опционально, флаг `--slowloris`)* — открывает **одно** соединение, шлёт частичный HTTP-запрос, затем добавляет по одному заголовку с задержкой в несколько секунд. Измеряет, сколько сервер терпит незавершённый запрос перед закрытием — грубая оценка агрессивности таймаута / наличия anti-slowloris защиты. Это тайминг-замер на одном соединении, а не атака истощения ресурсов — модуль никогда не открывает несколько параллельных соединений.
* **Анализ энтропии по Шеннону** — считается для каждого сырого байтового ответа, собранного на фазе J3 (см. Фазу 6 выше), и выводится по каждой пробе, а также доступен как отдельный хелпер для любого захваченного payload'а.
* **Симуляция replay TLS ClientHello** — отправляет побайтово идентичный ClientHello (тот же `ClientRandom`) на TLS-порт дважды подряд. Если оба раза приходит валидный совпадающий `ServerHello`, эндпоинт, судя по всему, не проверяет повтор/переиспользование nonce на уровне TLS — актуально для аудита Shadowsocks-AEAD/XTLS-style развёртываний на предмет проблем с обработкой nonce. Отключается через `--no-replay`.
* **TTL-детект middlebox** — сравнивает IP TTL в SYN-ACK с заведомо открытого порта и TTL в RST с заведомо закрытого порта. Разница в 2+ хопа говорит о том, что за эти два пути отвечает не один и тот же хост/интерфейс — типичная сигнатура middlebox/MITM. Отключается через `--no-ttl`.
* **HTML-отчёт (`--html`)** — рендерит отдельную тёмную HTML-страницу (score, ТСПУ-вердикт, все strong/soft/info сигналы и результаты всех модулей выше) в дополнение к обычным JSON/Markdown-выводам.
* **`--compare OLD.json`** — сравнивает score, лейбл и полный набор сигналов текущего скана с ранее сохранённым `--json`-отчётом, выводя, какие сигналы появились, какие пропали, и дельту score. Полезно, чтобы отслеживать, реально ли снизило детектируемость то или иное изменение конфигурации.

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

`sudo` обязателен для ICMP traceroute, `scapy` SYN-скана и модулей PMTUD/TTL-middlebox.

```bash
# Полный скан: все 65535 портов + полный пайплайн + все доп. модули
sudo ./env/bin/python3 byebyevpnlinux.py scan <IP_ИЛИ_ДОМЕН>

# Быстрый скан: ~210 curated VPN/proxy/TLS/admin портов
sudo ./env/bin/python3 byebyevpnlinux.py scan <IP_ИЛИ_ДОМЕН> --fast

# Экспорт JSON-отчёта, Markdown-транскрипта и отдельного HTML-отчёта
sudo ./env/bin/python3 byebyevpnlinux.py scan <IP_ИЛИ_ДОМЕН> --json --save --html

# Сравнить этот скан с прошлым JSON-отчётом (дельта score/label/сигналов)
sudo ./env/bin/python3 byebyevpnlinux.py scan <IP_ИЛИ_ДОМЕН> --json --compare old_report.json

# Включить Slowloris-style тайминг-пробу (опционально, +~12с)
sudo ./env/bin/python3 byebyevpnlinux.py scan <IP_ИЛИ_ДОМЕН> --slowloris

# Пропустить отдельные доп. модули
sudo ./env/bin/python3 byebyevpnlinux.py scan <IP_ИЛИ_ДОМЕН> --no-pmtud --no-bgp --no-ttl --no-fronting --no-replay

# Пассивный режим: без UDP / service-fuzzer / J3 / FakeDNS / fronting / replay / slowloris
# (только TCP-скан + GeoIP + traceroute + PMTUD + BGP + PTR + TTL-middlebox)
sudo ./env/bin/python3 byebyevpnlinux.py scan <IP_ИЛИ_ДОМЕН> --passive

# С джиттер-задержками между пробами (менее заметно, дольше)
sudo ./env/bin/python3 byebyevpnlinux.py scan <IP_ИЛИ_ДОМЕН> --stealth

# Отдельные модули
sudo ./env/bin/python3 byebyevpnlinux.py dpi <IP_ИЛИ_ДОМЕН>            # только SNI-RST проба
sudo ./env/bin/python3 byebyevpnlinux.py ech <ДОМЕН>                   # только DNS HTTPS-RR / ECH проба
sudo ./env/bin/python3 byebyevpnlinux.py audit-config <ПУТЬ>           # офлайн-аудит WireGuard/Xray конфига
sudo ./env/bin/python3 byebyevpnlinux.py sweep <CIDR>                  # sweep подсети (до /24) с JA4S на хост
```

#### Справочник флагов `scan`

| Флаг | Эффект |
|---|---|
| `--fast` | curated ~210 портов вместо полного 1–65535 |
| `--json` | экспорт `<host>_report.json` |
| `--save [PATH]` | сохранить Markdown-транскрипт скана |
| `--stealth` | джиттер-задержки между пробами |
| `--passive` | пропустить UDP / fuzzer / J3 / FakeDNS / fronting / replay / slowloris |
| `--j3-subset N` | выполнить только J3-пробу №N (1–8) |
| `--html [PATH]` | сохранить отдельный HTML-отчёт (по умолчанию `<host>_report.html`) |
| `--compare OLD.json` | сравнить этот скан с прошлым JSON-отчётом |
| `--slowloris` | включить Slowloris-style тайминг-пробу (опционально, +~12с) |
| `--no-pmtud` | пропустить PMTUD-фингерпринт MTU |
| `--no-bgp` | пропустить BGP-анализ аномалий (RIPEstat) |
| `--no-ttl` | пропустить TTL-детект middlebox |
| `--no-fronting` | пропустить проверку domain fronting |
| `--no-replay` | пропустить симуляцию replay TLS ClientHello |

---

**Отказ от ответственности:**
Данный инструмент предназначен исключительно для образовательных целей, анализа защиты сетей и оценки OPSEC собственных инфраструктур. Автор не несёт ответственности за любое неправомерное использование инструмента.
