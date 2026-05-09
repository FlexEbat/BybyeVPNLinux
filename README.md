# ByebyeVPNLinux

```
  ___      _           __   _____ _  _ _    _              
 | _ )_  _| |__ _  _ __\ \ / / _ \ \| | |  (_)_ _ _  ___ __
 | _ \ || | '_ \ || / -_) V /|  _/ .` | |__| | ' \ || \ \ /
 |___/\_, |_.__/\_, \___|\_/ |_| |_|\_|____|_|_||_\_,_/_\_\
      |__/      |__/                                                                                                                                          
```

🌍 **[English](#english)** | 🇷🇺 **[Русский](#русский)**

---

<a id="english"></a>
## 🇬🇧 English

> **Note:** This project is a Linux fork of the original [ByeByeVPN](https://github.com/pwnnex/ByeByeVPN) tool. It has been heavily adapted and extended for Linux environments, utilizing raw sockets, `scapy` for stealth scanning and accurate network tracing, and `curl_cffi` for advanced TLS fingerprinting.

### 📌 Overview
**ByebyeVPNLinux** is an enterprise-grade network analysis and penetration testing tool designed to evaluate the detectability of VPNs, Proxies, and circumvention tools (like Xray, Trojan, Shadowsocks, WireGuard, Amnezia, etc.) against Deep Packet Inspection (DPI) systems. It specifically emulates the logic of Russian TSPU (ТСПУ) and the Great Firewall of China (GFW).

It scans a target IP or domain, runs a massive battery of L3-L7 active and passive network probes, and calculates a "DPI Exposure Score" to determine how obvious your VPN tunnel is to a passive network observer or active censor.

### ⚙️ Core Checking Strategies & How They Work

The scanner performs 8 distinct phases of deep analysis:

#### 1. DNS Resolution
Resolves the target domain to an IPv4 address to establish the primary testing target.

#### 2. GeoIP, BGP & OSINT (Parallel Lookup)
*   **GeoIP & ASN:** Queries 7 providers concurrently. If the ASN belongs to a Datacenter or Cloud provider (Hetzner, AWS, etc.), it flags the IP as `HOSTING`. DPI systems use this as a primary pre-filter.
*   **BGP Prefix:** Extracts routing prefixes to determine ASN legitimacy.
*   **Reverse DNS (PTR):** Checks if the IP has a valid PTR record. A missing PTR or a mismatch with the TLS domain is a classic signature of "grey" proxy infrastructure.

#### 3. TCP Stealth SYN-scan & L3 Profiling
*   **Stealth SYN Scan (Scapy):** Performs a fast, half-open TCP scan that leaves minimal logs on the target server.
*   **Path MTU Discovery (PMTUD):** Sends ICMP packets with the `DF` (Don't Fragment) flag at varying sizes (1500 to 1380). If the connection MTU is `< 1500` (e.g., 1420), it mathematically proves the presence of VPN encapsulation overhead.
*   **TTL Tracking:** Compares the Time-To-Live (TTL) of packets returning from open vs. closed ports. A TTL difference `> 2` strongly indicates a Middlebox/TSPU is actively injecting packets into the stream.
*   **OS Fingerprinting:** Guesses the target OS based on the TCP Receive Window size (p0f style).

#### 4. UDP Probes & FakeDNS Detection
*   **Real Handshakes:** Instead of dumb UDP port scanning, it sends **actual protocol initialization payloads** for WireGuard, AmneziaWG (Sx=8), OpenVPN, QUIC, TUIC v5, Hysteria2, L2TP, and IKEv2.
*   **WireGuard Malformed Profiling:** Sends broken WG packets to determine if the protocol runs in the Kernel or in Userspace (`wireguard-go`).
*   **FakeDNS Leak:** Sends a DNS query for a blocked domain. If the server returns a local IP (e.g., `198.18.x.x` or `10.x.x.x`), it exposes an active Xray/V2Ray FakeDNS routing module.

#### 5. Service, Web & Crypto Fingerprinting (L7)
*   **uTLS Dual-Probe (Reality Discriminator):** Performs two TLS handshakes: one using standard `OpenSSL` and one spoofing `Chrome 131`. If the server drops one but accepts the other, it proves the server is analyzing the `ClientHello` (JA3/JA4 fingerprinting) — a hallmark of XTLS-Reality.
*   **Certificate Transparency (CT Logs):** Queries `crt.sh`. If a valid certificate is missing from public CT logs (or was issued minutes ago), it flags a dynamically generated ShadowTLS/Reality certificate.
*   **ALPN & Cert Validity:** Checks negotiated ALPNs (h2, http/1.1) and detects 10-year self-signed certificates (classic OpenVPN/Shadowsocks).
*   **WebSocket Upgrade Anomaly:** Sends a fake WS upgrade request. Unusual responses (e.g., 400 Bad Request instead of 404) reveal V2Ray WS masking.
*   **Timing Attacks (Slowloris):** Sends incomplete HTTP headers. Proxies abruptly close these connections (< 3s), while real web servers wait patiently.
*   **Domain Fronting:** Sends one SNI but a different HTTP `Host` header. Misconfigured proxies will process it, whereas real CDNs will return `421 Misdirected Request`.

#### 6. J3 / TSPU Active Probing & Replay Attacks
*   **Canned Fallback Detect:** Sends raw TCP garbage, SSH banners, and `0xFF` bytes. If the server responds with the **exact same HTTP error** (e.g., identical 360-byte `400 Bad Request`) for different garbage, it is a guaranteed Xray/Trojan fallback signature.
*   **Entropy Analysis:** Calculates the Shannon entropy of the server's response. Entropy `> 7.5` indicates highly obfuscated/encrypted garbage (VMess/Shadowsocks signature).
*   **Replay Attacks:** Records a successful TLS ClientHello and sends it again in a new connection. If the server instantly drops the second connection, it proves Anti-Replay protection is active (Shadowsocks-AEAD / XTLS).
*   **SS-AEAD Length Probe:** Sends exactly 50 bytes. Shadowsocks-AEAD servers will wait for the block to finish and immediately disconnect, revealing their presence.
*   **HTTP/2 Profiling:** Sends raw H2 prefaces to detect non-standard proxy HTTP/2 implementations.

#### 7. SNITCH Latency & ICMP Traceroute
*   **SNITCH (Speed of Light):** Calculates the physical distance between the scanner and the target using GeoIP. It computes the absolute minimum time light takes to travel this distance in fiber optics. If the measured `TCP RTT` is *faster* than the speed of light, the server is using an Anycast network (Cloudflare) or a WARP proxy.
*   **Traceroute:** Uses `scapy` to send ICMP packets with incrementing TTL. Looks for `10.X.Y.Z` subnets in the middle of the route (typical management subnets for DPI/TSPU hardware).

#### 8. Verdict, Reporting & Diffing
Aggregates all Strong, Soft, and Informational signals to generate a final score (0-100) and an emulated TSPU DPI block verdict. Supports JSON/HTML exports and cross-report diffing.

### 🚀 Installation

This tool requires **Linux** and root privileges (for Scapy raw sockets).

```bash
# Clone the repository
git clone https://github.com/FlexEbat/BybyeVPNLinux.git
cd ByebyeVPNLinux

# Create a virtual environment (Recommended)
python3 -m venv env
source env/bin/activate

# Install dependencies
pip install scapy curl_cffi
```

### 💻 Usage

Run the script with `sudo` (required for ICMP Traceroute, PMTUD, and Scapy SYN scanning).

```bash
# Full scan (all 65535 ports)
sudo ./env/bin/python3 byebyevpnlinux.py <IP_OR_DOMAIN>

# Fast scan (only common VPN/Web ports)
sudo ./env/bin/python3 byebyevpnlinux.py <IP_OR_DOMAIN> --fast

# Export results to JSON and HTML
sudo ./env/bin/python3 byebyevpnlinux.py <IP_OR_DOMAIN> --json --html

# Compare current scan against a previous JSON report (Continuous Monitoring)
sudo ./env/bin/python3 byebyevpnlinux.py <IP_OR_DOMAIN> --compare <IP_OR_DOMAIN>_report.json
```

---

<a id="русский"></a>
## 🇷🇺 Русский

> **Примечание:** Этот проект является Linux-форком оригинальной утилиты [ByeByeVPN](https://github.com/pwnnex/ByeByeVPN). Он был глубоко переработан и расширен для работы в Linux с использованием сырых сокетов, библиотеки `scapy` для скрытного сканирования и точной трассировки сети, а также `curl_cffi` для продвинутого фингерпринтинга TLS.

### 📌 Обзор
**ByebyeVPNLinux** — это инструмент корпоративного уровня (Enterprise-grade) для сетевого анализа и пентеста. Он создан для оценки «заметности» VPN-туннелей, прокси и средств обхода блокировок (Xray, Trojan, Shadowsocks, WireGuard, Amnezia и др.) для систем глубокого анализа пакетов (DPI). Скрипт детально эмулирует логику работы российских комплексов ТСПУ и Великого Китайского Файрвола (GFW).

Он сканирует целевой IP/домен, выполняет массивную серию активных и пассивных сетевых проверок на уровнях L3-L7 и рассчитывает "DPI Exposure Score" (уровень заметности), чтобы понять, насколько очевиден ваш туннель для цензора.

### ⚙️ Стратегии проверок и как они работают

Сканер выполняет 8 различных фаз глубокого анализа:

#### 1. DNS Разрешение (DNS Resolution)
Определяет IPv4-адрес целевого домена для базовой маршрутизации.

#### 2. GeoIP, BGP и OSINT (Параллельный опрос)
*   **GeoIP и ASN:** Опрашивает 7 провайдеров. Если ASN принадлежит дата-центру (Hetzner, AWS и т.д.), IP получает флаг `HOSTING`. Системы DPI используют это как первичный фильтр доверия.
*   **BGP Prefix:** Извлекает маршрутные префиксы для проверки легитимности ASN.
*   **Reverse DNS (PTR):** Проверяет наличие обратной DNS-записи. Отсутствие PTR или несоответствие домену TLS — классический признак "серой" прокси-инфраструктуры.

#### 3. TCP Stealth SYN-сканирование и профилирование L3
*   **Stealth SYN Scan (Scapy):** "Тихое" полуоткрытое сканирование портов, оставляющее минимум следов в логах целевого сервера.
*   **Path MTU Discovery (PMTUD):** Отправляет ICMP-пакеты с флагом `DF` (Don't Fragment) разного размера (от 1500 до 1380). Если MTU соединения `< 1500` (например, 1420), скрипт математически доказывает наличие издержек туннельной инкапсуляции (VPN).
*   **TTL Tracking (Поиск инъекций):** Сравнивает TTL пакетов от открытых и закрытых портов. Разница `> 2` является 100% доказательством того, что DPI (ТСПУ/GFW) стоит на маршруте и активно подделывает пакеты.
*   **OS Fingerprinting:** Угадывает ОС сервера по размеру окна TCP Receive Window (аналог утилиты p0f).

#### 4. Пробы UDP и обнаружение FakeDNS
*   **Real Handshakes:** Вместо обычного сканирования отправляет **реальные пакеты инициализации протоколов** (WireGuard, AmneziaWG (Sx=8), OpenVPN, QUIC, TUIC v5, Hysteria2, L2TP, IKEv2).
*   **WG Malformed Profiling:** Отправка "битых" пакетов WireGuard для определения того, работает ли протокол в ядре (Kernel) или в Userspace (`wireguard-go`).
*   **FakeDNS Leak:** Отправляет DNS-запрос заблокированного домена. Если сервер возвращает локальный IP (например, `198.18.x.x` или `10.x.x.x`), скрипт выявляет включенный модуль FakeDNS (часто используется в Xray/V2Ray).

#### 5. Фингерпринтинг сервисов, Web и Криптографии (L7)
*   **uTLS Dual-Probe (Детектор Reality):** Выполняет два TLS-рукопожатия: одно стандартное через `OpenSSL`, второе с маскировкой под `Chrome 131`. Если сервер сбрасывает одно соединение, но принимает второе, это доказывает анализ `ClientHello` (JA3/JA4) — маркер XTLS-Reality.
*   **Certificate Transparency (CT Logs):** Проверяет серверный сертификат по базе `crt.sh`. Отсутствие сертификата в публичных логах (или выдача 5 минут назад) выдает динамически сгенерированные сертификаты ShadowTLS/Reality.
*   **ALPN и Валидность:** Проверяет согласованные протоколы (h2, http/1.1) и выявляет самоподписанные сертификаты на 10 лет (классика OpenVPN/Shadowsocks).
*   **WebSocket Upgrade Anomaly:** Отправка фальшивого запроса на WS-соединение. Странные ответы (400 Bad Request вместо 404) выдают маскировку V2Ray WS.
*   **Тайминг-атаки (Slowloris):** Отправка неполных HTTP-заголовков. Прокси агрессивно рвут такие соединения (< 3 сек), тогда как настоящие веб-серверы ждут тайм-аута.
*   **Domain Fronting:** Отправка SNI одного домена, а HTTP-заголовка `Host` — другого. Настоящие CDN заблокируют это (`421 Misdirected Request`), а глупые прокси пропустят.

#### 6. J3 / Активное зондирование ТСПУ и Replay-атаки
*   **Canned Fallback Detect:** Отправка разного TCP-мусора, SSH-баннеров и байтов `0xFF`. Если сервер отвечает **абсолютно одинаковой HTTP-ошибкой** (например, идентичный `400 Bad Request`) на разный мусор — это гарантированная сигнатура fallback-заглушки Xray/Trojan.
*   **Анализ Энтропии:** Вычисляет энтропию по Шеннону ответа сервера. Энтропия `> 7.5` указывает на сильно обфусцированные/зашифрованные данные (сигнатура VMess/Shadowsocks).
*   **Replay-атаки (Воспроизведение):** Скрипт записывает успешный `TLS ClientHello` и отправляет его заново в новом соединении. Если сервер мгновенно рвет второе соединение, это доказывает наличие Anti-Replay защиты (Shadowsocks-AEAD / XTLS).
*   **SS-AEAD Length Probe:** Отправка ровно 50 байт мусора. Серверы Shadowsocks-AEAD ждут завершения блока и сразу рвут соединение, раскрывая себя.
*   **HTTP/2 Profiling:** Отправка сырых H2 префиксов для обнаружения нестандартных HTTP/2 реализаций внутри прокси.

#### 7. SNITCH-Латентность и ICMP Traceroute
*   **SNITCH (Скорость света):** Вычисляет физическое расстояние до сервера (по GeoIP) и рассчитывает минимальное время прохождения света по оптоволокну. Если `TCP RTT` (пинг) *быстрее* скорости света, значит сервер использует Anycast-сеть (Cloudflare) или WARP-прокси.
*   **Traceroute:** Использует `scapy` для отправки ICMP-пакетов с возрастающим TTL. Ищет подсети `10.X.Y.Z` в середине маршрута — типичные сети управления ТСПУ/DPI.

#### 8. Вердикт, Отчеты и Сравнение (Diffing)
Скрипт формирует финальный рейтинг (0-100) и эмулирует вердикт блокировки ТСПУ. Поддерживает экспорт в JSON/HTML и сравнение текущего сканирования с предыдущим.

### 🚀 Установка

Для работы утилиты требуется **Linux** и права root (для сырых сокетов Scapy).

```bash
# Клонируем репозиторий
git clone https://github.com/FlexEbat/ByebyeVPNLinux.git
cd ByebyeVPNLinux

# Создаем виртуальное окружение (Рекомендуется)
python3 -m venv env
source env/bin/activate

# Устанавливаем зависимости
pip install scapy curl_cffi
```

### 💻 Использование

Запускайте скрипт через `sudo` (это необходимо для работы ICMP Traceroute, PMTUD и Scapy SYN-сканирования).

```bash
# Полное сканирование (все 65535 портов)
sudo ./env/bin/python3 byebyevpnlinux.py <IP_ИЛИ_ДОМЕН>

# Быстрое сканирование (только основные порты VPN/Web)
sudo ./env/bin/python3 byebyevpnlinux.py <IP_ИЛИ_ДОМЕН> --fast

# Экспорт результатов в форматы JSON и HTML
sudo ./env/bin/python3 byebyevpnlinux.py <IP_ИЛИ_ДОМЕН> --json --html

# Сравнение текущего сканирования с предыдущим отчетом (Для мониторинга)
sudo ./env/bin/python3 byebyevpnlinux.py <IP_ИЛИ_ДОМЕН> --compare <IP_ИЛИ_ДОМЕН>_report.json
```

---
⚠️ **Disclaimer / Отказ от ответственности:**  
*This tool is intended for educational purposes, network defense analysis, and evaluating the OPSEC of your own servers. The author is not responsible for any misuse.*

*Инструмент предназначен исключительно для образовательных целей, анализа защиты сетей и проверки OPSEC собственных серверов. Автор не несет ответственности за любое неправомерное использование.*
