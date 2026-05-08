# ByebyeVPNLinux (Full TSPU/DPI/VPN Detectability Scanner)

🌍 **[English](#english)** | 🇷🇺 **[Русский](#русский)**

---

<a id="english"></a>
## 🇬🇧 English

> **Note:** This project is a Linux fork of the original [BybyeVPN](https://github.com/pwnnex/ByeByeVPN) tool. It has been adapted and extended for Linux environments, utilizing raw sockets, `scapy` for accurate network tracing, and `curl_cffi` for advanced TLS fingerprinting.

### 📌 Overview
**ByebyeVPNLinux** is an advanced network analysis and penetration testing tool designed to evaluate the detectability of VPNs, Proxies, and circumvention tools (like Xray, Trojan, Shadowsocks, WireGuard, Amnezia, etc.) against Deep Packet Inspection (DPI) systems, specifically emulating the logic of the Russian TSPU (ТСПУ) middleboxes.

It scans a target IP or domain, runs a battery of active and passive network probes, and calculates a "DPI Exposure Score" to determine how obvious the VPN tunnel is to a passive network observer.

### ⚙️ Core Checking Strategies & How They Work

The scanner performs 8 distinct phases of analysis:

#### 1. DNS Resolution
Resolves the target domain to an IPv4 address. 

#### 2. GeoIP & ASN Analysis (Parallel Lookup)
*   **Strategy:** Queries multiple GeoIP providers concurrently.
*   **What it looks for:** Extracts the ASN (Autonomous System Number) and company name. If the ASN belongs to a known Datacenter or Cloud provider (DigitalOcean, Hetzner, AWS, etc.), it flags the IP as `HOSTING`. 
*   **DPI Logic:** DPI systems use ASN databases as a primary pre-filter. Residential IPs are trusted more than Datacenter IPs.

#### 3. TCP Port Scan & Stack Fingerprinting
*   **Strategy:** Performs a rapid asynchronous TCP connect scan. Extracts TCP metadata (RTT, MSS, Receive Window) via `getsockopt`. Checks how closed ports behave (Port 65000).
*   **What it looks for:** 
    *   **MSS (Maximum Segment Size):** If MSS is suspiciously low (e.g., `< 1350`), it strongly implies MTU overhead caused by tunnel encapsulation (VPN).
    *   **Closed Port Behavior:** If closed ports simply `drop` packets instead of returning `RST`, it indicates strict L3 firewalling or DPI ACLs.

#### 4. UDP Real Handshake Probes
*   **Strategy:** Instead of standard UDP scanning (which is unreliable), it sends **actual protocol initialization payloads** (handshakes).
*   **Payloads included:** WireGuard, AmneziaWG (Sx=8), OpenVPN (HARD_RESET), QUIC v1, TUIC v5, Hysteria2, L2TP, IKEv2.
*   **What it looks for:** If the server replies to the handshake, the specific VPN protocol is confirmed to be running.

#### 5. Service Fingerprinting & uTLS Dual-Probe
*   **Strategy:** Tests open ports for proxy behavior and TLS anomalies.
*   **What it looks for:**
    *   **HTTP Proxy:** Sends `CONNECT 8.8.8.8:443 HTTP/1.1`. If it succeeds or returns a specific error, an open proxy is detected.
    *   **Header Leaks:** Checks for `Via` or `X-Forwarded-For` in HTTP responses.
    *   **uTLS Dual-Probe (Reality Discriminator):** Performs two TLS handshakes: one using standard `OpenSSL` and one spoofing `Chrome 131` via `curl_cffi`. If the server drops one but accepts the other, it proves the server is analyzing the `ClientHello` (JA3/JA4 fingerprinting) — a hallmark of XTLS-Reality or strict CDN routing.

#### 6. J3 / TSPU Active Probing (Junk Probes)
*   **Strategy:** Sends malformed or unexpected data (raw TCP garbage, SSH banners, invalid SNI, `0xFF` bytes) to HTTP/TLS ports.
*   **What it looks for (Canned Fallback):** Real web servers (nginx/apache) respond differently depending on the garbage received. Proxy servers (like Xray or Trojan) usually route non-matching traffic to a static "fallback" handler. If the tool receives the **exact same HTTP response** (e.g., identical 360-byte `400 Bad Request`) for different raw TCP garbage, it is a guaranteed Xray/Trojan signature.

#### 7. SNITCH Latency & ICMP Traceroute
*   **Strategy:** Physics verification and network path tracing.
*   **SNITCH (Speed of Light):** Calculates the physical distance between the scanner and the target server using the Haversine formula based on GeoIP. It calculates the theoretical minimum time light takes to travel this distance in fiber optics. If the measured `TCP RTT` is *faster* than the speed of light, the server is hiding behind an Anycast network (like Cloudflare) or a WARP proxy.
*   **Traceroute:** Uses `scapy` to send ICMP packets with incrementing TTL. Looks for `10.X.Y.Z` subnets in the middle of the route, which are typical management subnets for DPI/TSPU hardware injection.

#### 8. Verdict & DPI Matrix
Aggregates all Strong, Soft, and Informational signals to generate a final score (0-100) and an emulated TSPU DPI block verdict.

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

Run the script with `sudo` (required for ICMP Traceroute and raw TCP socket analysis).

```bash
# Full scan (all 65535 ports)
sudo ./env/bin/python3 byebyevpnlinux.py <IP_OR_DOMAIN>

# Fast scan (only common VPN/Web ports)
sudo ./env/bin/python3 byebyevpnlinux.py <IP_OR_DOMAIN> --fast
```

---

<a id="русский"></a>
## 🇷🇺 Русский

> **Примечание:** Этот проект является Linux-форком оригинальной утилиты [BybyeVPN](https://github.com/pwnnex/ByeByeVPN). Он был адаптирован и расширен для работы в Linux с использованием сырых сокетов, библиотеки `scapy` для точной трассировки сети и `curl_cffi` для продвинутого фингерпринтинга TLS.

### 📌 Обзор
**ByebyeVPNLinux** — это продвинутый инструмент для сетевого анализа и пентеста, созданный для оценки «заметности» VPN-туннелей, прокси и средств обхода блокировок (Xray, Trojan, Shadowsocks, WireGuard, Amnezia и др.) для систем глубокого анализа пакетов (DPI). Скрипт эмулирует логику работы российских комплексов ТСПУ.

Он сканирует целевой IP/домен, выполняет серию активных и пассивных сетевых проверок и рассчитывает "DPI Exposure Score" (уровень заметности), чтобы понять, насколько очевиден ваш туннель для пассивного наблюдателя.

### ⚙️ Стратегии проверок и как они работают

Сканер выполняет 8 различных фаз анализа:

#### 1. DNS Разрешение (DNS Resolution)
Определяет IPv4-адрес целевого домена.

#### 2. Анализ GeoIP и ASN (Параллельный опрос)
*   **Стратегия:** Одновременный опрос нескольких GeoIP-провайдеров.
*   **Что ищет:** Извлекает номер автономной системы (ASN) и имя компании. Если ASN принадлежит известному дата-центру или хостингу (DigitalOcean, Hetzner, AWS и т.д.), IP получает флаг `HOSTING`.
*   **Логика DPI:** Системы DPI используют базы ASN как первичный фильтр. Домашним/мобильным IP-адресам доверяют больше, чем серверным.

#### 3. Сканирование TCP-портов и отпечаток стека
*   **Стратегия:** Выполняет быстрое асинхронное TCP-сканирование. Извлекает метаданные TCP (RTT, MSS, Receive Window) через `getsockopt`. Проверяет поведение закрытых портов (на примере порта 65000).
*   **Что ищет:**
    *   **MSS (Maximum Segment Size):** Если MSS подозрительно мал (например, `< 1350`), это явно указывает на издержки инкапсуляции пакетов внутри туннеля (VPN).
    *   **Поведение закрытых портов:** Если закрытые порты просто «глотают» пакеты (`drop`) вместо ответа `RST`, это указывает на жесткий L3-файрвол или ACL на стороне провайдера/DPI.

#### 4. Пробы UDP-рукопожатий (Real Handshakes)
*   **Стратегия:** Вместо обычного UDP-сканирования (которое ненадежно), скрипт отправляет **реальные пакеты инициализации протоколов** (handshakes).
*   **Включенные пейлоады:** WireGuard, AmneziaWG (Sx=8), OpenVPN (HARD_RESET), QUIC v1, TUIC v5, Hysteria2, L2TP, IKEv2.
*   **Что ищет:** Если сервер отвечает на рукопожатие, скрипт со 100% точностью подтверждает наличие конкретного VPN-протокола на порту.

#### 5. Фингерпринтинг сервисов и uTLS Dual-Probe
*   **Стратегия:** Тестирует открытые порты на наличие прокси-поведения и аномалий TLS.
*   **Что ищет:**
    *   **HTTP Proxy:** Отправляет запрос `CONNECT 8.8.8.8:443 HTTP/1.1`. В случае успеха порт помечается как открытый прокси.
    *   **Утечка заголовков:** Ищет `Via` или `X-Forwarded-For` в HTTP-ответах.
    *   **uTLS Dual-Probe (Детектор Reality):** Выполняет два TLS-рукопожатия: одно стандартное через `OpenSSL`, второе с маскировкой под `Chrome 131` через `curl_cffi`. Если сервер сбрасывает одно соединение, но принимает второе, это доказывает, что сервер анализирует `ClientHello` (JA3/JA4) — классический маркер XTLS-Reality или жесткой фильтрации CDN.

#### 6. J3 / Активное зондирование ТСПУ (Мусорные пробы)
*   **Стратегия:** Отправляет искаженные или неожиданные данные (сырой TCP-мусор, баннеры SSH, неверный SNI, байты `0xFF`) на HTTP/TLS порты.
*   **Что ищет (Canned Fallback):** Настоящие веб-серверы (nginx/apache) выдают разные ошибки в зависимости от типа поступившего мусора. Прокси-серверы (Xray, Trojan) обычно перенаправляют весь несовпадающий трафик на статический "fallback". Если инструмент получает **абсолютно одинаковый HTTP-ответ** (например, идентичный `400 Bad Request` байт в байт) на разный сырой мусор — это гарантированная сигнатура Xray/Trojan.

#### 7. SNITCH-Латентность и ICMP Traceroute
*   **Стратегия:** Физическая верификация и трассировка маршрута.
*   **SNITCH (Скорость света):** Вычисляет физическое расстояние между сканером и целевым сервером по формуле гаверсинуса (на основе GeoIP). Рассчитывает теоретическое минимальное время, за которое свет проходит это расстояние по оптоволокну. Если измеренный `TCP RTT` (пинг) *быстрее* скорости света, значит сервер прячется за Anycast-сетью (например, Cloudflare) или WARP-прокси.
*   **Traceroute:** Использует `scapy` для отправки ICMP-пакетов с возрастающим TTL. Ищет подсети `10.X.Y.Z` в середине маршрута — это типичные служебные сети управления для оборудования ТСПУ/DPI.

#### 8. Вердикт и Матрица DPI
Собирает все сильные, слабые и информационные сигналы для создания итогового рейтинга (0-100) и выдает эмулированный вердикт блокировки ТСПУ.

### 🚀 Установка

Для работы утилиты требуется **Linux** и права root (для сырых сокетов Scapy).

```bash
# Клонируем репозиторий
git clone https://github.com/FlexEbat/BybyeVPNLinux.git
cd ByebyeVPNLinux

# Создаем виртуальное окружение (Рекомендуется)
python3 -m venv env
source env/bin/activate

# Устанавливаем зависимости
pip install scapy curl_cffi
```

### 💻 Использование

Запускайте скрипт через `sudo` (это необходимо для работы ICMP Traceroute и анализа TCP стека).

```bash
# Полное сканирование (все 65535 портов)
sudo ./env/bin/python3 byebyevpnlinux.py <IP_ИЛИ_ДОМЕН>

# Быстрое сканирование (только основные порты VPN/Web)
sudo ./env/bin/python3 byebyevpnlinux.py <IP_ИЛИ_ДОМЕН> --fast
```

---
⚠️ **Disclaimer / Отказ от ответственности:**  
*This tool is intended for educational purposes, network defense analysis, and evaluating the OPSEC of your own servers. The author is not responsible for any misuse.*
*Инструмент предназначен исключительно для образовательных целей, анализа защиты сетей и проверки OPSEC собственных серверов. Автор не несет ответственности за любое неправомерное использование.*
