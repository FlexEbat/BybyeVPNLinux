# BybyeVPNLinux

⚠️ **Disclaimer / Note:** This is a Python/Linux fork of the original C++ tool [ByeByeVPN by pwnnex](https://github.com/pwnnex/ByeByeVPN). All original logic (J3 probing, SNITCH, UDP Handshakes, JA4S, GeoIP consensus, etc.) has been carefully ported and extended with deep Linux OS system checks according to standard deep packet inspection guidelines.

🌐 **Choose language:** [English](#english) | [Русский](#русский)

---

## English

### What is this?
**BybyeVPNLinux** is a full-featured VPN, Proxy, and Reality detectability analyzer for Linux. It emulates Deep Packet Inspection (DPI) and Server-side network analysis to determine if a given IP address belongs to a VPN server, proxy, or data center.

### Features
* **GeoIP Consensus:** Queries 9 separate IP intelligence databases to cross-check ASN and server hosting status.
* **TCP Stack Fingerprinting:** Detects anomalous TCP MSS window sizes (indicative of tunneling like WireGuard/OpenVPN).
* **UDP Probes (Real Handshakes):** Sends authentic handshakes for WireGuard, OpenVPN, IKEv2, QUIC, Tailscale, Hysteria2, AmneziaWG (with Double Probe for Sx=8).
* **J3 Active Probing:** Emulates standard DPI systems (like TSPU) by sending 8 distinct payloads to TLS ports to unmask XTLS/Reality.
* **Service Fingerprinting:** Detects open SOCKS5, HTTP CONNECT Proxies, Microsoft SSTP, and leaked HTTP headers (`X-Forwarded-For`, `Via`).
* **SNITCH (Speed of Light Verification):** Compares physical geographic distance to measured TCP RTT to detect impossibly fast responses (Cloudflare WARP/Anycast anomalies).
* **Client-Side Auditing (`local` command):** Checks the local Linux system for virtual interfaces (`tun0`, `wg0`), split-tunneling routing anomalies, custom DNS, and utilities like `proxychains` or `tsocks`.

### Requirements
* Linux OS
* Python 3.8+
* Sudo privileges (required for ICMP Traceroute, `/proc/net/dev` reading, and raw TCP analysis).

### Installation (via Virtual Environment)
It is highly recommended to install the dependencies inside a `venv` to avoid conflicting with your system's Python packages.

---

## Русский

### Что это?
**BybyeVPNLinux** — это полнофункциональный анализатор для выявления VPN, прокси и XTLS/Reality под ОС Linux. Он эмулирует системы ТСПУ (DPI) и проводит глубокий сетевой анализ, чтобы выяснить, является ли указанный IP-адрес VPN-сервером, прокси или обычным дата-центром.

### Особенности
* **Консенсус GeoIP:** Опрашивает 9 независимых баз данных IP-разведки для перекрестной проверки ASN и принадлежности к хостингам.
* **Отпечаток TCP стека (Fingerprint):** Выявляет аномалии размера окна TCP MSS, характерные для туннелей (WireGuard/OpenVPN).
* **UDP Пробы (Реальные хендшейки):** Отправляет настоящие handshake для WireGuard, OpenVPN, IKEv2, QUIC, Tailscale, Hysteria2, AmneziaWG (включая двойную пробу для Sx=8).
* **J3 Active Probing:** Отправляет 8 различных пакетов на TLS порты (включая .invalid SNI и пустой TCP), выявляя логику глухой защиты XTLS/Reality.
* **Детект сервисов:** Находит открытые SOCKS5, HTTP CONNECT Proxy, Microsoft SSTP и утечки HTTP-заголовков (`X-Forwarded-For`, `Via`).
* **SNITCH (Проверка скоростью света):** Сравнивает физическое расстояние между вами и сервером с реальным TCP RTT для выявления невозможных скоростей (Anycast/WARP).
* **Локальный аудит (Команда `local`):** Сканирует саму машину Linux на наличие виртуальных интерфейсов (`tun0`, `wg0`), аномалий маршрутизации (split-tunneling) и использования утилит вроде `proxychains` / `tsocks`.

### Требования
* ОС Linux
* Python 3.8+
* Права `sudo` (необходимы для ICMP трассировки, чтения `/proc/net/dev` и сырого TCP-анализа).

### Установка (через venv)
Крайне рекомендуется устанавливать зависимости в виртуальное окружение, чтобы не сломать системный Python.

```bash
git clone https://github.com/YOUR_USER/BybyeVPNLinux.git
cd BybyeVPNLinux
python3 -m venv env
source env/bin/activate
pip install scapy curl_cffi
```

### Как использовать
Запускайте скрипт с правами `sudo`, указывая путь к Python внутри созданного `venv`:

```bash
# Интерактивное меню
sudo ./env/bin/python3 byebyevpnlinux.py

# Полный серверный скан целевого IP
sudo ./env/bin/python3 byebyevpnlinux.py scan 8.8.8.8

# Сохранить отчет о сканировании в Markdown-файл
sudo ./env/bin/python3 byebyevpnlinux.py scan 8.8.8.8 --save

# Проверить свою машину на наличие локальных признаков VPN
sudo ./env/bin/python3 byebyevpnlinux.py local
```
```

---
