# ByebyeVPNLinux

**[English](#english)** | **[Русский](#русский)**

---

<a id="english"></a>
## English

**Note:** This project is a Linux fork of the original [ByeByeVPN](https://github.com/pwnnex/ByeByeVPN) tool. It has been fundamentally rewritten for Linux environments to utilize raw sockets, the `scapy` library for precise network-level manipulation, and `curl_cffi` for accurate TLS fingerprint spoofing.

ByebyeVPNLinux is a low-level network diagnostic and penetration testing toolkit. Its primary purpose is to evaluate the operational security (OPSEC) and detectability of circumvention protocols, proxies, and VPNs (Xray, Trojan, Shadowsocks, WireGuard, AmneziaWG, etc.) against passive and active Deep Packet Inspection (DPI) systems. 

The tool closely emulates the heuristic algorithms and active probing mechanisms deployed by state-level middleboxes, specifically the Russian TSPU (Technical Means of Threat Counteraction) and the Great Firewall of China (GFW). It calculates a DPI Exposure Score based on RFC violations, cryptographic anomalies, timing attacks, and physical routing inconsistencies.

### Core Checking Strategies & Technical Mechanics

The scanner executes eight distinct phases of deep analysis, shifting from Layer 3 (Network) up to Layer 7 (Application).

#### 1. DNS Resolution
Before initiating TCP/UDP flows, the tool resolves the target domain to an IPv4 address. This establishes the baseline IP for all subsequent direct-to-IP routing tests, bypassing local DNS caching or DNS-over-HTTPS configurations that might obscure the actual endpoint.

#### 2. GeoIP, BGP Routing & OSINT (Parallel Verification)
DPI systems use Autonomous System Number (ASN) databases as the first layer of traffic classification. 
*   **ASN Profiling:** The tool queries multiple GeoIP databases simultaneously. If the IP resolves to a commercial datacenter or cloud provider (e.g., Hetzner, DigitalOcean, AWS), it is flagged. State censors inherently distrust traffic flowing to commercial ASNs compared to residential or mobile ISPs.
*   **BGP Routing Analysis:** Extracts BGP prefixes to verify if the routing advertisement aligns with the claimed ASN, identifying potential BGP hijacking or bulletproof hosting anomalies.
*   **Reverse DNS (PTR):** A legitimate web server usually has a PTR record that matches its TLS domain. Proxy servers often lack PTR records entirely or resolve to default generic hostnames (e.g., `vps-12345.hoster.com`). A mismatch here is a strong indicator of "grey" infrastructure.

#### 3. TCP Stealth SYN-scan & L3 Profiling
Instead of standard OS-level `connect()` calls, which leave traces in the target's application logs, this phase constructs raw packets.
*   **Stealth SYN Scan:** Uses `scapy` to send SYN packets. If a SYN-ACK is received, the tool immediately sends an RST packet to tear down the half-open connection without notifying the application layer.
*   **Path MTU Discovery (PMTUD):** The standard Ethernet Maximum Transmission Unit is 1500 bytes. Tunneling protocols (WireGuard, IPsec) add headers, forcing the MTU down. The tool sends ICMP Echo Requests with the `DF` (Don't Fragment) flag set, incrementally reducing the payload size. If the maximum transmissible size is exactly 1420 or 1380 bytes, it mathematically proves the presence of VPN encapsulation on the route.
*   **TTL Tracking & Middlebox Detection:** Analyzes the Time-To-Live (TTL) field of returning IP packets. If an open port responds with a TTL of 54, but a closed port responds with a TTL of 114, it proves that a Middlebox (like a TSPU DPI node) is intercepting the connection and injecting its own packets before they reach the actual server.
*   **TCP Window Fingerprinting:** Reads the raw TCP Window size and MSS values from the SYN-ACK to fingerprint the underlying operating system kernel independently of the application layer.

#### 4. UDP Probes & FakeDNS Detection
Standard UDP port scanning relies on unreliable ICMP Destination Unreachable responses. This tool uses protocol-specific initiation payloads.
*   **Deterministic Handshakes:** Sends exact initialization bytes for WireGuard, AmneziaWG (with specific Sx=8 magic headers), OpenVPN (HARD_RESET), QUIC, TUIC v5, Hysteria2, L2TP, and IKEv2. A valid response absolutely confirms the protocol's presence.
*   **WireGuard Malformed Profiling:** Sends intentionally broken WireGuard MAC sequences. Kernel-space WireGuard ignores them silently; userspace implementations (like `wireguard-go`) often generate discernible error patterns or specific ICMP responses.
*   **FakeDNS Leak Detection:** Proxy clients like V2Ray often hijack DNS requests, returning fake local IP addresses (e.g., 198.18.0.1) to internal clients to track connections. The tool sends a raw DNS query for a known blocked domain. If the server responds with a private IP range, the FakeDNS routing module is exposed.

#### 5. Service, Web & Cryptographic Fingerprinting (L7)
*   **uTLS Dual-Probe (Reality Discriminator):** XTLS-Reality circumvents DPI by dropping connections that do not match specific TLS ClientHello fingerprints (like modern browsers). The tool initiates two TLS connections: one with a default OpenSSL fingerprint and one mimicking Chrome 131 using `curl_cffi`. If the server drops OpenSSL but accepts Chrome, the Reality discriminator is actively filtering traffic.
*   **Certificate Transparency (CT) Validation:** Queries `crt.sh`. Legitimate Let's Encrypt or ZeroSSL certificates are logged in public CT databases. If a server presents a valid certificate that is missing from CT logs, it indicates the certificate is being dynamically spoofed in memory (a signature of ShadowTLS or XTLS-Reality).
*   **ALPN & Long-term Certs:** Verifies Application-Layer Protocol Negotiation (ALPN). Additionally, checks the certificate's validity span. Self-signed certificates valid for 10 years are a classic signature of legacy Shadowsocks or OpenVPN setups.
*   **Timing Attacks (Slowloris Variant):** Sends a partial HTTP GET request without the terminating `\r\n\r\n`. Standard web servers (Nginx/Apache) will wait up to 60 seconds for the request to complete. Proxy servers are configured to aggressively terminate stalled connections (often under 3 seconds) to prevent resource exhaustion attacks.
*   **Domain Fronting Checks:** Sends a TLS ClientHello with a benign SNI, but sets the HTTP `Host` header to the actual target domain. Strict CDNs reject this with a 421 Misdirected Request. Misconfigured proxies process it blindly.

#### 6. J3 / TSPU Active Probing & Replay Attacks
DPI systems actively probe suspected proxy ports by sending garbage data to see how the server reacts.
*   **Canned Fallback Detection:** The tool sends raw TCP garbage, SSH protocol banners, and `0xFF` bytes to the target port. Standard web servers will return different HTTP errors (or simply close the socket) depending on the input. Proxies (Xray/Trojan) route all unrecognized traffic to a static fallback handler. If the tool receives the exact same HTTP response (e.g., a mathematically identical 360-byte 400 Bad Request) for entirely different malformed payloads, it is a definitive proxy fallback signature.
*   **Entropy Analysis:** Calculates the Shannon entropy of the server's response to random bytes. If the entropy exceeds 7.5 bits per byte, the response is heavily obfuscated or encrypted without standard protocol headers, which is a core signature of VMess or Shadowsocks.
*   **Replay Attacks:** Records a valid TLS ClientHello packet and transmits it again in a new TCP session. Protocols like Shadowsocks-AEAD and XTLS track nonces and session states; they will immediately drop the replayed connection to defend against active probing. Real web servers process replayed ClientHellos normally.
*   **SS-AEAD Length Probe:** Sends exactly 50 bytes of random data. Shadowsocks-AEAD expects specific block sizes and will wait for the block to complete, then abruptly terminate the connection, revealing its state machine behavior.

#### 7. Latency Physics (SNITCH) & ICMP Traceroute
*   **SNITCH (Speed of Light Verification):** Calculates the geographic distance between the scanning machine and the server's GeoIP location using the Haversine formula. It then computes the absolute minimum time required for light to travel that distance through fiber optic cables. If the measured TCP Round-Trip Time (RTT) is physically impossible (i.e., faster than the speed of light for that distance), the IP address is a localized Anycast edge node (like Cloudflare or WARP) masquerading as the target location.
*   **Traceroute Injection Mapping:** Uses `scapy` to execute an ICMP traceroute. It specifically analyzes intermediate hops looking for `10.X.Y.Z` internal subnets. Russian ISPs route traffic through these specific management subnets to pass packets through TSPU DPI hardware before they exit the country.

#### 8. Verdict, Reporting & Diffing
The tool processes the gathered data into a DPI Exposure Matrix. It classifies signals into Strong, Soft, and Informational categories, applies penalty weights, and calculates a final score from 0 to 100. 
It supports exporting raw data to JSON, generating HTML visual reports, and running diff comparisons (`--compare`) against previous scans to monitor OPSEC degradation over time.

### Installation

This tool operates at the network interface layer and requires a Linux environment with root privileges.

```bash
git clone https://github.com/FlexEbat/ByebyeVPNLinux.git
cd ByebyeVPNLinux

python3 -m venv env
source env/bin/activate

pip install scapy curl_cffi
```

### Usage

Root privileges (`sudo`) are strictly required for ICMP Traceroute, PMTUD, and Scapy SYN scanning.

```bash
# Full exhaustive scan across all 65535 TCP ports
sudo ./env/bin/python3 byebyevpnlinux.py <IP_OR_DOMAIN>

# Fast scan limited to common Web and VPN ports
sudo ./env/bin/python3 byebyevpnlinux.py <IP_OR_DOMAIN> --fast

# Execute scan and export raw JSON and an HTML report
sudo ./env/bin/python3 byebyevpnlinux.py <IP_OR_DOMAIN> --json --html

# Compare current network state against a historical JSON report
sudo ./env/bin/python3 byebyevpnlinux.py <IP_OR_DOMAIN> --compare <IP_OR_DOMAIN>_report.json
```

---

<a id="русский"></a>
## Русский

**Примечание:** Данный проект представляет собой Linux-форк оригинального инструмента [ByeByeVPN](https://github.com/pwnnex/ByeByeVPN). Исходный код был фундаментально переписан для работы в среде Linux с использованием сырых сокетов (raw sockets), библиотеки `scapy` для низкоуровневых манипуляций с сетевыми пакетами и `curl_cffi` для точной подделки TLS-фингерпринтов.

ByebyeVPNLinux — это низкоуровневый набор инструментов для сетевой диагностики и тестирования на проникновение. Его главная задача — оценка операционной безопасности (OPSEC) и степени обнаруживаемости протоколов обхода блокировок, прокси и VPN (Xray, Trojan, Shadowsocks, WireGuard, AmneziaWG и др.) системами глубокого анализа пакетов (DPI).

Инструмент детально эмулирует эвристические алгоритмы и механизмы активного зондирования, применяемые государственными системами фильтрации, в частности российскими ТСПУ (Технические средства противодействия угрозам) и Великим Китайским Файрволом (GFW). Итоговый рейтинг уязвимости для DPI рассчитывается на основе нарушений стандартов RFC, криптографических аномалий, тайминг-атак и физических несоответствий маршрутизации.

### Стратегии проверок и техническая реализация

Сканер выполняет восемь фаз глубокого анализа, двигаясь от сетевого уровня (Layer 3) к прикладному (Layer 7).

#### 1. Разрешение DNS
Перед инициализацией любых TCP/UDP соединений инструмент преобразует целевой домен в IPv4-адрес. Это устанавливает базовый IP для всех последующих тестов прямой маршрутизации, исключая влияние локального кэширования DNS или настроек DNS-over-HTTPS.

#### 2. GeoIP, BGP-маршрутизация и OSINT
Системы DPI используют базы данных автономных систем (ASN) как первый слой классификации трафика.
*   **Профилирование ASN:** Инструмент параллельно опрашивает несколько баз GeoIP. Если IP-адрес принадлежит коммерческому дата-центру или облачному провайдеру (Hetzner, DigitalOcean, AWS), он помечается. Государственные цензоры изначально применяют более строгие правила к трафику, идущему в коммерческие ASN, по сравнению с домашними провайдерами.
*   **Анализ BGP-маршрутизации:** Извлекает BGP-префиксы для проверки соответствия маршрутного анонса заявленной ASN, что позволяет выявлять перехваты BGP или аномалии "абузоустойчивых" хостингов.
*   **Reverse DNS (PTR):** Легитимный веб-сервер, как правило, имеет PTR-запись, совпадающую с его доменом TLS. У прокси-серверов PTR-записи часто отсутствуют или разрешаются в стандартные имена хостеров (например, `vps-12345.hoster.com`). Несоответствие здесь — сильный индикатор "серой" инфраструктуры.

#### 3. TCP Stealth SYN-сканирование и профилирование L3
Вместо стандартных системных вызовов `connect()`, которые оставляют следы в логах приложений на стороне сервера, эта фаза конструирует пакеты вручную.
*   **Stealth SYN Scan:** Использует `scapy` для отправки SYN-пакетов. При получении SYN-ACK инструмент немедленно отправляет пакет RST для разрыва полуоткрытого соединения, чтобы операционная система сервера не передала данные на уровень приложения.
*   **Path MTU Discovery (PMTUD):** Стандартный размер Maximum Transmission Unit для Ethernet составляет 1500 байт. Туннельные протоколы (WireGuard, IPsec) добавляют собственные заголовки, снижая доступный MTU. Инструмент отправляет ICMP Echo запросы с флагом `DF` (Don't Fragment), постепенно уменьшая размер полезной нагрузки. Если максимально возможный размер пакета составляет ровно 1420 или 1380 байт, это математически доказывает наличие инкапсуляции VPN на маршруте.
*   **Отслеживание TTL и обнаружение Middlebox:** Анализирует поле Time-To-Live (TTL) в возвращающихся IP-пакетах. Если открытый порт отвечает с TTL 54, а закрытый — с TTL 114, это доказывает, что оборудование промежуточной фильтрации (например, узел ТСПУ) перехватывает соединение и инжектит собственные пакеты до того, как они достигнут реального сервера.
*   **Фингерпринтинг TCP Window:** Считывает сырые значения TCP Window и MSS из пакета SYN-ACK для определения ядра операционной системы сервера независимо от прикладного ПО.

#### 4. UDP зондирование и обнаружение FakeDNS
Стандартное сканирование UDP портов полагается на ненадежные ответы ICMP Destination Unreachable. Этот инструмент использует специфичные для протоколов полезные нагрузки инициализации.
*   **Детерминированные рукопожатия:** Отправляет точные байтовые последовательности инициализации для WireGuard, AmneziaWG (со специфичными магическими заголовками Sx=8), OpenVPN (HARD_RESET), QUIC, TUIC v5, Hysteria2, L2TP и IKEv2. Валидный ответ абсолютно подтверждает наличие протокола.
*   **Профилирование искаженного WireGuard:** Отправляет намеренно поврежденные последовательности MAC-адресов WireGuard. Реализация протокола в пространстве ядра (Kernel) игнорирует их молча; реализации в пространстве пользователя (например, `wireguard-go`) часто генерируют отличимые паттерны ошибок или специфические ICMP-ответы.
*   **Утечка FakeDNS:** Прокси-клиенты вроде V2Ray часто перехватывают DNS-запросы, возвращая фиктивные локальные IP-адреса (например, 198.18.0.1) внутренним клиентам для отслеживания соединений. Инструмент отправляет сырой DNS-запрос для заведомо заблокированного домена. Если сервер отвечает диапазоном частных IP, это раскрывает наличие модуля маршрутизации FakeDNS.

#### 5. Фингерпринтинг сервисов, Web и криптографии (L7)
*   **uTLS Dual-Probe (Дискриминатор Reality):** XTLS-Reality обходит DPI, сбрасывая соединения, которые не соответствуют определенным отпечаткам TLS ClientHello (например, отпечаткам современных браузеров). Инструмент инициирует два TLS-соединения: одно со стандартным отпечатком OpenSSL и второе, имитирующее Chrome 131 с помощью `curl_cffi`. Если сервер сбрасывает OpenSSL, но принимает Chrome, это доказывает активную работу дискриминатора Reality.
*   **Валидация Certificate Transparency (CT):** Выполняет запрос к `crt.sh`. Легитимные сертификаты Let's Encrypt или ZeroSSL фиксируются в публичных базах CT. Если сервер предъявляет валидный сертификат, отсутствующий в логах CT, это указывает на то, что сертификат динамически генерируется в оперативной памяти (сигнатура ShadowTLS или XTLS-Reality).
*   **ALPN и долгосрочные сертификаты:** Проверяет согласование протоколов прикладного уровня (ALPN). Дополнительно анализируется срок действия сертификата. Самоподписанные сертификаты со сроком действия 10 лет — классическая сигнатура устаревших конфигураций Shadowsocks или OpenVPN.
*   **Тайминг-атаки (Вариация Slowloris):** Отправляет частичный HTTP GET запрос без завершающей последовательности `\r\n\r\n`. Стандартные веб-серверы (Nginx/Apache) ожидают завершения запроса до 60 секунд. Прокси-серверы настроены на агрессивное прерывание зависших соединений (часто менее чем за 3 секунды) для предотвращения атак на исчерпание ресурсов.
*   **Проверка Domain Fronting:** Отправляет TLS ClientHello с нейтральным SNI, но устанавливает HTTP-заголовок `Host` на реальный целевой домен. Строгие CDN отклоняют такие запросы ошибкой 421 Misdirected Request. Неправильно настроенные прокси обрабатывают их вслепую.

#### 6. J3 / Активное зондирование ТСПУ и Replay-атаки
Системы DPI активно проверяют подозрительные прокси-порты, отправляя мусорные данные, чтобы проанализировать реакцию сервера.
*   **Обнаружение Canned Fallback:** Инструмент отправляет сырой TCP-мусор, баннеры протокола SSH и байты `0xFF` на целевой порт. Стандартные веб-серверы вернут различные HTTP-ошибки (или просто закроют сокет) в зависимости от ввода. Прокси (Xray/Trojan) маршрутизируют весь нераспознанный трафик на статический обработчик fallback. Если инструмент получает абсолютно одинаковый HTTP-ответ (например, математически идентичную ошибку 400 Bad Request размером ровно 360 байт) на совершенно разные искаженные нагрузки — это неоспоримая сигнатура работы прокси.
*   **Анализ энтропии:** Рассчитывает энтропию по Шеннону для ответа сервера на случайные байты. Если энтропия превышает 7.5 бит на байт, ответ сильно обфусцирован или зашифрован без стандартных заголовков протокола, что является базовой сигнатурой VMess или Shadowsocks.
*   **Replay-атаки:** Записывает валидный пакет TLS ClientHello и передает его повторно в новой TCP-сессии. Протоколы типа Shadowsocks-AEAD и XTLS отслеживают nonce и состояния сессий; они немедленно сбрасывают повторное соединение для защиты от активного зондирования. Настоящие веб-серверы обрабатывают повторные ClientHello в штатном режиме.
*   **Зондирование длины SS-AEAD:** Отправляет ровно 50 байт случайных данных. Shadowsocks-AEAD ожидает определенных размеров блоков и будет ждать завершения блока, после чего резко разорвет соединение, раскрывая поведение своего конечного автомата.

#### 7. Латентная физика (SNITCH) и ICMP Traceroute
*   **SNITCH (Проверка скорости света):** Вычисляет географическое расстояние между сканирующей машиной и GeoIP-локацией сервера с помощью формулы гаверсинуса. Затем рассчитывает абсолютное минимальное время, необходимое свету для преодоления этого расстояния по оптоволоконным кабелям. Если измеренное время приема-передачи TCP (RTT) физически невозможно (т.е. быстрее скорости света для данного расстояния), значит IP-адрес является локализованным пограничным узлом Anycast (например, Cloudflare или WARP), маскирующимся под целевую локацию.
*   **Картирование инъекций Traceroute:** Использует `scapy` для выполнения ICMP-трассировки. Специфично анализирует промежуточные узлы на наличие внутренних подсетей `10.X.Y.Z`. Российские интернет-провайдеры маршрутизируют трафик через эти специфические подсети управления для пропуска пакетов через аппаратное обеспечение DPI ТСПУ перед выходом за пределы страны.

#### 8. Вердикт, отчетность и сравнение (Diffing)
Инструмент обрабатывает собранные данные в Матрицу обнаружения DPI (DPI Exposure Matrix). Сигналы классифицируются на Сильные, Слабые и Информационные, к ним применяются весовые коэффициенты штрафов, после чего рассчитывается итоговый балл от 0 до 100.
Поддерживается экспорт сырых данных в JSON, генерация визуальных HTML-отчетов и выполнение сравнений (`--compare`) с предыдущими сканированиями для мониторинга деградации OPSEC с течением времени.

### Установка

Данный инструмент работает на уровне сетевых интерфейсов и требует среды Linux с правами root.

```bash
git clone https://github.com/FlexEbat/ByebyeVPNLinux.git
cd ByebyeVPNLinux

python3 -m venv env
source env/bin/activate

pip install scapy curl_cffi
```

### Использование

Права суперпользователя (`sudo`) строго обязательны для выполнения ICMP Traceroute, PMTUD и Stealth SYN сканирования через Scapy.

```bash
# Полное исчерпывающее сканирование всех 65535 TCP портов
sudo ./env/bin/python3 byebyevpnlinux.py <IP_ИЛИ_ДОМЕН>

# Быстрое сканирование, ограниченное общими портами Web и VPN
sudo ./env/bin/python3 byebyevpnlinux.py <IP_ИЛИ_ДОМЕН> --fast

# Выполнение сканирования и экспорт сырого JSON и HTML-отчета
sudo ./env/bin/python3 byebyevpnlinux.py <IP_ИЛИ_ДОМЕН> --json --html

# Сравнение текущего состояния сети с историческим JSON-отчетом
sudo ./env/bin/python3 byebyevpnlinux.py <IP_ИЛИ_ДОМЕН> --compare <IP_ИЛИ_ДОМЕН>_report.json
```

---

**Отказ от ответственности:**
Данный инструмент предназначен исключительно для образовательных целей, анализа защиты сетей и оценки OPSEC собственных инфраструктур. Автор не несет ответственности за любое неправомерное использование инструмента.
