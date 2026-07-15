#!/usr/bin/env python3
"""
ByeByeVPN — Python port, v2.8.3 spec alignment
Full TSPU/DPI/VPN detectability scanner. Scan any IP/host the way a censor sees it.

This file implements the 8-phase pipeline as described:
  1  DNS resolve (A + AAAA, IPv4 priority)
  2  GeoIP aggregation (5 HTTPS-only providers, parallel)
  3a TCP port scan (1-65535 default / curated ~200 in --fast)
  3b TCP stack fingerprint (handshake timing + TCP_INFO MSS/window + closed-port behavior)
  4  UDP probes (WireGuard / AmneziaWG dual-probe & S1-sweep / Hysteria2)
  5  Service fingerprint + CT (SSH/SOCKS5/Shadowsocks/proxy-headers/crt.sh)
  5b uTLS dual-probe + JA4 + JA4S
  6  J3 / TSPU active probing (8 fixed probes)
  7  SNITCH (RTT vs GeoIP) + traceroute (ping.exe-shaped ICMP) + SSTP probe
  8  Verdict (0-100 / 4 labels) + separate TSPU 3-tier verdict

NOTE on honesty/limitations:
  - JA4/JA4S here are simplified/approximate implementations of the public JA4 spec
    (correct methodology: sorted cipher/extension hashing), not the exact reference
    implementation. Good enough for relative fingerprinting, not for cross-tool matching.
  - SNITCH's "expected RTT per country" table is a coarse heuristic bucket, not a
    real geolocation-latency model. Treat it as a soft signal only.
  - TCP_INFO / MSS-window fingerprinting is Linux-specific (uses SO TCP_INFO) and will
    silently degrade to "unavailable" on kernels/paths that don't expose it.
"""
import asyncio
import socket
import ssl
import sys
import os
import random
import time
import json
import argparse
import math
import struct
import re
import warnings
import ipaddress
import secrets
import statistics
import hashlib
import uuid

warnings.filterwarnings("ignore")

try:
    from scapy.all import IP, ICMP, TCP, sr1, sr, conf
    conf.verb = 0
except ImportError:
    print("Error: Install scapy -> pip install scapy")
    sys.exit(1)

RED, GREEN, YELLOW, CYAN, MAGENTA, RESET = '\033[91m', '\033[92m', '\033[93m', '\033[96m', '\033[95m', '\033[0m'

report_data = {
    "target": "", "ip": "", "verdict": {}, "tspu_verdict": {}, "signals": []
}

# Windows ping.exe ICMP payload (32 bytes): abcdefghijklmnopqrstuvwabcdefghi
PING_EXE_PAYLOAD = b"abcdefghijklmnopqrstuvwabcdefghi"

# ~200 curated ports covering VPN / proxy / TLS / admin services (--fast mode)
CURATED_PORTS = sorted(set([
    20, 21, 22, 23, 25, 53, 80, 110, 111, 123, 135, 139, 143, 161, 162, 389, 443, 445, 465, 500, 502, 514, 515, 520,
    548, 554, 587, 593, 636, 646, 689, 873, 902, 989, 990, 993, 995, 1080, 1081, 1090, 1099, 1177, 1194, 1214, 1241,
    1311, 1433, 1434, 1521, 1589, 1701, 1723, 1755, 1812, 1813, 1900, 2000, 2049, 2052, 2053, 2082, 2083, 2086, 2087,
    2095, 2096, 2222, 2375, 2376, 3000, 3128, 3260, 3306, 3389, 3690, 3703, 4145, 4433, 4500, 4567, 4664, 4899, 5000,
    5001, 5060, 5061, 5222, 5223, 5228, 5432, 5555, 5601, 5666, 5672, 5900, 5901, 5984, 5985, 5986, 6000, 6379, 6443,
    6666, 6697, 6881, 6969, 7000, 7001, 7070, 7443, 7547, 7777, 8000, 8001, 8008, 8009, 8080, 8081, 8082, 8083, 8086,
    8088, 8089, 8090, 8091, 8118, 8123, 8140, 8161, 8180, 8181, 8200, 8222, 8280, 8333, 8388, 8443, 8444, 8500, 8834,
    8880, 8888, 8889, 8983, 9000, 9001, 9042, 9043, 9050, 9051, 9060, 9090, 9091, 9092, 9100, 9150, 9160, 9200, 9300,
    9418, 9443, 9500, 9800, 9900, 9990, 9999, 10000, 10001, 10050, 10051, 10250, 10443, 11211, 11371, 12345, 15672,
    16992, 16993, 17500, 18080, 18081, 19999, 20000, 20443, 25565, 27015, 27017, 28017, 30000, 30303, 31337, 32400,
    32764, 33060, 33389, 36712, 37777, 40000, 41641, 44818, 47808, 49152, 50000, 50050, 51820, 54321, 55555, 60000,
    62078, 64738,
]))


class Logger:
    def __init__(self, no_color=False):
        self.no_color = no_color
        self.save_path = None
        self.log_buffer = []

    def p(self, msg="", color=None):
        raw_msg = msg
        if color and not self.no_color:
            msg = f"{color}{msg}{RESET}"
        sys.stdout.write(msg + "\n")
        sys.stdout.flush()
        clean_msg = re.sub(r'\x1B(?:[@-Z\-_]|\[[0-?]*[ -/]*[@-~])', '', raw_msg)
        self.log_buffer.append(clean_msg)

    def flush_save(self, target_host, json_export=False, save_file=None):
        if save_file:
            path = f"{target_host.replace('/', '_')}.md" if save_file == "AUTO" else save_file
            try:
                with open(path, "w", encoding="utf-8") as f:
                    f.write("```text\n")
                    f.write("\n".join(self.log_buffer))
                    f.write("\n```\n")
                print(f"\n[+] Scan saved to {path}")
            except Exception:
                pass
        if json_export:
            try:
                with open(f"{target_host.replace('/', '_')}_report.json", "w") as f:
                    json.dump(report_data, f, indent=4)
                print(f"[+] JSON report saved", GREEN)
            except Exception:
                pass


log = Logger()


async def stealth_sleep(args):
    if hasattr(args, 'stealth') and args.stealth:
        await asyncio.sleep(random.uniform(0.2, 1.2))


async def raw_tcp_exchange(ip, port, payload, timeout=2.0):
    try:
        r, w = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=timeout)
        w.write(payload)
        await w.drain()
        data = await asyncio.wait_for(r.read(2048), timeout=timeout)
        w.close()
        return data
    except Exception:
        return b""


async def https_get(host, path, port=443, timeout=3.0, extra_headers=""):
    """Minimal HTTPS GET — no UA/Accept-*/Sec-Fetch-*, matches the 'bare GET' hardening
    described for http_get()/https_probe() (no tool-specific header fingerprint)."""
    req = f"GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n{extra_headers}\r\n"
    ctx = ssl.create_default_context()
    ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
    try:
        r, w = await asyncio.wait_for(asyncio.open_connection(host, port, ssl=ctx), timeout=timeout)
        w.write(req.encode())
        await w.drain()
        chunks = []
        try:
            while True:
                chunk = await asyncio.wait_for(r.read(4096), timeout=timeout)
                if not chunk:
                    break
                chunks.append(chunk)
        except asyncio.TimeoutError:
            pass
        w.close()
        return b"".join(chunks)
    except Exception:
        return b""


# ===================================================================
# COMMON: Shannon entropy helper (used by J3 / replay / fakedns / slowloris modules)
# ===================================================================
def shannon_entropy(data: bytes) -> float:
    """Классическая энтропия Шеннона (бит/байт), 0..8. Высокая (~7.9-8.0) -> шифртекст/
    случайные данные; низкая -> текстовый/структурированный протокол (HTTP, банеры и т.д.)."""
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    ent = 0.0
    for c in counts:
        if c:
            p = c / n
            ent -= p * math.log2(p)
    return ent


def classify_entropy(ent: float) -> str:
    if ent >= 7.5:
        return "очень высокая -> похоже на шифртекст/случайные данные (AEAD, padding, TLS)"
    if ent >= 6.0:
        return "средняя-высокая -> смешанный бинарный/сжатый контент"
    if ent >= 4.0:
        return "средняя -> структурированный бинарный протокол"
    return "низкая -> текстовый протокол (HTTP/SSH-banner/plain)"


# ===================================================================
# MODULE 1: BYTE-ACCURATE CHROME 131 CLIENTHELLO + GENERIC TLS PARSER
#           + JA4 / JA4S (simplified, spec-shaped)
# ===================================================================
_JA4_CIPHERS = ["1301", "1302", "1303", "c02b", "c02f", "c02c", "c030", "cca9", "cca8",
                "c013", "c014", "009c", "009d", "002f", "0035"]
_JA4_EXTENSIONS = ["0000", "0010", "000a", "000d", "0033", "002b", "0015"]
_JA4_SIGALGS = ["0403", "0804", "0401", "0503", "0805", "0501", "0806", "0601", "0201"]
_JA4_ALPN = "h2"


def build_chrome_131_clienthello(sni_name):
    """Побайтовая генерация Chrome 131 ClientHello с GREASE и Padding"""
    grease_val = bytes.fromhex(random.choice(["0a0a", "1a1a", "2a2a", "3a3a", "4a4a"]))

    ciphers = grease_val + bytes.fromhex("130113021303c02bc02fc02cc030cca9cca8c013c014009c009d002f0035")

    ext_sni = b"\x00\x00" + struct.pack(">H", len(sni_name) + 3) + struct.pack(">H", len(sni_name) + 1) + b"\x00" + struct.pack(">H", len(sni_name)) + sni_name.encode()
    ext_alpn = bytes.fromhex("0010000e000c02683208687474702f312e31")
    ext_supported_groups = bytes.fromhex("000a00080006001d00170018")
    ext_sig_algs = bytes.fromhex("000d00140012040308040401050308050501080606010201")
    ext_key_share = bytes.fromhex("003300260024001d0020") + secrets.token_bytes(32)
    ext_versions = bytes.fromhex("002b00050403040303")

    extensions = grease_val + b"\x00\x00" + ext_sni + ext_alpn + ext_supported_groups + ext_sig_algs + ext_key_share + ext_versions
    pad_len = 512 - (43 + len(ciphers) + len(extensions))
    if pad_len > 0:
        extensions += bytes.fromhex("0015") + struct.pack(">H", pad_len - 4) + (b"\x00" * (pad_len - 4))

    payload = b"\x03\x03" + secrets.token_bytes(32) + b"\x00" + struct.pack(">H", len(ciphers)) + ciphers + b"\x01\x00" + struct.pack(">H", len(extensions)) + extensions
    ch = b"\x01\x00" + struct.pack(">H", len(payload)) + payload
    record = b"\x16\x03\x01" + struct.pack(">H", len(ch)) + ch
    return record


def build_random_invalid_sni_clienthello():
    """J3 probe #6: TLS ClientHello with a random .invalid SNI (never resolvable, never cached)."""
    sni_name = secrets.token_hex(8) + ".invalid"
    return build_chrome_131_clienthello(sni_name)


def parse_server_hello_detailed(data):
    """Generic-ish ServerHello parser: returns dict(version, cipher, extensions[]) or None."""
    if len(data) < 6 or data[0] != 0x16:
        return None
    try:
        # record header (5) + handshake header (4) -> ServerHello body starts at offset 9
        body = data[9:]
        if len(body) < 2 + 32 + 1:
            return None
        legacy_version = body[0:2].hex()
        pos = 2 + 32
        sess_id_len = body[pos]
        pos += 1 + sess_id_len
        cipher = body[pos:pos + 2].hex()
        pos += 2
        pos += 1  # compression method
        exts = []
        if pos + 2 <= len(body):
            ext_total_len = struct.unpack(">H", body[pos:pos + 2])[0]
            pos += 2
            end = pos + ext_total_len
            while pos + 4 <= min(end, len(body)):
                etype = body[pos:pos + 2].hex()
                elen = struct.unpack(">H", body[pos + 2:pos + 4])[0]
                exts.append(etype)
                pos += 4 + elen
        return {"version": legacy_version, "cipher": cipher, "extensions": exts}
    except Exception:
        return None


def parse_server_hello(data):
    """Backwards-compat shim used by dpi/sweep modules — returns just the cipher hex."""
    d = parse_server_hello_detailed(data)
    return d["cipher"] if d else None


def _ja4_hash(parts):
    return hashlib.sha256(",".join(parts).encode()).hexdigest()[:12]


def compute_ja4_client(protocol='t', tls_version='13', sni_present=True,
                        ciphers=None, extensions=None, alpn=_JA4_ALPN, sigalgs=None):
    ciphers = ciphers or _JA4_CIPHERS
    extensions = extensions or _JA4_EXTENSIONS
    sigalgs = sigalgs or _JA4_SIGALGS
    sni_flag = 'd' if sni_present else 'i'
    a = (alpn[:2] if alpn else "00")
    head = f"{protocol}{tls_version}{sni_flag}{min(len(ciphers), 99):02d}{min(len(extensions), 99):02d}{a}"
    cipher_hash = _ja4_hash(sorted(ciphers))
    ext_no_sni_alpn = sorted([e for e in extensions if e not in ("0000", "0010")])
    ext_hash = _ja4_hash(ext_no_sni_alpn + sigalgs)
    return f"{head}_{cipher_hash}_{ext_hash}"


def compute_ja4s_server(sh):
    """Approximate JA4S from a parsed ServerHello dict."""
    if not sh:
        return None
    version_map = {"0304": "13", "0303": "12", "0302": "11", "0301": "10"}
    ver = version_map.get(sh["version"], "??")
    exts = sh["extensions"]
    head = f"t{ver}{min(len(exts), 99):02d}"
    cipher_hash = _ja4_hash([sh["cipher"]])
    ext_hash = _ja4_hash(sorted(exts))
    return f"{head}_{cipher_hash}_{ext_hash}"


def classify_ja4s(sh):
    """Heuristic (not a reference DB) classification of the negotiated TLS stack."""
    if not sh:
        return "нет ServerHello (молчит/дропает)"
    exts = set(sh["extensions"])
    cipher = sh["cipher"]
    minimal = exts.issubset({"002b", "0033", "ff01"}) or len(exts) <= 2
    if minimal and cipher == "1301":
        return "минимальный набор extensions + TLS_AES_128_GCM_SHA256 -> похоже на Reality/Xray-стиль стек"
    if "0010" in exts and "0033" in exts and len(exts) <= 4:
        return "похоже на Go crypto/tls дефолт (возможно V2Ray/Trojan-Go/Caddy)"
    if len(exts) >= 5:
        return "богатый набор extensions -> похоже на OpenSSL (nginx/Apache) дефолтный стек"
    return "нестандартный/неопознанный TLS-стек (см. JA4S для ручного сопоставления)"


# ===================================================================
# MODULE 2: ECH / DNS HTTPS-RR (unchanged)
# ===================================================================
async def cmd_ech(domain):
    log.p(f"\n[*] ECH Probe for {domain} (DoH Google -> Cloudflare)", CYAN)
    try:
        resp = await raw_tcp_exchange("8.8.8.8", 443, f"GET /resolve?name={domain}&type=65 HTTP/1.1\r\nHost: dns.google\r\nConnection: close\r\n\r\n".encode())
        if b'"Answer"' not in resp:
            resp = await raw_tcp_exchange("1.1.1.1", 443, f"GET /dns-query?name={domain}&type=65 HTTP/1.1\r\nHost: cloudflare-dns.com\r\nAccept: application/dns-json\r\nConnection: close\r\n\r\n".encode())

        data = json.loads(resp.split(b"\r\n\r\n")[1])
        answers = data.get("Answer", [])
        if not answers:
            log.p(f"[-] Domain {domain} does NOT advertise HTTPS RR (Type 65). No ECH.", YELLOW)
            return

        log.p("[+] HTTPS RR found!", GREEN)
        for a in answers:
            rdata = a.get("data", "")
            if "ech=" in rdata or "echconfig" in rdata:
                log.p(f"  [!] ECH (Encrypted-ClientHello) parameter PRESENT! (Raw: {rdata[:40]}...)", GREEN)
            else:
                log.p("  [-] ECH parameter MISSING.", YELLOW)
    except Exception as e:
        log.p(f"[-] Parse error: {e}", RED)


# ===================================================================
# MODULE 3: DPI SNI-RST PROBE (unchanged)
# ===================================================================
async def cmd_dpi(host, port=443):
    log.p(f"\n[*] Active SNI-RST Path Probe -> {host}:{port}", CYAN)
    try:
        ip = socket.gethostbyname(host)
    except Exception:
        log.p("[-] DNS resolve failed.", RED)
        return

    async def send_ch(sni_name, split=False):
        try:
            r, w = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=3)
            ch_bytes = build_chrome_131_clienthello(sni_name)
            if split:
                w.write(ch_bytes[:25]); await w.drain(); await asyncio.sleep(0.2)
                w.write(ch_bytes[25:])
            else:
                w.write(ch_bytes)
            await w.drain()
            data = await asyncio.wait_for(r.read(1024), timeout=3)
            w.close()
            return True if data else False
        except ConnectionResetError:
            return "RST"
        except Exception:
            return "DROP"

    res_benign = await send_ch("google.com")
    res_target = await send_ch(host)

    if res_benign is True and res_target == "RST":
        log.p(f"\n[!] ACTIVE DPI SNI-RST INJECTION DETECTED!", RED)
        res_frag = await send_ch(host, split=True)
        if res_frag is True:
            log.p("[+] Bypass SUCCESS! Splitting CH defeated DPI.", GREEN)
        else:
            log.p(f"[-] Bypass FAILED. Fragmented SNI result: {res_frag}", RED)
    else:
        log.p(f"[-] No SNI-based RST injection detected. Target={res_target}, Benign={res_benign}", GREEN)


# ===================================================================
# MODULE 4: AUDIT-CONFIG (unchanged)
# ===================================================================
async def cmd_audit_config(path):
    log.p(f"\n[*] Offline Config Audit: {path}", CYAN)
    try:
        with open(path, "r") as f:
            content = f.read()
    except Exception as e:
        log.p(f"[-] Cannot read file: {e}", RED)
        return

    if "privatekey" in content.lower() and "address" in content.lower():
        log.p("[+] Identified as WireGuard/AmneziaWG Config.", GREEN)
        if "Jc = " not in content and "S1 = " not in content:
            log.p("[!] WARNING: Vanilla WireGuard detected. Highly vulnerable to TSPU DPI signature blocking.", RED)
        else:
            log.p("[+] AmneziaWG obfuscation parameters found. (Resilient against standard DPI)", GREEN)
    elif "outbounds" in content or "inbounds" in content:
        log.p("[+] Identified as Xray / sing-box Config.", GREEN)
        if "reality" in content:
            log.p("[+] REALITY detected. Ensure your 'serverNames' are not hosted on same ASN.", GREEN)
        if "xtls" in content:
            log.p("[!] NOTE: XTLS triggers anti-replay probes. Ensure fallback handles junk bytes correctly.", YELLOW)
        if "ws" in content.lower() or "websocket" in content.lower():
            log.p("[!] WARNING: WebSocket masking is often fingerprinted by TSPU via HTTP/1.1 Upgrade anomalies.", RED)
    else:
        log.p("[-] Unknown config format.", YELLOW)


# ===================================================================
# MODULE 5: SWEEP SUBNET (unchanged, now also prints JA4S classification)
# ===================================================================
async def cmd_sweep(cidr):
    log.p(f"\n[*] Subnet Sweep: {cidr} (Port 443 SNI checks)", CYAN)
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except Exception as e:
        log.p(f"[-] Invalid CIDR: {e}", RED)
        return

    async def check_ip(ip_str):
        try:
            r, w = await asyncio.wait_for(asyncio.open_connection(ip_str, 443), timeout=1.5)
            w.write(build_chrome_131_clienthello("google.com")); await w.drain()
            ans = await asyncio.wait_for(r.read(1024), timeout=1.5)
            w.close()
            if ans:
                sh = parse_server_hello_detailed(ans)
                ja4s = compute_ja4s_server(sh)
                log.p(f"  [+] {ip_str:<15} Open | JA4S: {ja4s} | {classify_ja4s(sh)}")
        except Exception:
            pass

    tasks = [check_ip(str(ip)) for ip in net.hosts()][:256]
    await asyncio.gather(*tasks)
    log.p("[*] Sweep complete.", GREEN)


# ===================================================================
# MODULE 9: PMTUD FINGERPRINT — detect VPN encapsulation overhead via
#           ICMP Echo with DF set, binary-searching the path MTU.
# ===================================================================
# Typical encapsulation overheads people actually ship:
#   1500  - no tunnel / native path
#   1480  - PPPoE
#   1420  - WireGuard/AmneziaWG default
#   1400  - common OpenVPN/L2TP-over-UDP default
#   1350  - Hysteria2/QUIC-over-UDP typical
#   1280  - IPv6 minimum / some aggressive tunnel configs
_PMTUD_KNOWN = [
    (1500, "нет туннеля / нативный путь"),
    (1480, "PPPoE overhead"),
    (1420, "WireGuard/AmneziaWG default MTU"),
    (1400, "типичный OpenVPN/L2TP-over-UDP default"),
    (1350, "типично для Hysteria2/QUIC-туннелей"),
    (1280, "IPv6-минимум / агрессивно урезанный туннель"),
]


def pmtud_probe(ip, hi=1500, lo=576):
    """Двоичный поиск MTU: ICMP Echo с DF=1, размер пакета уменьшается пока
    не перестанем получать 'Fragmentation Needed' (type 3 code 4) / таймауты."""
    log.p("\n[PMTUD] Path MTU discovery (ICMP DF-bit binary search)", CYAN)

    def probe_size(size):
        # ICMP header is 8 bytes, IP header (no options) is 20 bytes.
        payload_len = size - 28
        if payload_len < 0:
            return False
        pkt = IP(dst=ip, flags="DF") / ICMP(id=os.getpid() & 0xFFFF) / (b"P" * payload_len)
        reply = sr1(pkt, timeout=1.2, verbose=0)
        if reply is None:
            return False  # trattato как "не проходит" (осторожно, могло быть просто filtered)
        if reply.haslayer(ICMP) and reply[ICMP].type == 3 and reply[ICMP].code == 4:
            return False  # Fragmentation Needed
        return reply.haslayer(ICMP) and reply[ICMP].type == 0  # Echo Reply

    best = None
    a, b = lo, hi
    # квази-двоичный поиск с ограничением на число проб
    for _ in range(9):
        mid = (a + b) // 2
        ok = probe_size(mid)
        if ok:
            best = mid
            a = mid + 1
        else:
            b = mid - 1
        if a > b:
            break

    if best is None:
        log.p("  [-] PMTUD: нет ответов даже на минимальный размер — ICMP, вероятно, фильтруется.", YELLOW)
        return None

    note = "нестандартный MTU (возможна инкапсуляция)"
    for mtu_val, desc in _PMTUD_KNOWN:
        if abs(best - mtu_val) <= 4:
            note = desc
            break

    flag = best < 1500 - 4
    log.p(f"  Path MTU ~= {best}  -> {note}", RED if flag else GREEN)
    return {"mtu": best, "note": note, "encapsulated": flag}


# ===================================================================
# MODULE 10: BGP prefix / routing anomaly analysis (RIPEstat, HTTPS-only)
# ===================================================================
async def bgp_anomaly_check(ip, geoip_country=None, geoip_asn_str=None):
    log.p("\n[BGP] Prefix / routing anomaly check (stat.ripe.net)", CYAN)
    result = {"origin_asn": None, "prefix": None, "holder": None, "anomalies": []}
    try:
        resp = await https_get("stat.ripe.net", f"/data/network-info/data.json?resource={ip}", timeout=4.0)
        body = resp.split(b"\r\n\r\n", 1)[1]
        data = json.loads(body.decode("utf-8", "ignore"))
        net = data.get("data", {})
        asns = net.get("asns", [])
        prefix = net.get("prefix")
        result["origin_asn"] = asns[0] if asns else None
        result["prefix"] = prefix
        if len(asns) > 1:
            result["anomalies"].append(f"MOAS: префикс {prefix} анонсируется {len(asns)} разными AS ({asns}) — возможен hijack/leak.")
    except Exception:
        log.p("  [-] RIPEstat network-info недоступен.", YELLOW)
        return result

    try:
        resp2 = await https_get("stat.ripe.net", f"/data/as-overview/data.json?resource=AS{result['origin_asn']}", timeout=4.0)
        body2 = resp2.split(b"\r\n\r\n", 1)[1]
        data2 = json.loads(body2.decode("utf-8", "ignore"))
        holder = data2.get("data", {}).get("holder")
        result["holder"] = holder
        if geoip_asn_str and holder and geoip_asn_str.split()[0].lstrip("AS").isdigit() is False:
            # мягкая эвристика: холдер BGP не встречается ни в одной строке из GeoIP AS/org
            if holder.split(",")[0].split()[0].lower() not in geoip_asn_str.lower():
                result["anomalies"].append(
                    f"BGP holder AS{result['origin_asn']} '{holder}' не совпадает с ASN/org из GeoIP ('{geoip_asn_str}') — возможен reroute/hijack между слоями данных.")
    except Exception:
        pass

    try:
        resp3 = await https_get("stat.ripe.net", f"/data/rpki-validation/data.json?resource=AS{result['origin_asn']}&prefix={result['prefix']}", timeout=4.0)
        body3 = resp3.split(b"\r\n\r\n", 1)[1]
        data3 = json.loads(body3.decode("utf-8", "ignore"))
        status = data3.get("data", {}).get("status")
        if status and status != "valid":
            result["anomalies"].append(f"RPKI статус префикса: {status} (не valid).")
    except Exception:
        pass

    if result["anomalies"]:
        for a in result["anomalies"]:
            log.p(f"  [!] {a}", RED)
    else:
        log.p(f"  Origin AS{result['origin_asn']} ({result.get('holder') or '?'}), prefix {result['prefix']} — аномалий не найдено.", GREEN)
    return result


# ===================================================================
# MODULE 11: reverse-DNS (PTR) vs TLS-сертификат домена
# ===================================================================
async def ptr_cert_check(ip, target_host, open_ports):
    log.p("\n[PTR] Reverse-DNS vs TLS-сертификат", CYAN)
    ptr_name = None
    try:
        ptr_name = socket.gethostbyaddr(ip)[0]
    except Exception:
        pass

    tls_names = set()
    tls_port = 443 if 443 in open_ports else (8443 if 8443 in open_ports else None)
    if tls_port:
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
            raw_sock = socket.create_connection((ip, tls_port), timeout=3.0)
            with ctx.wrap_socket(raw_sock, server_hostname=target_host) as ssock:
                cert = ssock.getpeercert(binary_form=False) or {}
                for typ, val in cert.get("subjectAltName", []):
                    if typ == "DNS":
                        tls_names.add(val.lower())
                for rdn in cert.get("subject", ()):
                    for k, v in rdn:
                        if k == "commonName":
                            tls_names.add(v.lower())
        except Exception:
            pass

    if not ptr_name:
        log.p("  [-] PTR-запись отсутствует.", YELLOW)
    else:
        log.p(f"  PTR: {ptr_name}")

    mismatch = False
    if ptr_name and tls_names:
        ptr_l = ptr_name.lower().rstrip(".")
        match = any(ptr_l == n or ptr_l.endswith("." + n) or n.endswith("." + ptr_l) for n in tls_names)
        if not match:
            mismatch = True
            log.p(f"  [!] PTR ({ptr_name}) не совпадает ни с одним именем из сертификата ({', '.join(tls_names)}) "
                  f"— типично для VPS/хостинга с generic PTR под чужой сертификат.", RED)
        else:
            log.p("  PTR совпадает с доменом сертификата.", GREEN)
    elif ptr_name and not tls_names:
        log.p("  Сертификат не получен — сверка невозможна.", YELLOW)

    return {"ptr": ptr_name, "cert_names": sorted(tls_names), "mismatch": mismatch}


# ===================================================================
# MODULE 12: FakeDNS leak (V2Ray-style DNS hijack в приватный IP)
# ===================================================================
_FAKEDNS_PRIVATE_RANGES = [
    ipaddress.ip_network("198.18.0.0/15"),   # общий диапазон V2Ray/Xray FakeDNS pool
    ipaddress.ip_network("240.0.0.0/4"),     # Clash/some cores' fake-ip pool
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("100.64.0.0/10"),   # CGNAT, тоже встречается как fake-ip pool
]


def _dns_a_query(ip, qname, port=53, timeout=1.5):
    txid = random.randint(0, 0xFFFF)
    header = struct.pack(">HHHHHH", txid, 0x0100, 1, 0, 0, 0)
    qparts = b"".join(struct.pack("B", len(p)) + p.encode() for p in qname.split("."))
    question = qparts + b"\x00" + struct.pack(">HH", 1, 1)  # QTYPE=A, QCLASS=IN
    pkt = header + question
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.sendto(pkt, (ip, port))
        data, _ = s.recvfrom(512)
    except Exception:
        return []
    finally:
        s.close()
    try:
        ancount = struct.unpack(">H", data[6:8])[0]
        pos = 12
        # skip question section
        while data[pos] != 0:
            pos += data[pos] + 1
        pos += 5  # null byte + QTYPE + QCLASS
        ips = []
        for _ in range(ancount):
            # name (usually a pointer, 2 bytes)
            if data[pos] & 0xC0 == 0xC0:
                pos += 2
            else:
                while data[pos] != 0:
                    pos += data[pos] + 1
                pos += 1
            rtype, rclass, ttl, rdlen = struct.unpack(">HHIH", data[pos:pos + 10])
            pos += 10
            if rtype == 1 and rdlen == 4:
                ips.append(socket.inet_ntoa(data[pos:pos + 4]))
            pos += rdlen
        return ips
    except Exception:
        return []


def fakedns_leak_check(ip, open_ports):
    log.p("\n[FakeDNS] Проверка утечки FakeDNS (V2Ray-style hijack)", CYAN)
    if 53 not in open_ports:
        log.p("  [-] Порт 53/udp не открыт (или не просканирован) — пропуск.", YELLOW)
        return {"tested": False, "leak": False}

    probe_name = f"{secrets.token_hex(6)}.bbv-probe.invalid"
    answers = _dns_a_query(ip, probe_name)
    leaked_ranges = []
    for a in answers:
        addr = ipaddress.ip_address(a)
        for net in _FAKEDNS_PRIVATE_RANGES:
            if addr in net:
                leaked_ranges.append((a, str(net)))
                break

    if leaked_ranges:
        log.p(f"  [!] DNS-резолвер отвечает на несуществующее .invalid-имя приватным/fake-ip адресом: "
              f"{', '.join(f'{a} (∈{n})' for a, n in leaked_ranges)} — похоже на FakeDNS/DNS-хайджек.", RED)
        return {"tested": True, "leak": True, "answers": answers}
    if answers:
        log.p(f"  Ответ получен, но не в приватных/fake-ip диапазонах: {answers}", GREEN)
    else:
        log.p("  Нет ответа на заведомо несуществующее имя — DNS-хайджека не выявлено.", GREEN)
    return {"tested": True, "leak": False, "answers": answers}


# ===================================================================
# MODULE 13: domain fronting check (нейтральный SNI + чужой Host)
# ===================================================================
_FRONTING_NEUTRAL_SNI = ["www.cloudflare.com", "d1.awsstatic.com", "www.bing.com"]


async def domain_fronting_check(ip, port, target_host):
    log.p("\n[Fronting] Domain fronting (нейтральный SNI + Host != SNI)", CYAN)
    neutral_sni = random.choice(_FRONTING_NEUTRAL_SNI)
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
        raw = socket.create_connection((ip, port), timeout=3.0)
        with ctx.wrap_socket(raw, server_hostname=neutral_sni) as ssock:
            req = f"GET / HTTP/1.1\r\nHost: {target_host}\r\nConnection: close\r\n\r\n".encode()
            ssock.sendall(req)
            ssock.settimeout(3.0)
            chunks = []
            try:
                while True:
                    c = ssock.recv(4096)
                    if not c:
                        break
                    chunks.append(c)
            except Exception:
                pass
            resp = b"".join(chunks)
    except Exception:
        log.p(f"  [-] TLS-сессия с SNI={neutral_sni} не установилась — фронтинг через этот узел не проходит.", GREEN)
        return {"fronting_possible": False}

    status_line = resp.split(b"\r\n", 1)[0] if resp else b""
    accepted = resp and (b" 200 " in status_line or b" 30" in status_line)
    if accepted:
        log.p(f"  [!] SNI={neutral_sni}, Host={target_host}: сервер ответил {status_line.decode('utf-8','ignore')} "
              f"— запрос был обработан несмотря на несовпадение SNI/Host. Domain fronting через этот узел возможен.", RED)
    else:
        log.p(f"  SNI={neutral_sni} != Host={target_host} -> {status_line.decode('utf-8','ignore') or 'нет ответа'} "
              f"(фронтинг не подтверждён).", GREEN)
    return {"fronting_possible": bool(accepted), "sni": neutral_sni, "status": status_line.decode("utf-8", "ignore")}


# ===================================================================
# MODULE 14: Slowloris-style timing-проба (ОДНО соединение, не DoS!)
#            Шлём заголовки HTTP по одному с задержкой, смотрим когда
#            сервер потеряет терпение — сигнал агрессивности таймаута/WAF.
# ===================================================================
async def slowloris_timing_probe(ip, port, target_host, drip_delay=2.0, max_headers=6):
    log.p("\n[Slowloris] Timing-проба таймаута сервера (одно соединение, без флуда)", CYAN)
    t0 = time.time()
    sent_headers = 0
    closed_at = None
    try:
        r, w = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=3.0)
        w.write(f"GET /?probe={secrets.token_hex(4)} HTTP/1.1\r\n".encode())
        w.write(f"Host: {target_host}\r\n".encode())
        await w.drain()
        for i in range(max_headers):
            await asyncio.sleep(drip_delay)
            try:
                w.write(f"X-Bbv-Drip-{i}: {secrets.token_hex(2)}\r\n".encode())
                await w.drain()
                sent_headers += 1
            except Exception:
                closed_at = time.time() - t0
                break
            # неблокирующая проверка, не закрыл ли сервер сокет уже
            try:
                data = await asyncio.wait_for(r.read(1), timeout=0.05)
                if data == b"":
                    closed_at = time.time() - t0
                    break
            except asyncio.TimeoutError:
                pass
        try:
            w.close()
        except Exception:
            pass
    except Exception:
        pass

    if closed_at is not None:
        aggressiveness = "агрессивный" if closed_at < 5 else ("умеренный" if closed_at < 15 else "мягкий/отсутствует")
        log.p(f"  Сервер оборвал недозаполненный запрос через {closed_at:.1f}s "
              f"после {sent_headers} drip-заголовков -> таймаут {aggressiveness} (возможен anti-slowloris/WAF).",
              GREEN if closed_at < 10 else YELLOW)
        return {"tested": True, "closed_after_s": round(closed_at, 1), "headers_sent": sent_headers}
    else:
        log.p(f"  Сервер держал соединение открытым весь тест ({sent_headers} drip-заголовков, "
              f"{drip_delay * max_headers:.0f}s) -> таймаут не агрессивный / anti-slowloris не заметен.", YELLOW)
        return {"tested": True, "closed_after_s": None, "headers_sent": sent_headers}


# ===================================================================
# MODULE 15: TLS ClientHello replay simulation (nonce-tracking для
#            Shadowsocks-AEAD / XTLS) — ОДИН повтор идентичных байт,
#            не флуд. Цель: есть ли anti-replay на уровне сервера.
# ===================================================================
async def replay_probe(ip, port, target_host):
    log.p("\n[Replay] TLS ClientHello replay-симуляция (anti-replay check)", CYAN)
    ch = build_chrome_131_clienthello(target_host)

    async def one_shot(payload):
        return await raw_tcp_exchange(ip, port, payload, timeout=2.5)

    first = await one_shot(ch)
    await asyncio.sleep(0.3)
    second = await one_shot(ch)  # тот же самый ClientHello целиком (та же nonce/random)

    sh1 = parse_server_hello_detailed(first)
    sh2 = parse_server_hello_detailed(second)

    both_accepted = bool(sh1) and bool(sh2)
    identical_cipher = bool(sh1) and bool(sh2) and sh1["cipher"] == sh2["cipher"]

    if both_accepted and identical_cipher:
        log.p("  [!] Идентичный ClientHello (тот же ClientRandom) принят дважды подряд с валидным ServerHello "
              "-> анти-replay защита на TLS-уровне не наблюдается (актуально для AEAD/XTLS nonce-reuse рисков).", RED)
        verdict = "no_replay_protection_observed"
    elif bool(sh1) and not bool(sh2):
        log.p("  Первый ClientHello принят, повтор — отклонён/дропнут -> anti-replay похоже присутствует.", GREEN)
        verdict = "replay_rejected"
    elif not sh1:
        log.p("  Порт не отвечает валидным ServerHello на первый ClientHello — проверка неприменима.", YELLOW)
        verdict = "n/a"
    else:
        verdict = "inconclusive"
        log.p("  Результат неоднозначен (частичные ответы) — нужно ручное подтверждение.", YELLOW)

    return {"first_accepted": bool(sh1), "second_accepted": bool(sh2), "verdict": verdict}


# ===================================================================
# MODULE 16: TTL middlebox detection — сравнение TTL ответа с открытого
#            и с заведомо закрытого порта. Разница = что-то на пути
#            подменяет/проксирует один из путей (типичный признак ТСПУ/MITM).
# ===================================================================
def ttl_middlebox_check(ip, open_ports):
    log.p("\n[TTL] Сравнение TTL: открытый порт vs закрытый порт", CYAN)
    if not open_ports:
        log.p("  [-] Нет открытых портов для сравнения.", YELLOW)
        return {"tested": False}

    open_port = open_ports[0]
    closed_port = None
    open_set = set(open_ports)
    for p in range(1, 65535):
        if p not in open_set:
            closed_port = p
            break

    def get_ttl(port):
        pkt = IP(dst=ip) / TCP(dport=port, flags="S")
        reply = sr1(pkt, timeout=1.2, verbose=0)
        if reply is None or not reply.haslayer(IP):
            return None
        ttl = reply[IP].ttl
        if reply.haslayer(TCP) and reply[TCP].flags == 0x12:  # SYN-ACK
            sr1(IP(dst=ip) / TCP(dport=port, flags="R"), timeout=0.3, verbose=0)
        return ttl

    ttl_open = get_ttl(open_port)
    ttl_closed = get_ttl(closed_port) if closed_port else None

    if ttl_open is None or ttl_closed is None:
        log.p(f"  [-] Не удалось получить TTL для сравнения (open={ttl_open}, closed={ttl_closed}).", YELLOW)
        return {"tested": False, "ttl_open": ttl_open, "ttl_closed": ttl_closed}

    diff = abs(ttl_open - ttl_closed)
    flagged = diff >= 2  # 1 хоп разницы — шум; 2+ обычно значимо
    log.p(f"  TTL открытого порта {open_port}: {ttl_open}   TTL закрытого порта {closed_port}: {ttl_closed}"
          f"   diff={diff}", RED if flagged else GREEN)
    if flagged:
        log.p("  [!] Разные TTL для открытого/закрытого пути -> подозрение на middlebox "
              "(инжектится RST/ответ с другого хопа, а не с самого хоста).", RED)
    return {"tested": True, "ttl_open": ttl_open, "ttl_closed": ttl_closed, "diff": diff, "flagged": flagged}


# ===================================================================
# CORE PIPELINE
# ===================================================================

# ---------- Phase 1: DNS (A + AAAA, IPv4 priority) ----------
async def resolve_dns(host):
    log.p(f"\n[1/8] DNS resolve", CYAN)
    t0 = time.time()
    ipv4, ipv6 = None, None
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        infos = []

    for info in infos:
        family = info[0]
        addr = info[4][0]
        if family == socket.AF_INET and not ipv4:
            ipv4 = addr
        elif family == socket.AF_INET6 and not ipv6:
            ipv6 = addr

    dt = (time.time() - t0) * 1000
    if ipv4:
        log.p(f"  {host}  ->  {ipv4}  [A, {dt:.0f}ms]", GREEN)
    if ipv6:
        log.p(f"  {host}  ->  {ipv6}  [AAAA, {dt:.0f}ms]", GREEN)
    if not ipv4 and not ipv6:
        log.p("[-] DNS resolve failed (no A/AAAA).", RED)
    return ipv4, ipv6


# ---------- Phase 2: GeoIP, 5 HTTPS-only providers, parallel ----------
GEOIP_PROVIDERS = [
    ("ipapi.is", "/json/{ip}"),
    ("iplocate.io", "/api/lookup/{ip}"),
    ("ipwho.is", "/{ip}"),
    ("ipinfo.io", "/{ip}/json"),
    ("freeipapi.com", "/api/json/{ip}"),
]


async def _geoip_one(host, path_tpl, ip):
    path = path_tpl.format(ip=ip)
    resp = await https_get(host, path, timeout=3.0)
    if not resp:
        return None
    try:
        body = resp.split(b"\r\n\r\n", 1)[1]
        res = body.decode("utf-8", errors="ignore")
        c = re.search(r'"(?:countryCode|country_code|country)"\s*:\s*"([A-Za-z]{2})"', res)
        a = re.search(r'"(?:as|asn|org|company|isp)"\s*:\s*"?([^",}]+)"?', res)
        a_str = (a.group(1) if a else "Unknown").strip()
        hosting_kws = ['host', 'cloud', 'telecom', 'datacenter', 'vps', 'llc', 'hetzner', 'ovh', 'digital', 'aws']
        is_hosting = any(kw in a_str.lower() for kw in hosting_kws)
        country = c.group(1).upper() if c else "?"
        return {"provider": host, "country": country, "asn": a_str, "hosting": is_hosting}
    except Exception:
        return None


async def geoip_aggregation(ip):
    log.p(f"\n[2/8] GeoIP aggregation (5 HTTPS-only providers, parallel)", CYAN)
    tasks = [_geoip_one(host, tpl, ip) for host, tpl in GEOIP_PROVIDERS]
    results = await asyncio.gather(*tasks, return_exceptions=False)
    results = [r for r in results if r]
    is_hosting = False
    country = "?"
    asn_str = ""
    for r in results:
        is_hosting = is_hosting or r["hosting"]
        if r["country"] != "?":
            country = r["country"]
        if r["asn"] and r["asn"] != "Unknown":
            asn_str = r["asn"]
        log.p(f"  {r['provider']:<14} {ip}  {r['country']}  AS {r['asn']} {'(HOSTING)' if r['hosting'] else ''}",
              YELLOW if r["hosting"] else GREEN)
    if not results:
        log.p("  [-] All GeoIP providers unreachable/blocked.", YELLOW)
    return is_hosting, country, asn_str


# ---------- Phase 3a/3b: TCP port scan + stack fingerprint ----------
def _get_tcp_info_mss(sock):
    try:
        fmt = "B" * 7 + "x" + "I" * 4
        size = struct.calcsize(fmt)
        raw = sock.getsockopt(socket.IPPROTO_TCP, getattr(socket, "TCP_INFO", 11), size)
        vals = struct.unpack(fmt, raw[:size])
        return {"snd_mss": vals[9], "rcv_mss": vals[10]}
    except Exception:
        return None


async def test_closed_port_behavior(ip, open_ports):
    open_set = set(open_ports)
    candidate = None
    for p in range(1, 65535):
        if p not in open_set:
            candidate = p
            break
    if candidate is None:
        return "n/a"
    try:
        r, w = await asyncio.wait_for(asyncio.open_connection(ip, candidate), timeout=1.5)
        w.close()
        return f"port {candidate} unexpectedly OPEN"
    except ConnectionRefusedError:
        return f"port {candidate}: RST (normal closed-port behavior)"
    except asyncio.TimeoutError:
        return f"port {candidate}: silently dropped (filtered, no RST)"
    except Exception as e:
        return f"port {candidate}: {e}"


async def tcp_scan(ip, ports, args):
    mode = "FULL 1-65535" if not args.fast else f"curated ({len(ports)} ports)"
    log.p(f"\n[3a/8] TCP Stealth SYN-scan  mode={mode} (Ctrl+C to skip phase)", CYAN)
    open_ports = []
    try:
        ans, _ = sr(IP(dst=ip) / TCP(dport=ports, flags="S"), timeout=1.0, verbose=0)
        for s, r in ans:
            if r.haslayer(TCP) and r[TCP].flags == 0x12:
                open_ports.append(s[TCP].dport)
                sr1(IP(dst=ip) / TCP(dport=s[TCP].dport, flags="R"), timeout=0.1, verbose=0)
    except KeyboardInterrupt:
        log.p("\n[!] Q-SKIP: TCP scan aborted by user. Proceeding with found ports...", MAGENTA)

    if len(ports) > 1000 and len(open_ports) == 0:
        return [], 0, 0, "drop", True, None, "n/a"  # BGP Blackhole

    log.p(f"  Open ports: {open_ports}", GREEN)
    med, std = 0.0, 0.0
    mss_info = None

    if open_ports:
        test_port = open_ports[0]
        log.p(f"[3b/8] TCP Stack Fingerprint (6 connects to port {test_port}, TCP_INFO MSS/window)", CYAN)
        rtts = []
        for _ in range(6):
            t0 = time.time()
            try:
                r, w = await asyncio.wait_for(asyncio.open_connection(ip, test_port), timeout=1.0)
                sock = w.get_extra_info('socket')
                if sock is not None and mss_info is None:
                    mss_info = _get_tcp_info_mss(sock)
                rtts.append((time.time() - t0) * 1000)
                w.close()
            except Exception:
                pass
            await stealth_sleep(args)
        if len(rtts) > 1:
            med, std = statistics.median(rtts), statistics.stdev(rtts)
            log.p(f"  Handshake median={med:.1f}ms stddev={std:.1f}ms")
        if mss_info:
            log.p(f"  Peer TCP_INFO: snd_mss={mss_info['snd_mss']} rcv_mss={mss_info['rcv_mss']}")
        else:
            log.p(f"  TCP_INFO MSS/window: unavailable on this path/kernel", YELLOW)

    closed_beh = await test_closed_port_behavior(ip, open_ports)
    log.p(f"  Closed-port behavior: {closed_beh}")

    return open_ports, med, std, closed_beh, False, mss_info, closed_beh


# ---------- Phase 4: UDP probes (WG / AmneziaWG dual-probe & S1-sweep / Hysteria2) ----------
def run_udp_probes(ip):
    log.p("\n[4/8] UDP probes (WireGuard / AmneziaWG dual-probe & S1-sweep / Hysteria2)", CYAN)
    detected = []
    wg_init = b"\x01\x00\x00\x00" + secrets.token_bytes(144)

    def try_send(sock, payload, dst_port, label):
        try:
            sock.sendto(payload, (ip, dst_port))
            data, _ = sock.recvfrom(1024)
            return True
        except Exception:
            return False

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(0.8)

    # 1. Vanilla WireGuard on 51820
    if try_send(sock, wg_init, 51820, "WireGuard"):
        detected.append("WireGuard")
        log.p(f"  UDP:51820 WireGuard {RED}HANDSHAKE ACCEPTED{RESET}")
    vanilla_accepted = "WireGuard" in detected

    # 2. AmneziaWG Sx=8 dual-probe on 51820 (junk-prefixed) — meaningful if vanilla was rejected
    junk8 = secrets.token_bytes(8)
    if try_send(sock, junk8 + wg_init, 51820, "AmneziaWG Sx=8 :51820"):
        detected.append("AmneziaWG (Sx=8 @51820)")
        tag = "confirms obfuscation" if not vanilla_accepted else "note: vanilla WG also worked"
        log.p(f"  UDP:51820 AmneziaWG Sx=8 dual-probe {RED}ACCEPTED{RESET} ({tag})")

    # 3. AmneziaWG Sx=8 on dedicated port 55555
    if try_send(sock, junk8 + wg_init, 55555, "AmneziaWG Sx=8 :55555"):
        detected.append("AmneziaWG (Sx=8 @55555)")
        log.p(f"  UDP:55555 AmneziaWG Sx=8 {RED}HANDSHAKE ACCEPTED{RESET}")

    # 4. AmneziaWG S1 sweep — 12 junk-prefix sizes on 51820
    log.p("  Sweeping AmneziaWG obfuscation (S1, 12 sizes)...")
    s1_sizes = [1, 2, 4, 8, 12, 16, 24, 32, 48, 64, 96, 128]
    for s1_size in s1_sizes:
        if try_send(sock, secrets.token_bytes(s1_size) + wg_init, 51820, f"S1={s1_size}"):
            log.p(f"  UDP:51820 AmneziaWG S1={s1_size} {RED}HANDSHAKE ACCEPTED!{RESET}")
            detected.append(f"AmneziaWG (S1={s1_size})")
            break

    # 5. Hysteria2 QUIC v1 Initial on 36712 and 443
    quic_payload = b'\xc3\x00\x00\x00\x01\x08' + secrets.token_bytes(16) + secrets.token_bytes(1182)
    if try_send(sock, quic_payload, 36712, "Hysteria2 :36712"):
        detected.append("Hysteria2 QUIC (:36712)")
        log.p(f"  UDP:36712 Hysteria2 {RED}HANDSHAKE ACCEPTED{RESET}")
    if try_send(sock, quic_payload, 443, "Hysteria2 :443"):
        detected.append("Hysteria2 QUIC (:443)")
        log.p(f"  UDP:443   Hysteria2 {RED}HANDSHAKE ACCEPTED{RESET}")

    # 6. OpenVPN P_CONTROL_HARD_RESET_CLIENT_V2 (opcode 0x38, key-id 0) on 1194
    #    layout: [opcode<<3|key_id](1) + session_id(8) + hmac/packet-id(0 for reset) + ...
    ovpn_reset = bytes([0x38]) + secrets.token_bytes(8) + b"\x00" + secrets.token_bytes(4)
    if try_send(sock, ovpn_reset, 1194, "OpenVPN HARD_RESET"):
        detected.append("OpenVPN (HARD_RESET_CLIENT_V2 @1194)")
        log.p(f"  UDP:1194  OpenVPN HARD_RESET_CLIENT_V2 {RED}ACK/HANDSHAKE ACCEPTED{RESET}")

    # 7. TUIC v5 — QUIC v1 Initial with ALPN "tuic" is what actually distinguishes it;
    #    at raw-UDP level we send a QUICv1-shaped long-header Initial on TUIC's default port.
    tuic_quic = b'\xc3\x00\x00\x00\x01\x08' + secrets.token_bytes(16) + secrets.token_bytes(1182)
    if try_send(sock, tuic_quic, 443, "TUIC v5 :443"):
        detected.append("TUIC v5 (QUIC Initial @443)")
        log.p(f"  UDP:443   TUIC v5-shaped QUIC Initial {RED}ACCEPTED{RESET}")
    if try_send(sock, tuic_quic, 8443, "TUIC v5 :8443"):
        detected.append("TUIC v5 (QUIC Initial @8443)")
        log.p(f"  UDP:8443  TUIC v5-shaped QUIC Initial {RED}ACCEPTED{RESET}")

    # 8. L2TP SCCRQ (Start-Control-Connection-Request) control message on 1701
    #    layout: flags/ver(2) + length(2) + tunnel_id(2) + session_id(2) + Ns(2) + Nr(2) + AVPs...
    l2tp_sccrq = b"\xc8\x02" + struct.pack(">H", 20) + b"\x00\x00\x00\x00\x00\x00\x00\x00" + \
                 b"\x80\x08\x00\x00\x00\x00\x00\x01" + b"\x00\x01"
    if try_send(sock, l2tp_sccrq, 1701, "L2TP SCCRQ"):
        detected.append("L2TP (SCCRQ @1701)")
        log.p(f"  UDP:1701  L2TP SCCRQ {RED}RESPONSE RECEIVED{RESET}")

    # 9. IKEv2 SA_INIT (IKE_SA_INIT, exchange type 34) on 500/4500
    ike_hdr = secrets.token_bytes(8) + b"\x00" * 8 + b"\x21\x20\x22\x08" + b"\x00" * 4 + struct.pack(">I", 28)
    if try_send(sock, ike_hdr, 500, "IKEv2 SA_INIT :500"):
        detected.append("IKEv2 (SA_INIT @500)")
        log.p(f"  UDP:500   IKEv2 SA_INIT {RED}RESPONSE RECEIVED{RESET}")
    if try_send(sock, b"\x00" * 4 + ike_hdr, 4500, "IKEv2 SA_INIT :4500 (NAT-T)"):
        detected.append("IKEv2 (SA_INIT @4500 NAT-T)")
        log.p(f"  UDP:4500  IKEv2 SA_INIT (NAT-T) {RED}RESPONSE RECEIVED{RESET}")

    sock.close()
    if not detected:
        log.p("  No UDP tunnel handshakes accepted.", GREEN)
    return detected


# ---------- Phase 5 / 5b: Service fingerprint + CT + uTLS dual-probe + JA4/JA4S ----------
async def _ssh_banner(ip, port):
    try:
        r, w = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=2)
        data = await asyncio.wait_for(r.read(128), timeout=2)
        w.close()
        if data.startswith(b"SSH-"):
            return data.split(b"\r\n")[0].decode("utf-8", "ignore")
    except Exception:
        pass
    return None


async def _socks5_probe(ip, port):
    ans = await raw_tcp_exchange(ip, port, b"\x05\x01\x00", timeout=1.5)
    return bool(ans[:2] == b"\x05\x00") if len(ans) >= 2 else False


async def _shadowsocks_probe(ip, port):
    """SS-AEAD framing has no plaintext handshake; a well-formed junk salt+tag is either
    silently dropped (SS) or answered (something else). We time the drop only."""
    t0 = time.time()
    ans = await raw_tcp_exchange(ip, port, secrets.token_bytes(50), timeout=1.0)
    dt = time.time() - t0
    return (not ans) and dt < 0.3


async def crt_sh_lookup(domain):
    resp = await https_get("crt.sh", f"/?q={domain}&output=json", timeout=5.0)
    if not resp:
        return None
    try:
        body = resp.split(b"\r\n\r\n", 1)[1]
        entries = json.loads(body.decode("utf-8", "ignore"))
        if not isinstance(entries, list):
            return None
        issuers = sorted(set(e.get("issuer_name", "?") for e in entries))[:3]
        return {"count": len(entries), "issuers": issuers}
    except Exception:
        return None


async def service_fuzzer(ip, open_ports, target_host, args):
    log.p("\n[5/8] Service fingerprint + CT", CYAN)
    has_http_proxy, utls_diff, rkn_redirect = False, False, False
    ja4s_stack_notes = []

    # crt.sh CT-log check once per scan (domain-based, not IP-based)
    if not re.match(r"^\d{1,3}(\.\d{1,3}){3}$", target_host):
        log.p(f"  crt.sh CT-log lookup for {target_host}...")
        ct = await crt_sh_lookup(target_host)
        if ct is None:
            log.p("  [-] crt.sh unreachable or no data.", YELLOW)
        elif ct["count"] == 0:
            log.p("  [!] No CT log entries at all -> likely self-signed / not a real public cert.", RED)
        else:
            log.p(f"  [+] {ct['count']} CT log entries. Issuers: {', '.join(ct['issuers'])}", GREEN)

    for p in open_ports:
        log.p(f"  -> Port :{p}")
        await stealth_sleep(args)

        banner = await _ssh_banner(ip, p)
        if banner:
            log.p(f"     SSH banner: {banner}", GREEN)

        if await _socks5_probe(ip, p):
            log.p(f"     {RED}SOCKS5 greeting accepted (open SOCKS5 proxy){RESET}")

        if await _shadowsocks_probe(ip, p):
            log.p(f"     Silent immediate drop on junk (SS-AEAD-consistent behavior)", YELLOW)

        ans = await raw_tcp_exchange(ip, p, b"CONNECT 8.8.8.8:443 HTTP/1.1\r\nHost: 8.8.8.8:443\r\n\r\n")
        if b"200 OK" in ans:
            log.p(f"     {RED}HTTP/1.1 200 OK [Open Proxy]{RESET}")
            has_http_proxy = True

        ans = await raw_tcp_exchange(ip, p, b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
        if b"302" in ans and (b"rkn.gov.ru" in ans or b"warning.rt.ru" in ans):
            log.p(f"     {RED}302 Redirect to RKN block page!{RESET}")
            rkn_redirect = True
        if ans and re.search(rb"^HTTP/1\.[01] \d{3}", ans):
            # proxy-headers check: does the server leak Via/X-Forwarded-For style headers?
            if b"Via:" in ans or b"X-Forwarded-For" in ans:
                log.p(f"     Proxy-indicating headers present in response (Via/X-Forwarded-For)", YELLOW)

        if p in (443, 8443):
            sh = None
            ssl_success, chrome_success = False, False
            try:
                ctx = ssl.create_default_context()
                ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
                r1, w1 = await asyncio.wait_for(asyncio.open_connection(ip, p, ssl=ctx), timeout=2)
                w1.close(); ssl_success = True
            except Exception:
                pass

            try:
                ch_raw = build_chrome_131_clienthello(target_host)
                srv_hello = await raw_tcp_exchange(ip, p, ch_raw)
                sh = parse_server_hello_detailed(srv_hello)
                if sh:
                    chrome_success = True
            except Exception:
                pass

            if ssl_success != chrome_success:
                utls_diff = True
                log.p(f"     uTLS dual-probe: {YELLOW}Discriminator active! OpenSSL={ssl_success}, Chrome131={chrome_success}{RESET}")

            if sh:
                ja4c = compute_ja4_client()
                ja4s = compute_ja4s_server(sh)
                stack_note = classify_ja4s(sh)
                ja4s_stack_notes.append(stack_note)
                log.p(f"     JA4  (client, sent): {ja4c}")
                log.p(f"     JA4S (server, seen): {ja4s}  -> {stack_note}")

    return has_http_proxy, utls_diff, rkn_redirect, ja4s_stack_notes


# ---------- Phase 6: J3 / TSPU active probing (exact 8-probe spec) ----------
async def j3_probes(ip, open_ports, target_host, args):
    log.p("\n[6/8] J3 / TSPU Active Probing (8 fixed probes per TLS port)", CYAN)

    probes_list = [
        ("Empty TCP", b""),
        ("HTTP GET /", f"GET / HTTP/1.1\r\nHost: {target_host}\r\nConnection: close\r\n\r\n".encode()),
        ("CONNECT ex.com:443", b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n"),
        ("SSH banner", b"SSH-2.0-OpenSSH_9.2p1\r\n"),
        ("Random 512B", secrets.token_bytes(512)),
        ("TLS CH .invalid SNI", None),  # built per-port below (random each time)
        ("HTTP absolute-URI", f"GET http://{target_host}/ HTTP/1.1\r\nHost: {target_host}\r\n\r\n".encode()),
        ("0xFF x128", b"\xff" * 128),
    ]

    canned, replay, ss_drop = False, False, False

    for port in open_ports:
        log.p(f" -> port :{port}")
        responses = []
        for name, payload in probes_list:
            if name == "TLS CH .invalid SNI":
                payload = build_random_invalid_sni_clienthello()

            t0 = time.time()
            if name == "Empty TCP" and payload == b"":
                # open the connection, send nothing, see if server closes/sends first
                try:
                    r, w = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=2.0)
                    try:
                        ans = await asyncio.wait_for(r.read(256), timeout=1.5)
                    except asyncio.TimeoutError:
                        ans = b""
                    w.close()
                except Exception:
                    ans = b""
            else:
                ans = await raw_tcp_exchange(ip, port, payload)
            await stealth_sleep(args)

            if ans:
                responses.append(ans)
                clean_str = ans[:20].decode('utf-8', 'ignore').replace('\r', '').replace('\n', ' ')
                ent = shannon_entropy(ans)
                log.p(f"    RESP {name:<20} {len(ans)}B H={ent:.2f} ({classify_entropy(ent)}) {clean_str}", GREEN)
            else:
                if "Random" in name and (time.time() - t0) < 0.2:
                    ss_drop = True
                    log.p(f"    SILENT {name:<20} {RED}Immediate Drop (SS-AEAD-consistent){RESET}")
                else:
                    log.p(f"    SILENT {name:<20} dropped")

        silent_count = len(probes_list) - len(responses)
        if silent_count >= 7:
            log.p(f"    !! Drops all/nearly-all junk except valid TLS -> Reality/XTLS-consistent pattern.", RED)

        if len(responses) >= 2:
            f_lines = [r.split(b'\r\n')[0] for r in responses if b'\r\n' in r]
            if len(f_lines) > 2 and f_lines.count(f_lines[0]) >= 2 and b"HTTP/1." in f_lines[0]:
                canned = True
                log.p("    !! Canned HTTP response detected for non-HTTP raw junk.", RED)

    return canned, replay, ss_drop


# ---------- Phase 7: SNITCH (RTT vs GeoIP) + traceroute (ping.exe-shaped) + SSTP ----------
# Coarse RTT buckets — heuristic only, not a real geolocation-latency model.
_SNITCH_RTT_BUCKETS = {
    "RU": (3, 70), "UA": (5, 80), "KZ": (10, 100), "BY": (5, 80),
    "DE": (15, 90), "NL": (15, 90), "FR": (15, 90), "GB": (15, 100), "FI": (10, 90),
    "US": (90, 230), "CA": (90, 230),
    "SG": (100, 260), "JP": (100, 260), "HK": (90, 250), "CN": (60, 220),
}
_SNITCH_DEFAULT_BUCKET = (5, 260)


def snitch_check(med_rtt_ms, country):
    if med_rtt_ms <= 0:
        return None
    lo, hi = _SNITCH_RTT_BUCKETS.get(country, _SNITCH_DEFAULT_BUCKET)
    if med_rtt_ms < lo * 0.4:
        return f"RTT {med_rtt_ms:.0f}ms аномально низкий для заявленной GeoIP-страны {country} (ожидалось {lo}-{hi}ms) — возможен ближний прокси/анонимайзер перед реальным сервером."
    if med_rtt_ms > hi * 2.2:
        return f"RTT {med_rtt_ms:.0f}ms аномально высокий для заявленной GeoIP-страны {country} (ожидалось {lo}-{hi}ms) — возможен туннель/доп. хоп."
    return None


def run_trace(ip):
    log.p("\n[7/8] Traceroute (ping.exe-shaped ICMP payload) + SNITCH + SSTP", CYAN)
    ttl, tspu_hop = 1, False
    while ttl <= 15:
        pkt = IP(dst=ip, ttl=ttl) / ICMP(id=os.getpid() & 0xFFFF, seq=ttl) / PING_EXE_PAYLOAD
        reply = sr1(pkt, verbose=0, timeout=1.0)
        if reply is None:
            log.p(f" {ttl:<2} *")
        else:
            log.p(f" {ttl:<2} {reply.src}")
            if reply.src.startswith("10."):
                parts = reply.src.split('.')
                if len(parts) == 4 and int(parts[3]) in range(131, 255):
                    tspu_hop = True
            if reply.type == 0:
                break
        ttl += 1
    if tspu_hop:
        log.p(f"-> Informational: TSPU management subnet layout detected (10.X.Y.Z).", YELLOW)
    return tspu_hop


async def sstp_probe(host, ip, port=443):
    guid = uuid.uuid4()
    corr = uuid.uuid4()
    req = (f"SSTP_DUPLEX_POST /sra_{{{guid}}}/ HTTP/1.1\r\n"
           f"Host: {host}\r\n"
           f"Content-Length: 18446744073709551615\r\n"
           f"SSTPCORRELATIONID: {{{corr}}}\r\n\r\n").encode()
    ans = await raw_tcp_exchange(ip, port, req, timeout=2.5)
    detected = b"HTTP/1.1 200" in ans and b"SSTP" in ans.upper()
    if detected:
        log.p(f"  SSTP: {RED}server accepted SSTP_DUPLEX_POST (Microsoft SSTP present){RESET}")
    else:
        log.p(f"  SSTP: no response to SSTP negotiation.", GREEN)
    return detected


# ===================================================================
# MODULE 17: --html report generation
# ===================================================================
_HTML_TEMPLATE = """<!doctype html>
<html lang="ru"><head><meta charset="utf-8">
<title>ByeByeVPN report — {target}</title>
<style>
body{{font-family:monospace;background:#0d1117;color:#c9d1d9;padding:2rem;max-width:900px;margin:auto}}
h1{{color:#58a6ff}} h2{{color:#79c0ff;border-bottom:1px solid #30363d;padding-bottom:.3rem;margin-top:2rem}}
.score{{font-size:2.5rem;font-weight:bold}}
.clean{{color:#3fb950}} .noisy{{color:#d29922}} .susp{{color:#db6d28}} .bad{{color:#f85149}}
table{{border-collapse:collapse;width:100%;margin-top:.5rem}}
td,th{{border:1px solid #30363d;padding:.4rem .6rem;text-align:left;font-size:.9rem}}
.tag-strong{{color:#f85149}} .tag-soft{{color:#d29922}} .tag-info{{color:#79c0ff}}
</style></head><body>
<h1>ByeByeVPN — {target} ({ip})</h1>
<div class="score {score_class}">{score}/100 — {label}</div>
<p>TSPU verdict: <b>{tspu_tier}</b> — {tspu_reason}</p>
<h2>Сигналы</h2>
<table><tr><th>Тип</th><th>Описание</th></tr>{signal_rows}</table>
<h2>Новые модули</h2>
<table><tr><th>Модуль</th><th>Результат</th></tr>{extra_rows}</table>
<h2>Raw JSON</h2><pre>{raw_json}</pre>
</body></html>"""


def generate_html_report(data, out_path):
    label = data.get("verdict", {}).get("label", "?")
    score = data.get("verdict", {}).get("score", 0)
    score_class = {"CLEAN": "clean", "NOISY": "noisy", "SUSPICIOUS": "susp", "OBVIOUSLY VPN": "bad"}.get(label, "")

    rows = []
    for s in data.get("verdict", {}).get("strong", []):
        rows.append(f'<tr><td class="tag-strong">STRONG</td><td>{s}</td></tr>')
    for s in data.get("verdict", {}).get("soft", []):
        rows.append(f'<tr><td class="tag-soft">SOFT</td><td>{s}</td></tr>')
    for s in data.get("verdict", {}).get("info", []):
        rows.append(f'<tr><td class="tag-info">INFO</td><td>{s}</td></tr>')

    extra_rows = []
    for key in ("pmtud", "bgp", "ptr", "fakedns", "fronting", "slowloris", "replay", "ttl_middlebox"):
        if key in data:
            extra_rows.append(f"<tr><td>{key}</td><td><pre>{json.dumps(data[key], ensure_ascii=False, indent=2)}</pre></td></tr>")

    html = _HTML_TEMPLATE.format(
        target=data.get("target", "?"), ip=data.get("ip", "?"),
        score=score, label=label, score_class=score_class,
        tspu_tier=data.get("tspu_verdict", {}).get("tier", "?"),
        tspu_reason=data.get("tspu_verdict", {}).get("reason", "?"),
        signal_rows="".join(rows) or "<tr><td colspan=2>—</td></tr>",
        extra_rows="".join(extra_rows) or "<tr><td colspan=2>—</td></tr>",
        raw_json=json.dumps(data, ensure_ascii=False, indent=2),
    )
    try:
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(html)
        log.p(f"[+] HTML-отчёт сохранён: {out_path}", GREEN)
    except Exception as e:
        log.p(f"[-] Не удалось сохранить HTML-отчёт: {e}", RED)


# ===================================================================
# MODULE 18: --compare — diff текущего скана с прошлым JSON-отчётом
# ===================================================================
def compare_reports(old_path, new_data):
    log.p(f"\n[Compare] Diff с прошлым отчётом: {old_path}", CYAN)
    try:
        with open(old_path, "r", encoding="utf-8") as f:
            old = json.load(f)
    except Exception as e:
        log.p(f"  [-] Не удалось прочитать {old_path}: {e}", RED)
        return None

    old_v, new_v = old.get("verdict", {}), new_data.get("verdict", {})
    diff = {
        "score_old": old_v.get("score"), "score_new": new_v.get("score"),
        "label_old": old_v.get("label"), "label_new": new_v.get("label"),
        "signals_added": sorted(set(new_data.get("signals", [])) - set(old.get("signals", []))),
        "signals_removed": sorted(set(old.get("signals", [])) - set(new_data.get("signals", []))),
    }

    delta = (diff["score_new"] or 0) - (diff["score_old"] or 0)
    trend = GREEN if delta > 0 else (RED if delta < 0 else CYAN)
    log.p(f"  Score: {diff['score_old']} -> {diff['score_new']} ({'+' if delta >= 0 else ''}{delta})", trend)
    log.p(f"  Label: {diff['label_old']} -> {diff['label_new']}", trend)
    if diff["signals_added"]:
        log.p("  Новые сигналы:", RED)
        for s in diff["signals_added"]:
            log.p(f"    + {s}", RED)
    if diff["signals_removed"]:
        log.p("  Пропавшие сигналы (стало лучше):", GREEN)
        for s in diff["signals_removed"]:
            log.p(f"    - {s}", GREEN)
    if not diff["signals_added"] and not diff["signals_removed"]:
        log.p("  Набор сигналов не изменился.", CYAN)
    return diff


# ---------- Phase 8: verdict + separate TSPU 3-tier verdict ----------
async def cmd_scan(host, args):
    ipv4, ipv6 = await resolve_dns(host)
    ip = ipv4 or ipv6
    if not ip:
        return
    report_data["target"] = host
    report_data["ip"] = ip

    is_hosting, country, asn_str = await geoip_aggregation(ip)
    ports_to_scan = CURATED_PORTS if args.fast else list(range(1, 65536))

    bgp_result = await bgp_anomaly_check(ip, country, asn_str) if not args.no_bgp else {"anomalies": []}

    open_ports, med, std, closed_beh, bgp_drop, mss_info, closed_beh2 = await tcp_scan(ip, ports_to_scan, args)

    if args.passive:
        log.p("\n[!] PASSIVE MODE ON: Skipping UDP, J3 and Fuzzer.", MAGENTA)
        udp_det, has_proxy, utls, rkn, canned, rep, ss_drop, ja4s_notes = [], False, False, False, False, False, False, []
        sstp_hit = False
        fakedns_result = {"tested": False, "leak": False}
        fronting_result, slowloris_result, replay_result = {"fronting_possible": False}, {"tested": False}, {"verdict": "n/a"}
    else:
        udp_det = run_udp_probes(ip)
        has_proxy, utls, rkn, ja4s_notes = await service_fuzzer(ip, open_ports, host, args)
        canned, rep, ss_drop = await j3_probes(ip, open_ports, host, args)
        sstp_hit = await sstp_probe(host, ip) if 443 in open_ports else False
        fakedns_result = fakedns_leak_check(ip, open_ports)

        tls_port = 443 if 443 in open_ports else (8443 if 8443 in open_ports else None)
        if tls_port and not args.no_fronting:
            fronting_result = await domain_fronting_check(ip, tls_port, host)
        else:
            fronting_result = {"fronting_possible": False}
        if tls_port and not args.no_replay:
            replay_result = await replay_probe(ip, tls_port, host)
        else:
            replay_result = {"verdict": "n/a"}
        web_port = 80 if 80 in open_ports else tls_port
        if web_port and args.slowloris:
            slowloris_result = await slowloris_timing_probe(ip, web_port, host)
        else:
            slowloris_result = {"tested": False}

    ptr_result = await ptr_cert_check(ip, host, open_ports)
    pmtud_result = pmtud_probe(ip) if not args.no_pmtud else None
    ttl_result = ttl_middlebox_check(ip, open_ports) if not args.no_ttl else {"tested": False}

    tspu_hop = run_trace(ip)
    snitch_signal = snitch_check(med, country) if med else None
    if snitch_signal:
        log.p(f"  SNITCH: {YELLOW}{snitch_signal}{RESET}")

    # ---- Verdict (score 0-100, 4 labels) ----
    log.p("\n[8/8] Verdict\n", CYAN)
    strong, soft, info = [], [], []

    if bgp_drop: strong.append("BGP Blackhole.")
    if rkn: strong.append("HTTP 302 Redirect to RKN (TSPU Type A).")
    if canned: strong.append("Canned fallback page (Xray/Trojan).")
    if has_proxy: strong.append("Open HTTP CONNECT proxy.")
    if udp_det: strong.append(f"UDP tunnels: {','.join(udp_det)}")
    if ss_drop: strong.append("SS-AEAD-consistent silent drop.")
    if sstp_hit: strong.append("Microsoft SSTP endpoint detected.")

    if utls: soft.append("uTLS mismatch (Reality-style discriminator).")
    if std > 25.0: soft.append("Bimodal TCP Handshake (userspace TUN).")
    if is_hosting: soft.append("Target IP is Hosting ASN.")
    if snitch_signal: soft.append("SNITCH: RTT/GeoIP mismatch.")

    if fakedns_result.get("leak"): strong.append("FakeDNS leak: DNS-резолвер отдаёт приватный/fake-ip адрес.")
    if fronting_result.get("fronting_possible"): soft.append("Domain fronting: сервер принял запрос с чужим SNI/Host.")
    if replay_result.get("verdict") == "no_replay_protection_observed":
        soft.append("TLS ClientHello replay: анти-replay защита не наблюдается.")
    if ptr_result.get("mismatch"): soft.append("PTR/сертификат mismatch (generic хостинг-PTR).")
    if pmtud_result and pmtud_result.get("encapsulated"): soft.append(f"PMTUD: MTU={pmtud_result['mtu']} ({pmtud_result['note']}).")
    if ttl_result.get("flagged"): soft.append(f"TTL middlebox: diff={ttl_result.get('diff')} между открытым/закрытым портом.")
    for a in bgp_result.get("anomalies", []):
        soft.append(f"BGP: {a}")

    if tspu_hop: info.append("TSPU 10.X.Y.Z hop [Info only, no penalty].")
    for note in ja4s_notes:
        info.append(f"JA4S stack guess: {note}")
    if slowloris_result.get("tested") and slowloris_result.get("closed_after_s") is not None:
        info.append(f"Slowloris timing: сервер оборвал соединение через {slowloris_result['closed_after_s']}s.")

    score = 100
    if bgp_drop or rkn: score -= 40
    score -= len(strong) * 20
    score -= len(soft) * 10
    score = max(0, score)
    label = "CLEAN" if score > 84 else "NOISY" if score > 69 else "SUSPICIOUS" if score > 49 else "OBVIOUSLY VPN"

    log.p(f"Score: {score}/100  label: {label}\n", GREEN if label == "CLEAN" else RED)
    for s in strong: log.p(f"[!] {s}", RED)
    for s in soft: log.p(f"[-] {s}", YELLOW)
    for s in info: log.p(f"[i] {s}", CYAN)

    # ---- Separate TSPU 3-tier verdict ----
    named_protocol_hits = len(strong)  # each "strong" item above is a named-protocol/strong signal
    soft_anomaly_hits = len(soft)

    if named_protocol_hits >= 1:
        tspu_tier = "IMMEDIATE BLOCK"
        tspu_reason = "Named-протокол/сигнатура найдена — SYN/handshake будет дропаться."
    elif soft_anomaly_hits >= 2:
        tspu_tier = "BLOCK (cumulative)"
        tspu_reason = f"{soft_anomaly_hits} soft-аномалии — классификатор пересекает порог."
    elif soft_anomaly_hits == 1:
        tspu_tier = "THROTTLE / QoS"
        tspu_reason = "1 soft-аномалия — вероятен флаг на мониторинг / rate-limit, не блок."
    else:
        tspu_tier = "PASS / ALLOW"
        tspu_reason = "Сигнатур не найдено."

    log.p(f"\nTSPU verdict: {tspu_tier}  — {tspu_reason}", RED if "BLOCK" in tspu_tier else (YELLOW if tspu_tier.startswith("THROTTLE") else GREEN))

    report_data["verdict"] = {"score": score, "label": label, "strong": strong, "soft": soft, "info": info}
    report_data["tspu_verdict"] = {"tier": tspu_tier, "reason": tspu_reason}
    report_data["signals"] = strong + soft + info
    report_data["pmtud"] = pmtud_result
    report_data["bgp"] = bgp_result
    report_data["ptr"] = ptr_result
    report_data["fakedns"] = fakedns_result
    report_data["fronting"] = fronting_result
    report_data["slowloris"] = slowloris_result
    report_data["replay"] = replay_result
    report_data["ttl_middlebox"] = ttl_result

    if args.compare:
        compare_reports(args.compare, report_data)

    if args.html:
        html_path = args.html if isinstance(args.html, str) else f"{host.replace('/', '_')}_report.html"
        generate_html_report(report_data, html_path)

    log.flush_save(host, json_export=args.json, save_file=args.save)


async def main():
    if os.geteuid() != 0:
        print(f"{RED}Run via 'sudo' for Scapy SYN scan.{RESET}"); sys.exit(1)

    parser = argparse.ArgumentParser(description="ByeByeVPN v2.8.3 Python Port (spec-aligned)")
    sub = parser.add_subparsers(dest="cmd")

    p_scan = sub.add_parser("scan", help="Full TSPU/DPI scan")
    p_scan.add_argument("host")
    p_scan.add_argument("--fast", action="store_true", help="curated ~200 ports instead of full 1-65535")
    p_scan.add_argument("--json", action="store_true")
    p_scan.add_argument("--save", nargs="?", const="AUTO")
    p_scan.add_argument("--stealth", action="store_true")
    p_scan.add_argument("--passive", action="store_true")
    p_scan.add_argument("--j3-subset", type=int, choices=range(1, 9))
    p_scan.add_argument("--html", nargs="?", const=True, default=False,
                         help="сохранить HTML-отчёт (опционально: путь к файлу)")
    p_scan.add_argument("--compare", metavar="OLD.json",
                         help="сравнить текущий скан с прошлым JSON-отчётом (diff score/label/signals)")
    p_scan.add_argument("--slowloris", action="store_true",
                         help="включить Slowloris-style timing-пробу (одно соединение, +~12s к скану)")
    p_scan.add_argument("--no-pmtud", action="store_true", help="пропустить PMTUD MTU-фингерпринт")
    p_scan.add_argument("--no-bgp", action="store_true", help="пропустить BGP-анализ аномалий (RIPEstat)")
    p_scan.add_argument("--no-ttl", action="store_true", help="пропустить TTL middlebox-детект")
    p_scan.add_argument("--no-fronting", action="store_true", help="пропустить domain fronting проверку")
    p_scan.add_argument("--no-replay", action="store_true", help="пропустить TLS ClientHello replay-симуляцию")

    p_dpi = sub.add_parser("dpi", help="SNI-RST Probe")
    p_dpi.add_argument("host")

    p_ech = sub.add_parser("ech", help="DNS HTTPS-RR Probe")
    p_ech.add_argument("domain")

    p_audit = sub.add_parser("audit-config", help="Offline Config Analyzer")
    p_audit.add_argument("path")

    p_sweep = sub.add_parser("sweep", help="Subnet Scanner")
    p_sweep.add_argument("cidr")

    args = parser.parse_args()
    if not args.cmd:
        parser.print_help(); sys.exit(1)

    log.p("ByeByeVPN Python Port — v1.2 spec-aligned\n", MAGENTA)

    if args.cmd == "scan": await cmd_scan(args.host, args)
    elif args.cmd == "dpi": await cmd_dpi(args.host)
    elif args.cmd == "ech": await cmd_ech(args.domain)
    elif args.cmd == "audit-config": await cmd_audit_config(args.path)
    elif args.cmd == "sweep": await cmd_sweep(args.cidr)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nAborted.")
