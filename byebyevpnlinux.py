#!/usr/bin/env python3
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

warnings.filterwarnings("ignore")

try:
    from scapy.all import IP, ICMP, TCP, sr1, sr, conf
    conf.verb = 0
except ImportError:
    print("Error: Install scapy -> pip install scapy")
    sys.exit(1)

RED, GREEN, YELLOW, CYAN, MAGENTA, RESET = '\033[91m', '\033[92m', '\033[93m', '\033[96m', '\033[95m', '\033[0m'

report_data = {
    "target": "", "ip": "", "verdict": {}, "signals": []
}

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
            except: pass
        if json_export:
            try:
                with open(f"{target_host.replace('/', '_')}_report.json", "w") as f:
                    json.dump(report_data, f, indent=4)
                print(f"[+] JSON report saved", GREEN)
            except: pass

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
    except:
        return b""

# ===================================================================
# MODULE 1: BYTE-ACCURATE CHROME 131 & JA4S PARSER (v2.6.0)
# ===================================================================
def build_chrome_131_clienthello(sni_name):
    """Побайтовая генерация Chrome 131 ClientHello с GREASE и Padding"""
    grease_val = bytes.fromhex(random.choice(["0a0a", "1a1a", "2a2a", "3a3a", "4a4a"]))
    
    # Cipher Suites (Chrome 131 + GREASE)
    ciphers = grease_val + bytes.fromhex("130113021303c02bc02fc02cc030cca9cca8c013c014009c009d002f0035")
    
    # Extensions
    ext_sni = b"\x00\x00" + struct.pack(">H", len(sni_name) + 3) + struct.pack(">H", len(sni_name) + 1) + b"\x00" + struct.pack(">H", len(sni_name)) + sni_name.encode()
    ext_alpn = bytes.fromhex("0010000e000c02683208687474702f312e31")
    ext_supported_groups = bytes.fromhex("000a00080006001d00170018") # x25519, secp256r1, secp384r1
    ext_sig_algs = bytes.fromhex("000d00140012040308040401050308050501080606010201")
    ext_key_share = bytes.fromhex("003300260024001d0020") + secrets.token_bytes(32)
    ext_versions = bytes.fromhex("002b00050403040303")
    
    # Chrome 131 Pad to 512 bytes
    extensions = grease_val + b"\x00\x00" + ext_sni + ext_alpn + ext_supported_groups + ext_sig_algs + ext_key_share + ext_versions
    pad_len = 512 - (43 + len(ciphers) + len(extensions))
    if pad_len > 0:
        extensions += bytes.fromhex("0015") + struct.pack(">H", pad_len - 4) + (b"\x00" * (pad_len - 4))

    payload = b"\x03\x03" + secrets.token_bytes(32) + b"\x00" + struct.pack(">H", len(ciphers)) + ciphers + b"\x01\x00" + struct.pack(">H", len(extensions)) + extensions
    ch = b"\x01\x00" + struct.pack(">H", len(payload)) + payload
    record = b"\x16\x03\x01" + struct.pack(">H", len(ch)) + ch
    return record

def parse_server_hello(data):
    """Упрощенный JA4S парсер для извлечения Cipher и выявления аномалий TLS"""
    if len(data) < 42 or data[0] != 0x16: return None
    try:
        cipher = data[43:45].hex()
        return cipher
    except:
        return None

# ===================================================================
# MODULE 2: ECH / DNS HTTPS-RR (v2.8.3)
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
# MODULE 3: DPI SNI-RST PROBE (v2.8.2)
# ===================================================================
async def cmd_dpi(host, port=443):
    log.p(f"\n[*] Active SNI-RST Path Probe -> {host}:{port}", CYAN)
    try:
        ip = socket.gethostbyname(host)
    except:
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
        except ConnectionResetError: return "RST"
        except: return "DROP"

    res_benign = await send_ch("google.com")
    res_target = await send_ch(host)
    
    if res_benign == True and res_target == "RST":
        log.p(f"\n[!] ACTIVE DPI SNI-RST INJECTION DETECTED!", RED)
        res_frag = await send_ch(host, split=True)
        if res_frag == True: log.p("[+] Bypass SUCCESS! Splitting CH defeated DPI.", GREEN)
        else: log.p(f"[-] Bypass FAILED. Fragmented SNI result: {res_frag}", RED)
    else:
        log.p(f"[-] No SNI-based RST injection detected. Target={res_target}, Benign={res_benign}", GREEN)

# ===================================================================
# MODULE 4: AUDIT-CONFIG (v2.8.0)
# ===================================================================
async def cmd_audit_config(path):
    log.p(f"\n[*] Offline Config Audit: {path}", CYAN)
    try:
        with open(path, "r") as f: content = f.read()
    except Exception as e:
        log.p(f"[-] Cannot read file: {e}", RED); return

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
# MODULE 5: SWEEP SUBNET (v2.8.0)
# ===================================================================
async def cmd_sweep(cidr):
    log.p(f"\n[*] Subnet Sweep: {cidr} (Port 443 SNI checks)", CYAN)
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except Exception as e:
        log.p(f"[-] Invalid CIDR: {e}", RED); return

    async def check_ip(ip_str):
        try:
            r, w = await asyncio.wait_for(asyncio.open_connection(ip_str, 443), timeout=1.5)
            w.write(build_chrome_131_clienthello("google.com")); await w.drain()
            ans = await asyncio.wait_for(r.read(1024), timeout=1.5)
            w.close()
            if ans:
                c = parse_server_hello(ans)
                log.p(f"  [+] {ip_str:<15} Open | JA4S Cipher: {c}")
        except: pass

    tasks = [check_ip(str(ip)) for ip in net.hosts()][:256] # Limit to /24 max for safety
    await asyncio.gather(*tasks)
    log.p("[*] Sweep complete.", GREEN)

# ===================================================================
# CORE PIPELINE: TCP, UDP, J3, SERVICE (Updated to 100% parity)
# ===================================================================
async def geoip_aggregation(ip):
    log.p(f"\n[1/8] GeoIP (HTTPS Providers Only - No IP Leak)", CYAN)
    providers = [("ipapi.is", 443), ("iplocate.io", 443)]
    is_hosting = False
    
    for host, port in providers:
        req = f"GET /{ip}/json HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
        if host == "ipapi.is": req = f"GET /json/{ip} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
        
        ctx = ssl.create_default_context()
        ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
        try:
            r, w = await asyncio.wait_for(asyncio.open_connection(host, port, ssl=ctx), timeout=3)
            w.write(req.encode()); await w.drain()
            resp = await asyncio.wait_for(r.read(4096), timeout=3)
            w.close()
            res = resp.decode('utf-8', errors='ignore')
            c = re.search(r'"(?:countryCode|country)"\s*:\s*"([A-Z]{2})"', res, re.I)
            a = re.search(r'"(?:as|asn|org|name|company)"\s*:\s*"([^"]+)"', res, re.I)
            a_str = a.group(1) if a else "Unknown"
            hosting_kws = ['host', 'cloud', 'telecom', 'datacenter', 'vps', 'llc', 'hetzner', 'ovh', 'digital', 'aws']
            if any(kw in a_str.lower() for kw in hosting_kws): is_hosting = True
            log.p(f"  {host:<16} IP {ip} {c.group(1) if c else '?'} AS {a_str} {'(HOSTING)' if is_hosting else ''}", YELLOW if is_hosting else GREEN)
            break
        except: pass
    return is_hosting

async def tcp_scan(ip, ports, args):
    log.p(f"\n[2/8] TCP Stealth SYN-scan (Press Ctrl+C to skip phase)", CYAN)
    open_ports = []
    try:
        ans, _ = sr(IP(dst=ip)/TCP(dport=ports, flags="S"), timeout=1.0, verbose=0)
        for s, r in ans:
            if r.haslayer(TCP) and r[TCP].flags == 0x12:
                open_ports.append(s[TCP].dport)
                sr1(IP(dst=ip)/TCP(dport=s[TCP].dport, flags="R"), timeout=0.1, verbose=0)
    except KeyboardInterrupt:
        log.p("\n[!] Q-SKIP: TCP scan aborted by user. Proceeding with found ports...", MAGENTA)

    if len(ports) > 1000 and len(open_ports) == 0:
        return [], 0, 0, "drop", True # BGP Blackhole

    log.p(f"  Open ports: {open_ports}", GREEN)
    med, std = 0.0, 0.0
    
    if open_ports:
        test_port = open_ports[0]
        log.p(f"  TCP Stack Fingerprint (6 connects to port {test_port})...")
        rtts = []
        for _ in range(6):
            t0 = time.time()
            try:
                r, w = await asyncio.wait_for(asyncio.open_connection(ip, test_port), timeout=1.0)
                rtts.append((time.time() - t0) * 1000)
                w.close()
            except: pass
            await stealth_sleep(args)
        if len(rtts) > 1:
            med, std = statistics.median(rtts), statistics.stdev(rtts)
            log.p(f"  Handshake median={med:.1f}ms stddev={std:.1f}ms")

    return open_ports, med, std, "RST", False

def run_udp_probes(ip):
    log.p("\n[3/8] UDP Probes (WG, Amnezia Sweep, Hysteria)", CYAN)
    wg_init = b"\x01\x00\x00\x00" + secrets.token_bytes(144)
    quic_payload = b'\xc3\x00\x00\x00\x01\x08' + secrets.token_bytes(16) + secrets.token_bytes(1182)
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(0.8)
    detected = []

    try:
        sock.sendto(wg_init, (ip, 51820)); data, _ = sock.recvfrom(1024)
        detected.append("WireGuard")
        log.p(f"  UDP:51820 WireGuard {RED}HANDSHAKE ACCEPTED{RESET}")
    except: pass

    try:
        sock.sendto(quic_payload, (ip, 443)); data, _ = sock.recvfrom(1024)
        detected.append("Hysteria2 QUIC")
        log.p(f"  UDP:443   Hysteria2 {RED}HANDSHAKE ACCEPTED{RESET}")
    except: pass

    # AmneziaWG S1 Deep-Probe Sweep (v2.6.0)
    log.p("  Sweeping AmneziaWG obfuscation (S1)...")
    for s1_size in [4, 8, 12, 16, 24, 32, 64, 128]:
        try:
            sock.sendto(secrets.token_bytes(s1_size) + wg_init, (ip, 51820))
            data, _ = sock.recvfrom(1024)
            log.p(f"  UDP:51820 AmneziaWG Sx={s1_size} {RED}HANDSHAKE ACCEPTED!{RESET}")
            detected.append(f"AmneziaWG (S1={s1_size})")
            break
        except: pass
    sock.close()
    return detected

async def service_fuzzer(ip, open_ports, target_host, args):
    log.p("\n[5/8] Service Fingerprinting", CYAN)
    has_http_proxy, utls_diff, rkn_redirect = False, False, False

    for p in open_ports:
        log.p(f"  -> Port :{p}")
        await stealth_sleep(args)

        # 1. Open Proxy (Strict 200 OK fix)
        ans = await raw_tcp_exchange(ip, p, b"CONNECT 8.8.8.8:443 HTTP/1.1\r\nHost: 8.8.8.8:443\r\n\r\n")
        if b"200 OK" in ans:
            log.p(f"     {RED}HTTP/1.1 200 OK [Open Proxy]{RESET}")
            has_http_proxy = True

        # 2. RKN Redirect (TSPU Type A)
        ans = await raw_tcp_exchange(ip, p, b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
        if b"302" in ans and (b"rkn.gov.ru" in ans or b"warning.rt.ru" in ans):
            log.p(f"     {RED}302 Redirect to RKN block page!{RESET}")
            rkn_redirect = True

        # 3. uTLS Dual-Probe without curl_cffi (JA4S Analysis)
        if p in (443, 8443):
            ssl_success, chrome_success = False, False
            try:
                ctx = ssl.create_default_context()
                ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
                r1, w1 = await asyncio.wait_for(asyncio.open_connection(ip, p, ssl=ctx), timeout=2)
                w1.close(); ssl_success = True
            except: pass

            try:
                ch_raw = build_chrome_131_clienthello(target_host)
                srv_hello = await raw_tcp_exchange(ip, p, ch_raw)
                if parse_server_hello(srv_hello): chrome_success = True
            except: pass

            if ssl_success != chrome_success:
                utls_diff = True
                log.p(f"     uTLS Probe: {YELLOW}Discriminator active! OpenSSL={ssl_success}, Chrome={chrome_success}{RESET}")

    return has_http_proxy, utls_diff, rkn_redirect

async def j3_probes(ip, open_ports, args):
    log.p("\n[6/8] J3 / Active Probing (v2.8.0 gRPC & Anti-FP)", CYAN)
    
    tls_ch_static = bytes.fromhex("16030100c6010000c20303") + secrets.token_bytes(60)
    # H2 Preface + HEADERS Frame (gRPC Probe v2.8.0)
    grpc_probe = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + bytes.fromhex("000000040000000000") + bytes.fromhex("000005010400000001") 

    probes_list = [
        ("HTTP GET /", b"GET / HTTP/1.1\r\nHost: " + ip.encode() + b"\r\n\r\n"),
        ("SSH banner", b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\r\n"),
        ("Random 512B", secrets.token_bytes(512)),
        ("SS-AEAD Length", secrets.token_bytes(50)),
        ("TLS CH invalid", tls_ch_static),
        ("gRPC HTTP/2", grpc_probe),
        ("0xFF x128", b"\xff" * 128)
    ]

    random.shuffle(probes_list)
    if hasattr(args, 'j3_subset') and args.j3_subset:
        probes_list = probes_list[:args.j3_subset]

    canned, replay, ss_drop = False, False, False

    for port in open_ports:
        log.p(f" -> port :{port}")
        responses = []
        for name, payload in probes_list:
            t0 = time.time()
            ans = await raw_tcp_exchange(ip, port, payload)
            await stealth_sleep(args)
            if ans:
                responses.append(ans)
                clean_str = ans[:20].decode('utf-8', 'ignore').replace('\r', '').replace('\n', ' ')
                log.p(f"    RESP {name:<15} {len(ans)}B {clean_str}", GREEN)
            else:
                if "SS-AEAD" in name and (time.time() - t0) < 0.2:
                    ss_drop = True
                    log.p(f"    SILENT {name:<15} {RED}Immediate Drop (SS-AEAD)!{RESET}")
                else: log.p(f"    SILENT {name:<15} dropped")

        if len(responses) >= 2:
            f_lines = [r.split(b'\r\n')[0] for r in responses if b'\r\n' in r]
            if len(f_lines) > 2 and f_lines.count(f_lines[0]) >= 2 and b"HTTP/1." in f_lines[0]:
                canned = True
                log.p("    !! Canned HTTP response detected for non-HTTP raw junk.", RED)

    return canned, replay, ss_drop

def run_trace(ip):
    log.p("\n[7/8] Traceroute (TSPU Informational Check)", CYAN)
    ttl, tspu_hop = 1, False
    while ttl <= 15:
        pkt = IP(dst=ip, ttl=ttl)/ICMP(id=os.getpid() & 0xFFFF, seq=ttl)
        reply = sr1(pkt, verbose=0, timeout=1.0)
        if reply is None: log.p(f" {ttl:<2} *")
        else:
            log.p(f" {ttl:<2} {reply.src}")
            if reply.src.startswith("10."):
                parts = reply.src.split('.')
                if len(parts) == 4 and int(parts[3]) in range(131, 255): tspu_hop = True
            if reply.type == 0: break
        ttl += 1
    if tspu_hop: log.p(f"-> Informational: TSPU management subnet layout detected (10.X.Y.Z).", YELLOW)
    return tspu_hop

async def cmd_scan(host, args):
    try: ip = socket.gethostbyname(host)
    except: log.p("DNS failed", RED); return

    is_hosting = await geoip_aggregation(ip)
    ports_to_scan = [21, 22, 53, 80, 443, 1194, 3389, 8080, 8443] if args.fast else list(range(1, 1024))
    
    open_ports, med, std, closed_beh, bgp_drop = await tcp_scan(ip, ports_to_scan, args)

    if args.passive:
        log.p("\n[!] PASSIVE MODE ON: Skipping UDP, J3 and Fuzzer.", MAGENTA)
        udp_det, has_proxy, utls, rkn, canned, rep, ss_drop = [], False, False, False, False, False, False
    else:
        udp_det = run_udp_probes(ip)
        has_proxy, utls, rkn = await service_fuzzer(ip, open_ports, host, args)
        canned, rep, ss_drop = await j3_probes(ip, open_ports, args)

    tspu_hop = run_trace(ip)

    # Verdict
    log.p("\n[8/8] Verdict\n", CYAN)
    strong, soft, info = [], [], []

    if bgp_drop: strong.append("BGP Blackhole (TSPU Type B).")
    if rkn: strong.append("HTTP 302 Redirect to RKN (TSPU Type A).")
    if canned: strong.append("Canned fallback page (Xray/Trojan).")
    if has_proxy: strong.append("Open HTTP CONNECT proxy.")
    if udp_det: strong.append(f"UDP VPNs: {','.join(udp_det)}")
    if ss_drop: strong.append("SS-AEAD active drop.")

    if utls: soft.append("uTLS mismatch (Reality discriminator).")
    if std > 25.0: soft.append("Bimodal TCP Handshake (userspace TUN).")

    if tspu_hop: info.append("TSPU 10.X.Y.Z hop [Info only, no penalty].")
    if is_hosting: info.append("Target IP is Hosting ASN.")

    score = 100
    if bgp_drop or rkn: score -= 40
    score -= len(strong) * 25
    score -= len(soft) * 10
    score = max(0, score)

    verdict = "CLEAN" if score > 80 else "SUSPICIOUS" if score > 50 else "OBVIOUSLY-VPN"
    log.p(f"Final score: {score}/100  verdict: {verdict}\n", GREEN if verdict=="CLEAN" else RED)

    for s in strong: log.p(f"[!] {s}", RED)
    for s in soft: log.p(f"[-] {s}", YELLOW)
    for s in info: log.p(f"[i] {s}", CYAN)
    log.flush_save(host, json_export=args.json, save_file=args.save)

async def main():
    if os.geteuid() != 0:
        print(f"{RED}Run via 'sudo' for Scapy SYN scan.{RESET}"); sys.exit(1)

    parser = argparse.ArgumentParser(description="ByeByeVPN v2.8.3 Python Port (1:1 Parity)")
    sub = parser.add_subparsers(dest="cmd")

    p_scan = sub.add_parser("scan", help="Full TSPU/DPI scan")
    p_scan.add_argument("host")
    p_scan.add_argument("--fast", action="store_true")
    p_scan.add_argument("--json", action="store_true")
    p_scan.add_argument("--save", nargs="?", const="AUTO")
    p_scan.add_argument("--stealth", action="store_true")
    p_scan.add_argument("--passive", action="store_true")
    p_scan.add_argument("--j3-subset", type=int, choices=range(1,8))

    p_dpi = sub.add_parser("dpi", help="SNI-RST Probe")
    p_dpi.add_argument("host")

    p_ech = sub.add_parser("ech", help="DNS HTTPS-RR Probe")
    p_ech.add_argument("domain")

    p_audit = sub.add_parser("audit-config", help="Offline Config Analyzer")
    p_audit.add_argument("path")

    p_sweep = sub.add_parser("sweep", help="Subnet Scanner")
    p_sweep.add_argument("cidr")

    args = parser.parse_args()
    if not args.cmd: parser.print_help(); sys.exit(1)

    log.p("ByeByeVPN Python Port — v2.8.3 FULL Feature Parity\n", MAGENTA)

    if args.cmd == "scan": await cmd_scan(args.host, args)
    elif args.cmd == "dpi": await cmd_dpi(args.host)
    elif args.cmd == "ech": await cmd_ech(args.domain)
    elif args.cmd == "audit-config": await cmd_audit_config(args.path)
    elif args.cmd == "sweep": await cmd_sweep(args.cidr)

if __name__ == "__main__":
    try: asyncio.run(main())
    except KeyboardInterrupt: print("\nAborted.")
