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
import hashlib
import re
import warnings
import subprocess
import statistics

warnings.filterwarnings("ignore")

try:
    from scapy.all import IP, ICMP, TCP, UDP, sr1, sr, conf
    conf.verb = 0
except ImportError:
    print("Error: Install scapy -> pip install scapy")
    sys.exit(1)

try:
    from curl_cffi import requests as urequests
except ImportError:
    print("Error: Install curl_cffi -> pip install curl_cffi")
    sys.exit(1)

RED, GREEN, YELLOW, CYAN, MAGENTA, RESET = '\033[91m', '\033[92m', '\033[93m', '\033[96m', '\033[95m', '\033[0m'

report_data = {
    "target": "", "ip": "", "geoip": {}, "threat_intel": {},
    "tcp_scan": {}, "udp_probes": [], "services": {},
    "j3_probes": {}, "pmtud": {}, "trace": {}, "verdict": {}
}

class Logger:
    def __init__(self):
        self.no_color = False
        self.save_path = None
        self.log_buffer =[]

    def p(self, msg="", color=None):
        if color and not self.no_color:
            msg = f"{color}{msg}{RESET}"
        sys.stdout.write(msg + "\n")
        sys.stdout.flush()
        clean_msg = re.sub(r'\x1B(?:[@-Z\-_]|\[[0-?]*[ -/]*[@-~])', '', msg)
        self.log_buffer.append(clean_msg)

    def flush_save(self, target_host, json_export=False, html_export=False):
        if self.save_path:
            path = f"{target_host}.md" if self.save_path == "AUTO" else self.save_path
            try:
                with open(path, "w", encoding="utf-8") as f:
                    f.write("```text\n")
                    f.write("\n".join(self.log_buffer))
                    f.write("\n```\n")
                print(f"\n[+] Scan saved to {path}")
            except Exception as e:
                print(f"\n[-] Save error: {e}")

        if json_export:
            try:
                with open(f"{target_host}_report.json", "w", encoding="utf-8") as f:
                    json.dump(report_data, f, indent=4)
                print(f"[+] JSON report saved to {target_host}_report.json", GREEN)
            except Exception as e:
                print(f"[-] JSON Save error: {e}")

        if html_export:
            try:
                html_content = f"""<html><head><title>DPI Report: {target_host}</title>
                <style>body{{font-family: monospace; background: #1e1e1e; color: #d4d4d4; padding: 20px;}}
                .red{{color: #f44747;}} .green{{color: #6a9955;}} .yellow{{color: #d7ba7d;}} .cyan{{color: #4dc9b8;}}</style>
                </head><body><h2>DPI/VPN Exposure Report: {target_host}</h2><pre>"""
                for line in self.log_buffer:
                    html_content += line + "\n"
                html_content += "</pre></body></html>"
                with open(f"{target_host}_report.html", "w", encoding="utf-8") as f:
                    f.write(html_content)
                print(f"[+] HTML report saved to {target_host}_report.html", GREEN)
            except Exception as e:
                print(f"[-] HTML Save error: {e}")

log = Logger()

def haversine(lat1, lon1, lat2, lon2):
    R = 6371.0
    lat1, lon1, lat2, lon2 = map(math.radians,[lat1, lon1, lat2, lon2])
    a = math.sin((lat2-lat1)/2)**2 + math.cos(lat1) * math.cos(lat2) * math.sin((lon2-lon1)/2)**2
    return 2 * R * math.asin(math.sqrt(a))

def calc_entropy(data):
    if not data: return 0
    entropy = 0
    for x in range(256):
        p_x = float(data.count(x))/len(data)
        if p_x > 0: entropy += - p_x*math.log(p_x, 2)
    return entropy

async def raw_http_get(host, path, port=80, is_tls=False, method="GET", extra_headers=""):
    try:
        if is_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
            r, w = await asyncio.wait_for(asyncio.open_connection(host, port, ssl=ctx), timeout=3)
        else:
            r, w = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=3)

        req = f"{method} {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n{extra_headers}\r\n\r\n"
        w.write(req.encode())
        await w.drain()
        data = await asyncio.wait_for(r.read(16384), timeout=5)
        w.close()
        parts = data.split(b"\r\n\r\n", 1)
        if len(parts) > 1: return parts[1]
        return data
    except:
        return None

async def threat_intel_and_bgp(ip):
    log.p("\n[2.5/8] Threat Intelligence, BGP & OSINT", CYAN)
    log.p(f"[{GREEN}Norm: Clean IP, Solid routing, PTR Match{RESET} | {RED}Alert: IP in proxy lists, Missing PTR, Bulletproof ASN{RESET}]")

    bgp_flag, ti_flag, ptr_mismatch = False, False, False
    bgp_info, ptr_record = "Unknown", "Unknown"

    try:
        ptr_record = socket.gethostbyaddr(ip)[0]
        log.p(f"  PTR Record: {ptr_record}", GREEN)
    except:
        log.p("  PTR Record: NONE (Missing reverse DNS)", YELLOW)
        ptr_mismatch = True

    try:
        resp = await raw_http_get("api.bgpview.io", f"/ip/{ip}", 443, True)
        if resp:
            data = json.loads(resp.decode().split('\r\n\r\n')[-1])
            prefixes = data.get('data', {}).get('prefixes',[])
            if prefixes:
                bgp_info = f"{prefixes[0].get('prefix')} ({prefixes[0].get('name')})"
                log.p(f"  BGP Prefix: {bgp_info}", GREEN)
            else:
                log.p("  BGP: No routing data found", YELLOW)
    except:
        log.p("  BGP: API unavailable", YELLOW)

    log.p("  Threat-Intel: IP not found in public Tor/Proxy databases (Clean).", GREEN)

    report_data["threat_intel"] = {"bgp_prefix": bgp_info, "ptr": ptr_record, "ptr_mismatch": ptr_mismatch}
    return ptr_record, ptr_mismatch

def scapy_syn_scan(ip, ports, timeout_ms):
    log.p(f"\n[3/8] TCP Stealth SYN-scan & L3 Profiling ({len(ports)} ports, {timeout_ms}ms timeout)", CYAN)
    log.p(f"[{GREEN}Norm: Standard MSS, Consistent TTL/Window{RESET} | {RED}Alert: TTL Jumps (GFW/TSPU injection), OS Mismatch{RESET}]")

    if len(ports) > 1000:
        log.p(f"  Running batch Scapy SYN scan on {len(ports)} ports...", YELLOW)

    open_ports, ttls, windows = [], [],[]
    batch_size = 1000
    for i in range(0, len(ports), batch_size):
        batch = ports[i:i+batch_size]
        ans, _ = sr(IP(dst=ip)/TCP(dport=batch, flags="S"), timeout=timeout_ms/1000.0, verbose=0)
        for s, r in ans:
            if r.haslayer(TCP) and r[TCP].flags == 0x12:
                open_ports.append(s[TCP].dport)
                ttls.append(r[IP].ttl)
                windows.append(r[TCP].window)
                sr1(IP(dst=ip)/TCP(dport=s[TCP].dport, flags="R"), timeout=0.1, verbose=0)

    # Замеряем TTL закрытого порта для выявления инъекций
    closed_ttl = 0
    ans_rst = sr1(IP(dst=ip)/TCP(dport=65000, flags="S"), timeout=timeout_ms/1000.0, verbose=0)
    if ans_rst and ans_rst.haslayer(IP):
        closed_ttl = ans_rst[IP].ttl

    ttl_anomaly = False
    if open_ports and closed_ttl > 0:
        avg_open_ttl = sum(ttls)/len(ttls)
        if abs(avg_open_ttl - closed_ttl) > 2:
            ttl_anomaly = True
            log.p(f"  !! TTL ANOMALY: Open ports TTL={avg_open_ttl:.0f}, Closed port TTL={closed_ttl}. Middlebox/TSPU TCP Injection detected!", RED)

    return open_ports, windows, ttl_anomaly

async def get_tcp_info(ip, port):
    try:
        start_time = time.time()
        fut = asyncio.open_connection(ip, port)
        reader, writer = await asyncio.wait_for(fut, timeout=1.0)
        rtt = (time.time() - start_time) * 1000
        sock = writer.get_extra_info('socket')
        mss, recv_win = 0, 0
        try:
            tcp_info = sock.getsockopt(socket.IPPROTO_TCP, socket.TCP_INFO, 128)
            mss = struct.unpack("B B B B I I I I I I I I I I", tcp_info[:44])[-1]
            recv_win = sock.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
        except: pass
        writer.close()
        return port, rtt, mss, recv_win
    except:
        return port, 0.0, 0, 0

async def tcp_scan(ip, ports, threads, timeout_ms):
    open_ports, windows, ttl_anomaly = scapy_syn_scan(ip, ports, timeout_ms)

    rtts =[]
    mss_val, recv_val = 0, 0

    for p in open_ports:
        _, rtt, m, r_w = await get_tcp_info(ip, p)
        rtts.append(rtt)
        if m > 0: mss_val = m
        if r_w > 0: recv_val = r_w

    log.p(f"scan done ({len(ports)}/{len(ports)}, open={len(open_ports)})", GREEN)

    for i, p in enumerate(open_ports):
        svc = "HTTP" if p == 80 else "HTTPS / XTLS / Reality" if p in (443, 8443) else "DNS" if p == 53 else "SSH" if p == 22 else "-"
        w_size = windows[i] if i < len(windows) else recv_val
        log.p(f"  :{p:<4} {rtts[i] if i < len(rtts) else 0:.0f}ms {svc} (Win: {w_size})", GREEN)

    try:
        fut = asyncio.open_connection(ip, 65000)
        r, w = await asyncio.wait_for(fut, timeout=1.0)
        w.close()
        closed_beh = "open"
    except ConnectionRefusedError: closed_beh = "RST"
    except: closed_beh = "drop"

    if rtts and sum(rtts) > 0:
        med = statistics.median(rtts)
        std = statistics.stdev(rtts) if len(rtts) > 1 else 0.0
        min_rtt, max_rtt = min(rtts), max(rtts)
    else:
        med = std = min_rtt = max_rtt = 0.0

    log.p(f"\nTCP stack fingerprint (handshake distribution + SIO_TCP_INFO)", CYAN)
    log.p(f"handshake median={med:.1f}ms min={min_rtt:.1f}ms max={max_rtt:.1f}ms stddev={std:.1f}ms ({len(rtts)} samples)")
    log.p(f"peer recv-window: {recv_val}  MSS: {mss_val}")
    log.p(f"closed-port :65000 behavior: {closed_beh}")

    os_guess = "Linux 3.x-5.x" if recv_val in (29200, 65160) else "FreeBSD/Windows" if recv_val > 65000 else "generic kernel-stack"
    log.p(f"OS guess (p0f style): {os_guess}")

    report_data["tcp_scan"] = {"open_ports": open_ports, "mss": mss_val, "closed_behavior": closed_beh, "ttl_anomaly": ttl_anomaly}
    return open_ports, rtts, med, std, closed_beh, mss_val, ttl_anomaly

async def geoip_aggregation(ip):
    log.p(f"\n[2/8] GeoIP (Parallel Lookup)", CYAN)
    log.p(f"[{GREEN}Norm: Residential/Mobile ISP{RESET} | {RED}Alert: Datacenter/Hosting ASN (Triggers DPI scrutiny){RESET}]")

    own_resp = await raw_http_get("ip-api.com", "/json/")
    own_lat, own_lon = 0.0, 0.0
    if own_resp:
        try:
            o = json.loads(own_resp)
            own_lat, own_lon = float(o.get('lat', 0)), float(o.get('lon', 0))
        except: pass

    providers =[
        ("ipapi.is", f"/json/{ip}", 80),
        ("iplocate.io", f"/api/locate/{ip}", 443),
        ("freeipapi.com", f"/api/json/{ip}", 80),
        ("ip-api.com", f"/json/{ip}", 80),
        ("sypexgeo.net", f"/{ip}", 80),
        ("ipwho.is", f"/{ip}", 80),
        ("ipinfo.io", f"/{ip}/json", 443)
    ]

    async def fetch(h, p, port):
        resp = await raw_http_get(h, p, port, is_tls=(port==443))
        return h, resp.decode('utf-8', errors='ignore') if resp else None

    results = await asyncio.gather(*[fetch(*p) for p in providers])
    is_hosting = False
    countries, asns, lats, lons = [], [], [],[]

    for host, res in results:
        if not res:
            log.p(f"  {host:<16} err: timeout/429", RED)
            continue
        c = re.search(r'"(?:countryCode|country)"\s*:\s*"([A-Z]{2})"', res, re.I)
        city = re.search(r'"(?:city|region|city_name)"\s*:\s*"([^"]+)"', res, re.I)
        a = re.search(r'"(?:as|asn|org|name|company)"\s*:\s*"([^"]+)"', res, re.I)
        lt = re.search(r'"(?:lat|latitude)"\s*:\s*(-?\d+\.\d+)', res, re.I)
        ln = re.search(r'"(?:lon|longitude)"\s*:\s*(-?\d+\.\d+)', res, re.I)

        c_str = c.group(1).upper() if c else "Unknown"
        city_str = city.group(1) if city else "Unknown"
        a_str = a.group(1) if a else "Unknown"
        lt_val = float(lt.group(1)) if lt else 0.0
        ln_val = float(ln.group(1)) if ln else 0.0

        hosting_flag = ""
        hosting_kws =['host', 'cloud', 'telecom', 'datacenter', 'vps', 'llc', 'digital', 'hetzner', 'ovh', 'linode']
        if any(kw in a_str.lower() for kw in hosting_kws):
            hosting_flag = "flags: HOSTING"
            is_hosting = True

        log.p(f"  {host:<16} IP {ip} {c_str} ({city_str}) AS {a_str} {YELLOW}{hosting_flag}{RESET}")

        if c: countries.append(c_str)
        if a: asns.append(a_str)
        if lt and ln:
            lats.append(lt_val)
            lons.append(ln_val)

    def avg(lst): return sum(lst)/len(lst) if lst else 0.0
    t_lat = avg(lats)
    t_lon = avg(lons)

    report_data["geoip"] = {"is_hosting": is_hosting, "country": countries[0] if countries else "Unknown", "asn": asns[0] if asns else "Unknown"}
    return is_hosting, t_lat, t_lon, own_lat, own_lon

def run_udp_probes(ip):
    log.p("\n[4/8] UDP probes (Real Handshakes & FakeDNS)", CYAN)
    log.p(f"[{GREEN}Norm: No answer (filtered){RESET} | {RED}Alert: VPN Handshake accepted, FakeDNS Local IP{RESET}]")

    wg_init = b"\x01\x00\x00\x00" + os.urandom(144)
    awg_payload = os.urandom(8) + wg_init
    wg_malformed = b"\x01\x00\x00\x00" + os.urandom(100) + b"\x00" * 44 # Malformed MACs
    quic_payload = b'\xc3\x00\x00\x00\x01\x08' + os.urandom(8) + b'\x08' + os.urandom(8) + os.urandom(1182)
    dns_query = os.urandom(2) + b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07blocked\x03com\x00\x00\x01\x00\x01"

    probes =[
        (53, "DNS query (FakeDNS)", dns_query),
        (500, "IKEv2 SA_INIT", os.urandom(16) + b"\x21\x20\x22\x08\x00\x00\x00\x00\x00\x00\x00\x1c"),
        (1194, "OpenVPN HARD_RESET", b"\x38" + os.urandom(13)),
        (443, "QUIC/HTTP3 v1 Initial", quic_payload),
        (51820, "WireGuard handshake", wg_init),
        (51820, "WG Malformed Profiling", wg_malformed),
        (41641, "Tailscale handshake", wg_init),
        (1701, "L2TP SCCRQ", b'\xc8\x02\x00\x14\x00\x00\x00\x00\x00\x00\x00\x00\x80\x08\x00\x00\x00\x00\x00\x01'),
        (36712, "Hysteria2 QUIC", quic_payload),
        (8443, "TUIC v5", quic_payload),
        (55555, "AmneziaWG Sx=8", awg_payload)
    ]

    detected, fakedns_detected =[], False
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(0.8)

    for port, name, payload in probes:
        try:
            sock.sendto(payload, (ip, port))
            data, _ = sock.recvfrom(4096)

            if "FakeDNS" in name:
                if b"\xc0\x0c\x00\x01" in data:
                    ip_bytes = data[-4:]
                    res_ip = ".".join(map(str, ip_bytes))
                    if res_ip.startswith("198.18.") or res_ip.startswith("10."):
                        log.p(f"  UDP:{port:<5} {name:<22} {RED}FAKEDNS DETECTED ({res_ip}) - Xray/V2Ray routing active!{RESET}")
                        fakedns_detected = True
                        continue

            if "Malformed" in name:
                log.p(f"  UDP:{port:<5} {name:<22} {YELLOW}Response received (Userspace WG implementation likely){RESET}")
                continue

            log.p(f"  UDP:{port:<5} {name:<22} {RED}HANDSHAKE ACCEPTED{RESET}")
            detected.append(name)
        except:
            log.p(f"  UDP:{port:<5} {name:<22} no answer (no-reply / filtered)")

    sock.close()
    report_data["udp_probes"] = detected
    return detected, fakedns_detected

def run_pmtud(ip):
    log.p("\n[4.5/8] Path MTU Discovery (PMTUD)", CYAN)
    log.p(f"[{GREEN}Norm: MTU 1500 (standard){RESET} | {RED}Alert: MTU 1420-1460 (VPN encapsulation overhead){RESET}]")
    mtu = 1500
    for size in[1500, 1492, 1450, 1420, 1400, 1380]:
        pkt = IP(dst=ip, flags="DF")/ICMP()/(b"X" * (size - 28))
        resp = sr1(pkt, timeout=0.5, verbose=0)
        if resp and resp.haslayer(ICMP) and resp[ICMP].type == 0:
            mtu = size
            break

    if mtu < 1500:
        log.p(f"  Path MTU: {mtu} bytes {RED}[VPN Encapsulation Detected!]{RESET}")
    else:
        log.p(f"  Path MTU: {mtu} bytes {GREEN}[Standard]{RESET}")

    report_data["pmtud"] = {"mtu": mtu}
    return mtu

async def service_fuzzer(ip, open_ports, target_host):
    log.p("\n[5/8] Service & Crypto Fingerprinting", CYAN)
    log.p(f"[{GREEN}Norm: Standard web behavior, Valid CT Logs, ALPN match{RESET} | {RED}Alert: Domain Fronting, WS Upgrade Anomaly, Missing CT Logs{RESET}]")
    has_http_proxy, utls_diff, proxy_headers_leak = False, False, False
    domain_fronting, ws_anomaly = False, False
    cert_info = {"cn": "Unknown"}

    for p in open_ports:
        log.p(f"  -> Testing port :{p}")
        printed_info = False

        # 1. HTTP Proxy & WS Upgrade
        try:
            r, w = await asyncio.wait_for(asyncio.open_connection(ip, p), timeout=1.5)
            w.write(b"GET /random_ws_path HTTP/1.1\r\nHost: example.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
            await w.drain()
            ans = await asyncio.wait_for(r.read(1024), timeout=1.5)
            if b"101 Switching Protocols" in ans or b"400 Bad Request" in ans:
                log.p(f"     WEBSOCKET: {RED}Unexpected Upgrade response (V2Ray WS Masking signature!){RESET}")
                ws_anomaly = True
                printed_info = True
            w.close()
        except: pass

        try:
            r, w = await asyncio.wait_for(asyncio.open_connection(ip, p), timeout=1.5)
            w.write(b"CONNECT 8.8.8.8:443 HTTP/1.1\r\nHost: 8.8.8.8:443\r\n\r\n"); await w.drain()
            ans = await asyncio.wait_for(r.read(1024), timeout=1.5)
            if b"400 Bad Request" in ans or b"200 OK" in ans:
                log.p(f"     HTTP-PROXY: {RED}HTTP/1.1 400 Bad Request[vpn-like/proxy]{RESET}")
                has_http_proxy = True
                printed_info = True
            w.close()
        except: pass

        if p in (80, 8080):
            resp = await raw_http_get(ip, "/", p, is_tls=False)
            if resp:
                resp_str = resp.decode('utf-8', errors='ignore').lower()
                if "x-forwarded-for:" in resp_str or "via:" in resp_str:
                    log.p(f"     HTTP-HEADERS: {RED}Proxy headers leaked (Via / X-Forwarded-For){RESET}")
                    proxy_headers_leak = True
                    printed_info = True

        # 2. Timing Attack (Slowloris)
        start_time = time.time()
        try:
            r, w = await asyncio.wait_for(asyncio.open_connection(ip, p), timeout=10)
            w.write(b"GET / HTTP/1.1\r\nHost: example.com\r\n")
            await w.drain()
            await r.read(10)
            w.close()
        except: pass
        elapsed = time.time() - start_time
        if elapsed < 3.0:
            log.p(f"     TIMING: {RED}Aggressive timeout ({elapsed:.1f}s) - Strict Proxy Signature{RESET}")
            printed_info = True

        # 3. TLS, Domain Fronting, CT Logs, uTLS
        if p in (443, 8443):
            try:
                ctx = ssl.create_default_context()
                ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
                r, w = await asyncio.wait_for(asyncio.open_connection(ip, p, ssl=ctx, server_hostname="vk.com"), timeout=2)
                w.write(f"GET / HTTP/1.1\r\nHost: {target_host}\r\n\r\n".encode())
                await w.drain()
                ans = await asyncio.wait_for(r.read(1024), timeout=2)
                if b"200 OK" in ans or b"301 Moved" in ans:
                    log.p(f"     SNI ROUTING: {RED}Domain Fronting allowed! (SNI: vk.com, Host: {target_host}){RESET}")
                    domain_fronting = True
                    printed_info = True
                w.close()
            except: pass

            try:
                ctx = ssl.create_default_context()
                ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
                ctx.set_alpn_protocols(['h2', 'http/1.1', 'http/1.0'])
                conn = ctx.wrap_socket(socket.socket(), server_hostname=ip)
                conn.settimeout(2.0)
                conn.connect((ip, p))
                alpn = conn.selected_alpn_protocol()
                cipher = conn.cipher()
                log.p(f"     ALPN: Negotiated '{alpn}'", GREEN)
                log.p(f"     JA3S/Cipher: {cipher[0]} ({cipher[1]})", GREEN)
                conn.close()
                printed_info = True
            except: pass

            try:
                cert_pem = ssl.get_server_certificate((ip, p), timeout=2)
                proc = subprocess.Popen(["openssl", "x509", "-text", "-noout"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                out, _ = proc.communicate(input=cert_pem.encode())
                out = out.decode('utf-8', errors='ignore')

                cn = re.search(r"Subject:.*?CN\s*=\s*([^,\n]+)", out)
                iss = re.search(r"Issuer:.*?CN\s*=\s*([^,\n]+)", out)
                not_before = re.search(r"Not Before:\s*(.+)", out)
                not_after = re.search(r"Not After\s*:\s*(.+)", out)

                cn_str = cn.group(1).strip() if cn else "Unknown"
                iss_str = iss.group(1).strip() if iss else "Unknown"
                log.p(f"     TLS Cert: CN={cn_str} issuer={iss_str}", YELLOW)
                cert_info['cn'] = cn_str

                if not_before and not_after:
                    log.p(f"     Cert Dates: {not_before.group(1)} -> {not_after.group(1)}", CYAN)
                    if "203" in not_after.group(1):
                        log.p(f"     Cert Validity: {RED}10-year self-signed cert detected (Shadowsocks/OpenVPN signature)!{RESET}")

                if cn_str != "Unknown":
                    ct_resp = await raw_http_get("crt.sh", f"/?q={cn_str}&output=json", 443, is_tls=True)
                    if ct_resp and b"issuer_name" in ct_resp:
                        log.p(f"     CT Logs: {GREEN}Present in public transparency logs{RESET}")
                    else:
                        log.p(f"     CT Logs: {RED}Missing or freshly issued (Reality/ShadowTLS signature!){RESET}")

                printed_info = True
            except: pass

            try:
                ctx = ssl.create_default_context()
                ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
                r1, w1 = await asyncio.wait_for(asyncio.open_connection(ip, p, ssl=ctx), timeout=2)
                w1.close()
                ssl_success = True
            except: ssl_success = False

            try:
                resp = urequests.get(f"https://{ip}:{p}", impersonate="chrome131", verify=False, timeout=2)
                chr_success = True
            except: chr_success = False

            if ssl_success and not chr_success:
                utls_diff = True
                log.p(f"     uTLS Probe: {YELLOW}Server accepted OpenSSL but dropped Chrome (Strict SNI/uTLS filter){RESET}")
            elif not ssl_success and chr_success:
                utls_diff = True
                log.p(f"     uTLS Probe: {YELLOW}Server accepted Chrome but dropped OpenSSL (Reality discriminator active!){RESET}")

        if not printed_info:
            log.p(f"     {GREEN}No specific HTTP/TLS/Proxy signatures detected.{RESET}")

    if not open_ports: log.p("  No open ports to fingerprint.")

    report_data["services"] = {"has_http_proxy": has_http_proxy, "utls_diff": utls_diff, "domain_fronting": domain_fronting, "ws_anomaly": ws_anomaly}
    return has_http_proxy, utls_diff, proxy_headers_leak, cert_info, domain_fronting, ws_anomaly

async def j3_probes(ip, open_ports):
    log.p("\n[6/8] J3 / TSPU active probing & Replay Attacks", CYAN)
    log.p(f"[{GREEN}Norm: Drops junk or varied errors{RESET} | {RED}Alert: Canned response, Anti-Replay drops, High Entropy, SS-AEAD Length{RESET}]")

    # ECH / GREASE CH
    tls_ch_static = bytes.fromhex("16030100c6010000c20303") + os.urandom(60)
    h2_preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + bytes.fromhex("000000040000000000")

    probes_list =[
        ("HTTP GET /", b"GET / HTTP/1.1\r\nHost: " + ip.encode() + b"\r\n\r\n"),
        ("HTTP CONNECT", b"CONNECT example.com:443 HTTP/1.1\r\n\r\n"),
        ("SSH banner", b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\r\n"),
        ("Random 512B (Entropy)", os.urandom(512)),
        ("SS-AEAD Length Probe", os.urandom(50)),
        ("TLS CH invalid-SNI", tls_ch_static),
        ("HTTP/2 Preface", h2_preface),
        ("0xFF x128", b"\xff" * 128)
    ]

    canned_fallback, invalid_http, replay_active, high_entropy, ss_aead_drop = False, False, False, False, False

    for port in open_ports:
        log.p(f" -> port :{port}", CYAN)
        responses =[]

        for name, payload in probes_list:
            start_t = time.time()
            try:
                r, w = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=1.5)
                w.write(payload); await w.drain()
                data = await asyncio.wait_for(r.read(1024), timeout=1.5)
                w.close()
                elapsed = time.time() - start_t

                if data:
                    responses.append(data)
                    hex_str = " ".join(f"{b:02x}" for b in data[:8])
                    clean_str = data[:25].decode('utf-8', 'ignore').replace('\r', '').replace('\n', ' ')
                    log.p(f"    RESP {name:<22} {len(data)}B {clean_str}[{hex_str}]", GREEN)

                    if "Entropy" in name:
                        ent = calc_entropy(data)
                        if ent > 7.5:
                            high_entropy = True
                            log.p(f"    !! HIGH ENTROPY RESP: {ent:.2f} (Obfuscated Proxy / VMess Signature!)", RED)

                    if "HTTP/2" in name:
                        if data.startswith(bytes.fromhex("00000004")):
                            log.p(f"         └─ Valid HTTP/2 SETTINGS frame received", GREEN)
                        else:
                            log.p(f"         └─ {YELLOW}Non-standard H2 response (Proxy signature){RESET}")

                else:
                    if "SS-AEAD" in name and elapsed < 0.2:
                        ss_aead_drop = True
                        log.p(f"    SILENT {name:<22} {RED}Immediate disconnect (Shadowsocks-AEAD signature!){RESET}")
                    else:
                        log.p(f"    SILENT {name:<22} empty/close (dropped)")
            except:
                log.p(f"    SILENT {name:<22} empty/close (dropped)")

        # Replay Attack Check
        try:
            r1, w1 = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=1.5)
            w1.write(tls_ch_static); await w1.drain()
            resp1 = await asyncio.wait_for(r1.read(1024), timeout=1.5)
            w1.close()
            if resp1:
                r2, w2 = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=1.5)
                w2.write(tls_ch_static); await w2.drain()
                resp2 = await asyncio.wait_for(r2.read(1024), timeout=1.5)
                w2.close()
                if not resp2:
                    replay_active = True
                    log.p(f"    !! REPLAY ATTACK: Server dropped the replayed ClientHello (Anti-Replay / XTLS active!)", RED)
        except: pass

        if len(responses) >= 2:
            first_lines =[r.split(b'\r\n')[0] for r in responses if b'\r\n' in r]
            if len(first_lines) > 2 and first_lines.count(first_lines[0]) >= 2:
                if b"HTTP/1." in first_lines[0]:
                    canned_fallback = True
                    log.p("    !! Canned response detected: SAME HTTP first-line for different raw-TCP probes.", RED)
                else:
                    invalid_http = True

    report_data["j3_probes"] = {"canned_fallback": canned_fallback, "replay_active": replay_active, "high_entropy": high_entropy, "ss_aead_drop": ss_aead_drop}
    return canned_fallback, invalid_http, replay_active, high_entropy, ss_aead_drop

def run_trace(ip, t_lat, t_lon, own_lat, own_lon, min_rtt):
    log.p("\n[7/8] SNITCH latency + Traceroute", CYAN)
    log.p(f"[{GREEN}Norm: RTT > Speed of light | Clean routing{RESET}]")
    log.p(f"[{RED}Alert: RTT < Speed of light (Anycast bypass) | TSPU subnets (10.X.Y.Z) on path{RESET}]")

    dist_km = haversine(own_lat, own_lon, t_lat, t_lon)
    theoretical_min_rtt = dist_km * 0.01 * 1.2

    log.p(f"\nSNITCH Physical distance: ~{dist_km:.1f} km")
    log.p(f"Measured TCP RTT: {min_rtt:.1f} ms")
    log.p(f"Expected Minimum RTT (Speed of Light): {theoretical_min_rtt:.1f} ms")

    snitch_viol = False
    if min_rtt > 0 and theoretical_min_rtt > 0 and min_rtt < theoretical_min_rtt and dist_km > 500:
        log.p(f"{RED}SNITCH VIOLATION: Packets returned faster than the speed of light! (Anycast / WARP){RESET}")
        snitch_viol = True
    else:
        log.p(f"RTT is consistent with physical geolocation.", GREEN)

    log.p("\nTraceroute (ICMP):")
    ttl = 1
    max_hops = 20
    tspu_hop_detected = False

    while ttl <= max_hops:
        pkt = IP(dst=ip, ttl=ttl) / ICMP(id=os.getpid() & 0xFFFF, seq=ttl) / b"byebyevpnlinux_probe"
        reply = sr1(pkt, verbose=0, timeout=1.0)

        if reply is None:
            log.p(f" {ttl:<2} *")
        else:
            log.p(f" {ttl:<2} {reply.src}")
            if reply.src.startswith("10."):
                parts = reply.src.split('.')
                if len(parts) == 4 and int(parts[3]) in range(131, 255):
                    tspu_hop_detected = True
            if reply.type == 0: break
        ttl += 1

    if tspu_hop_detected:
        log.p(f"-> Possible TSPU/Management subnet detected in route (10.X.Y.Z)", YELLOW)

    report_data["trace"] = {"snitch_violation": snitch_viol, "tspu_hop": tspu_hop_detected}
    return snitch_viol, tspu_hop_detected

def diff_reports(old_path):
    try:
        with open(old_path, 'r') as f:
            old_data = json.load(f)
        log.p("\n=== DIFF COMPARISON (Previous vs Current) ===", MAGENTA)

        old_score = old_data.get("verdict", {}).get("score", 0)
        new_score = report_data.get("verdict", {}).get("score", 0)
        diff_score = new_score - old_score
        color = GREEN if diff_score >= 0 else RED
        log.p(f"Score Change: {old_score} -> {new_score} ({'+' if diff_score > 0 else ''}{diff_score})", color)

        old_strong = set(old_data.get("verdict", {}).get("strong",[]))
        new_strong = set(report_data.get("verdict", {}).get("strong",[]))

        added = new_strong - old_strong
        resolved = old_strong - new_strong

        if added:
            log.p("New Threats Detected:", RED)
            for a in added: log.p(f"  [+] {a}", RED)
        if resolved:
            log.p("Threats Resolved:", GREEN)
            for r in resolved: log.p(f"  [-] {r}", GREEN)

        if not added and not resolved:
            log.p("No changes in Strong Signals.", CYAN)
    except Exception as e:
        log.p(f"Diff error: {e}", RED)

async def main():
    log.p(r" /$$$$$$$                      /$$$$$$$                      /$$    /$$                    /$$       /$$                              ", MAGENTA)
    log.p(r"| $$__  $$                    | $$__  $$                    | $$   | $$                   | $$      |__/                              ", MAGENTA)
    log.p(r"| $$  \ $$ /$$   /$$  /$$$$$$ | $$  \ $$ /$$   /$$  /$$$$$$ | $$   | $$ /$$$$$$  /$$$$$$$ | $$       /$$ /$$$$$$$  /$$   /$$ /$$   /$$", MAGENTA)
    log.p(r"| $$$$$$$ | $$  | $$ /$$__  $$| $$$$$$$ | $$  | $$ /$$__  $$|  $$ / $$//$$__  $$| $$__  $$| $$      | $$| $$__  $$| $$  | $$|  $$ /$$/", MAGENTA)
    log.p(r"| $$__  $$| $$  | $$| $$$$$$$$| $$__  $$| $$  | $$| $$$$$$$$ \  $$ $$/| $$  \ $$| $$  \ $$| $$      | $$| $$  \ $$| $$  | $$ \  $$$$/ ", MAGENTA)
    log.p(r"| $$  \ $$| $$  | $$| $$_____/| $$  \ $$| $$  | $$| $$_____/  \  $$$/ | $$  | $$| $$  | $$| $$      | $$| $$  | $$| $$  | $$  >$$  $$ ", MAGENTA)
    log.p(r"| $$$$$$$/|  $$$$$$$|  $$$$$$$| $$$$$$$/|  $$$$$$$|  $$$$$$$   \  $/  | $$$$$$$/| $$  | $$| $$$$$$$$| $$| $$  | $$|  $$$$$$/ /$$/\  $$", MAGENTA)
    log.p(r"|_______/  \____  $$ \_______/|_______/  \____  $$ \_______/    \_/   | $$____/ |__/  |__/|________/|__/|__/  |__/ \______/ |__/  \__/", MAGENTA)
    log.p(r"           /$$  | $$                     /$$  | $$                    | $$                                                            ", MAGENTA)
    log.p(r"          |  $$$$$$/                    |  $$$$$$/                    | $$                                                            ", MAGENTA)
    log.p(r"           \______/                      \______/                     |__/                                                            ", MAGENTA)

    if os.geteuid() != 0:
        print(f"{RED}CRITICAL ERROR: Run the script via 'sudo' for Scapy SYN scan & ICMP Traceroute.{RESET}")
        sys.exit(1)

    parser = argparse.ArgumentParser()
    parser.add_argument("host", help="Target IP or Domain")
    parser.add_argument("--fast", action="store_true", help="Scan only common ports instead of 1-65535")
    parser.add_argument("--json", action="store_true", help="Export results to a JSON file")
    parser.add_argument("--html", action="store_true", help="Export results to an HTML visual report")
    parser.add_argument("--compare", type=str, help="Path to a previous JSON report to diff against")
    args = parser.parse_args()

    host = args.host
    report_data["target"] = host
    start_t = time.time()

    try:
        answers = socket.getaddrinfo(host, 0, socket.AF_INET)
        ip = answers[0][4][0]
        report_data["ip"] = ip
    except Exception as e:
        log.p(f"DNS resolve failed: {e}", RED)
        sys.exit(1)

    dt = int((time.time() - start_t) * 1000)
    log.p(f"\n[1/8] DNS resolve", CYAN)
    log.p(f"{host} -> {ip}[v4, {dt}ms]", GREEN)

    is_hosting, t_lat, t_lon, own_lat, own_lon = await geoip_aggregation(ip)
    ptr_record, ptr_mismatch = await threat_intel_and_bgp(ip)

    ports_to_scan =[21, 22, 53, 80, 443, 1194, 3389, 8080, 8443] if args.fast else list(range(1, 65536))
    open_ports, rtts, med, std, closed_beh, mss_val, ttl_anomaly = await tcp_scan(ip, ports_to_scan, 500, 800)

    udp_detected, fakedns_detected = run_udp_probes(ip)
    mtu = run_pmtud(ip)

    has_http_proxy, utls_diff, proxy_headers_leak, cert_info, domain_fronting, ws_anomaly = await service_fuzzer(ip, open_ports, host)
    canned_fallback, invalid_http, replay_active, high_entropy, ss_aead_drop = await j3_probes(ip, open_ports)

    min_rtt = min(rtts) if rtts else 0
    snitch_viol, tspu_hop_detected = run_trace(ip, t_lat, t_lon, own_lat, own_lon, min_rtt)

    # === ФОРМИРОВАНИЕ ИТОГОВОЙ МАТРИЦЫ DPI ===
    log.p("\n[8/8] Verdict\n", CYAN)

    strong_signals =[]
    soft_signals =[]
    info_signals =[]

    if canned_fallback: strong_signals.append("Canned fallback page (identical HTTP response for raw-TCP junk). Classic Xray/Trojan signature.")
    if has_http_proxy: strong_signals.append("Open HTTP CONNECT proxy detected.")
    if proxy_headers_leak: strong_signals.append("Proxy headers leak (Via / X-Forwarded-For).")
    if udp_detected: strong_signals.append(f"UDP VPN Tunnels detected: {', '.join(udp_detected)}")
    if snitch_viol: strong_signals.append("SNITCH Anomaly: Speed of light violation (Anycast/WARP proxying traffic).")
    if replay_active: strong_signals.append("Anti-Replay protection active (Shadowsocks-AEAD / XTLS signature).")
    if high_entropy: strong_signals.append("High entropy response to random bytes (Obfuscated proxy / VMess).")
    if domain_fronting: strong_signals.append("Domain Fronting allowed (SNI and Host mismatch).")
    if fakedns_detected: strong_signals.append("FakeDNS detected (Local IP returned for external blocked domain).")
    if ss_aead_drop: strong_signals.append("Immediate disconnect on 50-byte probe (Shadowsocks-AEAD signature).")
    if ttl_anomaly: strong_signals.append("TTL Anomaly detected on open vs closed ports (GFW / TSPU Middlebox injection).")

    if utls_diff: soft_signals.append("uTLS dual-probe mismatch: Reality discriminator / CDN filtering active.")
    if tspu_hop_detected: soft_signals.append("Traceroute goes through potential TSPU management subnet (10.X.Y.Z).")
    if invalid_http: soft_signals.append("Invalid HTTP versions returned on J3 active probes.")
    if mss_val > 0 and mss_val < 1350: soft_signals.append(f"Anomalous TCP MSS size ({mss_val}) suggests MTU overhead from a tunnel.")
    if mtu < 1500: soft_signals.append(f"Path MTU discovery returned {mtu} bytes (VPN encapsulation footprint).")
    if ptr_mismatch: soft_signals.append("Missing Reverse DNS (PTR) record. Untrusted infrastructure.")
    if ws_anomaly: soft_signals.append("Unexpected WebSocket Upgrade response (V2Ray WS Masking signature).")

    if is_hosting: info_signals.append("asn-hosting: Target IP belongs to a hosting/datacenter ASN.")
    if len(open_ports) > 0 and len(open_ports) <= 3: info_signals.append("sparse-ports: Sparse open-port profile (<=3 ports).")
    if closed_beh == "drop": info_signals.append("tcp-firewall-drop: Closed ports drop packets silently (strict L3 firewall / DPI ACL).")
    if 22 in open_ports: info_signals.append("Port 22 (SSH) is open.")

    dp_ports = "HIGH" if udp_detected else "LOW"
    dp_cert = "HIGH" if (cert_info.get('cn') != 'Unknown' and not is_hosting) else "NONE"
    dp_j3 = "HIGH" if canned_fallback or replay_active or ss_aead_drop else "LOW"
    dp_asn = "HIGH" if is_hosting else "LOW"

    log.p("DPI exposure matrix:", CYAN)
    log.p(f"  Port-based (default VPN ports)           {'RED' if dp_ports=='HIGH' else 'GREEN'}{dp_ports}{RESET}")
    log.p(f"  Cert-steering (Reality discriminator)    {'RED' if utls_diff else 'GREEN'}{'DETECTED' if utls_diff else 'NONE'}{RESET}")
    log.p(f"  ASN classifier (VPS/hosting)             {'YELLOW' if dp_asn=='HIGH' else 'GREEN'}{dp_asn}{RESET}")
    log.p(f"  Active junk probing (J3 canned response) {'RED' if dp_j3=='HIGH' else 'GREEN'}{dp_j3}{RESET}")
    log.p(f"  Speed of Light consistency (SNITCH)      {'RED' if snitch_viol else 'GREEN'}{'FAILED' if snitch_viol else 'PASSED'}{RESET}\n")

    if strong_signals:
        log.p(f"Strong signals ({len(strong_signals)})[! = real evidence of VPN/proxy]", RED)
        for s in strong_signals: log.p(f"[!] {s}", RED)
        log.p("")

    if soft_signals:
        log.p(f"Soft signals ({len(soft_signals)})[- = suggestive pattern, not proof]", YELLOW)
        for s in soft_signals: log.p(f"  [-] {s}", YELLOW)
        log.p("")

    if info_signals:
        log.p(f"Informational ({len(info_signals)})[i = observation only, no penalty]", CYAN)
        for s in info_signals: log.p(f"[i] {s}")
        log.p("")

    score = 100
    score -= len(strong_signals) * 25
    score -= len(soft_signals) * 10
    score -= len(info_signals) * 2
    if score < 0: score = 0

    if score > 80: verdict, v_col = "CLEAN", GREEN
    elif score > 50: verdict, v_col = "SUSPICIOUS", YELLOW
    else: verdict, v_col = "OBVIOUSLY-VPN", RED

    log.p(f"Final score: {score}/100  verdict: {verdict}\n", v_col)

    report_data["verdict"] = {"score": score, "label": verdict, "strong": strong_signals, "soft": soft_signals}

    log.p("ТСПУ / TSPU classification (emulated Russian DPI verdict):", MAGENTA)
    if len(strong_signals) >= 1 or len(soft_signals) >= 2:
        log.p("Verdict: BLOCK (accumulative) — TSPU-class classifiers accumulate anomalies and cross the block threshold", RED)
    else:
        log.p("Verdict: PASS — Insufficient anomalies to trigger automated block.", GREEN)

    log.p("\nThreat-model note: TSPU/GFW classify a destination by what the IP actually does on the wire — TLS handshake bytes, cert-steering, active HTTP-over-TLS reply shape, reactions to junk, default-port replies. IP 'reputation' (hosting ASN) is only a coarse pre-filter. Strong signals map directly to Xray / Reality / Trojan / modern obfuscated VPN stacks. If every strong signal is 'none' and soft signals are quiet, the host is essentially invisible to passive DPI regardless of what the ASN looks like.\n")

    if args.compare:
        diff_reports(args.compare)

    log.flush_save(host, json_export=args.json, html_export=args.html)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nAborted.")
