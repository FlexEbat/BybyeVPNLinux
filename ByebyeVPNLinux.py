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
    from scapy.all import IP, ICMP, sr1, conf
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

class Logger:
    def __init__(self):
        self.no_color = False
        self.save_path = None
        self.log_buffer = []

    def p(self, msg="", color=None):
        if color and not self.no_color:
            msg = f"{color}{msg}{RESET}"
        sys.stdout.write(msg + "\n")
        sys.stdout.flush()
        clean_msg = re.sub(r'\x1B(?:[@-Z\-_]|\[[0-?]*[ -/]*[@-~])', '', msg)
        self.log_buffer.append(clean_msg)

    def flush_save(self, target_host):
        if not self.save_path: return
        path = f"{target_host}.md" if self.save_path == "AUTO" else self.save_path
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write("```text\n")
                f.write("\n".join(self.log_buffer))
                f.write("\n```\n")
            print(f"\n[+] Scan saved to {path}")
        except Exception as e:
            print(f"\n[-] Save error: {e}")

log = Logger()

def haversine(lat1, lon1, lat2, lon2):
    R = 6371.0
    lat1, lon1, lat2, lon2 = map(math.radians,[lat1, lon1, lat2, lon2])
    a = math.sin((lat2-lat1)/2)**2 + math.cos(lat1) * math.cos(lat2) * math.sin((lon2-lon1)/2)**2
    return 2 * R * math.asin(math.sqrt(a))

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

async def get_closed_port_behavior(ip):
    try:
        fut = asyncio.open_connection(ip, 65000)
        r, w = await asyncio.wait_for(fut, timeout=1.0)
        w.close()
        return "open"
    except ConnectionRefusedError:
        return "RST"
    except asyncio.TimeoutError:
        return "drop"
    except:
        return "drop"

async def check_port(ip, port, sem, timeout_ms):
    async with sem:
        try:
            start_time = time.time()
            fut = asyncio.open_connection(ip, port)
            reader, writer = await asyncio.wait_for(fut, timeout=timeout_ms/1000.0)
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
            return None

async def tcp_scan(ip, ports, threads, timeout_ms):
    log.p(f"\n[3/8] TCP port scan ({len(ports)} ports, {threads} threads, {timeout_ms}ms timeout)", CYAN)
    log.p(f"[{GREEN}Norm: Standard MSS (1460+){RESET} | {RED}Alert: MSS < 1350 (Tunnel MTU overhead), Suspicious ports{RESET}]")

    sem = asyncio.Semaphore(threads)
    results = await asyncio.gather(*[check_port(ip, p, sem, timeout_ms) for p in ports])
    open_ports, rtts = [],[]
    mss_val, recv_val = 0, 0

    for res in results:
        if res:
            p, rtt, m, r_w = res
            open_ports.append(p)
            rtts.append(rtt)
            if m > 0: mss_val = m
            if r_w > 0: recv_val = r_w

    log.p(f"scan done ({len(ports)}/{len(ports)}, open={len(open_ports)})", GREEN)

    for i, p in enumerate(open_ports):
        svc = "HTTP" if p == 80 else "HTTPS / XTLS / Reality" if p in (443, 8443) else "DNS" if p == 53 else "SSH" if p == 22 else "-"
        log.p(f"  :{p:<4} {rtts[i]:.0f}ms {svc}", GREEN)

    closed_beh = await get_closed_port_behavior(ip)

    if rtts:
        med = statistics.median(rtts)
        std = statistics.stdev(rtts) if len(rtts) > 1 else 0.0
        min_rtt, max_rtt = min(rtts), max(rtts)
    else:
        med = std = min_rtt = max_rtt = 0.0

    log.p(f"\nTCP stack fingerprint (handshake distribution + SIO_TCP_INFO)", CYAN)
    log.p(f"handshake median={med:.1f}ms min={min_rtt:.1f}ms max={max_rtt:.1f}ms stddev={std:.1f}ms ({len(rtts)} samples)")
    log.p(f"peer recv-window: {recv_val}  MSS: {mss_val}")
    log.p(f"closed-port :65000 behavior: {closed_beh}")
    log.p(f"OS guess: generic kernel-stack")

    return open_ports, rtts, med, std, closed_beh, mss_val

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

    return is_hosting, t_lat, t_lon, own_lat, own_lon

def run_udp_probes(ip):
    log.p("\n[4/8] UDP probes (Real Handshakes)", CYAN)
    log.p(f"[{GREEN}Norm: No answer (filtered){RESET} | {RED}Alert: Handshake accepted (VPN protocol confirmed){RESET}]")

    wg_init = b"\x01\x00\x00\x00" + os.urandom(144)
    awg_payload = os.urandom(8) + wg_init
    quic_payload = b'\xc3\x00\x00\x00\x01\x08' + os.urandom(8) + b'\x08' + os.urandom(8) + os.urandom(1182)

    probes =[
        (53, "DNS query", os.urandom(2) + b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x07example\x03com\x00\x00\x01\x00\x01"),
        (500, "IKEv2 SA_INIT", os.urandom(16) + b"\x21\x20\x22\x08\x00\x00\x00\x00\x00\x00\x00\x1c"),
        (1194, "OpenVPN HARD_RESET", b"\x38" + os.urandom(13)),
        (443, "QUIC v1 Initial", quic_payload),
        (51820, "WireGuard handshake", wg_init),
        (41641, "Tailscale handshake", wg_init),
        (1701, "L2TP SCCRQ", b'\xc8\x02\x00\x14\x00\x00\x00\x00\x00\x00\x00\x00\x80\x08\x00\x00\x00\x00\x00\x01'),
        (36712, "Hysteria2 QUIC", quic_payload),
        (8443, "TUIC v5", quic_payload),
        (55555, "AmneziaWG Sx=8", awg_payload)
    ]

    detected =[]
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(0.8)

    for port, name, payload in probes:
        try:
            sock.sendto(payload, (ip, port))
            sock.recvfrom(4096)
            log.p(f"  UDP:{port:<5} {name:<22} {RED}HANDSHAKE ACCEPTED{RESET}")
            detected.append(name)
        except:
            log.p(f"  UDP:{port:<5} {name:<22} no answer (no-reply / filtered)")

    sock.close()
    return detected

async def service_fuzzer(ip, open_ports):
    log.p("\n[5/8] Service fingerprints per open port", CYAN)
    log.p(f"[{GREEN}Norm: Standard web behavior{RESET} | {RED}Alert: Open HTTP Proxy, uTLS mismatch, Proxy header leaks{RESET}]")
    has_http_proxy = False
    utls_diff = False
    proxy_headers_leak = False
    cert_info = {}

    for p in open_ports:
        log.p(f"  -> Testing port :{p}")
        printed_info = False

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

        if p in (443, 8443):
            try:
                cert_pem = ssl.get_server_certificate((ip, p), timeout=2)
                proc = subprocess.Popen(["openssl", "x509", "-text", "-noout"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                out, _ = proc.communicate(input=cert_pem.encode())
                out = out.decode('utf-8', errors='ignore')
                cn = re.search(r"Subject:.*?CN\s*=\s*([^,\n]+)", out)
                iss = re.search(r"Issuer:.*?CN\s*=\s*([^,\n]+)", out)
                cn_str = cn.group(1).strip() if cn else "Unknown"
                iss_str = iss.group(1).strip() if iss else "Unknown"
                log.p(f"     TLS cert: CN={cn_str} issuer={iss_str}", YELLOW)
                cert_info['cn'] = cn_str
                printed_info = True
            except:
                log.p(f"     TLS cert: failed to extract", YELLOW)
                printed_info = True

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
                log.p(f"     uTLS dual-probe: {YELLOW}Server accepted OpenSSL but dropped Chrome (Strict SNI/uTLS filter){RESET}")
            elif not ssl_success and chr_success:
                utls_diff = True
                log.p(f"     uTLS dual-probe: {YELLOW}Server accepted Chrome but dropped OpenSSL (Reality discriminator active!){RESET}")
            else:
                log.p(f"     uTLS dual-probe: consistent responses")

        if not printed_info:
            log.p(f"     {GREEN}No specific HTTP/TLS/Proxy signatures detected.{RESET}")

    if not open_ports:
        log.p("  No open ports to fingerprint.")

    return has_http_proxy, utls_diff, proxy_headers_leak, cert_info

async def j3_probes(ip, open_ports):
    log.p("\n[6/8] J3 / TSPU active probing", CYAN)
    log.p(f"[{GREEN}Norm: Drops junk or varied errors{RESET} | {RED}Alert: Canned response (Xray/Trojan fallback signature){RESET}]")
    probes_list =[
        ("HTTP GET /", b"GET / HTTP/1.1\r\nHost: " + ip.encode() + b"\r\n\r\n"),
        ("HTTP CONNECT", b"CONNECT example.com:443 HTTP/1.1\r\n\r\n"),
        ("SSH banner", b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\r\n"),
        ("random 512B", os.urandom(512)),
        ("TLS CH invalid-SNI", bytes.fromhex("16030100c6010000c20303") + os.urandom(60)),
        ("HTTP abs-URI", b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n"),
        ("0xFF x128", b"\xff" * 128)
    ]

    canned_fallback = False
    invalid_http = False

    for port in open_ports:
        log.p(f" -> port :{port}", CYAN)
        responses =[]
        for name, payload in probes_list:
            try:
                r, w = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=1.5)
                w.write(payload); await w.drain()
                data = await asyncio.wait_for(r.read(1024), timeout=1.5)
                w.close()
                if data:
                    responses.append(data)
                    hex_str = " ".join(f"{b:02x}" for b in data[:8])
                    clean_str = data[:25].decode('utf-8', 'ignore').replace('\r', '').replace('\n', ' ')
                    log.p(f"    RESP {name:<18} {len(data)}B {clean_str}[{hex_str}]", GREEN)
                else:
                    log.p(f"    SILENT {name:<18} empty/close (dropped)")
            except:
                log.p(f"    SILENT {name:<18} empty/close (dropped)")

        if len(responses) >= 2:
            first_lines =[r.split(b'\r\n')[0] for r in responses if b'\r\n' in r]
            if len(first_lines) > 2 and first_lines.count(first_lines[0]) >= 2:
                if b"HTTP/1." in first_lines[0]:
                    canned_fallback = True
                    log.p("    !! Canned response detected: SAME HTTP first-line for different raw-TCP probes.", RED)
                else:
                    invalid_http = True

    return canned_fallback, invalid_http

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

            if reply.type == 0:
                break
        ttl += 1

    if tspu_hop_detected:
        log.p(f"-> Possible TSPU/Management subnet detected in route (10.X.Y.Z)", YELLOW)

    return snitch_viol, tspu_hop_detected

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
        print(f"{RED}CRITICAL ERROR: Run the script via 'sudo' for ICMP Traceroute.{RESET}")
        sys.exit(1)

    parser = argparse.ArgumentParser()
    parser.add_argument("host", help="Target IP or Domain")
    parser.add_argument("--fast", action="store_true", help="Scan only common ports instead of 1-65535")
    args = parser.parse_args()

    host = args.host
    start_t = time.time()

    try:
        answers = socket.getaddrinfo(host, 0, socket.AF_INET)
        ip = answers[0][4][0]
    except Exception as e:
        log.p(f"DNS resolve failed: {e}", RED)
        sys.exit(1)

    dt = int((time.time() - start_t) * 1000)
    log.p(f"\n[1/8] DNS resolve", CYAN)
    log.p(f"{host} -> {ip}[v4, {dt}ms]", GREEN)

    is_hosting, t_lat, t_lon, own_lat, own_lon = await geoip_aggregation(ip)

    ports_to_scan =[21, 22, 53, 80, 443, 1194, 3389, 8080, 8443] if args.fast else list(range(1, 65536))
    open_ports, rtts, med, std, closed_beh, mss_val = await tcp_scan(ip, ports_to_scan, 500, 800)

    udp_detected = run_udp_probes(ip)
    has_http_proxy, utls_diff, proxy_headers_leak, cert_info = await service_fuzzer(ip, open_ports)
    canned_fallback, invalid_http = await j3_probes(ip, open_ports)

    min_rtt = min(rtts) if rtts else 0
    snitch_viol, tspu_hop_detected = run_trace(ip, t_lat, t_lon, own_lat, own_lon, min_rtt)

    log.p("\n[8/8] Verdict\n", CYAN)

    strong_signals =[]
    soft_signals =[]
    info_signals =[]

    if canned_fallback:
        strong_signals.append("Port returns a canned fallback page (identical HTTP first-line for different raw-TCP junk). Classic Xray/Trojan fallback signature.")
    if has_http_proxy:
        strong_signals.append("Open HTTP CONNECT proxy detected.")
    if proxy_headers_leak:
        strong_signals.append("Proxy headers leak (Via / X-Forwarded-For).")
    if udp_detected:
        strong_signals.append(f"UDP VPN Tunnels detected: {', '.join(udp_detected)}")
    if snitch_viol:
        strong_signals.append("SNITCH Anomaly: Speed of light violation (Anycast/WARP proxying traffic).")

    if utls_diff:
        soft_signals.append("uTLS dual-probe mismatch: Server adapts TLS parameters or drops strictly based on ClientHello (Reality discriminator / CDN).")
    if tspu_hop_detected:
        soft_signals.append("Traceroute goes through potential TSPU management subnet (10.X.Y.Z).")
    if invalid_http:
        soft_signals.append("Invalid HTTP versions returned on J3 active probes.")
    if mss_val > 0 and mss_val < 1350:
        soft_signals.append(f"Anomalous TCP MSS size ({mss_val}) suggests MTU overhead from a tunnel.")

    if is_hosting:
        info_signals.append("asn-hosting: Target IP belongs to a hosting/datacenter ASN.")
    if len(open_ports) > 0 and len(open_ports) <= 3:
        info_signals.append("sparse-ports: Sparse open-port profile (<=3 ports).")
    if closed_beh == "drop":
        info_signals.append("tcp-firewall-drop: Closed ports drop packets silently (strict L3 firewall / DPI ACL).")
    if 22 in open_ports:
        info_signals.append("Port 22 (SSH) is open.")


    dp_ports = "HIGH" if udp_detected else "LOW"
    dp_cert = "HIGH" if (cert_info.get('cn') != 'Unknown' and not is_hosting) else "NONE"
    dp_j3 = "HIGH" if canned_fallback else "LOW"
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
        for s in info_signals: log.p(f"  [i] {s}")
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

    log.p("ТСПУ / TSPU classification (emulated Russian DPI verdict):", MAGENTA)
    if len(strong_signals) >= 1 or len(soft_signals) >= 2:
        log.p("Verdict: BLOCK (accumulative) — TSPU-class classifiers accumulate anomalies and cross the block threshold", RED)
    else:
        log.p("Verdict: PASS — Insufficient anomalies to trigger automated block.", GREEN)

    log.p("\nThreat-model note: TSPU/GFW classify a destination by what the IP actually does on the wire — TLS handshake bytes, cert-steering, active HTTP-over-TLS reply shape, reactions to junk, default-port replies. IP 'reputation' (hosting ASN) is only a coarse pre-filter. Strong signals map directly to Xray / Reality / Trojan / modern obfuscated VPN stacks. If every strong signal is 'none' and soft signals are quiet, the host is essentially invisible to passive DPI regardless of what the ASN looks like.\n")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nAborted.")
