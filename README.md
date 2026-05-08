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

```bash
git clone https://github.com/YOUR_USER/BybyeVPNLinux.git
cd BybyeVPNLinux
python3 -m venv env
source env/bin/activate
pip install scapy curl_cffi
