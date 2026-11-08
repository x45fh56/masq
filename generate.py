import json
import random
import re
import time
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

# ======================= تنظیمات =======================
APIS = [
    "https://masque.configwireguard.workers.dev/",
    "https://masque.configwireguard2.workers.dev/",
    "https://masque.configwireguard3.workers.dev/",
    "https://masque.configwireguard4.workers.dev/",
]
PORTS = ["8095", "443", "8443", "4443", "1701", "4500", "500"]
MODE = "h2"                      # یا "h3"
SNI = "www.cloudflare.com"
DNS = ["1.1.1.1", "8.8.8.8"]
COUNT = 10
TRACE_URL = "https://cloudflare.com/cdn-cgi/trace"


# ======================= توابع کمکی =======================
def pem_body(s):
    return re.sub(r"-----[^-]+-----|\s", "", s or "")


def enc(s):
    # معادل encodeURIComponent در جاوااسکریپت
    return urllib.parse.quote(str(s), safe="!~*'()")


def get_key():
    for url in APIS:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=30) as r:
                data = json.loads(r.read().decode())
            cfg = data["content"] if isinstance(data.get("content"), dict) and data["content"].get("private_key") else data
            for f in ("private_key", "endpoint_pub_key", "ipv4"):
                if not cfg.get(f):
                    raise ValueError(f"missing {f}")
            return cfg
        except Exception as e:
            print(f"{url} failed: {e}")
            time.sleep(2)
    raise SystemExit("all APIs failed")


def pick_nodes():
    used, nodes = set(), []
    while len(nodes) < COUNT:
        n = (f"162.159.198.{random.randint(1, 254)}", random.choice(PORTS))
        if n not in used:
            used.add(n)
            nodes.append(n)
    return nodes


def tunnel_addresses(k):
    address = [k["ipv4"].split("/")[0] + "/32"]
    if k.get("ipv6"):
        address.append(k["ipv6"].split("/")[0] + "/128")
    return address


def masque_stream_settings(k):
    return {
        "method": "masque",
        "masqueSettings": {"warp": {
            "privateKey": k["private_key"].strip(),
            "publicKey": pem_body(k["endpoint_pub_key"]),
            "address": tunnel_addresses(k),
        }},
        "security": "tls",
        "tlsSettings": {"serverName": SNI, "alpn": [MODE]},
    }


# ======================= Xray (v2rayN / Throne / OneXray) =======================
def build_xray(k, nodes):
    outbounds = []
    for ip, port in nodes:
        outbounds.append({
            "protocol": "masque",
            "settings": {"address": ip, "port": int(port), "remoteDNS": DNS},
            "streamSettings": masque_stream_settings(k),
            "tag": f"{MODE.upper()} | Official | {ip} | {port}",
        })
    return json.dumps({"log": {"loglevel": "warning"}, "outbounds": outbounds}, indent=2)


# ======================= Mobile (PingNG / v2rayNG / Happ / Streisand) =======================
def build_xray_mobile(k, nodes):
    items = []
    for ip, port in nodes:
        outbound = {
            "protocol": "masque",
            "settings": {"address": ip, "port": int(port), "remoteDNS": DNS},
            "streamSettings": masque_stream_settings(k),
            "tag": "proxy",
        }
        items.append({
            "log": {"loglevel": "warning"},
            "dns": {
                "hosts": {
                    "one.one.one.one": ["1.1.1.1", "1.0.0.1", "2606:4700:4700::1111", "2606:4700:4700::1001"],
                    "dns.google": ["8.8.8.8", "8.8.4.4", "2001:4860:4860::8888", "2001:4860:4860::8844"],
                    "cloudflare-dns.com": ["104.16.249.249", "104.16.248.249", "2606:4700::6810:f8f9", "2606:4700::6810:f9f9"],
                    "dns.cloudflare.com": ["162.159.61.8", "172.64.41.8", "2a06:98c1:52::8", "2803:f800:53::8"],
                    "dns.quad9.net": ["9.9.9.9", "149.112.112.112", "2620:fe::fe", "2620:fe::9"],
                    "engage.cloudflareclient.com": ["162.159.192.1", "2606:4700:d0::a29f:c001"],
                },
                "servers": [
                    {"address": "localhost", "domains": ["geosite:category-ir", "domain:ir"],
                     "skipFallback": True, "tag": "direct-dns"},
                    "https://cloudflare-dns.com/dns-query",
                    "https://dns.google/dns-query",
                    "8.8.8.8",
                ],
                "tag": "dns-module",
            },
            "inbounds": [{
                "tag": "socks",
                "port": 10808,
                "listen": "127.0.0.1",      # اگر اتصال برقرار نشد برای تست "0.0.0.0" بگذار
                "protocol": "mixed",
                "sniffing": {"enabled": False, "destOverride": ["http", "tls"], "routeOnly": False},
                "settings": {"auth": "noauth", "udp": True, "allowTransparent": False},
            }],
            "outbounds": [
                outbound,
                {"tag": "direct", "protocol": "freedom"},
                {"tag": "block", "protocol": "blackhole"},
            ],
            "routing": {
                "domainStrategy": "AsIs",
                "rules": [
                    {"type": "field", "outboundTag": "proxy", "domain": ["domain:googleapis.cn", "domain:gstatic.com"]},
                    {"type": "field", "port": "443", "network": "udp", "outboundTag": "block"},
                    {"type": "field", "outboundTag": "direct", "ip": ["geoip:private"]},
                    {"type": "field", "outboundTag": "direct", "domain": ["geosite:private"]},
                    {"type": "field", "outboundTag": "direct", "domain": ["domain:ir", "geosite:category-ir"]},
                    {"type": "field", "outboundTag": "direct", "ip": ["geoip:ir"]},
                    {"type": "field", "inboundTag": ["direct-dns"], "outboundTag": "direct"},
                    {"type": "field", "inboundTag": ["dns-module"], "outboundTag": "proxy"},
                ],
            },
            "metrics": {"listen": "127.0.0.1:10812"},
            "policy": {"system": {"statsOutboundUplink": True, "statsOutboundDownlink": True}},
            "stats": {},
            "remarks": f"{MODE.upper()} | Official | {ip} | {port} | MASQUE Nav",
        })
    return json.dumps(items, indent=2)


# ======================= Clash (Mihomo) =======================
CLASH_TEMPLATE = """# Generated - __STAMP__
# Needs a Mihomo core with MASQUE support (keep the core up to date)

mode: rule
allow-lan: true
mixed-port: 7890
bind-address: '*'
ipv6: false
unified-delay: true
tcp-concurrent: true
log-level: info
global-ua: clash.meta

geodata-mode: true
geox-url:
  geoip: "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geoip.dat"
  geosite: "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geosite.dat"
geo-auto-update: true
geo-update-interval: 24

profile:
  store-selected: true
  store-fake-ip: true

sniffer:
  enable: true
  sniff:
    HTTP:
      ports: [80, 8080-8880]
      override-destination: true
    TLS:
      ports: [443, 8443]
    QUIC:
      ports: [443, 8443]

dns:
  enable: true
  ipv6: false
  listen: 0.0.0.0:1053
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  fake-ip-filter:
    - geosite:private
    - geosite:category-ir
    - "*.lan"
    - "*.local"
    - "*.arpa"
    - localhost
  use-hosts: true
  respect-rules: true
  default-nameserver:
    - 1.1.1.1
    - 8.8.8.8
  nameserver:
    - https://cloudflare-dns.com/dns-query
    - https://dns.google/dns-query
  nameserver-policy:
    "geosite:category-ir":
      - system
    "geosite:geolocation-!cn":
      - https://cloudflare-dns.com/dns-query#proxy=Proxy-Select
      - https://dns.google/dns-query#proxy=Proxy-Select
  proxy-server-nameserver:
    - system
    - 1.1.1.1

proxy-groups:
  - name: Proxy-Select
    type: select
    proxies: [Endpoint-Auto, Endpoint-Manual, Endpoint-Failover, DIRECT]
  - name: Endpoint-Auto
    type: url-test
    url: __TRACE__
    interval: 300
    tolerance: 30
    proxies: __NAMES__
  - name: Endpoint-Failover
    type: fallback
    url: __TRACE__
    interval: 300
    proxies: __NAMES__
  - name: Endpoint-Manual
    type: select
    proxies: __NAMES__

rules:
  - GEOSITE,private,DIRECT
  - GEOIP,private,DIRECT,no-resolve
  - GEOSITE,category-ir,DIRECT
  - GEOIP,IR,DIRECT,no-resolve
  - MATCH,Proxy-Select

proxies:
__PROXIES__
"""


def build_clash(k, nodes):
    v4 = k["ipv4"].split("/")[0]
    v6 = (k.get("ipv6") or "").split("/")[0]
    priv = k["private_key"].strip()
    pub = pem_body(k["endpoint_pub_key"])
    names, blocks = [], []
    for ip, port in nodes:
        name = f"Official | {ip} | {port} | MASQUE Nav"
        names.append(name)
        lines = [
            f'  - name: "{name}"',
            "    type: masque",
            f"    server: {ip}",
            f"    port: {port}",
            f'    private-key: "{priv}"',
            f'    public-key: "{pub}"',
            f"    ip: {v4}",
        ]
        if v6:
            lines.append(f"    ipv6: {v6}")
        lines += [
            "    uri: https://cloudflareaccess.com",
            "    mtu: 1280",
            "    udp: true",
            "    remote-dns-resolve: true",
            "    congestion-controller: bbr",
            f"    dns: [ {', '.join(DNS)} ]",
            f"    sni: {SNI}",
        ]
        if MODE == "h2":
            lines.append("    network: h2")
        blocks.append("\n".join(lines))
    stamp = datetime.now(timezone.utc).strftime("%Y/%m/%d %H:%M:%S UTC")
    return (CLASH_TEMPLATE
            .replace("__STAMP__", stamp)
            .replace("__TRACE__", TRACE_URL)
            .replace("__NAMES__", json.dumps(names))
            .replace("__PROXIES__", "\n\n".join(blocks)))


# ======================= MahsaNG (masque:// links) =======================
def build_mahsa_links(k, nodes):
    raw = pem_body(k["private_key"])
    address = tunnel_addresses(k)
    first_dns = DNS[0] if DNS else "1.1.1.1"

    links = []
    for ip, port in nodes:
        host = f"[{ip}]" if ":" in ip else ip
        q = [
            ("transport", MODE),
            ("address", ",".join(address)),
            ("mtu", "1280"),
            ("remoteDNS", first_dns),
            ("sni", SNI),
            ("insecure", "1"),
            ("keepalive", "5"),
        ]
        query = "&".join(f"{a}={enc(b)}" for a, b in q)
        tag = f"{MODE.upper()} | Official | {ip} | {port} | MASQUE Nav"
        links.append(f"masque://{enc(raw)}@{host}:{port}?{query}#{enc(tag)}")
    return "\n".join(links)


# ======================= اجرای اصلی =======================
def main():
    k = get_key()
    nodes = pick_nodes()
    Path("output").mkdir(exist_ok=True)

    xray_json = build_xray(k, nodes)
    Path("output/masque-xray.json").write_text(xray_json, encoding="utf-8")
    Path("output/masque-xray.txt").write_text(xray_json, encoding="utf-8")
    Path("output/masque-mobile.json").write_text(build_xray_mobile(k, nodes), encoding="utf-8")
    Path("output/masque-clash.yaml").write_text(build_clash(k, nodes), encoding="utf-8")
    Path("output/masque-mahsang.txt").write_text(build_mahsa_links(k, nodes), encoding="utf-8")
    print(f"wrote {len(nodes)} nodes (xray json+txt, mobile json, clash yaml, mahsang links)")


main()
