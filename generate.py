import json
import os
import random
import re
import shutil
import subprocess
import tempfile
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
MODES = ["h2", "h3"]             # هر دو نسخه ساخته می‌شود
PER_GROUP = 5                    # تعداد نود برای هر (منبع × مود)
SNI = "www.cloudflare.com"
DNS = ["1.1.1.1", "8.8.8.8"]
TRACE_URL = "https://cloudflare.com/cdn-cgi/trace"


# ======================= توابع کمکی =======================
def pem_body(s):
    return re.sub(r"-----[^-]+-----|\s", "", s or "")


def enc(s):
    # معادل encodeURIComponent در جاوااسکریپت
    return urllib.parse.quote(str(s), safe="!~*'()")


def valid_key(cfg):
    return isinstance(cfg, dict) and all(cfg.get(f) for f in ("private_key", "endpoint_pub_key", "ipv4"))


def tunnel_addresses(k):
    address = [k["ipv4"].split("/")[0] + "/32"]
    if k.get("ipv6"):
        address.append(k["ipv6"].split("/")[0] + "/128")
    return address


def pick_nodes(n):
    used, nodes = set(), []
    while len(nodes) < n:
        node = (f"162.159.198.{random.randint(1, 254)}", random.choice(PORTS))
        if node not in used:
            used.add(node)
            nodes.append(node)
    return nodes


# ======================= منبع ۱: مستقیم از کلودفلر (با usque) =======================
def register_direct():
    exe = os.environ.get("USQUE_BIN") or shutil.which("usque")
    if not exe and Path("bin/usque").exists():
        exe = "bin/usque"
    if not exe:
        print("[direct] usque not found, skipping")
        return None
    exe = str(Path(exe).resolve())
    with tempfile.TemporaryDirectory() as d:
        cfg_path = Path(d) / "config.json"
        try:
            # "y" برای پذیرش شرایط استفاده، اگر ابزار سؤالی بپرسد
            subprocess.run([exe, "-c", str(cfg_path), "register"], input="y\n", text=True,
                           capture_output=True, timeout=120, check=True, cwd=d)
            cfg = json.loads(cfg_path.read_text(encoding="utf-8"))
            if not valid_key(cfg):
                raise ValueError("config.json lacks required fields")
            print("[direct] registered OK")
            return cfg
        except subprocess.CalledProcessError as e:
            print("[direct] failed:", ((e.stderr or "") + (e.stdout or ""))[-300:])
        except Exception as e:
            print(f"[direct] failed: {e}")
    return None


# ======================= منبع ۲: Worker =======================
def get_key_worker():
    for url in APIS:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=30) as r:
                data = json.loads(r.read().decode())
            cfg = data["content"] if isinstance(data.get("content"), dict) and data["content"].get("private_key") else data
            if not valid_key(cfg):
                raise ValueError("response lacks required fields")
            print(f"[worker] OK from {url}")
            return cfg
        except Exception as e:
            print(f"[worker] {url} failed: {e}")
            time.sleep(2)
    return None


# ======================= ساخت لیست نودها (همه منابع × همه مودها) =======================
def build_entries(sources):
    entries = []
    for src, k in sources:
        for mode in MODES:
            for ip, port in pick_nodes(PER_GROUP):
                entries.append({"k": k, "src": src, "mode": mode, "ip": ip, "port": port})
    return entries


def label(e):
    return f"{e['mode'].upper()} | {e['src']} | {e['ip']} | {e['port']}"


def stream_settings(e):
    k = e["k"]
    return {
        "method": "masque",
        "masqueSettings": {"warp": {
            "privateKey": k["private_key"].strip(),
            "publicKey": pem_body(k["endpoint_pub_key"]),
            "address": tunnel_addresses(k),
        }},
        "security": "tls",
        "tlsSettings": {"serverName": SNI, "alpn": [e["mode"]]},
    }


# ======================= Xray (v2rayN / Throne / OneXray) =======================
def build_xray(entries):
    outbounds = [{
        "protocol": "masque",
        "settings": {"address": e["ip"], "port": int(e["port"]), "remoteDNS": DNS},
        "streamSettings": stream_settings(e),
        "tag": label(e),
    } for e in entries]
    return json.dumps({"log": {"loglevel": "warning"}, "outbounds": outbounds}, indent=2)


# ======================= Mobile (PingNG / v2rayNG / Happ / Streisand) =======================
def build_xray_mobile(entries):
    items = []
    for e in entries:
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
                {
                    "protocol": "masque",
                    "settings": {"address": e["ip"], "port": int(e["port"]), "remoteDNS": DNS},
                    "streamSettings": stream_settings(e),
                    "tag": "proxy",
                },
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
            "remarks": label(e) + " | MASQUE Nav",
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


def build_clash(entries):
    names, blocks = [], []
    for e in entries:
        k = e["k"]
        v4 = k["ipv4"].split("/")[0]
        v6 = (k.get("ipv6") or "").split("/")[0]
        name = label(e)
        names.append(name)
        lines = [
            f'  - name: "{name}"',
            "    type: masque",
            f"    server: {e['ip']}",
            f"    port: {e['port']}",
            f'    private-key: "{k["private_key"].strip()}"',
            f'    public-key: "{pem_body(k["endpoint_pub_key"])}"',
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
        if e["mode"] == "h2":
            lines.append("    network: h2")
        blocks.append("\n".join(lines))
    stamp = datetime.now(timezone.utc).strftime("%Y/%m/%d %H:%M:%S UTC")
    return (CLASH_TEMPLATE
            .replace("__STAMP__", stamp)
            .replace("__TRACE__", TRACE_URL)
            .replace("__NAMES__", json.dumps(names))
            .replace("__PROXIES__", "\n\n".join(blocks)))


# ======================= MahsaNG (masque:// links) =======================
def build_mahsa_links(entries):
    first_dns = DNS[0] if DNS else "1.1.1.1"
    links = []
    for e in entries:
        k = e["k"]
        host = f"[{e['ip']}]" if ":" in e["ip"] else e["ip"]
        q = [
            ("transport", e["mode"]),
            ("address", ",".join(tunnel_addresses(k))),
            ("mtu", "1280"),
            ("remoteDNS", first_dns),
            ("sni", SNI),
            ("insecure", "1"),
            ("keepalive", "5"),
        ]
        query = "&".join(f"{a}={enc(b)}" for a, b in q)
        links.append(f"masque://{enc(pem_body(k['private_key']))}@{host}:{e['port']}?{query}#{enc(label(e) + ' | MASQUE Nav')}")
    return "\n".join(links)


# ======================= اجرای اصلی =======================
def main():
    sources = []
    direct = register_direct()
    if direct:
        sources.append(("Direct", direct))
    time.sleep(2)
    worker = get_key_worker()
    if worker:
        sources.append(("Worker", worker))
    if not sources:
        raise SystemExit("no key source worked")

    entries = build_entries(sources)
    out = Path("output")
    out.mkdir(exist_ok=True)

    xray_json = build_xray(entries)
    (out / "masque-xray.json").write_text(xray_json, encoding="utf-8")
    (out / "masque-xray.txt").write_text(xray_json, encoding="utf-8")
    (out / "masque-mobile.json").write_text(build_xray_mobile(entries), encoding="utf-8")
    (out / "masque-clash.yaml").write_text(build_clash(entries), encoding="utf-8")
    (out / "masque-mahsang.txt").write_text(build_mahsa_links(entries), encoding="utf-8")
    print(f"sources: {[s for s, _ in sources]} | nodes: {len(entries)} (H2+H3)")


main()
