#!/usr/bin/env python3
"""
Reflector scanner v2.
- Isi SOURCES dengan URL gist/raw real yang lo dapet dari Google.
- Skrip download, parse, validasi, output reflectors.txt.
- Kalau URL kosong, skip tipe itu.
"""
import socket
import concurrent.futures
import re
import sys
from pathlib import Path

# === ISI URL DI SINI ===
# Cari di Google: "open memcached list github"
#                 "open cldap list github"
#                 "open dns resolver list github"
# Ambil URL raw (gist.githubusercontent.com/... atau raw.githubusercontent.com/...)
SOURCES = {
    "memcached": [
        # "https://raw.githubusercontent.com/USER/REPO/main/memcached.txt",
    ],
    "cldap": [
        # "https://raw.githubusercontent.com/USER/REPO/main/cldap.txt",
    ],
    "dns": [
        # "https://raw.githubusercontent.com/USER/REPO/main/dns.txt",
    ],
}

PORTS = {"memcached": 11211, "cldap": 389, "dns": 53}

PAYLOADS = {
    "memcached": b"stats\r\n",
    "cldap": bytes([0x30,0x25,0x02,0x01,0x01,0x63,0x20,0x04,0x00,0x0a,0x01,0x00,0x0a,0x01,0x00,0x02,
                    0x01,0x00,0x02,0x01,0x00,0x01,0x01,0x00,0x87,0x0b,0x6f,0x62,0x6a,0x65,0x63,0x74,
                    0x43,0x6c,0x61,0x73,0x73,0x30,0x00]),
    "dns": bytes([0x12,0x34,0x01,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,
                  0x03,105,115,99,0x03,111,114,103,0x00,0x00,0xff,0x00,0x01]),
}

def download_source(kind):
    import urllib.request
    ips = set()
    for url in SOURCES.get(kind, []):
        if not url or url.startswith("#"):
            continue
        try:
            with urllib.request.urlopen(url, timeout=15) as r:
                text = r.read().decode("utf-8", errors="ignore")
                for line in text.splitlines():
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    m = re.match(r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", line)
                    if m:
                        ips.add(m.group(1))
            print(f"    [+] {url.split('/')[-1]}: {len(ips)} unique so far")
        except Exception as e:
            print(f"    [warn] {url}: {e}", file=sys.stderr)
    return list(ips)

def validate(ip, kind, timeout=3):
    port = PORTS[kind]
    payload = PAYLOADS[kind]
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)
        s.sendto(payload, (ip, port))
        data, _ = s.recvfrom(4096)
        s.close()
        return (ip, len(data)) if data else None
    except Exception:
        return None

def main():
    out = Path("reflectors.txt")
    all_valid = {}

    for kind in ["memcached", "cldap", "dns"]:
        print(f"[*] {kind}: downloading...")
        ips = download_source(kind)
        print(f"    total {len(ips)} IPs")

        if not ips:
            print(f"    skip (no URLs configured)")
            continue

        print(f"[*] {kind}: validating {len(ips)} IPs (50 threads)...")
        valid = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as ex:
            futures = {ex.submit(validate, ip, kind): ip for ip in ips}
            for fut in concurrent.futures.as_completed(futures):
                r = fut.result()
                if r:
                    valid.append(r)
                    print(f"    [+] {r[0]}:{PORTS[kind]} -> {r[1]} bytes")

        all_valid[kind] = valid
        print(f"[*] {kind}: {len(valid)}/{len(ips)} valid")

    # merge dengan reflectors.txt yang ada (jangan hilangin yang lama)
    existing = set()
    if out.exists():
        for line in out.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                parts = line.split()
                if len(parts) >= 3:
                    existing.add((parts[0], parts[1], parts[2]))

    new_entries = set()
    for kind, entries in all_valid.items():
        for ip, rbytes in entries:
            new_entries.add((ip, str(PORTS[kind]), kind))

    combined = existing | new_entries
    with out.open("w") as f:
        f.write("# reflector_ip port type\n")
        for ip, port, kind in sorted(combined):
            f.write(f"{ip} {port} {kind}\n")

    print(f"\n[+] total: {len(combined)} reflectors (existing: {len(existing)}, new: {len(new_entries)})")
    print(f"[+] saved -> {out}")

if __name__ == "__main__":
    main()
