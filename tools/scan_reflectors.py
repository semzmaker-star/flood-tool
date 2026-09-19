#!/usr/bin/env python3
"""Reflector scanner - download public lists + validate live."""
import socket
import concurrent.futures
import re
import sys
from pathlib import Path

# public gists/repos yang share open reflector lists
SOURCES = {
    "memcached": [
        "https://gist.githubusercontent.com/securityops/4d5c3a7e6f9b8c2a1d/raw/memcached.txt",
    ],
    "cldap": [
        "https://gist.githubusercontent.com/securityops/4d5c3a7e6f9b8c2a1d/raw/cldap.txt",
    ],
    "dns": [
        "https://raw.githubusercontent.com/opendns/public-domain-lists/master/opendns-random-domains.txt",
    ],
}

PORTS = {"memcached": 11211, "cldap": 389, "dns": 53}

PAYLOADS = {
    "memcached": b"stats\r\n",
    "cldap": bytes([0x30,0x25,0x02,0x01,0x01,0x63,0x20,0x04,0x00,0x0a,0x01,0x00,0x0a,0x01,0x00,0x02,
                    0x01,0x00,0x02,0x01,0x00,0x01,0x01,0x00,0x87,0x0b,0x6f,0x62,0x6a,0x65,0x63,0x74,
                    0x43,0x6c,0x61,0x73,0x73,0x30,0x00]),
    "dns": bytes([0x12,0x34,0x01,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,
                  0x03,105,115,99,0x03,0x6f,0x72,0x67,0x00,0x00,0xff,0x00,0x01]),
}

def download_source(kind):
    """Try download from public sources. Return list of IPs."""
    import urllib.request
    ips = set()
    for url in SOURCES.get(kind, []):
        try:
            with urllib.request.urlopen(url, timeout=10) as r:
                text = r.read().decode("utf-8", errors="ignore")
                for line in text.splitlines():
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    m = re.match(r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", line)
                    if m:
                        ips.add(m.group(1))
        except Exception as e:
            print(f"  [warn] {url}: {e}", file=sys.stderr)
    return list(ips)

def validate(ip, kind, timeout=3):
    """Send probe, see if we get a response."""
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
        print(f"    got {len(ips)} IPs")

        if not ips:
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

    with out.open("w") as f:
        f.write("# reflector_ip port type response_bytes\n")
        for kind, entries in all_valid.items():
            for ip, rbytes in entries:
                f.write(f"{ip} {PORTS[kind]} {kind} {rbytes}\n")

    print(f"\n[+] saved {sum(len(v) for v in all_valid.values())} reflectors -> {out}")

if __name__ == "__main__":
    main()
