package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
)

var isDebug bool

func debugLog(format string, v ...any) {
	if isDebug {
		log.Printf(format, v...)
	}
}

func main() {
	log.SetFlags(log.Ltime | log.Lmsgprefix)
	log.SetPrefix("wg-proxy ")

	if os.Getenv("DEBUG") == "1" || os.Getenv("DEBUG") == "true" {
		isDebug = true
	}

	configPath := flag.String("config", "wg-proxy.conf", "path to config file")
	flag.Parse()

	// Allow env override of config path
	if p := os.Getenv("WG_PROXY_CONFIG"); p != "" {
		*configPath = p
	}

	cfg, err := Load(*configPath)
	if err != nil {
		log.Fatalf("config: %v", err)
	}

	log.Printf("tunnel IP %s, %d peer(s), %d forward rule(s)",
		cfg.Interface.Address, len(cfg.Peers), len(cfg.Forwards))

	// Build the WireGuard userspace tunnel (no TUN, no NET_ADMIN, no kernel module)
	tun, err := NewTunnel(cfg)
	if err != nil {
		log.Fatalf("tunnel: %v", err)
	}
	defer tun.Close()
	log.Printf("WireGuard tunnel up")

	if len(cfg.Forwards) == 0 {
		log.Printf("warning: no [Forward] rules — nothing is being forwarded")
	}

	// Start each forwarding rule in its own goroutine.
	// A fatal error in any rule is logged but does not kill the others.
	for _, rule := range cfg.Forwards {
		rule := rule
		switch rule.Proto {
		case "tcp":
			go func() {
				log.Printf("TCP  %s  ->  %s", rule.Local(), rule.Remote())
				if err := TCPForward(tun.Net, rule.Local(), rule.Remote()); err != nil {
					log.Fatalf("TCP forward %s: %v", rule, err)
				}
			}()
		case "udp":
			go func() {
				log.Printf("UDP  %s  ->  %s", rule.Local(), rule.Remote())
				if err := UDPForward(tun.Net, rule.Local(), rule.Remote()); err != nil {
					log.Fatalf("UDP forward %s: %v", rule, err)
				}
			}()
		}
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
	received := <-sig
	log.Printf("received %s, shutting down", received)
}
