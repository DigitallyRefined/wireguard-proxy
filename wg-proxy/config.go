// Package config loads wg-proxy configuration from a file or environment variables.
//
// File format (wg-proxy.conf):
//
//	[Interface]
//	PrivateKey = <base64 or hex>
//	Address    = 10.0.0.2
//	ListenPort = 51820         # optional
//	DNS        = 1.1.1.1       # optional, default 1.1.1.1
//	MTU        = 1420          # optional, default 1420
//
//	[Peer]
//	PublicKey           = <base64 or hex>
//	PresharedKey        = <base64 or hex>              # optional
//	Endpoint            = 1.2.3.4:51820                # optional
//	AllowedIPs          = 10.0.0.0/24, 192.168.1.0/24
//	PersistentKeepalive = 0                            # optional, default 0
//
//	# Forwarding rules
//	# proto  bind-addr       bind-port  remote-addr    remote-port
//	[Forward]
//	tcp      0.0.0.0         8080       10.0.0.1       8080
//	tcp      127.0.0.1       6379       10.0.0.1       6379
//	udp      0.0.0.0         5353       10.0.0.1       53
//	udp      127.0.0.1       1194       10.0.0.5       1194
//
// Environment variable override:
//
//	WG_PRIVATE_KEY                base64 or hex private key
//	WG_ADDRESS                    tunnel IP, e.g. 10.0.0.2
//	WG_LISTEN_PORT                optional WireGuard listen port, e.g. 51820
//	WG_MTU                        optional MTU, default 1420
//	WG_DNS                        optional DNS, default 1.1.1.1
//	WG_PEER_PUBLIC_KEY            base64 or hex peer public key
//	WG_PEER_PRESHARED_KEY         base64 or hex peer preshared key, optional
//	WG_PEER_ENDPOINT              optional host:port of WireGuard server
//	WG_PEER_ALLOWED_IPS           comma-separated CIDRs, default 0.0.0.0/0
//	WG_PEER_PERSISTENT_KEEPALIVE  optional persistent keepalive interval in seconds
//	WG_FORWARDS                   space-separated rules:
//	                               "tcp:0.0.0.0:8080:10.0.0.1:8080,udp:0.0.0.0:5353:10.0.0.1:53"

package main

import (
	"bufio"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/netip"
	"os"
	"strings"
)

type Config struct {
	Interface InterfaceConfig
	Peers     []PeerConfig
	Forwards  []ForwardRule
}

type InterfaceConfig struct {
	PrivateKey string // always hex-encoded internally
	Address    netip.Addr
	ListenPort int
	DNS        []netip.Addr
	MTU        int
}

type PeerConfig struct {
	PublicKey           string // always hex-encoded internally
	PresharedKey        string // always hex-encoded internally
	Endpoint            string // host:port
	AllowedIPs          []netip.Prefix
	PersistentKeepalive int
}

type ForwardRule struct {
	Proto      string // "tcp" or "udp"
	BindAddr   string // e.g. "127.0.0.1"
	BindPort   string // e.g. "5432"
	RemoteAddr string // e.g. "10.0.0.1"
	RemotePort string // e.g. "5432"
}

// Local returns the local bind address as host:port.
func (r ForwardRule) Local() string {
	return r.BindAddr + ":" + r.BindPort
}

// Remote returns the remote address as host:port.
func (r ForwardRule) Remote() string {
	return r.RemoteAddr + ":" + r.RemotePort
}

// String returns a human-readable representation of the rule.
func (r ForwardRule) String() string {
	return fmt.Sprintf("%s  %s:%s  ->  %s:%s",
		strings.ToUpper(r.Proto), r.BindAddr, r.BindPort, r.RemoteAddr, r.RemotePort)
}

// Load reads config from file if path is given, otherwise falls back to environment variables.
func Load(path string) (*Config, error) {
	if path != "" {
		return loadFromFile(path)
	}
	cfg, err := loadFromEnv()
	if err != nil {
		return nil, fmt.Errorf("environment config: %w", err)
	}
	return cfg, validate(cfg)
}

// loadFromFile parses a wg-proxy.conf file.
func loadFromFile(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close()

	cfg := &Config{}
	var section string
	var currentPeer *PeerConfig

	scanner := bufio.NewScanner(f)
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())

		// Skip blank lines and comments
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}

		// Section header
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			name := strings.ToLower(line[1 : len(line)-1])
			// Commit previous peer when we hit a new section
			if section == "peer" && currentPeer != nil {
				cfg.Peers = append(cfg.Peers, *currentPeer)
				currentPeer = nil
			}
			section = name
			if section == "peer" {
				currentPeer = &PeerConfig{PersistentKeepalive: 0}
			}
			continue
		}

		switch section {
		case "interface":
			// key = value
			k, v, ok := cutKV(line)
			if !ok {
				return nil, fmt.Errorf("line %d: expected key = value", lineNo)
			}
			if err := parseInterfaceKV(&cfg.Interface, k, v); err != nil {
				return nil, fmt.Errorf("line %d [Interface] %s: %w", lineNo, k, err)
			}

		case "peer":
			k, v, ok := cutKV(line)
			if !ok {
				return nil, fmt.Errorf("line %d: expected key = value", lineNo)
			}
			if err := parsePeerKV(currentPeer, k, v); err != nil {
				return nil, fmt.Errorf("line %d [Peer] %s: %w", lineNo, k, err)
			}

		case "forward":
			// format: proto  bind-addr  bind-port  remote-addr  remote-port
			rule, err := parseForwardLine(line)
			if err != nil {
				return nil, fmt.Errorf("line %d [Forward]: %w", lineNo, err)
			}
			cfg.Forwards = append(cfg.Forwards, rule)
		}
	}

	// Commit last peer
	if currentPeer != nil {
		cfg.Peers = append(cfg.Peers, *currentPeer)
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	applyDefaults(&cfg.Interface)
	return cfg, validate(cfg)
}

func parseInterfaceKV(iface *InterfaceConfig, k, v string) error {
	switch strings.ToLower(k) {
	case "privatekey":
		key, err := decodeKey(v)
		if err != nil {
			return err
		}
		iface.PrivateKey = key
	case "address":
		// Accept "10.0.0.2" or "10.0.0.2/24"
		addr, err := netip.ParseAddr(strings.Split(v, "/")[0])
		if err != nil {
			return err
		}
		iface.Address = addr
	case "listenport":
		if _, err := fmt.Sscanf(v, "%d", &iface.ListenPort); err != nil {
			return fmt.Errorf("invalid ListenPort %q", v)
		}
	case "dns":
		for _, d := range strings.Split(v, ",") {
			d = strings.TrimSpace(d)
			addr, err := netip.ParseAddr(d)
			if err != nil {
				return err
			}
			iface.DNS = append(iface.DNS, addr)
		}
	case "mtu":
		if _, err := fmt.Sscanf(v, "%d", &iface.MTU); err != nil {
			return fmt.Errorf("invalid MTU %q", v)
		}
	default:
		// Silently ignore unknown keys (forward-compat)
	}
	return nil
}

func parsePeerKV(peer *PeerConfig, k, v string) error {
	switch strings.ToLower(k) {
	case "publickey":
		key, err := decodeKey(v)
		if err != nil {
			return err
		}
		peer.PublicKey = key
	case "presharedkey":
		key, err := decodeKey(v)
		if err != nil {
			return err
		}
		peer.PresharedKey = key
	case "endpoint":
		peer.Endpoint = v
	case "allowedips":
		for _, cidr := range strings.Split(v, ",") {
			cidr = strings.TrimSpace(cidr)
			prefix, err := netip.ParsePrefix(cidr)
			if err != nil {
				return fmt.Errorf("invalid CIDR %q: %w", cidr, err)
			}
			peer.AllowedIPs = append(peer.AllowedIPs, prefix)
		}
	case "persistentkeepalive":
		if _, err := fmt.Sscanf(v, "%d", &peer.PersistentKeepalive); err != nil {
			return fmt.Errorf("invalid PersistentKeepalive %q", v)
		}
	}
	return nil
}

// parseForwardLine parses a forwarding rule line:
//	tcp  127.0.0.1  5432  10.0.0.1  5432
func parseForwardLine(line string) (ForwardRule, error) {
	fields := strings.Fields(line)
	if len(fields) != 5 {
		return ForwardRule{}, fmt.Errorf(
			"expected: proto bind-addr bind-port remote-addr remote-port, got %q", line)
	}
	proto := strings.ToLower(fields[0])
	if proto != "tcp" && proto != "udp" {
		return ForwardRule{}, fmt.Errorf("proto must be tcp or udp, got %q", proto)
	}
	return ForwardRule{
		Proto:      proto,
		BindAddr:   fields[1],
		BindPort:   fields[2],
		RemoteAddr: fields[3],
		RemotePort: fields[4],
	}, nil
}

// loadFromEnv builds a Config entirely from environment variables.
func loadFromEnv() (*Config, error) {
	privKey := os.Getenv("WG_PRIVATE_KEY")
	address := os.Getenv("WG_ADDRESS")
	peerPub := os.Getenv("WG_PEER_PUBLIC_KEY")
	peerPreshared := os.Getenv("WG_PEER_PRESHARED_KEY")
	peerEP := os.Getenv("WG_PEER_ENDPOINT")

	var missing []string
	if privKey == "" {
		missing = append(missing, "WG_PRIVATE_KEY")
	}
	if address == "" {
		missing = append(missing, "WG_ADDRESS")
	}
	if peerPub == "" {
		missing = append(missing, "WG_PEER_PUBLIC_KEY")
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("missing required environment variables: %s", strings.Join(missing, ", "))
	}

	privKeyHex, err := decodeKey(privKey)
	if err != nil {
		return nil, fmt.Errorf("WG_PRIVATE_KEY invalid: %w", err)
	}

	var listenPort int
	if lp := os.Getenv("WG_LISTEN_PORT"); lp != "" {
		if _, err := fmt.Sscanf(lp, "%d", &listenPort); err != nil {
			return nil, fmt.Errorf("WG_LISTEN_PORT invalid: %w", err)
		}
	}

	var mtu int
	if m := os.Getenv("WG_MTU"); m != "" {
		if _, err := fmt.Sscanf(m, "%d", &mtu); err != nil {
			return nil, fmt.Errorf("WG_MTU invalid: %w", err)
		}
	}

	peerPubHex, err := decodeKey(peerPub)
	if err != nil {
		return nil, fmt.Errorf("WG_PEER_PUBLIC_KEY invalid: %w", err)
	}

	var peerPresharedHex string
	if peerPreshared != "" {
		peerPresharedHex, err = decodeKey(peerPreshared)
		if err != nil {
			return nil, fmt.Errorf("WG_PEER_PRESHARED_KEY invalid: %w", err)
		}
	}

	addrStr := strings.Split(address, "/")[0]
	addr, err := netip.ParseAddr(addrStr)
	if err != nil {
		return nil, fmt.Errorf("WG_ADDRESS invalid: %w", err)
	}

	cfg := &Config{
		Interface: InterfaceConfig{
			PrivateKey: privKeyHex,
			Address:    addr,
			ListenPort: listenPort,
			MTU:        mtu,
		},
	}
	applyDefaults(&cfg.Interface)

	if dns := os.Getenv("WG_DNS"); dns != "" {
		for _, d := range strings.Split(dns, ",") {
			d = strings.TrimSpace(d)
			if a, err := netip.ParseAddr(d); err == nil {
				cfg.Interface.DNS = append(cfg.Interface.DNS, a)
			}
		}
	}

	var persistentKeepalive int
	if pk := os.Getenv("WG_PEER_PERSISTENT_KEEPALIVE"); pk != "" {
		fmt.Sscanf(pk, "%d", &persistentKeepalive)
	}

	allowedIPs := envOr("WG_PEER_ALLOWED_IPS", "0.0.0.0/0")
	peer := PeerConfig{
		PublicKey:           peerPubHex,
		PresharedKey:        peerPresharedHex,
		Endpoint:            peerEP,
		PersistentKeepalive: persistentKeepalive,
	}
	for _, cidr := range strings.Split(allowedIPs, ",") {
		cidr = strings.TrimSpace(cidr)
		if prefix, err := netip.ParsePrefix(cidr); err == nil {
			peer.AllowedIPs = append(peer.AllowedIPs, prefix)
		}
	}
	cfg.Peers = append(cfg.Peers, peer)

	// WG_FORWARDS="tcp:127.0.0.1:5432:10.0.0.1:5432,udp:127.0.0.1:5353:10.0.0.1:53"
	if fwds := os.Getenv("WG_FORWARDS"); fwds != "" {
		for _, f := range strings.Split(fwds, ",") {
			f = strings.TrimSpace(f)
			if f == "" {
				continue
			}
			// Split on colons: proto:bindAddr:bindPort:remoteAddr:remotePort
			parts := strings.SplitN(f, ":", 5)
			if len(parts) != 5 {
				continue
			}
			proto := strings.ToLower(parts[0])
			if proto != "tcp" && proto != "udp" {
				continue
			}
			cfg.Forwards = append(cfg.Forwards, ForwardRule{
				Proto:      proto,
				BindAddr:   parts[1],
				BindPort:   parts[2],
				RemoteAddr: parts[3],
				RemotePort: parts[4],
			})
		}
	}

	return cfg, nil
}

func applyDefaults(iface *InterfaceConfig) {
	if iface.MTU == 0 {
		iface.MTU = 1420
	}
	if iface.ListenPort == 0 {
		iface.ListenPort = 51820
	}
	if len(iface.DNS) == 0 {
		iface.DNS = []netip.Addr{netip.MustParseAddr("1.1.1.1")}
	}
}

func validate(cfg *Config) error {
	if cfg.Interface.PrivateKey == "" {
		return fmt.Errorf("Interface: PrivateKey is required")
	}
	if !cfg.Interface.Address.IsValid() {
		return fmt.Errorf("Interface: Address is required")
	}
	if len(cfg.Peers) == 0 {
		return fmt.Errorf("at least one [Peer] is required")
	}
	for i, p := range cfg.Peers {
		if p.PublicKey == "" {
			return fmt.Errorf("Peer[%d]: PublicKey required", i)
		}
		if len(p.AllowedIPs) == 0 {
			return fmt.Errorf("Peer[%d]: AllowedIPs required", i)
		}
	}
	return nil
}

// decodeKey accepts WireGuard keys as either base64 (wg-quick standard)
// or 64-character lowercase hex, and always returns 64-char hex.
func decodeKey(s string) (string, error) {
	s = strings.TrimSpace(s)
	if len(s) == 64 {
		b, err := hex.DecodeString(s)
		if err == nil && len(b) == 32 {
			return s, nil // already hex
		}
	}
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return "", fmt.Errorf("key must be base64 (wg-quick) or 64-char hex: %w", err)
	}
	if len(b) != 32 {
		return "", fmt.Errorf("key must decode to 32 bytes, got %d", len(b))
	}
	return hex.EncodeToString(b), nil
}

func cutKV(line string) (string, string, bool) {
	k, v, ok := strings.Cut(line, "=")
	if !ok {
		return "", "", false
	}
	return strings.TrimSpace(k), strings.TrimSpace(v), true
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
