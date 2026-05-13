// Package tunnel creates a WireGuard userspace tunnel using wireguard-go's
// netstack backend. No TUN device, no NET_ADMIN capability, no kernel module.
package main

import (
	"fmt"
	"net/netip"
	"reflect"
	"unsafe"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

// Tunnel holds the live WireGuard device and the netstack Net handle
// that callers use to dial or listen through the tunnel.
type Tunnel struct {
	Net *netstack.Net
	dev *device.Device
}

// New builds and brings up a WireGuard userspace tunnel from cfg.
// The returned Tunnel.Net can be used to Dial (TCP/UDP) or Listen
// on addresses reachable through the WireGuard peer network.
func NewTunnel(cfg *Config) (*Tunnel, error) {
	tun, tnet, err := netstack.CreateNetTUN(
		[]netip.Addr{cfg.Interface.Address},
		cfg.Interface.DNS,
		cfg.Interface.MTU,
	)
	if err != nil {
		return nil, fmt.Errorf("create netstack TUN: %w", err)
	}

	// Performance Tuning: Optimize the userspace netstack for high-throughput
	// and low-latency. We use reflect/unsafe to access the unexported stack field.
	netstackValue := reflect.ValueOf(tnet).Elem()
	stackField := netstackValue.FieldByName("stack")
	netStack := (*stack.Stack)(unsafe.Pointer(stackField.UnsafeAddr()))

	// Tune TCP buffer sizes (increase to 1MB)
	// This improves throughput on high-bandwidth or high-latency links.
	receiveBufferSize := tcpip.TCPReceiveBufferSizeRangeOption{
		Min:     4096,
		Default: 65536,
		Max:     1048576,
	}
	netStack.SetOption(&receiveBufferSize)

	sendBufferSize := tcpip.TCPSendBufferSizeRangeOption{
		Min:     4096,
		Default: 65536,
		Max:     1048576,
	}
	netStack.SetOption(&sendBufferSize)

	logger := device.NewLogger(device.LogLevelError, "(wg) ")
	dev := device.NewDevice(tun, conn.NewDefaultBind(), logger)

	ipcConf, err := buildIPC(cfg)
	if err != nil {
		return nil, err
	}

	if err := dev.IpcSet(ipcConf); err != nil {
		return nil, fmt.Errorf("ipc set: %w", err)
	}

	if err := dev.Up(); err != nil {
		return nil, fmt.Errorf("device up: %w", err)
	}

	return &Tunnel{Net: tnet, dev: dev}, nil
}

// Close shuts down the WireGuard device cleanly.
func (t *Tunnel) Close() {
	t.dev.Close()
}

// buildIPC produces the WireGuard IPC configuration string understood
// by device.IpcSet. Format mirrors `wg setconf` output.
func buildIPC(cfg *Config) (string, error) {
	var b []byte

	// Interface section
	b = appendf(b, "private_key=%s\n", cfg.Interface.PrivateKey)

	// Peer sections
	for _, p := range cfg.Peers {
		b = appendf(b, "public_key=%s\n", p.PublicKey)
		if p.PresharedKey != "" {
			b = appendf(b, "preshared_key=%s\n", p.PresharedKey)
		}
		b = appendf(b, "endpoint=%s\n", p.Endpoint)

		for _, prefix := range p.AllowedIPs {
			b = appendf(b, "allowed_ip=%s\n", prefix.String())
		}

		if p.PersistentKeepalive > 0 {
			b = appendf(b, "persistent_keepalive_interval=%d\n", p.PersistentKeepalive)
		}
	}

	return string(b), nil
}

func appendf(b []byte, format string, args ...any) []byte {
	return fmt.Appendf(b, format, args...)
}
