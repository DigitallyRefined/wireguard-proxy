// Package forward implements TCP and UDP port forwarding
// through a WireGuard netstack tunnel.
//
// TCP: bind a local address, accept connections, dial the remote through
// the tunnel, and copy bidirectionally.
//
// UDP: bind a local address, track per-client sessions by source address,
// dial the remote through the tunnel for each session, and relay datagrams
// in both directions. Sessions expire after udpIdleTimeout of silence.
package main

import (
	"context"
	"io"
	"net"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/tun/netstack"
)

const (
	udpBufSize     = 65535
	udpIdleTimeout  = 5 * time.Minute
	dialTimeout     = 10 * time.Second
	maxPoolSize     = 10
)

var (
	tcpConnPool = make(map[string]chan net.Conn)
	poolMu      sync.Mutex
)

func getFromPool(remoteAddr string) net.Conn {
	poolMu.Lock()
	defer poolMu.Unlock()
	ch, ok := tcpConnPool[remoteAddr]
	if !ok {
		return nil
	}
	for {
		select {
		case conn := <-ch:
			// Check if connection is still alive (roughly)
			// We can't easily check for half-closed without a read,
			// but for high-frequency sequential requests, this is usually fine.
			return conn
		default:
			return nil
		}
	}
}

func putInPool(remoteAddr string, conn net.Conn) {
	poolMu.Lock()
	defer poolMu.Unlock()
	ch, ok := tcpConnPool[remoteAddr]
	if !ok {
		ch = make(chan net.Conn, 20)
		tcpConnPool[remoteAddr] = ch
	}
	select {
	case ch <- conn:
	default:
		conn.Close()
	}
}

func maintainPool(tnet *netstack.Net, remoteAddr string) {
	for {
		poolMu.Lock()
		ch, ok := tcpConnPool[remoteAddr]
		var count int
		if ok {
			count = len(ch)
		}
		poolMu.Unlock()

		if count < maxPoolSize {
			// Dial multiple in parallel to replenish faster
			needed := maxPoolSize - count
			if needed > 3 {
				needed = 3 // Don't overwhelm with too many parallel dials
			}
			for i := 0; i < needed; i++ {
				go func() {
					ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
					conn, err := tnet.DialContext(ctx, "tcp", remoteAddr)
					cancel()
					if err == nil {
						if tc, ok := conn.(*net.TCPConn); ok {
							tc.SetKeepAlive(true)
							tc.SetKeepAlivePeriod(30 * time.Second)
							tc.SetNoDelay(true)
						}
						putInPool(remoteAddr, conn)
					}
				}()
			}
			time.Sleep(1 * time.Second) // Wait for some dials to finish
		} else {
			time.Sleep(500 * time.Millisecond)
		}
	}
}

// TCP binds localAddr (e.g. "127.0.0.1:5432"), accepts TCP connections,
// and forwards each one to remoteAddr (e.g. "10.0.0.1:5432") through tnet.
// Blocks until the listener fails.
func TCPForward(tnet *netstack.Net, localAddr, remoteAddr string) error {
	ln, err := net.Listen("tcp", localAddr)
	if err != nil {
		return err
	}
	defer ln.Close()

	// Start pool maintainer
	go maintainPool(tnet, remoteAddr)

	for {
		client, err := ln.Accept()
		if err != nil {
			return err
		}
		go handleTCP(tnet, client, remoteAddr)
	}
}

func handleTCP(tnet *netstack.Net, client net.Conn, remoteAddr string) {
	start := time.Now()
	defer client.Close()

	var remote net.Conn
	// Try pool first
	if pooled := getFromPool(remoteAddr); pooled != nil {
		remote = pooled
	} else {
		// Fallback to direct dial with retry
		for i := 0; i < 2; i++ {
			ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
			var err error
			remote, err = tnet.DialContext(ctx, "tcp", remoteAddr)
			cancel()
			if err == nil {
				break
			}
			if i == 0 {
				// Don't log retry for sequential load unless it's really slow
				time.Sleep(200 * time.Millisecond)
				continue
			}
			debugLog("TCP: dial %s through tunnel (failed after %v): %v", remoteAddr, time.Since(start), err)
			return
		}
	}

	if d := time.Since(start); d > 500*time.Millisecond {
		debugLog("TCP: dial %s took %v", remoteAddr, d)
	}

	defer remote.Close()

	// Ensure keepalives are set (if not already from pool)
	if tc, ok := remote.(*net.TCPConn); ok {
		tc.SetKeepAlive(true)
		tc.SetKeepAlivePeriod(30 * time.Second)
		tc.SetNoDelay(true)
	}

	// Copy in both directions simultaneously; close both sides when either ends.
	done := make(chan struct{}, 2)
	copy := func(dst, src net.Conn) {
		io.Copy(dst, src)
		// Half-close where possible so the other side sees EOF cleanly.
		if tc, ok := dst.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
		done <- struct{}{}
	}

	go copy(remote, client)
	go copy(client, remote)

	<-done // wait for one direction to finish, then close everything
}

// udpSession is one client ↔ remote tunnel session.
type udpSession struct {
	remote     net.Conn  // UDP conn through the WireGuard tunnel
	lastActive time.Time
}

// UDP binds localAddr (e.g. "127.0.0.1:5353") and forwards datagrams to
// remoteAddr (e.g. "10.0.0.1:53") through tnet.
//
// Each unique source address on the local side gets its own tunnel connection
// so that multiple clients (e.g. different processes querying DNS) are
// correctly multiplexed. Sessions expire after udpIdleTimeout.
//
// Blocks until the listener fails.
func UDPForward(tnet *netstack.Net, localAddr, remoteAddr string) error {
	local, err := net.ListenPacket("udp", localAddr)
	if err != nil {
		return err
	}
	defer local.Close()

	var (
		mu       sync.Mutex
		sessions = map[string]*udpSession{}
	)

	// Reap idle sessions periodically.
	go func() {
		ticker := time.NewTicker(udpIdleTimeout / 2)
		defer ticker.Stop()
		for range ticker.C {
			mu.Lock()
			for key, s := range sessions {
				if time.Since(s.lastActive) > udpIdleTimeout {
					s.remote.Close()
					delete(sessions, key)
				}
			}
			mu.Unlock()
		}
	}()

	buf := make([]byte, udpBufSize)
	for {
		n, clientAddr, err := local.ReadFrom(buf)
		if err != nil {
			return err
		}

		data := make([]byte, n)
		copy(data, buf[:n])

		key := clientAddr.String()

		mu.Lock()
		sess, ok := sessions[key]
		if !ok {
			// Open a new tunnel connection for this client address.
			remote, err := tnet.DialContext(context.Background(), "udp", remoteAddr)
			if err != nil {
				mu.Unlock()
				debugLog("UDP: dial %s through tunnel: %v", remoteAddr, err)
				continue
			}
			sess = &udpSession{remote: remote, lastActive: time.Now()}
			sessions[key] = sess

			// Return path: tunnel → original client.
			go relayUDPResponse(remote, local, clientAddr, key, &mu, sessions)
		}
		sess.lastActive = time.Now()
		mu.Unlock()

		if _, err := sess.remote.Write(data); err != nil {
			debugLog("UDP: write to tunnel (%s): %v", remoteAddr, err)
		}
	}
}

// relayUDPResponse reads datagrams from the tunnel and writes them back to the
// originating client address on the local PacketConn.
func relayUDPResponse(
	remote net.Conn,
	local net.PacketConn,
	clientAddr net.Addr,
	sessionKey string,
	mu *sync.Mutex,
	sessions map[string]*udpSession,
) {
	defer func() {
		remote.Close()
		mu.Lock()
		delete(sessions, sessionKey)
		mu.Unlock()
	}()

	buf := make([]byte, udpBufSize)
	for {
		// Apply a read deadline so idle sessions are reaped by the GC goroutine
		// rather than leaking goroutines indefinitely.
		remote.SetReadDeadline(time.Now().Add(udpIdleTimeout))

		n, err := remote.Read(buf)
		if err != nil {
			// Timeout or closed — normal exit.
			return
		}

		// Update last-active timestamp.
		mu.Lock()
		if sess, ok := sessions[sessionKey]; ok {
			sess.lastActive = time.Now()
		}
		mu.Unlock()

		if _, err := local.WriteTo(buf[:n], clientAddr); err != nil {
			debugLog("UDP: write to client %s: %v", clientAddr, err)
			return
		}
	}
}
