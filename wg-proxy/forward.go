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
	"log"
	"net"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/tun/netstack"
)

const (
	udpBufSize    = 65535
	udpIdleTimeout = 5 * time.Minute
)

// TCP binds localAddr (e.g. "127.0.0.1:5432"), accepts TCP connections,
// and forwards each one to remoteAddr (e.g. "10.0.0.1:5432") through tnet.
// Blocks until the listener fails.
func TCPForward(tnet *netstack.Net, localAddr, remoteAddr string) error {
	ln, err := net.Listen("tcp", localAddr)
	if err != nil {
		return err
	}
	defer ln.Close()

	for {
		client, err := ln.Accept()
		if err != nil {
			// Listener closed — not an error worth logging at runtime.
			return err
		}
		go handleTCP(tnet, client, remoteAddr)
	}
}

func handleTCP(tnet *netstack.Net, client net.Conn, remoteAddr string) {
	defer client.Close()

	remote, err := tnet.DialContext(context.Background(), "tcp", remoteAddr)
	if err != nil {
		log.Printf("TCP: dial %s through tunnel: %v", remoteAddr, err)
		return
	}
	defer remote.Close()

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
				log.Printf("UDP: dial %s through tunnel: %v", remoteAddr, err)
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
			log.Printf("UDP: write to tunnel (%s): %v", remoteAddr, err)
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
			log.Printf("UDP: write to client %s: %v", clientAddr, err)
			return
		}
	}
}
