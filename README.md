# wireguard-proxy

A zero-privilege WireGuard port forwarder using userspace networking (netstack).  
No `NET_ADMIN`, no `/dev/net/tun`, no kernel module — works in any unprivileged container environment.

Tunnels all traffic through WireGuard.

---

## How it works

```text
your app
  └── connect to 127.0.0.1:5432
        └── wg-proxy TCP forward
              └── wireguard-go netstack (pure userspace)
                    └── encrypted UDP → WireGuard server → 10.0.0.1:5432
```

Your app just connects to a local port and is automatically routed through the WireGuard tunnel.

---

## Config file (`wg-proxy.conf`)

```ini
[Interface]
PrivateKey = <base64 or 64-char hex>
Address    = 10.0.0.2
ListenPort = 51820         # optional
DNS        = 1.1.1         # optional, default 1.1.1.1
MTU        = 1420          # optional, default 1420

[Peer]
PublicKey           = <base64 or 64-char hex>
PresharedKey        = <server-preshared-key-base64>  # optional
Endpoint            = wireguard.example.com:51820    # optional
AllowedIPs          = 10.0.0.0/24, 192.168.100.0/24
PersistentKeepalive = 25                             # optional, default 25

# Forwarding rules
# proto  bind-addr    bind-port  remote-addr remote-port
[Forward]
tcp      0.0.0.0      8080       10.0.0.1    8080    # Postgres
tcp      127.0.0.1    6379       10.0.0.1    6379    # Redis
tcp      127.0.0.1    3306       10.0.0.1    3306    # MySQL
udp      0.0.0.0      5353       10.0.0.1    53      # DNS
```

Keys accept both **base64** (wg-quick standard) and **64-char hex**.

---

## Environment variable config

Set these in your container environment instead of a config file:

| Variable              | Description                   | Example                       |
| --------------------- | ----------------------------- | ----------------------------- |
| `WG_PRIVATE_KEY`      | Interface private key         | `base64...`                   |
| `WG_ADDRESS`          | Tunnel IP                     | `10.0.0.2`                    |
| `WG_DNS`              | DNS server (optional)         | `1.1.1.1`                     |
| `WG_PEER_PUBLIC_KEY`  | Peer public key               | `base64...`                   |
| `WG_PEER_ENDPOINT`    | Peer host:port (optional)     | `wireguard.example.com:51820` |
| `WG_PEER_ALLOWED_IPS` | Comma-separated CIDRs         | `10.0.0.0/24`                 |
| `WG_FORWARDS`         | Comma-separated forward rules | see below                     |

### `WG_FORWARDS` format

```text
proto:bindAddr:bindPort:remoteAddr:remotePort
```

Multiple rules separated by commas:

```bash
WG_FORWARDS=tcp:127.0.0.1:5432:10.0.0.1:5432,tcp:127.0.0.1:6379:10.0.0.1:6379,udp:127.0.0.1:5353:10.0.0.1:53
```

---

## Running

```bash
# From a config file
./wg-proxy -config wg-proxy.conf

# From environment variables (no config file needed)
export WG_PRIVATE_KEY=...
export WG_ADDRESS=10.0.0.2
export WG_PEER_PUBLIC_KEY=...
export WG_PEER_PRESHARED_KEY=...
export WG_PEER_ENDPOINT=wireguard.example.com:51820
export WG_FORWARDS=tcp:127.0.0.1:5432:10.0.0.1:5432
./wg-proxy
```

---

## Build

```bash
# Local
go build -o wg-proxy ./cmd/wg-proxy

# Static binary for Linux
CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o wg-proxy ./cmd/wg-proxy

# Docker
docker build -t wg-proxy .
```

---

## Generating keys

```bash
# Generate private key (base64, wg-quick compatible)
wg genkey | tee privatekey | wg pubkey > publickey
cat privatekey   # → paste as WG_PRIVATE_KEY
cat publickey    # → give to the server operator
```

---

## Using the forwards from bash

Once `wg-proxy` is running, every forward is just a local port:

```bash
# Postgres (through WireGuard to 10.0.0.1:5432)
psql postgresql://user:pass@127.0.0.1:5432/mydb

# Redis
redis-cli -h 127.0.0.1 -p 6379 ping

# MySQL
mysql -h 127.0.0.1 -P 3306 -u user -p

# DNS query through the tunnel
dig @127.0.0.1 -p 5353 internal.service.local

# Any TCP tool — nc, curl, ssh, etc.
curl http://127.0.0.1:8080/api
nc 127.0.0.1 9000
```

---

## Multiple peers

Add multiple `[Peer]` sections in the config file. Each peer's `AllowedIPs`
determines which remote addresses route through it. Environment variable mode
currently supports one peer; use a config file for multi-peer setups.

---

## Limitations

- **UDP sessions** are per source-address, with a 5-minute idle timeout
- **Arbitrary UDP** (any destination) is not supported — each remote must be
  declared explicitly as a forward rule
