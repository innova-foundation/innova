# Innova IPFS Gateway - Self-Hosted Setup Guide

## Overview

Innova's encrypted file sharing system (Hyperfile) uses IPFS for decentralized storage. By default, wallets connect to `ipfs.innova-foundation.com:5001`. You can run your own IPFS gateway for maximum control, privacy, and no file size limits beyond the 1TB protocol maximum.

## File Size Tiers

| Tier | Gateway | Max File Size | Chunk Size |
|------|---------|---------------|------------|
| Free | Infura (fallback) | 100 MB | 1 MB |
| Self-Hosted | Your own IPFS node | 10 TB | 1-4 MB (adaptive) |
| Innova Foundation | ipfs.innova-foundation.com | 10 TB | 1-4 MB (adaptive) |

## Quick Setup (Ubuntu/Debian)

### 1. Install IPFS

```bash
wget https://dist.ipfs.tech/kubo/v0.24.0/kubo_v0.24.0_linux-amd64.tar.gz
tar xvfz kubo_v0.24.0_linux-amd64.tar.gz
cd kubo && sudo bash install.sh
ipfs init
```

### 2. Configure for Innova Gateway Use

```bash
# Allow API access from external IPs (for wallet connections)
ipfs config Addresses.API /ip4/0.0.0.0/tcp/5001

# Set CORS headers for web access
ipfs config --json API.HTTPHeaders.Access-Control-Allow-Origin '["*"]'
ipfs config --json API.HTTPHeaders.Access-Control-Allow-Methods '["PUT", "POST", "GET"]'

# Increase upload limits for large files
ipfs config --json Datastore.StorageMax '"100GB"'

# Enable garbage collection (auto-cleanup of unpinned content)
ipfs config --json Datastore.GCPeriod '"1h"'
```

### 3. Run as a Service

Create `/etc/systemd/service/ipfs.service`:

```ini
[Unit]
Description=IPFS Daemon
After=network.target

[Service]
User=ipfs
ExecStart=/usr/local/bin/ipfs daemon --enable-gc
Restart=on-failure
RestartSec=5
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
```

```bash
sudo useradd -m -s /bin/bash ipfs
sudo -u ipfs ipfs init
sudo systemctl enable ipfs
sudo systemctl start ipfs
```

### 4. Optional: TLS Reverse Proxy (nginx)

For HTTPS on port 5001:

```nginx
server {
    listen 5001 ssl;
    server_name ipfs.yourdomain.com;

    ssl_certificate /etc/letsencrypt/live/ipfs.yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/ipfs.yourdomain.com/privkey.pem;

    client_max_body_size 1100M;  # 1TB chunked, but individual requests are chunk-sized

    location / {
        proxy_pass http://127.0.0.1:5001;
        proxy_set_header Host $host;
        proxy_read_timeout 300s;
    }
}
```

### 5. Configure Innova Wallets

Add to `innova.conf`:

```
hyperfilelocal=1
hyperfileip=your-server-ip:5001
```

Or for domain with TLS:
```
hyperfilelocal=1
hyperfileip=ipfs.yourdomain.com:5001
```

## Security Notes

- **All files are AES-256-GCM encrypted BEFORE upload** — IPFS stores only ciphertext
- **Encryption keys travel via smessage** (E2E encrypted) — never touch IPFS
- **GCM authentication tags** prevent tampering — modified files are rejected
- **Chunked uploads** split files into 1-4MB encrypted pieces with per-chunk nonces
- **No plaintext ever touches IPFS** — even if your IPFS node is compromised, files are unreadable

## Architecture

```
Sender Wallet                          IPFS Node                    Recipient Wallet
     |                                     |                              |
     |-- Encrypt file (AES-256-GCM) ------>|                              |
     |-- Upload chunk 1 ----------------->|                              |
     |-- Upload chunk 2 ----------------->|                              |
     |-- Upload manifest ---------------->|                              |
     |                                     |                              |
     |-- Send [file:CID:key:name:size] via smessage (E2E encrypted) ---->|
     |                                     |                              |
     |                                     |<-- Download manifest --------|
     |                                     |<-- Download chunk 1 ---------|
     |                                     |<-- Download chunk 2 ---------|
     |                                     |          Decrypt (AES-256-GCM)
```

## Monitoring

```bash
# Check IPFS status
ipfs id
ipfs stats repo
ipfs stats bw

# From Innova wallet RPC console
hyperfileversion
```
