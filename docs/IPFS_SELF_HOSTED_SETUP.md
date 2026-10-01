# Innova IPFS Gateway - Self-Hosted Setup Guide

## Overview

Innova's file sharing (Hyperfile) uses IPFS for decentralized storage. By default, wallets connect to `ipfs.innova-foundation.com:5001`. You can run your own IPFS gateway for maximum control, privacy, and no file size limits beyond the 10TB protocol maximum (`nyxmaxfilesize`).

### What is and is not encrypted

Two different paths share this gateway, and only one of them encrypts:

* **Chat attachments** (the messaging tab) are encrypted client-side with
  AES-256-GCM under a random per-file key before upload; the key travels inside
  the encrypted message, not through IPFS.
* **The Hyperfile tab and the `hyperfile*` RPCs upload in the clear.** There is
  no encryption on that path.

Uploads are not anonymous. The gateway you upload through — including the
Foundation default — sees your IP address, and the default gateway string
carries no URL scheme, so a stock wallet talks to it over plain HTTP. For
chunked uploads the manifest is pinned in cleartext and publishes the chunk CIDs
and the exact plaintext file size. Run your own gateway if any of that matters
to you.

## File Size Tiers

| Tier | Gateway | Max File Size | Chunk Size |
|------|---------|---------------|------------|
| Self-Hosted | Your own IPFS node | 10 TB | 1-4 MB (adaptive) |
| Innova Foundation | ipfs.innova-foundation.com | 10 TB | 1-4 MB (adaptive) |

There is no public fallback endpoint: `hyperfileip` must point at a reachable
IPFS API, or Hyperfile refuses to run.

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

Create `/etc/systemd/system/ipfs.service`:

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

    client_max_body_size 1100M;  # 10TB max via chunking, but individual requests are chunk-sized

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

Chat attachments and Hyperfile uploads are different paths (see above):

- **Chat attachments only** are AES-256-GCM encrypted client-side before
  upload — IPFS stores only ciphertext for that path. The key travels via
  smessage (E2E encrypted) and never touches IPFS. GCM authentication tags
  catch tampering, and chunked uploads use per-chunk nonces.
- **The Hyperfile tab and `hyperfile*` RPCs upload in the clear.** IPFS stores
  plaintext content for that path; run your own gateway if that matters to you.

## Architecture (chat-attachment encryption path)

Hyperfile tab/RPC uploads skip the encrypt/decrypt steps below and send
plaintext chunks directly.

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
