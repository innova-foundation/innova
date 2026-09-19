#!/usr/bin/env python3
# Copyright (c) 2026 The Innova developers
# Distributed under the MIT/X11 software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""A SOCKS5 proxy for a regtest NullSend fleet with no Tor.

Mix endpoints must be v3 onion names and every mix exchange is dialed through SOCKS5 with
per-exchange username/password credentials. This answers that handshake and forwards each
connection to 127.0.0.1 at the port the caller asked for, whatever name it asked for, so a
fleet whose coordinator and directory listen on distinct local ports can run a round with
made-up onion names. It offers no isolation and no anonymity: it is for tests only.

    mix_socks_stub.py --port 19089
"""

import argparse
import socket
import struct
import threading


def recv_exact(sock, n):
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise ConnectionError("closed")
        data += chunk
    return data


def pipe(src, dst):
    try:
        while True:
            data = src.recv(65536)
            if not data:
                break
            dst.sendall(data)
    except OSError:
        pass
    finally:
        for s in (src, dst):
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass


def handle(client):
    try:
        ver, nmethods = recv_exact(client, 2)
        methods = recv_exact(client, nmethods)
        if ver != 5:
            return
        if 2 in methods:
            client.sendall(b"\x05\x02")
            sub = recv_exact(client, 2)
            recv_exact(client, sub[1])
            plen = recv_exact(client, 1)[0]
            recv_exact(client, plen)
            client.sendall(b"\x01\x00")
        elif 0 in methods:
            client.sendall(b"\x05\x00")
        else:
            client.sendall(b"\x05\xff")
            return
        ver, cmd, _, atyp = recv_exact(client, 4)
        if ver != 5 or cmd != 1:
            return
        if atyp == 3:
            recv_exact(client, recv_exact(client, 1)[0])
        elif atyp == 1:
            recv_exact(client, 4)
        elif atyp == 4:
            recv_exact(client, 16)
        else:
            return
        (port,) = struct.unpack(">H", recv_exact(client, 2))
        upstream = socket.create_connection(("127.0.0.1", port), timeout=10)
        upstream.settimeout(None)
        client.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
        threading.Thread(target=pipe, args=(upstream, client), daemon=True).start()
        pipe(client, upstream)
    except (OSError, ConnectionError):
        try:
            client.sendall(b"\x05\x01\x00\x01\x00\x00\x00\x00\x00\x00")
        except OSError:
            pass
    finally:
        try:
            client.close()
        except OSError:
            pass


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, required=True)
    args = parser.parse_args()
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", args.port))
    server.listen(64)
    while True:
        client, _ = server.accept()
        threading.Thread(target=handle, args=(client,), daemon=True).start()


if __name__ == "__main__":
    main()
