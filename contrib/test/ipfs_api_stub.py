#!/usr/bin/env python3
"""Minimal stand-in for the Kubo /api/v0 HTTP surface the in-tree ipfs client uses.

Implements add / version / id / block/stat / block/get. `add` computes the real
CIDv0 (unixfs single-chunk dag-pb, sha2-256, base58btc), so what the daemon
stamps is the CID a real kubo would return for the same small file.
"""
import hashlib
import http.server
import json
import re
import sys

B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58encode(raw: bytes) -> str:
    n = int.from_bytes(raw, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = B58[r] + out
    for b in raw:
        if b:
            break
        out = "1" + out
    return out


def varint(n: int) -> bytes:
    out = b""
    while True:
        b = n & 0x7F
        n >>= 7
        out += bytes([b | (0x80 if n else 0)])
        if not n:
            return out


def unixfs_file(data: bytes) -> bytes:
    # Type=2 (File), Data, filesize
    out = b"\x08\x02"
    if data:
        out += b"\x12" + varint(len(data)) + data
    out += b"\x18" + varint(len(data))
    return out


def dagpb_cidv0(data: bytes) -> str:
    node = unixfs_file(data)
    pbnode = b"\x0a" + varint(len(node)) + node
    mh = b"\x12\x20" + hashlib.sha256(pbnode).digest()
    return b58encode(mh)


BLOCKS = {}


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        sys.stderr.write("stub %s\n" % (fmt % args))

    def _send(self, body: bytes, ctype="application/json"):
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        path = self.path.split("?")[0]
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length) if length else b""

        if path.endswith("/api/v0/add"):
            name, content = self._parse_multipart(body)
            cid = dagpb_cidv0(content)
            BLOCKS[cid] = content
            lines = (
                json.dumps({"Name": name, "Bytes": len(content)})
                + "\n"
                + json.dumps({"Name": name, "Hash": cid, "Size": str(len(content))})
                + "\n"
            )
            self._send(lines.encode())
            return

        if path.endswith("/api/v0/version"):
            self._send(json.dumps({"Version": "0.99.0-stub", "Commit": "stub"}).encode())
            return

        if path.endswith("/api/v0/id"):
            self._send(json.dumps({
                "ID": "12D3KooWStubStubStubStubStubStubStubStubStubStubStub",
                "Addresses": ["/ip4/127.0.0.1/tcp/4001"],
                "PublicKey": "CAESIHN0dWI=",
            }).encode())
            return

        if path.endswith("/api/v0/block/stat"):
            arg = self._arg()
            self._send(json.dumps({"Key": arg, "Size": len(BLOCKS.get(arg, b""))}).encode())
            return

        if path.endswith("/api/v0/block/get"):
            self._send(BLOCKS.get(self._arg(), b""), "application/octet-stream")
            return

        self.send_error(404, "no stub for %s" % path)

    def _arg(self):
        m = re.search(r"[?&]arg=([^&]*)", self.path)
        return m.group(1) if m else ""

    def _parse_multipart(self, body: bytes):
        ctype = self.headers.get("Content-Type", "")
        m = re.search(r'boundary="?([^";]+)"?', ctype)
        if not m:
            return "file", body
        sep = ("--" + m.group(1)).encode()
        for part in body.split(sep):
            if b"\r\n\r\n" not in part:
                continue
            head, rest = part.split(b"\r\n\r\n", 1)
            fm = re.search(rb'filename="([^"]*)"', head)
            if not fm:
                continue
            data = rest
            if data.endswith(b"\r\n"):
                data = data[:-2]
            return fm.group(1).decode(), data
        return "file", body


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 5001
    # self-check against the well-known empty-file CID
    assert dagpb_cidv0(b"") == "QmbFMke1KXqnYyBBWxB74N4c5SBnJMVAiMNRcGu6x1AwQH", dagpb_cidv0(b"")
    http.server.ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()
