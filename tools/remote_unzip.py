#!/usr/bin/env python3
"""pull one member out of a remote IPSW without downloading all 12 GB."""
import io, sys, os, zipfile, urllib.request

URL = sys.argv[1]
WANT = sys.argv[2] if len(sys.argv) > 2 else "kernelcache"
OUT = sys.argv[3] if len(sys.argv) > 3 else "/tmp/" + WANT
CHUNK = 1 << 20

class HttpFile(io.RawIOBase):
    def __init__(self, url):
        self.url = url
        req = urllib.request.Request(url, method="HEAD")
        with urllib.request.urlopen(req, timeout=60) as r:
            self.size = int(r.headers["Content-Length"])
            self.ranges = r.headers.get("Accept-Ranges", "")
        self.pos = 0
        self.fetched = 0
        print(f"remote {self.size/1e9:.2f} GB ranges={self.ranges}")

    def readable(self): return True
    def seekable(self): return True

    def seek(self, off, whence=0):
        if whence == 0: self.pos = off
        elif whence == 1: self.pos += off
        else: self.pos = self.size + off
        return self.pos

    def tell(self): return self.pos

    def read(self, n=-1):
        if n is None or n < 0: n = self.size - self.pos
        if n == 0 or self.pos >= self.size: return b""
        end = min(self.pos + n, self.size) - 1
        req = urllib.request.Request(self.url, headers={"Range": f"bytes={self.pos}-{end}"})
        with urllib.request.urlopen(req, timeout=120) as r:
            data = r.read()
        self.fetched += len(data)
        self.pos += len(data)
        return data

    def readinto(self, b):
        data = self.read(len(b))
        b[:len(data)] = data
        return len(data)

h = HttpFile(URL)
zf = zipfile.ZipFile(io.BufferedReader(h, buffer_size=1 << 16))
names = zf.namelist()
print(f"{len(names)} members")
hits = [n for n in names if WANT in n]
for n in hits:
    i = zf.getinfo(n)
    print(f"  {n:<48} {i.file_size/1e6:9.1f} MB -> {i.compress_size/1e6:9.1f} MB")
if not hits:
    print("no match"); sys.exit(1)

pick = max(hits, key=lambda n: zf.getinfo(n).file_size)
print(f"extracting {pick}")
with zf.open(pick) as src, open(OUT, "wb") as dst:
    while True:
        b = src.read(CHUNK)
        if not b: break
        dst.write(b)
print(f"wrote {OUT} {os.path.getsize(OUT)/1e6:.1f} MB, fetched {h.fetched/1e6:.1f} MB over the wire")
