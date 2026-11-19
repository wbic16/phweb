#!/usr/bin/env python3
"""test_phweb.py — non-interactive suite for phweb.

Builds fixtures (a hierarchical config.phext with a parent domain, a
subdomain override, and root defaults; docroots with an .html page and a
multi-scroll .phext), starts the server on localhost, and asserts the
RFC Box contract.  Exit 0 iff every check passes.
"""
import os
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
RUN = os.path.join(HERE, "test", "run")
PORT = 18443
SCROLL, VOLUME = b"\x17", b"\x1c"

RESULTS = []


def check(name, ok, detail=""):
    RESULTS.append((name, ok))
    print(f"{'PASS' if ok else 'FAIL'}: {name}" + (f" — {detail}" if detail and not ok else ""))


def write(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    mode = "wb" if isinstance(data, bytes) else "w"
    with open(path, mode) as f:
        f.write(data)


def curl(host, path, extra=()):
    """HTTPS GET via curl with an explicit Host (SNI + Host header)."""
    args = ["curl", "-sk", "--noproxy", "*", "--max-time", "10",
            "--resolve", f"{host}:{PORT}:127.0.0.1",
            f"https://{host}:{PORT}{path}"] + list(extra)
    return subprocess.run(args, capture_output=True)


def raw_get(host, path):
    """One raw HTTPS request; returns (status, headers dict, [chunk payloads])."""
    ctx = ssl._create_unverified_context()
    with ctx.wrap_socket(socket.create_connection(("127.0.0.1", PORT)),
                         server_hostname=host) as s:
        s.sendall(f"GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode())
        raw = b""
        while True:
            try:
                chunk = s.recv(65536)
            except ssl.SSLError:
                break
            if not chunk:
                break
            raw += chunk
    head, _, body = raw.partition(b"\r\n\r\n")
    lines = head.decode("iso-8859-1").split("\r\n")
    status = int(lines[0].split()[1])
    headers = {}
    for ln in lines[1:]:
        if ": " in ln:
            k, v = ln.split(": ", 1)
            headers[k.lower()] = v
    chunks = []
    if headers.get("transfer-encoding") == "chunked":
        rest = body
        while True:
            size_line, _, rest = rest.partition(b"\r\n")
            n = int(size_line.split(b";")[0], 16)
            if n == 0:
                break
            chunks.append(rest[:n])
            rest = rest[n + 2:]
    else:
        chunks = [body] if body else []
    return status, headers, chunks


def main():
    if os.path.exists(RUN):
        shutil.rmtree(RUN)
    os.makedirs(RUN)

    # --- fixtures -----------------------------------------------------
    write(f"{RUN}/root-www/index.html", "<h1>ROOT DEFAULT HOME</h1>\n")
    write(f"{RUN}/example-www/index.html", "<h1>EXAMPLE HOME</h1>\n")
    write(f"{RUN}/sub-www/index.html", "<h1>SUB OVERRIDE HOME</h1>\n")

    s1 = b"scroll one text\n"
    s2 = b"scroll two text\n"
    s3 = b"scroll three text\n"
    phext_bytes = s1 + SCROLL + s2 + VOLUME + s3
    write(f"{RUN}/root-www/data.phext", phext_bytes)

    root_scroll = (
        b"domain = (root)\n"
        b"docroot = " + f"{RUN}/root-www".encode() + b"\n"
        b"index = index.html\n"
        b"phext_stream = on\n"
    )
    example_scroll = (
        b"domain = example.test\n"
        b"docroot = " + f"{RUN}/example-www".encode() + b"\n"
        b"index = index.html\n"
    )
    # subdomain scroll lives one Volume later in this fixture; the
    # hierarchy that matters is the DNS walk (sub inherits from example,
    # which inherits from root) — sub sets ONLY its docroot.
    sub_scroll = (
        b"domain = sub.example.test\n"
        b"docroot = " + f"{RUN}/sub-www".encode() + b"\n"
    )
    config_path = f"{RUN}/config.phext"
    write(config_path, root_scroll + VOLUME + example_scroll + VOLUME + sub_scroll)

    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048",
                    "-keyout", f"{RUN}/key.pem", "-out", f"{RUN}/cert.pem",
                    "-days", "2", "-nodes", "-subj", "/CN=localhost",
                    "-addext", "subjectAltName=DNS:localhost,DNS:*.test,IP:127.0.0.1"],
                   check=True, capture_output=True)

    # --- start the server ---------------------------------------------
    proc = subprocess.Popen(
        [os.path.join(HERE, "phweb"), "-p", str(PORT), "-c", config_path,
         "-C", f"{RUN}/cert.pem", "-K", f"{RUN}/key.pem"],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    try:
        deadline = time.time() + 10
        up = False
        while time.time() < deadline:
            try:
                socket.create_connection(("127.0.0.1", PORT), 0.25).close()
                up = True
                break
            except OSError:
                if proc.poll() is not None:
                    break
                time.sleep(0.1)
        check("server starts on localhost", up)
        if not up:
            print(proc.stdout.read() if proc.stdout else "")
            return 1

        # (a) https GET of the html page returns its content
        r = curl("example.test", "/")
        check("(a) https GET html page (example.test)",
              r.returncode == 0 and b"EXAMPLE HOME" in r.stdout)

        # (b) Host: subdomain returns the SUBDOMAIN's content (override)
        r = curl("sub.example.test", "/")
        check("(b) subdomain Host overrides parent docroot",
              b"SUB OVERRIDE HOME" in r.stdout)

        # (c) unknown Host falls back to root defaults
        r = curl("unknown.test", "/")
        check("(c) unknown Host falls back to root defaults",
              b"ROOT DEFAULT HOME" in r.stdout)

        # (d) phext scroll selection returns exactly that scroll
        r = curl("unknown.test", "/data.phext@1.1.1/1.1.1/1.1.2")
        check("(d) /data.phext@1.1.1/1.1.1/1.1.2 returns scroll 2 exactly",
              r.stdout == s2, f"got {r.stdout!r}")

        # (e) DEFAULT .phext GET is the chunked scroll stream:
        #     chunked encoding, byte-identical reassembly, and the
        #     first chunk is scroll 1 (content + its delimiter),
        #     i.e. streaming order is coordinate order.
        status, headers, chunks = raw_get("unknown.test", "/data.phext")
        check("(e1) default .phext GET uses Transfer-Encoding: chunked",
              status == 200 and headers.get("transfer-encoding") == "chunked")
        check("(e2) streamed chunks reassemble byte-identical to source",
              b"".join(chunks) == phext_bytes)
        check("(e3) first chunk is scroll 1 (stream order = coordinate order)",
              len(chunks) >= 1 and chunks[0] == s1 + SCROLL,
              f"first chunk {chunks[0]!r}" if chunks else "no chunks")

        # (f) 404 for a missing path
        r = curl("example.test", "/nope.html", ["-o", "/dev/null", "-w", "%{http_code}"])
        check("(f) missing path returns 404", r.stdout.strip() == b"404")

        # (g) SIGHUP reload: repoint example.test at sub-www and reload
        example_scroll2 = example_scroll.replace(
            f"{RUN}/example-www".encode(), f"{RUN}/sub-www".encode())
        write(config_path, root_scroll + VOLUME + example_scroll2 + VOLUME + sub_scroll)
        os.kill(proc.pid, signal.SIGHUP)
        reloaded = False
        for _ in range(30):
            time.sleep(0.1)
            if b"SUB OVERRIDE HOME" in curl("example.test", "/").stdout:
                reloaded = True
                break
        check("(g) SIGHUP reloads config.phext without restart", reloaded)

        # (h) POST is refused 405
        r = subprocess.run(["curl", "-sk", "--noproxy", "*", "--max-time", "10",
                            "-X", "POST",
                            "--resolve", f"example.test:{PORT}:127.0.0.1",
                            f"https://example.test:{PORT}/", "-o", "/dev/null",
                            "-w", "%{http_code}"], capture_output=True)
        check("(h) POST returns 405", r.stdout.strip() == b"405")

        # (i) TOC request streams the scroll index
        r = curl("unknown.test", "/data.phext@toc")
        check("(i) /data.phext@toc lists all three coordinates",
              all(c in r.stdout for c in
                  (b"1.1.1/1.1.1/1.1.1", b"1.1.1/1.1.1/1.1.2", b"1.1.1/1.2.1/1.1.1")),
              f"got {r.stdout!r}")

        # (j) ?whole=1 returns the file whole, with Content-Length
        status, headers, chunks = raw_get("unknown.test", "/data.phext?whole=1")
        check("(j) ?whole=1 returns whole file with Content-Length",
              status == 200 and "content-length" in headers and
              b"".join(chunks) == phext_bytes)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()

    failed = [n for n, ok in RESULTS if not ok]
    print()
    if failed:
        print(f"TEST RESULT: FAIL ({len(failed)} check(s): {', '.join(failed)})")
        return 1
    print(f"TEST RESULT: PASS (all {len(RESULTS)} checks)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
