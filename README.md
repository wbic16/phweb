# phweb — an HTTPS web server written for phcc and phext

An **RFC Box run** over ietf.phext (task 33.7.8/8.8.13/9.7.9): a requirement
went in, a slice of the corpus came out (SLICE.md), code was composed from
the slice, and what the corpus or this build could not supply was recorded
as gaps (GAP.md) instead of being improvised.

**What it is:** a small HTTPS web server in portable C99 — written to be
compiled by **phcc** (Will's TinyCC fork) as well as a system `cc` — whose
native substrate is **phext** for *both* configuration and content. One
idea, two applications:

- **Configuration is a phext.** Every domain phweb serves is configured in
  a single `config.phext`; its scrolls are addressed by phext coordinate,
  and the coordinate tree mirrors the DNS tree (scheme below).
- **Content is phext streams.** A `.phext` resource *is* a stream of
  scrolls. The default response streams the scrolls one by one over
  HTTP/1.1 chunked transfer encoding, read incrementally from disk;
  HTTP/1.1 chunked streaming is how scrolls move.

**What it is not:** a production server. No HTTP/2 or HTTP/3, no ACME/EST
certificate management (self-signed test cert via `setup.sh`), no CGI or
scripting. See GAP.md for the full list, stated plainly.

## Files

| File | Contents |
|---|---|
| `phweb.c` | The whole server: TLS, HTTP/1.1, phext config, phext streaming |
| `Makefile` | `make` (system cc) or `make PHCC=1` (phcc) |
| `setup.sh` | Generates the self-signed test certificate into `certs/` |
| `config` | — configuration is `config.phext`; a worked example is `examples/config.phext` |
| `examples/` | Example config + two fixture sites (`www/`, `www-phext/`) |
| `test_phweb.py` | Non-interactive suite: 13 checks over HTTPS on localhost |
| `SLICE.md` | The corpus slice: RFCs, ietf.phext coordinates, statuses, implementation links |
| `GAP.md` | The gap record: phcc verification status, phext's non-IETF status, deferred work |

## Run

```sh
make                    # or: make PHCC=1
./setup.sh              # self-signed test cert -> certs/
./phweb -c examples/config.phext        # https://localhost:8443
python3 test_phweb.py   # full suite (uses its own fixtures + port)
```

Options: `-p port` (default 8443), `-c config.phext`, `-C cert.pem`,
`-K key.pem`. TLS is **1.3 only** (RFC 9846 — see SLICE.md for why the
number is 9846 and not 8446). The server forks per connection.

Reload configuration without restarting: `kill -HUP <pid>`, or from
localhost only, `GET /__phweb/reload` (which signals the parent process;
both paths run the same parent-side reload of `config.phext`).

## Configuring domains hierarchically via phext

phweb's entire domain configuration lives in **one phext file**,
`config.phext`. Phext coordinates are nine 1-indexed components,

```
library.shelf.series / collection.volume.book / chapter.section.scroll
```

addressed by delimiter bytes (0x01 Library, 0x1F Shelf, 0x1E Series,
0x1D Collection, 0x1C Volume, 0x1A Book, 0x19 Chapter, 0x18 Section,
0x17 Scroll), per the reference phext conventions (libphext). Hitting a
delimiter increments its level and resets all lower levels to 1.

The config scheme uses the **Volume** and **Chapter** dimensions to carry
the domain hierarchy:

| Coordinate | Scroll |
|---|---|
| `1.1.1/1.1.1/1.1.1` | **Root defaults** — apply to every host |
| `1.1.1/1.2.1/1.1.1` | First top-level domain (Volume 2) |
| `1.1.1/1.3.1/1.1.1` | Second top-level domain (Volume 3) |
| `1.1.1/1.2.1/2.1.1` | A **subdomain** of the domain at Volume 2 — Chapter 2 descends *inside* its parent domain's Volume |
| `1.1.1/1.2.1/2.1.2`, `…/3.1.1`, … | Further subdomains (Chapter 3), deeper nesting via Section/Scroll if ever needed |

So the coordinate tree *is* the DNS tree: a subdomain's scroll physically
sits inside its parent domain's Volume, one Chapter step down. The other
dimensions (Library/Shelf/Series/Collection/Book) stay at 1 in this
scheme and are reserved — e.g. a second Library for a second server
profile in the same file.

Each scroll is `key = value` lines (`#` comments; a `# domain: name`
comment also names the scroll):

```
domain = example.test        # or "(root)" on the root scroll
docroot = /srv/example       # directory served for this domain
index = index.html           # file served for a directory request
phext_stream = on            # off = .phext served whole-file only
```

**Lookup.** A request's `Host` walks the hierarchy: built-in defaults →
the root scroll → ancestor domains from the shallowest DNS suffix down
(`test`, then `example.test`) → the exact host (`sub.example.test`). Each
scroll overrides **only the fields it sets**, so a subdomain scroll that
sets only `docroot` inherits its parent domain's `index` and
`phext_stream`, which in turn inherit the root's. An unconfigured host is
served entirely from the root scroll's defaults.

## Serving content

Ordinary files are served whole with their content type. A directory
request serves the domain's configured `index` file (which may itself be
a `.phext` — a phext home page). `.phext` resources are native:

| Request | Response |
|---|---|
| `GET /notes.phext` | **Default: the scroll stream.** `Transfer-Encoding: chunked`; each scroll (content + its terminating delimiter) is flushed as its own chunk, in coordinate order, read incrementally from disk. Concatenating the chunks reproduces the file byte for byte. |
| `GET /notes.phext?whole=1` | The whole file, with `Content-Length` (the download form). Also used automatically for domains with `phext_stream = off`. |
| `GET /notes.phext@1.1.1/1.1.1/1.1.2` | **Coordinate addressing:** exactly that scroll's content (`text/plain; charset=utf-8`), found by an incremental scan. 404 if no scroll sits at the coordinate. `?coord=` works as a query-string equivalent. |
| `GET /notes.phext@toc` | The **scroll index, streamed**: one chunk per scroll — `coordinate <TAB> byte-count <TAB> first line`. |

Content types: `.html` → `text/html; charset=utf-8`; `.phext` and `.txt`
→ `text/plain; charset=utf-8` (phext is plain text at the byte level;
the scroll structure is carried by the delimiter bytes and the chunk
boundaries, not by a media type — there is no registered `…/phext` media
type, which is part of the gap recorded in GAP.md); common static types
(css/js/png/jpg/gif/svg) by extension; anything else
`application/octet-stream`.

HTTP behaviour (RFC 9110 / 9112): GET and HEAD, keep-alive, chunked
responses, `Host`-header virtual hosting, 400 for malformed or unsafe
paths (`..` components are rejected), 404 for missing files and missing
scrolls, 405 (with `Allow`) for other methods.
