# GAP.md — RFC-Box gap record: phweb

**Gap ID:** GAP-PHWEB-001 · **Opened by:** RFC Box run 33.7.8/8.8.13/9.7.9 (2026-11-18)
**Severity for this build:** documented limitations — the server is functional and its tests pass; the gaps block production and conformance claims, not the demonstration.

## Gap 1 — phcc build verification is DEFERRED (not done)

- phweb is *written for* phcc: portable C99, no GNU extensions (portable substitutes are used where glibc habits would creep in — e.g. a hand-rolled case-insensitive substring search instead of `strcasestr`), a single translation unit, and a Makefile with a `PHCC=1` switch that swaps `cc` for `phcc`.
- **But the phcc build has not been run.** Neither `phcc` nor `tcc` exists on this machine (checked 2026-11-18: PATH and `/usr/bin` carry neither), so the only verified build is the system compiler: `cc (Ubuntu 13.3.0) … -std=c99 -Wall -Wextra`, clean except two benign `snprintf` truncation warnings, since fixed.
- **REQ-PHWEB-1:** on a machine with phcc installed, run `make PHCC=1` and then the full test suite against the phcc-built binary; record the result here. Until then, "builds under phcc" is a design claim, not a verified fact.

## Gap 2 — phext is not an IETF standard

- The corpus standardizes the pipe, not the payload. HTTP/1.1 chunked transfer coding (RFC 9112 §7.1) is a standard; **phext itself is Will's format**, specified by the phext reference material (`~/workspace/phext/`, libphext conventions), and appears in no RFC. The same class of gap as the IKI run's TIA-102 absence and the browser run's WHATWG/HTML absence.
- Consequences recorded plainly: there is no registered media type for phext (phweb serves `.phext` as `text/plain; charset=utf-8` and carries scroll structure in delimiter bytes + chunk boundaries); the coordinate-addressing URL form (`/file.phext@<coordinate>`, `@toc`) is a phweb convention, not a standard; the config.phext hierarchy scheme (Volume = domain, Chapter = subdomain) is phweb's own allocation of the phext dimensions.
- **REQ-PHWEB-2:** if phext-over-HTTP interop with other implementations (e.g. the sibling terminal browser's phext mode, task 51.6.7/6.5.9/4.5.11) matters, pin these conventions in a written profile both sides test against.

## Gap 3 — HTTP/2 and HTTP/3 are absent

- The corpus holds both (9113 at 1.1.1/1.2.1/1.1.9113, canonical nghttp2; 9114 + QUIC 9000/9001/9002 at 1.1.1/1.2.1/1.1.9114, …9000–9002). phweb speaks HTTP/1.1 only, and enforces TLS 1.3 with no ALPN, so HTTP/2 negotiation never begins.
- **REQ-PHWEB-3:** HTTP/2 via the corpus's canonical nghttp2 if a second protocol is ever required; HTTP/3 is a larger step (a QUIC stack) and should be its own RFC Box run.

## Gap 4 — production certificate management is absent

- `setup.sh` makes a self-signed test certificate. There is no enrollment, renewal, or revocation: no ACME (RFC 8555, 1.1.1/1.2.1/1.1.8555; corpus canonical: Certbot), no EST (RFC 7030, 1.1.1/1.2.1/1.1.7030), no OCSP (RFC 6960).
- **REQ-PHWEB-4:** for any deployment beyond a lab bench, integrate ACME issuance/renewal and reload-on-renewal (the SIGHUP path already exists for config; certificates load only at startup today — certificate reload rides the same hook when this is built).

## Gap 5 — HTTP caching (RFC 9111) is not implemented

- Verified in the corpus (1.1.1/1.2.1/1.1.9111, INTERNET STANDARD) and deliberately deferred: phweb sends no `ETag`/`Last-Modified` and does not answer conditional requests (`If-Modified-Since` / `If-None-Match` → 304).
- **REQ-PHWEB-5:** add validators derived from file mtime/size and conditional-request handling; small, self-contained, and the natural next slice addition.

## Smaller recorded limits

- **Scroll-size bound:** streaming is incremental at the *file* level (the server starts responding without holding the file in memory), but a single scroll is buffered up to a 64 KiB flush threshold before its chunk is emitted; a scroll is never split except at that threshold.
- **One process per connection (fork), no TLS session resumption tuning, no SNI-based certificate selection** — the certificate is global; virtual hosting is by `Host` header only, which is the RFC 9110 model but means one cert must cover all domains (the test cert uses wildcard SANs).
- **Config reload replaces configuration wholesale**; a malformed new `config.phext` (unreadable file) keeps the old configuration only if the file cannot be opened — a parseable-but-wrong file takes effect. There is no config validation pass yet.
- **Range requests** (`Range:`) are not implemented for whole-file responses; the phext-native equivalents are coordinate selection and the TOC.

## Status

Gaps recorded and carried on task 33.7.8/8.8.13/9.7.9. Nothing in this build depends on closing them; every production claim does.
