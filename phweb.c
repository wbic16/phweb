/*
 * phweb — an HTTPS web server written for phcc and phext.
 *
 * phweb's native substrate is phext, for both configuration and content:
 *   - The domain configuration lives in one phext file (config.phext) whose
 *     scrolls mirror the DNS hierarchy (see README.md for the scheme).
 *   - A .phext resource IS a stream of scrolls: the default response is the
 *     scrolls streamed one by one over HTTP/1.1 chunked encoding, read
 *     incrementally from disk.  A single scroll is addressed by coordinate
 *     (/file.phext@1.1.1/1.1.1/1.1.1); /file.phext@toc streams the index.
 *
 * Substrate (ietf.phext slice, see SLICE.md): HTTP Semantics (RFC 9110),
 * HTTP/1.1 (RFC 9112), TLS 1.3 (RFC 9846), X.509 PKI (RFC 5280),
 * URI (RFC 3986).  TLS is provided by OpenSSL (the corpus's canonical
 * implementation for RFC 9846 / RFC 5280).
 *
 * Portable C99, no GNU extensions, so phcc (a TinyCC fork) can build it:
 *   cc -std=c99 -O2 -o phweb phweb.c -lssl -lcrypto
 */
#define _POSIX_C_SOURCE 200809L

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <netinet/in.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define PHWEB_VERSION "0.1"
#define MAX_LINE 8192
#define MAX_DOMAINS 1024
#define STREAM_FLUSH_AT 65536

/* ------------------------------------------------------------------ */
/* small helpers                                                       */
/* ------------------------------------------------------------------ */

static void *xmalloc(size_t n) {
    void *p = malloc(n ? n : 1);
    if (!p) { fprintf(stderr, "phweb: out of memory\n"); exit(1); }
    return p;
}

static void *xrealloc(void *p, size_t n) {
    void *q = realloc(p, n ? n : 1);
    if (!q) { fprintf(stderr, "phweb: out of memory\n"); exit(1); }
    return q;
}

static char *xstrdup(const char *s) {
    char *p = strdup(s);
    if (!p) { fprintf(stderr, "phweb: out of memory\n"); exit(1); }
    return p;
}

static char *dup_range(const char *s, size_t n) {
    char *p = xmalloc(n + 1);
    memcpy(p, s, n);
    p[n] = '\0';
    return p;
}

static void trim(char *s) {
    size_t n = strlen(s), i = 0;
    while (n > 0 && isspace((unsigned char)s[n - 1])) s[--n] = '\0';
    while (s[i] && isspace((unsigned char)s[i])) i++;
    if (i) memmove(s, s + i, strlen(s + i) + 1);
}

static void lower_str(char *s) {
    for (; *s; s++) *s = (char)tolower((unsigned char)*s);
}

/* case-insensitive substring search (portable strcasestr substitute) */
static int ci_contains(const char *hay, const char *needle) {
    size_t nl = strlen(needle), i;
    if (!nl) return 1;
    for (; *hay; hay++)
        if (!strncasecmp(hay, needle, nl)) return 1;
    (void)i;
    return 0;
}

typedef struct {
    unsigned char *data;
    size_t len, cap;
} DynBuf;

static void db_put(DynBuf *b, unsigned char c) {
    if (b->len + 1 > b->cap) {
        b->cap = b->cap ? b->cap * 2 : 256;
        b->data = xrealloc(b->data, b->cap);
    }
    b->data[b->len++] = c;
}

/* ------------------------------------------------------------------ */
/* phext: delimiters and coordinates (reference conventions)           */
/*                                                                     */
/* Delimiter hierarchy, highest to lowest (libphext):                  */
/*   0x01 Library, 0x1F Shelf, 0x1E Series, 0x1D Collection,           */
/*   0x1C Volume, 0x1A Book, 0x19 Chapter, 0x18 Section, 0x17 Scroll   */
/* A coordinate is nine 1-indexed components written                   */
/*   library.shelf.series/collection.volume.book/chapter.section.scroll*/
/* Hitting a delimiter increments its level and resets lower levels.   */
/* ------------------------------------------------------------------ */

static const unsigned char kDelim[9] =
    { 0x01, 0x1F, 0x1E, 0x1D, 0x1C, 0x1A, 0x19, 0x18, 0x17 };

static int delim_level(int c) {
    int i;
    for (i = 0; i < 9; i++)
        if (c == kDelim[i]) return i;
    return -1;
}

static void coord_format(const int coord[9], char *out, size_t cap) {
    snprintf(out, cap, "%d.%d.%d/%d.%d.%d/%d.%d.%d",
             coord[0], coord[1], coord[2], coord[3], coord[4], coord[5],
             coord[6], coord[7], coord[8]);
}

static void coord_advance(int coord[9], int level) {
    int j;
    coord[level] += 1;
    for (j = level + 1; j < 9; j++) coord[j] = 1;
}

/* One scroll of a parsed phext held in memory (used for config.phext). */
typedef struct {
    char coord[64];
    const unsigned char *ptr;
    size_t len;
} Scroll;

static size_t phext_parse(const unsigned char *data, size_t len,
                          Scroll *out, size_t max) {
    int coord[9] = { 1, 1, 1, 1, 1, 1, 1, 1, 1 };
    size_t n = 0, start = 0, i;
    for (i = 0; i < len; i++) {
        int lvl = delim_level(data[i]);
        if (lvl >= 0) {
            if (n < max) {
                coord_format(coord, out[n].coord, sizeof out[n].coord);
                out[n].ptr = data + start;
                out[n].len = i - start;
                n++;
            }
            coord_advance(coord, lvl);
            start = i + 1;
        }
    }
    if (start < len && n < max) {
        coord_format(coord, out[n].coord, sizeof out[n].coord);
        out[n].ptr = data + start;
        out[n].len = len - start;
        n++;
    }
    return n;
}

/* ------------------------------------------------------------------ */
/* configuration: domains configured hierarchically via phext          */
/*                                                                     */
/* config.phext layout (documented in README.md):                      */
/*   scroll 1.1.1/1.1.1/1.1.1            root defaults                 */
/*   scroll 1.1.1/1.2.1/1.1.1            first domain                  */
/*   scroll 1.1.1/1.3.1/1.1.1            second domain                 */
/*   scroll 1.1.1/1.2.1/2.1.1            a subdomain of the domain at  */
/*                                       1.1.1/1.2.1/1.1.1 (Chapter    */
/*                                       descends inside its Volume)   */
/* Volume (middle component) enumerates top-level domains; Chapter     */
/* enumerates subdomains within their parent domain's Volume, so the   */
/* coordinate tree mirrors the DNS tree.  A lookup walks root ->       */
/* ancestor domains -> the exact host, each scroll overriding only     */
/* the fields it sets.                                                 */
/* ------------------------------------------------------------------ */

typedef struct {
    char *name;     /* lowercase domain; "" = root defaults scroll */
    char *docroot;  /* NULL if unset */
    char *index;    /* NULL if unset */
    int stream;     /* -1 unset, 0 off, 1 on */
} Domain;

static Domain g_domains[MAX_DOMAINS];
static size_t g_ndomains = 0;
static char g_config_path[PATH_MAX] = "config.phext";

static void free_config(void) {
    size_t i;
    for (i = 0; i < g_ndomains; i++) {
        free(g_domains[i].name);
        free(g_domains[i].docroot);
        free(g_domains[i].index);
    }
    g_ndomains = 0;
}

static void apply_kv(Domain *d, char *key, char *val) {
    trim(key);
    trim(val);
    lower_str(key);
    if (!strcmp(key, "domain")) {
        lower_str(val);
        if (!strcmp(val, "(root)") || !strcmp(val, "root") ||
            !strcmp(val, "*") || !strcmp(val, "default"))
            val = (char *)"";
        free(d->name);
        d->name = xstrdup(val);
    } else if (!strcmp(key, "docroot")) {
        free(d->docroot);
        d->docroot = xstrdup(val);
    } else if (!strcmp(key, "index") || !strcmp(key, "default_index")) {
        free(d->index);
        d->index = xstrdup(val);
    } else if (!strcmp(key, "phext_stream") || !strcmp(key, "stream")) {
        lower_str(val);
        d->stream = (!strcmp(val, "on") || !strcmp(val, "true") ||
                     !strcmp(val, "yes") || !strcmp(val, "1")) ? 1 : 0;
    }
    /* unknown keys are ignored by design */
}

static void parse_domain_scroll(const unsigned char *text, size_t len) {
    Domain *d;
    char *copy, *save = NULL, *line;
    if (g_ndomains >= MAX_DOMAINS) return;
    d = &g_domains[g_ndomains];
    d->name = xstrdup("");
    d->docroot = NULL;
    d->index = NULL;
    d->stream = -1;

    copy = dup_range((const char *)text, len);
    for (line = strtok_r(copy, "\n", &save); line;
         line = strtok_r(NULL, "\n", &save)) {
        char *p = line;
        while (*p == ' ' || *p == '\t' || *p == '\r') p++;
        if (*p == '#') {
            /* a "# domain: name" comment also names the scroll's domain */
            p++;
            while (*p == ' ' || *p == '\t') p++;
            if (!strncasecmp(p, "domain", 6)) {
                char *v = p + 6;
                while (*v == ' ' || *v == '\t' || *v == ':' || *v == '=') v++;
                apply_kv(d, (char *)"domain", v);
            }
            continue;
        }
        if (!*p) continue;
        {
            char *eq = strchr(p, '=');
            char *co = strchr(p, ':');
            char *sep = eq ? eq : co;
            if (sep) {
                *sep = '\0';
                apply_kv(d, p, sep + 1);
            }
        }
    }
    free(copy);
    g_ndomains++;
}

static int load_config(const char *path) {
    FILE *f = fopen(path, "rb");
    unsigned char *data;
    long size;
    Scroll *scrolls;
    size_t i, n;

    if (!f) {
        fprintf(stderr, "phweb: cannot open config %s: %s\n",
                path, strerror(errno));
        return -1;
    }
    fseek(f, 0, SEEK_END);
    size = ftell(f);
    fseek(f, 0, SEEK_SET);
    data = xmalloc((size_t)size + 1);
    if (size > 0 && fread(data, 1, (size_t)size, f) != (size_t)size) {
        fprintf(stderr, "phweb: short read on %s\n", path);
        fclose(f);
        free(data);
        return -1;
    }
    fclose(f);

    scrolls = xmalloc(sizeof(Scroll) * (size_t)(size + 2));
    n = phext_parse(data, (size_t)size, scrolls, (size_t)(size + 2));

    free_config();
    for (i = 0; i < n; i++)
        parse_domain_scroll(scrolls[i].ptr, scrolls[i].len);

    free(scrolls);
    free(data);
    fprintf(stderr, "phweb: loaded %s (%lu domain scrolls)\n",
            path, (unsigned long)g_ndomains);
    return 0;
}

static const Domain *find_domain(const char *name) {
    size_t i;
    for (i = 0; i < g_ndomains; i++)
        if (!strcmp(g_domains[i].name, name)) return &g_domains[i];
    return NULL;
}

typedef struct {
    char docroot[PATH_MAX];
    char index[256];
    int stream;
} Effective;

static void apply_domain(const Domain *d, Effective *eff) {
    if (!d) return;
    if (d->docroot) snprintf(eff->docroot, sizeof eff->docroot, "%s", d->docroot);
    if (d->index) snprintf(eff->index, sizeof eff->index, "%s", d->index);
    if (d->stream >= 0) eff->stream = d->stream;
}

/* Walk the hierarchy: built-in defaults -> root scroll -> ancestor
 * domains from the shallowest suffix down to the exact host.  Each
 * scroll overrides only the fields it sets, so a subdomain inherits
 * from its parent domain unless it says otherwise. */
static void effective_config(const char *host, Effective *eff) {
    char hbuf[512];
    const char *starts[64];
    int ns = 0, i;
    const char *p;

    snprintf(eff->docroot, sizeof eff->docroot, "%s", "www");
    snprintf(eff->index, sizeof eff->index, "%s", "index.html");
    eff->stream = 1;

    apply_domain(find_domain(""), eff);

    snprintf(hbuf, sizeof hbuf, "%s", host);
    lower_str(hbuf);
    if (!*hbuf) return;
    starts[ns++] = hbuf;
    for (p = hbuf; *p && ns < 64; p++)
        if (*p == '.') starts[ns++] = p + 1;
    for (i = ns - 1; i >= 0; i--)
        apply_domain(find_domain(starts[i]), eff);
}

/* ------------------------------------------------------------------ */
/* TLS transport                                                       */
/* ------------------------------------------------------------------ */

static int ssl_write_all(SSL *ssl, const void *data, size_t len) {
    const unsigned char *p = (const unsigned char *)data;
    while (len > 0) {
        int chunk = len > 16384 ? 16384 : (int)len;
        int n = SSL_write(ssl, p, chunk);
        if (n <= 0) return -1;
        p += n;
        len -= (size_t)n;
    }
    return 0;
}

static int ssl_puts(SSL *ssl, const char *s) {
    return ssl_write_all(ssl, s, strlen(s));
}

/* buffered line reader over SSL */
typedef struct {
    SSL *ssl;
    unsigned char buf[16384];
    size_t pos, fill;
} Reader;

static int reader_getc(Reader *r) {
    if (r->pos >= r->fill) {
        int n = SSL_read(r->ssl, r->buf, sizeof r->buf);
        if (n <= 0) return -1;
        r->pos = 0;
        r->fill = (size_t)n;
    }
    return r->buf[r->pos++];
}

static int reader_gets(Reader *r, char *out, size_t cap) {
    size_t n = 0;
    int c;
    while (n + 1 < cap) {
        c = reader_getc(r);
        if (c < 0) {
            if (n == 0) return -1;
            break;
        }
        if (c == '\n') break;
        if (c != '\r') out[n++] = (char)c;
    }
    out[n] = '\0';
    return (int)n;
}

static void reader_discard(Reader *r, long n) {
    while (n-- > 0)
        if (reader_getc(r) < 0) return;
}

/* ------------------------------------------------------------------ */
/* HTTP responses                                                      */
/* ------------------------------------------------------------------ */

static const char *reason_phrase(int code) {
    switch (code) {
        case 200: return "OK";
        case 400: return "Bad Request";
        case 403: return "Forbidden";
        case 404: return "Not Found";
        case 405: return "Method Not Allowed";
        case 500: return "Internal Server Error";
        default:  return "Status";
    }
}

/* content_length < 0 selects chunked transfer encoding. */
static void send_head(SSL *ssl, int code, const char *ctype,
                      long content_length, int keep_alive,
                      const char *extra) {
    char buf[2048];
    char date[64];
    time_t t = time(NULL);
    struct tm tmv;
    gmtime_r(&t, &tmv);
    strftime(date, sizeof date, "%a, %d %b %Y %H:%M:%S GMT", &tmv);
    snprintf(buf, sizeof buf,
             "HTTP/1.1 %d %s\r\n"
             "Date: %s\r\n"
             "Server: phweb/%s\r\n"
             "Connection: %s\r\n",
             code, reason_phrase(code), date, PHWEB_VERSION,
             keep_alive ? "keep-alive" : "close");
    ssl_puts(ssl, buf);
    if (ctype) {
        snprintf(buf, sizeof buf, "Content-Type: %s\r\n", ctype);
        ssl_puts(ssl, buf);
    }
    if (content_length >= 0) {
        snprintf(buf, sizeof buf, "Content-Length: %ld\r\n", content_length);
        ssl_puts(ssl, buf);
    } else {
        ssl_puts(ssl, "Transfer-Encoding: chunked\r\n");
    }
    if (extra) ssl_puts(ssl, extra);
    ssl_puts(ssl, "\r\n");
}

static void send_error(SSL *ssl, int code, int is_head, int keep_alive) {
    char body[128];
    const char *extra = (code == 405) ? "Allow: GET, HEAD\r\n" : NULL;
    snprintf(body, sizeof body, "%d %s\n", code, reason_phrase(code));
    send_head(ssl, code, "text/plain; charset=utf-8",
              (long)strlen(body), keep_alive, extra);
    if (!is_head) ssl_puts(ssl, body);
}

static void send_chunk(SSL *ssl, const void *data, size_t len) {
    char hdr[32];
    if (len == 0) return;
    snprintf(hdr, sizeof hdr, "%zx\r\n", len);
    ssl_puts(ssl, hdr);
    ssl_write_all(ssl, data, len);
    ssl_puts(ssl, "\r\n");
}

static void send_final_chunk(SSL *ssl) {
    ssl_puts(ssl, "0\r\n\r\n");
}

/* ------------------------------------------------------------------ */
/* file helpers                                                        */
/* ------------------------------------------------------------------ */

static const char *content_type(const char *path) {
    const char *dot = strrchr(path, '.');
    if (!dot) return "application/octet-stream";
    if (!strcasecmp(dot, ".html") || !strcasecmp(dot, ".htm"))
        return "text/html; charset=utf-8";
    if (!strcasecmp(dot, ".phext")) return "text/plain; charset=utf-8";
    if (!strcasecmp(dot, ".txt")) return "text/plain; charset=utf-8";
    if (!strcasecmp(dot, ".css")) return "text/css";
    if (!strcasecmp(dot, ".js")) return "text/javascript";
    if (!strcasecmp(dot, ".png")) return "image/png";
    if (!strcasecmp(dot, ".jpg") || !strcasecmp(dot, ".jpeg"))
        return "image/jpeg";
    if (!strcasecmp(dot, ".gif")) return "image/gif";
    if (!strcasecmp(dot, ".svg")) return "image/svg+xml";
    return "application/octet-stream";
}

static int ends_with(const char *s, const char *suffix) {
    size_t a = strlen(s), b = strlen(suffix);
    return a >= b && !strcasecmp(s + a - b, suffix);
}

static void url_decode(char *s) {
    char *r = s, *w = s;
    while (*r) {
        if (*r == '%' && isxdigit((unsigned char)r[1]) &&
            isxdigit((unsigned char)r[2])) {
            char hex[3] = { r[1], r[2], '\0' };
            *w++ = (char)strtol(hex, NULL, 16);
            r += 3;
        } else {
            *w++ = *r++;
        }
    }
    *w = '\0';
}

static int path_is_safe(const char *path) {
    const char *p = path;
    if (path[0] != '/') return 0;
    while (1) {
        const char *slash = strchr(p, '/');
        size_t n = slash ? (size_t)(slash - p) : strlen(p);
        if ((n == 2 && !strncmp(p, "..", 2)) ||
            (n == 1 && p[0] == '.'))
            return 0;
        if (!slash) return 1;
        p = slash + 1;
    }
}

static void normalize_host(const char *hdr, char *out, size_t cap) {
    size_t n = 0;
    while (hdr[n] && hdr[n] != ':' && n + 1 < cap) {
        out[n] = (char)tolower((unsigned char)hdr[n]);
        n++;
    }
    out[n] = '\0';
    if (n && out[n - 1] == '.') out[n - 1] = '\0';
}

/* ------------------------------------------------------------------ */
/* phext streaming: scrolls read incrementally from disk               */
/* ------------------------------------------------------------------ */

typedef struct {
    FILE *f;
    unsigned char buf[8192];
    size_t pos, fill;
    int eof;
} FReader;

static int fr_getc(FReader *r) {
    if (r->pos >= r->fill) {
        size_t n;
        if (r->eof) return -1;
        n = fread(r->buf, 1, sizeof r->buf, r->f);
        if (n == 0) { r->eof = 1; return -1; }
        r->pos = 0;
        r->fill = n;
    }
    return r->buf[r->pos++];
}

/* Default .phext response: the scrolls, streamed in coordinate order.
 * Each scroll (content + its terminating delimiter) is flushed as its
 * own chunk as soon as its delimiter is read; the file is never held
 * whole in memory.  Concatenating the chunks reproduces the file
 * byte for byte. */
static void serve_phext_stream(SSL *ssl, FILE *f, int is_head,
                               int keep_alive) {
    FReader r;
    DynBuf scroll = { NULL, 0, 0 };
    int c;

    send_head(ssl, 200, "text/plain; charset=utf-8", -1, keep_alive, NULL);
    if (is_head) {
        send_final_chunk(ssl);
        return;
    }
    memset(&r, 0, sizeof r);
    r.f = f;
    while ((c = fr_getc(&r)) >= 0) {
        db_put(&scroll, (unsigned char)c);
        if (delim_level(c) >= 0 || scroll.len >= STREAM_FLUSH_AT) {
            send_chunk(ssl, scroll.data, scroll.len);
            scroll.len = 0;
        }
    }
    if (scroll.len) send_chunk(ssl, scroll.data, scroll.len);
    send_final_chunk(ssl);
    free(scroll.data);
}

/* Single scroll by coordinate, found by an incremental scan. */
static void serve_phext_coord(SSL *ssl, FILE *f, const char *want,
                              int is_head, int keep_alive) {
    FReader r;
    DynBuf cur = { NULL, 0, 0 };
    int coord[9] = { 1, 1, 1, 1, 1, 1, 1, 1, 1 };
    int c;

    memset(&r, 0, sizeof r);
    r.f = f;
    for (;;) {
        c = fr_getc(&r);
        if (c < 0 || delim_level(c) >= 0) {
            char here[64];
            coord_format(coord, here, sizeof here);
            if (!strcmp(here, want)) {
                send_head(ssl, 200, "text/plain; charset=utf-8",
                          (long)cur.len, keep_alive, NULL);
                if (!is_head && cur.len)
                    ssl_write_all(ssl, cur.data, cur.len);
                free(cur.data);
                return;
            }
            if (c < 0) break;
            coord_advance(coord, delim_level(c));
            cur.len = 0;
        } else {
            db_put(&cur, (unsigned char)c);
        }
    }
    free(cur.data);
    {
        char body[192];
        snprintf(body, sizeof body, "404 Not Found: no scroll at %s\n", want);
        send_head(ssl, 404, "text/plain; charset=utf-8",
                  (long)strlen(body), keep_alive, NULL);
        if (!is_head) ssl_puts(ssl, body);
    }
}

/* The scroll index, streamed: one line per scroll as it is scanned —
 * coordinate, content byte count, and the scroll's first line. */
static void serve_phext_toc(SSL *ssl, FILE *f, int is_head,
                            int keep_alive) {
    FReader r;
    int coord[9] = { 1, 1, 1, 1, 1, 1, 1, 1, 1 };
    size_t len = 0;
    char title[96];
    size_t tlen = 0;
    int in_title = 1, any = 0, c;

    send_head(ssl, 200, "text/plain; charset=utf-8", -1, keep_alive, NULL);
    if (is_head) {
        send_final_chunk(ssl);
        return;
    }
    memset(&r, 0, sizeof r);
    r.f = f;
    title[0] = '\0';
    for (;;) {
        c = fr_getc(&r);
        if (c < 0 || delim_level(c) >= 0) {
            char line[256], here[64];
            coord_format(coord, here, sizeof here);
            title[tlen] = '\0';
            snprintf(line, sizeof line, "%s\t%lu\t%s%s\n", here,
                     (unsigned long)len, tlen ? title : "(empty)",
                     "");
            send_chunk(ssl, line, strlen(line));
            any = 1;
            if (c < 0) break;
            coord_advance(coord, delim_level(c));
            len = 0;
            tlen = 0;
            title[0] = '\0';
            in_title = 1;
        } else {
            len++;
            if (in_title) {
                if (c == '\n') {
                    in_title = 0;
                } else if (tlen + 1 < sizeof title) {
                    title[tlen++] = (char)c;
                }
            }
        }
    }
    (void)any;
    send_final_chunk(ssl);
}

/* Whole-file response (?whole=1, or any non-phext file). */
static void serve_whole_file(SSL *ssl, FILE *f, long size,
                             const char *ctype, int is_head,
                             int keep_alive) {
    unsigned char buf[16384];
    size_t n;
    send_head(ssl, 200, ctype, size, keep_alive, NULL);
    if (is_head) return;
    while ((n = fread(buf, 1, sizeof buf, f)) > 0)
        if (ssl_write_all(ssl, buf, n) < 0) return;
}

/* ------------------------------------------------------------------ */
/* request serving                                                     */
/* ------------------------------------------------------------------ */

static volatile sig_atomic_t g_reload = 0;

static void on_sighup(int sig) {
    (void)sig;
    g_reload = 1;
}

static void serve(SSL *ssl, const char *target, const char *host_hdr,
                  int is_head, int keep_alive, const char *peer_ip) {
    char path[4096], query[2048];
    char coord[80] = "";
    const char *q;
    Effective eff;
    char host[512];
    char full[PATH_MAX];
    struct stat st;
    int is_phext;

    snprintf(path, sizeof path, "%s", target);
    query[0] = '\0';
    q = strchr(path, '?');
    if (q) {
        snprintf(query, sizeof query, "%s", q + 1);
        path[q - path] = '\0';
    }
    url_decode(path);

    /* config reload endpoint (localhost only): signals the parent
     * process, whose SIGHUP handler reloads config.phext. */
    if (!strcmp(path, "/__phweb/reload")) {
        if (!strcmp(peer_ip, "127.0.0.1") || !strcmp(peer_ip, "::1")) {
            static const char msg[] = "phweb: reload signalled\n";
            kill(getppid(), SIGHUP);
            send_head(ssl, 200, "text/plain; charset=utf-8",
                      (long)(sizeof msg - 1), keep_alive, NULL);
            if (!is_head) ssl_puts(ssl, msg);
        } else {
            send_error(ssl, 403, is_head, keep_alive);
        }
        return;
    }

    if (!path_is_safe(path)) {
        send_error(ssl, 400, is_head, keep_alive);
        return;
    }

    /* coordinate addressing: /file.phext@<coordinate> or /file.phext@toc */
    {
        char *at = strstr(path, ".phext@");
        if (at) {
            snprintf(coord, sizeof coord, "%s", at + 7);
            at[6] = '\0'; /* truncate path right after ".phext" */
        }
    }
    if (!coord[0]) {
        const char *cq = strstr(query, "coord=");
        if (cq) {
            const char *end = strchr(cq + 6, '&');
            size_t n = end ? (size_t)(end - (cq + 6)) : strlen(cq + 6);
            if (n >= sizeof coord) n = sizeof coord - 1;
            memcpy(coord, cq + 6, n);
            coord[n] = '\0';
        }
    }

    normalize_host(host_hdr, host, sizeof host);
    effective_config(host, &eff);

    snprintf(full, sizeof full, "%s/%s", eff.docroot, path + 1);
    if (stat(full, &st) != 0) {
        send_error(ssl, 404, is_head, keep_alive);
        return;
    }
    if (S_ISDIR(st.st_mode)) {
        size_t n = strlen(full);
        snprintf(full + n, sizeof full - n, "/%s", eff.index);
        if (stat(full, &st) != 0 || !S_ISREG(st.st_mode)) {
            send_error(ssl, 404, is_head, keep_alive);
            return;
        }
    }
    if (!S_ISREG(st.st_mode)) {
        send_error(ssl, 404, is_head, keep_alive);
        return;
    }

    is_phext = ends_with(full, ".phext");
    {
        FILE *f = fopen(full, "rb");
        if (!f) {
            send_error(ssl, 404, is_head, keep_alive);
            return;
        }
        if (is_phext) {
            int whole = ci_contains(query, "whole=1");
            if (coord[0] && !strcmp(coord, "toc"))
                serve_phext_toc(ssl, f, is_head, keep_alive);
            else if (coord[0])
                serve_phext_coord(ssl, f, coord, is_head, keep_alive);
            else if (whole || !eff.stream)
                serve_whole_file(ssl, f, (long)st.st_size,
                                 "text/plain; charset=utf-8",
                                 is_head, keep_alive);
            else
                serve_phext_stream(ssl, f, is_head, keep_alive);
        } else {
            serve_whole_file(ssl, f, (long)st.st_size,
                             content_type(full), is_head, keep_alive);
        }
        fclose(f);
    }
}

static void handle_conn(SSL *ssl, const char *peer_ip) {
    Reader r;
    char line[MAX_LINE];

    memset(&r, 0, sizeof r);
    r.ssl = ssl;
    for (;;) {
        char method[16], target[4096], version[32];
        char host[512] = "";
        long content_length = 0;
        int conn_close = 0, conn_ka = 0, n, is_head, keep_alive;

        n = reader_gets(&r, line, sizeof line);
        if (n <= 0) return;
        if (n == 0) continue; /* stray CRLF between requests */
        if (sscanf(line, "%15s %4095s %31s", method, target, version) != 3) {
            send_error(ssl, 400, 0, 0);
            return;
        }
        for (;;) {
            n = reader_gets(&r, line, sizeof line);
            if (n < 0) return;
            if (n == 0) break;
            if (!strncasecmp(line, "Host:", 5)) {
                char *v = line + 5;
                while (*v == ' ' || *v == '\t') v++;
                snprintf(host, sizeof host, "%.500s", v);
            } else if (!strncasecmp(line, "Connection:", 11)) {
                if (ci_contains(line + 11, "close")) conn_close = 1;
                if (ci_contains(line + 11, "keep-alive")) conn_ka = 1;
            } else if (!strncasecmp(line, "Content-Length:", 15)) {
                content_length = atol(line + 15);
            }
        }
        if (content_length > 0) reader_discard(&r, content_length);

        keep_alive = !conn_close &&
                     (!strcmp(version, "HTTP/1.1") || conn_ka);
        is_head = !strcasecmp(method, "HEAD");
        if (strcasecmp(method, "GET") && !is_head) {
            send_error(ssl, 405, 0, keep_alive);
            if (!keep_alive) return;
            continue;
        }
        serve(ssl, target, host, is_head, keep_alive, peer_ip);
        if (!keep_alive) return;
    }
}

/* ------------------------------------------------------------------ */
/* main                                                                */
/* ------------------------------------------------------------------ */

int main(int argc, char **argv) {
    int port = 8443, opt;
    const char *cert = "certs/phweb.crt";
    const char *key = "certs/phweb.key";
    SSL_CTX *ctx;
    int listener;
    struct sockaddr_in addr;
    struct sigaction sa;

    while ((opt = getopt(argc, argv, "p:c:C:K:h")) != -1) {
        switch (opt) {
            case 'p': port = atoi(optarg); break;
            case 'c': snprintf(g_config_path, sizeof g_config_path, "%s", optarg); break;
            case 'C': cert = optarg; break;
            case 'K': key = optarg; break;
            default:
                fprintf(stderr,
                        "usage: phweb [-p port] [-c config.phext] "
                        "[-C cert.pem] [-K key.pem]\n");
                return 2;
        }
    }

    if (load_config(g_config_path) != 0) return 1;

    SSL_library_init();
    SSL_load_error_strings();
    ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) { ERR_print_errors_fp(stderr); return 1; }
    /* TLS 1.3 only (RFC 9846, the corpus's successor to RFC 8446). */
    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);
    if (SSL_CTX_use_certificate_file(ctx, cert, SSL_FILETYPE_PEM) != 1 ||
        SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM) != 1 ||
        SSL_CTX_check_private_key(ctx) != 1) {
        fprintf(stderr, "phweb: cannot load cert %s / key %s "
                        "(run ./setup.sh first)\n", cert, key);
        ERR_print_errors_fp(stderr);
        return 1;
    }

    listener = socket(AF_INET, SOCK_STREAM, 0);
    if (listener < 0) { perror("socket"); return 1; }
    {
        int one = 1;
        setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    }
    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons((unsigned short)port);
    if (bind(listener, (struct sockaddr *)&addr, sizeof addr) != 0) {
        perror("bind");
        return 1;
    }
    if (listen(listener, 64) != 0) { perror("listen"); return 1; }

    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_sighup;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0; /* no SA_RESTART: accept() must wake for reloads */
    sigaction(SIGHUP, &sa, NULL);

    memset(&sa, 0, sizeof sa);
    sa.sa_handler = SIG_IGN;
    sigaction(SIGPIPE, &sa, NULL);

    memset(&sa, 0, sizeof sa);
    sa.sa_flags = SA_NOCLDWAIT;
    sa.sa_handler = SIG_DFL;
    sigaction(SIGCHLD, &sa, NULL);

    fprintf(stderr, "phweb %s listening on https://0.0.0.0:%d "
                    "(config %s; SIGHUP reloads)\n",
            PHWEB_VERSION, port, g_config_path);

    for (;;) {
        struct sockaddr_in peer;
        socklen_t plen = sizeof peer;
        int conn = accept(listener, (struct sockaddr *)&peer, &plen);
        if (conn < 0) {
            if (errno == EINTR) {
                if (g_reload) {
                    g_reload = 0;
                    fprintf(stderr, "phweb: reloading %s\n", g_config_path);
                    load_config(g_config_path);
                }
                continue;
            }
            perror("accept");
            continue;
        }
        {
            char peer_ip[64] = "?";
            pid_t pid;
            inet_ntop(AF_INET, &peer.sin_addr, peer_ip, sizeof peer_ip);
            pid = fork();
            if (pid == 0) {
                SSL *ssl;
                close(listener);
                ssl = SSL_new(ctx);
                SSL_set_fd(ssl, conn);
                if (SSL_accept(ssl) == 1)
                    handle_conn(ssl, peer_ip);
                SSL_shutdown(ssl);
                SSL_free(ssl);
                close(conn);
                _exit(0);
            }
            close(conn);
        }
    }
    return 0;
}
