// trash.c: command line interface to the FreeDesktop trash can, implementing
// trash-put, trash-list, trash-restore, trash-empty and trash-rm as a single
// binary that takes on the persona of the name it is invoked as; link the
// same executable under every name:
//
// Release build:
//   cc -std=c23 -O2 -Wall -Wextra -Wconversion -Wno-sign-conversion
//     -o trash-put trash.c
//   ln -sf trash-put trash trash-list trash-restore trash-empty trash-rm
//
// Debug build (assertions trap, undefined behavior stops in the debugger):
//   cc -g3 -std=c23 -Wall -Wextra -Wconversion -Wno-sign-conversion
//     -fsanitize=undefined -fsanitize-trap -o trash-put trash.c
//
// Test build (the conformance suite against a virtual OS; see the Makefile's
// trash-test and check targets):
//   cc -std=c23 -O2 -Wall -Wextra -Wconversion -DTEST -o trash-test trash.c
//
// The program never allocates with malloc, never frees, and has no global
// state; everything hangs off the Os context and one arena pair.
//
// This is free and unencumbered software released into the public domain.

// Feature test macros must precede any libc header: <stdint.h> pulls in
// glibc's features.h, which latches them for the whole file.
#define _GNU_SOURCE 1

#include <stddef.h>
#include <stdint.h>

typedef uint8_t   u8;
typedef int32_t   b32;
typedef int32_t   i32;
typedef uint32_t  u32;
typedef int64_t   i64;
typedef uint64_t  u64;
typedef char      byte;
typedef ptrdiff_t iz;
typedef size_t    uz;

#define countof(a) (iz)(sizeof(a) / sizeof(*(a)))
#define affirm(c)  while (!(c)) __builtin_unreachable()
#define S(s)       (Str){(u8 *)s, sizeof(s)-1}
#define STR(s)     {(u8 *)s, sizeof(s)-1}
#define xset(d, c, n) __builtin_memset(d, c, n)
#define xcpy(d, s, n) __builtin_memcpy(d, s, n)
#define maxof(t)   ((t)-1 < 1 ? (((t)1 << (sizeof(t)*8 - 2)) - 1)*2 + 1 : (t)-1)

// Linux errno values the core branches on; <errno.h> is included only in
// the platform layer below, so the core names them itself.
enum : i32 {
    EPERM = 1, ENOENT = 2, EINTR = 4, EACCES = 13, EEXIST = 17, EXDEV = 18,
    ENOTDIR = 20, EISDIR = 21, EINVAL = 22, ENOSPC = 28, EROFS = 30,
    ENAMETOOLONG = 36, ENOTEMPTY = 39, ELOOP = 40, EDQUOT = 122,
};


typedef struct Os Os;

// Core types
//
// Zero is a valid, empty state for every struct here.

enum : i32 {
    KIND_NONE = 0,
    KIND_FILE,
    KIND_DIR,
    KIND_LINK,
    KIND_FIFO,
    KIND_SOCK,
    KIND_BLK,
    KIND_CHR,
};

typedef struct {
    i64 dev;
    i64 ino;
    i32 kind;
    u32 mode;   // permission and flag bits: st_mode & 07777
    i64 size;
} Stat;

typedef struct {
    i32 year, month, day;
    i32 hour, min, sec;
} DateTime;

typedef struct {
    u8 *data;   // 0 marks an absent string
    iz  len;
} Str;

typedef struct DirEnt DirEnt;
struct DirEnt {
    DirEnt *next;
    Str     name;
};

typedef struct User User;
struct User {
    User *next;
    Str   dir;
    i32   uid;
};

enum : i32 { ACCESS_F = 0, ACCESS_X = 1, ACCESS_W = 2, ACCESS_R = 4 };

// The platform object: one per process, owned by the layer at the bottom.
struct Os {
    Str name;   // the persona: the basename this executable was invoked as
    u64 rng;    // xorshift state for os_rand
};

// Arena: one block from the platform, split into a permanent region and a
// scratch region.  Scratch is passed by value and dies at return.
typedef struct Arena Arena;

// Platform API — implemented by the Linux layer at the bottom of this file.

// Terminate the process (the core flushes its outputs first).
[[noreturn]] static void  os_exit(Os *, i32 status);
// Write the whole buffer to a file descriptor; 0 on error.
static b32                os_write(Os *, i32 fd, u8 *buf, iz len);
// Read up to cap bytes; -1 on error, 0 at end of file.
static iz                 os_read(Os *, i32 fd, u8 *buf, iz cap);
// Open for reading, or create exclusively for writing with the given mode.
static i32                os_open(Os *, Arena scratch, Str path, b32 create,
                                  u32 mode);
static void               os_close(Os *, i32 fd);
// Look up an environment variable; a null Str (data == 0) when unset.
static Str                os_getenv(Os *, Str name);
// File status; scratch holds the null-terminated path copy.
static b32                os_stat(Os *, Arena scratch, Str path, b32 follow,
                                  Stat *);
// Read a symlink target into *out, allocated in *a.
static b32                os_readlink(Os *, Arena *a, Str path, Str *out);
static b32                os_mkdir(Os *, Arena scratch, Str path, u32 mode);
static b32                os_unlink(Os *, Arena scratch, Str path);
// chmod(2) with an octal mode.
static b32                os_chmod(Os *, Arena scratch, Str path, u32 mode);
static b32                os_rmdir(Os *, Arena scratch, Str path);
static b32                os_rename(Os *, Arena scratch, Str from, Str to);
static b32                os_symlink(Os *, Arena scratch, Str target, Str path);
// access(2); mode is one of the ACCESS_ enumerators.
static b32                os_access(Os *, Arena scratch, Str path, i32 mode);
static b32                os_isatty(Os *, i32 fd);
static i32                os_getuid(Os *);
// The current local time.
static void               os_now(Os *, DateTime *);
// Every passwd account, linked through User.next, built in *a.
static User               *os_users(Os *, Arena *a);
// A directory's entries in readdir order, built in *a; 0 on error.
// A directory's entries in readdir order, built in *a; *ok is 0 only on
// failure (an empty directory yields no entries with *ok set to 1).
static DirEnt             *os_listdir(Os *, Arena *a, Str path, b32 *ok);
static i32                os_errno(Os *);
// Static error text for an errno; no allocation.
static Str                os_strerror(Os *, i32 err);
// This executable's own path, in *a.
static Str                os_selfexe(Os *, Arena *a);
// Columns of the terminal on stdout, 0 when stdout is not one.
static iz                 os_termwidth(Os *);
// The current working directory, in *a; a null Str with errno set on failure.
static Str                os_getcwd(Os *, Arena *a);
// A pseudo-random 64-bit value (trash name collision suffixes).
static u64                os_rand(Os *);

// Arena: one block from the platform, split into a permanent region and a
// scratch region.  Scratch is passed by value and dies at return.
typedef struct Arena {
    Os   *os;
    byte *beg;
    byte *end;
} Arena;

[[noreturn]] static void oom(Os *os)
{
    u8 msg[] = ": out of memory\n";
    os_write(os, 2, os->name.data, os->name.len);
    os_write(os, 2, msg, countof(msg) - 1);
    os_exit(os, 1);
}

static void *alloc(Arena *a, iz count, iz size, iz align)
{
    affirm(count >= 0 && size > 0);
    iz pad = (iz)-(uz)a->beg & (align - 1);
    if (count >= (a->end - a->beg - pad)/size) {
        oom(a->os);
    }
    byte *r = a->beg + pad;
    a->beg += pad + count*size;
    return xset(r, 0, (uz)(count*size));
}

#define new(a, n, t) (t *)alloc(a, n, sizeof(t), _Alignof(t))


// Strings

static Str span(u8 *beg, u8 *end)
{
    affirm(beg <= end);
    return (Str){beg, end - beg};
}

static Str import(u8 *s)
{
    Str r = {};
    r.data = s;
    for (; r.data[r.len]; r.len++) {}
    return r;
}

static b32 equals(Str a, Str b)
{
    return a.len == b.len && (!a.len || !__builtin_memcmp(a.data, b.data,
                                                          (uz)a.len));
}

static Str cuthead(Str s, iz len)
{
    affirm(len >= 0 && len <= s.len);
    if (!len) return s;   // null plus zero is UB in C
    s.data += len;
    s.len  -= len;
    return s;
}

static Str takehead(Str s, iz len)
{
    affirm(len >= 0 && len <= s.len);
    s.len = len;
    return s;
}

static Str cuttail(Str s, iz len)
{
    affirm(len >= 0 && len <= s.len);
    s.len -= len;
    return s;
}

static Str taketail(Str s, iz len)
{
    affirm(len >= 0 && len <= s.len);
    return cuthead(s, s.len - len);
}

static b32 startswith(Str s, Str prefix)
{
    return s.len >= prefix.len && equals(takehead(s, prefix.len), prefix);
}

static b32 endswith(Str s, Str suffix)
{
    return s.len >= suffix.len && equals(taketail(s, suffix.len), suffix);
}

static Str clone(Arena *a, Str s)
{
    Str r = s;
    r.data = new(a, s.len, u8);
    if (r.len) xcpy(r.data, s.data, (uz)r.len);
    return r;
}

// Extends head in place when it sits at the front of the arena.
static Str concat(Arena *a, Str head, Str tail)
{
    if (!head.data || (byte *)(head.data + head.len) != a->beg) {
        head = clone(a, head);
    }
    head.len += clone(a, tail).len;
    return head;
}

static Str istr(Arena *a, i64 x)
{
    u8  buf[32];
    u8 *end = buf + countof(buf);
    u8 *beg = end;
    i64 t   = x < 0 ? x : -x;
    do {
        *--beg = (u8)('0' - (i32)(t%10));
    } while (t /= 10);
    if (x < 0) {
        *--beg = '-';
    }
    return clone(a, span(beg, end));
}

typedef struct {
    Str head;
    Str tail;
    b32 ok;
} Cut;

static Cut cut(Str s, u8 c)
{
    u8 *beg = s.data;
    u8 *end = s.data + s.len;
    u8 *cut = beg;
    for (; cut < end && *cut != c; cut++) {}
    Cut r  = {};
    r.ok   = cut < end;
    r.head = span(beg, cut);
    r.tail = span(cut + r.ok, end);
    return r;
}

static iz utf8_seq(Str s, iz i);

// Unicode: whitespace as str.isspace(), and decimal digits (category Nd,
// each block ten contiguous code points starting at its zero).
static b32 pyspace(u32 cp)
{
    return (cp >= 9 && cp <= 13) || (cp >= 0x1C && cp <= 0x20) || cp == 0x85
        || cp == 0xA0 || cp == 0x1680 || (cp >= 0x2000 && cp <= 0x200A)
        || cp == 0x2028 || cp == 0x2029 || cp == 0x202F || cp == 0x205F
        || cp == 0x3000;
}

static i32 decimaldigit(u32 cp)
{
    static const u32 zeros[] = {
        0x30, 0x660, 0x6F0, 0x7C0, 0x966, 0x9E6, 0xA66, 0xAE6, 0xB66, 0xBE6,
        0xC66, 0xCE6, 0xD66, 0xDE6, 0xE50, 0xED0, 0xF20, 0x1040, 0x1090,
        0x17E0, 0x1810, 0x1946, 0x19D0, 0x1A80, 0x1A90, 0x1B50, 0x1BB0,
        0x1C40, 0x1C50, 0xA620, 0xA8D0, 0xA900, 0xA9D0, 0xA9F0, 0xAA50,
        0xABF0, 0xFF10, 0x104A0, 0x10D30, 0x11066, 0x110F0, 0x11136, 0x111D0,
        0x112F0, 0x11450, 0x114D0, 0x11650, 0x116C0, 0x11730, 0x118E0,
        0x11950, 0x11C50, 0x11D50, 0x11DA0, 0x11F50, 0x16A60, 0x16AC0,
        0x16B50, 0x1D7CE, 0x1D7D8, 0x1D7E2, 0x1D7EC, 0x1D7F6, 0x1E140,
        0x1E2F0, 0x1E4F0, 0x1E950, 0x1FBF0,
    };
    for (iz k = 0; k < (iz)countof(zeros); k++) {
        if (cp >= zeros[k] && cp < zeros[k] + 10) {
            return (i32)(cp - zeros[k]);
        }
    }
    return -1;
}

static u32 utf8_cp(Str s, iz i, iz n)   // the code point of a valid sequence
{
    u8  c  = s.data[i];
    u32 cp = n == 1 ? c : n == 2 ? c & 0x1Fu : n == 3 ? c & 0x0Fu : c & 0x07u;
    for (iz k = 1; k < n; k++) {
        cp = cp<<6 | (s.data[i+k] & 0x3Fu);
    }
    return cp;
}

typedef struct {
    Str digits;   // normalized: no leading zeros, "0" for zero
    i64 value;    // saturated to the i64 range
    b32 neg;
    b32 ok;       // int() accepts the text
    b32 toobig;   // magnitude beyond the i64 range
} IntParsed;

// Python's int(str): surrounding whitespace, an optional sign, then digits
// (any script) with single underscores between them.  Past 4300 digits
// Python refuses, and so do we.
static IntParsed parseint(Arena *a, Str s)
{
    IntParsed r = {};
    u32 *cp = new(a, s.len, u32);
    iz   n  = 0;
    for (iz i = 0; i < s.len;) {
        iz k = utf8_seq(s, i);
        if (!k) {
            return r;
        }
        cp[n++] = utf8_cp(s, i, k);
        i += k;
    }
    iz lo = 0, hi = n;
    while (lo < hi && pyspace(cp[lo])) {
        lo++;
    }
    while (hi > lo && pyspace(cp[hi-1])) {
        hi--;
    }
    if (lo < hi && (cp[lo] == '+' || cp[lo] == '-')) {
        r.neg = cp[lo] == '-';
        lo++;
    }
    u8 *d     = new(a, hi - lo + 1, u8);
    iz  nd    = 0;
    b32 prevd = 0;   // the previous character was a digit
    for (iz i = lo; i < hi; i++) {
        i32 dv = decimaldigit(cp[i]);
        if (dv >= 0) {
            d[nd++] = (u8)('0' + dv);
            prevd   = 1;
        } else if (cp[i] == '_' && prevd && i + 1 < hi) {
            prevd = 0;
        } else {
            return r;
        }
    }
    if (!nd || nd > 4300 || !prevd) {
        return r;
    }
    iz z = 0;
    while (z < nd - 1 && d[z] == '0') {
        z++;
    }
    r.digits = span(d + z, d + nd);
    r.ok     = 1;
    for (iz i = 0; i < r.digits.len; i++) {
        i64 dd = r.digits.data[i] - '0';
        if (!r.toobig && r.value > (maxof(i64) - dd)/10) {
            r.toobig = 1;
            r.value  = maxof(i64);
        } else if (!r.toobig) {
            r.value = r.value*10 + dd;
        }
    }
    if (r.neg && !r.toobig) {
        r.value = -r.value;
    }
    return r;
}


// Buffered output

typedef struct {
    Os *os;
    i32 fd;
    iz  len;
    b32 err;
    u8  buf[1<<14];
} Output;

static Output *newoutput(Arena *a, Os *os, i32 fd)
{
    Output *b = new(a, 1, Output);
    b->os = os;
    b->fd = fd;
    return b;
}

static void flush(Output *b)
{
    if (!b->err && b->len) {
        b->err |= !os_write(b->os, b->fd, b->buf, b->len);
        b->len = 0;
    }
}

static void print(Output *b, Str s)
{
    for (iz off = 0; !b->err && off < s.len;) {
        iz avail = countof(b->buf) - b->len;
        iz count = s.len - off < avail ? s.len - off : avail;
        xcpy(b->buf + b->len, s.data + off, (uz)count);
        off    += count;
        b->len += count;
        if (b->len == countof(b->buf)) {
            flush(b);
        }
    }
}

static void printu8(Output *b, u8 c)
{
    print(b, (Str){&c, 1});
}

static void printi64(Output *b, i64 x)
{
    u8  buf[32];
    u8 *end = buf + countof(buf);
    u8 *beg = end;
    i64 t   = x < 0 ? x : -x;   // negative covers the full range
    do {
        *--beg = (u8)('0' - (i32)(t%10));
    } while (t /= 10);
    if (x < 0) {
        *--beg = '-';
    }
    print(b, span(beg, end));
}

// Two lowercase hex digits, for \xNN escapes.
static void printhex2(Output *b, u32 x)
{
    printu8(b, (u8)"0123456789abcdef"[x>>4 & 15]);
    printu8(b, (u8)"0123456789abcdef"[x    & 15]);
}

// Right-align a non-negative number in `width` columns.
static void printpad(Output *b, i64 x, iz width)
{
    iz digits = 1;
    for (i64 t = x; t >= 10; t /= 10) {
        digits++;
    }
    for (iz i = digits; i < width; i++) {
        printu8(b, ' ');
    }
    printi64(b, x);
}

// Quotes a path the way GNU ls does on a terminal (upstream's shell_escape):
// names made only of [A-Za-z0-9%+-./:=@_,] pass through; otherwise runs of
// printable characters go in single quotes (a quote itself as '\''), and
// each control character (< 0x20, 0x7f, or a C1 code point) becomes its own
// $'\n'-style segment.  Valid UTF-8 text stays as is.  A byte that is not
// valid UTF-8 becomes a $'\xNN' segment, which the shell reads back right
// (upstream would show it inside the quotes as a literal \xNN).
static void printq(Output *b, Str s)
{
    b32 safe = s.len > 0;
    for (iz i = 0; i < s.len; i++) {
        u8 c = s.data[i];
        safe &= (c>='A' && c<='Z') || (c>='a' && c<='z') || (c>='0' && c<='9')
             || c=='%' || c=='+' || c=='-' || c=='.' || c=='/' || c==':'
             || c=='=' || c=='@' || c=='_' || c==',';
    }
    if (safe) {
        print(b, s);
        return;
    }
    b32 quoted = 0;
    for (iz i = 0; i < s.len;) {
        iz  n  = utf8_seq(s, i);
        u8  c  = s.data[i];
        b32 c1 = n == 2 && c == 0xC2 && s.data[i+1] >= 0x80
              && s.data[i+1] <= 0x9F;
        b32 bad = !n || c < 0x20 || c == 0x7F || c1;
        if (!bad) {
            if (!quoted) {
                printu8(b, '\'');
                quoted = 1;
            }
            if (c == '\'') {
                print(b, S("'\\''"));
            } else {
                print(b, span(s.data + i, s.data + i + n));
            }
            i += n;
            continue;
        }
        if (quoted) {
            printu8(b, '\'');
            quoted = 0;
        }
        print(b, S("$'\\"));
        u32 cp = c1 ? s.data[i+1] : c;
        switch (cp) {
        case 0x07: printu8(b, 'a'); break;
        case 0x08: printu8(b, 'b'); break;
        case 0x09: printu8(b, 't'); break;
        case 0x0A: printu8(b, 'n'); break;
        case 0x0B: printu8(b, 'v'); break;
        case 0x0C: printu8(b, 'f'); break;
        case 0x0D: printu8(b, 'r'); break;
        default:
            if (!n) {
                printu8(b, 'x');
                printhex2(b, c);
            } else {
                printu8(b, (u8)('0' + (cp>>6 & 7)));
                printu8(b, (u8)('0' + (cp>>3 & 7)));
                printu8(b, (u8)('0' + (cp    & 7)));
            }
        }
        printu8(b, '\'');
        i += c1 ? 2 : (n ? n : 1);
    }
    if (quoted) {
        printu8(b, '\'');
    }
}


// Paths

// Python's os.path.split: tail keeps its trailing slashes, head loses all of
// its separators unless it is all separators.
static void splitpath(Str p, Str *phead, Str *ptail)
{
    iz i = p.len;
    while (i && p.data[i-1] != '/') {
        i--;
    }
    Str head = takehead(p, i);
    Str tail = cuthead(p, i);
    b32 allsep = head.len > 0;
    for (iz k = 0; k < head.len; k++) {
        if (head.data[k] != '/') {
            allsep = 0;
        }
    }
    if (head.len && !allsep) {
        while (head.len && head.data[head.len-1] == '/') {
            head = cuttail(head, 1);
        }
    }
    if (!head.len) {
        head = (p.len && p.data[0]=='/') ? S("/") : S(".");
    }
    *phead = head;
    *ptail = tail;
}

static Str basename(Str p)
{
    Str head, tail;
    splitpath(p, &head, &tail);
    return tail;
}

static Str dirname(Str p)
{
    Str head, tail;
    splitpath(p, &head, &tail);
    return head;
}

// Python's os.path.join of two parts; an empty tail still adds the slash.
static Str join(Arena *a, Str head, Str tail)
{
    if (!tail.len) {
        if (head.len && head.data[head.len-1] != '/') {
            return concat(a, head, S("/"));
        }
        return clone(a, head);
    }
    if (tail.data[0] == '/') {
        return clone(a, tail);
    }
    if (!head.len) {
        return clone(a, tail);
    }
    if (head.data[head.len-1] != '/') {
        head = concat(a, head, S("/"));
    }
    return concat(a, head, tail);
}

// POSIX normpath: collapses separators, removes '.' components, applies '..'
// lexically.  Exactly two leading separators are preserved.
static Str normpath(Arena *a, Str p)
{
    b32 abs = p.len && p.data[0] == '/';
    b32 dbl = p.len >= 2 && p.data[0]=='/' && p.data[1]=='/'
           && (p.len==2 || p.data[2] != '/');
    iz  cap = p.len/2 + 2;
    Str *st = new(a, cap, Str);
    iz  n   = 0;
    iz  i   = 0;
    while (i < p.len) {
        while (i < p.len && p.data[i] == '/') {
            i++;
        }
        iz s = i;
        while (i < p.len && p.data[i] != '/') {
            i++;
        }
        if (i == s) {
            continue;
        }
        Str c = span(p.data + s, p.data + i);
        if (equals(c, S("."))) {
            continue;
        }
        if (equals(c, S("..")) && n && !equals(st[n-1], S(".."))) {
            n--;
        } else if (equals(c, S("..")) && !abs) {
            st[n++] = c;
        } else if (!equals(c, S(".."))) {
            st[n++] = c;
        }
    }
    iz total = 0;
    for (iz k = 0; k < n; k++) {
        total += st[k].len;
    }
    total += n ? n - 1 : 0;
    if (abs) {
        total += dbl ? 2 : 1;
    }
    if (!total) {
        return S(".");
    }
    u8 *d = new(a, total, u8);
    u8 *e = d;
    if (abs) {
        *e++ = '/';
        if (dbl) {
            *e++ = '/';
        }
    }
    for (iz k = 0; k < n; k++) {
        if (k) {
            *e++ = '/';
        }
        xcpy(e, st[k].data, (uz)st[k].len);
        e += st[k].len;
    }
    return span(d, e);
}

// Builds the path for a resolved component stack.
static Str rjoin(Arena *a, b32 rooted, Str *res, iz n, Str c)
{
    iz total = c.len;
    for (iz k = 0; k < n; k++) {
        total += res[k].len + 1;
    }
    if (rooted) {
        total += 1;
    }
    u8 *d = new(a, total, u8);
    u8 *e = d;
    if (rooted) {
        *e++ = '/';
    }
    for (iz k = 0; k < n; k++) {
        xcpy(e, res[k].data, (uz)res[k].len);
        e += res[k].len;
        *e++ = '/';
    }
    xcpy(e, c.data, (uz)c.len);
    e += c.len;
    return span(d, e);
}

static b32 ismountpoint(Os *os, Arena scratch, Str path)
{
    Stat s1 = {}, s2 = {};
    if (!os_stat(os, scratch, path, 1, &s1)) {
        return 0;
    }
    Str up = join(&scratch, path, S(".."));
    if (!os_stat(os, scratch, up, 1, &s2)) {
        return 0;
    }
    return s1.dev != s2.dev || s1.ino == s2.ino;
}

// The volume a path lives on: the nearest mount point at or above it.
// The result is cloned into *r; scratch holds the walk.
static Str volume_of(Os *os, Arena *r, Arena scratch, Str path)
{
    Str cur = clone(&scratch, path);
    for (;;) {
        if (ismountpoint(os, scratch, cur)) {
            return clone(r, cur);
        }
        Str d = dirname(cur);
        if (equals(d, cur)) {
            return clone(r, cur);
        }
        cur = d;
    }
}


// fnmatch.fnmatchcase, ported from Python's fnmatch.translate: * crosses
// '/', ? and [...] work on code points (a byte that is not valid UTF-8 is
// the lone surrogate U+DC00 + byte), no escapes, and a [ without its ] is a
// plain [.  The pattern compiles to tokens, then matches with the classic
// star backtracking.

typedef struct {
    u32 lo, hi;
} CRange;

enum : i32 { FT_CHAR, FT_ANY, FT_STAR, FT_SET, FT_NEVER };

typedef struct {
    i32     kind;
    u32     cp;
    b32     neg;
    CRange *r;
    iz      nr;
} FTok;

static u32 *decodecps(Arena *a, Str s, iz *n)
{
    u32 *cp = new(a, s.len + 1, u32);
    iz   k  = 0;
    for (iz i = 0; i < s.len;) {
        iz m = utf8_seq(s, i);
        cp[k++] = m ? utf8_cp(s, i, m) : 0xDC00u + s.data[i];
        i += m ? m : 1;
    }
    *n = k;
    return cp;
}

typedef struct {
    u32 *d;
    iz   n;
} Chunk;

// One [...] class, from its body (the code points between the brackets).
static FTok fnclass(Arena *a, u32 *st, iz m)
{
    FTok t = {.kind = FT_SET};
    b32 dash = 0;
    for (iz i = 0; i < m; i++) {
        dash |= st[i] == '-';
    }
    Chunk *ch = new(a, m + 2, Chunk);
    iz     nc = 0;
    if (!dash) {
        ch[nc++] = (Chunk){st, m};
    } else {
        iz k = st[0] == '!' ? 2 : 1;
        iz start = 0;
        for (;;) {
            iz f = -1;
            for (iz i = k; i < m; i++) {
                if (st[i] == '-') {
                    f = i;
                    break;
                }
            }
            if (f < 0) {
                break;
            }
            ch[nc++] = (Chunk){st + start, f - start};
            start = f + 1;
            k = f + 3;
        }
        if (start < m) {
            ch[nc++] = (Chunk){st + start, m - start};
        } else {   // the pattern ends in a hyphen: it joins the last chunk
            u32 *d = new(a, ch[nc-1].n + 1, u32);
            for (iz i = 0; i < ch[nc-1].n; i++) {
                d[i] = ch[nc-1].d[i];
            }
            d[ch[nc-1].n] = '-';
            ch[nc-1] = (Chunk){d, ch[nc-1].n + 1};
        }
        // Drop empty ranges: lo > hi removes both ends.
        for (iz k2 = nc - 1; k2 > 0; k2--) {
            Chunk *p = &ch[k2 - 1], *q = &ch[k2];
            if (p->n && q->n && p->d[p->n - 1] > q->d[0]) {
                u32 *d = new(a, p->n + q->n, u32);
                iz   n = 0;
                for (iz i = 0; i < p->n - 1; i++) d[n++] = p->d[i];
                for (iz i = 1; i < q->n; i++)     d[n++] = q->d[i];
                *p = (Chunk){d, n};
                for (iz i = k2; i + 1 < nc; i++) {
                    ch[i] = ch[i + 1];
                }
                nc--;
            }
        }
    }
    iz total = nc ? nc - 1 : 0;   // the hyphens between chunks
    for (iz i = 0; i < nc; i++) {
        total += ch[i].n;
    }
    if (!total) {
        t.kind = FT_NEVER;
        return t;
    }
    if (nc && ch[0].n && ch[0].d[0] == '!') {
        if (total == 1) {
            t.kind = FT_ANY;
            return t;
        }
        t.neg = 1;
        ch[0].d++;
        ch[0].n--;
    }
    t.r = new(a, total + 1, CRange);
    for (iz i = 0; i < nc; i++) {
        for (iz k2 = 0; k2 < ch[i].n; k2++) {
            t.r[t.nr++] = (CRange){ch[i].d[k2], ch[i].d[k2]};
        }
        if (i && ch[i-1].n && ch[i].n) {
            t.r[t.nr++] = (CRange){ch[i-1].d[ch[i-1].n - 1], ch[i].d[0]};
        }
    }
    return t;
}

static b32 fnsingle(FTok *t, u32 c)
{
    switch (t->kind) {
    case FT_ANY:
        return 1;
    case FT_CHAR:
        return t->cp == c;
    case FT_SET: {
        b32 hit = 0;
        for (iz i = 0; i < t->nr && !hit; i++) {
            hit = t->r[i].lo <= c && c <= t->r[i].hi;
        }
        return hit != t->neg;
    }
    default:
        return 0;
    }
}

static b32 fnmatch_(Arena scratch, Str pat, Str name)
{
    iz   np, nn;
    u32 *p = decodecps(&scratch, pat, &np);
    u32 *x = decodecps(&scratch, name, &nn);
    FTok *t = new(&scratch, np + 1, FTok);
    iz   nt = 0;
    for (iz i = 0; i < np;) {
        u32 c = p[i++];
        if (c == '*') {
            if (!nt || t[nt-1].kind != FT_STAR) {
                t[nt++] = (FTok){.kind = FT_STAR};
            }
        } else if (c == '?') {
            t[nt++] = (FTok){.kind = FT_ANY};
        } else if (c == '[') {
            iz j = i;
            if (j < np && p[j] == '!') j++;
            if (j < np && p[j] == ']') j++;
            while (j < np && p[j] != ']') j++;
            if (j >= np) {
                t[nt++] = (FTok){.kind = FT_CHAR, .cp = '['};
            } else {
                t[nt++] = fnclass(&scratch, p + i, j - i);
                i = j + 1;
            }
        } else {
            t[nt++] = (FTok){.kind = FT_CHAR, .cp = c};
        }
    }
    iz ti = 0, xi = 0, st = -1, sx = 0;
    while (xi < nn) {
        if (ti < nt && t[ti].kind != FT_STAR && fnsingle(&t[ti], x[xi])) {
            ti++;
            xi++;
        } else if (ti < nt && t[ti].kind == FT_STAR) {
            st = ti++;
            sx = xi;
        } else if (st >= 0) {
            ti = st + 1;
            xi = ++sx;
        } else {
            return 0;
        }
    }
    while (ti < nt && t[ti].kind == FT_STAR) {
        ti++;
    }
    return ti == nt;
}


// Percent encoding (FreeDesktop trashinfo Path=)

static Str percentencode(Arena *a, Str s)
{
    u8 *d = new(a, s.len*3, u8);
    iz  n = 0;
    for (iz i = 0; i < s.len; i++) {
        u8  c = s.data[i];
        b32 keep = (c>='A' && c<='Z') || (c>='a' && c<='z') || (c>='0' && c<='9')
                || c=='_' || c=='.' || c=='-' || c=='~' || c=='/';
        if (keep) {
            d[n++] = c;
        } else {
            d[n++] = '%';
            d[n++] = (u8)"0123456789ABCDEF"[c>>4 & 15];
            d[n++] = (u8)"0123456789ABCDEF"[c    & 15];
        }
    }
    return span(d, d + n);
}

static b32 hexval(u8 c, u32 *out)
{
    if (c >= '0' && c <= '9') {
        *out = c - '0';
    } else if (c >= 'a' && c <= 'f') {
        *out = c - 'a' + 10;
    } else if (c >= 'A' && c <= 'F') {
        *out = c - 'A' + 10;
    } else {
        return 0;
    }
    return 1;
}

static Str percentdecode(Arena *a, Str s)
{
    u8 *d = new(a, s.len, u8);
    iz  n = 0;
    for (iz i = 0; i < s.len; i++) {
        u32 hi, lo;
        if (s.data[i]=='%' && i+2 < s.len
            && hexval(s.data[i+1], &hi) && hexval(s.data[i+2], &lo)) {
            d[n++] = (u8)(hi<<4 | lo);
            i += 2;
        } else {
            d[n++] = s.data[i];
        }
    }
    return span(d, d + n);
}


// UTF-8 validation (strict: no overlongs, surrogates or out-of-range)

// Length of the valid UTF-8 sequence at s.data[i], 0 if there is none.
static iz utf8_seq(Str s, iz i)
{
    u8 c = s.data[i];
    if (c < 0x80) {
        return 1;
    }
    iz  n;
    u8  lo = 0x80, hi = 0xBF;
    if (c < 0xC2) {
        return 0;   // continuation byte or overlong form
    } else if (c < 0xE0) {
        n = 1;
    } else if (c < 0xF0) {
        n = 2;
        if (c == 0xE0) lo = 0xA0;
        if (c == 0xED) hi = 0x9F;
    } else if (c < 0xF5) {
        n = 3;
        if (c == 0xF0) lo = 0x90;
        if (c == 0xF4) hi = 0x8F;
    } else {
        return 0;
    }
    if (i + n >= s.len || s.data[i+1] < lo || s.data[i+1] > hi) {
        return 0;
    }
    for (iz k = 2; k <= n; k++) {
        if ((s.data[i+k] & 0xC0) != 0x80) {
            return 0;
        }
    }
    return n + 1;
}

static b32 valid_utf8(Str s)
{
    for (iz i = 0; i < s.len;) {
        iz n = utf8_seq(s, i);
        if (!n) {
            return 0;
        }
        i += n;
    }
    return 1;
}

// Python's UnicodeDecodeError text for the first invalid byte of s, or a
// null Str when s is valid UTF-8 (how a trashinfo that open().read() cannot
// decode is reported).
static Str utf8_error(Arena *a, Str s)
{
    for (iz i = 0; i < s.len;) {
        iz n = utf8_seq(s, i);
        if (n) {
            i += n;
            continue;
        }
        u8  c    = s.data[i];
        iz  end  = i + 1;   // one past the offending bytes
        Str why  = S("invalid start byte");
        iz  need = c >= 0xF0 && c <= 0xF4 ? 3
                 : c >= 0xE0 && c <= 0xEF ? 2
                 : c >= 0xC2 && c <= 0xDF ? 1 : 0;
        if (need) {
            why = S("unexpected end of data");
            end = s.len;
            u8 lo = 0x80, hi = 0xBF;
            if (c == 0xE0) lo = 0xA0;
            if (c == 0xED) hi = 0x9F;
            if (c == 0xF0) lo = 0x90;
            if (c == 0xF4) hi = 0x8F;
            for (iz k = 1; k <= need && i + k < s.len; k++) {
                u8  b  = s.data[i+k];
                b32 ok = k == 1 ? b >= lo && b <= hi : (b & 0xC0) == 0x80;
                if (!ok) {
                    why = S("invalid continuation byte");
                    end = i + k;
                    break;
                }
            }
        }
        Str m = S("'utf-8' codec can't decode ");
        if (end - i == 1) {
            Str h = {.data = new(a, 2, u8), .len = 2};
            h.data[0] = (u8)"0123456789abcdef"[c>>4];
            h.data[1] = (u8)"0123456789abcdef"[c&15];
            m = concat(a, concat(a, m, S("byte 0x")), h);
            m = concat(a, m, S(" in position "));
            m = concat(a, m, istr(a, i));
        } else {
            m = concat(a, m, S("bytes in position "));
            m = concat(a, m, istr(a, i));
            m = concat(a, m, S("-"));
            m = concat(a, m, istr(a, end - 1));
        }
        m = concat(a, m, S(": "));
        return concat(a, m, why);
    }
    return (Str){};
}


// Dates

// Howard Hinnant's civil algorithms (proleptic Gregorian).
static i64 days_from_civil(i64 y, i32 m, i32 d)
{
    y -= m <= 2;
    i64 era = (y >= 0 ? y : y - 399) / 400;
    i32 yoe = (i32)(y - era * 400);
    i32 doy = (153*(m + (m > 2 ? -3 : 9)) + 2)/5 + d - 1;
    i32 doe = yoe * 365 + yoe/4 - yoe/100 + doy;
    return era * 146097 + (i64)doe - 719468;
}

static i32 days_in_month(i64 y, i32 m)
{
    static const i32 len[12] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
    if (m == 2 && y%4==0 && (y%100!=0 || y%400==0)) {
        return 29;
    }
    return len[m-1];
}

static i64 datetime_key(DateTime t)
{
    return days_from_civil(t.year, t.month, t.day) * 86400
         + (i64)t.hour*3600 + (i64)t.min*60 + t.sec;
}

// datetime.strptime(text, "%Y-%m-%dT%H:%M:%S"), the way CPython's _strptime
// reads it: a regex per field tried in order with backtracking (so " 5" is a
// day, a 't' passes for the 'T', and any Unicode decimal digit passes where
// the regex has \d), the first match must end at the end of the text, and
// the numbers must then make a valid datetime (year 1..9999, seconds 0..59).
enum : i32 { DF_Y, DF_MON, DF_D, DF_H, DF_MIN, DF_S, DF_COUNT };

static b32 x_is(u32 *x, iz n, iz i, u32 c)
{
    return i < n && x[i] == c;
}

static i32 dfdigit(u32 *x, iz n, iz i)   // \d: a Unicode decimal digit
{
    return i < n ? decimaldigit(x[i]) : -1;
}

static b32 dfin(u32 *x, iz n, iz i, u32 lo, u32 hi)   // [lo-hi], ASCII
{
    return i < n && x[i] >= lo && x[i] <= hi;
}

// The alternatives of one field at x[i], in the regex's order: lengths and
// values.  Returns how many.
static iz dfalts(i32 f, u32 *x, iz n, iz i, iz *len, i32 *val)
{
    iz k = 0;
    i32 d0 = dfdigit(x, n, i), d1 = dfdigit(x, n, i + 1);
    i32 a0 = dfin(x, n, i, '0', '9') ? (i32)(x[i] - '0') : -1;
    i32 a1 = dfin(x, n, i + 1, '0', '9') ? (i32)(x[i+1] - '0') : -1;
    switch (f) {
    case DF_D:   // 3[0-1] | [1-2]\d | 0[1-9] | [1-9] | ' '[1-9]
        if (x_is(x, n, i, '3') && dfin(x, n, i + 1, '0', '1')) {
            len[k] = 2; val[k++] = 30 + a1;
        }
        if (dfin(x, n, i, '1', '2') && d1 >= 0) {
            len[k] = 2; val[k++] = a0 * 10 + d1;
        }
        if (x_is(x, n, i, '0') && dfin(x, n, i + 1, '1', '9')) {
            len[k] = 2; val[k++] = a1;
        }
        if (dfin(x, n, i, '1', '9')) {
            len[k] = 1; val[k++] = a0;
        }
        if (x_is(x, n, i, ' ') && dfin(x, n, i + 1, '1', '9')) {
            len[k] = 2; val[k++] = a1;
        }
        break;
    case DF_MON:   // 1[0-2] | 0[1-9] | [1-9]
        if (x_is(x, n, i, '1') && dfin(x, n, i + 1, '0', '2')) {
            len[k] = 2; val[k++] = 10 + a1;
        }
        if (x_is(x, n, i, '0') && dfin(x, n, i + 1, '1', '9')) {
            len[k] = 2; val[k++] = a1;
        }
        if (dfin(x, n, i, '1', '9')) {
            len[k] = 1; val[k++] = a0;
        }
        break;
    case DF_H:   // 2[0-3] | [0-1]\d | \d
        if (x_is(x, n, i, '2') && dfin(x, n, i + 1, '0', '3')) {
            len[k] = 2; val[k++] = 20 + a1;
        }
        if (dfin(x, n, i, '0', '1') && d1 >= 0) {
            len[k] = 2; val[k++] = a0 * 10 + d1;
        }
        if (d0 >= 0) {
            len[k] = 1; val[k++] = d0;
        }
        break;
    case DF_MIN:   // [0-5]\d | \d
        if (dfin(x, n, i, '0', '5') && d1 >= 0) {
            len[k] = 2; val[k++] = a0 * 10 + d1;
        }
        if (d0 >= 0) {
            len[k] = 1; val[k++] = d0;
        }
        break;
    case DF_S:   // 6[0-1] | [0-5]\d | \d
        if (x_is(x, n, i, '6') && dfin(x, n, i + 1, '0', '1')) {
            len[k] = 2; val[k++] = 60 + a1;
        }
        if (dfin(x, n, i, '0', '5') && d1 >= 0) {
            len[k] = 2; val[k++] = a0 * 10 + d1;
        }
        if (d0 >= 0) {
            len[k] = 1; val[k++] = d0;
        }
        break;
    }
    return k;
}

// Matches the rest of the format from field f at x[i]; the end of the match
// goes in *end.  The literal after each field is part of the backtracking.
static b32 dfmatch(i32 f, u32 *x, iz n, iz i, i32 *v, iz *end)
{
    static const u32 lit[DF_COUNT] = {'-', '-', 'T', ':', ':', 0};
    if (f == DF_Y) {
        for (iz k = 0; k < 4; k++) {
            i32 d = dfdigit(x, n, i + k);
            if (d < 0) {
                return 0;
            }
            v[DF_Y] = v[DF_Y]*10 + d;
        }
        i += 4;
        if (!x_is(x, n, i, '-')) {
            return 0;
        }
        return dfmatch(DF_MON, x, n, i + 1, v, end);
    }
    iz  len[5];
    i32 val[5];
    iz  na = dfalts(f, x, n, i, len, val);
    for (iz a = 0; a < na; a++) {
        iz j = i + len[a];
        v[f] = val[a];
        if (f == DF_S) {
            *end = j;
            return 1;
        }
        b32 ok = lit[f] == 'T' ? j < n && (x[j] == 'T' || x[j] == 't')
                               : x_is(x, n, j, lit[f]);
        if (ok && dfmatch(f + 1, x, n, j + 1, v, end)) {
            return 1;
        }
    }
    return 0;
}

static b32 parse_datetime(Str s, DateTime *out)
{
    u32 x[32];
    iz  n = 0;
    for (iz i = 0; i < s.len; n++) {
        if (n == countof(x)) {
            return 0;   // longer than any match
        }
        iz k = utf8_seq(s, i);
        x[n] = k ? utf8_cp(s, i, k) : 0xDC00u + s.data[i];
        i += k ? k : 1;
    }
    i32 v[DF_COUNT] = {};
    iz  end = 0;
    if (!dfmatch(DF_Y, x, n, 0, v, &end) || end != n) {
        return 0;
    }
    if (v[DF_Y] < 1 || v[DF_MON] < 1 || v[DF_MON] > 12 || v[DF_D] < 1
        || v[DF_D] > days_in_month(v[DF_Y], v[DF_MON]) || v[DF_H] > 23
        || v[DF_MIN] > 59 || v[DF_S] > 59) {
        return 0;
    }
    out->year  = v[DF_Y];
    out->month = v[DF_MON];
    out->day   = v[DF_D];
    out->hour  = v[DF_H];
    out->min   = v[DF_MIN];
    out->sec   = v[DF_S];
    return 1;
}

static u8 *put2(u8 *d, i32 v)
{
    affirm(v >= 0 && v < 100);
    d[0] = (u8)('0' + v/10);
    d[1] = (u8)('0' + v%10);
    return d + 2;
}

// Nineteen bytes: <YYYY><sep><MM>-<DD><mid><hh>:<mm>:<ss>
static Str format_datetime(Arena *a, DateTime t, u8 dsep, u8 mid)
{
    u8 *d = new(a, 19, u8);
    u8 *e = d;
    affirm(t.year >= 0 && t.year <= 9999);
    e[0] = (u8)('0' + t.year/1000 % 10);
    e[1] = (u8)('0' + t.year/100  % 10);
    e[2] = (u8)('0' + t.year/10   % 10);
    e[3] = (u8)('0' + t.year      % 10);
    e += 4;
    *e++ = dsep;
    e = put2(e, t.month);
    *e++ = '-';
    e = put2(e, t.day);
    *e++ = mid;
    e = put2(e, t.hour);
    *e++ = ':';
    e = put2(e, t.min);
    *e++ = ':';
    e = put2(e, t.sec);
    return (Str){d, 19};
}


// Whole-file and line input

// Reads a whole file into *a.  The buffer grows in place at the arena front.
static b32 readall(Os *os, Arena *a, Str path, Str *out)
{
    i32 fd = os_open(os, *a, path, 0, 0);
    if (fd < 0) {
        return 0;
    }
    iz  cap = 1 << 12;
    u8 *d   = new(a, cap, u8);
    iz  n   = 0;
    for (;;) {
        if (n == cap) {
            affirm((byte *)d + cap == a->beg);   // in-place growth contract
            new(a, cap, u8);
            cap += cap;
        }
        iz r = os_read(os, fd, d + n, cap - n);
        if (r < 0) {
            os_close(os, fd);
            return 0;
        }
        if (!r) {
            break;
        }
        n += r;
    }
    os_close(os, fd);
    *out = span(d, d + n);
    return 1;
}

typedef struct {
    Os *os;
    i32 fd;
    u8  buf[1 << 12];
    iz  len;
    iz  pos;
} LineReader;

// Reads one line without its newline into *a.  Returns 0 on end of input
// with no data; a final unterminated line still counts as a line.
static b32 readline(Os *os, LineReader *r, Arena *a, Str *out)
{
    Str s = {};
    for (;;) {
        if (r->pos == r->len) {
            r->pos = 0;
            r->len = os_read(os, r->fd, r->buf, countof(r->buf));
            if (r->len <= 0) {
                if (!s.len) {
                    return 0;
                }
                break;
            }
        }
        u8 *beg = r->buf + r->pos;
        u8 *end = r->buf + r->len;
        u8 *nl  = beg;
        for (; nl < end && *nl != '\n'; nl++) {}
        iz take = nl < end ? nl - beg + 1 : end - beg;
        s = concat(a, s, span(beg, beg + take));
        r->pos += take;
        if (nl < end) {
            break;
        }
    }
    if (s.len && s.data[s.len-1] == '\n') {
        s = cuttail(s, 1);   // like input(): a carriage return stays
    }
    *out = s;
    return 1;
}

// Command context and diagnostics

typedef struct {
    Os     *os;
    Arena  *perm;
    Arena   scratch;
    Output *out;
    Output *err;
    Str     prog;   // persona: basename of argv[0]
} Ctx;

[[noreturn]] static void finish(Ctx *c, i32 status)
{
    flush(c->out);
    flush(c->err);
    os_exit(c->os, status);
}

// "<prog>: <msg>" on stderr, then exit.
[[noreturn]] static void die(Ctx *c, i32 status, Str msg)
{
    print(c->err, c->prog);
    print(c->err, S(": "));
    print(c->err, msg);
    print(c->err, S("\n"));
    finish(c, status);
}

static void say(Ctx *, Output *b, Str msg)   // one line, no prefix
{
    print(b, msg);
    print(b, S("\n"));
}

// "<prog>: <msg>" on stderr (no exit).
static void prefixes(Ctx *c, Output *b, Str msg)
{
    print(b, c->prog);
    print(b, S(": "));
    say(c, b, msg);
}

// lexists: a dangling symlink exists, like Python's os.path.lexists.
static b32 lexists(Os *os, Arena scratch, Str path)
{
    Stat st = {};
    return os_stat(os, scratch, path, 0, &st);
}


// Pushes one resolved component, doubling the stack in *a when it is full:
// symlink targets can add arbitrarily many components beyond the path's own.
static void rpush(Arena *a, Str **res, iz *cap, iz *rn, Str c)
{
    if (*rn == *cap) {
        Str *grown = new(a, *cap*2, Str);
        for (iz k = 0; k < *rn; k++) {
            grown[k] = (*res)[k];
        }
        *res = grown;
        *cap *= 2;
    }
    (*res)[(*rn)++] = c;
}

// The cwd, or the command's failure when it cannot be read (a deleted
// working directory), as os.getcwd() raising ends upstream.
static Str cwd_or_die(Ctx *c, Arena *a)
{
    Str cwd = os_getcwd(c->os, a);
    if (!cwd.data) {
        i32 err = os_errno(c->os);
        Str m = concat(a, S("[Errno "), istr(a, err));
        m = concat(a, m, S("] "));
        die(c, 1, concat(a, m, os_strerror(c->os, err)));
    }
    return cwd;
}

// Python's os.path.realpath: symlinks resolved, nonexistent tails kept as
// given.  A relative path needs the cwd; without one the command fails, as
// os.getcwd() raising would.
static Str realpath_(Ctx *c, Arena *a, Arena scratch, Str p)
{
    enum { MAXLINKS = 40 };
    Os *os = c->os;

    iz  cap = p.len/2 + 2;
    Str *res = new(a, cap, Str);
    iz  rn = 0;
    b32 rooted = p.len && p.data[0] == '/';

    // Pending components: a stack of spans.  Symlink targets push a run of
    // components that must be processed before whatever is already pending,
    // so runs are pushed in reverse.
    typedef struct WNode WNode;
    struct WNode {
        WNode *next;
        Str    s;
    };
    WNode *work = 0;

    // Seed with p's components in reverse.
    Str *seed = new(a, cap, Str);
    iz  sn = 0;
    for (iz i = 0; i < p.len;) {
        while (i < p.len && p.data[i] == '/') {
            i++;
        }
        iz s = i;
        while (i < p.len && p.data[i] != '/') {
            i++;
        }
        if (i > s) {
            seed[sn++] = span(p.data + s, p.data + i);
        }
    }
    for (iz k = sn; k-- > 0;) {
        WNode *n = new(a, 1, WNode);
        n->s    = seed[k];
        n->next = work;
        work    = n;
    }

    i32 links = 0;
    while (work) {
        WNode *w = work;
        work = w->next;
        Str c = w->s;
        if (equals(c, S("."))) {
            continue;
        }
        if (equals(c, S(".."))) {
            if (rn && !equals(res[rn-1], S(".."))) {
                rn--;
            } else if (!rooted) {
                rpush(a, &res, &cap, &rn, c);
            }
            continue;
        }
        Str cand = rjoin(a, rooted, res, rn, c);
        Stat st  = {};
        if (!os_stat(os, scratch, cand, 0, &st)) {
            rpush(a, &res, &cap, &rn, c);   // nonexistent: keep lexically
            continue;
        }
        if (st.kind == KIND_LINK) {
            Str target;
            if (!os_readlink(os, a, cand, &target) || ++links > MAXLINKS) {
                rpush(a, &res, &cap, &rn, c);
                continue;
            }
            if (target.len && target.data[0] == '/') {
                rn = 0;
                rooted = 1;
            }
            Str *push = new(a, target.len/2 + 2, Str);
            iz pn = 0;
            for (iz i = 0; i < target.len;) {
                while (i < target.len && target.data[i] == '/') {
                    i++;
                }
                iz s = i;
                while (i < target.len && target.data[i] != '/') {
                    i++;
                }
                if (i > s) {
                    push[pn++] = span(target.data + s, target.data + i);
                }
            }
            for (iz k = pn; k-- > 0;) {
                WNode *n = new(a, 1, WNode);
                n->s    = push[k];
                n->next = work;
                work    = n;
            }
            continue;
        }
        rpush(a, &res, &cap, &rn, c);
    }

    if (rooted) {
        Str r = rjoin(a, 1, res, rn, S(""));
        return takehead(r, r.len - 1);   // drop the trailing separator
    }
    Str rel = S(".");
    if (rn) {
        rel = rjoin(a, 0, res, rn, S(""));
        rel = takehead(rel, rel.len - 1);
    }
    return normpath(a, join(a, cwd_or_die(c, a), rel));
}

// os.path.abspath: a relative path joins the cwd; absolute ones need none.
static Str abspath_(Ctx *c, Arena *a, Str p)
{
    if (p.len && p.data[0] == '/') {
        return normpath(a, p);
    }
    return normpath(a, join(a, cwd_or_die(c, a), p));
}


// Trashinfo files

enum : i32 { TI_OK = 0, TI_NOPATH, TI_BADUTF8, TI_READERR };

typedef struct {
    Str      path;        // percent-decoded original location; valid iff TI_OK
    DateTime date;
    b32      has_date;
    Str      infopath;
    Str      why;         // TI_BADUTF8: Python's decode error text
} TrashInfo;

// Reads and parses one .trashinfo file.  Only the first Path= and the first
// DeletionDate= line are considered; the date must match
// "YYYY-MM-DDTHH:MM:SS" with strptime-lenient padding and no timezone.  The
// result lives in *a (a scratch copy); clone what must survive.
static TrashInfo trashinfo_read(Ctx *c, Arena *a, Arena, Str infopath,
                                i32 *status)
{
    TrashInfo ti = {};
    ti.infopath = infopath;
    Str content;
    if (!readall(c->os, a, infopath, &content)) {
        *status = TI_READERR;
        return ti;
    }
    if (!valid_utf8(content)) {
        ti.why  = utf8_error(a, content);
        *status = TI_BADUTF8;
        return ti;
    }
    b32 dated = 0;
    Str rest  = content;
    while (rest.len) {
        // Text-mode reading: \r\n and a lone \r end a line like \n does.
        iz k = 0;
        for (; k < rest.len && rest.data[k] != '\n' && rest.data[k] != '\r';
             k++) {}
        Str line = takehead(rest, k);
        iz  skip = k < rest.len ? 1 : 0;
        if (k + 1 < rest.len && rest.data[k] == '\r'
            && rest.data[k+1] == '\n') {
            skip = 2;
        }
        rest = cuthead(rest, k + skip);
        if (!ti.path.data && startswith(line, S("Path="))) {
            ti.path = percentdecode(a, cuthead(line, 5));
        } else if (!dated && startswith(line, S("DeletionDate="))) {
            dated = 1;   // the first line wins, even when invalid
            ti.has_date = parse_datetime(cuthead(line, 13), &ti.date);
        }
    }
    if (!ti.path.data) {
        *status = TI_NOPATH;
        return ti;
    }
    *status = TI_OK;
    return ti;
}

// <trash>/files/<stem> for an info entry named <stem>.trashinfo (spec 3.4).
static Str backuppath(Arena *a, Str trashdir, Str infoname)
{
    affirm(endswith(infoname, S(".trashinfo")));
    Str stem = takehead(infoname, infoname.len - 10);
    return join(a, join(a, trashdir, S("files")), stem);
}

static Str fmt_date(Arena *a, DateTime t)   // "YYYY-MM-DD HH:MM:SS"
{
    return format_datetime(a, t, '-', ' ');
}


// The first n characters of s, counting each invalid byte as one character
// (Python's surrogateescape view of a file name); n may exceed the length.
static Str takechars(Str s, iz n)
{
    iz i = 0;
    for (; n > 0 && i < s.len; n--) {
        iz k = utf8_seq(s, i);
        i += k ? k : 1;
    }
    return takehead(s, i);
}

static iz countchars(Str s)
{
    iz n = 0;
    for (iz i = 0; i < s.len; n++) {
        iz k = utf8_seq(s, i);
        i += k ? k : 1;
    }
    return n;
}

// Python's repr() of a str, as it shows inside upstream's warning texts.
static Str pyrepr(Arena *a, Str s)
{
    b32 sq = 0, dq = 0;
    for (iz i = 0; i < s.len; i++) {
        sq |= s.data[i] == '\'';
        dq |= s.data[i] == '"';
    }
    u8  q = sq && !dq ? '"' : '\'';
    Str r = {.data = new(a, 0, u8)};
    r = concat(a, r, (Str){&q, 1});
    for (iz i = 0; i < s.len;) {
        iz n = utf8_seq(s, i);
        u8 c = s.data[i];
        if (!n) {
            u8 esc[6] = {'\\', 'u', 'd', 'c',
                         (u8)"0123456789abcdef"[c>>4],
                         (u8)"0123456789abcdef"[c&15]};
            r = concat(a, r, (Str){esc, 6});
            i++;
        } else if (c == q || c == '\\') {
            u8 esc[2] = {'\\', c};
            r = concat(a, r, (Str){esc, 2});
            i++;
        } else if (c == '\n' || c == '\r' || c == '\t') {
            u8 esc[2] = {'\\', c == '\n' ? 'n' : c == '\r' ? 'r' : 't'};
            r = concat(a, r, (Str){esc, 2});
            i++;
        } else if (c < 0x20 || c == 0x7F) {
            u8 esc[4] = {'\\', 'x', (u8)"0123456789abcdef"[c>>4],
                         (u8)"0123456789abcdef"[c&15]};
            r = concat(a, r, (Str){esc, 4});
            i++;
        } else {
            r = concat(a, r, span(s.data + i, s.data + i + n));
            i += n;
        }
    }
    return concat(a, r, (Str){&q, 1});
}


// Argument parsing: Python 3.12's argparse, as these commands use it
//
// A command describes its parser as data (Parser, Arg), the arguments in
// upstream's registration order.  ap_parse follows argparse's own algorithm:
// every argument is classified into an O/A/- pattern (an option, a plain
// argument, the first --), then positionals and optionals are consumed in
// turn, so errors surface in the same order and with the same words.
// ap_usage and ap_help follow HelpFormatter and wrap to $COLUMNS (or the
// terminal, or 80) minus two.

enum : i32 { AK_STORE, AK_FLAG, AK_COUNT, AK_APPEND, AK_HELP, AK_VERSION,
             AK_COMPLETION };
enum : i32 { NA_ONE, NA_ZERO, NA_OPT, NA_STAR };

typedef struct {
    Str opts[4];      // option strings, empty for a positional
    iz  nopts;
    Str metavar;      // shown for a value (positionals always have one)
    Str choices[4];
    iz  nchoices;
    i32 kind;
    i32 nargs;
    b32 isint;        // type=int
    Str help;         // null: no help text
    b32 hidden;       // help=SUPPRESS
    Str defshow;      // ArgumentDefaultsHelpFormatter's "(default: ...)"
} Arg;

typedef struct {
    Str  usage;       // explicit usage text, else computed
    Str  description;
    Str  epilog;
    b32  rawdesc;     // RawDescriptionHelpFormatter
    b32  defaults;    // ArgumentDefaultsHelpFormatter
    Arg *args;
    iz   nargs;
} Parser;

typedef struct OptVal OptVal;
struct OptVal {
    OptVal *next;
    i32     id;     // index into the command's Arg table
    Str     val;
};

typedef struct {
    OptVal *vals;    // in command-line order
    Str    *pos;     // positional arguments
    iz      npos;
} ParsedOpts;

static b32 optgiven(ParsedOpts *p, i32 id)
{
    for (OptVal *v = p->vals; v; v = v->next) {
        if (v->id == id) {
            return 1;
        }
    }
    return 0;
}

static iz optcount(ParsedOpts *p, i32 id)
{
    iz n = 0;
    for (OptVal *v = p->vals; v; v = v->next) {
        n += v->id == id;
    }
    return n;
}

// The last value given for an option; a null Str when absent.
static Str optlast(ParsedOpts *p, i32 id)
{
    Str r = {};
    for (OptVal *v = p->vals; v; v = v->next) {
        if (v->id == id) {
            r = v->val;
        }
    }
    return r;
}

static Str optval(ParsedOpts *p, i32 id, iz k)
{
    iz n = 0;
    for (OptVal *v = p->vals; v; v = v->next) {
        if (v->id == id && n++ == k) {
            return v->val;
        }
    }
    affirm(0);
    return (Str){};
}

// -- text wrapping (textwrap.wrap, for the help strings) -----------------

static Str collapse(Arena *a, Str s)   // \s+ -> " ", stripped
{
    Str r = {.data = new(a, 0, u8)};
    b32 gap = 0;
    for (iz i = 0; i < s.len; i++) {
        u8 c = s.data[i];
        if (c==' ' || c=='\t' || c=='\n' || c=='\r' || c=='\f' || c=='\v') {
            gap = r.len > 0;
        } else {
            if (gap) {
                r = concat(a, r, S(" "));
                gap = 0;
            }
            r = concat(a, r, (Str){&c, 1});
        }
    }
    return r;
}

static b32 isletter(u8 c)
{
    return (c>='A' && c<='Z') || (c>='a' && c<='z') || c=='_' || c>=0x80;
}

static b32 isword(u8 c)
{
    return isletter(c) || (c>='0' && c<='9');
}

static b32 iswordpunct(u8 c)
{
    return isword(c) || c=='!' || c=='"' || c=='\'' || c=='&' || c=='.'
        || c==',' || c=='?';
}

// -{2,} followed by a word character, starting at t[k]
static b32 emdash(Str t, iz k)
{
    iz j = k;
    while (j < t.len && t.data[j] == '-') {
        j++;
    }
    return j - k >= 2 && j < t.len && isword(t.data[j]);
}

// A hyphen at t[k] that textwrap may break after: two letters, or
// letter-hyphen-letter, before it, and letter, optional hyphen, letter after.
static b32 hyphenbreak(Str t, iz k)
{
    b32 behind = (k >= 2 && isletter(t.data[k-2]) && isletter(t.data[k-1]))
              || (k >= 3 && isletter(t.data[k-3]) && t.data[k-2]=='-'
                  && isletter(t.data[k-1]));
    if (!behind || k + 2 >= t.len || !isletter(t.data[k+1])) {
        return 0;
    }
    return isletter(t.data[k+2])
        || (t.data[k+2] == '-' && k + 3 < t.len && isletter(t.data[k+3]));
}

// textwrap's wordsep_re: words (split after some hyphens and before
// em-dashes) and single spaces.
static iz wordchunks(Arena *a, Str t, Str **out)
{
    Str *ch = new(a, t.len + 1, Str);
    iz   n  = 0;
    for (iz i = 0; i < t.len;) {
        if (t.data[i] == ' ') {
            ch[n++] = span(t.data + i, t.data + i + 1);
            i++;
            continue;
        }
        if (t.data[i] == '-' && i > 0 && iswordpunct(t.data[i-1])
            && emdash(t, i)) {
            iz k = i;
            while (k < t.len && t.data[k] == '-') {
                k++;
            }
            ch[n++] = span(t.data + i, t.data + k);
            i = k;
            continue;
        }
        iz k = i + 1;
        for (; k < t.len && t.data[k] != ' '; k++) {
            if (t.data[k] == '-' && hyphenbreak(t, k)) {
                k++;
                break;
            }
            if (iswordpunct(t.data[k-1]) && emdash(t, k)) {
                break;
            }
        }
        ch[n++] = span(t.data + i, t.data + k);
        i = k;
    }
    *out = ch;
    return n;
}

// textwrap.wrap(text, width): the lines, in *out.
static iz wraplines(Arena *a, Str text, iz width, Str **out)
{
    Str  t  = collapse(a, text);
    Str *ch;
    iz   nc = wordchunks(a, t, &ch);
    Str *lines = new(a, nc + t.len + 2, Str);
    iz   nl = 0;
    for (iz ci = 0; ci < nc;) {
        Str line = {.data = new(a, 0, u8)};
        iz  cur  = 0;
        b32 lastspace = 0;
        if (nl > 0 && ch[ci].len == 1 && ch[ci].data[0] == ' ') {
            ci++;
        }
        while (ci < nc) {
            iz l = countchars(ch[ci]);
            if (cur + l > width) {
                break;
            }
            line = concat(a, line, ch[ci]);
            lastspace = ch[ci].len == 1 && ch[ci].data[0] == ' ';
            cur += l;
            ci++;
        }
        if (ci < nc && countchars(ch[ci]) > width) {   // a word too long
            iz  left  = width < 1 ? 1 : width - cur;
            Str chunk = ch[ci];
            iz  end   = left;
            if (countchars(chunk) > left) {
                iz h = -1;   // chunk.rfind('-', 0, left)
                for (iz k = 0; k < left && k < chunk.len; k++) {
                    if (chunk.data[k] == '-') {
                        h = k;
                    }
                }
                b32 other = 0;
                for (iz k = 0; k < h; k++) {
                    other |= chunk.data[k] != '-';
                }
                if (h > 0 && other) {
                    end = h + 1;
                }
            }
            Str head = takechars(chunk, end);
            line = concat(a, line, head);
            ch[ci] = cuthead(chunk, head.len);
            lastspace = 0;
        }
        if (lastspace) {
            line = cuttail(line, 1);
        }
        if (line.len) {
            lines[nl++] = line;
        }
    }
    *out = lines;
    return nl;
}

// -- HelpFormatter -------------------------------------------------------

static Str ap_metavar(Arena *a, Arg *x)
{
    if (x->metavar.data) {
        return x->metavar;
    }
    Str r = S("{");
    for (iz k = 0; k < x->nchoices; k++) {
        r = concat(a, r, k ? S(",") : S(""));
        r = concat(a, r, x->choices[k]);
    }
    return concat(a, r, S("}"));
}

static Str ap_fmtargs(Arena *a, Arg *x)   // _format_args
{
    Str m = ap_metavar(a, x);
    switch (x->nargs) {
    case NA_OPT:
        return concat(a, concat(a, S("["), m), S("]"));
    case NA_STAR:
        return concat(a, concat(a, S("["), m), S(" ...]"));
    default:
        return m;
    }
}

// How the argument is shown on the left of its help line.
static Str ap_invocation(Arena *a, Arg *x)
{
    if (!x->nopts) {
        return ap_metavar(a, x);
    }
    Str r = {.data = new(a, 0, u8)};
    for (iz k = 0; k < x->nopts; k++) {
        r = concat(a, r, k ? S(", ") : S(""));
        r = concat(a, r, x->opts[k]);
        if (x->nargs != NA_ZERO) {
            r = concat(a, concat(a, r, S(" ")), ap_fmtargs(a, x));
        }
    }
    return r;
}

// One argument's piece of the usage line.
static Str ap_usagepart(Arena *a, Arg *x)
{
    if (!x->nopts) {
        return ap_fmtargs(a, x);
    }
    Str r = x->opts[0];
    if (x->nargs != NA_ZERO) {
        r = concat(a, concat(a, r, S(" ")), ap_fmtargs(a, x));
    }
    return concat(a, concat(a, S("["), r), S("]"));
}

static Str joinparts(Arena *a, Str *parts, iz n)
{
    Str r = {.data = new(a, 0, u8)};
    for (iz k = 0; k < n; k++) {
        r = concat(a, r, k ? S(" ") : S(""));
        r = concat(a, r, parts[k]);
    }
    return r;
}

// get_lines of _format_usage: parts wrapped at text_width after indent.
static iz ap_getlines(Arena *a, Str *parts, iz n, iz indent, iz prefixlen,
                      iz text_width, Str *lines)
{
    iz nl = 0;
    Str line = {.data = new(a, 0, u8)};
    b32 have = 0;
    iz  line_len = prefixlen ? prefixlen - 1 : indent - 1;
    for (iz k = 0; k < n; k++) {
        iz plen = countchars(parts[k]);
        if (line_len + 1 + plen > text_width && have) {
            lines[nl++] = line;
            line = (Str){.data = new(a, 0, u8)};
            have = 0;
            line_len = indent - 1;
        }
        line = concat(a, concat(a, line, have ? S(" ") : S("")), parts[k]);
        have = 1;
        line_len += plen + 1;
    }
    if (have) {
        lines[nl++] = line;
    }
    return nl;
}

static Str spaces(Arena *a, iz n)
{
    Str r = {.data = new(a, 0, u8)};
    for (iz i = 0; i < n; i++) {
        r = concat(a, r, S(" "));
    }
    return r;
}

// _format_usage: "usage: ...\n\n"
static Str ap_usage(Arena *a, Parser *p, Str prog, iz width)
{
    Str prefix = S("usage: ");
    Str usage;
    if (p->usage.data) {
        usage = clone(a, p->usage);
        // "%(prog)s" is the only placeholder in an explicit usage
        Str pat = S("%(prog)s");
        iz at = -1;
        for (iz i = 0; i + pat.len <= usage.len; i++) {
            if (equals(takehead(cuthead(usage, i), pat.len), pat)) {
                at = i;
                break;
            }
        }
        if (at >= 0) {
            Str r = concat(a, clone(a, takehead(usage, at)), prog);
            usage = concat(a, r, cuthead(usage, at + pat.len));
        }
    } else {
        Str *opt = new(a, p->nargs + 1, Str), *pos = new(a, p->nargs + 1, Str);
        iz   no = 0, np = 0;
        for (iz k = 0; k < p->nargs; k++) {
            Arg *x = &p->args[k];
            if (x->hidden) {
                continue;
            }
            if (x->nopts) {
                opt[no++] = ap_usagepart(a, x);
            } else {
                pos[np++] = ap_usagepart(a, x);
            }
        }
        Str ou = joinparts(a, opt, no), pu = joinparts(a, pos, np);
        Str au = concat(a, concat(a, clone(a, ou), no && np ? S(" ") : S("")),
                        pu);
        usage = au.len ? concat(a, concat(a, clone(a, prog), S(" ")), au)
                       : clone(a, prog);
        iz text_width = width;
        if (countchars(prefix) + countchars(usage) > text_width) {
            iz  pl = countchars(prefix);
            iz  gl = countchars(prog);
            Str *lines = new(a, 2*p->nargs + 8, Str);
            iz  nl = 0;
            if ((pl + gl) * 4 <= 3 * text_width) {   // <= 0.75 * text_width
                iz indent = pl + gl + 1;
                Str ind = spaces(a, indent);
                if (no) {
                    Str *first = new(a, no + 1, Str);
                    first[0] = prog;
                    for (iz k = 0; k < no; k++) {
                        first[k + 1] = opt[k];
                    }
                    nl = ap_getlines(a, first, no + 1, indent, pl, text_width,
                                     lines);
                    // the first line carries the prefix, not the indent
                    nl += ap_getlines(a, pos, np, indent, 0, text_width,
                                      lines + nl);
                    for (iz k = 1; k < nl; k++) {
                        lines[k] = concat(a, clone(a, ind), lines[k]);
                    }
                } else if (np) {
                    Str *first = new(a, np + 1, Str);
                    first[0] = prog;
                    for (iz k = 0; k < np; k++) {
                        first[k + 1] = pos[k];
                    }
                    nl = ap_getlines(a, first, np + 1, indent, pl, text_width,
                                     lines);
                    for (iz k = 1; k < nl; k++) {
                        lines[k] = concat(a, clone(a, ind), lines[k]);
                    }
                } else {
                    lines[nl++] = prog;
                }
            } else {
                iz  indent = pl;
                Str ind = spaces(a, indent);
                Str *all = new(a, no + np + 1, Str);
                for (iz k = 0; k < no; k++) all[k] = opt[k];
                for (iz k = 0; k < np; k++) all[no + k] = pos[k];
                Str *tmp = new(a, 2*p->nargs + 8, Str);
                iz  nt = ap_getlines(a, all, no + np, indent, 0, text_width,
                                     tmp);
                if (nt > 1) {
                    nt = ap_getlines(a, opt, no, indent, 0, text_width, tmp);
                    nt += ap_getlines(a, pos, np, indent, 0, text_width,
                                      tmp + nt);
                }
                lines[nl++] = prog;
                for (iz k = 0; k < nt; k++) {
                    lines[nl++] = concat(a, clone(a, ind), tmp[k]);
                }
            }
            usage = (Str){.data = new(a, 0, u8)};
            for (iz k = 0; k < nl; k++) {
                usage = concat(a, concat(a, usage, k ? S("\n") : S("")),
                               lines[k]);
            }
        }
    }
    return concat(a, concat(a, clone(a, prefix), usage), S("\n\n"));
}

static Str ap_fill(Arena *a, Parser *p, Str text, iz width)   // _fill_text
{
    if (p->rawdesc) {
        return text;
    }
    Str *lines;
    iz   n = wraplines(a, text, width, &lines);
    Str  r = {.data = new(a, 0, u8)};
    for (iz k = 0; k < n; k++) {
        r = concat(a, concat(a, r, k ? S("\n") : S("")), lines[k]);
    }
    return r;
}

// One argument's block in the help (_format_action), at indent 2.
static Str ap_action(Arena *a, Parser *p, Arg *x, iz help_position,
                     iz help_width)
{
    iz  indent       = 2;
    iz  action_width = help_position - indent - 2;
    Str header       = ap_invocation(a, x);
    iz  hl           = countchars(header);
    iz  indent_first = 0;
    Str r            = spaces(a, indent);
    if (!x->help.len) {
        return concat(a, concat(a, r, header), S("\n"));
    } else if (hl <= action_width) {
        r = concat(a, r, header);
        r = concat(a, r, spaces(a, action_width - hl));
        r = concat(a, r, S("  "));
    } else {
        r = concat(a, concat(a, r, header), S("\n"));
        indent_first = help_position;
    }
    Str text = x->help;
    if (p->defaults && x->defshow.data && (x->nopts || x->nargs == NA_OPT
                                           || x->nargs == NA_STAR)) {
        text = concat(a, concat(a, clone(a, text), S(" (default: ")),
                       concat(a, clone(a, x->defshow), S(")")));
    }
    Str *lines;
    iz   n = wraplines(a, text, help_width, &lines);
    for (iz k = 0; k < n; k++) {
        r = concat(a, r, spaces(a, k ? help_position : indent_first));
        r = concat(a, concat(a, r, lines[k]), S("\n"));
    }
    return r;
}

static Str ap_section(Arena *a, Parser *p, b32 positional, Str heading,
                      iz help_position, iz help_width)
{
    Str items = {.data = new(a, 0, u8)};
    for (iz k = 0; k < p->nargs; k++) {
        Arg *x = &p->args[k];
        if (x->hidden || (x->nopts == 0) != positional) {
            continue;
        }
        items = concat(a, items, ap_action(a, p, x, help_position, help_width));
    }
    if (!items.len) {
        return S("");
    }
    Str r = concat(a, clone(a, S("\n")), heading);
    r = concat(a, r, S(":\n"));
    return concat(a, concat(a, r, items), S("\n"));
}

// parser.format_help()
static Str ap_help(Arena *a, Parser *p, Str prog, iz width)
{
    iz maxpos = width - 20 > 4 ? width - 20 : 4;
    if (maxpos > 24) {
        maxpos = 24;
    }
    iz maxlen = 0;
    for (iz k = 0; k < p->nargs; k++) {
        Arg *x = &p->args[k];
        if (!x->hidden) {
            iz l = countchars(ap_invocation(a, x)) + 2;
            maxlen = l > maxlen ? l : maxlen;
        }
    }
    iz help_position = maxlen + 2 < maxpos ? maxlen + 2 : maxpos;
    iz help_width    = width - help_position > 11 ? width - help_position : 11;
    iz text_width    = width > 11 ? width : 11;

    Str r = ap_usage(a, p, prog, width);
    if (p->description.len) {
        r = concat(a, r, ap_fill(a, p, p->description, text_width));
        r = concat(a, r, S("\n\n"));
    }
    r = concat(a, r, ap_section(a, p, 1, S("positional arguments"),
                                help_position, help_width));
    r = concat(a, r, ap_section(a, p, 0, S("options"), help_position,
                                help_width));
    if (p->epilog.len) {
        r = concat(a, r, ap_fill(a, p, p->epilog, text_width));
        r = concat(a, r, S("\n\n"));
    }
    // three or more newlines become two; the ends are stripped to one
    Str o = {.data = new(a, 0, u8)};
    iz  nl = 0;
    for (iz i = 0; i < r.len; i++) {
        nl = r.data[i] == '\n' ? nl + 1 : 0;
        if (nl <= 2) {
            o = concat(a, o, span(r.data + i, r.data + i + 1));
        }
    }
    while (o.len && o.data[0] == '\n') {
        o = cuthead(o, 1);
    }
    while (o.len && o.data[o.len-1] == '\n') {
        o = cuttail(o, 1);
    }
    return concat(a, o, S("\n"));
}

// -- parsing -------------------------------------------------------------

typedef struct {
    Ctx    *c;
    Parser *p;
    Str     prog;
    Arena  *a;
} AP;

// The width argparse wraps to: $COLUMNS, else the terminal's, else 80; less 2.
static iz ap_width(Ctx *c)
{
    iz cols = 0;
    Str env = os_getenv(c->os, S("COLUMNS"));
    if (env.data) {
        IntParsed ip = parseint(c->perm, env);
        if (ip.ok && !ip.toobig && !ip.neg) {
            cols = ip.value;
        }
    }
    if (cols <= 0) {
        cols = os_termwidth(c->os);
    }
    if (cols <= 0) {
        cols = 80;
    }
    return cols - 2;
}

// parser.error(): the usage, then "<prog>: error: <message>", exit 2.
[[noreturn]] static void ap_error(AP *ap, Str msg)
{
    Ctx *c = ap->c;
    Str u = ap_usage(ap->a, ap->p, ap->prog, ap_width(c));
    while (u.len && u.data[u.len-1] == '\n') {
        u = cuttail(u, 1);
    }
    print(c->err, u);
    print(c->err, S("\n"));
    print(c->err, ap->prog);
    print(c->err, S(": error: "));
    print(c->err, msg);
    print(c->err, S("\n"));
    finish(c, 2);
}

static Str ap_argname(AP *ap, Arg *x)
{
    if (!x->nopts) {
        return x->metavar;
    }
    Str r = {.data = new(ap->a, 0, u8)};
    for (iz k = 0; k < x->nopts; k++) {
        r = concat(ap->a, concat(ap->a, r, k ? S("/") : S("")), x->opts[k]);
    }
    return r;
}

[[noreturn]] static void ap_argerror(AP *ap, Arg *x, Str msg)
{
    Str m = concat(ap->a, S("argument "), ap_argname(ap, x));
    m = concat(ap->a, m, S(": "));
    ap_error(ap, concat(ap->a, m, msg));
}

// "usage" parser.error() for the commands' own checks
[[noreturn]] static void ap_fail(Ctx *c, Parser *p, Str msg)
{
    AP ap = {c, p, c->prog, c->perm};
    ap_error(&ap, msg);
}

typedef struct {
    Arg *arg;        // null: not an option of this parser
    Str  ostr;       // the option string matched
    b32  sepeq;      // separated by '='
    b32  hasexp;     // an explicit argument is attached
    Str  exp;
} OTuple;

typedef struct {
    Str  s;
    Arg *arg;
} OStr;

static b32 looks_negative(Str s)   // '^-\d+$|^-\d*\.\d+$' (a final \n is ok)
{
    if (s.len && s.data[s.len-1] == '\n') {
        s = cuttail(s, 1);
    }
    if (s.len < 2 || s.data[0] != '-') {
        return 0;
    }
    iz i = 1, nd = 0;
    iz before = 0;
    for (; i < s.len;) {
        iz k = utf8_seq(s, i);
        if (!k || decimaldigit(utf8_cp(s, i, k)) < 0) {
            break;
        }
        i += k;
        before++;
    }
    if (i == s.len) {
        return before > 0;
    }
    if (s.data[i] != '.') {
        return 0;
    }
    i++;
    for (; i < s.len;) {
        iz k = utf8_seq(s, i);
        if (!k || decimaldigit(utf8_cp(s, i, k)) < 0) {
            return 0;
        }
        i += k;
        nd++;
    }
    return nd > 0;
}

// _get_option_tuples
static iz ap_tuples(AP *ap, OStr *tab, iz ntab, Str arg, OTuple *out)
{
    iz n = 0;
    Cut eq = cut(arg, '=');
    if (arg.len > 1 && arg.data[1] == '-') {
        for (iz k = 0; k < ntab; k++) {
            if (startswith(tab[k].s, eq.head)) {
                out[n++] = (OTuple){tab[k].arg, tab[k].s, eq.ok, eq.ok, eq.tail};
            }
        }
    } else {
        Str shortp = takehead(arg, 2);
        for (iz k = 0; k < ntab; k++) {
            if (equals(tab[k].s, shortp)) {
                out[n++] = (OTuple){tab[k].arg, tab[k].s, 0, 1, cuthead(arg, 2)};
            } else if (startswith(tab[k].s, eq.head)) {
                out[n++] = (OTuple){tab[k].arg, tab[k].s, eq.ok, eq.ok, eq.tail};
            }
        }
    }
    (void)ap;
    return n;
}

// _parse_optional: how many tuples (0: a positional, -1: none matched
// but it is an optional all the same), filling out.
static iz ap_optional(AP *ap, OStr *tab, iz ntab, Str arg, OTuple *out)
{
    if (!arg.len || arg.data[0] != '-') {
        return 0;
    }
    for (iz k = 0; k < ntab; k++) {
        if (equals(tab[k].s, arg)) {
            out[0] = (OTuple){tab[k].arg, arg, 0, 0, {}};
            return 1;
        }
    }
    if (arg.len == 1) {
        return 0;
    }
    Cut eq = cut(arg, '=');
    if (eq.ok) {
        for (iz k = 0; k < ntab; k++) {
            if (equals(tab[k].s, eq.head)) {
                out[0] = (OTuple){tab[k].arg, eq.head, 1, 1, eq.tail};
                return 1;
            }
        }
    }
    iz n = ap_tuples(ap, tab, ntab, arg, out);
    if (n) {
        return n;
    }
    if (looks_negative(arg)) {
        return 0;
    }
    for (iz i = 0; i < arg.len; i++) {
        if (arg.data[i] == ' ') {
            return 0;
        }
    }
    out[0] = (OTuple){0, arg, 0, 0, {}};
    return 1;
}

typedef struct {
    Arg *x;
    Str *args;
    iz   n;
} ActT;

typedef struct {
    OptVal  *vals;
    OptVal **tail;
    Str     *pos;
    iz       npos;
} APState;

static void ap_record(AP *ap, APState *st, Arg *x, Str val)
{
    OptVal *v = new(ap->a, 1, OptVal);
    v->id  = (i32)(x - ap->p->args);
    v->val = val;
    *st->tail = v;
    st->tail  = &v->next;
}

// take_action: convert and check the values, then perform.
static void ap_take(AP *ap, APState *st, Arg *x, Str *args, iz nargs)
{
    Ctx *c = ap->c;
    Str  val = {};
    if (nargs == 1 && (x->nargs == NA_ONE || x->nargs == NA_OPT)) {
        val = args[0];
        if (x->isint && !parseint(ap->a, val).ok) {
            Str m = concat(ap->a, S("invalid int value: "), pyrepr(ap->a, val));
            ap_argerror(ap, x, m);
        }
        if (x->nchoices) {
            b32 ok = 0;
            for (iz k = 0; k < x->nchoices; k++) {
                ok |= equals(x->choices[k], val);
            }
            if (!ok) {
                Str m = concat(ap->a, S("invalid choice: "),
                               pyrepr(ap->a, val));
                m = concat(ap->a, m, S(" (choose from "));
                for (iz k = 0; k < x->nchoices; k++) {
                    m = concat(ap->a, concat(ap->a, m, k ? S(", ") : S("")),
                               x->choices[k]);
                }
                ap_argerror(ap, x, concat(ap->a, m, S(")")));
            }
        }
    }
    switch (x->kind) {
    case AK_HELP:
        print(c->out, ap_help(ap->a, ap->p, ap->prog, ap_width(c)));
        finish(c, 0);
    case AK_VERSION:
        print(c->out, S("0.26.9.29\n"));
        finish(c, 0);
    case AK_COMPLETION:
        print(c->out, S("Please install shtab firstly!\n"));
        finish(c, 0);
    default:
        break;
    }
    if (!x->nopts) {   // a positional: its values
        for (iz k = 0; k < nargs; k++) {
            st->pos[st->npos++] = args[k];
        }
        return;
    }
    ap_record(ap, st, x, val);
}

static ParsedOpts ap_parse(Ctx *c, Parser *p, iz argc, Str *args)
{
    Arena *a = c->perm;
    AP     ap = {c, p, c->prog, a};
    APState st = {};
    st.tail = &st.vals;
    st.pos  = new(a, argc + 1, Str);

    iz    ntab = 0;
    OStr *tab  = new(a, p->nargs*4 + 1, OStr);
    Arg  *posarg = 0;
    for (iz k = 0; k < p->nargs; k++) {
        Arg *x = &p->args[k];
        for (iz q = 0; q < x->nopts; q++) {
            tab[ntab++] = (OStr){x->opts[q], x};
        }
        if (!x->nopts) {
            posarg = x;
        }
    }

    // the O/A/- pattern, and the tuples of every option-like argument
    u8      *pat    = new(a, argc + 1, u8);
    OTuple **tuples = new(a, argc + 1, OTuple *);
    iz      *ntup   = new(a, argc + 1, iz);
    iz       maxopt = -1;
    for (iz i = 0; i < argc; i++) {
        if (equals(args[i], S("--"))) {
            pat[i] = '-';
            for (i++; i < argc; i++) {
                pat[i] = 'A';
            }
            break;
        }
        OTuple *t = new(a, ntab + 2, OTuple);
        iz      n = ap_optional(&ap, tab, ntab, args[i], t);
        pat[i] = n ? 'O' : 'A';
        if (n) {
            tuples[i] = t;
            ntup[i]   = n;
            maxopt    = i;
        }
    }

    Str *extras  = new(a, argc + 1, Str);
    iz   nextras = 0;
    b32  posdone = 0;

    // consume_positionals (one positional at most per parser)
    #define PATAT(i) ((i) < argc ? pat[i] : 0)
    iz start = 0;
    for (;;) {
        // the next option index, or the loop ends
        if (start > maxopt) {
            break;
        }
        iz next = start;
        while (next < argc && !tuples[next]) {
            next++;
        }
        if (start != next) {
            // consume any positionals preceding the next option
            iz stop = start;
            if (posarg && !posdone) {
                iz n = 0;
                if (posarg->nargs == NA_OPT) {
                    while (PATAT(start + n) == '-') n++;
                    if (PATAT(start + n) == 'A') n++;
                    while (PATAT(start + n) == '-') n++;
                } else if (posarg->nargs == NA_STAR) {
                    while (PATAT(start + n) == '-' || PATAT(start + n) == 'A') {
                        n++;
                    }
                } else {   // exactly one: -*A-*
                    iz m = 0;
                    while (PATAT(start + m) == '-') m++;
                    if (PATAT(start + m) == 'A') {
                        n = m + 1;
                        while (PATAT(start + n) == '-') n++;
                    }
                }
                b32 consumed = !(n == 0 && PATAT(start + n) == 'O');
                if (posarg->nargs == NA_ONE && n == 0) {
                    consumed = 0;
                }
                if (consumed) {
                    Str *vals = new(a, n + 1, Str);
                    iz   nv = 0;
                    b32  skipped = 0;
                    for (iz i = start; i < start + n; i++) {
                        if (pat[i] == '-' && !skipped) {
                            skipped = 1;   // the first -- is dropped
                            continue;
                        }
                        vals[nv++] = args[i];
                    }
                    ap_take(&ap, &st, posarg, vals, nv);
                    posdone = 1;
                    stop = start + n;
                }
            }
            if (stop > start) {
                start = stop;
                continue;
            }
            // not at an option: the arguments up to it are extra
            for (iz i = start; i < next; i++) {
                extras[nextras++] = args[i];
            }
            start = next;
        }

        // consume_optional
        OTuple *t = tuples[start];
        iz      nt = ntup[start];
        if (nt > 1) {
            Str m = concat(a, S("ambiguous option: "), args[start]);
            m = concat(a, m, S(" could match "));
            for (iz k = 0; k < nt; k++) {
                m = concat(a, concat(a, m, k ? S(", ") : S("")), t[k].ostr);
            }
            ap_error(&ap, m);
        }
        Arg *x = t[0].arg;
        Str  ostr = t[0].ostr;
        b32  sepeq = t[0].sepeq, hasexp = t[0].hasexp;
        Str  exp = t[0].exp;
        ActT *acts = new(a, args[start].len + 2, ActT);
        iz   nacts = 0;
        iz   stop = start + 1;
        for (;;) {
            if (!x) {
                extras[nextras++] = args[start];
                stop = start + 1;
                nacts = -1;
                break;
            }
            if (hasexp) {
                iz count = x->nargs == NA_ZERO ? 0 : 1;   // match_argument(.., 'A')
                if (count == 0 && ostr.data[1] != '-' && exp.len) {
                    if (sepeq || exp.data[0] == '-') {
                        Str m = concat(a, S("ignored explicit argument "),
                                       pyrepr(a, exp));
                        ap_argerror(&ap, x, m);
                    }
                    acts[nacts].x = x;
                    acts[nacts].args = 0;
                    acts[nacts++].n = 0;
                    Str o2 = concat(a, clone(a, takehead(ostr, 1)),
                                    takehead(exp, 1));
                    Arg *x2 = 0;
                    for (iz k = 0; k < ntab; k++) {
                        if (equals(tab[k].s, o2)) {
                            x2 = tab[k].arg;
                            break;
                        }
                    }
                    if (x2) {
                        x = x2;
                        ostr = o2;
                        exp = cuthead(exp, 1);
                        if (!exp.len) {
                            hasexp = 0;
                            sepeq = 0;
                        } else if (exp.data[0] == '=') {
                            sepeq = 1;
                            exp = cuthead(exp, 1);
                        } else {
                            sepeq = 0;
                        }
                        continue;
                    }
                    extras[nextras++] = concat(a, clone(a, takehead(ostr, 1)),
                                               exp);
                    stop = start + 1;
                    break;
                } else if (count == 1) {
                    Str *v = new(a, 1, Str);
                    v[0] = exp;
                    acts[nacts].x = x;
                    acts[nacts].args = v;
                    acts[nacts++].n = 1;
                    stop = start + 1;
                    break;
                } else {
                    Str m = concat(a, S("ignored explicit argument "),
                                   pyrepr(a, exp));
                    ap_argerror(&ap, x, m);
                }
            } else {
                iz first = start + 1;
                iz count = 0;
                if (x->nargs == NA_ONE) {
                    if (PATAT(first) != 'A') {
                        ap_argerror(&ap, x, S("expected one argument"));
                    }
                    count = 1;
                }
                acts[nacts].x = x;
                acts[nacts].args = args + first;
                acts[nacts++].n = count;
                stop = first + count;
                break;
            }
        }
        if (nacts > 0) {
            for (iz k = 0; k < nacts; k++) {
                ap_take(&ap, &st, acts[k].x, acts[k].args, acts[k].n);
            }
        }
        start = stop;
    }

    // consume any positionals following the last optional
    {
        iz stop = start;
        if (posarg && !posdone) {
            iz n = 0;
            if (posarg->nargs == NA_OPT) {
                while (PATAT(start + n) == '-') n++;
                if (PATAT(start + n) == 'A') n++;
                while (PATAT(start + n) == '-') n++;
            } else if (posarg->nargs == NA_STAR) {
                while (PATAT(start + n) == '-' || PATAT(start + n) == 'A') {
                    n++;
                }
            } else {
                iz m = 0;
                while (PATAT(start + m) == '-') m++;
                if (PATAT(start + m) == 'A') {
                    n = m + 1;
                    while (PATAT(start + n) == '-') n++;
                }
            }
            b32 consumed = !(n == 0 && PATAT(start + n) == 'O');
            if (posarg->nargs == NA_ONE && n == 0) {
                consumed = 0;
            }
            if (consumed) {
                Str *vals = new(a, n + 1, Str);
                iz   nv = 0;
                b32  skipped = 0;
                for (iz i = start; i < start + n; i++) {
                    if (pat[i] == '-' && !skipped) {
                        skipped = 1;
                        continue;
                    }
                    vals[nv++] = args[i];
                }
                ap_take(&ap, &st, posarg, vals, nv);
                stop = start + n;
            }
        }
        for (iz i = stop; i < argc; i++) {
            extras[nextras++] = args[i];
        }
    }
    #undef PATAT

    if (nextras) {
        Str m = S("unrecognized arguments:");
        for (iz k = 0; k < nextras; k++) {
            m = concat(a, concat(a, m, S(" ")), extras[k]);
        }
        ap_error(&ap, m);
    }
    ParsedOpts r = {};
    r.vals = st.vals;
    r.pos  = st.pos;
    r.npos = st.npos;
    return r;
}


// Trash directory discovery
//
// The scanner yields an ordered event list: found trash dirs (with the
// volume used to join relative Path= values) and rejected ones with a
// reason, in discovery order.

enum : i32 { EV_FOUND = 0, EV_SKIP_STICKY, EV_SKIP_SYMLINK, EV_SKIP_TRUST };

typedef struct ScanEv ScanEv;
struct ScanEv {
    ScanEv *next;
    i32     kind;
    Str     path;
    Str     volume;   // EV_FOUND: the volume its relative Path= values join
};

typedef struct {
    ScanEv  *head;
    ScanEv **tail;
} EvList;

static void evpush(Arena *a, EvList *l, i32 kind, Str path, Str volume)
{
    ScanEv *n = new(a, 1, ScanEv);
    n->kind   = kind;
    n->path   = path;
    n->volume = volume;
    *l->tail  = n;
    l->tail   = &n->next;
}

typedef struct {
    Str *data;
    iz  len;
} Strs;

static b32 is_symlink(Os *os, Arena scratch, Str path)
{
    Stat st = {};
    return os_stat(os, scratch, path, 0, &st) && st.kind == KIND_LINK;
}

// The home trash directory (spec 4.1).  An empty XDG_DATA_HOME counts as
// unset, per the XDG basedir specification.
static b32 home_trash(Ctx *c, Arena *a, Str *out)
{
    Str x = os_getenv(c->os, S("XDG_DATA_HOME"));
    if (x.data && x.len) {
        *out = concat(a, x, S("/Trash"));
        return 1;
    }
    Str h = os_getenv(c->os, S("HOME"));
    if (h.data && h.len) {
        *out = concat(a, h, S("/.local/share/Trash"));
        return 1;
    }
    return 0;
}

static b32 mountfstype_ok(Str fs)
{
    static const Str ok[] = {
        STR("nfs"), STR("nfs4"), STR("p9"), STR("btrfs"),
        STR("fuse.glusterfs"), STR("fuse.mergerfs"), STR("fuse.gocryptfs"),
    };
    if (startswith(fs, S("fuse"))) {
        return 1;
    }
    for (iz k = 0; k < (iz)countof(ok); k++) {
        if (equals(ok[k], fs)) {
            return 1;
        }
    }
    return 0;
}

// Kernel octal escapes in /proc/self/mounts paths (\040 for a space).
static Str unescape_mount(Arena *a, Str s)
{
    u8 *d = new(a, s.len, u8);
    iz  n = 0;
    for (iz i = 0; i < s.len; i++) {
        u32 v = 0;
        b32 oct = s.data[i] == '\\' && i + 3 < s.len;
        for (iz k = 1; oct && k <= 3; k++) {
            u8 c = s.data[i + k];
            if (c < '0' || c > '7') {
                oct = 0;
            } else {
                v = v*8 + (u32)(c - '0');
            }
        }
        if (oct) {
            d[n++] = (u8)v;
            i += 3;
        } else {
            d[n++] = s.data[i];
        }
    }
    return span(d, d + n);
}

// The volume list: TRASH_VOLUMES when set and non-empty, otherwise the
// system mount table filtered to real filesystems (spec 4.4).
static Strs volumes_list(Ctx *c, Arena *a, Arena)
{
    Str env = os_getenv(c->os, S("TRASH_VOLUMES"));
    if (env.data && env.len) {
        Str *v = new(a, env.len/2 + 2, Str);
        iz  n  = 0;
        for (Cut k = {.tail=env, .ok=1}; k.ok;) {
            k = cut(k.tail, ':');
            if (k.head.len) {
                v[n++] = k.head;
            }
        }
        return (Strs){v, n};
    }
    Str content;
    if (!readall(c->os, a, S("/proc/self/mounts"), &content)) {
        return (Strs){};
    }
    iz  nlines = 1;
    for (iz i = 0; i < content.len; i++) {
        nlines += content.data[i] == '\n';
    }
    Str *v = new(a, nlines, Str);
    iz  n  = 0;

    // Mount points seen so far: an open-addressed table of indexes into v,
    // one more than the index so that zero means an empty slot.
    iz  tcap = 2;
    while (tcap < nlines*2) {
        tcap *= 2;
    }
    iz *seen = new(a, tcap, iz);

    for (Cut lc = {.tail=content, .ok=1}; lc.ok;) {
        lc       = cut(lc.tail, '\n');
        Str line = lc.head;
        Cut f    = {.tail=line, .ok=1};
        Str fields[4] = {};
        iz  nf   = 0;
        while (f.ok && nf < 4) {
            f = cut(f.tail, ' ');
            if (f.head.len) {
                fields[nf++] = f.head;
            }
        }
        if (nf < 3) {
            continue;
        }
        Str dev  = unescape_mount(a, fields[0]);
        Str mnt  = unescape_mount(a, fields[1]);
        Str fs   = fields[2];
        b32 keep = mountfstype_ok(fs)
                || startswith(dev, S("/dev/"))
                || (equals(fs, S("tmpfs")) && equals(mnt, S("/tmp")));
        if (!keep) {
            continue;
        }
        u64 h = 0xcbf29ce484222325u;   // FNV-1a
        for (iz k = 0; k < mnt.len; k++) {
            h = (h ^ mnt.data[k]) * 0x100000001b3u;
        }
        b32 dup = 0;
        iz  i   = (iz)(h & (u64)(tcap - 1));
        for (; seen[i]; i = (i + 1) & (tcap - 1)) {
            if (equals(v[seen[i] - 1], mnt)) {
                dup = 1;
                break;
            }
        }
        if (!dup) {
            seen[i] = n + 1;
            v[n++]  = mnt;
        }
    }
    return (Strs){v, n};
}

// Both volume trash methods for one volume (spec 4.2/4.3).  For reading, the
// sticky bit is checked before the symlink, and a missing $uid entry under
// .Trash is silently ignored.
static void scan_volume_dirs(Ctx *c, Arena *a, Arena scratch, Strs volumes,
                             i32 uid, EvList *ev)
{
    for (iz k = 0; k < volumes.len; k++) {
        Str vol    = volumes.data[k];
        Str parent = join(a, vol, S(".Trash"));
        Str td1    = join(a, parent, istr(a, uid));
        Stat st1   = {};
        if (os_stat(c->os, scratch, td1, 1, &st1)) {
            Stat sp = {};
            b32 ok  = os_stat(c->os, scratch, parent, 1, &sp)
                   && sp.kind == KIND_DIR && (sp.mode & 01000);
            if (!ok) {
                evpush(a, ev, EV_SKIP_STICKY, td1, (Str){});
            } else if (is_symlink(c->os, scratch, parent)) {
                evpush(a, ev, EV_SKIP_SYMLINK, td1, (Str){});
            } else {
                evpush(a, ev, EV_FOUND, td1, vol);
            }
        }
        Str td2  = join(a, vol, concat(a, S(".Trash-"), istr(a, uid)));
        Stat st2 = {};
        if (os_stat(c->os, scratch, td2, 1, &st2) && st2.kind == KIND_DIR) {
            evpush(a, ev, EV_FOUND, td2, vol);
        }
    }
}

typedef struct {
    b32 all_users;
    i32 uid;
    b32 homevol;   // the home trash's volume is its mount point, not "/"
} ScanOpts;

typedef struct {
    ScanEv *events;
} Scan;

// The trash dirs a scanning command looks at: the home trash first (its
// existence is not checked), then every volume's two methods (spec 4).
static Scan scan_trash_dirs(Ctx *c, Arena *a, Arena scratch, ScanOpts o)
{
    Scan   s  = {};
    EvList ev = {};
    ev.tail   = &ev.head;
    if (o.all_users) {
        for (User *u = os_users(c->os, a); u; u = u->next) {
            if (u->dir.len) {
                Str ht = concat(a, u->dir, S("/.local/share/Trash"));
                evpush(a, &ev, EV_FOUND, ht, S("/"));
            }
            scan_volume_dirs(c, a, scratch, volumes_list(c, a, scratch),
                             u->uid, &ev);
        }
    } else {
        Str ht;
        if (home_trash(c, a, &ht)) {
            Str hv = o.homevol
                   ? volume_of(c->os, a, scratch, abspath_(c, a, ht))
                   : S("/");
            evpush(a, &ev, EV_FOUND, ht, hv);
        }
        scan_volume_dirs(c, a, scratch, volumes_list(c, a, scratch),
                         o.uid, &ev);
    }
    s.events = ev.head;
    return s;
}

// Putting files in the trash (trash-put, trash)

// Python's path.rstrip('/') or path: a path of only slashes stays as given.
static Str stripslashes(Str s)
{
    Str t = s;
    while (t.len && t.data[t.len-1] == '/') {
        t = cuttail(t, 1);
    }
    return t.len ? t : s;
}

// The description vocabulary of trash-put's messages (spec 5.4).
static Str describe(Arena *, Os *, Arena, Str arg, Stat *st,
                    b32 exists)
{
    if (!exists) {
        return S("non existent");
    }
    switch (st->kind) {
    case KIND_LINK:
        return S("symbolic link");
    case KIND_DIR: {
        Str bn = basename(arg);
        if (equals(bn, S(".")) && arg.len > 1) {
            return S("'.' directory");
        }
        if (equals(bn, S("..")) && arg.len > 2) {
            return S("'..' directory");
        }
        return S("directory");
    }
    case KIND_FILE:
        return st->size ? S("regular file") : S("regular empty file");
    default:
        return S("entry");
    }
}

// Renders "[Errno N] <strerror>: '<path>'" as a string.
static Str errtext(Arena *a, Os *os, i32 err, Str path)
{
    Str s = concat(a, S("[Errno "), istr(a, err));
    s = concat(a, s, S("] "));
    s = concat(a, s, os_strerror(os, err));
    s = concat(a, s, S(": '"));
    s = concat(a, s, path);
    s = concat(a, s, S("'"));
    return s;
}

// rm -r without following symlinks.  1 when the path is gone.
static b32 rmtree(Ctx *c, Arena scratch, Str path)
{
    Os *os = c->os;
    Stat st = {};
    if (!os_stat(os, scratch, path, 0, &st)) {
        return os_errno(os) == ENOENT;   // gone is gone
    }
    if (st.kind == KIND_DIR) {
        Arena t       = scratch;
        b32 ok;
        DirEnt *ents  = os_listdir(os, &t, path, &ok);
        if (ok && ents) {
            for (DirEnt *e = ents; e; e = e->next) {
                Arena tc = t;   // fresh: past ents, so children cannot
                if (!rmtree(c, tc, join(&tc, path, e->name))) {   // clobber
                    return 0;
                }
            }
        }
        return os_rmdir(os, scratch, path);
    }
    return os_unlink(os, scratch, path);
}

// unlink(2) with a recursive fallback, like os.remove falling back to
// shutil.rmtree.  1 when the path is gone.
static b32 remove_path(Ctx *c, Arena scratch, Str path)
{
    if (os_unlink(c->os, scratch, path)) {
        return 1;
    }
    i32 err = os_errno(c->os);
    if (err == ENOENT) {
        return 1;
    }
    return rmtree(c, scratch, path);
}

// Copies one file's bytes and mode.  False, with *preason, on failure.
static b32 copy_file(Ctx *c, Arena *a, Arena scratch, Str src, Str dst,
                     u32 mode, Str *preason)
{
    Os *os = c->os;
    i32 in = os_open(os, scratch, src, 0, 0);
    if (in < 0) {
        *preason = errtext(a, os, os_errno(os), src);
        return 0;
    }
    i32 out = os_open(os, scratch, dst, 1, mode & 0777u);
    if (out < 0) {
        os_close(os, in);
        *preason = errtext(a, os, os_errno(os), dst);
        return 0;
    }
    u8 *buf = new(&scratch, 1 << 12, u8);
    for (;;) {
        iz r = os_read(os, in, buf, 1 << 12);
        if (r < 0) {
            os_close(os, in);
            os_close(os, out);
            *preason = errtext(a, os, os_errno(os), src);
            return 0;
        }
        if (!r) {
            break;
        }
        if (!os_write(os, out, buf, r)) {
            os_close(os, in);
            os_close(os, out);
            *preason = errtext(a, os, os_errno(os), dst);
            return 0;
        }
    }
    os_close(os, in);
    os_close(os, out);
    return 1;
}

// Copies a file, symlink or directory tree, leaving the source alone
// (copytree with symlinks=True).  A directory is created writable and given
// the source's mode once it is filled, so a read-only one can be copied.
static b32 copy_path(Ctx *c, Arena *a, Arena scratch, Str src, Str dst,
                     Str *preason)
{
    Os *os = c->os;
    Stat ss = {};
    if (!os_stat(os, scratch, src, 0, &ss)) {
        *preason = errtext(a, os, os_errno(os), src);
        return 0;
    }
    switch (ss.kind) {
    case KIND_LINK: {
        Str target;
        if (!os_readlink(os, a, src, &target)) {
            *preason = errtext(a, os, os_errno(os), src);
            return 0;
        }
        if (!os_symlink(os, scratch, target, dst)) {
            *preason = errtext(a, os, os_errno(os), dst);
            return 0;
        }
        return 1;
    }
    case KIND_DIR: {
        if (!os_mkdir(os, scratch, dst, 0777)) {
            *preason = errtext(a, os, os_errno(os), dst);
            return 0;
        }
        Arena t = scratch;
        b32 ok;
        DirEnt *ents = os_listdir(os, &t, src, &ok);
        if (!ok) {
            *preason = errtext(a, os, os_errno(os), src);
            return 0;
        }
        for (DirEnt *e = ents; e; e = e->next) {
            Arena tc = t;
            Str s2 = join(&tc, src, e->name);
            Str d2 = join(&tc, dst, e->name);
            if (!copy_path(c, a, tc, s2, d2, preason)) {
                return 0;
            }
        }
        os_chmod(os, scratch, dst, ss.mode);
        return 1;
    }
    case KIND_FILE: {
        Stat ds = {};   // copy2 overwrites a file in place
        if (os_stat(os, scratch, dst, 0, &ds) && ds.kind != KIND_DIR) {
            os_unlink(os, scratch, dst);
        }
        return copy_file(c, a, scratch, src, dst, ss.mode, preason);
    }
    case KIND_FIFO:
        *preason = concat(a, concat(a, S("`"), src), S("` is a named pipe"));
        return 0;
    default:
        *preason = errtext(a, os, EINVAL, src);
        return 0;
    }
}

// rename(2) when possible; when it fails for any reason, copy then remove
// the source, like shutil.move.  The error reported is that of the fallback,
// as there.  A failed copy leaves the source whole.
static b32 move_path(Ctx *c, Arena *a, Arena scratch, Str src, Str dst,
                     Str *preason)
{
    if (os_rename(c->os, scratch, src, dst)) {
        return 1;
    }
    if (!copy_path(c, a, scratch, src, dst, preason)) {
        return 0;
    }
    if (!remove_path(c, scratch, src)) {
        *preason = errtext(a, c->os, os_errno(c->os), src);
        return 0;
    }
    return 1;
}

// entries_if_dir_exists: a directory that cannot even be stat'ed (missing,
// or hidden behind an unreadable parent) counts as missing and *state is 1;
// one that exists but cannot be listed leaves its errno in *state as a
// negative number (upstream dies on it); otherwise *state is 0.
static DirEnt *listexisting(Ctx *c, Arena *a, Str path, i32 *state)
{
    *state = 0;
    Stat st = {};
    if (!os_stat(c->os, *a, path, 1, &st)) {
        *state = 1;
        return 0;
    }
    b32 ok;
    DirEnt *ents = os_listdir(c->os, a, path, &ok);
    if (!ok) {
        *state = -os_errno(c->os);
    }
    return ents;
}

// Trash dirs under HOME show as ~/... in -v messages (spec 5.8).
static Str shrink(Os *os, Arena *a, Str path, b32 disabled)
{
    if (disabled) {
        return path;
    }
    Str home = os_getenv(os, S("HOME"));
    if (home.data && home.len) {
        Str pfx = concat(a, normpath(a, home), S("/"));
        if (pfx.len > 1 && startswith(path, pfx)) {
            return concat(a, S("~/"), cuthead(path, pfx.len));
        }
    }
    return path;
}

// mkdir -p with Python's error semantics: an existing directory is fine, an
// existing file is FileExistsError; only the leaf gets mode, parents are
// created 0777 (umask applies), as os.makedirs does.
static i32 makedirs(Ctx *c, Arena scratch, Str path, u32 mode, i32 *perr,
                    Str *epath)
{
    if (os_mkdir(c->os, scratch, path, mode)) {
        return 0;
    }
    i32 err = os_errno(c->os);
    if (err == EEXIST) {
        Stat st = {};
        if (os_stat(c->os, scratch, path, 1, &st) && st.kind == KIND_DIR) {
            return 0;
        }
        *perr  = err;
        *epath = path;
        return -1;
    }
    if (err == ENOENT) {
        Str d = dirname(path);
        if (!equals(d, path) && !equals(d, S("."))) {
            if (makedirs(c, scratch, d, 0777, perr, epath)) {
                return -1;
            }
            if (os_mkdir(c->os, scratch, path, mode)) {
                return 0;
            }
            err = os_errno(c->os);
            if (err == EEXIST) {
                Stat st = {};
                if (os_stat(c->os, scratch, path, 1, &st)
                    && st.kind == KIND_DIR) {
                    return 0;
                }
            }
        }
    }
    *perr  = err;
    *epath = path;
    return -1;
}

// Invalid UTF-8 bytes the way Python's stderr shows file names (surrogate
// escapes with backslashreplace): byte 0xff is \udcff.
static Str pyesc(Arena *a, Str s)
{
    b32 bad = 0;
    for (iz i = 0; i < s.len && !bad;) {
        iz k = utf8_seq(s, i);
        bad = !k;
        i += k ? k : 1;
    }
    if (!bad) {
        return s;
    }
    Str r = {.data = new(a, 0, u8)};
    for (iz i = 0; i < s.len;) {
        iz k = utf8_seq(s, i);
        if (k) {
            r = concat(a, r, span(s.data + i, s.data + i + k));
            i += k;
        } else {
            u8 esc[6] = {'\\', 'u', 'd', 'c',
                         (u8)"0123456789abcdef"[s.data[i]>>4],
                         (u8)"0123456789abcdef"[s.data[i]&15]};
            r = concat(a, r, (Str){esc, 6});
            i++;
        }
    }
    return r;
}

// A line of trash-put's log on stderr: "<prog>: <msg>".
static void putlog(Ctx *c, Arena *a, Str msg)
{
    prefixes(c, c->err, pyesc(a, msg));
}

// Writes the .trashinfo for one candidate, picking a collision suffix
// (spec 3.2).  Returns 0 and sets *outinfo/*outfiles, or -1 with *preason.
// Like upstream, only errors that no other name could fix (permissions, a
// full or read-only disk) end the search; a name that is too long shrinks
// the stem from then on, and the others just try the next suffix.  Failed
// attempts are logged under -vv.
static i32 write_trashinfo(Ctx *c, Arena *a, Arena scratch, Str trashdir,
                           Str stem, Str origloc, DateTime now, b32 debug,
                           Str *outinfo, Str *outfiles, Str *preason)
{
    enum { MAXATTEMPTS = 1 << 17 };   // upstream retries without end

    b32 toolong = 0;
    for (i64 k = 0; k < MAXATTEMPTS; k++) {
        Str suffix = k == 0
                   ? S("")
                   : k <= 99
                   ? concat(a, S("_"), istr(a, k))
                   : concat(a, S("_"), istr(a, (i64)(os_rand(c->os) & 65535)));
        Str after  = concat(a, suffix, S(".trashinfo"));
        Str base   = stem;
        if (toolong) {   // basename[0:len(basename) - len(after)], in chars
            iz n = countchars(stem) - countchars(after);
            if (n < 0) {
                n += countchars(stem);
            }
            base = takechars(stem, n < 0 ? 0 : n);
        }
        Str name     = concat(a, base, suffix);
        Str files    = join(a, join(a, trashdir, S("files")), name);
        if (lexists(c->os, scratch, files)) {
            continue;
        }
        Str infopath = join(a, join(a, trashdir, S("info")),
                            concat(a, base, after));
        i32 fd = os_open(c->os, scratch, infopath, 1, 0600);
        i32 err = 0;
        if (fd >= 0) {
            Output *b = newoutput(a, c->os, fd);
            print(b, S("[Trash Info]\nPath="));
            print(b, percentencode(a, origloc));
            print(b, S("\nDeletionDate="));
            print(b, format_datetime(a, now, '-', 'T'));
            print(b, S("\n"));
            flush(b);
            if (b->err) {
                err = os_errno(c->os);
            }
            os_close(c->os, fd);
            if (!b->err) {
                *outinfo  = infopath;
                *outfiles = files;
                return 0;
            }
            os_unlink(c->os, scratch, infopath);
        } else {
            err = os_errno(c->os);
        }
        if (err == EACCES || err == EPERM || err == ENOSPC || err == EDQUOT
            || err == EROFS) {
            *preason = concat(a, S("failed to create trashinfo file: "),
                              errtext(a, c->os, err, infopath));
            return -1;
        }
        toolong |= err == ENAMETOOLONG;
        if (debug) {
            Str m = concat(a, S("attempt for creating "), infopath);
            putlog(c, a, concat(a, m, S(" failed.")));
        }
    }
    *preason = S("no available trash name");
    return -1;
}

// Original location for a trashinfo Path= (spec 3.2): the normpath'd
// argument with its parent replaced by the parent's realpath; volume
// candidates store it relative to their volume, unless that volume is "/".
static Str original_location(Arena *a, Str parent_real, Str stem, Str topdir,
                             b32 relative)
{
    Str parent = parent_real;
    if (relative) {
        Str pfx = concat(a, topdir, S("/"));
        if (equals(parent, topdir)) {
            parent = S("");
        } else if (startswith(parent, pfx)) {
            parent = cuthead(parent, pfx.len);
        }
    }
    return join(a, parent, stem);
}

enum : i32 { CHECK_NONE = 0, CHECK_TOPDIR };

typedef struct {
    Str td;        // trash dir path
    Str volume;    // the candidate's own volume, as -vv shows it
    Str topdir;    // volume prefix stripped from Path=, "/" for absolute
    i32 check;
    b32 relative;
    b32 homefallback;
} Cand;

typedef struct {
    iz  verbose;      // -v count
    b32 force;
    b32 interactive;  // -f and -i share one variable, last one wins
    Str force_volume;
} PutFlags;

typedef struct {
    Str trash_dir;               // {0} unless --trash-dir
    Str home;                    // {0} when neither XDG_DATA_HOME nor HOME
    b32 home_fallback;           // --home-fallback given
    b32 home_fallback_enabled;   // TRASH_ENABLE_HOME_FALLBACK=1
    b32 no_shrink;               // TRASH_PUT_DISABLE_SHRINK=1
} PutEnv;

// Trashes one argument (spec 5.4).  Sets *pfailed when the file could not
// be trashed; every diagnostic goes to stderr.
// rename(2), with a writability fix-up for directories: moving a
// directory to a different parent rewrites its '..' entry, which takes
// write access to the directory itself (spec 5.6) — granted for the move
// and restored on the backup copy afterwards.
static b32 trash_rename(Ctx *c, Arena scratch, Str from, Str to, Stat *st)
{
    if (os_rename(c->os, scratch, from, to)) {
        return 1;
    }
    u32 old = st->mode;
    if (os_errno(c->os) != EACCES || st->kind != KIND_DIR || (old & 0200)) {
        return 0;
    }
    if (!os_chmod(c->os, scratch, from, old | 0200)) {
        return 0;
    }
    if (!os_rename(c->os, scratch, from, to)) {
        os_chmod(c->os, scratch, from, old);   // best effort restore
        return 0;
    }
    os_chmod(c->os, scratch, to, old);
    return 1;
}

static void put_one_file(Ctx *c, Arena *a, Arena scratch, Str arg, PutFlags f,
                         i64 uid, PutEnv *pe, LineReader *lr, b32 *pfailed)
{
    Os *os = c->os;

    Str raw    = stripslashes(arg);
    Stat st    = {};
    b32 exists = os_stat(os, scratch, raw, 0, &st);
    Str desc   = describe(a, os, scratch, raw, &st, exists);

    // Dot entries are refused before anything else (step 2).
    Str bn = basename(raw);
    if (equals(bn, S(".")) || equals(bn, S(".."))) {
        Str m = concat(a, S("cannot trash "), desc);
        m = concat(a, m, S(" '"));
        m = concat(a, m, raw);
        m = concat(a, m, S("'"));
        putlog(c, a, m);
        *pfailed = 1;
        return;
    }

    // Missing files: a silent success under -f, a failure otherwise (step 3).
    if (!exists) {
        if (f.force) {
            return;
        }
        putlog(c, a, concat(a, concat(a, S("cannot trash non existent '"),
                                      raw), S("'")));
        *pfailed = 1;
        return;
    }

    // Interactive prompt, only for accessible paths (step 4); dangling
    // symlinks fail F_OK and are not asked about.  It comes before the
    // delete-permission check, as upstream's order has it.
    if (f.interactive && os_access(os, scratch, raw, ACCESS_F)) {
        flush(c->out);
        print(c->out, c->prog);
        print(c->out, S(": trash "));
        print(c->out, desc);
        print(c->out, S(" '"));
        print(c->out, raw);
        print(c->out, S("'? "));
        flush(c->out);
        Str line;
        if (!readline(os, lr, a, &line)) {
            prefixes(c, c->err, S("EOF while reading the answer"));
            finish(c, 1);
        }
        if (!(line.len && (line.data[0]=='y' || line.data[0]=='Y'))) {
            return;   // a "no" answer is a silent success
        }
    }

    // Delete-permission pre-check on the realpath'd parent of the argument
    // as given (step 5); the volume comes from the same parent.  The
    // original location instead resolves the lexically normalized path.
    Str np     = normpath(a, raw);
    Str vdir   = realpath_(c, a, scratch, dirname(raw));
    Str rdir   = realpath_(c, a, scratch, dirname(np));
    if (!os_access(os, scratch, vdir, ACCESS_W | ACCESS_X)) {
        Str m = concat(a, S("cannot trash "), desc);
        m = concat(a, m, S(" '"));
        m = concat(a, m, raw);
        m = concat(a, m, S("' because deleting it is not allowed"));
        putlog(c, a, m);
        *pfailed = 1;
        return;
    }

    Str realvol = volume_of(os, a, scratch, vdir);
    Str filevol = f.force_volume.data ? f.force_volume : realvol;

    // Candidates, in order (spec 5.5).  With --trash-dir there is exactly
    // one; otherwise home, then the file's volume's two methods, then the
    // home trash again when --home-fallback was given.
    Cand cands[4];
    iz   ncands = 0;
    if (pe->trash_dir.data) {
        Cand n       = {};
        n.td         = pe->trash_dir;
        n.volume     = volume_of(os, a, scratch,
                                 abspath_(c, a, n.td));
        n.topdir     = n.volume;
        n.relative   = 1;
        cands[ncands++] = n;
    } else {
        if (pe->home.data) {
            Cand n    = {};
            n.td      = pe->home;
            n.volume  = volume_of(os, a, scratch,
                                  abspath_(c, a, n.td));
            n.topdir  = S("/");
            cands[ncands++] = n;
        }
        Cand m1        = {};
        m1.td          = join(a, filevol,
                              concat(a, S(".Trash/"), istr(a, uid)));
        m1.volume      = filevol;
        m1.topdir      = filevol;
        m1.check       = CHECK_TOPDIR;
        m1.relative    = 1;
        cands[ncands++] = m1;
        Cand m2        = {};
        m2.td          = join(a, filevol,
                              concat(a, S(".Trash-"), istr(a, uid)));
        m2.volume      = filevol;
        m2.topdir      = filevol;
        m2.relative    = 1;
        cands[ncands++] = m2;
        if (pe->home_fallback && pe->home.data) {
            Cand n         = {};
            n.td           = pe->home;
            n.volume       = cands[0].volume;
            n.topdir       = S("/");
            n.homefallback = 1;
            cands[ncands++] = n;
        }
    }

    Str  stem    = basename(np);
    Str  block   = S("");   // collected " `- failed to trash" lines
    b32  trashed = 0;
    for (iz k = 0; k < ncands && !trashed; k++) {
        Cand *cd = &cands[k];
        if (f.verbose >= 2) {
            Str m =  S("trying trash dir: ");
            m = concat(a, m, normpath(a, cd->td));
            m = concat(a, m, S(" from volume: "));
            m = concat(a, m, cd->volume);
            putlog(c, a, m);
        }

        // Security checks (spec 4.2): info/files symlinks first for every
        // candidate, then the method-1 parent checks.
        Str reason = {};
        if (is_symlink(os, scratch, join(&scratch, cd->td, S("info")))
            || is_symlink(os, scratch, join(&scratch, cd->td, S("files")))) {
            Str m =  S("trash dir is insecure, its parent should "
                                "not be a symlink, trash-dir: ");
            m = concat(a, m, normpath(a, cd->td));
            m = concat(a, m, S(", parent: "));
            m = concat(a, m, dirname(cd->td));
            reason = m;
        } else if (cd->check == CHECK_TOPDIR) {
            Str p = dirname(cd->td);
            if (!lexists(os, scratch, p)) {
                reason =  S("trash dir cannot be created because "
                                     "its parent does not exists");
            } else {
                Stat ps = {};
                if (!os_stat(os, scratch, p, 1, &ps)
                    || ps.kind != KIND_DIR) {
                    reason =  S("trash dir cannot be created as "
                                         "its parent is a file instead of "
                                         "being a directory");
                } else if (is_symlink(os, scratch, p)) {
                    reason =  S("trash dir is insecure, its parent "
                                         "should not be a symlink");
                } else if (!(ps.mode & 01000)) {
                    reason =  S("trash dir is insecure, its parent "
                                         "should be sticky");
                }
            }
            if (reason.data) {
                reason = concat(a, reason, S(", trash-dir: "));
                reason = concat(a, reason, normpath(a, cd->td));
                reason = concat(a, reason, S(", parent: "));
                reason = concat(a, reason, p);
            }
        }

        // The volume gate (spec 5.5): the trash dir's own volume must be
        // the file's.
        if (!reason.data) {
            if (cd->homefallback && !pe->home_fallback_enabled) {
                reason = S("home fallback not enabled");
            } else if (!cd->homefallback) {
                Str tv = volume_of(os, a, scratch,
                                   realpath_(c, a, scratch,
                                             normpath(a, cd->td)));
                if (!equals(tv, filevol)) {
                    Str m =  S("trash dir and file to be trashed "
                                        "are not in the same volume, "
                                        "trash-dir volume: ");
                    m = concat(a, m, tv);
                    m = concat(a, m, S(", file volume: "));
                    m = concat(a, m, filevol);
                    reason = m;
                }
            }
        }

        // Directory creation.
        if (!reason.data) {
            i32 err;
            Str epath;
            Str td   = cd->td;
            b32 bad  = makedirs(c, scratch, td, 0700, &err, &epath)
                    || makedirs(c, scratch, join(a, td, S("info")), 0700,
                                &err, &epath)
                    || makedirs(c, scratch, join(a, td, S("files")), 0700,
                                &err, &epath);
            if (bad) {
                reason = concat(a, S("error during directory creation: "),
                                errtext(a, os, err, epath));
            }
        }

        // Info file, then the move; a failed move rolls both back (3.2).
        if (!reason.data) {
            Str origloc = original_location(a, rdir, stem, cd->topdir,
                                            cd->relative);
            DateTime now;
            os_now(os, &now);
            Str infopath, files;
            if (write_trashinfo(c, a, scratch, cd->td, stem, origloc, now,
                                f.verbose >= 2, &infopath, &files,
                                &reason)) {
                // reason is set
            } else {
                if (f.verbose >= 2) {
                    Str m =  S(".trashinfo created as ");
                    m = concat(a, m, infopath);
                    m = concat(a, m, S("."));
                    putlog(c, a, m);
                }
                Str why = {};
                if (trash_rename(c, scratch, np, files, &st)
                    || move_path(c, a, scratch, np, files, &why)) {
                    trashed = 1;
                    if (f.verbose >= 1) {
                        Str m =  S("'");
                        m = concat(a, m, raw);
                        m = concat(a, m, S("' trashed in "));
                        m = concat(a, m, shrink(os, a, normpath(a, cd->td),
                                                pe->no_shrink));
                        putlog(c, a, m);
                    }
                } else {
                    // Drop a partial copy: no unremovable file may stay.
                    if (lexists(os, scratch, files)) {
                        remove_path(c, scratch, files);
                    }
                    os_unlink(os, scratch, infopath);
                    Str m =  S("failed to move ");
                    m = concat(a, m, raw);
                    m = concat(a, m, S(" in "));
                    m = concat(a, m, join(a, cd->td, S("files")));
                    m = concat(a, m, S(": "));
                    m = concat(a, m, why);
                    reason = m;
                }
            }
        }

        if (!trashed) {
            Str m =  c->prog;
            m = concat(a, m, S(":  `- failed to trash "));
            m = concat(a, m, raw);
            m = concat(a, m, S(" in "));
            m = concat(a, m, normpath(a, cd->td));
            m = concat(a, m, S(", because "));
            m = concat(a, m, reason);
            m = concat(a, m, S("\n"));
            block = concat(a, block, m);
        }
    }

    if (!trashed) {
        Str m = concat(a, S("cannot trash "), desc);
        m = concat(a, m, S(" '"));
        m = concat(a, m, raw);
        m = concat(a, m, S("' (from volume '"));
        m = concat(a, m, filevol);
        m = concat(a, m, S("')"));
        putlog(c, a, m);
        print(c->err, pyesc(a, block));
        *pfailed = 1;
    }
}

enum {
    PUT_HELP, PUT_COMPLETION, PUT_DIRECTORY, PUT_FORCE, PUT_INTERACTIVE,
    PUT_RECURSIVE, PUT_TRASHDIR, PUT_VERBOSE, PUT_FORCE_VOLUME,
    PUT_HOME_FALLBACK, PUT_VERSION, PUT_FILES,
};

static i32 cmd_put(Ctx *c, iz argc, Str *argv)
{
    Arena *a = c->perm;

    Arg args[] = {
        [PUT_HELP] = {.opts = {S("-h"), S("--help")}, .nopts = 2,
                      .kind = AK_HELP, .nargs = NA_ZERO,
                      .help = S("show this help message and exit")},
        [PUT_COMPLETION] = {.opts = {S("--print-completion")}, .nopts = 1,
                      .choices = {S("bash"), S("zsh"), S("tcsh")},
                      .nchoices = 3, .kind = AK_COMPLETION, .nargs = NA_ONE,
                      .help = S("print shell completion script")},
        [PUT_DIRECTORY] = {.opts = {S("-d"), S("--directory")}, .nopts = 2,
                      .kind = AK_FLAG, .nargs = NA_ZERO,
                      .help = S("ignored (for GNU rm compatibility)")},
        [PUT_FORCE] = {.opts = {S("-f"), S("--force")}, .nopts = 2,
                      .kind = AK_FLAG, .nargs = NA_ZERO,
                      .help = S("silently ignore nonexistent files")},
        [PUT_INTERACTIVE] = {.opts = {S("-i"), S("--interactive")}, .nopts = 2,
                      .kind = AK_FLAG, .nargs = NA_ZERO,
                      .help = S("prompt before every removal")},
        [PUT_RECURSIVE] = {.opts = {S("-r"), S("-R"), S("--recursive")},
                      .nopts = 3, .kind = AK_FLAG, .nargs = NA_ZERO,
                      .help = S("ignored (for GNU rm compatibility)")},
        [PUT_TRASHDIR] = {.opts = {S("--trash-dir")}, .nopts = 1,
                      .metavar = S("TRASHDIR"), .kind = AK_STORE,
                      .nargs = NA_ONE,
                      .help = S("use TRASHDIR as trash folder")},
        [PUT_VERBOSE] = {.opts = {S("-v"), S("--verbose")}, .nopts = 2,
                      .kind = AK_COUNT, .nargs = NA_ZERO,
                      .help = S("explain what is being done")},
        [PUT_FORCE_VOLUME] = {.opts = {S("--force-volume")}, .nopts = 1,
                      .metavar = S("FORCED_VOLUME"), .kind = AK_STORE,
                      .nargs = NA_ONE, .hidden = 1},
        [PUT_HOME_FALLBACK] = {.opts = {S("--home-fallback")}, .nopts = 1,
                      .kind = AK_FLAG, .nargs = NA_ZERO, .hidden = 1},
        [PUT_VERSION] = {.opts = {S("--version")}, .nopts = 1,
                      .kind = AK_VERSION, .nargs = NA_ZERO,
                      .help = S("show program's version number and exit")},
        [PUT_FILES] = {.metavar = S("files"), .nargs = NA_STAR},
    };
    Parser pr = {
        .usage       = S("%(prog)s [OPTION]... FILE..."),
        .description = S("Put files in trash"),
        .epilog      = S("all trash-cli commands:\n"
                         "  trash-put             trash files and directories.\n"
                         "  trash-empty           empty the trashcan(s).\n"
                         "  trash-list            list trashed files.\n"
                         "  trash-restore         restore a trashed file.\n"
                         "  trash-rm              remove individual files from "
                         "the trashcan\n"
                         "\n"
                         "To remove a file whose name starts with a '-', for "
                         "example '-foo',\n"
                         "use one of these commands:\n"
                         "\n"
                         "    trash -- -foo\n"
                         "\n"
                         "    trash ./-foo\n"
                         "\n"
                         "Report bugs to "
                         "https://github.com/andreafrancia/trash-cli/issues"),
        .rawdesc     = 1,
        .args        = args,
        .nargs       = (iz)countof(args),
    };

    // Existing files that look like options are refused before parsing
    // (spec 5.3); everything after -- is exempt.
    for (iz i = 0; i < argc; i++) {
        Str t = argv[i];
        if (equals(t, S("--"))) {
            break;
        }
        if (t.len >= 2 && t.data[0] == '-' && lexists(c->os, c->scratch, t)) {
            Str m =  S("refusing to treat existing file ");
            m = concat(a, m, t);
            m = concat(a, m, S(" as an option (use './"));
            m = concat(a, m, t);
            m = concat(a, m, S("' or a '--' separator)"));
            ap_fail(c, &pr, m);
        }
    }

    ParsedOpts p = ap_parse(c, &pr, argc, argv);
    if (!p.npos) {
        ap_fail(c, &pr, S("Please specify the files to trash."));
    }

    PutFlags f = {};
    f.verbose = optcount(&p, PUT_VERBOSE);
    for (OptVal *v = p.vals; v; v = v->next) {
        if (v->id == PUT_FORCE)       { f.force = 1;       f.interactive = 0; }
        if (v->id == PUT_INTERACTIVE) { f.force = 0;       f.interactive = 1; }
    }
    f.force_volume = optlast(&p, PUT_FORCE_VOLUME);
    if (!f.force_volume.len) {
        f.force_volume = (Str){};   // empty means unset, as in Python
    }

    i64 uid = os_getuid(c->os);
    Str fake = os_getenv(c->os, S("TRASH_PUT_FAKE_UID_FOR_TESTING"));
    if (fake.data) {
        IntParsed ip = parseint(a, fake);
        if (!ip.ok || ip.toobig) {
            die(c, 1, S("invalid TRASH_PUT_FAKE_UID_FOR_TESTING"));
        }
        uid = ip.value;
    }

    PutEnv pe = {};
    pe.trash_dir = optlast(&p, PUT_TRASHDIR);
    if (!pe.trash_dir.len) {
        pe.trash_dir = (Str){};
    }
    home_trash(c, a, &pe.home);
    pe.home_fallback = optgiven(&p, PUT_HOME_FALLBACK);
    Str fbenv = os_getenv(c->os, S("TRASH_ENABLE_HOME_FALLBACK"));
    pe.home_fallback_enabled = fbenv.data && equals(fbenv, S("1"));
    Str shrenv = os_getenv(c->os, S("TRASH_PUT_DISABLE_SHRINK"));
    pe.no_shrink = shrenv.data && equals(shrenv, S("1"));

    LineReader lr = {};
    lr.os = c->os;
    lr.fd = 0;

    b32 failed = 0;
    for (iz i = 0; i < p.npos; i++) {
        put_one_file(c, a, c->scratch, p.pos[i], f, uid, &pe, &lr, &failed);
    }
    finish(c, failed ? 74 : 0);
}

// Listing trashed files (trash-list)

enum {
    LIST_HELP, LIST_COMPLETION, LIST_VERSION, LIST_DEBUGVOLUMES, LIST_VOLUMES,
    LIST_TRASHDIRS, LIST_TRASHDIR, LIST_SIZE, LIST_FILES, LIST_ALLUSERS,
    LIST_PYTHON,
};

enum : i32 {
    LA_LIST = 0, LA_VERSION, LA_VOLUMES, LA_TRASHDIRS, LA_DEBUGVOLUMES,
    LA_PYTHON,
};

// Passes valid UTF-8 through and renders other bytes as \xNN escapes, the
// way piped trash-list output shows them (spec 6.2).
static void printpathraw(Output *b, Str s)
{
    for (iz i = 0; i < s.len;) {
        iz n = utf8_seq(s, i);
        if (n) {
            print(b, span(s.data + i, s.data + i + n));
            i += n;
        } else {
            print(b, S("\\x"));
            printhex2(b, s.data[i]);
            i++;
        }
    }
}

// Scans and prints trashinfo entries; shared by the main listing and the
// hidden --size/--files variants.  -1 after a fatal error (an unreadable
// info directory, or a missing backup copy under --size).
static i32 list_entries(Ctx *c, Arena *, Arena scratch, Scan scan,
                        b32 size, b32 files, b32 quoting, b32 allusers)
{
    Os *os = c->os;
    for (ScanEv *ev = scan.events; ev; ev = ev->next) {
        if (ev->kind != EV_FOUND) {
            continue;
        }
        Arena td     = scratch;
        Str infodir  = join(&td, ev->path, S("info"));
        i32 state;
        DirEnt *ents = listexisting(c, &td, infodir, &state);
        if (state == 1) {
            continue;   // a trash dir that is not there contributes nothing
        }
        if (state < 0) {
            if (allusers) {
                continue;   // other users' trash dirs may be unreadable
            }
            say(c, c->err, errtext(&td, os, -state, infodir));
            return -1;
        }
        for (DirEnt *ent = ents; ent; ent = ent->next) {
            if (!endswith(ent->name, S(".trashinfo"))) {
                continue;
            }
            Arena te = td;
            Str infopath = join(&te, join(&te, ev->path, S("info")),
                                ent->name);
            i32 status;
            TrashInfo ti = trashinfo_read(c, &te, te, infopath, &status);
            if (status == TI_READERR) {
                say(c, c->err, errtext(&te, os, os_errno(os), infopath));
                continue;
            }
            if (status == TI_BADUTF8) {
                Str m =  S("Parse Error: ");
                m = concat(&te, m, infopath);
                m = concat(&te, m, S(": Unable to parse trashinfo (invalid "
                                    "UTF-8)."));
                say(c, c->err, m);
                continue;
            }
            if (status == TI_NOPATH) {
                Str m =  S("Parse Error: ");
                m = concat(&te, m, infopath);
                m = concat(&te, m, S(": Unable to parse Path."));
                say(c, c->err, m);
                continue;
            }
            Str loc = join(&te, ev->volume, ti.path);
            Str backup = backuppath(&te, ev->path, ent->name);
            if (size) {
                // getsize(): a dangling symlink counts 0, a missing backup
                // is fatal.
                Stat bs = {};
                if (!os_stat(os, te, backup, 1, &bs)) {
                    i32 err = os_errno(os);
                    Stat ls = {};
                    if (err == ENOENT && os_stat(os, te, backup, 0, &ls)
                        && ls.kind == KIND_LINK) {
                        bs.size = 0;
                    } else {
                        say(c, c->err, errtext(&te, os, err, backup));
                        return -1;
                    }
                }
                printi64(c->out, bs.size);
            } else if (ti.has_date) {
                print(c->out, fmt_date(&te, ti.date));
            } else {
                print(c->out, S("\?\?\?\?-\?\?-\?\? ??:??:??"));
            }
            print(c->out, S(" "));
            if (quoting) {
                printq(c->out, loc);
            } else {
                printpathraw(c->out, loc);
            }
            if (files) {
                print(c->out, S(" -> "));
                if (quoting) {
                    printq(c->out, backup);
                } else {
                    printpathraw(c->out, backup);
                }
            }
            print(c->out, S("\n"));
        }
    }
    return 0;
}

static i32 cmd_list(Ctx *c, iz argc, Str *argv)
{
    Arena *a = c->perm;
    Arg args[] = {
        [LIST_HELP] = {.opts = {S("-h"), S("--help")}, .nopts = 2,
                       .kind = AK_HELP, .nargs = NA_ZERO,
                       .help = S("show this help message and exit")},
        [LIST_COMPLETION] = {.opts = {S("--print-completion")}, .nopts = 1,
                       .choices = {S("bash"), S("zsh"), S("tcsh")},
                       .nchoices = 3, .kind = AK_COMPLETION, .nargs = NA_ONE,
                       .help = S("print shell completion script")},
        [LIST_VERSION] = {.opts = {S("--version")}, .nopts = 1,
                       .kind = AK_FLAG, .nargs = NA_ZERO,
                       .help = S("show program's version number and exit")},
        [LIST_DEBUGVOLUMES] = {.opts = {S("--debug-volumes")}, .nopts = 1,
                       .kind = AK_FLAG, .nargs = NA_ZERO, .hidden = 1},
        [LIST_VOLUMES] = {.opts = {S("--volumes")}, .nopts = 1,
                       .kind = AK_FLAG, .nargs = NA_ZERO,
                       .help = S("list volumes")},
        [LIST_TRASHDIRS] = {.opts = {S("--trash-dirs")}, .nopts = 1,
                       .kind = AK_FLAG, .nargs = NA_ZERO,
                       .help = S("list trash dirs")},
        [LIST_TRASHDIR] = {.opts = {S("--trash-dir")}, .nopts = 1,
                       .metavar = S("TRASH_DIRS"), .kind = AK_APPEND,
                       .nargs = NA_ONE,
                       .help = S("specify the trash directory to use")},
        [LIST_SIZE] = {.opts = {S("--size")}, .nopts = 1, .kind = AK_FLAG,
                       .nargs = NA_ZERO, .hidden = 1},
        [LIST_FILES] = {.opts = {S("--files")}, .nopts = 1, .kind = AK_FLAG,
                       .nargs = NA_ZERO, .hidden = 1},
        [LIST_ALLUSERS] = {.opts = {S("--all-users")}, .nopts = 1,
                       .kind = AK_FLAG, .nargs = NA_ZERO,
                       .help = S("list trashcans of all the users")},
        [LIST_PYTHON] = {.opts = {S("--python")}, .nopts = 1,
                       .kind = AK_FLAG, .nargs = NA_ZERO, .hidden = 1},
    };
    Parser pr = {
        .description = S("List trashed files"),
        .epilog      = S("Report bugs to "
                         "https://github.com/andreafrancia/trash-cli/issues"),
        .args        = args,
        .nargs       = (iz)countof(args),
    };

    ParsedOpts p = ap_parse(c, &pr, argc, argv);

    // The action flags share one variable: the last one wins (spec 6.1);
    // --size and --files are independent switches of the main listing.
    i32 action = LA_LIST;
    for (OptVal *v = p.vals; v; v = v->next) {
        switch (v->id) {
        case LIST_VERSION:      action = LA_VERSION;      break;
        case LIST_VOLUMES:      action = LA_VOLUMES;      break;
        case LIST_TRASHDIRS:    action = LA_TRASHDIRS;    break;
        case LIST_DEBUGVOLUMES: action = LA_DEBUGVOLUMES; break;
        case LIST_PYTHON:       action = LA_PYTHON;       break;
        }
    }

    if (action == LA_VERSION) {
        say(c, c->out, concat(a, concat(a, clone(a, c->prog), S(" ")),
                              S("0.26.9.29")));
        finish(c, 0);
    }
    if (action == LA_PYTHON) {
        say(c, c->out, os_selfexe(c->os, a));
        finish(c, 0);
    }
    if (action == LA_DEBUGVOLUMES) {
        Str env = os_getenv(c->os, S("TRASH_VOLUMES"));
        print(c->out, S("TRASH_VOLUMES: "));
        say(c, c->out, env.data ? env : S("(unset)"));
        Str content;
        if (readall(c->os, a, S("/proc/self/mounts"), &content)) {
            say(c, c->out, S("mounts:"));
            print(c->out, content);
            print(c->out, S("\n"));
        }
        Strs vols = volumes_list(c, a, c->scratch);
        say(c, c->out, S("selected volumes:"));
        for (iz k = 0; k < vols.len; k++) {
            say(c, c->out, vols.data[k]);
        }
        finish(c, 0);
    }
    if (action == LA_VOLUMES) {
        Strs vols = volumes_list(c, a, c->scratch);
        for (iz k = 0; k < vols.len; k++) {
            say(c, c->out, vols.data[k]);
        }
        finish(c, 0);
    }

    // --trash-dir values replace discovery entirely (spec 4.5), except
    // under --all-users, which ignores them (spec 4.6).
    iz ntd = optcount(&p, LIST_TRASHDIR);
    if (ntd && !optgiven(&p, LIST_ALLUSERS)) {
        EvList ev = {};
        ev.tail   = &ev.head;
        for (iz k = 0; k < ntd; k++) {
            Str dir = optval(&p, LIST_TRASHDIR, k);
            evpush(a, &ev, EV_FOUND, dir,
                   volume_of(c->os, a, c->scratch, abspath_(c, a, dir)));
        }
        Scan one = {ev.head};
        if (action == LA_TRASHDIRS) {
            for (ScanEv *evv = one.events; evv; evv = evv->next) {
                say(c, c->out, evv->path);
            }
            finish(c, 0);
        }
        b32 quoting = os_isatty(c->os, 1)
                   && !os_getenv(c->os, S("TRASH_RAW_OUTPUT")).data;
        if (list_entries(c, a, c->scratch, one, optgiven(&p, LIST_SIZE),
                         optgiven(&p, LIST_FILES), quoting, 0)) {
            finish(c, 1);
        }
        finish(c, 0);
    }

    Scan s = scan_trash_dirs(c, a, c->scratch,
                             (ScanOpts){.all_users = optgiven(&p, LIST_ALLUSERS),
                                        .uid = os_getuid(c->os)});
    if (action == LA_TRASHDIRS) {
        // Home first (always), then the volume methods with their reasons.
        for (ScanEv *ev = s.events; ev; ev = ev->next) {
            if (ev->kind == EV_SKIP_STICKY) {
                say(c, c->out, concat(a, S("parent_not_sticky: "), ev->path));
            } else if (ev->kind == EV_SKIP_SYMLINK) {
                say(c, c->out, concat(a, S("parent_is_symlink: "), ev->path));
            } else {
                say(c, c->out, ev->path);
            }
        }
        finish(c, 0);
    }
    for (ScanEv *ev = s.events; ev; ev = ev->next) {
        if (ev->kind == EV_SKIP_STICKY) {
            say(c, c->err,
                concat(a, S("TrashDir skipped because parent not sticky: "),
                       ev->path));
        } else if (ev->kind == EV_SKIP_SYMLINK) {
            say(c, c->err,
                concat(a, S("TrashDir skipped because parent is symlink: "),
                       ev->path));
        }
    }
    b32 quoting = os_isatty(c->os, 1)
               && !os_getenv(c->os, S("TRASH_RAW_OUTPUT")).data;
    if (list_entries(c, a, c->scratch, s, optgiven(&p, LIST_SIZE),
                     optgiven(&p, LIST_FILES), quoting,
                     optgiven(&p, LIST_ALLUSERS))) {
        finish(c, 1);
    }
    finish(c, 0);
}


// Restoring trashed files (trash-restore)

enum { RES_HELP, RES_COMPLETION, RES_PATH, RES_SORT, RES_TRASHDIR,
       RES_VERSION, RES_OVERWRITE };

typedef struct {
    Str      loc;       // original location, decoded and joined
    Str      infopath;
    Str      backup;
    Str      key;       // --sort path: location followed by the date text
    b32      has_date;
    DateTime date;
} ResCand;

typedef struct ResNode ResNode;
struct ResNode {
    ResNode *next;
    ResCand  c;
};

typedef struct {
    ResNode  *head;
    ResNode **tail;
    iz        n;
} ResList;

static void respush(ResList *l, Arena *a, ResCand c)
{
    ResNode *n = new(a, 1, ResNode);
    n->c     = c;
    *l->tail = n;
    l->tail  = &n->next;
    l->n++;
}

// A trash dir of the shape $volume/.Trash/$uid or $volume/.Trash-$uid:
// its relative Path= values must stay inside the volume (spec 3.3).
static b32 is_volume_trash(Arena *a, Str td, Str volume)
{
    Str n      = normpath(a, td);
    Str v      = normpath(a, volume);
    Str parent = dirname(n);
    Str name   = basename(n);
    return (equals(parent, v) && startswith(name, S(".Trash-")))
        || equals(parent, join(a, v, S(".Trash")));
}

// A relative Path= that resolves inside the volume; 0 otherwise.
static b32 path_in_volume(Arena *a, Str vol, Str rel, Str *out)
{
    if (rel.len && rel.data[0] == '/') {
        return 0;
    }
    Str nv  = normpath(a, vol);
    Str r   = normpath(a, join(a, nv, rel));
    Str pfx = join(a, nv, S(""));   // with the trailing slash, even for "/"
    if (!equals(r, nv) && !startswith(r, pfx)) {
        return 0;
    }
    *out = r;
    return 1;
}

// Restore's extra distrust rules (spec 4.7): a trash dir whose info/ or
// files/ subdirectory is a symlink or world-writable is disqualified.
static b32 restore_trust_ok(Ctx *c, Arena scratch, Str td, Str *why)
{
    static const Str subs[2] = {STR("info"), STR("files")};
    for (iz k = 0; k < 2; k++) {
        Str p   = join(&scratch, td, subs[k]);
        Stat st = {};
        if (!os_stat(c->os, scratch, p, 0, &st)) {
            continue;
        }
        Str m =  S("TrashDir skipped because its ");
        m = concat(&scratch, m, subs[k]);
        if (st.kind == KIND_LINK) {
            m = concat(&scratch, m, S(" dir is a symbolic link: "));
            m = concat(&scratch, m, td);
            *why = m;
            return 0;
        }
        if (st.mode & 0002) {
            m = concat(&scratch, m, S(" dir is world writable: "));
            m = concat(&scratch, m, td);
            *why = m;
            return 0;
        }
    }
    return 1;
}

// Gathers the restore candidates under `search` (spec 7.3/7.4).  Failures
// are warnings; the exit status is decided later.
static void restore_collect(Ctx *c, Arena *a, Arena scratch, ScanEv *dirs,
                            Str search, ResList *out)
{
    Os *os = c->os;
    for (ScanEv *ev = dirs; ev; ev = ev->next) {
        if (ev->kind != EV_FOUND) {
            continue;
        }
        Arena td     = scratch;
        Str tdn      = normpath(&td, ev->path);
        Str infodir  = join(&td, tdn, S("info"));
        b32 ok;
        DirEnt *ents = os_listdir(os, &td, infodir, &ok);
        if (!ok) {
            continue;   // like upstream: a trash dir without a readable info/
        }
        b32 voltrash = !equals(ev->volume, S("/"))
                    && is_volume_trash(a, ev->path, ev->volume);
        for (DirEnt *ent = ents; ent; ent = ent->next) {
            Arena te = td;
            if (!endswith(ent->name, S(".trashinfo"))) {
                say(c, c->err, S("Non .trashinfo file in info dir"));
                continue;
            }
            Str infopath = join(&te, infodir, ent->name);
            i32 status;
            TrashInfo ti = trashinfo_read(c, &te, te, infopath, &status);
            if (status == TI_READERR) {
                Str err = errtext(&te, os, os_errno(os), infopath);
                Str m = concat(&te, S("IOErrorReadingTrashInfo(path="),
                               pyrepr(&te, infopath));
                m = concat(&te, m, S(", error="));
                m = concat(&te, m, pyrepr(&te, err));
                say(c, c->err, concat(&te, m, S(")")));
                continue;
            }
            Str why = {};
            Str loc = {};
            if (status == TI_BADUTF8) {
                why = ti.why;
            } else if (status == TI_NOPATH) {
                why = S("Unable to parse Path");
            } else if (voltrash) {
                if (!path_in_volume(&te, ev->volume, ti.path, &loc)) {
                    b32 abs = ti.path.len && ti.path.data[0] == '/';
                    why = abs ? S("Path= must be relative for volume trashes")
                              : S("Path= escapes the volume root");
                }
            } else {
                loc = normpath(&te, join(&te, ev->volume, ti.path));
            }
            if (why.data) {
                Str m = concat(&te, S("Non parsable trashinfo file: "),
                               infopath);
                m = concat(&te, m, S(", because "));
                say(c, c->err, concat(&te, m, why));
                continue;
            }
            b32 hit = equals(loc, search)
                   || equals(search, S("/"))
                   || startswith(loc, concat(&te, search, S("/")));
            if (!hit) {
                continue;
            }
            ResCand rc = {};
            rc.loc      = clone(a, loc);
            rc.infopath = clone(a, infopath);
            rc.backup   = clone(a, backuppath(&te, tdn, ent->name));
            rc.has_date = ti.has_date;
            rc.date     = ti.date;
            respush(out, a, rc);
        }
    }
}

// Orders by code point, the way Python compares str: a byte that is not
// valid UTF-8 stands for the lone surrogate U+DC00 + byte.
static i32 cmpchars(Str x, Str y)
{
    iz i = 0, j = 0;
    while (i < x.len && j < y.len) {
        iz nx = utf8_seq(x, i), ny = utf8_seq(y, j);
        u32 cx = nx ? utf8_cp(x, i, nx) : 0xDC00u + x.data[i];
        u32 cy = ny ? utf8_cp(y, j, ny) : 0xDC00u + y.data[j];
        if (cx != cy) {
            return cx < cy ? -1 : 1;
        }
        i += nx ? nx : 1;
        j += ny ? ny : 1;
    }
    return (i < x.len) - (j < y.len);
}

// True when x sorts strictly before y.  By path, that is location plus
// date text (upstream's key); by date, undated entries go last (the
// corrected behavior: no crash on mixed dates).
static b32 cand_before(ResCand *x, ResCand *y, Str sort)
{
    if (equals(sort, S("path"))) {
        return cmpchars(x->key, y->key) < 0;
    }
    if (x->has_date != y->has_date) {
        return x->has_date;
    }
    if (x->has_date) {
        return datetime_key(x->date) < datetime_key(y->date);
    }
    return 0;
}

// Stable merge sort, bottom-up, through tmp.
static void sortcands(ResCand *arr, ResCand *tmp, iz n, Str sort)
{
    for (iz w = 1; w < n; w *= 2) {
        for (iz lo = 0; lo < n; lo += 2*w) {
            iz mid = lo + w   < n ? lo + w   : n;
            iz hi  = lo + 2*w < n ? lo + 2*w : n;
            iz i = lo, j = mid, k = lo;
            while (i < mid && j < hi) {
                tmp[k++] = cand_before(&arr[j], &arr[i], sort) ? arr[j++]
                                                                : arr[i++];
            }
            while (i < mid) {
                tmp[k++] = arr[i++];
            }
            while (j < hi) {
                tmp[k++] = arr[j++];
            }
        }
        for (iz k = 0; k < n; k++) {
            arr[k] = tmp[k];
        }
    }
}

// What to restore, from the prompt's answer (upstream's parse_indexes):
// every item is parsed first, then every index is range-checked, so a bad
// item anywhere beats an out-of-range one before it.  Dies with the
// message.  Fills order with the selected indexes in the order asked,
// repeats dropped.
// A message on stderr without the program name, then exit 1: upstream's Die.
[[noreturn]] static void bail(Ctx *c, Str msg)
{
    say(c, c->err, msg);
    finish(c, 1);
}

static iz parse_selection(Ctx *c, Arena *a, Str line, iz n, iz *order)
{
    iz nitems = 1;
    for (iz i = 0; i < line.len; i++) {
        nitems += line.data[i] == ',';
    }
    IntParsed *lo = new(a, nitems, IntParsed);
    IntParsed *hi = new(a, nitems, IntParsed);
    b32       *rg = new(a, nitems, b32);
    iz         k  = 0;
    for (Cut it = {.tail=line, .ok=1}; it.ok; k++) {
        it = cut(it.tail, ',');
        Str item = it.head;
        Cut dash = cut(item, '-');
        Str first = dash.ok ? dash.head : item;
        if (dash.ok) {
            if (!first.len || !dash.tail.len) {
                bail(c, concat(a, S("Invalid entry: open interval: "), item));
            }
            rg[k] = 1;
        }
        lo[k] = parseint(a, first);
        if (!lo[k].ok) {
            bail(c, concat(a, S("Invalid entry: not an index: "), first));
        }
        if (dash.ok) {
            hi[k] = parseint(a, dash.tail);
            if (!hi[k].ok) {
                bail(c, concat(a, S("Invalid entry: not an index: "),
                                 dash.tail));
            }
        }
    }
    u8 *seen = new(a, n, u8);
    iz  cnt  = 0;
    for (iz i = 0; i < nitems; i++) {
        i64 first = lo[i].toobig ? maxof(i64) : lo[i].value;
        i64 last  = rg[i] ? (hi[i].toobig ? maxof(i64) : hi[i].value) : first;
        if (first > last) {
            continue;   // an empty range selects nothing
        }
        if (first >= n || last >= n) {   // the first index past the end
            Str m = S("Invalid entry: out of range 0..");
            m = concat(a, m, istr(a, n - 1));
            m = concat(a, m, S(": "));
            bail(c, concat(a, m, first >= n ? lo[i].digits : istr(a, n)));
        }
        for (i64 v = first; v <= last; v++) {
            if (!seen[v]) {
                seen[v]       = 1;
                order[cnt++]  = v;
            }
        }
    }
    return cnt;
}

static i32 cmd_restore(Ctx *c, iz argc, Str *argv)
{
    Arena *a = c->perm;
    Arg args[] = {
        [RES_HELP] = {.opts = {S("-h"), S("--help")}, .nopts = 2,
                      .kind = AK_HELP, .nargs = NA_ZERO,
                      .help = S("show this help message and exit")},
        [RES_COMPLETION] = {.opts = {S("--print-completion")}, .nopts = 1,
                      .choices = {S("bash"), S("zsh"), S("tcsh")},
                      .nchoices = 3, .kind = AK_COMPLETION, .nargs = NA_ONE,
                      .help = S("print shell completion script"),
                      .defshow = S("None")},
        [RES_PATH] = {.metavar = S("path"), .nargs = NA_OPT,
                      .help = S("Restore files from given path instead of "
                                "current directory"),
                      .defshow = S("")},
        [RES_SORT] = {.opts = {S("--sort")}, .nopts = 1,
                      .choices = {S("date"), S("path"), S("none")},
                      .nchoices = 3, .kind = AK_STORE, .nargs = NA_ONE,
                      .help = S("Sort list of restore candidates by given "
                                "field"),
                      .defshow = S("date")},
        [RES_TRASHDIR] = {.opts = {S("--trash-dir")}, .nopts = 1,
                      .metavar = S("TRASH_DIR"), .kind = AK_STORE,
                      .nargs = NA_ONE, .hidden = 1},
        [RES_VERSION] = {.opts = {S("--version")}, .nopts = 1,
                      .kind = AK_FLAG, .nargs = NA_ZERO},
        [RES_OVERWRITE] = {.opts = {S("--overwrite")}, .nopts = 1,
                      .kind = AK_FLAG, .nargs = NA_ZERO,
                      .help = S("Overwrite existing files with files coming "
                                "out of the trash"),
                      .defshow = S("False")},
    };
    Parser pr = {
        .description = S("Restores from trash chosen file"),
        .defaults    = 1,
        .args        = args,
        .nargs       = (iz)countof(args),
    };

    ParsedOpts p = ap_parse(c, &pr, argc, argv);
    if (optgiven(&p, RES_VERSION)) {
        say(c, c->out, concat(a, concat(a, clone(a, c->prog), S(" ")),
                              S("0.26.9.29")));
        finish(c, 0);
    }

    Str sort = optlast(&p, RES_SORT);
    if (!sort.data) {
        sort = S("date");
    }
    b32  overwrite = optgiven(&p, RES_OVERWRITE);
    Str  trash_dir = optlast(&p, RES_TRASHDIR);
    if (!trash_dir.len) {
        trash_dir = (Str){};   // empty means unset, as in Python
    }
    Str  patharg   = p.npos ? p.pos[0] : (Str){};

    // The search path (spec 7.3): the argument resolved against the
    // realpath of the current directory; without an argument, that
    // directory itself.
    Str cwd    = realpath_(c, a, c->scratch, S("."));
    Str search = patharg.data ? normpath(a, join(a, cwd, patharg)) : cwd;

    Scan s = {};
    if (trash_dir.data) {
        EvList ev = {};
        ev.tail   = &ev.head;
        evpush(a, &ev, EV_FOUND, trash_dir,
               volume_of(c->os, a, c->scratch, abspath_(c, a, trash_dir)));
        s.events = ev.head;
    } else {
        s = scan_trash_dirs(c, a, c->scratch,
                            (ScanOpts){.uid = os_getuid(c->os), .homevol = 1});
        for (ScanEv *ev = s.events; ev; ev = ev->next) {
            if (ev->kind == EV_SKIP_STICKY) {
                say(c, c->err,
                    concat(a, S("TrashDir skipped because parent not "
                                "sticky: "), ev->path));
            } else if (ev->kind == EV_SKIP_SYMLINK) {
                say(c, c->err,
                    concat(a, S("TrashDir skipped because parent is "
                                "symlink: "), ev->path));
            } else if (ev->kind == EV_FOUND) {
                Str why;
                if (!restore_trust_ok(c, c->scratch, ev->path, &why)) {
                    say(c, c->err, why);
                    ev->kind = EV_SKIP_TRUST;
                }
            }
        }
    }

    ResList list = {};
    list.tail   = &list.head;
    restore_collect(c, a, c->scratch, s.events, search, &list);
    if (!list.n) {
        Str m = patharg.data
              ? concat(a, S("No files trashed from '"),
                       concat(a, search, S("'")))
              : concat(a, S("No files trashed from current dir ('"),
                       concat(a, cwd, S("')")));
        say(c, c->out, m);
        finish(c, 0);
    }

    ResCand *arr = new(a, list.n, ResCand);
    {
        iz k = 0;
        for (ResNode *n = list.head; n; n = n->next) {
            arr[k++] = n->c;
        }
    }
    for (iz k = 0; k < list.n; k++) {
        Str ds = arr[k].has_date ? fmt_date(a, arr[k].date) : S("None");
        arr[k].key = concat(a, clone(a, arr[k].loc), ds);
    }
    if (!equals(sort, S("none"))) {   // --sort none keeps the scan order
        sortcands(arr, new(a, list.n, ResCand), list.n, sort);
    }

    for (iz k = 0; k < list.n; k++) {
        printpad(c->out, k, 4);
        print(c->out, S(" "));
        if (arr[k].has_date) {
            print(c->out, fmt_date(a, arr[k].date));
        } else {
            print(c->out, S("None"));
        }
        print(c->out, S(" "));
        printpathraw(c->out, arr[k].loc);
        print(c->out, S("\n"));
    }
    print(c->out, S("What file to restore [0.."));
    printi64(c->out, list.n - 1);
    print(c->out, S("]: "));
    flush(c->out);

    LineReader lr = {};
    lr.os = c->os;
    lr.fd = 0;
    Str line;
    if (!readline(c->os, &lr, a, &line)) {
        print(c->err, S("\n"));   // exactly a blank line (spec 7.6)
        finish(c, 1);
    }
    if (!line.len) {   // empty reply: nothing is selected (spec 7.6)
        say(c, c->out, S("No files were restored"));
        finish(c, 0);
    }

    iz *order = new(a, list.n, iz);
    iz  nsel  = parse_selection(c, a, line, list.n, order);

    // Restore each selected candidate in the order asked; batch errors do
    // not abort the run, but any failure makes the exit status 1 (7.7).
    b32 anyfail = 0;
    for (iz q = 0; q < nsel; q++) {
        ResCand *cd = &arr[order[q]];
        Str dbase = basename(cd->loc);
        if (cd->loc.len && __builtin_memchr(cd->loc.data, 0, (uz)cd->loc.len)) {
            say(c, c->err, S("embedded null byte"));   // Python's ValueError
            anyfail = 1;
            continue;
        }
        if (lexists(c->os, c->scratch, cd->loc)) {
            Stat ds = {};
            os_stat(c->os, c->scratch, cd->loc, 1, &ds);   // isdir follows
            if (!overwrite || ds.kind == KIND_DIR) {
                Str m =  S("Refusing to overwrite existing file \"");
                m = concat(a, m, dbase);
                m = concat(a, m, S("\"."));
                say(c, c->err, m);
                anyfail = 1;
                continue;
            }
        }
        Str dp = dirname(cd->loc);
        Stat dps = {};
        b32 isdir = os_stat(c->os, c->scratch, dp, 1, &dps)
                 && dps.kind == KIND_DIR;
        if (!isdir) {
            i32 perr;
            Str epath;
            if (makedirs(c, c->scratch, dp, 0777, &perr, &epath)) {
                say(c, c->err, errtext(a, c->os, perr, epath));
                anyfail = 1;
                continue;
            }
        }
        Str reason;
        if (!move_path(c, a, c->scratch, cd->backup, cd->loc, &reason)) {
            say(c, c->err, reason);
            anyfail = 1;
            continue;
        }
        remove_path(c, c->scratch, cd->infopath);
    }
    finish(c, anyfail ? 1 : 0);
}

// Emptying trash cans (trash-empty)

enum {
    EMPTY_HELP, EMPTY_COMPLETION, EMPTY_VERSION, EMPTY_VERBOSE,
    EMPTY_TRASHDIR, EMPTY_PRINTTIME, EMPTY_ALLUSERS, EMPTY_INTERACTIVE,
    EMPTY_FORCE, EMPTY_DRYRUN, EMPTY_DAYS,
};

// Removes one path (or announces the removal).  Failures are reported and
// the loop continues; the exit status of trash-empty stays 0 (spec 8.4).
static void empty_remove(Ctx *c, Arena *a, Str path, b32 verbose, b32 dry)
{
    if (dry) {
        say(c, c->out, concat(a, S("would remove "), path));
        return;
    }
    if (verbose) {
        say(c, c->out, concat(a, S("removing "), path));
    }
    if (!remove_path(c, *a, path)) {
        prefixes(c, c->err, concat(a, S("cannot remove "), path));
    }
}

// Empties one trash dir (spec 8.4): info-driven removals first, backup copy
// before info file, then the orphans regardless of any days argument.
static void empty_one_dir(Ctx *c, Arena *, Arena scratch, Str td,
                          b32 have_days, i64 cutoff, b32 verbose, b32 dry,
                          b32 faketime, Str fakedate)
{
    Os *os = c->os;
    Arena t    = scratch;
    Str infodir  = join(&t, td, S("info"));
    i32 state;
    DirEnt *ents = listexisting(c, &t, infodir, &state);
    if (state == 1) {
        return;
    }
    if (state < 0) {
        die(c, 1, errtext(&t, os, -state, infodir));
    }
    for (DirEnt *e = ents; e; e = e->next) {
        if (!endswith(e->name, S(".trashinfo"))) {
            continue;   // non-trashinfo info entries are never touched
        }
        Arena te = t;
        Str infopath = join(&te, infodir, e->name);
        if (have_days) {
            i32 status;
            TrashInfo ti = trashinfo_read(c, &te, te, infopath, &status);
            if (status == TI_READERR) {
                die(c, 1, errtext(&te, os, os_errno(os), infopath));
            }
            if (status == TI_BADUTF8) {
                Str m = concat(&te, infopath,
                               S(": unable to parse trashinfo "
                                 "(invalid UTF-8)"));
                prefixes(c, c->err, m);
                continue;   // unparsable dates are kept
            }
            if (fakedate.data && !faketime) {   // the clock is read per file
                Str m =  S("invalid TRASH_DATE: ");
                m = concat(&te, m, fakedate);
                prefixes(c, c->err, m);
            }
            if (!ti.has_date) {
                continue;   // missing or invalid date: kept (spec 8.3)
            }
            if (!(datetime_key(ti.date) < cutoff)) {
                continue;   // strictly older only (spec 8.3)
            }
        }
        empty_remove(c, &te, backuppath(&te, td, e->name), verbose, dry);
        empty_remove(c, &te, infopath, verbose, dry);
    }
    Arena tf      = t;
    Str filesdir  = join(&tf, td, S("files"));
    b32 fok;
    DirEnt *fents = os_listdir(os, &tf, filesdir, &fok);
    if (fok && fents) {
        for (DirEnt *e = fents; e; e = e->next) {
            Str info = join(&tf, infodir,
                            concat(&tf, e->name, S(".trashinfo")));
            if (lexists(os, tf, info)) {
                continue;
            }
            empty_remove(c, &tf, join(&tf, filesdir, e->name), verbose, dry);
        }
    }
}

static i32 cmd_empty(Ctx *c, iz argc, Str *argv)
{
    Arena *a = c->perm;
    Arg args[] = {
        [EMPTY_HELP] = {.opts = {S("-h"), S("--help")}, .nopts = 2,
                        .kind = AK_HELP, .nargs = NA_ZERO,
                        .help = S("show this help message and exit")},
        [EMPTY_COMPLETION] = {.opts = {S("--print-completion")}, .nopts = 1,
                        .choices = {S("bash"), S("zsh"), S("tcsh")},
                        .nchoices = 3, .kind = AK_COMPLETION,
                        .nargs = NA_ONE,
                        .help = S("print shell completion script")},
        [EMPTY_VERSION] = {.opts = {S("--version")}, .nopts = 1,
                        .kind = AK_FLAG, .nargs = NA_ZERO,
                        .help = S("show program's version number and exit")},
        [EMPTY_VERBOSE] = {.opts = {S("-v"), S("--verbose")}, .nopts = 2,
                        .kind = AK_COUNT, .nargs = NA_ZERO,
                        .help = S("list files that will be deleted")},
        [EMPTY_TRASHDIR] = {.opts = {S("--trash-dir")}, .nopts = 1,
                        .metavar = S("TRASH_DIR"), .kind = AK_APPEND,
                        .nargs = NA_ONE,
                        .help = S("specify the trash directory to use")},
        [EMPTY_PRINTTIME] = {.opts = {S("--print-time")}, .nopts = 1,
                        .kind = AK_FLAG, .nargs = NA_ZERO, .hidden = 1},
        [EMPTY_ALLUSERS] = {.opts = {S("--all-users")}, .nopts = 1,
                        .kind = AK_FLAG, .nargs = NA_ZERO,
                        .help = S("empty all trashcan of all the users")},
        [EMPTY_INTERACTIVE] = {.opts = {S("-i"), S("--interactive")},
                        .nopts = 2, .kind = AK_FLAG, .nargs = NA_ZERO,
                        .help = S("ask before emptying trash directories")},
        [EMPTY_FORCE] = {.opts = {S("-f")}, .nopts = 1, .kind = AK_FLAG,
                        .nargs = NA_ZERO,
                        .help = S("don't ask before emptying trash "
                                  "directories")},
        [EMPTY_DRYRUN] = {.opts = {S("--dry-run")}, .nopts = 1,
                        .kind = AK_FLAG, .nargs = NA_ZERO,
                        .help = S("show which files would have been "
                                  "removed")},
        [EMPTY_DAYS] = {.metavar = S("days"), .nargs = NA_OPT, .isint = 1},
    };
    Parser pr = {
        .description = S("Purge trashed files."),
        .epilog      = S("Report bugs to "
                         "https://github.com/andreafrancia/trash-cli/issues"),
        .args        = args,
        .nargs       = (iz)countof(args),
    };

    ParsedOpts p = ap_parse(c, &pr, argc, argv);
    if (optgiven(&p, EMPTY_VERSION)) {
        say(c, c->out, concat(a, concat(a, clone(a, c->prog), S(" ")),
                              S("0.26.9.29")));
        finish(c, 0);
    }

    b32 verbose   = optgiven(&p, EMPTY_VERBOSE);
    b32 dry       = optgiven(&p, EMPTY_DRYRUN);
    b32 all_users = optgiven(&p, EMPTY_ALLUSERS);
    i64 uid       = os_getuid(c->os);

    // days (spec 8.3): already checked to be an int while parsing.
    b32 have_days = 0;
    i64 days      = 0;
    Str daysarg   = p.npos ? p.pos[0] : (Str){};
    if (daysarg.data) {
        have_days = 1;
        days      = parseint(a, daysarg).value;
    }

    // The clock: TRASH_DATE when it parses, else the real local time
    // (spec 10).  An invalid value is warned about per compared file.
    DateTime now;
    Str  fakedate = os_getenv(c->os, S("TRASH_DATE"));
    b32  faketime = 0;
    if (fakedate.data) {
        faketime = parse_datetime(fakedate, &now);
    }
    if (!faketime) {
        os_now(c->os, &now);
    }

    if (optgiven(&p, EMPTY_PRINTTIME)) {
        if (fakedate.data && !faketime) {
            prefixes(c, c->err, concat(a, S("invalid TRASH_DATE: "), fakedate));
        }
        say(c, c->out, format_datetime(a, now, '-', 'T'));
        finish(c, 0);
    }

    // The cutoff must stay within the representable date range (years
    // 1..9999); out-of-range values are usage errors (corrected).
    i64 cutoff = 0;
    if (have_days) {
        i64 limit = maxof(i64)/86400;
        b32 toobig = days > limit || days < -limit;
        if (!toobig) {
            cutoff = datetime_key(now) - days * 86400;
            toobig = cutoff < -62135596800LL || cutoff > 253402300799LL;
        }
        if (toobig) {
            Str m =  S("argument days: value out of range: ");
            m = concat(a, m, pyrepr(a, daysarg));
            ap_fail(c, &pr, m);
        }
    }

    Scan s = {};
    iz ntd = optcount(&p, EMPTY_TRASHDIR);
    if (ntd) {
        EvList ev = {};
        ev.tail   = &ev.head;
        for (iz k = 0; k < ntd; k++) {
            evpush(a, &ev, EV_FOUND, optval(&p, EMPTY_TRASHDIR, k),
                   (Str){});
        }
        s.events = ev.head;
    } else {
        s = scan_trash_dirs(c, a, c->scratch, (ScanOpts){.all_users = all_users,
                                                         .uid = (i32)uid});
    }

    // Interactive by default, and only ever one confirmation for all the
    // trash dirs together (spec 8.5).
    i32 mode = os_isatty(c->os, 0);
    for (OptVal *v = p.vals; v; v = v->next) {
        if (v->id == EMPTY_FORCE)       { mode = 0; }
        if (v->id == EMPTY_INTERACTIVE) { mode = 1; }
    }
    if (mode) {
        b32 any = 0;
        any = s.events != 0;   // skipped dirs count: the list is not empty
        if (!any) {
            say(c, c->out, S("No trash directories to empty."));
            finish(c, 0);
        }
        say(c, c->out, S("Would empty the following trash directories:"));
        for (ScanEv *ev = s.events; ev; ev = ev->next) {
            if (ev->kind == EV_FOUND) {
                say(c, c->out, concat(a, S("    - "), ev->path));
            }
        }
        print(c->out, S("Proceed? (y/N) "));
        flush(c->out);
        LineReader lr = {};
        lr.os = c->os;
        lr.fd = 0;
        Str line;
        if (!readline(c->os, &lr, a, &line)) {
            prefixes(c, c->err, S("EOF while reading the answer"));
            finish(c, 1);
        }
        if (!(line.len && (line.data[0]=='y' || line.data[0]=='Y'))) {
            finish(c, 0);   // declined: nothing is removed
        }
    }

    for (ScanEv *ev = s.events; ev; ev = ev->next) {
        if (ev->kind == EV_FOUND) {
            empty_one_dir(c, a, c->scratch, ev->path, have_days, cutoff,
                          verbose, dry, faketime, fakedate);
        }
    }
    finish(c, 0);
}


// Removing matching files from the trash (trash-rm)

// "<prog>: cannot remove <path>: [Errno N] <reason>" for a failed removal.
static void rmfailed(Ctx *c, Arena *a, Str path)
{
    i32 err = os_errno(c->os);
    Str m = concat(a, S("cannot remove "), path);
    m = concat(a, m, S(": [Errno "));
    m = concat(a, m, istr(a, err));
    m = concat(a, m, S("] "));
    prefixes(c, c->err, concat(a, m, os_strerror(c->os, err)));
}

static i32 cmd_rm(Ctx *c, iz argc, Str *argv)
{
    Arena *a = c->perm;
    if (!argc) {
        // The exact usage block, exit 8 (spec 9.1).  There are no options:
        // --help and --version are patterns like any other.
        say(c, c->err, S("Usage:"));
        say(c, c->err, S("    trash-rm PATTERN"));
        say(c, c->err, S(""));
        say(c, c->err, S("Please specify PATTERN."));
        say(c, c->err, S("trash-rm uses fnmatch.fnmatchcase to match "
                         "patterns, see https://docs.python.org/3/library/"
                         "fnmatch.html for more details."));
        finish(c, 8);
    }
    Str pattern = argv[0];   // only the first argument is used (spec 9.1)

    Arena scratch = c->scratch;
    b32 failed = 0;
    Scan s = scan_trash_dirs(c, a, c->scratch,
                             (ScanOpts){.uid = os_getuid(c->os)});
    for (ScanEv *ev = s.events; ev; ev = ev->next) {
        if (ev->kind != EV_FOUND) {
            continue;   // rejected dirs are skipped silently (spec 9.3)
        }
        Arena t      = scratch;
        Str infodir  = join(&t, ev->path, S("info"));
        i32 state;
        DirEnt *ents = listexisting(c, &t, infodir, &state);
        if (state == 1) {
            continue;
        }
        if (state < 0) {
            die(c, 1, errtext(&t, c->os, -state, infodir));
        }
        for (DirEnt *e = ents; e; e = e->next) {
            if (!endswith(e->name, S(".trashinfo"))) {
                continue;
            }
            Arena te = t;
            Str infopath = join(&te, infodir, e->name);
            i32 status;
            TrashInfo ti = trashinfo_read(c, &te, te, infopath, &status);
            if (status == TI_READERR) {
                die(c, 1, errtext(&te, c->os, os_errno(c->os), infopath));
            }
            if (status == TI_BADUTF8) {
                Str m = concat(&te, infopath,
                               S(": unable to parse trashinfo "
                                 "(invalid UTF-8)"));
                prefixes(c, c->err, m);
                continue;
            }
            if (status == TI_NOPATH) {
                Str m = concat(&te, infopath, S(": unable to parse 'Path'"));
                prefixes(c, c->err, m);
                continue;
            }
            Str loc = join(&te, ev->volume, ti.path);
            // A pattern starting with / matches the whole original
            // location, anything else the basename only (spec 9.2); an
            // empty pattern matches nothing.
            Str target = pattern.len && pattern.data[0] == '/'
                       ? loc
                       : basename(loc);
            if (!fnmatch_(te, pattern, target)) {
                continue;
            }
            // The backup copy first, then the info file; a failure is
            // reported and, with the backup still there, the info file is
            // left to describe it.  The run goes on and exits 1.
            Str backup = backuppath(&te, ev->path, e->name);
            if (lexists(c->os, te, backup) && !remove_path(c, te, backup)) {
                rmfailed(c, &te, backup);
                failed = 1;
                continue;
            }
            if (!remove_path(c, te, infopath)) {
                rmfailed(c, &te, infopath);
                failed = 1;
            }
        }
    }
    finish(c, failed ? 1 : 0);
}


// Dispatch

typedef struct {
    Str  name;
    i32 (*fn)(Ctx *, iz, Str *);
} Persona;

// Dispatches on the basename of argv[0]; the personas are symlinks (or
// hard links) to one executable.
[[noreturn]] static void dispatch(Ctx *c, iz argc, Str *argv)
{
    Arena *a = c->perm;
    Persona personas[] = {
        {S("trash"),         cmd_put},
        {S("trash-put"),     cmd_put},
        {S("trash-list"),    cmd_list},
        {S("trash-restore"), cmd_restore},
        {S("trash-empty"),   cmd_empty},
        {S("trash-rm"),      cmd_rm},
    };
    Str persona = basename(argv[0]);
    for (iz k = 0; k < (iz)countof(personas); k++) {
        if (equals(persona, personas[k].name)) {
            finish(c, personas[k].fn(c, argc - 1, argv + 1));
        }
    }
    Str m =  S("unknown command name '");
    m = concat(a, m, persona);
    m = concat(a, m, S("'; link this executable as one of"));
    for (iz k = 0; k < (iz)countof(personas); k++) {
        m = concat(a, m, k ? S(", ") : S(" "));
        m = concat(a, m, personas[k].name);
    }
    die(c, 2, m);
}

// The Linux platform layer.

#if !defined(__linux)
#error "unsupported platform: trash needs Linux"
#else

// The core's basename(Str) must not collide with the libc declaration
// pulled in below; nothing here calls the libc one.
#define basename libc_basename
#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <dirent.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#undef basename

#ifndef TEST
// The Linux platform implementations.  With -DTEST the whole region below is
// replaced by a virtual operating system plus the conformance suite; the core
// above is compiled identically either way.

// A NUL-terminated copy of a path in scratch, for the raw calls.
static char *cstr(Arena *scratch, Str path)
{
    affirm(scratch->beg <= scratch->end);
    uz n = (uz)path.len;
    if ((iz)(scratch->end - scratch->beg) < (iz)(n + 1)) {
        oom(scratch->os);
    }
    byte *z = scratch->beg;
    scratch->beg += (iz)(n + 1);
    if (n) {
        __builtin_memcpy(z, path.data, n);
    }
    z[n] = 0;
    if (n && __builtin_strlen((char *)z) != n) {
        z[0] = 0;   // an embedded NUL names nothing: the call fails ENOENT
    }
    return (char *)z;
}

[[noreturn]] static void os_exit(Os *, i32 status)
{
    _exit(status);
}

static b32 os_write(Os *, i32 fd, u8 *buf, iz len)
{
    while (len) {
        iz r = write(fd, buf, (uz)len);
        if (r < 0) {
            if (errno == EINTR) {
                continue;
            }
            return 0;
        }
        buf += r;
        len -= r;
    }
    return 1;
}

static iz os_read(Os *, i32 fd, u8 *buf, iz cap)
{
    for (;;) {
        iz r = read(fd, buf, (uz)cap);
        if (r < 0 && errno == EINTR) {
            continue;
        }
        return r;
    }
}

static i32 os_open(Os *, Arena scratch, Str path, b32 create, u32 mode)
{
    char *z = cstr(&scratch, path);
    return create ? open(z, O_WRONLY | O_CREAT | O_EXCL, mode)
                  : open(z, O_RDONLY);
}

static void os_close(Os *, i32 fd)
{
    close(fd);
}

static Str os_getenv(Os *, Str name)
{
    byte z[512];
    if (name.len >= (iz)countof(z)) {
        return (Str){};
    }
    if (name.len) {
        __builtin_memcpy(z, name.data, (uz)name.len);
    }
    z[name.len] = 0;
    char *v = getenv((char *)z);
    return v ? import((u8 *)v) : (Str){};
}

static b32 os_stat(Os *, Arena scratch, Str path, b32 follow, Stat *out)
{
    struct stat st;
    char *z = cstr(&scratch, path);
    if ((follow ? stat : lstat)(z, &st)) {
        return 0;
    }
    i32 kind = KIND_NONE;
    if      (S_ISREG(st.st_mode))  { kind = KIND_FILE; }
    else if (S_ISDIR(st.st_mode))  { kind = KIND_DIR; }
    else if (S_ISLNK(st.st_mode))  { kind = KIND_LINK; }
    else if (S_ISFIFO(st.st_mode)) { kind = KIND_FIFO; }
    else if (S_ISSOCK(st.st_mode)) { kind = KIND_SOCK; }
    else if (S_ISBLK(st.st_mode))  { kind = KIND_BLK; }
    else if (S_ISCHR(st.st_mode))  { kind = KIND_CHR; }
    *out = (Stat){
        .dev  = (i64)st.st_dev,
        .ino  = (i64)st.st_ino,
        .kind = kind,
        .mode = (u32)(st.st_mode & 07777u),
        .size = (i64)st.st_size,
    };
    return 1;
}

static b32 os_readlink(Os *, Arena *a, Str path, Str *out)
{
    enum { CAP = 1 << 12 };
    u8 *buf = new(a, CAP, u8);
    iz r = readlink(cstr(a, path), (char *)buf, CAP);
    if (r < 0) {
        return 0;
    }
    *out = span(buf, buf + r);
    return 1;
}

static b32 os_mkdir(Os *, Arena scratch, Str path, u32 mode)
{
    return !mkdir(cstr(&scratch, path), mode);
}

static b32 os_unlink(Os *, Arena scratch, Str path)
{
    return !unlink(cstr(&scratch, path));
}

static b32 os_chmod(Os *, Arena scratch, Str path, u32 mode)
{
    return !chmod(cstr(&scratch, path), mode);
}

static b32 os_rmdir(Os *, Arena scratch, Str path)
{
    return !rmdir(cstr(&scratch, path));
}

static b32 os_rename(Os *, Arena scratch, Str from, Str to)
{
    return !rename(cstr(&scratch, from), cstr(&scratch, to));
}

static b32 os_symlink(Os *, Arena scratch, Str target, Str path)
{
    return !symlink(cstr(&scratch, target), cstr(&scratch, path));
}

static b32 os_access(Os *, Arena scratch, Str path, i32 mode)
{
    return !access(cstr(&scratch, path), mode);
}

static b32 os_isatty(Os *, i32 fd)
{
    return isatty(fd);
}

static i32 os_getuid(Os *)
{
    return (i32)getuid();
}

static void os_now(Os *, DateTime *out)
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    struct tm tm;
    localtime_r(&ts.tv_sec, &tm);
    *out = (DateTime){
        .year  = tm.tm_year + 1900,
        .month = tm.tm_mon + 1,
        .day   = tm.tm_mday,
        .hour  = tm.tm_hour,
        .min   = tm.tm_min,
        .sec   = tm.tm_sec,
    };
}

static User *os_users(Os *, Arena *a)
{
    User *head = 0;
    User **tail = &head;
    setpwent();
    for (struct passwd *pw; (pw = getpwent());) {
        User *u  = new(a, 1, User);
        u->dir   = clone(a, import((u8 *)pw->pw_dir));   // static buffer
        u->uid   = (i32)pw->pw_uid;
        *tail  = u;
        tail   = &u->next;
    }
    endpwent();
    return head;
}

static DirEnt *os_listdir(Os *, Arena *a, Str path, b32 *ok)
{
    *ok = 0;
    DIR *d = opendir(cstr(a, path));
    if (!d) {
        return 0;
    }
    DirEnt *head = 0;
    DirEnt **tail = &head;
    for (struct dirent *de; (de = readdir(d));) {
        if (de->d_name[0] == '.' && (de->d_name[1] == 0 ||
                                     (de->d_name[1] == '.' &&
                                      de->d_name[2] == 0))) {
            continue;
        }
        DirEnt *e  = new(a, 1, DirEnt);
        e->name    = clone(a, import((u8 *)de->d_name));   // dies with d
        *tail      = e;
        tail       = &e->next;
    }
    closedir(d);
    *ok = 1;
    return head;
}

static i32 os_errno(Os *)
{
    return errno;
}

static iz os_termwidth(Os *)
{
    struct winsize ws;
    if (ioctl(1, TIOCGWINSZ, &ws) || !ws.ws_col) {
        return 0;
    }
    return ws.ws_col;
}

static Str os_strerror(Os *, i32 err)
{
    return import((u8 *)strerror(err));
}

static Str os_selfexe(Os *os, Arena *a)
{
    enum { CAP = 1 << 12 };
    u8 *buf = new(a, CAP, u8);
    iz r = readlink("/proc/self/exe", (char *)buf, CAP);
    if (r < 0) {
        return os->name;
    }
    return span(buf, buf + r);
}

static Str os_getcwd(Os *, Arena *a)
{
    for (iz cap = 1 << 8; cap <= 1 << 16; cap <<= 1) {
        u8 *buf = new(a, cap, u8);
        if (getcwd((char *)buf, (uz)cap)) {
            return span(buf, buf + strlen((char *)buf));
        }
        if (errno != ERANGE) {
            return (Str){};   // e.g. the directory was removed: errno is set
        }
    }
    errno = ENAMETOOLONG;
    return (Str){};
}

static u64 os_rand(Os *os)
{
    u64 x = os->rng;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    os->rng = x;
    return x;
}

// The entry point: one memory block split into the two arenas.

static i32 cmd_put(Ctx *c, iz argc, Str *argv);
static i32 cmd_list(Ctx *c, iz argc, Str *argv);
static i32 cmd_restore(Ctx *c, iz argc, Str *argv);
static i32 cmd_empty(Ctx *c, iz argc, Str *argv);
static i32 cmd_rm(Ctx *c, iz argc, Str *argv);
[[noreturn]] static void dispatch(Ctx *c, iz argc, Str *argv);

int main(int argc, char **av)
{
    enum { CAP = 1 << 28 };
    byte *mem = mmap(0, CAP, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mem == MAP_FAILED) {
        u8 msg[] = "trash: out of memory\n";
        if (write(2, msg, countof(msg) - 1)) {}
        return 1;
    }

    Os os = {};
    os.name = basename(import((u8 *)av[0]));
    os.rng  = (u64)time(0) << 32 | (u64)getpid();
    if (!os.rng) {
        os.rng = 1;
    }

    Arena perm    = {&os, mem, mem + CAP/4*3};
    Arena scratch = {&os, perm.end, mem + CAP};

    Ctx c = {};
    c.os      = &os;
    c.perm    = &perm;
    c.scratch = scratch;
    c.out     = newoutput(&perm, &os, 1);
    c.err     = newoutput(&perm, &os, 2);

    Str *argv = new(&perm, argc, Str);
    for (i32 i = 0; i < argc; i++) {
        argv[i] = import((u8 *)av[i]);
    }
    c.prog = basename(argv[0]);

    dispatch(&c, argc, argv);
}

#else  // TEST

// The virtual operating system, plus the conformance suite that runs against
// it.  This region implements the same os_* prototype table as the Linux
// layer would, so the core under test is byte-for-byte the shipping code.
// State lives in one arena rewound between tests: O(1) reset.

#include <setjmp.h>
#include <stdarg.h>

typedef struct VNode VNode;
struct VNode {
    VNode *next;    // next sibling
    VNode *kids;    // first child
    VNode *parent;
    Str    name;    // component bytes; any bytes except '/' and NUL
    i32    kind;
    u32    mode;    // low twelve bits, st_mode style
    i32    uid;
    Str    data;    // KIND_FILE
    Str    linkto;  // KIND_LINK
    i64    ino;
};

typedef struct {
    VNode *n;    // 0 when closed; fds 0-2 live in the console, not here
    iz    off;
    b32   w;
} VFd;

typedef struct {
    Str path;    // mount point; everything under it reports this dev
    i64 dev;
} VMnt;

typedef struct {
    Arena     fs;      // every virtual allocation; rewound between tests
    VNode    *root;
    Str       mounts;  // served as /proc/self/mounts
    VMnt      mnt[256]; // the same mounts, for st_dev emulation
    i32       nmnts;
    Str       cwd;
    i32       uid;     // the current user
    DateTime  now;     // the virtual clock
    b32       istty[3];
    iz        termcols;  // the terminal's width on stdout (0: unknown)
    Str       stdinbuf;
    iz        stdinpos;
    Str       out;     // bytes written to fd 1
    Str       err;     // bytes written to fd 2
    Str       env[24][2];
    i32       nenv;
    i32       errnum;  // the virtual errno
    VFd       fd[24];
    i32       status;
    jmp_buf   exitjmp;
} Vos;

static Vos     *v;
static Arena   *gperm;
static Arena   *gscratch;
static jmp_buf  testjmp;
static Str      curtest;
static i32      nran;
static i32      nfailed;
static Str      gfilter;
static b32      gverbose;

#define VUID 1000   // the current user's uid in the virtual OS

// -- diagnostics ------------------------------------------------------------

static void vrepr(char *dst, uz cap, Str s)
{
    uz k = 0;
    for (iz i = 0; i < s.len && k + 5 < cap; i++) {
        u8 c = s.data[i];
        if (c == '\n') {
            dst[k++] = '\\'; dst[k++] = 'n';
        } else if (c == '\t') {
            dst[k++] = '\\'; dst[k++] = 't';
        } else if (c < 0x20 || c >= 0x7f) {
            k += (uz)sprintf(dst + k, "\\x%02x", c);
        } else {
            dst[k++] = (char)c;
        }
    }
    dst[k] = 0;
}

static void vfail(const char *file, i32 line, char *fmt, ...)
{
    char msg[1024];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof msg, fmt, ap);
    va_end(ap);
    fprintf(stderr, "FAIL %.*s: %s:%d: %s\n", (i32)curtest.len,
            curtest.data ? (char *)curtest.data : "", file, line, msg);
    nfailed++;
    longjmp(testjmp, 1);
}

#define CK(cond) ((cond) ? (void)0 \
                 : vfail(__FILE__, __LINE__, "expected: %s", #cond))
#define CK_EQ(got, want) ((got) == (want) ? (void)0 \
                 : vfail(__FILE__, __LINE__, "%s = %lld, want %lld", \
                         #got, (i64)(got), (i64)(want)))
#define CK_S(got, want)  ck_s(__FILE__, __LINE__, (got), (want))
#define CK_HAS(hay, needle)  ck_has(__FILE__, __LINE__, 1, hay, S(needle))
#define CK_NOHAS(hay, needle) ck_has(__FILE__, __LINE__, 0, hay, S(needle))
#define CK_HAS_S(hay, needle)  ck_has(__FILE__, __LINE__, 1, hay, needle)
#define CK_HAS_C(hay, needle)  ck_has(__FILE__, __LINE__, 1, hay, import((u8 *)(needle)))
#define CK_NOHAS_C(hay, needle) ck_has(__FILE__, __LINE__, 0, hay, import((u8 *)(needle)))
#define CK_NOHAS_S(hay, needle) ck_has(__FILE__, __LINE__, 0, hay, needle)
#define CK_STARTS(got, want) ck_starts(__FILE__, __LINE__, got, S(want))

static void ck_s(const char *file, i32 line, Str got, Str want)
{
    if (equals(got, want)) {
        return;
    }
    char g[768], w[768];
    vrepr(g, sizeof g, got);
    vrepr(w, sizeof w, want);
    vfail(file, line, "got %s, want %s", g, w);
}

static b32 hasstr(Str hay, Str needle)
{
    if (!needle.len) {
        return 1;
    }
    for (iz i = 0; i + needle.len <= hay.len; i++) {
        if (equals(takehead(cuthead(hay, i), needle.len), needle)) {
            return 1;
        }
    }
    return 0;
}

static void ck_has(const char *file, i32 line, b32 want, Str hay, Str needle)
{
    b32 got = hasstr(hay, needle);
    if (got != want) {
        char g[512], n[256];
        vrepr(g, sizeof g, hay);
        vrepr(n, sizeof n, needle);
        vfail(file, line, "%s: %s %s \"%s\"", want ? "missing" : "forbidden",
              want ? "not found in" : "found in", g, n);
    }
}

static void ck_starts(const char *file, i32 line, Str got, Str want)
{
    if (!startswith(got, want)) {
        char g[768], w[256];
        vrepr(g, sizeof g, got);
        vrepr(w, sizeof w, want);
        vfail(file, line, "got %s, want prefix %s", g, w);
    }
}

// -- the virtual filesystem --------------------------------------------------

static char *vfmt(char *fmt, ...)
{
    char *buf = new(&v->fs, 1024, char);
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, 1024, fmt, ap);
    va_end(ap);
    return buf;
}

static Str vcat(char *a, char *b)
{
    return concat(&v->fs, import((u8 *)a), import((u8 *)b));
}

// The dev a path reports: that of the longest mount point at or above it.
// Lexical on the path given; the fixtures never alias across devices.
static i64 vdevof(Str path)
{
    i64 dev = 1;
    iz best = 1;                       // "/" holds dev 1
    for (i32 i = 0; i < v->nmnts; i++) {
        Str m = v->mnt[i].path;
        b32 under = startswith(path, m)
                && (m.len == 1 || path.len == m.len || path.data[m.len] == '/');
        if (under && m.len > best) {
            best = m.len;
            dev  = v->mnt[i].dev;
        }
    }
    return dev;
}

static VNode *vnewnode(i32 kind, u32 mode, Str name)
{
    static i64 nextino;
    VNode *n = new(&v->fs, 1, VNode);
    n->kind   = kind;
    n->mode   = mode;
    n->name   = clone(&v->fs, name);
    n->uid    = v->uid;
    n->ino    = ++nextino;
    return n;
}

static void vattach(VNode *p, VNode *n)
{
    n->parent = p;
    n->next   = p->kids;
    p->kids   = n;
}

static void vdetach(VNode *p, VNode *n)
{
    for (VNode **k = &p->kids; *k; k = &(*k)->next) {
        if (*k == n) {
            *k    = n->next;
            n->next = 0;
            n->parent = 0;
            return;
        }
    }
    affirm(0);
}

// Absolute form of a path: relative paths resolve against the virtual cwd,
// as the kernel's would.
static Str vabs(Str path)
{
    if (path.len && path.data[0] == '/') {
        return path;
    }
    if (!path.len || !v->cwd.len) {
        return path;
    }
    return concat(&v->fs, v->cwd, concat(&v->fs, S("/"), path));
}

// Splits "/a/b/c" into dir "/a/b" and base "c"; "/" has no base.  Sets
// v->errnum and returns 0 when the last component is empty or missing.
static b32 vsplit(Str path, Str *dir, Str *base)
{
    path = vabs(path);
    if (!path.len || path.data[0] != '/') {
        v->errnum = ENOENT;
        return 0;
    }
    iz last = -1;
    for (iz i = (iz)path.len - 1; i >= 1; i--) {
        if (path.data[i] == '/') {
            last = i;
            break;
        }
    }
    if (last < 0) {
        *dir  = S("/");
        *base = cuthead(path, 1);
    } else {
        *dir  = last ? takehead(path, last) : S("/");
        *base = cuthead(path, last + 1);
    }
    if (!base->len) {
        v->errnum = ENOENT;
        return 0;
    }
    return 1;
}

// The permission bits that apply to the current user.
static u32 vbits(VNode *n)
{
    if (v->uid == 0) {
        return 7;
    }
    return n->uid == v->uid ? (n->mode >> 6) & 7u : n->mode & 7u;
}

static b32 vcan(VNode *n, i32 bit)
{
    return (vbits(n) & (u32)bit) != 0;
}

static Str nextcomp(Str *rest)
{
    Str s = *rest;
    iz i = 0;
    while (i < s.len && s.data[i] != '/') {
        i++;
    }
    Str comp = takehead(s, i);
    while (i < s.len && s.data[i] == '/') {
        i++;
    }
    *rest = cuthead(s, i);
    return comp;
}

// Resolves an absolute path.  Intermediate symlinks are always followed; the
// final component only when follow is set.  Requires x on every directory
// traversed.  On failure sets v->errnum and returns 0.
static b32 vwalk(Str path, b32 follow, VNode **out, Str *outpath)
{
    v->errnum = 0;
    if (path.len && __builtin_memchr(path.data, 0, (uz)path.len)) {
        v->errnum = ENOENT;   // like the real layer: a NUL names nothing
        return 0;
    }
    path = vabs(path);
    if (!path.len || path.data[0] != '/') {
        v->errnum = ENOENT;
        return 0;
    }
    Str rest = cuthead(path, 1);
    VNode *cur = v->root;
    VNode *par = 0;
    Str rpath = S("/");   // the resolved path of cur, for dev lookup
    i32 links = 0;
    for (;;) {
        while (rest.len && rest.data[0] == '/') {
            rest = cuthead(rest, 1);
        }
        if (!rest.len) {
            break;
        }
        if (cur->kind != KIND_DIR) {
            v->errnum = ENOTDIR;
            return 0;
        }
        if (!vcan(cur, ACCESS_X)) {
            v->errnum = EACCES;
            return 0;
        }
        Str comp = nextcomp(&rest);
        if (equals(comp, S("."))) {
            continue;
        }
        if (equals(comp, S(".."))) {
            if (cur->parent) {
                cur = cur->parent;
                par = cur->parent;
            }
            rpath = dirname(rpath);
            continue;
        }
        VNode *kid = 0;
        for (VNode *k = cur->kids; k; k = k->next) {
            if (equals(k->name, comp)) {
                kid = k;
                break;
            }
        }
        if (!kid) {
            v->errnum = ENOENT;
            return 0;
        }
        par = cur;
        cur = kid;
        rpath = equals(rpath, S("/"))
              ? concat(&v->fs, S("/"), comp)
              : concat(&v->fs, rpath, concat(&v->fs, S("/"), comp));
        if (cur->kind == KIND_LINK && (rest.len || follow)) {
            if (++links > 8) {
                v->errnum = ELOOP;
                return 0;
            }
            Str t = cur->linkto;
            if (t.len && t.data[0] == '/') {
                cur = v->root;
                par = 0;
                rpath = S("/");
            } else {
                cur = par ? par : v->root;
                par = cur->parent;
                rpath = dirname(rpath);
            }
            if (rest.len) {
                t = concat(&v->fs, t, concat(&v->fs, S("/"), rest));
            }
            rest = t;
        }
    }
    *out = cur;
    if (outpath) {
        *outpath = rpath;
    }
    return 1;
}

static VNode *vfindin(VNode *dir, Str base)
{
    for (VNode *k = dir->kids; k; k = k->next) {
        if (equals(k->name, base)) {
            return k;
        }
    }
    return 0;
}

// Resolves the parent directory of path and hands back the final component.
static b32 vparentof(Str path, VNode **parent, Str *base)
{
    Str dir;
    if (!vsplit(path, &dir, base)) {
        return 0;
    }
    if (!vwalk(dir, 1, parent, 0)) {
        return 0;
    }
    if ((*parent)->kind != KIND_DIR) {
        v->errnum = ENOTDIR;
        return 0;
    }
    return 1;
}

static b32 vparentwritable(VNode *p)
{
    if (vcan(p, ACCESS_W) && vcan(p, ACCESS_X)) {
        return 1;
    }
    v->errnum = EACCES;
    return 0;
}

// -- the virtual os_* implementations -----------------------------------------

[[noreturn]] static void os_exit(Os *os, i32 status)
{
    (void)os;
    v->status = status;
    longjmp(v->exitjmp, 1);
}

static b32 os_write(Os *os, i32 fd, u8 *buf, iz len)
{
    (void)os;
    if (fd == 1 || fd == 2) {
        Str *acc = fd == 1 ? &v->out : &v->err;
        *acc = concat(&v->fs, *acc, (Str){buf, len});
        return 1;
    }
    VFd *s = &v->fd[fd];
    if (!s->n || !s->w) {
        v->errnum = EBADF;
        return 0;
    }
    if (s->off == s->n->data.len) {
        s->n->data = concat(&v->fs, s->n->data, (Str){buf, len});
        s->off += len;
    } else {
        Str head = takehead(s->n->data, s->off);
        Str tail = cuthead(s->n->data, s->off + len);
        s->n->data = concat(&v->fs, concat(&v->fs, head, (Str){buf, len}),
                            tail);
        s->off += len;
    }
    return 1;
}

static iz os_read(Os *os, i32 fd, u8 *buf, iz cap)
{
    (void)os;
    if (fd == 0) {
        Str rest = cuthead(v->stdinbuf, v->stdinpos);
        iz take = rest.len < cap ? rest.len : cap;
        if (take > 0) {
            xcpy(buf, rest.data, (uz)take);
        }
        v->stdinpos += take;
        return take;
    }
    VFd *s = &v->fd[fd];
    if (!s->n) {
        v->errnum = EBADF;
        return -1;
    }
    if (s->n->kind == KIND_DIR) {
        v->errnum = EISDIR;
        return -1;
    }
    Str rest = cuthead(s->n->data, s->off);
    iz take = rest.len < cap ? rest.len : cap;
    if (take > 0) {
        xcpy(buf, rest.data, (uz)take);
    }
    s->off += take;
    return take;
}

static i32 vallocfd(VNode *n, b32 w)
{
    for (i32 i = 3; i < 24; i++) {
        if (!v->fd[i].n) {
            v->fd[i].n   = n;
            v->fd[i].off = 0;
            v->fd[i].w   = w;
            return i;
        }
    }
    v->errnum = ENFILE;
    return -1;
}

static i32 os_open(Os *os, Arena scratch, Str path, b32 create, u32 mode)
{
    (void)os;
    (void)scratch;
    if (create) {
        VNode *p;
        Str base;
        if (!vparentof(path, &p, &base)) {
            return -1;
        }
        if (base.len > 255) {
            v->errnum = ENAMETOOLONG;
            return -1;
        }
        if (!vparentwritable(p)) {
            return -1;
        }
        if (vfindin(p, base)) {
            v->errnum = EEXIST;
            return -1;
        }
        VNode *n = vnewnode(KIND_FILE, mode, base);
        vattach(p, n);
        return vallocfd(n, 1);
    }
    VNode *n;
    if (!vwalk(path, 1, &n, 0)) {
        return -1;
    }
    if (n->kind != KIND_DIR && !vcan(n, ACCESS_R)) {
        v->errnum = EACCES;
        return -1;
    }
    return vallocfd(n, 0);
}

static void os_close(Os *os, i32 fd)
{
    (void)os;
    if (fd >= 3 && fd < 24) {
        v->fd[fd].n = 0;
    }
}

static Str os_getenv(Os *os, Str name)
{
    (void)os;
    for (i32 i = 0; i < v->nenv; i++) {
        if (equals(v->env[i][0], name)) {
            return v->env[i][1];
        }
    }
    return (Str){};
}

static b32 os_stat(Os *os, Arena scratch, Str path, b32 follow, Stat *out)
{
    (void)os;
    (void)scratch;
    VNode *n;
    Str rpath;
    if (!vwalk(path, follow, &n, &rpath)) {
        return 0;
    }
    *out = (Stat){.dev = vdevof(rpath), .ino = n->ino, .kind = n->kind,
                  .mode = n->mode, .size = n->data.len};
    return 1;
}

static b32 os_readlink(Os *os, Arena *a, Str path, Str *out)
{
    (void)os;
    (void)a;
    VNode *n;
    if (!vwalk(path, 0, &n, 0)) {
        return 0;
    }
    if (n->kind != KIND_LINK) {
        v->errnum = EINVAL;
        return 0;
    }
    *out = n->linkto;
    return 1;
}

static b32 os_mkdir(Os *os, Arena scratch, Str path, u32 mode)
{
    (void)os;
    (void)scratch;
    VNode *p;
    Str base;
    if (!vparentof(path, &p, &base) || !vparentwritable(p)) {
        return 0;
    }
    if (vfindin(p, base)) {
        v->errnum = EEXIST;
        return 0;
    }
    vattach(p, vnewnode(KIND_DIR, mode, base));
    return 1;
}

static b32 os_unlink(Os *os, Arena scratch, Str path)
{
    (void)os;
    (void)scratch;
    VNode *p;
    Str base;
    if (!vparentof(path, &p, &base) || !vparentwritable(p)) {
        return 0;
    }
    VNode *n = vfindin(p, base);
    if (!n) {
        v->errnum = ENOENT;
        return 0;
    }
    if (n->kind == KIND_DIR) {
        v->errnum = EISDIR;
        return 0;
    }
    vdetach(p, n);
    return 1;
}

static b32 os_chmod(Os *os, Arena scratch, Str path, u32 mode)
{
    (void)os;
    (void)scratch;
    VNode *n;
    if (!vwalk(path, 1, &n, 0)) {
        return 0;
    }
    if (v->uid && n->uid != v->uid) {
        v->errnum = EPERM;
        return 0;
    }
    n->mode = mode;
    return 1;
}

static b32 os_rmdir(Os *os, Arena scratch, Str path)
{
    (void)os;
    (void)scratch;
    VNode *p;
    Str base;
    if (!vparentof(path, &p, &base) || !vparentwritable(p)) {
        return 0;
    }
    VNode *n = vfindin(p, base);
    if (!n) {
        v->errnum = ENOENT;
        return 0;
    }
    if (n->kind != KIND_DIR) {
        v->errnum = ENOTDIR;
        return 0;
    }
    if (n->kids) {
        v->errnum = ENOTEMPTY;
        return 0;
    }
    vdetach(p, n);
    return 1;
}

static b32 os_rename(Os *os, Arena scratch, Str from, Str to)
{
    (void)os;
    (void)scratch;
    VNode *fp, *tp;
    Str fbase, tbase;
    if (!vparentof(from, &fp, &fbase) || !vparentwritable(fp)) {
        return 0;
    }
    if (!vparentof(to, &tp, &tbase) || !vparentwritable(tp)) {
        return 0;
    }
    VNode *n = vfindin(fp, fbase);
    if (!n) {
        v->errnum = ENOENT;
        return 0;
    }
    if (vdevof(vabs(from)) != vdevof(vabs(to))) {
        v->errnum = EXDEV;
        return 0;
    }
    // Kernel rename semantics for an existing destination: a file replaces
    // a file, a directory replaces an empty directory, all else fails.
    VNode *victim = vfindin(tp, tbase);
    if (victim) {
        if (n->kind == KIND_DIR) {
            if (victim->kind != KIND_DIR) {
                v->errnum = ENOTDIR;
                return 0;
            }
            if (victim->kids) {
                v->errnum = ENOTEMPTY;
                return 0;
            }
        } else if (victim->kind == KIND_DIR) {
            v->errnum = EISDIR;
            return 0;
        }
    }
    // Moving a directory to a different parent rewrites its '..' entry,
    // which the kernel refuses without write access to the directory
    // itself (spec 5.6).  trash_rename() depends on this exact behavior.
    if (fp != tp && n->kind == KIND_DIR && !(n->mode & 0200)) {
        v->errnum = EACCES;
        return 0;
    }
    vdetach(fp, n);
    if (victim) {
        vdetach(tp, victim);
    }
    n->name = clone(&v->fs, tbase);
    vattach(tp, n);
    return 1;
}

static b32 os_symlink(Os *os, Arena scratch, Str target, Str path)
{
    (void)os;
    (void)scratch;
    VNode *p;
    Str base;
    if (!vparentof(path, &p, &base) || !vparentwritable(p)) {
        return 0;
    }
    if (vfindin(p, base)) {
        v->errnum = EEXIST;
        return 0;
    }
    VNode *n = vnewnode(KIND_LINK, 0777, base);
    n->linkto = clone(&v->fs, target);
    vattach(p, n);
    return 1;
}

static b32 os_access(Os *os, Arena scratch, Str path, i32 mode)
{
    (void)os;
    (void)scratch;
    VNode *n;
    if (!vwalk(path, 1, &n, 0)) {
        return 0;
    }
    if ((mode & ACCESS_R) && !vcan(n, ACCESS_R)) {
        v->errnum = EACCES;
        return 0;
    }
    if ((mode & ACCESS_W) && !vcan(n, ACCESS_W)) {
        v->errnum = EACCES;
        return 0;
    }
    if ((mode & ACCESS_X) && !vcan(n, ACCESS_X)) {
        v->errnum = EACCES;
        return 0;
    }
    return 1;
}

static b32 os_isatty(Os *os, i32 fd)
{
    (void)os;
    return fd >= 0 && fd < 3 ? v->istty[fd] : 0;
}

static i32 os_getuid(Os *os)
{
    (void)os;
    return v->uid;
}

static void os_now(Os *os, DateTime *out)
{
    (void)os;
    *out = v->now;
}

static User *os_users(Os *os, Arena *a)
{
    (void)os;
    static const struct { i32 uid; char *dir; } table[] = {
        {VUID,      "/home"},
        {VUID + 1,  "/otherhome"},
        {VUID + 2,  "/gonehome"},
    };
    User *head = 0;
    User **tail = &head;
    for (uz i = 0; i < countof(table); i++) {
        User *u = new(a, 1, User);
        u->uid = table[i].uid;
        u->dir = clone(a, import((u8 *)table[i].dir));
        *tail  = u;
        tail   = &u->next;
    }
    return head;
}

static DirEnt *os_listdir(Os *os, Arena *a, Str path, b32 *ok)
{
    (void)os;
    *ok = 0;
    VNode *n;
    if (!vwalk(path, 1, &n, 0)) {
        return 0;
    }
    if (n->kind != KIND_DIR) {
        v->errnum = ENOTDIR;
        return 0;
    }
    if (!vcan(n, ACCESS_R)) {
        v->errnum = EACCES;
        return 0;
    }
    DirEnt *head = 0;
    DirEnt **tail = &head;
    for (VNode *k = n->kids; k; k = k->next) {
        DirEnt *e = new(a, 1, DirEnt);
        e->name = clone(a, k->name);   // like the real layer: names live in *a
        *tail   = e;
        tail    = &e->next;
    }
    *ok = 1;
    return head;
}

static i32 os_errno(Os *os)
{
    (void)os;
    return v->errnum;
}

static iz os_termwidth(Os *os)
{
    (void)os;
    return v->istty[1] ? v->termcols : 0;
}

static Str os_strerror(Os *os, i32 err)
{
    (void)os;
    switch (err) {
    case EPERM:        return S("Operation not permitted");
    case ENOENT:       return S("No such file or directory");
    case EACCES:       return S("Permission denied");
    case EEXIST:       return S("File exists");
    case EISDIR:       return S("Is a directory");
    case ENOTDIR:      return S("Not a directory");
    case ELOOP:        return S("Too many levels of symbolic links");
    case ENAMETOOLONG: return S("File name too long");
    case ENOTEMPTY:    return S("Directory not empty");
    case EINVAL:       return S("Invalid argument");
    case EBADF:        return S("Bad file descriptor");
    case ENFILE:       return S("Too many open files in system");
    default:           return S("Unknown error");
    }
}

static Str os_selfexe(Os *os, Arena *a)
{
    (void)os;
    (void)a;
    return S("/usr/bin/trash-put");
}

static Str os_getcwd(Os *os, Arena *a)
{
    (void)os;
    (void)a;
    if (!v->cwd.len) {   // a deleted working directory
        v->errnum = ENOENT;
        return (Str){};
    }
    return v->cwd;
}

static u64 os_rand(Os *os)
{
    u64 x = os->rng;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    os->rng = x;
    return x;
}

// -- the sandbox --------------------------------------------------------------

// mkdir -p, mode 0755, ignoring entries that already exist.
static VNode *vmknode(Str path)
{
    Str dir, base;
    if (!vsplit(path, &dir, &base)) {
        return v->root;
    }
    VNode *p = vmknode(dir);
    VNode *n = vfindin(p, base);
    if (!n) {
        n = vnewnode(KIND_DIR, 0755, base);
        vattach(p, n);
        return n;
    }
    if (n->kind == KIND_LINK) {
        // mkdir -p descends through symlinked intermediates; fixture links
        // always carry absolute targets.
        CK(n->linkto.len && n->linkto.data[0] == '/');
        CK(vwalk(n->linkto, 1, &n, 0));
        CK(n->kind == KIND_DIR);
    }
    return n;
}

static void vmkdir(char *path)
{
    vmknode(import((u8 *)path));
}

static void vwriter(char *path, Str bytes, u32 mode)
{
    Str p = import((u8 *)path);
    Str dir, base;
    CK(vsplit(p, &dir, &base));
    VNode *parent = vmknode(dir);
    VNode *n = vfindin(parent, base);
    if (!n) {
        n = vnewnode(KIND_FILE, mode, base);
        vattach(parent, n);
    }
    n->kind = KIND_FILE;
    n->mode = mode;
    n->data = clone(&v->fs, bytes);
}

static void vwrite(char *path, char *bytes)
{
    vwriter(path, import((u8 *)bytes), 0644);
}

// Registers a mount point in both the /proc/self/mounts content (with the
// kernel's \040 escapes) and the dev table.
static void addmount(char *path, i64 dev)
{
    affirm(v->nmnts < 256);
    Str m = import((u8 *)path);
    Str esc = {};
    for (iz i = 0; i < m.len; i++) {
        if (m.data[i] == ' ') {
            esc = concat(&v->fs, esc, S("\\040"));
        } else {
            esc = concat(&v->fs, esc, takehead(cuthead(m, i), 1));
        }
    }
    v->mnt[v->nmnts].path = clone(&v->fs, m);
    v->mnt[v->nmnts].dev  = dev;
    v->nmnts++;
    char *line = vfmt("/dev/vd%lld %.*s ext4 0 0\n", (long long)dev,
                      (int)esc.len, (char *)esc.data);
    v->mounts = concat(&v->fs, v->mounts, import((u8 *)line));
    vwriter("/proc/self/mounts", v->mounts, 0444);
}

static void vsymlink(char *target, char *path)
{
    Str p = import((u8 *)path);
    Str dir, base;
    CK(vsplit(p, &dir, &base));
    VNode *parent = vmknode(dir);
    CK(!vfindin(parent, base));
    VNode *n = vnewnode(KIND_LINK, 0777, base);
    n->linkto = clone(&v->fs, import((u8 *)target));
    vattach(parent, n);
}

static void vfifo(char *path)
{
    Str p = import((u8 *)path);
    Str dir, base;
    CK(vsplit(p, &dir, &base));
    VNode *parent = vmknode(dir);
    CK(!vfindin(parent, base));
    vattach(parent, vnewnode(KIND_FIFO, 0644, base));
}

static void vchmod(char *path, u32 mode)
{
    VNode *n;
    CK(vwalk(import((u8 *)path), 0, &n, 0));
    n->mode = mode;
}

static b32 vexists(char *path)
{
    VNode *n;
    return vwalk(import((u8 *)path), 0, &n, 0);
}

static Str vread(char *path)
{
    VNode *n;
    CK(vwalk(import((u8 *)path), 1, &n, 0));
    return n->data;
}

static i32 namecmp(Str a, Str b)
{
    iz n = a.len < b.len ? a.len : b.len;
    i32 r = n ? __builtin_memcmp(a.data, b.data, (uz)n) : 0;
    return r ? r : (a.len < b.len ? -1 : a.len > b.len);
}

// The kids of a directory, sorted; at most 64.
static iz vlist(char *path, Str *out)
{
    VNode *n;
    CK(vwalk(import((u8 *)path), 1, &n, 0));
    CK(n->kind == KIND_DIR);
    iz k = 0;
    for (VNode *c = n->kids; c; c = c->next) {
        CK(k < 64);
        out[k++] = c->name;
    }
    for (iz i = 1; i < k; i++) {
        Str x = out[i];
        iz j = i;
        while (j > 0 && namecmp(out[j - 1], x) > 0) {
            out[j] = out[j - 1];
            j--;
        }
        out[j] = x;
    }
    return k;
}

// -- assertions on the filesystem ----------------------------------------------

static void ck_gone(char *path)
{
    if (vexists(path)) {
        vfail(__FILE__, __LINE__, "expected gone: %s", path);
    }
}

static void ck_present(char *path)
{
    if (!vexists(path)) {
        vfail(__FILE__, __LINE__, "expected present: %s", path);
    }
}

static void ck_mode(char *path, u32 want)
{
    VNode *n;
    CK(vwalk(import((u8 *)path), 0, &n, 0));
    if (n->mode != want) {
        vfail(__FILE__, __LINE__, "mode of %s is %o, want %o", path, n->mode,
              want);
    }
}

static void ck_kind(char *path, i32 want)
{
    VNode *n;
    CK(vwalk(import((u8 *)path), 0, &n, 0));
    CK_EQ(n->kind, want);
}

static Str vlinkto(char *path)
{
    VNode *n;
    CK(vwalk(import((u8 *)path), 0, &n, 0));
    CK_EQ(n->kind, KIND_LINK);
    return n->linkto;
}

static void ck_contents(char *path, char *want)
{
    CK_S(vread(path), import((u8 *)want));
}

static void ck_list(char *path, ...)
{
    Str got[64];
    iz ng = vlist(path, got);
    Str want[64];
    iz nw = 0;
    va_list ap;
    va_start(ap, path);
    for (;;) {
        char *a = va_arg(ap, char *);
        if (!a) {
            break;
        }
        CK(nw < 64);
        want[nw++] = import((u8 *)a);
    }
    va_end(ap);
    if (ng != nw) {
        vfail(__FILE__, __LINE__, "%s holds %lld entries, want %lld", path,
              (i64)ng, (i64)nw);
    }
    for (iz i = 0; i < ng; i++) {
        if (!equals(got[i], want[i])) {
            char g[256], w[256];
            vrepr(g, sizeof g, got[i]);
            vrepr(w, sizeof w, want[i]);
            vfail(__FILE__, __LINE__, "%s[%lld] is %s, want %s", path,
                  (i64)i, g, w);
        }
    }
}

// -- trash fixture builders ----------------------------------------------------

// Splits on newlines; a trailing newline does not make a final empty line.
static iz vlines(Str s, Str *out)
{
    iz k = 0;
    iz start = 0;
    for (iz i = 0; i <= s.len; i++) {
        if (i == s.len || s.data[i] == '\n') {
            if (i == s.len && i == start) {
                break;
            }
            CK(k < 32);
            out[k++] = takehead(cuthead(s, start), i - start);
            start = i + 1;
        }
    }
    return k;
}

static void mktrash(char *trash)
{
    vmkdir(vfmt("%s/info", trash));
    vmkdir(vfmt("%s/files", trash));
}

// Writes <trash>/info/<stem>.trashinfo; raw replaces the whole content.
static void winfo(char *trash, char *stem, char *path, char *date, Str raw)
{
    Str content;
    if (raw.data) {
        content = raw;
    } else {
        CK(path);
        content = import((u8 *)vfmt("[Trash Info]\nPath=%s\n", path));
        if (date) {
            content = concat(&v->fs, content,
                             import((u8 *)vfmt("DeletionDate=%s\n", date)));
        }
    }
    vwriter(vfmt("%s/info/%s.trashinfo", trash, stem), content, 0644);
}

static void wbackup(char *trash, char *stem, char *content)
{
    vwriter(vfmt("%s/files/%s", trash, stem), import((u8 *)content), 0644);
}

static void make_trashed(char *trash, char *stem, char *path, char *date)
{
    winfo(trash, stem, path, date, (Str){});
    wbackup(trash, stem, "data");
}

// A volume trash dir under /vol: method 1 is /vol/.Trash/<uid>, method 2
// is /vol/.Trash-<uid> (spec 4.2/4.3).
static char *volume_trash(i32 method, i32 uid)
{
    char *t = method == 1 ? vfmt("/vol/.Trash/%d", uid)
                          : vfmt("/vol/.Trash-%d", uid);
    mktrash(t);
    return t;
}

// -- environment and console helpers -------------------------------------------

static void envset(char *name, char *val)
{
    Str n = import((u8 *)name);
    Str x = clone(&v->fs, import((u8 *)val));
    for (i32 i = 0; i < v->nenv; i++) {
        if (equals(v->env[i][0], n)) {
            v->env[i][1] = x;
            return;
        }
    }
    affirm(v->nenv < 24);
    v->env[v->nenv][0] = clone(&v->fs, n);
    v->env[v->nenv][1] = x;
    v->nenv++;
}

static void envdel(char *name)
{
    Str n = import((u8 *)name);
    for (i32 i = 0; i < v->nenv; i++) {
        if (equals(v->env[i][0], n)) {
            for (i32 j = i + 1; j < v->nenv; j++) {
                v->env[j - 1][0] = v->env[j][0];
                v->env[j - 1][1] = v->env[j][1];
            }
            v->nenv--;
            return;
        }
    }
}

static void setstdin(char *bytes)
{
    v->stdinbuf = import((u8 *)bytes);
    v->stdinpos = 0;
}

static void setcwd(char *cwd)
{
    v->cwd = import((u8 *)cwd);
}

// -- running one command ---------------------------------------------------------

typedef struct {
    i32 exit;
    Str out;
    Str err;
} Res;

static Res vruna(Str persona, iz argc, Str *args)
{
    v->out = (Str){};
    v->err = (Str){};
    v->stdinpos = 0;
    v->status = -1;
    for (i32 i = 0; i < 24; i++) {
        v->fd[i].n = 0;
    }
    Os os = {};
    os.name = persona;
    os.rng  = 0x9e3779b97f4a7c15ull;
    Arena perm = *gperm;
    Arena scratch = *gscratch;
    Ctx c = {};
    c.os      = &os;
    c.perm    = &perm;
    c.scratch = scratch;
    c.prog    = basename(persona);
    c.out     = newoutput(&perm, &os, 1);
    c.err     = newoutput(&perm, &os, 2);
    Str *argv = new(&perm, argc + 1, Str);
    argv[0] = persona;
    for (iz i = 0; i < argc; i++) {
        argv[i + 1] = args[i];
    }
    if (!setjmp(v->exitjmp)) {
        dispatch(&c, argc + 1, argv);
    }
    Res r = {v->status, v->out, v->err};
    return r;
}

static Res vrun(char *persona, ...)
{
    Str args[24];
    iz n = 0;
    va_list ap;
    va_start(ap, persona);
    for (;;) {
        char *a = va_arg(ap, char *);
        if (!a) {
            break;
        }
        CK(n < 24);
        args[n++] = import((u8 *)a);
    }
    va_end(ap);
    return vruna(import((u8 *)persona), n, args);
}

#define RUN(persona, ...) vrun(persona __VA_OPT__(,) __VA_ARGS__, (char *)0)
#define tput(...)      RUN("trash-put", __VA_ARGS__)
#define ttrash(...)    RUN("trash", __VA_ARGS__)
#define tlist(...)     RUN("trash-list", __VA_ARGS__)
#define trestore(...)  RUN("trash-restore", __VA_ARGS__)
#define tempty(...)    RUN("trash-empty", __VA_ARGS__)
#define trm(...)       RUN("trash-rm", __VA_ARGS__)

// -- the sandbox fresh per test ---------------------------------------------------

static Os    vosos;
static Vos   vosobj;
static Arena permspace;
static Arena scratchspace;

static void newsandbox(void)
{
    v->uid    = VUID;
    v->now    = (DateTime){2026, 6, 1, 12, 0, 0};
    v->cwd    = S("/work");
    v->mounts = S("/dev/vda / ext4 0 0\n");
    v->root   = vnewnode(KIND_DIR, 0755, S(""));
    vwriter("/proc/self/mounts", v->mounts, 0444);
    vmkdir("/home");
    vmkdir("/xdg");
    vmkdir("/work");
    vmkdir("/vol");
    envset("HOME", "/home");
    envset("XDG_DATA_HOME", "/xdg");
    envset("TRASH_VOLUMES", "/vol");
}

// -- the suite ----------------------------------------------------------------------
//
// One X-macro line per test, named after its trash_test.py counterpart.  The
// trash-rm class names carry an rm_ prefix because both suites have same-named
// tests in different classes (e.g. non_utf8_trashinfo_is_skipped).

#define TESTS(X) \
    X(put_version_is_bare) \
    X(other_versions_are_prefixed_with_program_name) \
    X(trash_version_matches_put) \
    X(put_help) \
    X(put_help_lists_all_commands) \
    X(trash_help_uses_invoked_name) \
    X(list_help) \
    X(empty_help) \
    X(restore_help) \
    X(unknown_option_exits_2) \
    X(ambiguous_abbreviation_exits_2) \
    X(unambiguous_abbreviation_works) \
    X(positional_arguments_are_rejected_by_list) \
    X(rm_usage_when_no_args) \
    X(rm_has_no_help_or_version) \
    X(version_and_help_go_to_stdout) \
    X(trashes_file) \
    X(trashinfo_exact_format) \
    X(deletion_date_is_recent_local_time) \
    X(trashes_directory_without_recursive_flag) \
    X(trashes_read_only_directory) \
    X(trashes_symlink_itself_not_target) \
    X(trashes_dangling_symlink) \
    X(trashes_fifo) \
    X(trailing_slash_is_stripped) \
    X(space_is_percent_encoded_in_path) \
    X(invalid_utf8_byte_is_percent_encoded) \
    X(utf8_name_round_trips) \
    X(records_parent_realpath) \
    X(collision_suffixes) \
    X(info_file_mode_is_0600) \
    X(trash_dirs_created_0700) \
    X(trash_is_put_with_its_own_name) \
    X(options_before_and_after_the_files) \
    X(option_between_files_is_rejected) \
    X(dash_dash_separator) \
    X(option_shaped_file_via_dot_slash) \
    X(absolute_path_argument) \
    X(relative_xdg_data_home_used_verbatim) \
    X(home_falls_back_to_home_variable) \
    X(no_arguments) \
    X(nonexistent_file) \
    X(force_ignores_nonexistent) \
    X(mixed_success_and_failure_exits_74) \
    X(dot_argument_refused) \
    X(dotdot_argument_refused) \
    X(option_shaped_existing_file_refused) \
    X(interactive_yes_trashes) \
    X(interactive_no_keeps) \
    X(interactive_anything_but_y_means_no) \
    X(interactive_prompt_describes_the_file) \
    X(interactive_dangling_symlink_not_prompted) \
    X(interactive_eof_crashes) \
    X(interactive_force_last_one_wins) \
    X(verbose_success_message) \
    X(verbose_home_prefix_shrinks_to_tilde) \
    X(verbose_shrink_can_be_disabled) \
    X(verbose_twice_shows_debug_lines) \
    X(undeletable_original_refused) \
    X(all_candidates_failed_report) \
    X(home_fallback_requires_environment) \
    X(fake_uid_changes_candidate_paths) \
    X(trash_dir_created_if_missing) \
    X(trash_dir_with_equals_sign) \
    X(trash_dir_that_is_a_file_fails) \
    X(trash_dir_with_symlinked_info_refused) \
    X(same_volume_gate_with_custom_trash_dir) \
    X(accepted_but_ignored_rm_flags) \
    X(empty_trash_is_silent) \
    X(listing_format) \
    X(duplicate_paths_are_all_listed) \
    X(missing_deletion_date_sentinel) \
    X(invalid_deletion_date_sentinel) \
    X(timezone_suffix_makes_date_invalid) \
    X(missing_path_is_a_parse_error) \
    X(non_trashinfo_entries_are_ignored) \
    X(orphans_are_not_listed) \
    X(unreadable_info_file_is_reported) \
    X(non_utf8_trashinfo_is_skipped) \
    X(hidden_files_option) \
    X(hidden_size_option) \
    X(hidden_size_option_without_backup_crashes) \
    X(custom_trash_dir_used_verbatim) \
    X(custom_trash_dir_does_not_exist_is_silent) \
    X(multiple_custom_trash_dirs) \
    X(all_users_runs) \
    X(all_users_ignores_trash_dir) \
    X(volumes_come_from_trash_volumes) \
    X(trash_dirs_lists_home_then_volume) \
    X(method1_requires_sticky_parent) \
    X(method1_with_sticky_parent_is_listed) \
    X(sticky_bit_is_checked_before_symlink) \
    X(symlink_parent_is_reported) \
    X(method2_needs_only_to_be_a_directory) \
    X(method1_missing_is_silent) \
    X(main_listing_scan_order_home_then_volume) \
    X(volume_entry_path_is_joined_with_volume) \
    X(main_listing_reports_skipped_dirs_on_stderr) \
    X(paths_are_quoted_on_a_terminal) \
    X(paths_are_raw_when_piped) \
    X(trash_raw_output_disables_quoting) \
    X(zero_candidates_message) \
    X(listing_and_prompt_format) \
    X(restore_by_index) \
    X(empty_reply_restores_nothing) \
    X(eof_at_prompt) \
    X(invalid_index) \
    X(out_of_range_index) \
    X(open_interval_rejected) \
    X(range_is_inclusive_and_comma_list_works) \
    X(overwrite_refusal) \
    X(overwrite_flag_replaces_file) \
    X(directory_is_never_overwritten) \
    X(missing_parent_directories_are_created) \
    X(restore_directory) \
    X(path_arg_selects_subtree) \
    X(path_arg_relative_dot) \
    X(path_arg_absolute) \
    X(slash_path_matches_everything) \
    X(prefix_must_not_match_partial_names) \
    X(sort_date_ascending) \
    X(sort_path) \
    X(sort_none_keeps_scan_order) \
    X(missing_date_prints_none) \
    X(missing_date_sorts_last) \
    X(percent_encoded_path_is_decoded) \
    X(batch_restores_what_it_can) \
    X(no_candidates_with_path_arg_names_the_path) \
    X(parsed_date_shown_without_timezone_conversion) \
    X(world_writable_files_dir_distrusted) \
    X(world_writable_info_dir_distrusted) \
    X(symlinked_info_dir_distrusted) \
    X(symlinked_files_dir_distrusted) \
    X(custom_trash_dir_bypasses_trust_checks) \
    X(empties_silently) \
    X(removes_backup_before_info) \
    X(non_trashinfo_info_entries_are_kept) \
    X(orphans_are_removed) \
    X(no_trash_dirs_is_silent) \
    X(dry_run_lines_and_order) \
    X(dry_run_deletes_nothing) \
    X(verbose_prints_removing_lines) \
    X(days_boundary_is_strict) \
    X(days_keeps_files_with_missing_date) \
    X(without_days_missing_date_is_removed) \
    X(days_invalid_int) \
    X(days_extra_positional) \
    X(days_negative_empties_everything) \
    X(huge_days_is_a_usage_error) \
    X(piped_stdin_means_non_interactive) \
    X(interactive_prompt_and_decline) \
    X(interactive_accepts_anything_starting_with_y) \
    X(explicit_i_prompts_even_with_piped_stdin) \
    X(interactive_eof_crashes_empty) \
    X(trash_dir_selects_only_that_dir) \
    X(volume_trash_method2_is_emptied) \
    X(invalid_trash_date_warns_and_keeps) \
    X(trash_date_in_future_empties) \
    X(print_time_with_trash_date) \
    X(print_time_without_trash_date) \
    X(unremovable_file_is_reported_and_skipped) \
    X(rm_exact_basename) \
    X(rm_glob_pattern) \
    X(rm_absolute_pattern_matches_full_original_location) \
    X(rm_absolute_glob_crosses_slashes) \
    X(rm_relative_pattern_with_slash_never_matches) \
    X(rm_matching_is_case_sensitive) \
    X(rm_extra_arguments_are_ignored) \
    X(rm_no_match_is_silent_success) \
    X(rm_empty_pattern_matches_nothing) \
    X(rm_unparseable_path_is_reported_and_skipped) \
    X(rm_non_utf8_trashinfo_is_skipped) \
    X(rm_orphans_are_untouched) \
    X(rm_removes_volume_trash_entries) \
    X(rm_dangling_backup_copy_is_removed) \
    X(restore_volume_relative_path) \
    X(empty_xdg_data_home_is_unset) \
    X(all_users_skips_unreadable_homes) \
    X(mounts_octal_escapes) \
    X(rename_fixup_restores_mode) \
    X(home_fallback_candidate) \
    X(rm_removes_nested_directory_completely) \
    X(empty_removes_nested_directory_completely) \
    X(put_through_symlink_with_deep_target) \
    X(put_trash_dir_through_deep_symlink) \
    X(volumes_beyond_sixty_four_are_scanned) \
    X(restore_in_deleted_cwd_fails_cleanly) \
    X(put_retries_next_suffix_when_info_exists) \
    X(put_hard_info_error_is_reported) \
    X(put_move_error_reports_the_copy_failure) \
    X(put_across_devices_copies_and_removes) \
    X(put_vv_shows_each_candidates_volume) \
    X(put_root_volume_paths_have_no_double_slash) \
    X(put_empty_trash_dir_and_force_volume_are_unset) \
    X(put_interactive_prompt_precedes_permission_check) \
    X(put_message_escapes_invalid_utf8) \
    X(put_parents_of_trash_dir_follow_the_umask) \
    X(put_long_name_retries_with_first_suffix) \
    X(put_vv_logs_failed_info_attempts) \
    X(list_trash_dir_uses_its_volume) \
    X(restore_trash_dir_uses_its_volume) \
    X(restore_home_trash_on_a_mount_uses_the_mount_point) \
    X(restore_sort_path_uses_location_plus_date) \
    X(restore_sort_is_stable_over_many_entries) \
    X(restore_normalizes_path) \
    X(restore_volume_with_trailing_slash) \
    X(list_size_and_files_are_independent) \
    X(list_size_of_dangling_backup_is_zero) \
    X(list_tty_quoting_follows_upstream) \
    X(restore_overwrite_refuses_symlink_to_directory) \
    X(restore_prompt_grammar_errors) \
    X(restore_prompt_restores_in_order_asked_without_repeats) \
    X(restore_errors_have_no_prefix) \
    X(restore_prompt_carriage_return_is_not_empty) \
    X(restore_reports_undecodable_trashinfo_like_python) \
    X(restore_listing_escapes_invalid_bytes) \
    X(restore_reports_unreadable_trashinfo_like_python) \
    X(restore_overwrite_across_devices) \
    X(rm_star_pattern_matches_names_containing_a_star) \
    X(rm_matches_characters_not_bytes) \
    X(rm_reports_removal_failures_and_exits_1) \
    X(empty_rm_and_list_skip_a_trash_dir_behind_an_unreadable_parent) \
    X(empty_warns_about_a_bad_trash_date_per_trashinfo) \
    X(empty_print_time_warns_about_a_bad_trash_date) \
    X(deletion_dates_follow_strptime) \
    X(days_follows_python_int) \
    X(trash_date_follows_strptime_and_is_not_trimmed) \
    X(trashinfo_lines_end_at_any_newline_style) \
    X(restore_refuses_a_path_with_an_embedded_nul) \
    X(argparse_output_matches_python) \
    X(argparse_option_value_cannot_look_like_an_option) \
    X(argparse_clusters_and_explicit_arguments) \
    X(argparse_negative_numbers_and_separator) \
    X(argparse_errors_come_in_argparse_order) \
    X(argparse_width_follows_columns_then_the_terminal) \
    X(smoke_list_shows_entry)

#define X(n) static void test_##n(void);
TESTS(X)
#undef X

typedef struct {
    Str  name;
    void (*fn)(void);
} Test;

static const Test tests[] = {
#define X(n) {S(#n), test_##n},
TESTS(X)
#undef X
};

// -- the tests ----------------------------------------------------------------------

// Any command can read /proc/self/mounts through the virtual filesystem.
static void test_smoke_list_shows_entry(void)
{
    mktrash("/trash");
    make_trashed("/trash", "s", "/work/w", "2001-02-03T04:05:06");
    Res r = tlist("--trash-dir", "/trash");
    CK_EQ(r.exit, 0);
    CK_S(r.out, S("2001-02-03 04:05:06 /work/w\n"));
}

// -- Section 2: conventions shared by all commands (spec 2) --------------------

static void test_put_version_is_bare(void)
{
    Res r = tput("--version");
    CK_EQ(r.exit, 0);
    CK_S(r.err, S(""));
    CK_S(r.out, S("0.26.9.29\n"));
}

static void test_other_versions_are_prefixed_with_program_name(void)
{
    Res p = tput("--version");
    CK_EQ(p.exit, 0);
    char *cmds[] = {"trash-list", "trash-empty", "trash-restore"};
    for (uz i = 0; i < countof(cmds); i++) {
        Res r = RUN(cmds[i], "--version");
        CK_EQ(r.exit, 0);
        Str want = concat(&v->fs, vcat(cmds[i], " "), p.out);
        CK_S(r.out, want);
        CK_S(r.err, S(""));
    }
}

static void test_trash_version_matches_put(void)
{
    CK_S(tput("--version").out, ttrash("--version").out);
}

static void test_put_help(void)
{
    Res r = tput("--help");
    CK_EQ(r.exit, 0);
    CK_S(r.err, S(""));
    CK_STARTS(r.out, "usage: trash-put [OPTION]... FILE...");
    CK_HAS(r.out, "Put files in trash");
    char *opts[] = {"-f, --force", "-i, --interactive", "--trash-dir",
                    "-v, --verbose", "--version", "-d, --directory",
                    "-r, -R, --recursive"};
    for (uz i = 0; i < countof(opts); i++) {
        CK_HAS_C(r.out, opts[i]);
    }
}

static void test_put_help_lists_all_commands(void)
{
    Res r = tput("--help");
    CK_HAS(r.out, "all trash-cli commands:");
    CK_HAS(r.out, "trash -- -foo");
}

static void test_trash_help_uses_invoked_name(void)
{
    Res r = ttrash("--help");
    CK_EQ(r.exit, 0);
    CK_STARTS(r.out, "usage: trash [OPTION]... FILE...");
}

static void test_list_help(void)
{
    Res r = tlist("--help");
    CK_EQ(r.exit, 0);
    CK_S(r.err, S(""));
    CK_STARTS(r.out, "usage: trash-list");
    char *opts[] = {"--volumes", "--trash-dirs", "--trash-dir", "--all-users",
                    "--version"};
    for (uz i = 0; i < countof(opts); i++) {
        CK_HAS_C(r.out, opts[i]);
    }
    CK_HAS(r.out, "List trashed files");
}

static void test_empty_help(void)
{
    Res r = tempty("--help");
    CK_EQ(r.exit, 0);
    CK_S(r.err, S(""));
    CK_STARTS(r.out, "usage: trash-empty");
    char *opts[] = {"-v, --verbose", "--trash-dir", "--all-users",
                    "-i, --interactive", "-f", "--dry-run"};
    for (uz i = 0; i < countof(opts); i++) {
        CK_HAS_C(r.out, opts[i]);
    }
    CK_HAS(r.out, "Purge trashed files.");
    CK_HAS(r.out, "[days]");
}

static void test_restore_help(void)
{
    Res r = trestore("--help");
    CK_EQ(r.exit, 0);
    CK_S(r.err, S(""));
    CK_STARTS(r.out, "usage: trash-restore");
    CK_HAS(r.out, "--sort {date,path,none}");
    CK_HAS(r.out, "--overwrite");
    CK_HAS(r.out, "[path]");
    CK_NOHAS(r.out, "--trash-dir");   // functional but hidden (spec 7.1, 11.5)
}

static void test_unknown_option_exits_2(void)
{
    Res r = tput("--no-such-option");
    CK_EQ(r.exit, 2);
    CK_HAS(r.err, "unrecognized arguments: --no-such-option");
    CK_HAS(r.err, "usage:");
    CK_S(r.out, S(""));
}

static void test_ambiguous_abbreviation_exits_2(void)
{
    Res r = tlist("--tr");
    CK_EQ(r.exit, 2);
    CK_HAS(r.err, "ambiguous option: --tr");
}

static void test_unambiguous_abbreviation_works(void)
{
    Res r = tput("--vers");
    CK_EQ(r.exit, 0);
    CK_S(r.out, tput("--version").out);
}

static void test_positional_arguments_are_rejected_by_list(void)
{
    Res r = tlist("some-arg");
    CK_EQ(r.exit, 2);
    CK_HAS(r.err, "unrecognized arguments: some-arg");
}

static void test_rm_usage_when_no_args(void)
{
    Res r = trm();
    CK_EQ(r.exit, 8);
    CK_S(r.out, S(""));
    CK_S(r.err, S("Usage:\n"
                  "    trash-rm PATTERN\n"
                  "\n"
                  "Please specify PATTERN.\n"
                  "trash-rm uses fnmatch.fnmatchcase to match patterns, see "
                  "https://docs.python.org/3/library/fnmatch.html for more "
                  "details.\n"));
}

static void test_rm_has_no_help_or_version(void)
{
    char *opts[] = {"--help", "--version"};
    for (uz i = 0; i < countof(opts); i++) {
        Res r = trm(opts[i]);
        CK_EQ(r.exit, 0);
        CK_S(r.out, S(""));
        CK_S(r.err, S(""));
    }
}

static void test_version_and_help_go_to_stdout(void)
{
    Res r = tlist("--version");
    CK_S(r.err, S(""));
    CK(r.out.len > 0);
    r = tlist("--help");
    CK_S(r.err, S(""));
    CK(r.out.len > 0);
}

// -- Sections 5 + 3.2: trash-put basics (spec 5, 3.2) ----------------------------

static void test_trashes_file(void)
{
    vwrite("/work/foo.txt", "hello");
    Res r = tput("foo.txt");
    CK_EQ(r.exit, 0);
    CK_S(r.out, S(""));
    CK_S(r.err, S(""));
    ck_gone("/work/foo.txt");
    ck_list("/xdg/Trash/files", "foo.txt", (char *)0);
    ck_list("/xdg/Trash/info", "foo.txt.trashinfo", (char *)0);
}

static void test_trashinfo_exact_format(void)
{
    // spec 3.2: exact three-line format, absolute Path=; the virtual clock
    // makes the date deterministic.
    vwrite("/work/foo.txt", "x");
    CK_EQ(tput("foo.txt").exit, 0);
    ck_contents("/xdg/Trash/info/foo.txt.trashinfo",
                "[Trash Info]\n"
                "Path=/work/foo.txt\n"
                "DeletionDate=2026-06-01T12:00:00\n");
}

static void test_deletion_date_is_recent_local_time(void)
{
    // spec 3.2: DeletionDate is the (virtual) local time of the call.
    vwrite("/work/foo.txt", "x");
    CK_EQ(tput("foo.txt").exit, 0);
    CK_HAS(vread("/xdg/Trash/info/foo.txt.trashinfo"),
           "DeletionDate=2026-06-01T12:00:00\n");
}

static void test_trashes_directory_without_recursive_flag(void)
{
    // spec 5.2: -r is unnecessary, directories go recursively.
    vmkdir("/work/dir");
    vwrite("/work/dir/inner.txt", "in");
    Res r = tput("dir");
    CK_EQ(r.exit, 0);
    ck_gone("/work/dir");
    ck_present("/xdg/Trash/files/dir/inner.txt");
    ck_present("/xdg/Trash/info/dir.trashinfo");
}

static void test_trashes_read_only_directory(void)
{
    // spec 5.6: only removing from the parent must be allowed.
    vmkdir("/work/rodir");
    vchmod("/work/rodir", 0500);
    Res r = tput("rodir");
    CK_EQ(r.exit, 0);
    ck_gone("/work/rodir");
}

static void test_trashes_symlink_itself_not_target(void)
{
    // spec 5.6: the link is moved, never its target.
    vwrite("/work/target.txt", "T");
    vsymlink("target.txt", "/work/link");
    Res r = tput("link");
    CK_EQ(r.exit, 0);
    ck_present("/work/target.txt");
    ck_kind("/xdg/Trash/files/link", KIND_LINK);
    CK_S(vlinkto("/xdg/Trash/files/link"), S("target.txt"));
}

static void test_trashes_dangling_symlink(void)
{
    vsymlink("/work/no-such-target", "/work/dangling");
    Res r = tput("dangling");
    CK_EQ(r.exit, 0);
    ck_gone("/work/dangling");
    ck_kind("/xdg/Trash/files/dangling", KIND_LINK);
}

static void test_trashes_fifo(void)
{
    // spec 5.4: special files are trashed ("entry").
    vfifo("/work/fifo");
    Res r = tput("fifo");
    CK_EQ(r.exit, 0);
    ck_gone("/work/fifo");
    ck_kind("/xdg/Trash/files/fifo", KIND_FIFO);
}

static void test_trailing_slash_is_stripped(void)
{
    // spec 5.3: `dir/` trashes `dir` (info name is `dir`).
    vmkdir("/work/dir");
    Res r = tput("dir/");
    CK_EQ(r.exit, 0);
    ck_gone("/work/dir");
    ck_present("/xdg/Trash/info/dir.trashinfo");
    ck_present("/xdg/Trash/files/dir");
}

static void test_space_is_percent_encoded_in_path(void)
{
    // spec 3.2: space becomes %20; files/ keeps the raw name.
    vwrite("/work/file with space.txt", "x");
    CK_EQ(tput("file with space.txt").exit, 0);
    CK_HAS(vread("/xdg/Trash/info/file with space.txt.trashinfo"),
           "Path=/work/file%20with%20space.txt\n");
    ck_present("/xdg/Trash/files/file with space.txt");
}

static void test_invalid_utf8_byte_is_percent_encoded(void)
{
    // spec 3.2: raw 0xFF byte becomes %FF.
    vwriter("/work/we\xffird", S("x"), 0644);
    Res r = tput("we\xffird");
    CK_EQ(r.exit, 0);
    CK_HAS(vread("/xdg/Trash/info/we\xffird.trashinfo"),
           "Path=/work/we%FFird\n");
}

static void test_utf8_name_round_trips(void)
{
    vwrite("/work/caf\xc3\xa9.txt", "caf\xc3\xa9 content");
    Res r = tput("caf\xc3\xa9.txt");
    CK_EQ(r.exit, 0);
    CK_HAS(vread("/xdg/Trash/info/caf\xc3\xa9.txt.trashinfo"),
           "Path=/work/caf%C3%A9.txt\n");
    r = tlist();
    CK_EQ(r.exit, 0);
    CK_HAS(r.out, "/work/caf\xc3\xa9.txt");
}

static void test_records_parent_realpath(void)
{
    // spec 3.2: the parent of Path= is the parent's realpath.
    vmkdir("/work/realdir");
    vwrite("/work/realdir/f.txt", "x");
    vsymlink("/work/realdir", "/work/linkdir");
    Res r = tput("linkdir/f.txt");
    CK_EQ(r.exit, 0);
    CK_HAS(vread("/xdg/Trash/info/f.txt.trashinfo"), "Path=/work/realdir/f.txt\n");
}

static void test_collision_suffixes(void)
{
    // spec 3.2: foo, foo_1, foo_2.
    for (i32 i = 0; i < 3; i++) {
        vwrite("/work/dup", vfmt("content %d", i));
        CK_EQ(tput("dup").exit, 0);
    }
    ck_list("/xdg/Trash/files", "dup", "dup_1", "dup_2", (char *)0);
    ck_list("/xdg/Trash/info", "dup.trashinfo", "dup_1.trashinfo",
            "dup_2.trashinfo", (char *)0);
}

static void test_info_file_mode_is_0600(void)
{
    vwrite("/work/foo.txt", "x");
    tput("foo.txt");
    ck_mode("/xdg/Trash/info/foo.txt.trashinfo", 0600);
}

static void test_trash_dirs_created_0700(void)
{
    vwrite("/work/foo.txt", "x");
    tput("foo.txt");
    ck_mode("/xdg/Trash", 0700);
    ck_mode("/xdg/Trash/files", 0700);
    ck_mode("/xdg/Trash/info", 0700);
}

static void test_trash_is_put_with_its_own_name(void)
{
    // spec 2.1: the program name in messages is argv[0] basename.
    vwrite("/work/tf", "x");
    Res r = ttrash("-v", "tf");
    CK_EQ(r.exit, 0);
    CK_STARTS(r.err, "trash: 'tf' trashed in ");
}

static void test_options_before_and_after_the_files(void)
{
    // spec 5.3: options may precede or follow the file list.
    char *names[] = {"f1", "f2", "f3"};
    for (uz i = 0; i < countof(names); i++) {
        vwrite(vfmt("/work/%s", names[i]), "x");
    }
    Res r = tput("-v", "f1", "f2", "f3", "--verbose");
    CK_EQ(r.exit, 0);
    for (uz i = 0; i < countof(names); i++) {
        ck_gone(vfmt("/work/%s", names[i]));
    }
}

static void test_option_between_files_is_rejected(void)
{
    // spec 5.3: an option between file arguments makes the rest
    // unrecognized, exit 2.
    vwrite("/work/f1", "x");
    vwrite("/work/f2", "x");
    Res r = tput("f1", "-v", "f2");
    CK_EQ(r.exit, 2);
    CK_HAS(r.err, "unrecognized arguments: f2");
    ck_present("/work/f1");
    ck_present("/work/f2");
}

static void test_dash_dash_separator(void)
{
    // spec 5.3: after --, option-shaped names are files.
    vwrite("/work/--weird", "x");
    Res r = tput("--", "--weird");
    CK_EQ(r.exit, 0);
    ck_gone("/work/--weird");
    ck_present("/xdg/Trash/files/--weird");
}

static void test_option_shaped_file_via_dot_slash(void)
{
    vwrite("/work/--weird", "x");
    Res r = tput("./--weird");
    CK_EQ(r.exit, 0);
    ck_gone("/work/--weird");
}

static void test_absolute_path_argument(void)
{
    vwrite("/work/abs.txt", "x");
    Res r = tput("/work/abs.txt");
    CK_EQ(r.exit, 0);
    ck_gone("/work/abs.txt");
}

static void test_relative_xdg_data_home_used_verbatim(void)
{
    // spec 4.1: a relative XDG_DATA_HOME is used as-is, resolved against
    // the current directory.
    vwrite("/work/rel.txt", "x");
    envset("XDG_DATA_HOME", "rel-data");
    Res r = tput("rel.txt");
    CK_EQ(r.exit, 0);
    ck_present("/work/rel-data/Trash/files/rel.txt");
    r = tlist();
    CK_EQ(r.exit, 0);
    CK_HAS(r.out, "/work/rel.txt");
}

static void test_home_falls_back_to_home_variable(void)
{
    // spec 4.1: without XDG_DATA_HOME, $HOME/.local/share/Trash.
    vwrite("/work/homey.txt", "x");
    envdel("XDG_DATA_HOME");
    Res r = tput("homey.txt");
    CK_EQ(r.exit, 0);
    ck_present("/home/.local/share/Trash/files/homey.txt");
    r = tlist();
    CK_EQ(r.exit, 0);
    CK_HAS(r.out, "/work/homey.txt");
}

// -- Sections 5.3-5.9: errors, interactive mode, verbose output -----------------

static void test_no_arguments(void)
{
    Res r = tput();
    CK_EQ(r.exit, 2);
    CK_S(r.out, S(""));
    CK_HAS(r.err, "usage: trash-put [OPTION]... FILE...");
    CK_HAS(r.err, "trash-put: error: Please specify the files to trash.");
}

static void test_nonexistent_file(void)
{
    // spec 5.4 step 3: exit 74, exact message.
    Res r = tput("no-such-file");
    CK_EQ(r.exit, 74);
    CK_S(r.err, S("trash-put: cannot trash non existent 'no-such-file'\n"));
    CK_S(r.out, S(""));
}

static void test_force_ignores_nonexistent(void)
{
    // spec 5.2: -f makes missing files silent successes.
    Res r = tput("-f", "no-such-file", "also-missing");
    CK_EQ(r.exit, 0);
    CK_S(r.out, S(""));
    CK_S(r.err, S(""));
}

static void test_mixed_success_and_failure_exits_74(void)
{
    // spec 5.9: any failure means exit 74, others still trashed.
    vwrite("/work/real.txt", "x");
    Res r = tput("real.txt", "missing.txt");
    CK_EQ(r.exit, 74);
    ck_gone("/work/real.txt");
    CK_HAS(r.err, "cannot trash non existent 'missing.txt'");
}

static void test_dot_argument_refused(void)
{
    // spec 5.4 step 2: dot entries refused, exit 74.
    Res r = tput(".");
    CK_EQ(r.exit, 74);
    CK_HAS(r.err, "trash-put: cannot trash directory '.'");
    ck_present("/work");   // nothing was trashed
}

static void test_dotdot_argument_refused(void)
{
    Res r = tput("..");
    CK_EQ(r.exit, 74);
    CK_HAS(r.err, "trash-put: cannot trash directory '..'");
}

static void test_option_shaped_existing_file_refused(void)
{
    // spec 5.3: existing files that look like options are refused before
    // argparse (exit 2), suggesting -- or ./.
    vwrite("/work/--foo", "x");
    Res r = tput("--foo");
    CK_EQ(r.exit, 2);
    CK_HAS(r.err, "refusing to treat existing file --foo as an option");
    CK_HAS(r.err, "(use './--foo' or a '--' separator)");
    ck_present("/work/--foo");
}

static void test_interactive_yes_trashes(void)
{
    vwrite("/work/ifile", "x");
    setstdin("Y\n");
    Res r = tput("-i", "ifile");
    CK_EQ(r.exit, 0);
    ck_gone("/work/ifile");
}

static void test_interactive_no_keeps(void)
{
    vwrite("/work/ifile", "x");
    setstdin("n\n");
    Res r = tput("-i", "ifile");
    CK_EQ(r.exit, 0);
    ck_present("/work/ifile");
}

static void test_interactive_anything_but_y_means_no(void)
{
    char *answers[] = {"\n", "no\n", "maybe\n"};
    for (uz i = 0; i < countof(answers); i++) {
        vwrite("/work/ifile", "x");
        setstdin(answers[i]);
        Res r = tput("-i", "ifile");
        CK_EQ(r.exit, 0);
        ck_present("/work/ifile");
    }
}

static void test_interactive_prompt_describes_the_file(void)
{
    // spec 5.7: prompt format and describer vocabulary.
    vwrite("/work/empty-file", "");
    Res r = tput("-i", "empty-file");
    setstdin("n\n");
    r = tput("-i", "empty-file");
    CK_HAS(r.out, "trash-put: trash regular empty file 'empty-file'? ");
    vwrite("/work/regular.txt", "not empty");
    setstdin("n\n");
    r = tput("-i", "regular.txt");
    CK_HAS(r.out, "trash-put: trash regular file 'regular.txt'? ");
    vmkdir("/work/adir");
    setstdin("n\n");
    r = tput("-i", "adir");
    CK_HAS(r.out, "trash-put: trash directory 'adir'? ");
    vwrite("/work/target.txt", "x");
    vsymlink("target.txt", "/work/alink");
    setstdin("n\n");
    r = tput("-i", "alink");
    CK_HAS(r.out, "trash-put: trash symbolic link 'alink'? ");
}

static void test_interactive_dangling_symlink_not_prompted(void)
{
    // spec 5.4 step 5: F_OK fails for dangling symlinks.
    vsymlink("no-such-target", "/work/dangling");
    setstdin("n\n");
    Res r = tput("-i", "dangling");
    CK_EQ(r.exit, 0);
    CK_S(r.out, S(""));
    ck_gone("/work/dangling");
}

static void test_interactive_eof_crashes(void)
{
    // spec 5.9: EOF under -i is an unhandled exception (exit 1).
    vwrite("/work/ifile", "x");
    setstdin("");
    Res r = tput("-i", "ifile");
    CK_EQ(r.exit, 1);
}

static void test_interactive_force_last_one_wins(void)
{
    // spec 5.2: -f and -i share a variable; rightmost wins.
    vwrite("/work/ifile", "x");
    setstdin("n\n");
    Res r = tput("-f", "-i", "ifile");
    CK_EQ(r.exit, 0);
    ck_present("/work/ifile");   // -i won: asked, said no
    r = tput("-i", "-f", "ifile");
    CK_EQ(r.exit, 0);
    ck_gone("/work/ifile");      // -f won: no prompt
}

static void test_verbose_success_message(void)
{
    // spec 5.8: "'<path>' trashed in <trash-dir>" on stderr.
    vwrite("/work/vfile.txt", "x");
    Res r = tput("-v", "vfile.txt");
    CK_EQ(r.exit, 0);
    CK_S(r.err, S("trash-put: 'vfile.txt' trashed in /xdg/Trash\n"));
}

static void test_verbose_home_prefix_shrinks_to_tilde(void)
{
    // spec 5.8: trash dirs under HOME are shown as ~/...
    vwrite("/work/vfile.txt", "x");
    envset("XDG_DATA_HOME", "/home/xdg-data");
    Res r = tput("-v", "vfile.txt");
    CK_EQ(r.exit, 0);
    CK_S(r.err, S("trash-put: 'vfile.txt' trashed in ~/xdg-data/Trash\n"));
}

static void test_verbose_shrink_can_be_disabled(void)
{
    // spec 10: TRASH_PUT_DISABLE_SHRINK=1.
    vwrite("/work/vfile.txt", "x");
    envset("XDG_DATA_HOME", "/home/xdg-data");
    envset("TRASH_PUT_DISABLE_SHRINK", "1");
    Res r = tput("-v", "vfile.txt");
    CK_EQ(r.exit, 0);
    CK_HAS(r.err, "trashed in /home/xdg-data/Trash");
}

static void test_verbose_twice_shows_debug_lines(void)
{
    // spec 5.8: -vv adds candidate trials and info-file notes.
    vwrite("/work/vfile.txt", "x");
    Res r = tput("-vv", "vfile.txt");
    CK_EQ(r.exit, 0);
    Str lines[32];
    iz n = vlines(r.err, lines);
    CK_EQ(n, 3);
    CK_S(lines[0], S("trash-put: trying trash dir: /xdg/Trash from volume: /"));
    CK_S(lines[1],
         S("trash-put: .trashinfo created as /xdg/Trash/info/vfile.txt.trashinfo."));
    CK_STARTS(lines[2], "trash-put: 'vfile.txt' trashed in ");
}

static void test_undeletable_original_refused(void)
{
    // spec 5.4 step 4: parent must be deletable-into.
    vmkdir("/work/rodir");
    vwrite("/work/rodir/f", "x");
    vchmod("/work/rodir", 0500);
    Res r = tput("rodir/f");
    CK_EQ(r.exit, 74);
    CK_HAS(r.err, "trash-put: cannot trash regular file 'rodir/f' "
                  "because deleting it is not allowed");
    ck_present("/work/rodir/f");
}

static void test_all_candidates_failed_report(void)
{
    // spec 5.8: every reason is reported, in candidate order, with
    // " `- failed to trash" lines (hidden --force-volume makes all fail).
    vwrite("/work/gvf", "x");
    Res r = tput("--force-volume", "/no-such-volume", "gvf");
    CK_EQ(r.exit, 74);
    Str lines[32];
    iz n = vlines(r.err, lines);
    CK_EQ(n, 4);
    CK_S(lines[0], S("trash-put: cannot trash regular file 'gvf' "
                     "(from volume '/no-such-volume')"));
    CK_S(lines[1], S("trash-put:  `- failed to trash gvf in /xdg/Trash, "
                     "because trash dir and file to be trashed are not in "
                     "the same volume, trash-dir volume: /, file volume: "
                     "/no-such-volume"));
    CK_S(lines[2], S("trash-put:  `- failed to trash gvf in "
                     "/no-such-volume/.Trash/1000, because trash dir cannot "
                     "be created because its parent does not exists, "
                     "trash-dir: /no-such-volume/.Trash/1000, parent: "
                     "/no-such-volume/.Trash"));
    CK_S(lines[3], S("trash-put:  `- failed to trash gvf in "
                     "/no-such-volume/.Trash-1000, because trash dir and "
                     "file to be trashed are not in the same volume, "
                     "trash-dir volume: /, file volume: /no-such-volume"));
}

static void test_home_fallback_requires_environment(void)
{
    // spec 5.5 candidate 4: --home-fallback alone is not enough.
    vwrite("/work/gvf", "x");
    Res r = tput("--force-volume", "/no-such-volume", "--home-fallback",
                 "gvf");
    CK_EQ(r.exit, 74);
    CK_HAS(r.err, "because home fallback not enabled");
}

static void test_fake_uid_changes_candidate_paths(void)
{
    // spec 10: TRASH_PUT_FAKE_UID_FOR_TESTING.
    vwrite("/work/gvf", "x");
    envset("TRASH_PUT_FAKE_UID_FOR_TESTING", "4242");
    Res r = tput("--force-volume", "/no-such-volume", "gvf");
    CK_EQ(r.exit, 74);
    CK_HAS(r.err, "/no-such-volume/.Trash/4242");
    CK_HAS(r.err, "/no-such-volume/.Trash-4242");
}

static void test_trash_dir_created_if_missing(void)
{
    // spec 4.5: the dir is created (mode 0700) with info/ files/.
    vwrite("/work/gf1", "x");
    Res r = tput("--trash-dir", "reltrash", "gf1");
    CK_EQ(r.exit, 0);
    ck_list("/work/reltrash", "files", "info", (char *)0);
    ck_mode("/work/reltrash", 0700);
    ck_present("/work/reltrash/files/gf1");
    // spec 3.2: with --trash-dir on the '/' volume, Path= stays absolute.
    CK_HAS(vread("/work/reltrash/info/gf1.trashinfo"), "Path=/work/gf1\n");
}

static void test_trash_dir_with_equals_sign(void)
{
    vwrite("/work/gf1", "x");
    Res r = tput("--trash-dir=eqtrash", "gf1");
    CK_EQ(r.exit, 0);
    ck_present("/work/eqtrash/files/gf1");
}

static void test_trash_dir_that_is_a_file_fails(void)
{
    vwrite("/work/gf1", "x");
    vwrite("/work/notadir", "x");
    Res r = tput("--trash-dir", "notadir", "gf1");
    CK_EQ(r.exit, 74);
    CK_HAS(r.err, "error during directory creation");
    CK_HAS(r.err, "File exists");
    ck_present("/work/gf1");
}

static void test_trash_dir_with_symlinked_info_refused(void)
{
    // spec 4.2: info/ or files/ being a symlink makes every candidate
    // insecure, including --trash-dir (NoCheck) candidates.
    vmkdir("/elsewhere");
    vmkdir("/mytrash");
    vsymlink("/elsewhere", "/mytrash/info");
    vwrite("/work/gf1", "x");
    Res r = tput("--trash-dir", "/mytrash", "gf1");
    CK_EQ(r.exit, 74);
    CK_HAS(r.err, "trash dir is insecure, its parent should not be "
                  "a symlink, trash-dir: /mytrash, parent: ");
    ck_present("/work/gf1");
}

static void test_same_volume_gate_with_custom_trash_dir(void)
{
    // spec 5.5: the file must be on the trash dir's volume.
    vwrite("/work/gvf", "x");
    vmkdir("/mytrash");
    Res r = tput("--force-volume", "/elsewhere", "--trash-dir", "/mytrash",
                 "gvf");
    CK_EQ(r.exit, 74);
    CK_HAS(r.err, "trash dir and file to be trashed are not in the same "
                  "volume, trash-dir volume: /, file volume: /elsewhere");
}

static void test_accepted_but_ignored_rm_flags(void)
{
    // spec 5.2: -d, -r, -R, --recursive are accepted and ignored.
    vmkdir("/work/dir");
    Res r = tput("-d", "-r", "-R", "--recursive", "dir");
    CK_EQ(r.exit, 0);
    ck_gone("/work/dir");
}

// -- Section 6: trash-list (spec 6.2, 6.3) ---------------------------------------

// '<n> <YYYY-MM-DD HH:MM:SS|None> <path>' -> path, per spec 7.5.
static i32 cmpstr_test(Str a, Str b)
{
    return namecmp(a, b);
}

static Str linepath_restore(Str line)
{
    iz i = 0;
    while (i < line.len && line.data[i] == ' ') {
        i++;
    }
    while (i < line.len && line.data[i] >= '0' && line.data[i] <= '9') {
        i++;
    }
    while (i < line.len && line.data[i] == ' ') {
        i++;
    }
    if (i + 19 <= line.len && line.data[i + 4] == '-') {
        i += 19;   // the "YYYY-MM-DD HH:MM:SS" run
        while (i < line.len && line.data[i] == ' ') {
            i++;
        }
    } else {
        while (i < line.len && line.data[i] != ' ') {   // e.g. None
            i++;
        }
        while (i < line.len && line.data[i] == ' ') {
            i++;
        }
    }
    return cuthead(line, i);
}

static Str linepath(Str line)   // '<date> <time> <path>' -> path
{
    iz first = 0;
    while (first < line.len && line.data[first] != ' ') {
        first++;
    }
    iz second = first + 1;
    while (second < line.len && line.data[second] != ' ') {
        second++;
    }
    return cuthead(line, second + 1);
}

static void sortstrs(Str *a, iz n)
{
    for (iz i = 1; i < n; i++) {
        Str x = a[i];
        iz j = i;
        while (j > 0 && namecmp(a[j - 1], x) > 0) {
            a[j] = a[j - 1];
            j--;
        }
        a[j] = x;
    }
}

static void test_empty_trash_is_silent(void)
{
    Res r = tlist();
    CK_EQ(r.exit, 0);
    CK_S(r.out, S(""));
    CK_S(r.err, S(""));
}

static void test_listing_format(void)
{
    // spec 6.2: "<date> <original location>".
    char *names[] = {"one.txt", "two.txt"};
    for (uz i = 0; i < countof(names); i++) {
        vwrite(vfmt("/work/%s", names[i]), "x");
        CK_EQ(tput(names[i]).exit, 0);
    }
    Res r = tlist();
    CK_EQ(r.exit, 0);
    Str lines[32];
    iz n = vlines(r.out, lines);
    CK_EQ(n, 2);
    Str got[32];
    for (iz i = 0; i < n; i++) {
        got[i] = linepath(lines[i]);
        CK_STARTS(lines[i], "2026-06-01 12:00:00 ");
    }
    sortstrs(got, n);
    Str want[32];
    for (uz i = 0; i < countof(names); i++) {
        want[i] = import((u8 *)vfmt("/work/%s", names[i]));
    }
    sortstrs(want, 2);
    CK_S(got[0], want[0]);
    CK_S(got[1], want[1]);
}

static void test_duplicate_paths_are_all_listed(void)
{
    // spec 6.2: no deduplication.
    for (i32 i = 0; i < 2; i++) {
        vwrite("/work/same.txt", "x");
        CK_EQ(tput("same.txt").exit, 0);
    }
    Str lines[32];
    iz n = vlines(tlist().out, lines);
    CK_EQ(n, 2);
    CK_S(linepath(lines[0]), linepath(lines[1]));
}

static void test_missing_deletion_date_sentinel(void)
{
    // spec 3.3/6.2: no DeletionDate -> "????-??-?? ??:??:??".
    mktrash("/xdg/Trash");
    winfo("/xdg/Trash", "nodate", "/work/whatever", (char *)0, (Str){});
    wbackup("/xdg/Trash", "nodate", "data");
    Res r = tlist();
    CK_EQ(r.exit, 0);
    CK_S(r.out, S("\?\?\?\?-\?\?-\?\? ??:??:?? /work/whatever\n"));
}

static void test_invalid_deletion_date_sentinel(void)
{
    mktrash("/xdg/Trash");
    winfo("/xdg/Trash", "bad", "/work/w", "not-a-date", (Str){});
    wbackup("/xdg/Trash", "bad", "data");
    Res r = tlist();
    CK_EQ(r.exit, 0);
    CK_HAS(r.out, "\?\?\?\?-\?\?-\?\? ??:??:?? /work/w");
}

static void test_timezone_suffix_makes_date_invalid(void)
{
    // spec 3.3: no timezone suffix is accepted.
    mktrash("/xdg/Trash");
    winfo("/xdg/Trash", "tz", "/work/w", "2020-01-02T03:04:05Z", (Str){});
    wbackup("/xdg/Trash", "tz", "data");
    Res r = tlist();
    CK_HAS(r.out, "\?\?\?\?-\?\?-\?\? ??:??:??");
}

static void test_missing_path_is_a_parse_error(void)
{
    // spec 6.3: no Path= -> stderr message, not listed, exit 0.
    mktrash("/xdg/Trash");
    winfo("/xdg/Trash", "nopath", (char *)0, (char *)0,
          S("[Trash Info]\nDeletionDate=2020-01-02T03:04:05\n"));
    wbackup("/xdg/Trash", "nopath", "data");
    vwrite("/work/kept.txt", "x");
    tput("kept.txt");
    Res r = tlist();
    CK_EQ(r.exit, 0);
    CK_S(r.err, S("Parse Error: /xdg/Trash/info/nopath.trashinfo: "
                  "Unable to parse Path.\n"));
    Str lines[32];
    iz n = vlines(r.out, lines);
    CK_EQ(n, 1);
    CK_S(linepath(lines[0]), S("/work/kept.txt"));
}

static void test_non_trashinfo_entries_are_ignored(void)
{
    mktrash("/xdg/Trash");
    vwrite("/xdg/Trash/info/README", "not a trashinfo");
    Res r = tlist();
    CK_EQ(r.exit, 0);
    CK_S(r.out, S(""));
    CK_S(r.err, S(""));
}

static void test_orphans_are_not_listed(void)
{
    // spec 6.2: only info/ drives the listing.
    mktrash("/xdg/Trash");
    wbackup("/xdg/Trash", "orphan", "data");
    Res r = tlist();
    CK_EQ(r.exit, 0);
    CK_S(r.out, S(""));
}

static void test_unreadable_info_file_is_reported(void)
{
    // spec 6.3: IOError text on stderr, scanning continues.
    mktrash("/xdg/Trash");
    winfo("/xdg/Trash", "secret", "/work/w", (char *)0, (Str){});
    wbackup("/xdg/Trash", "secret", "data");
    vchmod("/xdg/Trash/info/secret.trashinfo", 0);
    vwrite("/work/ok.txt", "x");
    tput("ok.txt");
    Res r = tlist();
    CK_EQ(r.exit, 0);
    CK_HAS(r.err, "[Errno 13] Permission denied: "
                  "'/xdg/Trash/info/secret.trashinfo'");
    Str lines[32];
    iz n = vlines(r.out, lines);
    CK_EQ(n, 1);
    CK_S(linepath(lines[0]), S("/work/ok.txt"));
}

static void test_non_utf8_trashinfo_is_skipped(void)
{
    // spec 6.3 (corrected): an unparsable trashinfo gets a warning naming
    // the file, is skipped, and the run exits 0.
    mktrash("/xdg/Trash");
    winfo("/xdg/Trash", "bin", (char *)0, (char *)0,
          S("[Trash Info]\nPath=/x\xffy\n"
            "DeletionDate=2020-01-01T00:00:00\n"));
    Res r = tlist();
    CK_EQ(r.exit, 0);
    Str lines[32];
    CK_EQ(vlines(r.out, lines), 0);
    CK_HAS(r.err, "/xdg/Trash/info/bin.trashinfo");
}

static void test_hidden_files_option(void)
{
    // spec 6.1: --files appends " -> <backup copy path>".
    mktrash("/xdg/Trash");
    make_trashed("/xdg/Trash", "stem", "/work/w", "2020-01-02T03:04:05");
    Res r = tlist("--files");
    CK_EQ(r.exit, 0);
    Str lines[32];
    iz n = vlines(r.out, lines);
    CK_EQ(n, 1);
    CK_S(lines[0], S("2020-01-02 03:04:05 /work/w -> /xdg/Trash/files/stem"));
}

static void test_hidden_size_option(void)
{
    // spec 6.1: --size prints the backup copy's size.
    mktrash("/xdg/Trash");
    make_trashed("/xdg/Trash", "stem", "/work/w", (char *)0);
    Res r = tlist("--size");
    CK_EQ(r.exit, 0);
    Str lines[32];
    iz n = vlines(r.out, lines);
    CK_EQ(n, 1);
    CK_S(lines[0], S("4 /work/w"));
}

static void test_hidden_size_option_without_backup_crashes(void)
{
    // spec 6.3: --size on a missing backup copy is fatal.
    mktrash("/xdg/Trash");
    winfo("/xdg/Trash", "stem", "/work/w", "2020-01-02T03:04:05", (Str){});
    Res r = tlist("--size");
    CK_EQ(r.exit, 1);
}

static void test_custom_trash_dir_used_verbatim(void)
{
    // spec 4.5: --trash-dir replaces discovery, no trust checks.
    mktrash("/trash");
    make_trashed("/trash", "a", "/work/a", "2020-01-02T03:04:05");
    Res r = tlist("--trash-dir", "/trash");
    CK_EQ(r.exit, 0);
    Str lines[32];
    iz n = vlines(r.out, lines);
    CK_EQ(n, 1);
    CK_S(lines[0], S("2020-01-02 03:04:05 /work/a"));
}

static void test_custom_trash_dir_does_not_exist_is_silent(void)
{
    // spec 6.3: nonexistent --trash-dir -> nothing, exit 0.
    Res r = tlist("--trash-dir", "/nope");
    CK_EQ(r.exit, 0);
    CK_S(r.out, S(""));
    CK_S(r.err, S(""));
}

static void test_multiple_custom_trash_dirs(void)
{
    mktrash("/t1");
    mktrash("/t2");
    make_trashed("/t1", "a", "/work/a", (char *)0);
    make_trashed("/t2", "b", "/work/b", (char *)0);
    Res r = tlist("--trash-dir", "/t1", "--trash-dir", "/t2");
    CK_EQ(r.exit, 0);
    Str lines[32];
    iz n = vlines(r.out, lines);
    CK_EQ(n, 2);
    Str got[32];
    got[0] = linepath(lines[0]);
    got[1] = linepath(lines[1]);
    sortstrs(got, 2);
    CK_S(got[0], S("/work/a"));
    CK_S(got[1], S("/work/b"));
}

static void test_all_users_runs(void)
{
    // spec 4.6: --all-users enumerates the user table.
    Res r = tlist("--all-users");
    CK_EQ(r.exit, 0);
}

static void test_all_users_ignores_trash_dir(void)
{
    // spec 4.6: in --all-users mode, --trash-dir is ignored.
    mktrash("/trash");
    make_trashed("/trash", "x", "/work/x", (char *)0);
    Res r = tlist("--trash-dir", "/trash", "--all-users");
    CK_EQ(r.exit, 0);
    CK_NOHAS(r.out, "/work/x");
}

// -- Section 4: volume enumeration (spec 4.2-4.4) ---------------------------------

static void test_volumes_come_from_trash_volumes(void)
{
    // spec 4.4: TRASH_VOLUMES is colon-split; empty items drop.
    envset("TRASH_VOLUMES", "/a:/b::/c");
    Res r = tlist("--volumes");
    CK_EQ(r.exit, 0);
    CK_S(r.out, S("/a\n/b\n/c\n"));
}

static void test_trash_dirs_lists_home_then_volume(void)
{
    // spec 4.2/6.1: home trash first, then per-volume dirs.
    volume_trash(2, VUID);
    Res r = tlist("--trash-dirs");
    CK_EQ(r.exit, 0);
    Str lines[32];
    iz n = vlines(r.out, lines);
    CK_EQ(n, 2);
    CK_S(lines[0], S("/xdg/Trash"));
    CK_S(lines[1], S("/vol/.Trash-1000"));
}

static void test_method1_requires_sticky_parent(void)
{
    // spec 4.2: .Trash without the sticky bit -> skipped.
    vmkdir("/vol/.Trash");
    volume_trash(1, VUID);
    Res r = tlist("--trash-dirs");
    CK_EQ(r.exit, 0);
    Str lines[32];
    iz n = vlines(r.out, lines);
    CK_EQ(n, 2);
    CK_S(lines[0], S("/xdg/Trash"));
    CK_S(lines[1], S("parent_not_sticky: /vol/.Trash/1000"));
}

static void test_method1_with_sticky_parent_is_listed(void)
{
    vmkdir("/vol/.Trash");
    vchmod("/vol/.Trash", 01700);
    volume_trash(1, VUID);
    Res r = tlist("--trash-dirs");
    CK_EQ(r.exit, 0);
    Str lines[32];
    iz n = vlines(r.out, lines);
    CK_EQ(n, 2);
    CK_S(lines[1], S("/vol/.Trash/1000"));
}

static void test_sticky_bit_is_checked_before_symlink(void)
{
    // spec 4.2: a symlink to a non-sticky dir reports "not sticky"
    // (sticky is checked first).
    vmkdir("/plain-target");
    vsymlink("/plain-target", "/vol/.Trash");
    volume_trash(1, VUID);
    Res r = tlist("--trash-dirs");
    CK_HAS(r.out, "parent_not_sticky: /vol/.Trash/1000");
    CK_NOHAS(r.out, "parent_is_symlink");
}

static void test_symlink_parent_is_reported(void)
{
    // spec 4.2: a symlink to a sticky dir reports the symlink.
    vmkdir("/sticky-target");
    vchmod("/sticky-target", 01700);
    vsymlink("/sticky-target", "/vol/.Trash");
    volume_trash(1, VUID);
    Res r = tlist("--trash-dirs");
    CK_HAS(r.out, "parent_is_symlink: /vol/.Trash/1000");
    CK_NOHAS(r.out, "parent_not_sticky");
}

static void test_method2_needs_only_to_be_a_directory(void)
{
    // spec 4.3: .Trash-$uid has no sticky/symlink checks.
    volume_trash(2, VUID);   // parent (the volume) is not sticky at all
    Res r = tlist("--trash-dirs");
    CK_EQ(r.exit, 0);
    CK_HAS(r.out, "/vol/.Trash-1000");
}

static void test_method1_missing_is_silent(void)
{
    // spec 4.2: a missing .Trash/<uid> is silently ignored.
    Res r = tlist("--trash-dirs");
    CK_EQ(r.exit, 0);
    Str lines[32];
    iz n = vlines(r.out, lines);
    CK_EQ(n, 1);
    CK_S(lines[0], S("/xdg/Trash"));
    CK_S(r.err, S(""));
}

static void test_main_listing_scan_order_home_then_volume(void)
{
    // spec 6.2: home trash entries first, then volume trash.
    vwrite("/work/home-file", "x");
    CK_EQ(tput("home-file").exit, 0);
    char *trash = volume_trash(2, VUID);
    make_trashed(trash, "v1", "volfile", "2001-02-03T04:05:06");
    Res r = tlist();
    CK_EQ(r.exit, 0);
    Str lines[32];
    iz n = vlines(r.out, lines);
    CK_EQ(n, 2);
    CK_S(linepath(lines[0]), S("/work/home-file"));
    CK_S(linepath(lines[1]), S("/vol/volfile"));
}

static void test_volume_entry_path_is_joined_with_volume(void)
{
    // spec 6.2: relative Path= is joined with the trash dir's volume
    // (not the trash dir).
    char *trash = volume_trash(2, VUID);
    make_trashed(trash, "v1", "volfile", "2001-02-03T04:05:06");
    Res r = tlist();
    CK_HAS(r.out, "2001-02-03 04:05:06 /vol/volfile");
}

static void test_main_listing_reports_skipped_dirs_on_stderr(void)
{
    // spec 4.2: skip reasons go to stderr in the main listing.
    vmkdir("/vol/.Trash");
    volume_trash(1, VUID);
    Res r = tlist();
    CK_EQ(r.exit, 0);
    CK_S(r.err, S("TrashDir skipped because parent not sticky: "
                  "/vol/.Trash/1000\n"));
}

// -- Output hygiene: trash-list on a terminal (spec 6.2 quoting) ------------------

static void test_paths_are_quoted_on_a_terminal(void)
{
    vwrite("/work/spaced name.txt", "x");
    CK_EQ(tput("spaced name.txt").exit, 0);
    v->istty[1] = 1;
    Res r = tlist();
    CK_HAS(r.out, "'/work/spaced name.txt'");
}

static void test_paths_are_raw_when_piped(void)
{
    vwrite("/work/spaced name.txt", "x");
    CK_EQ(tput("spaced name.txt").exit, 0);
    Res r = tlist();
    CK_HAS(r.out, "/work/spaced name.txt");
    CK_NOHAS(r.out, "'/work/spaced name.txt'");
}

static void test_trash_raw_output_disables_quoting(void)
{
    // spec 10: TRASH_RAW_OUTPUT forces raw output.
    vwrite("/work/spaced name.txt", "x");
    CK_EQ(tput("spaced name.txt").exit, 0);
    v->istty[1] = 1;
    envset("TRASH_RAW_OUTPUT", "1");
    Res r = tlist();
    CK_HAS(r.out, "/work/spaced name.txt");
    CK_NOHAS(r.out, "'/work/spaced name.txt'");
}

// -- Section 7: trash-restore (spec 7) --------------------------------------------

static void test_zero_candidates_message(void)
{
    // spec 7.5: exact message with the realpath of the cwd.
    Res r = trestore();
    CK_EQ(r.exit, 0);
    CK_S(r.out, S("No files trashed from current dir ('/work')\n"));
    CK_S(r.err, S(""));
}

static void test_listing_and_prompt_format(void)
{
    // spec 7.5: "%4d %s %s" plus "What file to restore [0..N]: ".
    mktrash("/trash");
    make_trashed("/trash", "gone1", "/work/gone1", "2001-02-03T04:05:06");
    setstdin("\n");
    Res r = trestore("--trash-dir", "/trash");
    CK_EQ(r.exit, 0);
    CK_S(r.out, S("   0 2001-02-03 04:05:06 /work/gone1\n"
                  "What file to restore [0..0]: No files were restored\n"));
    CK_S(r.err, S(""));
}

static void test_restore_by_index(void)
{
    // spec 7.7: move back to the original location, remove the info file
    // and backup copy.
    mktrash("/trash");
    make_trashed("/trash", "f1", "/work/f1", "2001-01-01T00:00:00");
    wbackup("/trash", "f1", "restored content");
    setstdin("0\n");
    Res r = trestore("--trash-dir", "/trash");
    CK_EQ(r.exit, 0);
    CK_S(r.err, S(""));
    ck_contents("/work/f1", "restored content");
    Str names[64];
    CK_EQ(vlist("/trash/info", names), 0);
    CK_EQ(vlist("/trash/files", names), 0);
}

static void test_empty_reply_restores_nothing(void)
{
    mktrash("/trash");
    make_trashed("/trash", "f1", "/work/f1", (char *)0);
    setstdin("\n");
    Res r = trestore("--trash-dir", "/trash");
    CK_EQ(r.exit, 0);
    CK_HAS(r.out, "No files were restored");
    ck_present("/trash/info/f1.trashinfo");
}

static void test_eof_at_prompt(void)
{
    // spec 7.6: EOF/Ctrl-C -> blank line on stderr, exit 1.
    mktrash("/trash");
    make_trashed("/trash", "f1", "/work/f1", (char *)0);
    setstdin("");
    Res r = trestore("--trash-dir", "/trash");
    CK_EQ(r.exit, 1);
    CK_S(r.err, S("\n"));
}

static void test_invalid_index(void)
{
    mktrash("/trash");
    make_trashed("/trash", "f1", "/work/f1", (char *)0);
    setstdin("x\n");
    Res r = trestore("--trash-dir", "/trash");
    CK_EQ(r.exit, 1);
    CK_HAS(r.err, "Invalid entry: not an index: x");
}

static void test_out_of_range_index(void)
{
    mktrash("/trash");
    make_trashed("/trash", "f1", "/work/f1", (char *)0);
    setstdin("5\n");
    Res r = trestore("--trash-dir", "/trash");
    CK_EQ(r.exit, 1);
    CK_HAS(r.err, "Invalid entry: out of range 0..0: 5");
}

static void test_open_interval_rejected(void)
{
    // spec 7.6: "-1" and "1-" are not valid.
    mktrash("/trash");
    make_trashed("/trash", "f1", "/work/f1", (char *)0);
    char *bad[] = {"-1", "1-"};
    for (uz i = 0; i < countof(bad); i++) {
        setstdin(vfmt("%s\n", bad[i]));
        Res r = trestore("--trash-dir", "/trash");
        CK_EQ(r.exit, 1);
        CK_HAS_C(r.err, vfmt("Invalid entry: open interval: %s", bad[i]));
    }
}

static void test_range_is_inclusive_and_comma_list_works(void)
{
    // spec 7.6: "0-2, 3" -> 0 1 2 3; spaces around commas OK.
    mktrash("/trash");
    char *names[] = {"w0", "w1", "w2", "w3"};
    for (uz i = 0; i < countof(names); i++) {
        make_trashed("/trash", vfmt("f%lld", (long long)i),
                     vfmt("/work/%s", names[i]),
                     vfmt("2001-01-0%lldT00:00:00", (long long)(i + 1)));
    }
    setstdin("0-2, 3\n");
    Res r = trestore("--trash-dir", "/trash");
    CK_EQ(r.exit, 0);
    for (uz i = 0; i < countof(names); i++) {
        ck_present(vfmt("/work/%s", names[i]));
    }
    Str empty[64];
    CK_EQ(vlist("/trash/info", empty), 0);
}

static void test_overwrite_refusal(void)
{
    // spec 7.7 step 1: exact message (basename only), the file stays in
    // the trash, exit 1.
    mktrash("/trash");
    make_trashed("/trash", "r1", "/work/r1", "2001-01-01T00:00:00");
    wbackup("/trash", "r1", "from trash");
    vwrite("/work/r1", "occupant");
    setstdin("0\n");
    Res r = trestore("--trash-dir", "/trash");
    CK_EQ(r.exit, 1);
    CK_S(r.err, S("Refusing to overwrite existing file \"r1\".\n"));
    ck_contents("/work/r1", "occupant");
    ck_present("/trash/info/r1.trashinfo");
}

static void test_overwrite_flag_replaces_file(void)
{
    mktrash("/trash");
    make_trashed("/trash", "r1", "/work/r1", (char *)0);
    wbackup("/trash", "r1", "from trash");
    vwrite("/work/r1", "occupant");
    setstdin("0\n");
    Res r = trestore("--trash-dir", "/trash", "--overwrite");
    CK_EQ(r.exit, 0);
    ck_contents("/work/r1", "from trash");
}

static void test_directory_is_never_overwritten(void)
{
    // spec 7.7: existing directories are refused even with --overwrite.
    mktrash("/trash");
    make_trashed("/trash", "r1", "/work/r1", (char *)0);
    wbackup("/trash", "r1", "file");
    vmkdir("/work/r1");
    for (i32 withflag = 0; withflag < 2; withflag++) {
        setstdin("0\n");
        Res r = withflag ? trestore("--trash-dir", "/trash", "--overwrite")
                         : trestore("--trash-dir", "/trash");
        CK_EQ(r.exit, 1);
        CK_HAS(r.err, "Refusing to overwrite existing file \"r1\".");
    }
}

static void test_missing_parent_directories_are_created(void)
{
    // spec 7.7 step 2.
    mktrash("/trash");
    make_trashed("/trash", "ab", "/work/deep/a/b.txt", (char *)0);
    wbackup("/trash", "ab", "deep content");
    setstdin("0\n");
    Res r = trestore("--trash-dir", "/trash");
    CK_EQ(r.exit, 0);
    ck_contents("/work/deep/a/b.txt", "deep content");
}

static void test_restore_directory(void)
{
    mktrash("/trash");
    vmkdir("/work/adir");
    vwrite("/work/adir/inner", "i");
    CK_EQ(tput("adir").exit, 0);
    setstdin("0\n");
    Res r = trestore("--trash-dir", "/xdg/Trash");
    CK_EQ(r.exit, 0);
    ck_present("/work/adir/inner");
}

static void test_path_arg_selects_subtree(void)
{
    // spec 7.3: candidates equal to the path or under it.
    mktrash("/trash");
    make_trashed("/trash", "x", "/work/d/x", "2001-01-01T00:00:00");
    make_trashed("/trash", "y", "/work/y", "2002-01-01T00:00:00");
    setstdin("\n");
    Res r = trestore("--trash-dir", "/trash", "/work/d");
    CK_EQ(r.exit, 0);
    Str lines[32];
    iz n = vlines(r.out, lines);
    CK_EQ(n, 2);   // listing plus the prompt line
    CK_S(lines[0], S("   0 2001-01-01 00:00:00 /work/d/x"));
}

static void test_path_arg_relative_dot(void)
{
    mktrash("/trash");
    make_trashed("/trash", "x", "/work/x", (char *)0);
    make_trashed("/trash", "out", "/outside", (char *)0);
    setstdin("\n");
    Res r = trestore("--trash-dir", "/trash", ".");
    CK_EQ(r.exit, 0);
    Str lines[32];
    iz n = vlines(r.out, lines);
    CK_EQ(n, 2);
    CK_S(linepath_restore(lines[0]), S("/work/x"));
}

static void test_path_arg_absolute(void)
{
    mktrash("/trash");
    make_trashed("/trash", "x", "/work/x", (char *)0);
    setstdin("\n");
    Res r = trestore("--trash-dir", "/trash", "/work/x");
    CK_EQ(r.exit, 0);
    CK_HAS(r.out, "/work/x");
}

static void test_slash_path_matches_everything(void)
{
    // spec 7.3: path == '/' matches every original location, including
    // absolute Path= values recorded from anywhere.
    mktrash("/trash");
    make_trashed("/trash", "x", "/work/x", "2001-01-01T00:00:00");
    make_trashed("/trash", "abs", "/some/deep/dir/file",
                 "2002-01-01T00:00:00");
    setstdin("\n");
    Res r = trestore("--trash-dir", "/trash", "/");
    CK_EQ(r.exit, 0);
    Str lines[32];
    iz n = vlines(r.out, lines);
    CK_EQ(n, 3);
    Str got[32];
    got[0] = linepath_restore(lines[0]);
    got[1] = linepath_restore(lines[1]);
    sortstrs(got, 2);
    CK_S(got[0], S("/some/deep/dir/file"));
    CK_S(got[1], S("/work/x"));
}

static void test_prefix_must_not_match_partial_names(void)
{
    // spec 7.3: /prefix does not match /prefix-other.
    mktrash("/trash");
    make_trashed("/trash", "x", "/work/prefix-other", (char *)0);
    setstdin("\n");
    Res r = trestore("--trash-dir", "/trash", "/work/prefix");
    CK_EQ(r.exit, 0);
    CK_S(r.out, S("No files trashed from '/work/prefix'\n"));
}

static void test_sort_date_ascending(void)
{
    // spec 7.5: --sort date (default) is ascending by date.
    mktrash("/trash");
    char *names[] = {"c", "a", "b"};
    char *dates[] = {"2003-03-03T03:03:03", "2001-01-01T01:01:01",
                     "2002-02-02T02:02:02"};
    for (uz i = 0; i < countof(names); i++) {
        make_trashed("/trash", names[i], vfmt("/work/%s", names[i]),
                     dates[i]);
    }
    setstdin("\n");
    Res r = trestore("--trash-dir", "/trash");
    CK_EQ(r.exit, 0);
    Str lines[32];
    iz n = vlines(r.out, lines);
    CK_EQ(n, 4);
    CK_S(lines[0], S("   0 2001-01-01 01:01:01 /work/a"));
    CK_S(lines[1], S("   1 2002-02-02 02:02:02 /work/b"));
    CK_S(lines[2], S("   2 2003-03-03 03:03:03 /work/c"));
}

static void test_sort_path(void)
{
    // spec 7.5: --sort path sorts by original location.
    mktrash("/trash");
    make_trashed("/trash", "b", "/work/b.txt", "2001-01-01T00:00:00");
    make_trashed("/trash", "a", "/work/a.txt", "2002-01-01T00:00:00");
    setstdin("\n");
    Res r = trestore("--trash-dir", "/trash", "--sort", "path");
    CK_EQ(r.exit, 0);
    Str lines[32];
    iz n = vlines(r.out, lines);
    CK_EQ(n, 3);
    CK_S(lines[0], S("   0 2002-01-01 00:00:00 /work/a.txt"));
    CK_S(lines[1], S("   1 2001-01-01 00:00:00 /work/b.txt"));
}

static void test_sort_none_keeps_scan_order(void)
{
    // spec 11.1 (corrected): --sort none keeps the scan order and exits 0.
    mktrash("/trash");
    make_trashed("/trash", "x", "/work/x", "2001-01-01T00:00:00");
    setstdin("\n");
    Res r = trestore("--trash-dir", "/trash", "--sort", "none");
    CK_EQ(r.exit, 0);
    Str lines[32];
    iz n = vlines(r.out, lines);
    CK_EQ(n, 2);
    CK_S(lines[0], S("   0 2001-01-01 00:00:00 /work/x"));
}

static void test_missing_date_prints_none(void)
{
    // spec 7.5: a missing DeletionDate shows as "None".
    mktrash("/trash");
    make_trashed("/trash", "nd", "/work/nd", (char *)0);
    setstdin("\n");
    Res r = trestore("--trash-dir", "/trash");
    CK_EQ(r.exit, 0);
    Str lines[32];
    iz n = vlines(r.out, lines);
    CK_EQ(n, 2);
    CK_S(lines[0], S("   0 None /work/nd"));
}

static void test_missing_date_sorts_last(void)
{
    // spec 7.5 (corrected): an undated entry sorts after the dated ones
    // and shows as "None"; the run succeeds.
    mktrash("/trash");
    make_trashed("/trash", "dated", "/work/d", "2001-01-01T00:00:00");
    make_trashed("/trash", "dateless", "/work/n", (char *)0);
    setstdin("\n");
    Res r = trestore("--trash-dir", "/trash");
    CK_EQ(r.exit, 0);
    Str lines[32];
    iz n = vlines(r.out, lines);
    CK_EQ(n, 3);
    CK_S(lines[0], S("   0 2001-01-01 00:00:00 /work/d"));
    CK_S(lines[1], S("   1 None /work/n"));
}

static void test_percent_encoded_path_is_decoded(void)
{
    mktrash("/trash");
    make_trashed("/trash", "s", "/work/with space",
                 "2001-01-01T00:00:00");
    setstdin("\n");
    Res r = trestore("--trash-dir", "/trash");
    CK_HAS(r.out, "/work/with space");
}

static void test_batch_restores_what_it_can(void)
{
    // spec 7.7: batch errors are not fatal to the batch; every failure
    // produces one stderr line and the exit code is 1.
    mktrash("/trash");
    make_trashed("/trash", "k1", "/work/k1", "2001-01-01T00:00:00");
    make_trashed("/trash", "k2", "/work/k2", "2002-01-01T00:00:00");
    wbackup("/trash", "k1", "one");
    wbackup("/trash", "k2", "two");
    vwrite("/work/k2", "occupant");
    setstdin("0,1\n");
    Res r = trestore("--trash-dir", "/trash");
    CK_EQ(r.exit, 1);
    ck_contents("/work/k1", "one");
    ck_contents("/work/k2", "occupant");
    CK_S(r.err, S("Refusing to overwrite existing file \"k2\".\n"));
    ck_list("/trash/info", "k2.trashinfo", (char *)0);
}

static void test_no_candidates_with_path_arg_names_the_path(void)
{
    // spec 7.5 (corrected): the zero-candidates message names the searched
    // path; without an argument, the cwd.
    setstdin("\n");
    Res r = trestore("/nowhere");
    CK_EQ(r.exit, 0);
    CK_S(r.out, S("No files trashed from '/nowhere'\n"));
}

static void test_parsed_date_shown_without_timezone_conversion(void)
{
    // spec 7.5: the naive DeletionDate is shown as stored.
    mktrash("/trash");
    make_trashed("/trash", "x", "/work/x", "2007-08-30T12:36:00");
    setstdin("\n");
    Res r = trestore("--trash-dir", "/trash");
    CK_HAS(r.out, "   0 2007-08-30 12:36:00");
}

// -- Section 4.7: restore distrusts unsafe trash dirs -----------------------------

static char *prep_home_trash(void)
{
    mktrash("/xdg/Trash");
    make_trashed("/xdg/Trash", "x", "/work/x", (char *)0);
    return "/xdg/Trash";
}

static void test_world_writable_files_dir_distrusted(void)
{
    char *trash = prep_home_trash();
    vchmod("/xdg/Trash/files", 0777);
    Res r = trestore();
    CK_EQ(r.exit, 0);
    CK_HAS(r.err, "TrashDir skipped because its files dir is world "
                  "writable: /xdg/Trash");
    CK_NOHAS(r.out, "/work/x");
    (void)trash;
}

static void test_world_writable_info_dir_distrusted(void)
{
    prep_home_trash();
    vchmod("/xdg/Trash/info", 0777);
    Res r = trestore();
    CK_EQ(r.exit, 0);
    CK_HAS(r.err, "TrashDir skipped because its info dir is world "
                  "writable: /xdg/Trash");
}

static void test_symlinked_info_dir_distrusted(void)
{
    prep_home_trash();
    vchmod("/xdg/Trash/info", 0700);
    CK(os_rename(0, *gscratch, S("/xdg/Trash/info"),
                 S("/xdg/Trash/info-real")));
    vsymlink("/xdg/Trash/info-real", "/xdg/Trash/info");
    Res r = trestore();
    CK_EQ(r.exit, 0);
    CK_HAS(r.err, "TrashDir skipped because its info dir is a symbolic "
                  "link: /xdg/Trash");
    CK_NOHAS(r.out, "/work/x");
}

static void test_symlinked_files_dir_distrusted(void)
{
    prep_home_trash();
    CK(os_rename(0, *gscratch, S("/xdg/Trash/files"),
                 S("/xdg/Trash/files-real")));
    vsymlink("/xdg/Trash/files-real", "/xdg/Trash/files");
    Res r = trestore();
    CK_EQ(r.exit, 0);
    CK_HAS(r.err, "TrashDir skipped because its files dir is a symbolic "
                  "link: /xdg/Trash");
}

static void test_custom_trash_dir_bypasses_trust_checks(void)
{
    // spec 4.5: --trash-dir dirs are used as-is.
    prep_home_trash();
    vchmod("/xdg/Trash/files", 0777);
    setstdin("\n");
    Res r = trestore("--trash-dir", "/xdg/Trash");
    CK_EQ(r.exit, 0);
    CK_HAS(r.out, "/work/x");
    CK_NOHAS(r.err, "world writable");
}

// -- Section 8: trash-empty (spec 8) -----------------------------------------------

static void test_empties_silently(void)
{
    // spec 8.6: no output, exit 0.
    vwrite("/work/a", "x");
    vwrite("/work/b", "x");
    CK_EQ(tput("a", "b").exit, 0);
    Res r = tempty("-f");
    CK_EQ(r.exit, 0);
    CK_S(r.out, S(""));
    CK_S(r.err, S(""));
    Str names[64];
    CK_EQ(vlist("/xdg/Trash/info", names), 0);
    CK_EQ(vlist("/xdg/Trash/files", names), 0);
}

static void test_removes_backup_before_info(void)
{
    // spec 8.4: per trashinfo, files/ entry first, then info.
    mktrash("/trash");
    make_trashed("/trash", "p", "/work/p", (char *)0);
    CK_EQ(tempty("-f", "--trash-dir", "/trash").exit, 0);
    ck_gone("/trash/files/p");
    ck_gone("/trash/info/p.trashinfo");
}

static void test_non_trashinfo_info_entries_are_kept(void)
{
    // spec 8.4: only *.trashinfo entries in info/ are deleted.
    mktrash("/trash");
    make_trashed("/trash", "p", "/work/p", (char *)0);
    vwrite("/trash/info/notes.txt", "keep me");
    CK_EQ(tempty("-f", "--trash-dir", "/trash").exit, 0);
    ck_present("/trash/info/notes.txt");
    ck_list("/trash/info", "notes.txt", (char *)0);
}

static void test_orphans_are_removed(void)
{
    // spec 8.4: files/ entries without info are deleted too, regardless
    // of any days argument.
    mktrash("/xdg/Trash");
    wbackup("/xdg/Trash", "orphan", "data");
    make_trashed("/xdg/Trash", "p", "/work/p", "2999-01-01T00:00:00");
    CK_EQ(tempty("-f", "--trash-dir", "/xdg/Trash").exit, 0);
    ck_gone("/xdg/Trash/files/orphan");
    ck_gone("/xdg/Trash/info/p.trashinfo");
}

static void test_no_trash_dirs_is_silent(void)
{
    // spec 8.2: nonexistent dirs contribute nothing.
    Res r = tempty("-f");
    CK_EQ(r.exit, 0);
    CK_S(r.out, S(""));
    CK_S(r.err, S(""));
}

static void test_dry_run_lines_and_order(void)
{
    // spec 8.6: "would remove <files entry>" then its info.
    mktrash("/trash");
    make_trashed("/trash", "p", "/work/p", (char *)0);
    Res r = tempty("--dry-run", "-f", "--trash-dir", "/trash");
    CK_EQ(r.exit, 0);
    Str lines[32];
    iz n = vlines(r.out, lines);
    CK_EQ(n, 2);
    CK_S(lines[0], S("would remove /trash/files/p"));
    CK_S(lines[1], S("would remove /trash/info/p.trashinfo"));
}

static void test_dry_run_deletes_nothing(void)
{
    mktrash("/trash");
    make_trashed("/trash", "p", "/work/p", (char *)0);
    CK_EQ(tempty("--dry-run", "-f", "--trash-dir", "/trash").exit, 0);
    ck_present("/trash/files/p");
    ck_present("/trash/info/p.trashinfo");
}

static void test_verbose_prints_removing_lines(void)
{
    // spec 8.6: -v prints "removing <path>" before each removal.
    mktrash("/trash");
    make_trashed("/trash", "p", "/work/p", (char *)0);
    Res r = tempty("-v", "-f", "--trash-dir", "/trash");
    CK_EQ(r.exit, 0);
    Str lines[32];
    iz n = vlines(r.out, lines);
    CK_EQ(n, 2);
    CK_S(lines[0], S("removing /trash/files/p"));
    CK_S(lines[1], S("removing /trash/info/p.trashinfo"));
}

static void test_days_boundary_is_strict(void)
{
    // spec 8.3: deleted iff deletion_date < now - days.  With days=0 the
    // cutoff is exactly now (TRASH_DATE): a file deleted at the cutoff
    // second is kept, one second earlier is removed.
    char *now = "2026-01-08T00:00:00";
    envset("TRASH_DATE", now);
    mktrash("/trash");
    make_trashed("/trash", "at_cutoff", "/work/at_cutoff", now);
    make_trashed("/trash", "older", "/work/older",
                 "2026-01-07T23:59:59");
    Res r = tempty("-f", "0", "--trash-dir", "/trash");
    CK_EQ(r.exit, 0);
    ck_present("/trash/info/at_cutoff.trashinfo");
    ck_gone("/trash/info/older.trashinfo");
}

static void test_days_keeps_files_with_missing_date(void)
{
    // spec 8.3: missing/unparseable DeletionDate -> kept.
    mktrash("/trash");
    make_trashed("/trash", "nd", "/work/nd", (char *)0);
    CK_EQ(tempty("-f", "7", "--trash-dir", "/trash").exit, 0);
    ck_present("/trash/info/nd.trashinfo");
}

static void test_without_days_missing_date_is_removed(void)
{
    // spec 8.3: without days everything goes, date or not.
    mktrash("/trash");
    make_trashed("/trash", "nd", "/work/nd", (char *)0);
    CK_EQ(tempty("-f", "--trash-dir", "/trash").exit, 0);
    ck_gone("/trash/info/nd.trashinfo");
}

static void test_days_invalid_int(void)
{
    // spec 8.1: argparse error, exit 2.
    Res r = tempty("1.5");
    CK_EQ(r.exit, 2);
    CK_HAS(r.err, "invalid int value: '1.5'");
}

static void test_days_extra_positional(void)
{
    Res r = tempty("1", "2");
    CK_EQ(r.exit, 2);
    CK_HAS(r.err, "unrecognized arguments: 2");
}

static void test_days_negative_empties_everything(void)
{
    // spec 8.3: negative days move the cutoff into the future; no
    // validation rejects them.
    char *now = "2026-01-08T00:00:00";
    mktrash("/trash");
    make_trashed("/trash", "now", "/work/now", now);
    envset("TRASH_DATE", now);
    Res r = tempty("-f", "-1", "--trash-dir", "/trash");
    CK_EQ(r.exit, 0);
    ck_gone("/trash/info/now.trashinfo");
}

static void test_huge_days_is_a_usage_error(void)
{
    // spec 8.3 (corrected): an out-of-range days value is a clean usage
    // error, exit 2.
    vwrite("/work/x", "x");
    tput("x");
    Res r = tempty("-f", "99999999999999999999");
    CK_EQ(r.exit, 2);
    CK_HAS(r.err, "error: argument days: value out of range: "
                  "'99999999999999999999'");
}

static void test_piped_stdin_means_non_interactive(void)
{
    // spec 8.1: interactive defaults to isatty(0); with piped stdin and
    // no -i/-f, emptying proceeds without prompting.
    vwrite("/work/a", "x");
    tput("a");
    setstdin("");
    Res r = tempty();
    CK_EQ(r.exit, 0);
    CK_S(r.out, S(""));
    Str names[64];
    CK_EQ(vlist("/xdg/Trash/info", names), 0);
}

static void test_interactive_prompt_and_decline(void)
{
    // spec 8.5: one confirmation for all trash dirs together.
    mktrash("/trash");
    make_trashed("/trash", "p", "/work/p", (char *)0);
    setstdin("n\n");
    Res r = tempty("-i", "--trash-dir", "/trash");
    CK_EQ(r.exit, 0);
    // With piped stdin there is no echo: the prompt has no trailing
    // newline, so stdout is exactly the prompt block.
    CK_S(r.out, S("Would empty the following trash directories:\n"
                  "    - /trash\n"
                  "Proceed? (y/N) "));
    ck_present("/trash/info/p.trashinfo");
}

static void test_interactive_accepts_anything_starting_with_y(void)
{
    mktrash("/trash");
    make_trashed("/trash", "p", "/work/p", (char *)0);
    setstdin("Yeah\n");
    Res r = tempty("-i", "--trash-dir", "/trash");
    CK_EQ(r.exit, 0);
    ck_gone("/trash/info/p.trashinfo");
}

static void test_explicit_i_prompts_even_with_piped_stdin(void)
{
    // spec 8.5: no isatty re-check at prompt time.
    mktrash("/trash");
    make_trashed("/trash", "p", "/work/p", (char *)0);
    setstdin("\n");
    Res r = tempty("-i", "--trash-dir", "/trash");
    CK_EQ(r.exit, 0);
    CK_HAS(r.out, "Proceed? (y/N)");
    ck_present("/trash/info/p.trashinfo");
}

static void test_interactive_eof_crashes_empty(void)
{
    // spec 8.5: EOF at the prompt is unhandled (exit 1).
    mktrash("/trash");
    make_trashed("/trash", "p", "/work/p", (char *)0);
    setstdin("");
    Res r = tempty("-i", "--trash-dir", "/trash");
    CK_EQ(r.exit, 1);
}

static void test_trash_dir_selects_only_that_dir(void)
{
    // spec 4.5: --trash-dir replaces default discovery.
    mktrash("/t1");
    mktrash("/t2");
    make_trashed("/t1", "a", "/work/a", (char *)0);
    make_trashed("/t2", "b", "/work/b", (char *)0);
    CK_EQ(tempty("-f", "--trash-dir", "/t1").exit, 0);
    Str names[64];
    CK_EQ(vlist("/t1/info", names), 0);
    ck_list("/t2/info", "b.trashinfo", (char *)0);
}

static void test_volume_trash_method2_is_emptied(void)
{
    // spec 4.3/8.2: .Trash-$uid on TRASH_VOLUMES volumes.
    char *trash = volume_trash(2, VUID);
    make_trashed(trash, "v", "volfile", "2001-01-01T00:00:00");
    Res r = tempty("-f");
    CK_EQ(r.exit, 0);
    Str names[64];
    CK_EQ(vlist(vfmt("%s/info", trash), names), 0);
}

static void test_invalid_trash_date_warns_and_keeps(void)
{
    // spec 10: TRASH_DATE parse failure -> stderr message, real clock
    // used, exit still 0.
    vwrite("/work/now-file", "x");
    CK_EQ(tput("now-file").exit, 0);
    envset("TRASH_DATE", "garbage");
    Res r = tempty("-f", "7");
    CK_EQ(r.exit, 0);
    CK_S(r.err, S("trash-empty: invalid TRASH_DATE: garbage\n"));
    ck_present("/xdg/Trash/info/now-file.trashinfo");
}

static void test_trash_date_in_future_empties(void)
{
    vwrite("/work/old-file", "x");
    CK_EQ(tput("old-file").exit, 0);
    envset("TRASH_DATE", "2999-01-01T00:00:00");
    Res r = tempty("-f", "7");
    CK_EQ(r.exit, 0);
    CK_S(r.err, S(""));
    Str names[64];
    CK_EQ(vlist("/xdg/Trash/info", names), 0);
}

static void test_print_time_with_trash_date(void)
{
    // spec 8.1: hidden --print-time shows the (faked) clock.
    envset("TRASH_DATE", "1970-12-31T23:59:59");
    Res r = tempty("--print-time");
    CK_EQ(r.exit, 0);
    CK_S(r.out, S("1970-12-31T23:59:59\n"));
}

static void test_print_time_without_trash_date(void)
{
    Res r = tempty("--print-time");
    CK_EQ(r.exit, 0);
    // The virtual clock makes this exact rather than a range check.
    CK_S(r.out, S("2026-06-01T12:00:00\n"));
}

static void test_unremovable_file_is_reported_and_skipped(void)
{
    // spec 8.4: "cannot remove <path>" on stderr, loop continues, exit
    // stays 0.
    mktrash("/trash");
    winfo("/trash", "p", "/work/p", (char *)0, (Str){});
    winfo("/trash", "q", "/work/q", (char *)0, (Str){});
    make_trashed("/trash", "q", "/work/q", (char *)0);
    // A stuck directory standing in for the backup copy of p.
    vmkdir("/trash/files/p");
    vwrite("/trash/files/p/child", "x");
    vchmod("/trash/files/p", 0500);
    Res r = tempty("-f", "--trash-dir", "/trash");
    CK_EQ(r.exit, 0);
    CK_HAS(r.err, "trash-empty: cannot remove /trash/files/p");
    ck_gone("/trash/info/p.trashinfo");
    ck_gone("/trash/info/q.trashinfo");
    ck_present("/trash/files/p/child");
}

// -- Section 9: trash-rm (spec 9) ----------------------------------------------------

static void test_rm_exact_basename(void)
{
    // spec 9.2: non-/ patterns match the basename only.
    mktrash("/xdg/Trash");
    make_trashed("/xdg/Trash", "target", "/work/target.txt", (char *)0);
    make_trashed("/xdg/Trash", "keep", "/work/keep.txt", (char *)0);
    Res r = trm("target.txt");
    CK_EQ(r.exit, 0);
    CK_S(r.out, S(""));
    CK_S(r.err, S(""));
    ck_list("/xdg/Trash/info", "keep.trashinfo", (char *)0);
    ck_list("/xdg/Trash/files", "keep", (char *)0);
}

static void test_rm_glob_pattern(void)
{
    // spec 9.2: fnmatch glob against the basename.
    mktrash("/xdg/Trash");
    char *names[] = {"a.o", "b.o", "c.txt"};
    for (uz i = 0; i < countof(names); i++) {
        make_trashed("/xdg/Trash", names[i], vfmt("/work/%s", names[i]),
                     (char *)0);
    }
    Res r = trm("*.o");
    CK_EQ(r.exit, 0);
    ck_list("/xdg/Trash/info", "c.txt.trashinfo", (char *)0);
}

static void test_rm_absolute_pattern_matches_full_original_location(void)
{
    mktrash("/xdg/Trash");
    make_trashed("/xdg/Trash", "f1", "/some/deep/dir/file", (char *)0);
    make_trashed("/xdg/Trash", "f2", "/some/other", (char *)0);
    Res r = trm("/some/deep/dir/file");
    CK_EQ(r.exit, 0);
    ck_list("/xdg/Trash/info", "f2.trashinfo", (char *)0);
}

static void test_rm_absolute_glob_crosses_slashes(void)
{
    // spec 9.2: fnmatch '*' matches '/' too.
    mktrash("/xdg/Trash");
    make_trashed("/xdg/Trash", "f1", "/some/deep/dir/file", (char *)0);
    Res r = trm("/some/deep/*");
    CK_EQ(r.exit, 0);
    Str names[64];
    CK_EQ(vlist("/xdg/Trash/info", names), 0);
}

static void test_rm_relative_pattern_with_slash_never_matches(void)
{
    // spec 9.2: basenames never contain '/'.
    mktrash("/xdg/Trash");
    make_trashed("/xdg/Trash", "f3", "/some/deep/dir/file", (char *)0);
    Res r = trm("deep/dir");
    CK_EQ(r.exit, 0);
    ck_list("/xdg/Trash/info", "f3.trashinfo", (char *)0);
}

static void test_rm_matching_is_case_sensitive(void)
{
    mktrash("/xdg/Trash");
    make_trashed("/xdg/Trash", "case", "/work/Foo.txt", (char *)0);
    Res r = trm("foo.txt");
    CK_EQ(r.exit, 0);
    ck_list("/xdg/Trash/info", "case.trashinfo", (char *)0);
    r = trm("Foo.txt");
    CK_EQ(r.exit, 0);
    Str names[64];
    CK_EQ(vlist("/xdg/Trash/info", names), 0);
}

static void test_rm_extra_arguments_are_ignored(void)
{
    // spec 9.1: only the first argument is a pattern.
    mktrash("/xdg/Trash");
    make_trashed("/xdg/Trash", "aaa", "/work/aaa", (char *)0);
    make_trashed("/xdg/Trash", "bbb", "/work/bbb", (char *)0);
    Res r = trm("aaa", "bbb");
    CK_EQ(r.exit, 0);
    ck_list("/xdg/Trash/info", "bbb.trashinfo", (char *)0);
}

static void test_rm_no_match_is_silent_success(void)
{
    // spec 9.5: nothing printed whether zero or N matched.
    mktrash("/xdg/Trash");
    make_trashed("/xdg/Trash", "x", "/work/x", (char *)0);
    Res r = trm("nothing-matches-this");
    CK_EQ(r.exit, 0);
    CK_S(r.out, S(""));
    CK_S(r.err, S(""));
}

static void test_rm_empty_pattern_matches_nothing(void)
{
    // spec 9.2 (corrected): an empty pattern matches nothing; the run
    // succeeds and removes nothing.
    Res r = trm("");
    CK_EQ(r.exit, 0);
    mktrash("/xdg/Trash");
    make_trashed("/xdg/Trash", "x", "/work/x", (char *)0);
    r = trm("");
    CK_EQ(r.exit, 0);
    CK_S(r.out, S(""));
    CK_S(r.err, S(""));
    ck_list("/xdg/Trash/info", "x.trashinfo", (char *)0);
    ck_list("/xdg/Trash/files", "x", (char *)0);
}

static void test_rm_unparseable_path_is_reported_and_skipped(void)
{
    // spec 9.5: "unable to parse 'Path'" on stderr, continue.
    mktrash("/xdg/Trash");
    winfo("/xdg/Trash", "nopath", (char *)0, (char *)0,
          S("[Trash Info]\nDeletionDate=2020-01-01T00:00:00\n"));
    make_trashed("/xdg/Trash", "good", "/work/good", (char *)0);
    Res r = trm("*");
    CK_EQ(r.exit, 0);
    CK_S(r.err, S("trash-rm: /xdg/Trash/info/nopath.trashinfo: "
                  "unable to parse 'Path'\n"));
    ck_list("/xdg/Trash/info", "nopath.trashinfo", (char *)0);
}

static void test_rm_non_utf8_trashinfo_is_skipped(void)
{
    // spec 9.5 (corrected): an unparsable trashinfo gets a warning naming
    // the file, is skipped, and nothing is removed.
    mktrash("/xdg/Trash");
    winfo("/xdg/Trash", "bin", (char *)0, (char *)0,
          S("[Trash Info]\nPath=/x\xffy\n"));
    wbackup("/xdg/Trash", "bin", "data");
    Res r = trm("*");
    CK_EQ(r.exit, 0);
    CK_HAS(r.err, "/xdg/Trash/info/bin.trashinfo");
    ck_list("/xdg/Trash/info", "bin.trashinfo", (char *)0);
    ck_list("/xdg/Trash/files", "bin", (char *)0);
}

static void test_rm_orphans_are_untouched(void)
{
    // spec 9.4: iteration is over info/ only.
    mktrash("/xdg/Trash");
    wbackup("/xdg/Trash", "orphan", "data");
    make_trashed("/xdg/Trash", "x", "/work/x", (char *)0);
    Res r = trm("*");
    CK_EQ(r.exit, 0);
    ck_list("/xdg/Trash/files", "orphan", (char *)0);
}

static void test_rm_removes_volume_trash_entries(void)
{
    // spec 4.3: .Trash-$uid on TRASH_VOLUMES volumes is scanned.
    char *trash = volume_trash(2, VUID);
    make_trashed(trash, "v", "volfile", (char *)0);
    Res r = trm("volfile");
    CK_EQ(r.exit, 0);
    Str names[64];
    CK_EQ(vlist(vfmt("%s/info", trash), names), 0);
}

static void test_rm_dangling_backup_copy_is_removed(void)
{
    // spec 9.4: lexists-based removal takes dangling symlinks.
    mktrash("/xdg/Trash");
    winfo("/xdg/Trash", "d", "/work/d", (char *)0, (Str){});
    vsymlink("/gone-target", "/xdg/Trash/files/d");
    Res r = trm("d");
    CK_EQ(r.exit, 0);
    Str names[64];
    CK_EQ(vlist("/xdg/Trash/files", names), 0);
    CK_EQ(vlist("/xdg/Trash/info", names), 0);
}

// -- Review fixes: memory safety and crashes ---------------------------------

// A trashed directory with several nested subdirectories: the recursive
// removal must hold on to every sibling name while it descends.
static void nested_dir(char *trash, char *stem)
{
    mktrash(trash);
    winfo(trash, stem, vfmt("/work/%s", stem), (char *)0, (Str){});
    char *names[] = {"alpha", "bravo", "charlie", "delta", "echo", "foxtrot",
                     "golf"};
    for (uz i = 0; i < countof(names); i++) {
        vwrite(vfmt("%s/files/%s/%s/inner/deep/f", trash, stem, names[i]), "x");
        vwrite(vfmt("%s/files/%s/%s/g", trash, stem, names[i]), "y");
    }
}

static void test_rm_removes_nested_directory_completely(void)
{
    nested_dir("/xdg/Trash", "D");
    Res r = trm("D");
    CK_EQ(r.exit, 0);
    CK_S(r.err, S(""));
    ck_gone("/xdg/Trash/files/D");
    ck_gone("/xdg/Trash/info/D.trashinfo");
}

static void test_empty_removes_nested_directory_completely(void)
{
    nested_dir("/xdg/Trash", "D");
    Res r = tempty("-f");
    CK_EQ(r.exit, 0);
    CK_S(r.err, S(""));
    ck_gone("/xdg/Trash/files/D");
    ck_gone("/xdg/Trash/info/D.trashinfo");
}

// A symlink whose target has more components than the path using it.
static void test_put_through_symlink_with_deep_target(void)
{
    vmkdir("/deep/a/b/c/d/e/f/g/h/i/j/k/l");
    vsymlink("/deep/a/b/c/d/e/f/g/h/i/j/k/l", "/work/l2");
    vwrite("/deep/a/b/c/d/e/f/g/h/i/j/k/l/file", "data");
    Res r = tput("l2/file");
    CK_EQ(r.exit, 0);
    CK_S(r.err, S(""));
    ck_gone("/deep/a/b/c/d/e/f/g/h/i/j/k/l/file");
    ck_present("/xdg/Trash/files/file");
    Str info = vread("/xdg/Trash/info/file.trashinfo");
    CK_HAS(info, "Path=/deep/a/b/c/d/e/f/g/h/i/j/k/l/file\n");
}

static void test_put_trash_dir_through_deep_symlink(void)
{
    vmkdir("/deep/a/b/c/d/e/f/g/h/i/j/k/l/t");
    vsymlink("/deep/a/b/c/d/e/f/g/h/i/j/k/l", "/work/l2");
    vwrite("/work/file", "data");
    Res r = tput("--trash-dir", "l2/t", "file");
    CK_EQ(r.exit, 0);
    CK_S(r.err, S(""));
    ck_present("/deep/a/b/c/d/e/f/g/h/i/j/k/l/t/files/file");
}

// The 64-volume cap is gone: a trash dir on the 150th mount is found.
static void test_volumes_beyond_sixty_four_are_scanned(void)
{
    envdel("TRASH_VOLUMES");
    for (i32 i = 0; i < 200; i++) {
        char *m = vfmt("/m%d", i);
        vmkdir(m);
        addmount(m, 10 + i);
    }
    addmount("/m7", 99);   // a duplicate mount point is listed once
    mktrash("/m150/.Trash-1000");
    make_trashed("/m150/.Trash-1000", "far", "far", "2001-02-03T04:05:06");
    Res r = tlist("--volumes");
    CK_EQ(r.exit, 0);
    iz lines = 0;
    for (iz i = 0; i < r.out.len; i++) {
        lines += r.out.data[i] == '\n';
    }
    CK_EQ(lines, 201);   // "/" and 200 mounts
    CK_HAS(r.out, "/m199\n");
    r = tlist();
    CK_EQ(r.exit, 0);
    CK_S(r.out, S("2001-02-03 04:05:06 /m150/far\n"));
}

static void test_restore_in_deleted_cwd_fails_cleanly(void)
{
    mktrash("/xdg/Trash");
    make_trashed("/xdg/Trash", "a", "/work/a", "2001-02-03T04:05:06");
    setcwd("");
    Res r = trestore();
    CK_EQ(r.exit, 1);
    CK_S(r.err, S("trash-restore: [Errno 2] No such file or directory\n"));
    CK_S(r.out, S(""));
}

// -- Review fixes: trash-put ---------------------------------------------------

static void test_put_retries_next_suffix_when_info_exists(void)
{
    // A stale info file (no backup copy), or anything else already holding
    // the name, only sends the search on to the next suffix.
    mktrash("/xdg/Trash");
    winfo("/xdg/Trash", "f", "/elsewhere/f", (char *)0, (Str){});
    vmkdir("/xdg/Trash/info/g.trashinfo");
    vwrite("/work/f", "one");
    vwrite("/work/g", "two");
    Res r = tput("f", "g");
    CK_EQ(r.exit, 0);
    CK_S(r.err, S(""));
    ck_contents("/xdg/Trash/files/f_1", "one");
    ck_contents("/xdg/Trash/files/g_1", "two");
    ck_present("/xdg/Trash/info/f_1.trashinfo");
    ck_present("/xdg/Trash/info/g_1.trashinfo");
}

static void test_put_hard_info_error_is_reported(void)
{
    // EACCES cannot be fixed by another name: stop, with upstream's words.
    mktrash("/xdg/Trash");
    vchmod("/xdg/Trash/info", 0500);
    vchmod("/", 0555);   // no .Trash-1000 on the root volume to fall back on
    vwrite("/work/f", "one");
    Res r = tput("f");
    CK_EQ(r.exit, 74);
    CK_HAS(r.err, "failed to create trashinfo file: [Errno 13] Permission "
                  "denied: '/xdg/Trash/info/f.trashinfo'");
    ck_present("/work/f");
}

static void test_put_move_error_reports_the_copy_failure(void)
{
    // The rename fails, the fallback copy fails on the destination: that
    // error is the one reported, with the errno the kernel gave.
    mktrash("/xdg/Trash");
    vchmod("/xdg/Trash/files", 0500);
    vchmod("/", 0555);
    vwrite("/work/f", "one");
    Res r = tput("f");
    CK_EQ(r.exit, 74);
    CK_HAS(r.err, "failed to move f in /xdg/Trash/files: [Errno 13] "
                  "Permission denied: '/xdg/Trash/files/f'");
    ck_present("/work/f");
    ck_gone("/xdg/Trash/info/f.trashinfo");
}

static void test_put_across_devices_copies_and_removes(void)
{
    // rename(2) says EXDEV; shutil.move copies then removes the original.
    addmount("/vol", 2);
    vwrite("/vol/f", "data");
    vwrite("/vol/d/sub/x", "deep");
    vsymlink("/target", "/vol/lnk");
    Res r = tput("--force-volume", "/", "/vol/f", "/vol/d", "/vol/lnk");
    CK_EQ(r.exit, 0);
    CK_S(r.err, S(""));
    ck_gone("/vol/f");
    ck_gone("/vol/d");
    ck_gone("/vol/lnk");
    ck_contents("/xdg/Trash/files/f", "data");
    ck_contents("/xdg/Trash/files/d/sub/x", "deep");
    CK_S(vlinkto("/xdg/Trash/files/lnk"), S("/target"));
}

static void test_put_vv_shows_each_candidates_volume(void)
{
    addmount("/vol", 2);
    vwrite("/vol/f", "x");
    Res r = tput("-vv", "--force-volume", "/vol", "/vol/f");
    CK_EQ(r.exit, 0);
    // the home trash lives on "/", the method candidates on the file's volume
    CK_HAS(r.err, "trying trash dir: /xdg/Trash from volume: /\n");
    vwrite("/vol/f2", "x");
    r = tput("-vv", "--trash-dir", "/vol/mytrash", "/vol/f2");
    CK_HAS(r.err, "trying trash dir: /vol/mytrash from volume: /vol\n");
    // normalized, as upstream prints it
    vwrite("/work/g", "x");
    envset("XDG_DATA_HOME", "/xdg/");
    r = tput("-vv", "g");
    CK_HAS(r.err, "trying trash dir: /xdg/Trash from volume: /\n");
}

static void test_put_root_volume_paths_have_no_double_slash(void)
{
    envdel("XDG_DATA_HOME");
    envdel("HOME");
    vwrite("/work/f", "x");
    Res r = tput("-vv", "--force-volume", "/", "f");
    CK_EQ(r.exit, 0);
    CK_HAS(r.err, "trying trash dir: /.Trash/1000 from volume: /\n");
    CK_NOHAS(r.err, "//");
    ck_present("/.Trash-1000/files/f");
    Res v = tput("-v", "--force-volume", "/", "f");
    CK_HAS(v.err, "cannot trash non existent 'f'");
}

static void test_put_empty_trash_dir_and_force_volume_are_unset(void)
{
    vwrite("/work/f", "x");
    vwrite("/work/g", "x");
    Res r = tput("--trash-dir", "", "f");
    CK_EQ(r.exit, 0);
    ck_present("/xdg/Trash/files/f");
    r = tput("--force-volume", "", "g");
    CK_EQ(r.exit, 0);
    ck_present("/xdg/Trash/files/g");
}

static void test_put_interactive_prompt_precedes_permission_check(void)
{
    vwrite("/work/ro/g", "x");
    vchmod("/work/ro", 0555);
    setstdin("y\n");
    Res r = tput("-i", "ro/g");
    CK_EQ(r.exit, 74);
    CK_HAS(r.out, "trash-put: trash regular file 'ro/g'? ");
    CK_HAS(r.err, "cannot trash regular file 'ro/g' because deleting it is "
                  "not allowed");
}

static void test_put_message_escapes_invalid_utf8(void)
{
    // stderr shows undecodable bytes the way Python's surrogateescape does.
    Res r = tput("bad\xff" "name");
    CK_EQ(r.exit, 74);
    CK_HAS(r.err, "cannot trash non existent 'bad\\udcffname'");
}

static void test_put_parents_of_trash_dir_follow_the_umask(void)
{
    envdel("XDG_DATA_HOME");
    vwrite("/work/f", "x");
    Res r = tput("f");
    CK_EQ(r.exit, 0);
    // only the leaf is private; the parents get the default mode
    ck_mode("/home/.local", 0777);
    ck_mode("/home/.local/share", 0777);
    ck_mode("/home/.local/share/Trash", 0700);
    ck_mode("/home/.local/share/Trash/files", 0700);
}

static void test_put_long_name_retries_with_first_suffix(void)
{
    char name[256];
    for (i32 i = 0; i < 255; i++) {
        name[i] = 'a';
    }
    name[255] = 0;
    vwrite(vfmt("/work/%s", name), "x");
    Res r = tput(name);
    CK_EQ(r.exit, 0);
    CK_S(r.err, S(""));
    char stem[256];
    for (i32 i = 0; i < 243; i++) {
        stem[i] = 'a';
    }
    stem[243] = 0;
    ck_present(vfmt("/xdg/Trash/files/%s_1", stem));
    ck_present(vfmt("/xdg/Trash/info/%s_1.trashinfo", stem));
}

static void test_put_vv_logs_failed_info_attempts(void)
{
    mktrash("/xdg/Trash");
    winfo("/xdg/Trash", "f", "/elsewhere/f", (char *)0, (Str){});
    vwrite("/work/f", "x");
    Res r = tput("-vv", "f");
    CK_EQ(r.exit, 0);
    CK_HAS(r.err, "attempt for creating /xdg/Trash/info/f.trashinfo failed.");
    CK_HAS(r.err, ".trashinfo created as /xdg/Trash/info/f_1.trashinfo.");
}

// -- Review fixes: trash-list and trash-restore ---------------------------------

static void test_list_trash_dir_uses_its_volume(void)
{
    // put records a volume-relative Path=; the listing joins it back.
    addmount("/vol", 2);
    vwrite("/vol/agt/sub/g", "x");
    CK_EQ(tput("--trash-dir", "/vol/.Trash-1000", "/vol/agt/sub/g").exit, 0);
    CK_HAS(vread("/vol/.Trash-1000/info/g.trashinfo"), "Path=agt/sub/g\n");
    Res r = tlist("--trash-dir", "/vol/.Trash-1000");
    CK_EQ(r.exit, 0);
    CK_HAS(r.out, " /vol/agt/sub/g\n");
}

static void test_restore_trash_dir_uses_its_volume(void)
{
    addmount("/vol", 2);
    vwrite("/vol/agt/sub/g", "x");
    CK_EQ(tput("--trash-dir", "/vol/.Trash-1000", "/vol/agt/sub/g").exit, 0);
    ck_gone("/vol/agt/sub/g");
    setstdin("0\n");
    Res r = trestore("--trash-dir", "/vol/.Trash-1000", "/");
    CK_EQ(r.exit, 0);
    CK_S(r.err, S(""));
    CK_HAS(r.out, " /vol/agt/sub/g\n");
    ck_contents("/vol/agt/sub/g", "x");
}

static void test_restore_home_trash_on_a_mount_uses_the_mount_point(void)
{
    // upstream restore joins the home trash's relative Path= with the home
    // trash's volume; trash-list uses "/" for it (both reproduced).
    addmount("/vol", 2);
    envset("XDG_DATA_HOME", "/vol/h");
    mktrash("/vol/h/Trash");
    make_trashed("/vol/h/Trash", "r", "rel/h", "2001-02-03T04:05:06");
    Res r = tlist();
    CK_HAS(r.out, "2001-02-03 04:05:06 /rel/h\n");
    setcwd("/vol");
    setstdin("\n");
    r = trestore();
    CK_HAS(r.out, "   0 2001-02-03 04:05:06 /vol/rel/h\n");
}

static void test_restore_sort_path_uses_location_plus_date(void)
{
    // upstream sorts on original_location + str(date): " " < "." < "2"
    mktrash("/xdg/Trash");
    make_trashed("/xdg/Trash", "p1", "/work/a", "2001-01-01T00:00:00");
    make_trashed("/xdg/Trash", "p2", "/work/a.txt", "2001-01-01T00:00:00");
    make_trashed("/xdg/Trash", "p3", "/work/a b", "2001-01-01T00:00:00");
    setstdin("\n");
    Res r = trestore("--sort", "path");
    CK_EQ(r.exit, 0);
    Str lines[32];
    iz n = vlines(r.out, lines);
    CK_EQ(n, 4);
    CK_S(linepath_restore(lines[0]), S("/work/a b"));
    CK_S(linepath_restore(lines[1]), S("/work/a.txt"));
    CK_S(linepath_restore(lines[2]), S("/work/a"));
}

static void test_restore_sort_is_stable_over_many_entries(void)
{
    mktrash("/xdg/Trash");
    for (i32 i = 0; i < 100; i++) {
        make_trashed("/xdg/Trash", vfmt("e%03d", i), vfmt("/work/f%03d", i),
                     vfmt("2001-01-%02dT00:00:00", 1 + (i * 7) % 28));
    }
    setstdin("\n");
    Res r = trestore();
    CK_EQ(r.exit, 0);
    Str lines[128];
    Str rest = r.out;
    iz n = 0;
    for (;;) {
        Cut ln = cut(rest, '\n');
        if (!ln.ok) {
            break;
        }
        CK(n < 128);
        lines[n++] = ln.head;
        rest = ln.tail;
    }
    CK_EQ(n, 101);   // 100 entries, then "No files were restored"
    for (iz i = 1; i < 100; i++) {
        Str d0 = takehead(cuthead(lines[i-1], 5), 10);
        Str d1 = takehead(cuthead(lines[i], 5), 10);
        CK(cmpstr_test(d0, d1) <= 0);
    }
}

static void test_restore_normalizes_path(void)
{
    mktrash("/xdg/Trash");
    make_trashed("/xdg/Trash", "d1", "/work/d/", "2001-01-01T00:00:00");
    make_trashed("/xdg/Trash", "d2", "/work/d/../d4", "2001-01-01T00:00:00");
    setstdin("\n");
    Res r = trestore();
    CK_EQ(r.exit, 0);
    CK_HAS(r.out, " /work/d\n");
    CK_HAS(r.out, " /work/d4\n");
    CK_NOHAS(r.out, "/work/d/");
    r = trestore("/work/d4");
    CK_HAS(r.out, " /work/d4\n");
}

static void test_restore_volume_with_trailing_slash(void)
{
    envset("TRASH_VOLUMES", "/vol/");
    mktrash("/vol/.Trash-1000");
    make_trashed("/vol/.Trash-1000", "v", "work/v", "2001-01-01T00:00:00");
    Res r = tlist("--trash-dirs");
    CK_HAS(r.out, "/vol/.Trash-1000\n");
    CK_NOHAS(r.out, "//");
    setcwd("/vol/work");
    setstdin("\n");
    r = trestore();
    CK_EQ(r.exit, 0);
    CK_S(r.err, S(""));
    CK_HAS(r.out, " /vol/work/v\n");
}

static void test_list_size_and_files_are_independent(void)
{
    mktrash("/trash");
    winfo("/trash", "s", "/work/s", "2001-02-03T04:05:06", (Str){});
    wbackup("/trash", "s", "12345");
    Res r = tlist("--trash-dir", "/trash", "--size");
    CK_S(r.out, S("5 /work/s\n"));
    r = tlist("--trash-dir", "/trash", "--files");
    CK_S(r.out, S("2001-02-03 04:05:06 /work/s -> /trash/files/s\n"));
    r = tlist("--trash-dir", "/trash", "--size", "--files");
    CK_S(r.out, S("5 /work/s -> /trash/files/s\n"));
    r = tlist("--trash-dir", "/trash", "--files", "--size");
    CK_S(r.out, S("5 /work/s -> /trash/files/s\n"));
}

static void test_list_size_of_dangling_backup_is_zero(void)
{
    mktrash("/trash");
    winfo("/trash", "d", "/work/d", "2001-02-03T04:05:06", (Str){});
    vsymlink("/gone", "/trash/files/d");
    Res r = tlist("--trash-dir", "/trash", "--size");
    CK_EQ(r.exit, 0);
    CK_S(r.out, S("0 /work/d\n"));
    // a backup that is not even a symlink is fatal
    winfo("/trash", "m", "/work/m", "2001-02-03T04:05:06", (Str){});
    r = tlist("--trash-dir", "/trash", "--size");
    CK_EQ(r.exit, 1);
}

static void test_list_tty_quoting_follows_upstream(void)
{
    v->istty[1] = 1;
    mktrash("/trash");
    make_trashed("/trash", "q1", "/work/caf\xc3\xa9", "2001-01-01T00:00:00");
    make_trashed("/trash", "q2", "/work/a%0Ab", "2001-01-01T00:00:00");
    make_trashed("/trash", "q3", "/work/it's", "2001-01-01T00:00:00");
    make_trashed("/trash", "q4", "/work/x%y+z", "2001-01-01T00:00:00");
    make_trashed("/trash", "q5", "/work/a%FFb", "2001-01-01T00:00:00");
    make_trashed("/trash", "q6", "/work/tab\there", "2001-01-01T00:00:00");
    Res r = tlist("--trash-dir", "/trash");
    CK_EQ(r.exit, 0);
    CK_HAS(r.out, " '/work/caf\xc3\xa9'\n");
    CK_HAS(r.out, " '/work/a'$'\\n''b'\n");
    CK_HAS(r.out, " '/work/it'\\''s'\n");
    CK_HAS(r.out, " /work/x%y+z\n");
    CK_HAS(r.out, " '/work/a'$'\\xff''b'\n");
    CK_HAS(r.out, " '/work/tab'$'\\t''here'\n");
}

static void test_restore_overwrite_refuses_symlink_to_directory(void)
{
    mktrash("/xdg/Trash");
    make_trashed("/xdg/Trash", "t", "/work/t", "2001-01-01T00:00:00");
    vmkdir("/somedir");
    vsymlink("/somedir", "/work/t");
    setstdin("0\n");
    Res r = trestore("--overwrite");
    CK_EQ(r.exit, 1);
    CK_HAS(r.err, "Refusing to overwrite existing file \"t\".");
    CK_S(vlinkto("/work/t"), S("/somedir"));
}

static void test_restore_prompt_grammar_errors(void)
{
    mktrash("/xdg/Trash");
    for (i32 i = 0; i < 3; i++) {
        make_trashed("/xdg/Trash", vfmt("g%d", i), vfmt("/work/g%d", i),
                     vfmt("2001-01-0%dT00:00:00", i + 1));
    }
    struct { char *in, *err; } cases[] = {
        {"1,\n",       "Invalid entry: not an index: \n"},
        {"1,,2\n",     "Invalid entry: not an index: \n"},
        {"  \n",       "Invalid entry: not an index:   \n"},
        {"1-9\n",      "Invalid entry: out of range 0..2: 3\n"},
        {"1-2-3\n",    "Invalid entry: not an index: 2-3\n"},
        {"x,9\n",      "Invalid entry: not an index: x\n"},
        {"9,x\n",      "Invalid entry: not an index: x\n"},
        {"-1\n",       "Invalid entry: open interval: -1\n"},
        {" 1-\n",      "Invalid entry: open interval:  1-\n"},
        {"007\n",      "Invalid entry: out of range 0..2: 7\n"},
        {"99999999999999999999999\n",
                       "Invalid entry: out of range 0..2: 99999999999999999999999\n"},
        {"1 - 2\n",    "Invalid entry: out of range"},   // int() trims: 1..2 ok?
    };
    for (uz i = 0; i + 1 < countof(cases); i++) {
        setstdin(cases[i].in);
        Res r = trestore();
        CK_EQ(r.exit, 1);
        CK_S(r.err, import((u8 *)cases[i].err));
    }
    // int() tolerates whitespace, signs, underscores and other scripts
    setstdin(" +1_0 \n");
    Res r = trestore();
    CK_S(r.err, S("Invalid entry: out of range 0..2: 10\n"));
    setstdin("\xd9\xa1\n");   // ARABIC-INDIC DIGIT ONE
    r = trestore();
    CK_EQ(r.exit, 0);
    ck_present("/work/g1");
}

static void test_restore_prompt_restores_in_order_asked_without_repeats(void)
{
    mktrash("/xdg/Trash");
    for (i32 i = 0; i < 3; i++) {
        make_trashed("/xdg/Trash", vfmt("o%d", i), vfmt("/work/o%d", i),
                     vfmt("2001-01-0%dT00:00:00", i + 1));
        vwrite(vfmt("/work/o%d", i), "in the way");
    }
    setstdin("2,0,2,1-2\n");
    Res r = trestore();
    CK_EQ(r.exit, 1);
    CK_S(r.err, S("Refusing to overwrite existing file \"o2\".\n"
                  "Refusing to overwrite existing file \"o0\".\n"
                  "Refusing to overwrite existing file \"o1\".\n"));
    // an empty range selects nothing
    setstdin("2-1\n");
    r = trestore();
    CK_EQ(r.exit, 0);
    CK_S(r.err, S(""));
}

static void test_restore_errors_have_no_prefix(void)
{
    mktrash("/xdg/Trash");
    make_trashed("/xdg/Trash", "n", "/ro/n", "2001-01-01T00:00:00");
    vmkdir("/ro");
    vchmod("/ro", 0555);
    setcwd("/ro");
    setstdin("0\n");
    Res r = trestore();
    CK_EQ(r.exit, 1);
    CK_S(r.err, S("[Errno 13] Permission denied: '/ro/n'\n"));
    ck_present("/xdg/Trash/info/n.trashinfo");
    // a file where a directory should be: makedirs' own error
    vwrite("/blocker", "x");
    make_trashed("/xdg/Trash", "m", "/blocker/sub/m", "2001-01-02T00:00:00");
    setcwd("/blocker");
    setstdin("0\n");
    r = trestore();
    CK_EQ(r.exit, 1);
    CK_HAS(r.err, "[Errno 20] Not a directory: '/blocker/sub'");
}

static void test_restore_prompt_carriage_return_is_not_empty(void)
{
    mktrash("/xdg/Trash");
    make_trashed("/xdg/Trash", "c", "/work/c", "2001-01-01T00:00:00");
    setstdin("\r\n");
    Res r = trestore();
    CK_EQ(r.exit, 1);
    CK_S(r.err, S("Invalid entry: not an index: \r\n"));
    setstdin("0\r\n");   // int() trims the \r
    r = trestore();
    CK_EQ(r.exit, 0);
    ck_present("/work/c");
}

static void test_restore_reports_undecodable_trashinfo_like_python(void)
{
    mktrash("/xdg/Trash");
    winfo("/xdg/Trash", "bad", (char *)0, (char *)0,
          (Str){(u8 *)"[Trash Info]\nPath=/x\xff\n", 21});
    winfo("/xdg/Trash", "trunc", (char *)0, (char *)0,
          (Str){(u8 *)"Path=/x\xe2\x82", 9});
    winfo("/xdg/Trash", "cont", (char *)0, (char *)0,
          (Str){(u8 *)"Path=/x\xe2\x41y", 10});
    setstdin("\n");
    Res r = trestore();
    CK_EQ(r.exit, 0);
    CK_HAS(r.err, "Non parsable trashinfo file: /xdg/Trash/info/bad.trashinfo, "
                  "because 'utf-8' codec can't decode byte 0xff in position "
                  "20: invalid start byte\n");
    CK_HAS(r.err, "trunc.trashinfo, because 'utf-8' codec can't decode bytes "
                  "in position 7-8: unexpected end of data\n");
    CK_HAS(r.err, "cont.trashinfo, because 'utf-8' codec can't decode byte "
                  "0xe2 in position 7: invalid continuation byte\n");
}

static void test_restore_listing_escapes_invalid_bytes(void)
{
    mktrash("/xdg/Trash");
    winfo("/xdg/Trash", "e", "/work/a%FFb", "2001-01-01T00:00:00", (Str){});
    wbackup("/xdg/Trash", "e", "x");
    setstdin("\n");
    Res r = trestore();
    CK_HAS(r.out, " /work/a\\xffb\n");
}

static void test_restore_reports_unreadable_trashinfo_like_python(void)
{
    mktrash("/xdg/Trash");
    make_trashed("/xdg/Trash", "a", "/work/a", "2001-01-01T00:00:00");
    vchmod("/xdg/Trash/info/a.trashinfo", 0);
    setstdin("\n");
    Res r = trestore();
    CK_EQ(r.exit, 0);
    CK_HAS(r.err, "IOErrorReadingTrashInfo(path='/xdg/Trash/info/a.trashinfo',"
                  " error=\"[Errno 13] Permission denied: "
                  "'/xdg/Trash/info/a.trashinfo'\")\n");
}

static void test_restore_overwrite_across_devices(void)
{
    addmount("/vol", 2);
    mktrash("/xdg/Trash");
    make_trashed("/xdg/Trash", "x", "/vol/x", "2001-01-01T00:00:00");
    vwrite("/vol/x", "old");
    setcwd("/vol");
    setstdin("0\n");
    Res r = trestore("--overwrite");
    CK_EQ(r.exit, 0);
    CK_S(r.err, S(""));
    ck_contents("/vol/x", "data");
    ck_gone("/xdg/Trash/files/x");
    ck_gone("/xdg/Trash/info/x.trashinfo");
}

// -- Review fixes: trash-empty and trash-rm -------------------------------------

static void test_rm_star_pattern_matches_names_containing_a_star(void)
{
    mktrash("/xdg/Trash");
    make_trashed("/xdg/Trash", "s1", "/d/*!", (char *)0);
    make_trashed("/xdg/Trash", "s2", "/d/*b", (char *)0);
    make_trashed("/xdg/Trash", "s3", "/d/plain", (char *)0);
    Res r = trm("*");
    CK_EQ(r.exit, 0);
    Str names[64];
    CK_EQ(vlist("/xdg/Trash/info", names), 0);
}

static void test_rm_matches_characters_not_bytes(void)
{
    mktrash("/xdg/Trash");
    make_trashed("/xdg/Trash", "u1", "/d/\xc3\xa9", (char *)0);      // é
    make_trashed("/xdg/Trash", "u2", "/d/\xc3\xbcn\xc3\xa9.txt", (char *)0);
    make_trashed("/xdg/Trash", "u3", "/d/\xc3\xa9\xc3\xbcx", (char *)0);
    make_trashed("/xdg/Trash", "u4", "/d/z", (char *)0);
    CK_EQ(trm("?").exit, 0);                 // one character: é and z
    ck_gone("/xdg/Trash/info/u1.trashinfo");
    ck_gone("/xdg/Trash/info/u4.trashinfo");
    ck_present("/xdg/Trash/info/u2.trashinfo");
    CK_EQ(trm("\xc3\xbcn?.txt").exit, 0);    // ün?.txt
    ck_gone("/xdg/Trash/info/u2.trashinfo");
    CK_EQ(trm("??x").exit, 0);
    ck_gone("/xdg/Trash/info/u3.trashinfo");
    make_trashed("/xdg/Trash", "u5", "/d/\xc3\xa9", (char *)0);
    CK_EQ(trm("[\xc3\xa0-\xc3\xbc]").exit, 0);   // [à-ü]
    ck_gone("/xdg/Trash/info/u5.trashinfo");
}

static void test_rm_reports_removal_failures_and_exits_1(void)
{
    mktrash("/xdg/Trash");
    make_trashed("/xdg/Trash", "a", "/d/a", (char *)0);
    vchmod("/xdg/Trash/info", 0555);
    Res r = trm("a");
    CK_EQ(r.exit, 1);
    CK_S(r.err, S("trash-rm: cannot remove /xdg/Trash/info/a.trashinfo: "
                  "[Errno 13] Permission denied\n"));
    ck_gone("/xdg/Trash/files/a");
    ck_present("/xdg/Trash/info/a.trashinfo");
    // a backup that cannot be removed keeps its info file, and the next
    // entries are still handled
    vchmod("/xdg/Trash/info", 0755);
    vchmod("/xdg/Trash/files", 0555);
    make_trashed("/xdg/Trash", "b", "/d/b", (char *)0);
    r = trm("[ab]");
    CK_EQ(r.exit, 1);
    CK_HAS(r.err, "trash-rm: cannot remove /xdg/Trash/files/b: [Errno 13]");
    ck_present("/xdg/Trash/info/b.trashinfo");
    ck_gone("/xdg/Trash/info/a.trashinfo");
}

static void test_empty_rm_and_list_skip_a_trash_dir_behind_an_unreadable_parent(void)
{
    vmkdir("/locked/x/Trash/info");
    vwrite("/locked/x/Trash/info/a.trashinfo",
           "[Trash Info]\nPath=/d/a\nDeletionDate=2001-01-01T00:00:00\n");
    vchmod("/locked", 0);
    envset("XDG_DATA_HOME", "/locked/x");
    Res r = tempty("-f");
    CK_EQ(r.exit, 0);
    CK_S(r.err, S(""));
    r = trm("a");
    CK_EQ(r.exit, 0);
    CK_S(r.err, S(""));
    r = tlist();
    CK_EQ(r.exit, 0);
    CK_S(r.err, S(""));
}

static void test_empty_warns_about_a_bad_trash_date_per_trashinfo(void)
{
    mktrash("/xdg/Trash");
    make_trashed("/xdg/Trash", "a", "/d/a", "2001-01-01T00:00:00");
    make_trashed("/xdg/Trash", "b", "/d/b", (char *)0);       // no date
    make_trashed("/xdg/Trash", "c", "/d/c", "garbage");       // bad date
    envset("TRASH_DATE", "bogus");
    Res r = tempty("-f", "30");
    CK_EQ(r.exit, 0);
    CK_S(r.err, S("trash-empty: invalid TRASH_DATE: bogus\n"
                  "trash-empty: invalid TRASH_DATE: bogus\n"
                  "trash-empty: invalid TRASH_DATE: bogus\n"));
    // without days the clock is never read
    r = tempty("-f");
    CK_S(r.err, S(""));
}

static void test_empty_print_time_warns_about_a_bad_trash_date(void)
{
    envset("TRASH_DATE", "bogus");
    Res r = tempty("--print-time");
    CK_EQ(r.exit, 0);
    CK_S(r.out, S("2026-06-01T12:00:00\n"));
    CK_S(r.err, S("trash-empty: invalid TRASH_DATE: bogus\n"));
}

// -- Review fixes: shared parsing -------------------------------------------------

static void test_deletion_dates_follow_strptime(void)
{
    mktrash("/trash");
    struct { char *date, *want; } cases[] = {
        {"2020-1-2T3:4:5",        "2020-01-02 03:04:05"},
        {"2020-01- 2T03:04:05",   "2020-01-02 03:04:05"},
        {"2020-01-02t03:04:05",   "2020-01-02 03:04:05"},
        {"\xd9\xa2\xd9\xa0\xd9\xa2\xd9\xa0-01-02T03:04:05",
                                  "2020-01-02 03:04:05"},   // Arabic-Indic
        {"0000-01-02T03:04:05",   "\?\?\?\?-\?\?-\?\? \?\?:\?\?:\?\?"},
        {"2020-01-02T03:04:60",   "\?\?\?\?-\?\?-\?\? \?\?:\?\?:\?\?"},
        {"2020-02-30T03:04:05",   "\?\?\?\?-\?\?-\?\? \?\?:\?\?:\?\?"},
        {"2020-01-02T03:04:05 ",  "\?\?\?\?-\?\?-\?\? \?\?:\?\?:\?\?"},
        {"2020-01-02T03:04",      "\?\?\?\?-\?\?-\?\? \?\?:\?\?:\?\?"},
        {"2020-01-02T24:00:00",   "\?\?\?\?-\?\?-\?\? \?\?:\?\?:\?\?"},
    };
    for (uz i = 0; i < countof(cases); i++) {
        char *stem = vfmt("d%d", (int)i);
        winfo("/trash", stem, vfmt("/work/%s", stem), cases[i].date, (Str){});
        Res r = tlist("--trash-dir", "/trash");
        CK_HAS_C(r.out, vfmt("%s /work/%s\n", cases[i].want, stem));
    }
}

static void test_days_follows_python_int(void)
{
    mktrash("/xdg/Trash");
    for (char **d = (char *[]){"1_0", " 5 ", "+5", "\xd9\xa5", "007", 0}; *d;
         d++) {
        make_trashed("/xdg/Trash", "o", "/work/o", "2000-01-01T00:00:00");
        Res r = tempty("-f", *d);
        CK_EQ(r.exit, 0);
        ck_gone("/xdg/Trash/info/o.trashinfo");
    }
    CK_EQ(tempty("1__0").exit, 2);
    CK_EQ(tempty("_1").exit, 2);
    CK_EQ(tempty("1_").exit, 2);
    CK_EQ(tempty("1.5").exit, 2);
}

static void test_trash_date_follows_strptime_and_is_not_trimmed(void)
{
    envset("TRASH_DATE", "2020-1-2T3:4:5");
    Res r = tempty("--print-time");
    CK_S(r.out, S("2020-01-02T03:04:05\n"));
    CK_S(r.err, S(""));
    envset("TRASH_DATE", " 2020-01-02T03:04:05");
    r = tempty("--print-time");
    CK_S(r.out, S("2026-06-01T12:00:00\n"));
    CK_S(r.err, S("trash-empty: invalid TRASH_DATE:  2020-01-02T03:04:05\n"));
    envset("TRASH_DATE", "0000-01-02T03:04:05");
    r = tempty("--print-time");
    CK_S(r.out, S("2026-06-01T12:00:00\n"));
    CK_HAS(r.err, "invalid TRASH_DATE: 0000-01-02T03:04:05");
}

static void test_trashinfo_lines_end_at_any_newline_style(void)
{
    mktrash("/trash");
    Str cr = S("[Trash Info]\rPath=/work/cr\rDeletionDate=2001-02-03T04:05:06\r");
    Str crlf = S("[Trash Info]\r\nPath=/work/crlf\r\n"
                 "DeletionDate=2001-02-03T04:05:06\r\n");
    Str mid = S("[Trash Info]\nPath=/work/a\rb\nDeletionDate=2001-02-03T04:05:06\n");
    winfo("/trash", "cr", (char *)0, (char *)0, cr);
    winfo("/trash", "crlf", (char *)0, (char *)0, crlf);
    winfo("/trash", "mid", (char *)0, (char *)0, mid);
    Res r = tlist("--trash-dir", "/trash");
    CK_EQ(r.exit, 0);
    CK_HAS(r.out, "2001-02-03 04:05:06 /work/cr\n");
    CK_HAS(r.out, "2001-02-03 04:05:06 /work/crlf\n");
    CK_HAS(r.out, "2001-02-03 04:05:06 /work/a\n");   // the \r ended the line
}

static void test_restore_refuses_a_path_with_an_embedded_nul(void)
{
    mktrash("/xdg/Trash");
    make_trashed("/xdg/Trash", "z", "/work/a%00b", "2001-02-03T04:05:06");
    setstdin("0\n");
    Res r = trestore();
    CK_EQ(r.exit, 1);
    CK_S(r.err, S("embedded null byte\n"));
    ck_gone("/work/a");
    ck_present("/xdg/Trash/files/z");
    ck_present("/xdg/Trash/info/z.trashinfo");
}

// -- Review fixes: argparse fidelity -------------------------------------------

// generated from Python 3.12.15 argparse running the upstream parsers
typedef struct { char *persona; char *args[6]; i32 cols; i32 exit; char *out; char *err; } ApCase;

static const ApCase apcases[] = {
    {"trash-put", {"-h"}, 80, 0,
        "usage: trash-put [OPTION]... FILE...\n"
        "\n"
        "Put files in trash\n"
        "\n"
        "positional arguments:\n"
        "  files\n"
        "\n"
        "options:\n"
        "  -h, --help            show this help message and exit\n"
        "  --print-completion {bash,zsh,tcsh}\n"
        "                        print shell completion script\n"
        "  -d, --directory       ignored (for GNU rm compatibility)\n"
        "  -f, --force           silently ignore nonexistent files\n"
        "  -i, --interactive     prompt before every removal\n"
        "  -r, -R, --recursive   ignored (for GNU rm compatibility)\n"
        "  --trash-dir TRASHDIR  use TRASHDIR as trash folder\n"
        "  -v, --verbose         explain what is being done\n"
        "  --version             show program's version number and exit\n"
        "\n"
        "all trash-cli commands:\n"
        "  trash-put             trash files and directories.\n"
        "  trash-empty           empty the trashcan(s).\n"
        "  trash-list            list trashed files.\n"
        "  trash-restore         restore a trashed file.\n"
        "  trash-rm              remove individual files from the trashcan\n"
        "\n"
        "To remove a file whose name starts with a '-', for example '-foo',\n"
        "use one of these commands:\n"
        "\n"
        "    trash -- -foo\n"
        "\n"
        "    trash ./-foo\n"
        "\n"
        "Report bugs to https://github.com/andreafrancia/trash-cli/issues\n"
        "",
        ""},
    {"trash-put", {"-h"}, 50, 0,
        "usage: trash-put [OPTION]... FILE...\n"
        "\n"
        "Put files in trash\n"
        "\n"
        "positional arguments:\n"
        "  files\n"
        "\n"
        "options:\n"
        "  -h, --help            show this help message\n"
        "                        and exit\n"
        "  --print-completion {bash,zsh,tcsh}\n"
        "                        print shell completion\n"
        "                        script\n"
        "  -d, --directory       ignored (for GNU rm\n"
        "                        compatibility)\n"
        "  -f, --force           silently ignore\n"
        "                        nonexistent files\n"
        "  -i, --interactive     prompt before every\n"
        "                        removal\n"
        "  -r, -R, --recursive   ignored (for GNU rm\n"
        "                        compatibility)\n"
        "  --trash-dir TRASHDIR  use TRASHDIR as trash\n"
        "                        folder\n"
        "  -v, --verbose         explain what is being\n"
        "                        done\n"
        "  --version             show program's version\n"
        "                        number and exit\n"
        "\n"
        "all trash-cli commands:\n"
        "  trash-put             trash files and directories.\n"
        "  trash-empty           empty the trashcan(s).\n"
        "  trash-list            list trashed files.\n"
        "  trash-restore         restore a trashed file.\n"
        "  trash-rm              remove individual files from the trashcan\n"
        "\n"
        "To remove a file whose name starts with a '-', for example '-foo',\n"
        "use one of these commands:\n"
        "\n"
        "    trash -- -foo\n"
        "\n"
        "    trash ./-foo\n"
        "\n"
        "Report bugs to https://github.com/andreafrancia/trash-cli/issues\n"
        "",
        ""},
    {"trash-put", {"-h"}, 120, 0,
        "usage: trash-put [OPTION]... FILE...\n"
        "\n"
        "Put files in trash\n"
        "\n"
        "positional arguments:\n"
        "  files\n"
        "\n"
        "options:\n"
        "  -h, --help            show this help message and exit\n"
        "  --print-completion {bash,zsh,tcsh}\n"
        "                        print shell completion script\n"
        "  -d, --directory       ignored (for GNU rm compatibility)\n"
        "  -f, --force           silently ignore nonexistent files\n"
        "  -i, --interactive     prompt before every removal\n"
        "  -r, -R, --recursive   ignored (for GNU rm compatibility)\n"
        "  --trash-dir TRASHDIR  use TRASHDIR as trash folder\n"
        "  -v, --verbose         explain what is being done\n"
        "  --version             show program's version number and exit\n"
        "\n"
        "all trash-cli commands:\n"
        "  trash-put             trash files and directories.\n"
        "  trash-empty           empty the trashcan(s).\n"
        "  trash-list            list trashed files.\n"
        "  trash-restore         restore a trashed file.\n"
        "  trash-rm              remove individual files from the trashcan\n"
        "\n"
        "To remove a file whose name starts with a '-', for example '-foo',\n"
        "use one of these commands:\n"
        "\n"
        "    trash -- -foo\n"
        "\n"
        "    trash ./-foo\n"
        "\n"
        "Report bugs to https://github.com/andreafrancia/trash-cli/issues\n"
        "",
        ""},
    {"trash-list", {"-h"}, 80, 0,
        "usage: trash-list [-h] [--print-completion {bash,zsh,tcsh}] [--version]\n"
        "                  [--volumes] [--trash-dirs] [--trash-dir TRASH_DIRS]\n"
        "                  [--all-users]\n"
        "\n"
        "List trashed files\n"
        "\n"
        "options:\n"
        "  -h, --help            show this help message and exit\n"
        "  --print-completion {bash,zsh,tcsh}\n"
        "                        print shell completion script\n"
        "  --version             show program's version number and exit\n"
        "  --volumes             list volumes\n"
        "  --trash-dirs          list trash dirs\n"
        "  --trash-dir TRASH_DIRS\n"
        "                        specify the trash directory to use\n"
        "  --all-users           list trashcans of all the users\n"
        "\n"
        "Report bugs to https://github.com/andreafrancia/trash-cli/issues\n"
        "",
        ""},
    {"trash-list", {"-h"}, 50, 0,
        "usage: trash-list [-h]\n"
        "                  [--print-completion {bash,zsh,tcsh}]\n"
        "                  [--version] [--volumes]\n"
        "                  [--trash-dirs]\n"
        "                  [--trash-dir TRASH_DIRS]\n"
        "                  [--all-users]\n"
        "\n"
        "List trashed files\n"
        "\n"
        "options:\n"
        "  -h, --help            show this help message\n"
        "                        and exit\n"
        "  --print-completion {bash,zsh,tcsh}\n"
        "                        print shell completion\n"
        "                        script\n"
        "  --version             show program's version\n"
        "                        number and exit\n"
        "  --volumes             list volumes\n"
        "  --trash-dirs          list trash dirs\n"
        "  --trash-dir TRASH_DIRS\n"
        "                        specify the trash\n"
        "                        directory to use\n"
        "  --all-users           list trashcans of all\n"
        "                        the users\n"
        "\n"
        "Report bugs to\n"
        "https://github.com/andreafrancia/trash-\n"
        "cli/issues\n"
        "",
        ""},
    {"trash-list", {"-h"}, 120, 0,
        "usage: trash-list [-h] [--print-completion {bash,zsh,tcsh}] [--version] [--volumes] [--trash-dirs]\n"
        "                  [--trash-dir TRASH_DIRS] [--all-users]\n"
        "\n"
        "List trashed files\n"
        "\n"
        "options:\n"
        "  -h, --help            show this help message and exit\n"
        "  --print-completion {bash,zsh,tcsh}\n"
        "                        print shell completion script\n"
        "  --version             show program's version number and exit\n"
        "  --volumes             list volumes\n"
        "  --trash-dirs          list trash dirs\n"
        "  --trash-dir TRASH_DIRS\n"
        "                        specify the trash directory to use\n"
        "  --all-users           list trashcans of all the users\n"
        "\n"
        "Report bugs to https://github.com/andreafrancia/trash-cli/issues\n"
        "",
        ""},
    {"trash-restore", {"-h"}, 80, 0,
        "usage: trash-restore [-h] [--print-completion {bash,zsh,tcsh}]\n"
        "                     [--sort {date,path,none}] [--version] [--overwrite]\n"
        "                     [path]\n"
        "\n"
        "Restores from trash chosen file\n"
        "\n"
        "positional arguments:\n"
        "  path                  Restore files from given path instead of current\n"
        "                        directory (default: )\n"
        "\n"
        "options:\n"
        "  -h, --help            show this help message and exit\n"
        "  --print-completion {bash,zsh,tcsh}\n"
        "                        print shell completion script (default: None)\n"
        "  --sort {date,path,none}\n"
        "                        Sort list of restore candidates by given field\n"
        "                        (default: date)\n"
        "  --version\n"
        "  --overwrite           Overwrite existing files with files coming out of the\n"
        "                        trash (default: False)\n"
        "",
        ""},
    {"trash-restore", {"-h"}, 50, 0,
        "usage: trash-restore [-h]\n"
        "                     [--print-completion {bash,zsh,tcsh}]\n"
        "                     [--sort {date,path,none}]\n"
        "                     [--version] [--overwrite]\n"
        "                     [path]\n"
        "\n"
        "Restores from trash chosen file\n"
        "\n"
        "positional arguments:\n"
        "  path                  Restore files from given\n"
        "                        path instead of current\n"
        "                        directory (default: )\n"
        "\n"
        "options:\n"
        "  -h, --help            show this help message\n"
        "                        and exit\n"
        "  --print-completion {bash,zsh,tcsh}\n"
        "                        print shell completion\n"
        "                        script (default: None)\n"
        "  --sort {date,path,none}\n"
        "                        Sort list of restore\n"
        "                        candidates by given\n"
        "                        field (default: date)\n"
        "  --version\n"
        "  --overwrite           Overwrite existing files\n"
        "                        with files coming out of\n"
        "                        the trash (default:\n"
        "                        False)\n"
        "",
        ""},
    {"trash-restore", {"-h"}, 120, 0,
        "usage: trash-restore [-h] [--print-completion {bash,zsh,tcsh}] [--sort {date,path,none}] [--version] [--overwrite]\n"
        "                     [path]\n"
        "\n"
        "Restores from trash chosen file\n"
        "\n"
        "positional arguments:\n"
        "  path                  Restore files from given path instead of current directory (default: )\n"
        "\n"
        "options:\n"
        "  -h, --help            show this help message and exit\n"
        "  --print-completion {bash,zsh,tcsh}\n"
        "                        print shell completion script (default: None)\n"
        "  --sort {date,path,none}\n"
        "                        Sort list of restore candidates by given field (default: date)\n"
        "  --version\n"
        "  --overwrite           Overwrite existing files with files coming out of the trash (default: False)\n"
        "",
        ""},
    {"trash-empty", {"-h"}, 80, 0,
        "usage: trash-empty [-h] [--print-completion {bash,zsh,tcsh}] [--version] [-v]\n"
        "                   [--trash-dir TRASH_DIR] [--all-users] [-i] [-f] [--dry-run]\n"
        "                   [days]\n"
        "\n"
        "Purge trashed files.\n"
        "\n"
        "positional arguments:\n"
        "  days\n"
        "\n"
        "options:\n"
        "  -h, --help            show this help message and exit\n"
        "  --print-completion {bash,zsh,tcsh}\n"
        "                        print shell completion script\n"
        "  --version             show program's version number and exit\n"
        "  -v, --verbose         list files that will be deleted\n"
        "  --trash-dir TRASH_DIR\n"
        "                        specify the trash directory to use\n"
        "  --all-users           empty all trashcan of all the users\n"
        "  -i, --interactive     ask before emptying trash directories\n"
        "  -f                    don't ask before emptying trash directories\n"
        "  --dry-run             show which files would have been removed\n"
        "\n"
        "Report bugs to https://github.com/andreafrancia/trash-cli/issues\n"
        "",
        ""},
    {"trash-empty", {"-h"}, 50, 0,
        "usage: trash-empty [-h]\n"
        "                   [--print-completion {bash,zsh,tcsh}]\n"
        "                   [--version] [-v]\n"
        "                   [--trash-dir TRASH_DIR]\n"
        "                   [--all-users] [-i] [-f]\n"
        "                   [--dry-run]\n"
        "                   [days]\n"
        "\n"
        "Purge trashed files.\n"
        "\n"
        "positional arguments:\n"
        "  days\n"
        "\n"
        "options:\n"
        "  -h, --help            show this help message\n"
        "                        and exit\n"
        "  --print-completion {bash,zsh,tcsh}\n"
        "                        print shell completion\n"
        "                        script\n"
        "  --version             show program's version\n"
        "                        number and exit\n"
        "  -v, --verbose         list files that will be\n"
        "                        deleted\n"
        "  --trash-dir TRASH_DIR\n"
        "                        specify the trash\n"
        "                        directory to use\n"
        "  --all-users           empty all trashcan of\n"
        "                        all the users\n"
        "  -i, --interactive     ask before emptying\n"
        "                        trash directories\n"
        "  -f                    don't ask before\n"
        "                        emptying trash\n"
        "                        directories\n"
        "  --dry-run             show which files would\n"
        "                        have been removed\n"
        "\n"
        "Report bugs to\n"
        "https://github.com/andreafrancia/trash-\n"
        "cli/issues\n"
        "",
        ""},
    {"trash-empty", {"-h"}, 120, 0,
        "usage: trash-empty [-h] [--print-completion {bash,zsh,tcsh}] [--version] [-v] [--trash-dir TRASH_DIR] [--all-users]\n"
        "                   [-i] [-f] [--dry-run]\n"
        "                   [days]\n"
        "\n"
        "Purge trashed files.\n"
        "\n"
        "positional arguments:\n"
        "  days\n"
        "\n"
        "options:\n"
        "  -h, --help            show this help message and exit\n"
        "  --print-completion {bash,zsh,tcsh}\n"
        "                        print shell completion script\n"
        "  --version             show program's version number and exit\n"
        "  -v, --verbose         list files that will be deleted\n"
        "  --trash-dir TRASH_DIR\n"
        "                        specify the trash directory to use\n"
        "  --all-users           empty all trashcan of all the users\n"
        "  -i, --interactive     ask before emptying trash directories\n"
        "  -f                    don't ask before emptying trash directories\n"
        "  --dry-run             show which files would have been removed\n"
        "\n"
        "Report bugs to https://github.com/andreafrancia/trash-cli/issues\n"
        "",
        ""},
    {"trash-list", {"--v"}, 80, 2,
        "",
        "usage: trash-list [-h] [--print-completion {bash,zsh,tcsh}] [--version]\n"
        "                  [--volumes] [--trash-dirs] [--trash-dir TRASH_DIRS]\n"
        "                  [--all-users]\n"
        "trash-list: error: ambiguous option: --v could match --version, --volumes\n"
        ""},
    {"trash-list", {"--trash-dir"}, 80, 2,
        "",
        "usage: trash-list [-h] [--print-completion {bash,zsh,tcsh}] [--version]\n"
        "                  [--volumes] [--trash-dirs] [--trash-dir TRASH_DIRS]\n"
        "                  [--all-users]\n"
        "trash-list: error: argument --trash-dir: expected one argument\n"
        ""},
    {"trash-list", {"--trash-dir", "-v"}, 80, 2,
        "",
        "usage: trash-list [-h] [--print-completion {bash,zsh,tcsh}] [--version]\n"
        "                  [--volumes] [--trash-dirs] [--trash-dir TRASH_DIRS]\n"
        "                  [--all-users]\n"
        "trash-list: error: argument --trash-dir: expected one argument\n"
        ""},
    {"trash-list", {"--print-completion", "foo"}, 80, 2,
        "",
        "usage: trash-list [-h] [--print-completion {bash,zsh,tcsh}] [--version]\n"
        "                  [--volumes] [--trash-dirs] [--trash-dir TRASH_DIRS]\n"
        "                  [--all-users]\n"
        "trash-list: error: argument --print-completion: invalid choice: 'foo' (choose from bash, zsh, tcsh)\n"
        ""},
    {"trash-list", {"--volumes=1"}, 80, 2,
        "",
        "usage: trash-list [-h] [--print-completion {bash,zsh,tcsh}] [--version]\n"
        "                  [--volumes] [--trash-dirs] [--trash-dir TRASH_DIRS]\n"
        "                  [--all-users]\n"
        "trash-list: error: argument --volumes: ignored explicit argument '1'\n"
        ""},
    {"trash-list", {"-5x"}, 80, 2,
        "",
        "usage: trash-list [-h] [--print-completion {bash,zsh,tcsh}] [--version]\n"
        "                  [--volumes] [--trash-dirs] [--trash-dir TRASH_DIRS]\n"
        "                  [--all-users]\n"
        "trash-list: error: unrecognized arguments: -5x\n"
        ""},
    {"trash-list", {"x"}, 80, 2,
        "",
        "usage: trash-list [-h] [--print-completion {bash,zsh,tcsh}] [--version]\n"
        "                  [--volumes] [--trash-dirs] [--trash-dir TRASH_DIRS]\n"
        "                  [--all-users]\n"
        "trash-list: error: unrecognized arguments: x\n"
        ""},
    {"trash-list", {"--version", "--bogus"}, 80, 2,
        "",
        "usage: trash-list [-h] [--print-completion {bash,zsh,tcsh}] [--version]\n"
        "                  [--volumes] [--trash-dirs] [--trash-dir TRASH_DIRS]\n"
        "                  [--all-users]\n"
        "trash-list: error: unrecognized arguments: --bogus\n"
        ""},
    {"trash-list", {"--bogus", "--version"}, 80, 2,
        "",
        "usage: trash-list [-h] [--print-completion {bash,zsh,tcsh}] [--version]\n"
        "                  [--volumes] [--trash-dirs] [--trash-dir TRASH_DIRS]\n"
        "                  [--all-users]\n"
        "trash-list: error: unrecognized arguments: --bogus\n"
        ""},
    {"trash-restore", {"--sort", "foo"}, 80, 2,
        "",
        "usage: trash-restore [-h] [--print-completion {bash,zsh,tcsh}]\n"
        "                     [--sort {date,path,none}] [--version] [--overwrite]\n"
        "                     [path]\n"
        "trash-restore: error: argument --sort: invalid choice: 'foo' (choose from date, path, none)\n"
        ""},
    {"trash-restore", {"a", "b"}, 80, 2,
        "",
        "usage: trash-restore [-h] [--print-completion {bash,zsh,tcsh}]\n"
        "                     [--sort {date,path,none}] [--version] [--overwrite]\n"
        "                     [path]\n"
        "trash-restore: error: unrecognized arguments: b\n"
        ""},
    {"trash-restore", {"-vx"}, 80, 2,
        "",
        "usage: trash-restore [-h] [--print-completion {bash,zsh,tcsh}]\n"
        "                     [--sort {date,path,none}] [--version] [--overwrite]\n"
        "                     [path]\n"
        "trash-restore: error: unrecognized arguments: -vx\n"
        ""},
    {"trash-restore", {"--version", "x"}, 80, 0,
        "trash-restore 0.26.9.29\n"
        "",
        ""},
    {"trash-restore", {"--o=1"}, 80, 2,
        "",
        "usage: trash-restore [-h] [--print-completion {bash,zsh,tcsh}]\n"
        "                     [--sort {date,path,none}] [--version] [--overwrite]\n"
        "                     [path]\n"
        "trash-restore: error: argument --overwrite: ignored explicit argument '1'\n"
        ""},
    {"trash-empty", {"x", "6"}, 80, 2,
        "",
        "usage: trash-empty [-h] [--print-completion {bash,zsh,tcsh}] [--version] [-v]\n"
        "                   [--trash-dir TRASH_DIR] [--all-users] [-i] [-f] [--dry-run]\n"
        "                   [days]\n"
        "trash-empty: error: argument days: invalid int value: 'x'\n"
        ""},
    {"trash-empty", {"-v=x"}, 80, 2,
        "",
        "usage: trash-empty [-h] [--print-completion {bash,zsh,tcsh}] [--version] [-v]\n"
        "                   [--trash-dir TRASH_DIR] [--all-users] [-i] [-f] [--dry-run]\n"
        "                   [days]\n"
        "trash-empty: error: argument -v/--verbose: ignored explicit argument 'x'\n"
        ""},
    {"trash-empty", {"--force"}, 80, 2,
        "",
        "usage: trash-empty [-h] [--print-completion {bash,zsh,tcsh}] [--version] [-v]\n"
        "                   [--trash-dir TRASH_DIR] [--all-users] [-i] [-f] [--dry-run]\n"
        "                   [days]\n"
        "trash-empty: error: unrecognized arguments: --force\n"
        ""},
    {"trash-empty", {"--version", "abc"}, 80, 2,
        "",
        "usage: trash-empty [-h] [--print-completion {bash,zsh,tcsh}] [--version] [-v]\n"
        "                   [--trash-dir TRASH_DIR] [--all-users] [-i] [-f] [--dry-run]\n"
        "                   [days]\n"
        "trash-empty: error: argument days: invalid int value: 'abc'\n"
        ""},
    {"trash-empty", {"abc", "--version"}, 80, 2,
        "",
        "usage: trash-empty [-h] [--print-completion {bash,zsh,tcsh}] [--version] [-v]\n"
        "                   [--trash-dir TRASH_DIR] [--all-users] [-i] [-f] [--dry-run]\n"
        "                   [days]\n"
        "trash-empty: error: argument days: invalid int value: 'abc'\n"
        ""},
    {"trash-empty", {"abc", "-h"}, 80, 2,
        "",
        "usage: trash-empty [-h] [--print-completion {bash,zsh,tcsh}] [--version] [-v]\n"
        "                   [--trash-dir TRASH_DIR] [--all-users] [-i] [-f] [--dry-run]\n"
        "                   [days]\n"
        "trash-empty: error: argument days: invalid int value: 'abc'\n"
        ""},
    {"trash-empty", {"-vx"}, 80, 2,
        "",
        "usage: trash-empty [-h] [--print-completion {bash,zsh,tcsh}] [--version] [-v]\n"
        "                   [--trash-dir TRASH_DIR] [--all-users] [-i] [-f] [--dry-run]\n"
        "                   [days]\n"
        "trash-empty: error: unrecognized arguments: -x\n"
        ""},
    {"trash-empty", {"--ver"}, 80, 2,
        "",
        "usage: trash-empty [-h] [--print-completion {bash,zsh,tcsh}] [--version] [-v]\n"
        "                   [--trash-dir TRASH_DIR] [--all-users] [-i] [-f] [--dry-run]\n"
        "                   [days]\n"
        "trash-empty: error: ambiguous option: --ver could match --version, --verbose\n"
        ""},
    {"trash-empty", {"1_0x"}, 80, 2,
        "",
        "usage: trash-empty [-h] [--print-completion {bash,zsh,tcsh}] [--version] [-v]\n"
        "                   [--trash-dir TRASH_DIR] [--all-users] [-i] [-f] [--dry-run]\n"
        "                   [days]\n"
        "trash-empty: error: argument days: invalid int value: '1_0x'\n"
        ""},
    {"trash-empty", {"5", "--trash-dir"}, 80, 2,
        "",
        "usage: trash-empty [-h] [--print-completion {bash,zsh,tcsh}] [--version] [-v]\n"
        "                   [--trash-dir TRASH_DIR] [--all-users] [-i] [-f] [--dry-run]\n"
        "                   [days]\n"
        "trash-empty: error: argument --trash-dir: expected one argument\n"
        ""},
    {"trash-put", {"--trash-dir", "-v", "f"}, 80, 2,
        "",
        "usage: trash-put [OPTION]... FILE...\n"
        "trash-put: error: argument --trash-dir: expected one argument\n"
        ""},
    {"trash-put", {"-f=x", "f"}, 80, 2,
        "",
        "usage: trash-put [OPTION]... FILE...\n"
        "trash-put: error: argument -f/--force: ignored explicit argument 'x'\n"
        ""},
    {"trash-put", {"--ver", "f"}, 80, 2,
        "",
        "usage: trash-put [OPTION]... FILE...\n"
        "trash-put: error: ambiguous option: --ver could match --verbose, --version\n"
        ""},
    {"trash-put", {"-x", "f"}, 80, 2,
        "",
        "usage: trash-put [OPTION]... FILE...\n"
        "trash-put: error: unrecognized arguments: -x\n"
        ""},
    {"trash-put", {"--print-completion", "fish"}, 80, 2,
        "",
        "usage: trash-put [OPTION]... FILE...\n"
        "trash-put: error: argument --print-completion: invalid choice: 'fish' (choose from bash, zsh, tcsh)\n"
        ""},
    {"trash-put", {"--force-volume", "-v", "f"}, 80, 2,
        "",
        "usage: trash-put [OPTION]... FILE...\n"
        "trash-put: error: argument --force-volume: expected one argument\n"
        ""},
    {"trash-put", {"--f", "f"}, 80, 2,
        "",
        "usage: trash-put [OPTION]... FILE...\n"
        "trash-put: error: ambiguous option: --f could match --force, --force-volume\n"
        ""},
    {"trash-put", {"-5x"}, 80, 2,
        "",
        "usage: trash-put [OPTION]... FILE...\n"
        "trash-put: error: unrecognized arguments: -5x\n"
        ""},
    {"trash-put", {"--version"}, 80, 0,
        "0.26.9.29\n"
        "",
        ""},
    {"trash-put", {"-h", "x"}, 80, 0,
        "usage: trash-put [OPTION]... FILE...\n"
        "\n"
        "Put files in trash\n"
        "\n"
        "positional arguments:\n"
        "  files\n"
        "\n"
        "options:\n"
        "  -h, --help            show this help message and exit\n"
        "  --print-completion {bash,zsh,tcsh}\n"
        "                        print shell completion script\n"
        "  -d, --directory       ignored (for GNU rm compatibility)\n"
        "  -f, --force           silently ignore nonexistent files\n"
        "  -i, --interactive     prompt before every removal\n"
        "  -r, -R, --recursive   ignored (for GNU rm compatibility)\n"
        "  --trash-dir TRASHDIR  use TRASHDIR as trash folder\n"
        "  -v, --verbose         explain what is being done\n"
        "  --version             show program's version number and exit\n"
        "\n"
        "all trash-cli commands:\n"
        "  trash-put             trash files and directories.\n"
        "  trash-empty           empty the trashcan(s).\n"
        "  trash-list            list trashed files.\n"
        "  trash-restore         restore a trashed file.\n"
        "  trash-rm              remove individual files from the trashcan\n"
        "\n"
        "To remove a file whose name starts with a '-', for example '-foo',\n"
        "use one of these commands:\n"
        "\n"
        "    trash -- -foo\n"
        "\n"
        "    trash ./-foo\n"
        "\n"
        "Report bugs to https://github.com/andreafrancia/trash-cli/issues\n"
        "",
        ""},
};

static void test_argparse_output_matches_python(void)
{
    for (uz i = 0; i < countof(apcases); i++) {
        const ApCase *k = &apcases[i];
        Str args[6];
        iz  n = 0;
        while (n < 6 && k->args[n]) {
            args[n] = import((u8 *)k->args[n]);
            n++;
        }
        envset("COLUMNS", vfmt("%d", k->cols));
        Res r = vruna(import((u8 *)k->persona), n, args);
        Str want_out = import((u8 *)k->out), want_err = import((u8 *)k->err);
        if (r.exit != k->exit || !equals(r.out, want_out)
            || !equals(r.err, want_err)) {
            char g[1024], w[1024];
            vrepr(g, sizeof g, r.err);
            vrepr(w, sizeof w, want_err);
            vfail(__FILE__, __LINE__, "%s %s ... (columns %d): exit %d want "
                  "%d, out %s, stderr got %s, want %s", k->persona,
                  k->args[0], k->cols, r.exit, k->exit,
                  equals(r.out, want_out) ? "ok" : "differs", g, w);
        }
    }
}

static void test_argparse_option_value_cannot_look_like_an_option(void)
{
    Res r = tput("--trash-dir", "-v", "f");
    CK_EQ(r.exit, 2);
    CK_HAS(r.err, "trash-put: error: argument --trash-dir: expected one "
                  "argument\n");
    r = tput("--trash-dir=-v", "nonexistent");   // an explicit value is fine
    CK_EQ(r.exit, 74);
    r = tput("--force-volume", "--", "f");
    CK_EQ(r.exit, 2);
    r = tlist("--trash-dir", "--all-users");
    CK_EQ(r.exit, 2);
}

static void test_argparse_clusters_and_explicit_arguments(void)
{
    Res r = tput("-fv", "nonexistent");   // two flags in one token
    CK_EQ(r.exit, 0);
    r = tput("-vx", "f");                 // the unknown piece is reported alone
    CK_EQ(r.exit, 2);
    CK_HAS(r.err, "unrecognized arguments: -x\n");
    r = tput("-v=1", "f");
    CK_EQ(r.exit, 2);
    CK_HAS(r.err, "argument -v/--verbose: ignored explicit argument '1'\n");
    r = tput("--verbose=1", "f");
    CK_HAS(r.err, "argument -v/--verbose: ignored explicit argument '1'\n");
    r = tempty("--v=1");
    CK_HAS(r.err, "ambiguous option: --v=1 could match --version, --verbose\n");
    r = tput("--ver", "f");
    CK_HAS(r.err, "ambiguous option: --ver could match --verbose, --version\n");
}

static void test_argparse_negative_numbers_and_separator(void)
{
    mktrash("/xdg/Trash");
    make_trashed("/xdg/Trash", "a", "/work/-5", "2001-01-01T00:00:00");
    setstdin("\n");
    Res r = trestore("-5");   // a negative number is an argument, not an option
    CK_EQ(r.exit, 0);
    CK_HAS(r.out, " /work/-5\n");
    setstdin("\n");
    r = trestore("--", "-5");
    CK_HAS(r.out, " /work/-5\n");
    r = tempty("-f", "-5");   // days = -5: nothing older than five days ahead
    CK_EQ(r.exit, 0);
    r = tput("-fv", "--", "-x", "nonexistent");
    CK_EQ(r.exit, 0);
}

static void test_argparse_errors_come_in_argparse_order(void)
{
    // the first positional is converted before the extras are reported
    Res r = tempty("x", "6");
    CK_HAS(r.err, "argument days: invalid int value: 'x'\n");
    // an exiting option wins over what comes after it, not over earlier errors
    r = tput("--bogus", "--version");     // put's --version is an action
    CK_EQ(r.exit, 0);
    CK_S(r.out, S("0.26.9.29\n"));
    r = tlist("--version", "--bogus");    // list's is a plain flag: parse on
    CK_EQ(r.exit, 2);
    r = tempty("--version", "--bogus");
    CK_EQ(r.exit, 2);
    r = tempty("abc", "-h");   // the positional is converted before -h acts
    CK_EQ(r.exit, 2);
    r = tempty("-h", "abc");
    CK_EQ(r.exit, 0);
}

static void test_argparse_width_follows_columns_then_the_terminal(void)
{
    envdel("COLUMNS");
    Res r = tlist("-h");                   // 80 columns by default
    CK_HAS(r.out, "usage: trash-list [-h] [--print-completion {bash,zsh,tcsh}] "
                  "[--version]\n");
    v->istty[1]  = 1;
    v->termcols  = 50;
    r = tlist("-h");
    CK_HAS(r.out, "usage: trash-list [-h]\n"
                  "                  [--print-completion {bash,zsh,tcsh}]\n");
    envset("COLUMNS", "100");              // $COLUMNS beats the terminal
    r = tlist("-h");
    CK_HAS(r.out, "[--volumes] [--trash-dirs]");
    envset("COLUMNS", "0");                // not positive: the terminal again
    r = tlist("-h");
    CK_HAS(r.out, "usage: trash-list [-h]\n");
    envset("COLUMNS", "x");                // not a number: the terminal
    r = tlist("-h");
    CK_HAS(r.out, "usage: trash-list [-h]\n");
}

// -- Checks the real kernel could not arrange hermetically (spec 11) -----------

static void test_restore_volume_relative_path(void)
{
    // spec 3.3: in a volume trash dir (one sitting directly under a mount
    // point), Path= must be volume-relative; absolute values are refused
    // and relative ones restore joined with the volume.
    addmount("/vol", 2);
    char *trash = volume_trash(2, VUID);
    winfo(trash, "abs", "/vol/work/abs", "2001-01-01T00:00:00", (Str){});
    wbackup(trash, "abs", "data");
    winfo(trash, "rel", "work/rel", "2001-01-01T00:00:00", (Str){});
    wbackup(trash, "rel", "data");
    setcwd("/vol/work");
    setstdin("\n");
    Res r = trestore();
    CK_EQ(r.exit, 0);
    CK_HAS(r.err, "Non parsable trashinfo file: "
                  "/vol/.Trash-1000/info/abs.trashinfo, because Path= must "
                  "be relative for volume trashes");
    Str lines[32];
    iz n = vlines(r.out, lines);
    CK_EQ(n, 2);   // one listing line plus the prompt
    CK_S(linepath_restore(lines[0]), S("/vol/work/rel"));
}

static void test_empty_xdg_data_home_is_unset(void)
{
    // spec 4.1 (corrected): an empty XDG_DATA_HOME is treated as unset;
    // this would touch the real filesystem root on a live system.
    envset("XDG_DATA_HOME", "");
    vwrite("/work/f", "x");
    Res r = tput("f");
    CK_EQ(r.exit, 0);
    ck_present("/home/.local/share/Trash/files/f");
}

static void test_all_users_skips_unreadable_homes(void)
{
    // spec 4.6: other users' unreadable trash dirs are skipped silently.
    vmkdir("/otherhome");
    vchmod("/otherhome", 0);
    envdel("XDG_DATA_HOME");   // trash the file into the home trash
    vwrite("/work/f", "x");
    CK_EQ(tput("f").exit, 0);
    ck_present("/home/.local/share/Trash/files/f");
    Res r = tlist("--all-users");
    CK_EQ(r.exit, 0);
    CK_HAS(r.out, "/work/f");
    CK_S(r.err, S(""));
}

static void test_mounts_octal_escapes(void)
{
    // spec 4.4: the kernel octal-escapes spaces in /proc/self/mounts
    // mount points (\040); volume detection must decode them.  put maps
    // the file to its volume through st_dev, so the virtual OS gives the
    // mount point its own dev.
    addmount("/mnt/my docs", 2);
    vmkdir("/mnt/my docs");
    vwrite("/mnt/my docs/f", "x");
    setcwd("/mnt/my docs");
    Res r = tput("-vv", "f");
    CK_EQ(r.exit, 0);
    CK_HAS(r.err, "from volume: /mnt/my docs");
}

static void test_rename_fixup_restores_mode(void)
{
    // spec 5.6: the writability granted for the cross-parent move of a
    // read-only directory is restored on the backup copy.
    vmkdir("/work/rodir");
    vchmod("/work/rodir", 0500);
    CK_EQ(tput("rodir").exit, 0);
    ck_gone("/work/rodir");
    ck_mode("/xdg/Trash/files/rodir", 0500);
}

static void test_home_fallback_candidate(void)
{
    // spec 5.5 candidate 4: with TRASH_ENABLE_HOME_FALLBACK=1 the home
    // trash is tried again after the volume candidates.
    vwrite("/work/gvf", "x");
    envset("TRASH_ENABLE_HOME_FALLBACK", "1");
    Res r = tput("--force-volume", "/no-such-volume", "--home-fallback",
                 "-v", "gvf");
    CK_EQ(r.exit, 0);
    CK_S(r.err, S("trash-put: 'gvf' trashed in /xdg/Trash\n"));
    ck_present("/xdg/Trash/files/gvf");
}

// -- the runner ------------------------------------------------------------------------

int main(int argc, char **argv)
{
    enum { CAP = 1 << 28 };
    byte *mem = mmap(0, CAP, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mem == MAP_FAILED) {
        fprintf(stderr, "trash_test: out of memory\n");
        return 1;
    }
    vosos = (Os){.name = S("trash-test"), .rng = 1};

    Str filter = {};
    b32 verbose = 0;
    for (i32 i = 1; i < argc; i++) {
        if (equals(import((u8 *)argv[i]), S("-v"))) {
            verbose = 1;
        } else {
            filter = import((u8 *)argv[i]);
        }
    }
    gfilter = filter;
    gverbose = verbose;
    for (iz k = 0; k < (iz)countof(tests); k++) {
        if (gfilter.data && !hasstr(tests[k].name, gfilter)) {
            continue;
        }
        curtest = tests[k].name;
        nran++;
        i32 before = nfailed;

        // O(1) reset: the front third is the virtual OS arena, the middle
        // third is perm, the last third is scratch.
        v = &vosobj;
        memset(v, 0, sizeof *v);
        v->fs = (Arena){&vosos, mem, mem + CAP/3};
        permspace   = (Arena){&vosos, mem + CAP/3, mem + CAP/3*2};
        scratchspace = (Arena){&vosos, mem + CAP/3*2, mem + CAP};
        gperm = &permspace;
        gscratch = &scratchspace;

        if (setjmp(testjmp)) {
            // reported by vfail
        } else {
            newsandbox();
            tests[k].fn();
        }
        if (gverbose && nfailed == before) {
            printf("ok  %.*s\n", (i32)curtest.len, (char *)curtest.data);
        }
    }

    printf("%lld tests, %lld failed\n", (long long)nran, (long long)nfailed);
    return nfailed ? 1 : 0;
}

#endif  // TEST

#endif  // __linux
