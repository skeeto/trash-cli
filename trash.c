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
    ENOTDIR = 20, EISDIR = 21, ENOSPC = 28, EROFS = 30, ENAMETOOLONG = 36,
    ENOTEMPTY = 39, ELOOP = 40,
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
// The current working directory, in *a.
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

static b32 space(u8 c)
{
    return c==' ' || c=='\t' || c=='\n' || c=='\r' || c=='\v' || c=='\f';
}

static b32 digit(u8 c)
{
    return c >= '0' && c <= '9';
}

static Str trim(Str s)
{
    while (s.len && space(s.data[0])) {
        s = cuthead(s, 1);
    }
    while (s.len && space(s.data[s.len-1])) {
        s = cuttail(s, 1);
    }
    return s;
}

typedef struct {
    i64 value;
    b32 ok;      // syntactically an integer
    b32 toobig;  // magnitude beyond the i64 range
} IntParsed;

// Python int() semantics: optional sign, optional surrounding whitespace.
static IntParsed parseint(Str s)
{
    IntParsed r = {};
    Str t = trim(s);
    if (!t.len) {
        return r;
    }
    iz  i   = 0;
    b32 neg = 0;
    if (t.data[0]=='+' || t.data[0]=='-') {
        neg = t.data[0] == '-';
        i++;
    }
    if (i >= t.len) {
        return r;
    }
    for (; i < t.len; i++) {
        if (!digit(t.data[i])) {
            return r;
        }
        if (!r.toobig) {
            i64 d = t.data[i] - '0';
            if (r.value > (maxof(i64) - d)/10) {
                r.toobig = 1;
                r.value  = neg ? maxof(i64) : maxof(i64);
            } else {
                r.value = r.value*10 + d;
            }
        }
    }
    if (neg && !r.toobig) {
        r.value = -r.value;
    }
    r.ok = 1;
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

// Quotes a path the way GNU ls does on a terminal: plain names pass through,
// anything with a character outside [A-Za-z0-9/._-] is wrapped in single
// quotes, and control or non-ASCII bytes switch to $'...' escaping.
static void printq(Output *b, Str s)
{
    b32 needs = 0;
    b32 rawok = 1;
    for (iz i = 0; i < s.len; i++) {
        u8 c = s.data[i];
        b32 safe = (c>='A' && c<='Z') || (c>='a' && c<='z') || (c>='0' && c<='9')
                 || c=='/' || c=='.' || c=='_' || c=='-';
        if (!safe) {
            needs = 1;
            if (c < 0x20 || c >= 0x7F) {
                rawok = 0;
            }
        }
    }
    if (!needs) {
        print(b, s);
        return;
    }
    if (rawok) {
        printu8(b, '\'');
        for (iz i = 0; i < s.len; i++) {
            if (s.data[i] == '\'') {
                print(b, S("'\\''"));
            } else {
                printu8(b, s.data[i]);
            }
        }
        printu8(b, '\'');
        return;
    }
    print(b, S("$'"));
    for (iz i = 0; i < s.len; i++) {
        u8 c = s.data[i];
        switch (c) {
        case '\n': print(b, S("\\n")); break;
        case '\t': print(b, S("\\t")); break;
        case '\r': print(b, S("\\r")); break;
        case 0x07: print(b, S("\\a")); break;
        case 0x08: print(b, S("\\b")); break;
        case 0x0B: print(b, S("\\v")); break;
        case 0x0C: print(b, S("\\f")); break;
        case '\\': print(b, S("\\\\")); break;
        case '\'': print(b, S("\\'")); break;
        default:
            if (c < 0x20 || c >= 0x7F) {
                print(b, S("\\x"));
                printhex2(b, c);
            } else {
                printu8(b, c);
            }
        }
    }
    printu8(b, '\'');
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

static Str join(Arena *a, Str head, Str tail)
{
    if (!tail.len) {
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

static Str realpath_(Os *os, Arena *a, Arena scratch, Str p)
{
    enum { MAXLINKS = 40 };

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
                affirm(rn < cap);
                res[rn++] = c;
            }
            continue;
        }
        Str cand = rjoin(a, rooted, res, rn, c);
        Stat st  = {};
        if (!os_stat(os, scratch, cand, 0, &st)) {
            affirm(rn < cap);
            res[rn++] = c;   // nonexistent or unreadable: keep lexically
            continue;
        }
        if (st.kind == KIND_LINK) {
            Str target;
            if (!os_readlink(os, a, cand, &target) || ++links > MAXLINKS) {
                affirm(rn < cap);
                res[rn++] = c;
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
        affirm(rn < cap);
        res[rn++] = c;
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
    Str cwd = os_getcwd(os, a);
    return normpath(a, join(a, cwd, rel));
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


// fnmatch: case-sensitive shell globbing, * crosses '/', no escapes.

static iz classmatch(Str p, u8 c, b32 *m)   // p is after '['; -1 if no class
{
    iz  i    = 0;
    b32 neg  = 0;
    b32 hit  = 0;
    b32 first = 1;
    *m = 0;
    if (i < p.len && p.data[i] == '!') {
        neg = 1;
        i++;
    }
    while (i < p.len) {
        if (p.data[i] == ']' && !first) {
            *m = hit != neg;
            return i + 1;
        }
        first = 0;
        u8 lo = p.data[i];
        if (i+2 < p.len && p.data[i+1]=='-' && p.data[i+2] != ']') {
            if (lo <= c && c <= p.data[i+2]) {
                hit = 1;
            }
            i += 3;
        } else {
            if (lo == c) {
                hit = 1;
            }
            i++;
        }
    }
    return -1;
}

static b32 fnmatch_(Str pat, Str s)
{
    iz pi = 0, si = 0, star = -1, mark = 0;
    while (si < s.len) {
        b32 hit = 0;
        if (pi < pat.len && pat.data[pi] == '[') {
            b32 m = 0;
            iz adv = classmatch(cuthead(pat, pi + 1), s.data[si], &m);
            if (adv >= 0) {
                if (!m) {
                    if (star < 0) {
                        return 0;
                    }
                    pi  = star + 1;
                    si  = ++mark;
                    continue;
                }
                pi += adv + 1;
                si++;
                continue;
            }
            // unterminated '[': literal
        }
        if (!hit && pi < pat.len
            && (pat.data[pi] == '?' || pat.data[pi] == s.data[si])) {
            hit = 1;
            pi++;
            si++;
            continue;
        }
        if (!hit && pi < pat.len && pat.data[pi] == '*') {
            star = pi++;
            mark = si;
            continue;
        }
        if (star >= 0) {
            pi  = star + 1;
            si  = ++mark;
            continue;
        }
        return 0;
    }
    while (pi < pat.len && pat.data[pi] == '*') {
        pi++;
    }
    return pi == pat.len;
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

static b32 parseu(u8 *s, iz len, iz *i, iz maxdigits, i32 *out)
{
    iz  beg = *i;
    iz  n   = 0;
    i32 v   = 0;
    while (*i < len && n < maxdigits && digit(s[*i])) {
        v = v*10 + (s[*i] - '0');
        (*i)++;
        n++;
    }
    if (!n) {
        return 0;
    }
    *out = v;
    affirm(*i > beg);
    return 1;
}

// Exactly "YYYY-MM-DDTHH:MM:SS" with Python strptime leniency: the year is
// exactly four digits, the other fields one or two.  Nothing may follow.
static b32 parse_datetime(Str s, DateTime *out)
{
    u8 *d = s.data;
    iz  i = 0;
    i32 v[6];
    if (!parseu(d, s.len, &i, 4, &v[0]) || i != 4) {
        return 0;
    }
    if (i >= s.len || d[i++] != '-') {
        return 0;
    }
    if (!parseu(d, s.len, &i, 2, &v[1]) || i >= s.len || d[i++] != '-') {
        return 0;
    }
    if (!parseu(d, s.len, &i, 2, &v[2]) || i >= s.len || d[i++] != 'T') {
        return 0;
    }
    if (!parseu(d, s.len, &i, 2, &v[3]) || i >= s.len || d[i++] != ':') {
        return 0;
    }
    if (!parseu(d, s.len, &i, 2, &v[4]) || i >= s.len || d[i++] != ':') {
        return 0;
    }
    if (!parseu(d, s.len, &i, 2, &v[5]) || i != s.len) {
        return 0;
    }
    if (v[1] < 1 || v[1] > 12) {
        return 0;
    }
    if (v[2] < 1 || v[2] > days_in_month(v[0], v[1])) {
        return 0;
    }
    if (v[3] > 23 || v[4] > 59 || v[5] > 59) {
        return 0;
    }
    out->year  = v[0];
    out->month = v[1];
    out->day   = v[2];
    out->hour  = v[3];
    out->min   = v[4];
    out->sec   = v[5];
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
        s = cuttail(s, 1);
    }
    if (s.len && s.data[s.len-1] == '\r') {
        s = cuttail(s, 1);
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

// lexists: a dangling symlink exists, like Python's os.path.lexists.
static b32 lexists(Os *os, Arena scratch, Str path)
{
    Stat st = {};
    return os_stat(os, scratch, path, 0, &st);
}


// Trashinfo files

enum : i32 { TI_OK = 0, TI_NOPATH, TI_BADUTF8, TI_READERR };

typedef struct {
    Str      path;        // percent-decoded original location; valid iff TI_OK
    DateTime date;
    b32      has_date;
    Str      infopath;
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
        *status = TI_BADUTF8;
        return ti;
    }
    b32 dated = 0;
    Str rest  = content;
    while (rest.len) {
        Cut lc   = cut(rest, '\n');
        Str line = lc.head;
        rest     = lc.tail;
        if (line.len && line.data[line.len-1] == '\r') {
            line = cuttail(line, 1);
        }
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


// Option parser (argparse emulation)
//
// Long options match exactly or by unambiguous prefix; values may be given
// as --opt VALUE or --opt=VALUE.  Short options may be clustered (-vv).
// Everything after -- is positional.  A lone - and arguments that look like
// negative numbers are positional too.  Positionals must form one contiguous
// run: any positional that follows an option, and any option nobody claims,
// is reported as unrecognized.  -h/--help, --version and --print-completion
// act the moment they are seen, like argparse actions.

enum : u8 { ACT_NONE = 0, ACT_HELP, ACT_VERSION, ACT_COMPLETION };

typedef struct {
    Str name;        // long name without the leading dashes
    Str shorts;      // short option characters, e.g. S("rR"); empty if none
    b32 value;       // takes a value
    Str choices[8];  // allowed values, when the value is enumerated
    iz  nchoices;
    u8  action;
} OptSpec;

typedef struct OptVal OptVal;
struct OptVal {
    OptVal *next;
    i32     id;     // index into the command's OptSpec table
    Str     val;
};

typedef struct {
    OptVal *vals;    // in command-line order
    Str    *pos;     // positional arguments
    iz      npos;
    Str    *extras;  // unrecognized arguments, in order
    iz      nextras;
} ParsedOpts;

typedef struct {
    Ctx *ctx;
    Str  usage;         // error preamble, without trailing newline
    Str  help_usage;    // the usage line --help prints first, blank line after
    Str  help_body;     // the rest of the help text
    b32  bare_version;  // put personas print a bare version string
} OptEnv;

[[noreturn]] static void die_usage(OptEnv *e, Str msg)
{
    Ctx *c = e->ctx;
    print(c->err, e->usage);
    print(c->err, S("\n"));
    print(c->err, c->prog);
    print(c->err, S(": error: "));
    print(c->err, msg);
    print(c->err, S("\n"));
    finish(c, 2);
}

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

static void printchoices(OptEnv *e, OptSpec *sp, Str value)
{
    Ctx *c = e->ctx;
    print(c->err, S("argument --"));
    print(c->err, sp->name);
    print(c->err, S(": invalid choice: '"));
    print(c->err, value);
    print(c->err, S("' (choose from"));
    for (iz k = 0; k < sp->nchoices; k++) {
        print(c->err, k ? S(", ") : S(" "));
        print(c->err, S("'"));
        print(c->err, sp->choices[k]);
        print(c->err, S("'"));
    }
    print(c->err, S(")\n"));
    finish(c, 2);
}

[[noreturn]] static void perform_action(OptEnv *e, OptSpec *sp, Str val)
{
    Ctx *c = e->ctx;
    switch (sp->action) {
    case ACT_HELP:
        print(c->out, e->help_usage);
        print(c->out, e->help_body);
        finish(c, 0);
    case ACT_VERSION:
        if (e->bare_version) {
            print(c->out, S("0.26.9.29\n"));
        } else {
            print(c->out, c->prog);
            print(c->out, S(" 0.26.9.29\n"));
        }
        finish(c, 0);
    case ACT_COMPLETION:
        for (iz k = 0; k < sp->nchoices; k++) {
            if (equals(sp->choices[k], val)) {
                print(c->out, S("Please install shtab firstly!\n"));
                finish(c, 0);
            }
        }
        printchoices(e, sp, val);
    }
    affirm(0);
}

static ParsedOpts optparse(OptEnv *e, OptSpec *specs, iz nspecs, iz nargs,
                           iz argc, Str *argv, Arena *a)
{
    ParsedOpts r = {};
    r.pos    = new(a, argc, Str);
    r.extras = new(a, argc, Str);
    OptVal **tail = &r.vals;
    b32 noparse = 0;   // after --
    b32 closed  = 0;   // the positional run ended; later positionals are extras

    for (iz i = 0; i < argc; i++) {
        Str t = argv[i];
        if (noparse) {
            if (closed) {
                r.extras[r.nextras++] = t;
            } else {
                r.pos[r.npos++] = t;
            }
            continue;
        }
        if (equals(t, S("--"))) {
            noparse = 1;
            if (r.npos) {
                closed = 1;
            }
            continue;
        }
        if (t.len >= 2 && t.data[0] == '-' && t.data[1] == '-') {
            if (r.npos) {
                closed = 1;
            }
            Str body = cuthead(t, 2);
            Cut eq   = cut(body, '=');
            Str name = eq.head;
            Str val  = eq.tail;
            iz  match = -1;
            b32 exact = 0;
            for (iz k = 0; k < nspecs; k++) {
                if (equals(specs[k].name, name)) {
                    match = k;
                    exact = 1;
                    break;
                }
            }
            if (!exact) {
                iz hits = 0;
                for (iz k = 0; k < nspecs; k++) {
                    if (startswith(specs[k].name, name)) {
                        if (match < 0) {
                            match = k;
                        }
                        hits++;
                    }
                }
                if (hits > 1) {
                    Str msg = concat(a, S("ambiguous option: --"), name);
                    msg = concat(a, msg, S(" could match"));
                    for (iz k = 0; k < nspecs; k++) {
                        if (startswith(specs[k].name, name)) {
                            msg = concat(a, msg, S(" --"));
                            msg = concat(a, msg, specs[k].name);
                        }
                    }
                    die_usage(e, msg);
                }
            }
            if (match < 0) {
                r.extras[r.nextras++] = t;
                continue;
            }
            OptSpec *sp = &specs[match];
            if (sp->value) {
                if (!eq.ok) {
                    if (i + 1 >= argc) {
                        Str msg = concat(a, S("argument --"), sp->name);
                        msg = concat(a, msg, S(": expected one argument"));
                        die_usage(e, msg);
                    }
                    val = argv[++i];
                }
                if (sp->nchoices) {
                    b32 ok = 0;
                    for (iz k = 0; k < sp->nchoices; k++) {
                        ok |= equals(sp->choices[k], val);
                    }
                    if (!ok) {
                        printchoices(e, sp, val);
                    }
                }
            } else if (eq.ok) {
                Str msg = concat(a, S("argument --"), sp->name);
                msg = concat(a, msg, S(": ignored explicit argument '"));
                msg = concat(a, msg, val);
                msg = concat(a, msg, S("'"));
                die_usage(e, msg);
            }
            OptVal *v = new(a, 1, OptVal);
            v->id  = (i32)match;
            v->val = val;
            *tail  = v;
            tail   = &v->next;
            if (sp->action) {
                perform_action(e, sp, val);
            }
            continue;
        }
        if (t.len >= 2 && t.data[0] == '-' && t.data[1] != '-') {
            if (digit(t.data[1])) {   // a negative number is a positional
                if (closed) {
                    r.extras[r.nextras++] = t;
                } else {
                    r.pos[r.npos++] = t;
                }
                continue;
            }
            if (r.npos) {
                closed = 1;
            }
            b32 claimed = 0;
            for (iz k = 1; k < t.len; k++) {
                u8 ch = t.data[k];
                iz  m = -1;
                for (iz j = 0; j < nspecs && m < 0; j++) {
                    for (iz q = 0; q < specs[j].shorts.len; q++) {
                        if (specs[j].shorts.data[q] == ch) {
                            m = j;
                            break;
                        }
                    }
                }
                if (m < 0) {
                    if (!claimed) {
                        r.extras[r.nextras++] = t;   // whole token unrecognized
                        claimed = 1;
                    }
                    break;
                }
                affirm(!specs[m].value);
                OptVal *v = new(a, 1, OptVal);
                v->id = (i32)m;
                *tail = v;
                tail  = &v->next;
                if (specs[m].action) {
                    perform_action(e, &specs[m], (Str){});
                }
            }
            continue;
        }
        // positional
        if (closed) {
            r.extras[r.nextras++] = t;
        } else {
            r.pos[r.npos++] = t;
        }
    }

    // argparse can split one optional positional off a run but no more.
    if (nargs == 0) {
        for (iz k = 0; k < r.npos; k++) {
            r.extras[r.nextras++] = r.pos[k];
        }
        r.npos = 0;
    } else if (nargs == 1 && r.npos > 1) {
        for (iz k = 1; k < r.npos; k++) {
            r.extras[r.nextras++] = r.pos[k];
        }
        r.npos = 1;
    }

    if (r.nextras) {
        Str msg = S("unrecognized arguments:");
        for (iz k = 0; k < r.nextras; k++) {
            msg = concat(a, msg, S(" "));
            msg = concat(a, msg, r.extras[k]);
        }
        die_usage(e, msg);
    }
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
    Str *v = new(a, 64, Str);
    iz  n  = 0;
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
        b32 dup  = 0;
        for (iz k = 0; k < n; k++) {
            dup |= equals(v[k], mnt);
        }
        if (keep && !dup && n < 64) {
            v[n++] = mnt;
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
        Str parent = concat(a, vol, S("/.Trash"));
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
        Str td2  = concat(a, concat(a, vol, S("/.Trash-")), istr(a, uid));
        Stat st2 = {};
        if (os_stat(c->os, scratch, td2, 1, &st2) && st2.kind == KIND_DIR) {
            evpush(a, ev, EV_FOUND, td2, vol);
        }
    }
}

typedef struct {
    b32 all_users;
    i32 uid;
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
            evpush(a, &ev, EV_FOUND, ht, S("/"));
        }
        scan_volume_dirs(c, a, scratch, volumes_list(c, a, scratch),
                         o.uid, &ev);
    }
    s.events = ev.head;
    return s;
}

// Putting files in the trash (trash-put, trash)

static Str stripslashes(Str s)
{
    while (s.len > 1 && s.data[s.len-1] == '/') {
        s = cuttail(s, 1);
    }
    return s;
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

// ... and for two paths, as rename errors print.
static Str errtext2(Arena *a, Os *os, i32 err, Str from, Str to)
{
    Str s = concat(a, S("[Errno "), istr(a, err));
    s = concat(a, s, S("] "));
    s = concat(a, s, os_strerror(os, err));
    s = concat(a, s, S(": '"));
    s = concat(a, s, from);
    s = concat(a, s, S("' -> '"));
    s = concat(a, s, to);
    s = concat(a, s, S("'"));
    return s;
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
// existing file is FileExistsError; parents are created with the same mode.
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
            if (makedirs(c, scratch, d, mode, perr, epath)) {
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

// Writes the .trashinfo for one candidate, picking a collision suffix
// (spec 3.2).  Returns 0 and sets *outinfo/*outfiles, or -1 with *preason.
static i32 write_trashinfo(Ctx *c, Arena *a, Arena scratch, Str trashdir,
                           Str stem, Str origloc, DateTime now, Str *outinfo,
                           Str *outfiles, Str *preason)
{
    enum { MAXATTEMPTS = 10000 };

    for (i64 k = 0; k < MAXATTEMPTS; k++) {
        Str suffix = k == 0
                   ? S("")
                   : k <= 99
                   ? concat(a, S("_"), istr(a, k))
                   : concat(a, S("_"), istr(a, (i64)(os_rand(c->os) & 65535)));
        Str name   = concat(a, stem, suffix);
        Str files  = join(a, join(a, trashdir, S("files")), name);
        if (lexists(c->os, scratch, files)) {
            continue;
        }
        Str info     = concat(a, name, S(".trashinfo"));
        Str infopath = join(a, join(a, trashdir, S("info")), info);
        i32 fd = os_open(c->os, scratch, infopath, 1, 0600);
        if (fd >= 0) {
            Output *b = newoutput(a, c->os, fd);
            print(b, S("[Trash Info]\nPath="));
            print(b, percentencode(a, origloc));
            print(b, S("\nDeletionDate="));
            print(b, format_datetime(a, now, '-', 'T'));
            print(b, S("\n"));
            flush(b);
            os_close(c->os, fd);
            if (b->err) {
                os_unlink(c->os, scratch, infopath);
                *preason = S("error writing the trashinfo file");
                return -1;
            }
            *outinfo  = infopath;
            *outfiles = files;
            return 0;
        }
        i32 err = os_errno(c->os);
        if (err == ENAMETOOLONG) {
            // Shrink the stem so <stem><suffix>.trashinfo stays within
            // NAME_MAX (255); this also bounds the retry loop, fixing the
            // upstream pathology that only ever trimmed the suffix length.
            iz maxstem = 255 - 10 - suffix.len;
            if (maxstem >= 0 && stem.len > maxstem) {
                stem = takehead(stem, maxstem);
            }
            continue;
        }
        *preason = concat(a, S("error during trashinfo creation: "),
                          errtext(a, c->os, err, infopath));
        return -1;
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
        prefixes(c, c->err, m);
        *pfailed = 1;
        return;
    }

    // Missing files: a silent success under -f, a failure otherwise (step 3).
    if (!exists) {
        if (f.force) {
            return;
        }
        prefixes(c, c->err, concat(a, concat(a,  S("cannot trash non existent '"),
                                   raw),  S("'")));
        *pfailed = 1;
        return;
    }

    // Delete-permission pre-check on the realpath'd parent (step 4).
    Str np     = normpath(a, raw);
    Str parent = dirname(np);
    Str rdir   = realpath_(os, a, scratch, parent);
    if (!os_access(os, scratch, rdir, ACCESS_W | ACCESS_X)) {
        Str m = concat(a, S("cannot trash "), desc);
        m = concat(a, m, S(" '"));
        m = concat(a, m, raw);
        m = concat(a, m, S("' because deleting it is not allowed"));
        prefixes(c, c->err, m);
        *pfailed = 1;
        return;
    }

    // Interactive prompt, only for accessible paths (step 5); dangling
    // symlinks fail F_OK and are not asked about.
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

    Str realvol = volume_of(os, a, scratch, rdir);
    Str filevol = f.force_volume.data ? f.force_volume : realvol;

    // Candidates, in order (spec 5.5).  With --trash-dir there is exactly
    // one; otherwise home, then the file's volume's two methods, then the
    // home trash again when --home-fallback was given.
    Cand cands[4];
    iz   ncands = 0;
    if (pe->trash_dir.data) {
        Cand n       = {};
        n.td         = pe->trash_dir;
        n.topdir     = volume_of(os, a, scratch,
                                 realpath_(os, a, scratch, normpath(a, n.td)));
        n.relative   = 1;
        cands[ncands++] = n;
    } else {
        if (pe->home.data) {
            Cand n    = {};
            n.td      = pe->home;
            n.topdir  = S("/");
            cands[ncands++] = n;
        }
        Cand m1        = {};
        m1.td          = join(a, concat(a, filevol, S("/.Trash/")),
                              istr(a, uid));
        m1.topdir      = filevol;
        m1.check       = CHECK_TOPDIR;
        m1.relative    = 1;
        cands[ncands++] = m1;
        Cand m2        = {};
        m2.td          = concat(a, concat(a, filevol, S("/.Trash-")),
                                istr(a, uid));
        m2.topdir      = filevol;
        m2.relative    = 1;
        cands[ncands++] = m2;
        if (pe->home_fallback && pe->home.data) {
            Cand n         = {};
            n.td           = pe->home;
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
            m = concat(a, m, cd->td);
            m = concat(a, m, S(" from volume: "));
            m = concat(a, m, filevol);
            prefixes(c, c->err, m);
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
                                   realpath_(os, a, scratch,
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
                                &infopath, &files, &reason)) {
                // reason is set
            } else {
                if (f.verbose >= 2) {
                    Str m =  S(".trashinfo created as ");
                    m = concat(a, m, infopath);
                    m = concat(a, m, S("."));
                    prefixes(c, c->err, m);
                }
                if (trash_rename(c, scratch, np, files, &st)) {
                    trashed = 1;
                    if (f.verbose >= 1) {
                        Str m =  S("'");
                        m = concat(a, m, raw);
                        m = concat(a, m, S("' trashed in "));
                        m = concat(a, m, shrink(os, a, normpath(a, cd->td),
                                                pe->no_shrink));
                        prefixes(c, c->err, m);
                    }
                } else {
                    if (lexists(os, scratch, files)) {
                        os_unlink(os, scratch, files);
                    }
                    os_unlink(os, scratch, infopath);
                    i32 err = os_errno(os);
                    Str m =  S("failed to move ");
                    m = concat(a, m, np);
                    m = concat(a, m, S(" in "));
                    m = concat(a, m, join(a, cd->td, S("files")));
                    m = concat(a, m, S(": "));
                    m = concat(a, m, errtext2(a, os, err, np, files));
                    reason = m;
                }
            }
        }

        if (!trashed) {
            Str m =  c->prog;
            m = concat(a, m, S(":  `- failed to trash "));
            m = concat(a, m, raw);
            m = concat(a, m, S(" in "));
            m = concat(a, m, cd->td);
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
        prefixes(c, c->err, m);
        print(c->err, block);
        *pfailed = 1;
    }
}

static const char put_help_body[] =
    "\n"
    "Put files in trash.\n"
    "\n"
    "options:\n"
    "  -h, --help            show this help message and exit\n"
    "  --print-completion {bash,zsh,tcsh}\n"
    "                        print shell completion script\n"
    "  -d, --directory       ignored (for compatibility with rm)\n"
    "  -f, --force           silently ignore non existent files\n"
    "  -i, --interactive     ask before trashing each files\n"
    "  -r, -R, --recursive   ignored (for compatibility with rm)\n"
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
    "Report bugs to https://github.com/andreafrancia/trash-cli/issues\n";

enum {
    PUT_HELP, PUT_COMPLETION, PUT_DIRECTORY, PUT_FORCE, PUT_INTERACTIVE,
    PUT_RECURSIVE, PUT_TRASHDIR, PUT_VERBOSE, PUT_VERSION,
    PUT_FORCE_VOLUME, PUT_HOME_FALLBACK,
};

static i32 cmd_put(Ctx *c, iz argc, Str *argv)
{
    Arena *a = c->perm;

    OptSpec specs[] = {
        {S("help"),             S("h"),  0, {}, 0, ACT_HELP},
        {S("print-completion"), {},      1,
         {S("bash"), S("zsh"), S("tcsh")}, 3, ACT_COMPLETION},
        {S("directory"),        S("d"),  0, {}, 0, ACT_NONE},
        {S("force"),            S("f"),  0, {}, 0, ACT_NONE},
        {S("interactive"),      S("i"),  0, {}, 0, ACT_NONE},
        {S("recursive"),        S("rR"), 0, {}, 0, ACT_NONE},
        {S("trash-dir"),        {},      1, {}, 0, ACT_NONE},
        {S("verbose"),          S("v"),  0, {}, 0, ACT_NONE},
        {S("version"),          {},      0, {}, 0, ACT_VERSION},
        {S("force-volume"),     {},      1, {}, 0, ACT_NONE},
        {S("home-fallback"),    {},      0, {}, 0, ACT_NONE},
    };
    OptEnv e = {};
    e.ctx          = c;
    e.usage        = concat(a, S("usage: "), concat(a, c->prog,
                                                    S(" [OPTION]... FILE...")));
    e.help_usage   = concat(a, e.usage, S("\n\n"));
    e.help_body    = import((u8 *)put_help_body);
    e.bare_version = 1;

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
            die_usage(&e, m);
        }
    }

    ParsedOpts p = optparse(&e, specs, (iz)countof(specs), 2, argc, argv, a);
    if (!p.npos) {
        die_usage(&e, S("Please specify the files to trash."));
    }

    PutFlags f = {};
    f.verbose = optcount(&p, PUT_VERBOSE);
    for (OptVal *v = p.vals; v; v = v->next) {
        if (v->id == PUT_FORCE)       { f.force = 1;       f.interactive = 0; }
        if (v->id == PUT_INTERACTIVE) { f.force = 0;       f.interactive = 1; }
    }
    f.force_volume = optlast(&p, PUT_FORCE_VOLUME);

    i64 uid = os_getuid(c->os);
    Str fake = os_getenv(c->os, S("TRASH_PUT_FAKE_UID_FOR_TESTING"));
    if (fake.data) {
        IntParsed ip = parseint(fake);
        if (!ip.ok || ip.toobig) {
            die(c, 1, S("invalid TRASH_PUT_FAKE_UID_FOR_TESTING"));
        }
        uid = ip.value;
    }

    PutEnv pe = {};
    pe.trash_dir = optlast(&p, PUT_TRASHDIR);
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
    LIST_HELP, LIST_COMPLETION, LIST_VERSION, LIST_VOLUMES, LIST_TRASHDIRS,
    LIST_TRASHDIR, LIST_ALLUSERS, LIST_SIZE, LIST_FILES, LIST_DEBUGVOLUMES,
    LIST_PYTHON,
};

enum : i32 {
    LA_LIST = 0, LA_VOLUMES, LA_TRASHDIRS, LA_SIZE, LA_FILES,
    LA_DEBUGVOLUMES, LA_PYTHON,
};

static const char list_help_body[] =
    "\n"
    "List trashed files.\n"
    "\n"
    "options:\n"
    "  -h, --help            show this help message and exit\n"
    "  --print-completion {bash,zsh,tcsh}\n"
    "                        print shell completion script\n"
    "  --version             show program's version number and exit\n"
    "  --volumes             list the volumes in the trash\n"
    "  --trash-dirs          list the trash dirs in the volumes\n"
    "  --trash-dir TRASH_DIRS\n"
    "                        list only the trash dirs in this directory\n"
    "  --all-users           list the trash cans of all the users\n"
    "\n"
    "Report bugs to https://github.com/andreafrancia/trash-cli/issues\n";

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
                        i32 action, b32 quoting, b32 allusers)
{
    Os *os = c->os;
    for (ScanEv *ev = scan.events; ev; ev = ev->next) {
        if (ev->kind != EV_FOUND) {
            continue;
        }
        Arena td     = scratch;
        Str infodir  = join(&td, ev->path, S("info"));
        b32 ok;
        DirEnt *ents = os_listdir(os, &td, infodir, &ok);
        if (!ok) {
            i32 err = os_errno(os);
            if (err == ENOENT) {
                continue;   // a nonexistent trash dir contributes nothing
            }
            if (allusers) {
                continue;   // other users' trash dirs may be unreadable
            }
            say(c, c->err, errtext(&td, os, err, infodir));
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
            if (action == LA_SIZE) {
                Str backup = backuppath(&te, ev->path, ent->name);
                Stat bs    = {};
                if (!os_stat(os, te, backup, 1, &bs)) {
                    say(c, c->err, errtext(&te, os, os_errno(os), backup));
                    return -1;
                }
                printi64(c->out, bs.size);
                print(c->out, S(" "));
                printpathraw(c->out, loc);
                print(c->out, S("\n"));
                continue;
            }
            if (ti.has_date) {
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
            if (action == LA_FILES) {
                print(c->out, S(" -> "));
                printpathraw(c->out, backuppath(&te, ev->path, ent->name));
            }
            print(c->out, S("\n"));
        }
    }
    return 0;
}

static i32 cmd_list(Ctx *c, iz argc, Str *argv)
{
    Arena *a = c->perm;
    OptSpec specs[] = {
        {S("help"),             S("h"), 0, {}, 0, ACT_HELP},
        {S("print-completion"), {},     1,
         {S("bash"), S("zsh"), S("tcsh")}, 3, ACT_COMPLETION},
        {S("version"),          {},     0, {}, 0, ACT_VERSION},
        {S("volumes"),          {},     0, {}, 0, ACT_NONE},
        {S("trash-dirs"),       {},     0, {}, 0, ACT_NONE},
        {S("trash-dir"),        {},     1, {}, 0, ACT_NONE},
        {S("all-users"),        {},     0, {}, 0, ACT_NONE},
        {S("size"),             {},     0, {}, 0, ACT_NONE},
        {S("files"),            {},     0, {}, 0, ACT_NONE},
        {S("debug-volumes"),    {},     0, {}, 0, ACT_NONE},
        {S("python"),           {},     0, {}, 0, ACT_NONE},
    };
    Str usage = concat(a, S("usage: "), c->prog);
    usage = concat(a, usage,
                   S(" [-h] [--print-completion {bash,zsh,tcsh}] [--version]"
                     " [--volumes] [--trash-dirs] [--trash-dir TRASH_DIRS]"
                     " [--all-users]"));
    OptEnv e = {};
    e.ctx        = c;
    e.usage      = usage;
    e.help_usage = concat(a, usage, S("\n\n"));
    e.help_body  = import((u8 *)list_help_body);

    ParsedOpts p = optparse(&e, specs, (iz)countof(specs), 0, argc, argv, a);

    // The action flags share one variable: the last one wins (spec 6.1).
    i32 action = LA_LIST;
    for (OptVal *v = p.vals; v; v = v->next) {
        switch (v->id) {
        case LIST_VOLUMES:      action = LA_VOLUMES;      break;
        case LIST_TRASHDIRS:    action = LA_TRASHDIRS;    break;
        case LIST_SIZE:         action = LA_SIZE;         break;
        case LIST_FILES:        action = LA_FILES;        break;
        case LIST_DEBUGVOLUMES: action = LA_DEBUGVOLUMES; break;
        case LIST_PYTHON:       action = LA_PYTHON;       break;
        }
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
            evpush(a, &ev, EV_FOUND, optval(&p, LIST_TRASHDIR, k), S("/"));
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
        if (list_entries(c, a, c->scratch, one, action, quoting, 0)) {
            finish(c, 1);
        }
        finish(c, 0);
    }

    Scan s = scan_trash_dirs(c, a, c->scratch,
                             (ScanOpts){optgiven(&p, LIST_ALLUSERS),
                                        os_getuid(c->os)});
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
    if (list_entries(c, a, c->scratch, s, action, quoting,
                     optgiven(&p, LIST_ALLUSERS))) {
        finish(c, 1);
    }
    finish(c, 0);
}


// Restoring trashed files (trash-restore)

enum { RES_HELP, RES_COMPLETION, RES_SORT, RES_VERSION, RES_OVERWRITE,
       RES_TRASHDIR };

static const char restore_help_body[] =
    "\n"
    "Restore a trashed file.\n"
    "\n"
    "positional arguments:\n"
    "  path                  Restore from this path (default: current dir)\n"
    "\n"
    "options:\n"
    "  -h, --help            show this help message and exit\n"
    "  --print-completion {bash,zsh,tcsh}\n"
    "                        print shell completion script\n"
    "  --sort {date,path,none}\n"
    "                        sort the list by date or by path\n"
    "  --version             show program's version number and exit\n"
    "  --overwrite           replace existing files\n";

typedef struct {
    Str      loc;       // original location, decoded and joined
    Str      infopath;
    Str      backup;
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
    Str r   = normpath(a, join(a, vol, rel));
    Str pfx = concat(a, vol, S("/"));
    if (!equals(r, vol) && !startswith(r, pfx)) {
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

// rename(2) when possible; across devices, copy and remove (shutil.move).
static b32 move_path(Ctx *c, Arena *a, Arena scratch, Str src, Str dst,
                     Str *preason)
{
    Os *os = c->os;
    if (os_rename(os, scratch, src, dst)) {
        return 1;
    }
    i32 err = os_errno(os);
    if (err != EXDEV) {
        *preason = errtext2(a, os, err, src, dst);
        return 0;
    }
    Stat ss = {};
    if (!os_stat(os, scratch, src, 0, &ss)) {
        *preason = errtext(a, os, os_errno(os), src);
        return 0;
    }
    if (ss.kind == KIND_LINK) {
        Str target;
        if (!os_readlink(os, a, src, &target)
            || !os_symlink(os, scratch, target, dst)) {
            *preason = errtext(a, os, os_errno(os), dst);
            return 0;
        }
        os_unlink(os, scratch, src);
        return 1;
    }
    if (ss.kind == KIND_DIR) {
        if (!os_mkdir(os, scratch, dst, (u32)(ss.mode & 0777u))) {
            *preason = errtext(a, os, os_errno(os), dst);
            return 0;
        }
        b32 ok;
        DirEnt *ents = os_listdir(os, a, src, &ok);
        if (!ok) {
            *preason = errtext(a, os, os_errno(os), src);
            return 0;
        }
        for (DirEnt *e2 = ents; e2; e2 = e2->next) {
            Str s2 = join(a, src, e2->name);
            Str d2 = join(a, dst, e2->name);
            if (!move_path(c, a, scratch, s2, d2, preason)) {
                return 0;
            }
        }
        if (!os_rmdir(os, scratch, src)) {
            *preason = errtext(a, os, os_errno(os), src);
            return 0;
        }
        return 1;
    }
    // Everything else: copy the bytes, keep the mode.
    i32 in = os_open(os, scratch, src, 0, 0);
    if (in < 0) {
        *preason = errtext(a, os, os_errno(os), src);
        return 0;
    }
    i32 out = os_open(os, scratch, dst, 1, (u32)(ss.mode & 0777u));
    if (out < 0) {
        os_close(os, in);
        *preason = errtext(a, os, os_errno(os), dst);
        return 0;
    }
    u8 *buf = new(a, 1 << 12, u8);
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
    os_unlink(os, scratch, src);
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
        Str infodir  = join(&td, ev->path, S("info"));
        b32 ok;
        DirEnt *ents = os_listdir(os, &td, infodir, &ok);
        if (!ok) {
            i32 err = os_errno(os);
            if (err == ENOENT) {
                continue;
            }
            Str m =  S("TrashDir skipped because its info dir "
                                  "cannot be read: ");
            m = concat(&td, m, ev->path);
            say(c, c->err, m);
            continue;
        }
        b32 voltrash = !equals(ev->volume, S("/"))
                    && is_volume_trash(a, ev->path, ev->volume);
        for (DirEnt *ent = ents; ent; ent = ent->next) {
            Arena te = td;
            if (!endswith(ent->name, S(".trashinfo"))) {
                say(c, c->err, S("Non .trashinfo file in info dir"));
                continue;
            }
            Str infopath = join(&te, join(&te, ev->path, S("info")),
                                ent->name);
            i32 status;
            TrashInfo ti = trashinfo_read(c, &te, te, infopath, &status);
            if (status != TI_OK) {
                Str why = status == TI_READERR
                        ? errtext(&te, os, os_errno(os), infopath)
                        : status == TI_BADUTF8
                        ? S("the file is not valid UTF-8")
                        : S("Unable to parse Path");
                Str m =  S("Non parsable trashinfo file: ");
                m = concat(&te, m, infopath);
                m = concat(&te, m, S(", because "));
                m = concat(&te, m, why);
                say(c, c->err, m);
                continue;
            }
            Str loc = {};
            if (voltrash) {
                if (!path_in_volume(&te, ev->volume, ti.path, &loc)) {
                    b32 abs = ti.path.len && ti.path.data[0] == '/';
                    Str m =
                        abs ? S("Path= must be relative for volume trashes: ")
                            : S("Path= escapes the volume root: ");
                    m = concat(&te, m, infopath);
                    say(c, c->err, m);
                    continue;
                }
            } else {
                loc = join(&te, ev->volume, ti.path);
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
            rc.backup   = clone(a, backuppath(&te, ev->path, ent->name));
            rc.has_date = ti.has_date;
            rc.date     = ti.date;
            respush(out, a, rc);
        }
    }
}

static i32 cmpstr(Str a, Str b)
{
    iz  m = a.len < b.len ? a.len : b.len;
    i32 c = m ? __builtin_memcmp(a.data, b.data, (uz)m) : 0;
    return c ? c : (i32)(a.len - b.len);
}

// True when x sorts strictly before y; undated entries go last (the
// corrected behavior: no crash on mixed dates).
static b32 cand_before(ResCand *x, ResCand *y, Str sort)
{
    if (equals(sort, S("path"))) {
        i32 c = cmpstr(x->loc, y->loc);
        if (c) {
            return c < 0;
        }
    }
    if (x->has_date != y->has_date) {
        return x->has_date;
    }
    if (x->has_date) {
        return datetime_key(x->date) < datetime_key(y->date);
    }
    return 0;
}

static i32 cmd_restore(Ctx *c, iz argc, Str *argv)
{
    Arena *a = c->perm;
    OptSpec specs[] = {
        {S("help"),             S("h"), 0, {}, 0, ACT_HELP},
        {S("print-completion"), {},     1,
         {S("bash"), S("zsh"), S("tcsh")}, 3, ACT_COMPLETION},
        {S("sort"),             {},     1,
         {S("date"), S("path"), S("none")}, 3, ACT_NONE},
        {S("version"),          {},     0, {}, 0, ACT_VERSION},
        {S("overwrite"),        {},     0, {}, 0, ACT_NONE},
        {S("trash-dir"),        {},     1, {}, 0, ACT_NONE},
    };
    Str usage = concat(a, S("usage: "), c->prog);
    usage = concat(a, usage,
                   S(" [-h] [--print-completion {bash,zsh,tcsh}]"
                     " [--sort {date,path,none}] [--version] [--overwrite]"
                     " [path]"));
    OptEnv e = {};
    e.ctx        = c;
    e.usage      = usage;
    e.help_usage = concat(a, usage, S("\n\n"));
    e.help_body  = import((u8 *)restore_help_body);

    ParsedOpts p = optparse(&e, specs, (iz)countof(specs), 1, argc, argv, a);

    Str sort = optlast(&p, RES_SORT);
    if (!sort.data) {
        sort = S("date");
    }
    b32  overwrite = optgiven(&p, RES_OVERWRITE);
    Str  trash_dir = optlast(&p, RES_TRASHDIR);
    Str  patharg   = p.npos ? p.pos[0] : (Str){};

    // The search path (spec 7.3): the argument resolved against the
    // realpath of the current directory; without an argument, that
    // directory itself.
    Str cwd    = realpath_(c->os, a, c->scratch, S("."));
    Str search = patharg.data ? normpath(a, join(a, cwd, patharg)) : cwd;

    Scan s = {};
    if (trash_dir.data) {
        EvList ev = {};
        ev.tail   = &ev.head;
        evpush(a, &ev, EV_FOUND, trash_dir, S("/"));
        s.events = ev.head;
    } else {
        s = scan_trash_dirs(c, a, c->scratch,
                            (ScanOpts){0, os_getuid(c->os)});
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
    if (!equals(sort, S("none"))) {   // --sort none keeps the scan order
        for (iz i = 1; i < list.n; i++) {   // stable insertion sort
            ResCand t = arr[i];
            iz j = i;
            while (j > 0 && cand_before(&t, &arr[j-1], sort)) {
                arr[j] = arr[j-1];
                j--;
            }
            arr[j] = t;
        }
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
        print(c->out, arr[k].loc);
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
    if (!trim(line).len) {   // empty reply: nothing is selected (spec 7.6)
        say(c, c->out, S("No files were restored"));
        finish(c, 0);
    }

    u8 *sel = new(a, list.n, u8);
    for (Cut k = {.tail=line, .ok=1}; k.ok;) {
        k        = cut(k.tail, ',');
        Str item = trim(k.head);
        if (!item.len) {
            continue;
        }
        Cut dash = cut(item, '-');
        if (dash.ok) {
            Str lo = trim(dash.head), hi = trim(dash.tail);
            if (!lo.len || !hi.len) {
                say(c, c->err, concat(a, S("Invalid entry: open interval: "),
                                      item));
                finish(c, 1);
            }
            IntParsed pl = parseint(lo), ph = parseint(hi);
            if (!pl.ok || pl.toobig || pl.value < 0 || !ph.ok || ph.toobig
                || ph.value < 0) {
                say(c, c->err,
                    concat(a, S("Invalid entry: not an index: "), item));
                finish(c, 1);
            }
            for (i64 v = pl.value; v <= ph.value; v++) {
                if (v >= list.n) {
                    Str m =  S("Invalid entry: out of range 0..");
                    m = concat(a, m, istr(a, list.n - 1));
                    m = concat(a, m, S(": "));
                    m = concat(a, m, item);
                    say(c, c->err, m);
                    finish(c, 1);
                }
                sel[v] = 1;
            }
        } else {
            IntParsed pi = parseint(item);
            if (!pi.ok || pi.toobig || pi.value < 0) {
                say(c, c->err,
                    concat(a, S("Invalid entry: not an index: "), item));
                finish(c, 1);
            }
            if (pi.value >= list.n) {
                Str m =  S("Invalid entry: out of range 0..");
                m = concat(a, m, istr(a, list.n - 1));
                m = concat(a, m, S(": "));
                m = concat(a, m, item);
                say(c, c->err, m);
                finish(c, 1);
            }
            sel[pi.value] = 1;
        }
    }

    // Restore each selected candidate in ascending order; batch errors do
    // not abort the run, but any failure makes the exit status 1 (7.7).
    b32 anyfail = 0;
    for (iz k = 0; k < list.n; k++) {
        if (!sel[k]) {
            continue;
        }
        ResCand *cd = &arr[k];
        Str dbase = basename(cd->loc);
        if (lexists(c->os, c->scratch, cd->loc)) {
            Stat ds = {};
            os_stat(c->os, c->scratch, cd->loc, 0, &ds);
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
        if (!equals(dp, S(".")) && !lexists(c->os, c->scratch, dp)) {
            i32 perr;
            Str epath;
            if (makedirs(c, c->scratch, dp, 0777, &perr, &epath)) {
                Str m =  S("Failed to restore \"");
                m = concat(a, m, dbase);
                m = concat(a, m, S("\": "));
                m = concat(a, m, errtext(a, c->os, perr, epath));
                say(c, c->err, m);
                anyfail = 1;
                continue;
            }
        }
        Str reason;
        if (!move_path(c, a, c->scratch, cd->backup, cd->loc, &reason)) {
            Str m =  S("Failed to restore \"");
            m = concat(a, m, dbase);
            m = concat(a, m, S("\": "));
            m = concat(a, m, reason);
            say(c, c->err, m);
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
    EMPTY_TRASHDIR, EMPTY_ALLUSERS, EMPTY_INTERACTIVE, EMPTY_FORCE,
    EMPTY_DRYRUN, EMPTY_PRINTTIME,
};

static const char empty_help_body[] =
    "\n"
    "Purge trashed files.\n"
    "\n"
    "positional arguments:\n"
    "  days                  Trashed files older than 'days' will be removed\n"
    "\n"
    "options:\n"
    "  -h, --help            show this help message and exit\n"
    "  --print-completion {bash,zsh,tcsh}\n"
    "                        print shell completion script\n"
    "  --version             show program's version number and exit\n"
    "  -v, --verbose         explain what is being done\n"
    "  --trash-dir TRASH_DIR\n"
    "                        only empty the trash dirs in this directory\n"
    "  --all-users           empty all the users' trash cans\n"
    "  -i, --interactive     ask before emptying\n"
    "  -f, --force           don't ask before emptying\n"
    "  --dry-run             list the files that would be removed\n"
    "\n"
    "Report bugs to https://github.com/andreafrancia/trash-cli/issues\n";

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
    b32 ok;
    DirEnt *ents = os_listdir(os, &t, infodir, &ok);
    if (!ok) {
        i32 err = os_errno(os);
        if (err == ENOENT) {
            return;
        }
        die(c, 1, errtext(&t, os, err, infodir));
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
            if (!ti.has_date) {
                continue;   // missing or invalid date: kept (spec 8.3)
            }
            if (fakedate.data && !faketime) {
                Str m =  S("invalid TRASH_DATE: ");
                m = concat(&te, m, fakedate);
                prefixes(c, c->err, m);
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
    OptSpec specs[] = {
        {S("help"),             S("h"),  0, {}, 0, ACT_HELP},
        {S("print-completion"), {},      1,
         {S("bash"), S("zsh"), S("tcsh")}, 3, ACT_COMPLETION},
        {S("version"),          {},      0, {}, 0, ACT_VERSION},
        {S("verbose"),          S("v"),  0, {}, 0, ACT_NONE},
        {S("trash-dir"),        {},      1, {}, 0, ACT_NONE},
        {S("all-users"),        {},      0, {}, 0, ACT_NONE},
        {S("interactive"),      S("i"),  0, {}, 0, ACT_NONE},
        {S("force"),            S("f"),  0, {}, 0, ACT_NONE},
        {S("dry-run"),          {},      0, {}, 0, ACT_NONE},
        {S("print-time"),       {},      0, {}, 0, ACT_NONE},
    };
    Str usage = concat(a, S("usage: "), c->prog);
    usage = concat(a, usage,
                   S(" [-h] [--print-completion {bash,zsh,tcsh}] [--version]"
                     " [-v] [--trash-dir TRASH_DIR] [--all-users] [-i] [-f]"
                     " [--dry-run] [days]"));
    OptEnv e = {};
    e.ctx        = c;
    e.usage      = usage;
    e.help_usage = concat(a, usage, S("\n\n"));
    e.help_body  = import((u8 *)empty_help_body);

    ParsedOpts p = optparse(&e, specs, (iz)countof(specs), 1, argc, argv, a);

    b32 verbose   = optgiven(&p, EMPTY_VERBOSE);
    b32 dry       = optgiven(&p, EMPTY_DRYRUN);
    b32 all_users = optgiven(&p, EMPTY_ALLUSERS);
    i64 uid       = os_getuid(c->os);

    // days (spec 8.3): parsed first, argparse-style.
    b32 have_days = 0;
    i64 days      = 0;
    Str daysarg   = p.npos ? p.pos[0] : (Str){};
    if (daysarg.data) {
        IntParsed pi = parseint(daysarg);
        if (!pi.ok) {
            Str m =  S("argument days: invalid int value: '");
            m = concat(a, m, daysarg);
            m = concat(a, m, S("'"));
            die_usage(&e, m);
        }
        have_days = 1;
        days      = pi.value;
    }

    // The clock: TRASH_DATE when it parses, else the real local time
    // (spec 10).  An invalid value is warned about per compared file.
    DateTime now;
    Str  fakedate = os_getenv(c->os, S("TRASH_DATE"));
    b32  faketime = 0;
    if (fakedate.data) {
        faketime = parse_datetime(trim(fakedate), &now);
    }
    if (!faketime) {
        os_now(c->os, &now);
    }

    if (optgiven(&p, EMPTY_PRINTTIME)) {
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
            Str m =  S("argument days: value out of range: '");
            m = concat(a, m, daysarg);
            m = concat(a, m, S("'"));
            die_usage(&e, m);
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
        s = scan_trash_dirs(c, a, c->scratch, (ScanOpts){all_users,
                                                         (i32)uid});
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
        for (ScanEv *ev = s.events; ev; ev = ev->next) {
            any |= ev->kind == EV_FOUND;
        }
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
    Scan s = scan_trash_dirs(c, a, c->scratch,
                             (ScanOpts){0, os_getuid(c->os)});
    for (ScanEv *ev = s.events; ev; ev = ev->next) {
        if (ev->kind != EV_FOUND) {
            continue;   // rejected dirs are skipped silently (spec 9.3)
        }
        Arena t      = scratch;
        Str infodir  = join(&t, ev->path, S("info"));
        b32 ok;
        DirEnt *ents = os_listdir(c->os, &t, infodir, &ok);
        if (!ok) {
            i32 err = os_errno(c->os);
            if (err == ENOENT) {
                continue;
            }
            die(c, 1, errtext(&t, c->os, err, infodir));
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
            if (!fnmatch_(pattern, target)) {
                continue;
            }
            Str backup = backuppath(&te, ev->path, e->name);
            if (lexists(c->os, te, backup)) {
                remove_path(c, te, backup);
            }
            remove_path(c, te, infopath);
        }
    }
    finish(c, 0);
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

// Platform Layers

#if !defined(__unix__)
#error "unsupported platform: trash needs a unix-like"
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
        e->name    = import((u8 *)de->d_name);
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

static Str os_getcwd(Os *os, Arena *a)
{
    for (iz cap = 1 << 8; cap <= 1 << 16; cap <<= 1) {
        u8 *buf = new(a, cap, u8);
        if (getcwd((char *)buf, (uz)cap)) {
            return span(buf, buf + strlen((char *)buf));
        }
    }
    oom(os);
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
    VMnt      mnt[8];  // the same mounts, for st_dev emulation
    i32       nmnts;
    Str       cwd;
    i32       uid;     // the current user
    DateTime  now;     // the virtual clock
    b32       istty[3];
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

// Registers a mount point in both the /proc/self/mounts content (with the
// kernel's \040 escapes) and the dev table.
static void addmount(char *path, i64 dev)
{
    affirm(v->nmnts < 8);
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
    char *line = vfmt("/dev/vd%lld %s ext4 0 0\n", (long long)dev,
                      (char *)esc.data);
    v->mounts = concat(&v->fs, v->mounts, import((u8 *)line));
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
        e->name = k->name;
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
    CK_HAS(r.err, "Path= must be relative for volume trashes: "
                  "/vol/.Trash-1000/info/abs.trashinfo");
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
