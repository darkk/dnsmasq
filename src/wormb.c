/* dnsmasq is Copyright (c) 2000-2024 Simon Kelley

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; version 2 dated June, 1991, or
   (at your option) version 3 dated 29 June, 2007.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "dnsmasq.h"

#ifdef HAVE_INLINE_QSORT

#define REF(x, n) (((uintptr_t*)(x))[n])
#define QSORT_SIZEOF (2 * sizeof(uintptr_t))
#define QSORT_CMP(fn, pa, pb) ( \
    REF(pa, 0) <  REF(pb, 0) ? -1 : \
    REF(pa, 0) == REF(pb, 0) ? fn(&REF(pa, 1), &REF(pb, 1)) : 1 )

static void qsort_inline(void *a, size_t n, int (*cmp)(const void *, const void *));

typedef void (*qsort_fn)(void *base, size_t nmemb, size_t size, int (*cmp)(const void *, const void *));
static const qsort_fn libc_qsort = qsort;
#define QSORT_FALLBACK(a, n, es, cmp) (libc_qsort(a, n, es, cmp), 0)

void wormb_sort_pairs(struct worm_bsearch *w, int (*cb)(const void*, const void*))
{
  assert((wormb_data_end(w) - wormb_data_begin(w)) % 2 == 0);
  qsort_inline(wormb_data_begin(w), (wormb_data_end(w) - wormb_data_begin(w)) / 2, cb);
}

// A few qsort() implementation were benchmarked and OpenBSD one is the fastest
// and the easiest to embed. It's still ~15% slower than C++ std::sort<> for
// a similar task, but it's ≈6.2x times faster than libc_qsort()+cmp() callbacks.
// However, YMMV. Following qsort() implementations were tested: FreeBSD, glibc
// aka GNU C Library, musl, NetBSD, OpenBSD, OpenBSD heapsort(), g++ std::sort.
#include "openbsd-qsort.c"

#else // !HAVE_INLINE_QSORT

typedef int (*qsort_cmp)(const void *, const void *);
#if __USE_GNU
#  define qcomp(a, b, ctx) (a, b, ctx)
#  define qsort_rrr(base, nmemb, width, fn, ctx) qsort_r(base, nmemb, width, fn, ctx)
#else // MacOS, BSD and __ANDROID__
#  define qcomp(a, b, ctx) (ctx, a, b)
#  define qsort_rrr(base, nmemb, width, fn, ctx) qsort_r(base, nmemb, width, ctx, fn)
#endif
typedef int (*qsort_r_cmp) qcomp (const void *, const void *, void *);

#ifdef HAVE_DEVTOOLS
static int qsort_cmp_calls;
static int fctx qcomp(const void *av, const void *bv, void *ctx);
static int fcmp qcomp(const void *av, const void *bv, void *ctx)
{
  qsort_cmp_calls++;
  const u32 *a = av;
  const u32 *b = bv;
  assert((*a ^ *b) == (0x53544f50 ^ 0x57415221));
  assert(ctx == fctx);
  return *a < *b ? -1 : 1;
}
static int fctx qcomp(const void *av, const void *bv, void *ctx)
{
  return fcmp qcomp(av, bv, ctx);
}
void qsort_rrr_init()
{
  u32 arr[2] = { 0x53544f50, 0x57415221 };
  qsort_rrr(arr, countof(arr), sizeof(arr[0]), fcmp, fctx);
  assert(qsort_cmp_calls);
}
#endif

static int cmp_pairs qcomp(const void *pa, const void *pb, void *pctx)
{
  const uintptr_t *a = pa, *b = pb;
  const qsort_cmp cmp = pctx;
  return *a < *b ? -1 : *a == *b ? cmp(&a[1], &b[1]) : 1;
}

void wormb_sort_pairs(struct worm_bsearch *w, qsort_cmp cb)
{
  const size_t nptr = wormb_data_end(w) - wormb_data_begin(w);
  assert(nptr % 2 == 0);
  qsort_rrr(wormb_data_begin(w), nptr / 2, 2 * sizeof(uintptr_t), cmp_pairs, cb);
}

#endif
