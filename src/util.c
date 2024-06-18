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

/* The SURF random number generator was taken from djbdns-1.05, by 
   Daniel J Bernstein, which is public domain. */


#include "dnsmasq.h"

#ifdef HAVE_BROKEN_RTC
#include <sys/times.h>
#endif

#if defined(HAVE_LIBIDN2)
#include <idn2.h>
#elif defined(HAVE_IDN)
#include <idna.h>
#endif

#ifdef HAVE_LINUX_NETWORK
#include <sys/utsname.h>
#endif

#ifdef HAVE_DEVTOOLS
#include <math.h>
#endif

#include <malloc.h>

static void bp_init();

/* SURF random number generator */

static u32 seed[32];
static u32 in[12];
static u32 out[8];
static int outleft = 0;

void rand_init()
{
  int fd = open(RANDFILE, O_RDONLY);
  
  if (fd == -1 ||
      !read_write(fd, (unsigned char *)&seed, sizeof(seed), 1) ||
      !read_write(fd, (unsigned char *)&in, sizeof(in), 1))
    die(_("failed to seed the random number generator: %s"), NULL, EC_MISC);
  
  close(fd);

  bp_init();
}

#define ROTATE(x,b) (((x) << (b)) | ((x) >> (32 - (b))))
#define MUSH(i,b) x = t[i] += (((x ^ seed[i]) + sum) ^ ROTATE(x,b));

static void surf(void)
{
  u32 t[12]; u32 x; u32 sum = 0;
  int r; int i; int loop;

  for (i = 0;i < 12;++i) t[i] = in[i] ^ seed[12 + i];
  for (i = 0;i < 8;++i) out[i] = seed[24 + i];
  x = t[11];
  for (loop = 0;loop < 2;++loop) {
    for (r = 0;r < 16;++r) {
      sum += 0x9e3779b9;
      MUSH(0,5) MUSH(1,7) MUSH(2,9) MUSH(3,13)
      MUSH(4,5) MUSH(5,7) MUSH(6,9) MUSH(7,13)
      MUSH(8,5) MUSH(9,7) MUSH(10,9) MUSH(11,13)
    }
    for (i = 0;i < 8;++i) out[i] ^= t[i + 4];
  }
}

unsigned short rand16(void)
{
  if (!outleft) 
    {
      if (!++in[0]) if (!++in[1]) if (!++in[2]) ++in[3];
      surf();
      outleft = 8;
    }
  
  return (unsigned short) out[--outleft];
}

u32 rand32(void)
{
 if (!outleft) 
    {
      if (!++in[0]) if (!++in[1]) if (!++in[2]) ++in[3];
      surf();
      outleft = 8;
    }
  
  return out[--outleft]; 
}

u64 rand64(void)
{
  static int outleft = 0;

  if (outleft < 2)
    {
      if (!++in[0]) if (!++in[1]) if (!++in[2]) ++in[3];
      surf();
      outleft = 8;
    }
  
  outleft -= 2;

  return (u64)out[outleft+1] + (((u64)out[outleft]) << 32);
}


// Both bp.table and bp.pearson are a bit biased due to coexistence,
// but dieharder test suite is reasonably happy with bh_hash():
// 86/17/11 PASSED/WEAK/FAILED tests. cache_hash() in 2.90 was 1/0/113.
//
// PEARSON_LEN is 128 on 32-bit machine to 1) make initialization code uniform
// across 32-bit and 64-bit platforms making bp.pearson shorter than buz.table,
// 2) save 100 bytes of RAM.
//
// uintptr_t is used as a hash value type as keymask for a hashtable might
// be as long as 44 bits for 100k servers sample on x86_64.  So let's fill
// all the available bits in void* with entropy.
//
// https://www.dcs.gla.ac.uk/~hamer/cakes-talk.pdf
// http://www.serve.net/buz/Notes.1st.year/HTML/C6/rand.011.html
// http://www.serve.net/buz/Notes.1st.year/HTML/C6/rand.012.html

#if PTRBITS == 32
#  define PEARSON_LEN 128
#  define PEARSON_MASK 0x7F
#elif PTRBITS == 64
#  define PEARSON_LEN 256
#  define PEARSON_MASK 0xFF
#endif

static union bptable {
  // BUZ hash table. It should be balanced, each bit in all the words should
  // have equal number of ones and zeros.  uint[256] is not really a balanced
  // table for LDH input, so it's trimmed down to LDH alphabet.
  struct {
    uintptr_t table[38], init;
  } buz;
  // Pearson hash random permutation of bytes for random walk. Full byte is
  // used for both values of PEARSON_LEN to share entropy between BUZ and
  // Pearson tables while maintaining their invariants to some extent.
  u8 pearson[PEARSON_LEN];
} bp;

struct permutel {
    u16 index;
    u8 value;
    u8 used;
};

static int cmp16(const void *a, const void *b)
{
  return (int)(((struct permutel*)a)->index) - (int)(((struct permutel*)b)->index);
}

static void bp_init()
{
  struct permutel permutation[256];
  memset(permutation, 0, sizeof(permutation));
  for (int i = 0; i < countof(permutation); i += 2)
    {
      u32 rand = rand32();
      permutation[i].index = rand & 0xFFFF;
      permutation[i].value = i;
      permutation[i+1].index = rand >> 16;
      permutation[i+1].value = i+1;
    }
  qsort(permutation, countof(permutation), sizeof(permutation[0]), cmp16);

  // Let's initialize Pearson table first.  Meanwhile, the beginning of the BUZ
  // table is filled with pairs of bytes: value and ~value to keep it balanced.
  static_assert(sizeof(bp.pearson) < sizeof(bp.buz.table));
  const ssize_t szptr = sizeof(bp.buz.table[0]);
  const ssize_t sha_buz = sizeof(bp.pearson) / szptr;
  u8 filled[sizeof(bp.pearson)];
  memset(filled, 0, sizeof(filled));
  for (int done = 0; done < PEARSON_LEN / 2; done++)
    {
      ptrdiff_t out = memchr(filled + done, 0, sizeof(filled) - done) - (void*)filled;
      int in = 0;
      for (; permutation[in].used; in++)
	assert(in < countof(permutation));

      permutation[in].used = filled[out] = 1;
      bp.pearson[out] = permutation[in].value;

      const u8 notValue = ~permutation[in].value;
      for (; permutation[in].value != notValue; in++)
	assert(in < countof(permutation));

      // Keep offset of the byte within BUZ word.
      for (out = (rand32() % sha_buz) * szptr + (out % szptr); filled[out]; out = (out + szptr) % sizeof(bp.pearson))
	;

      permutation[in].used = filled[out] = 1;
      bp.pearson[out] = permutation[in].value;
    }

  {
    int count = 0;
    for (int i = 0; i < countof(permutation); i++)
      count += permutation[i].used;
    assert(count == sizeof(bp.pearson));
    for (int i = 0; i < PEARSON_LEN; i++)
      assert(filled[i]);
    for (int bit = 0; bit < 8 * szptr; bit++)
      {
	const uintptr_t mask = ((uintptr_t)1u) << bit;
	int count = 0;
	for (int i = 0; i < sha_buz; ++i)
	  count += !!(bp.buz.table[i] & mask);
	assert(count == sha_buz / 2);
      }
  }

  // Fill the rest of BUZ words.
  // static_assert is unrolled due to -O0 compilation being unable to expand `const` variables.
  static_assert(sizeof(bp.buz.table) - sizeof(bp.pearson) == sizeof(bp.buz.table[0]) * 6);
  memset(bp.buz.table + sha_buz, 0, 6 * szptr);
  for (int bit = 0; bit < PTRBITS; bit++)
    {
      const uintptr_t mask = (uintptr_t)1u << bit;
      unsigned int a, b, c;
      u32 r;
      do { // Unif[1,6]
	for (r = rand32() | 0xC0000000; r != 3 && ((r&7) == 0 || (r&7) == 7); r >>= 3) ;
      } while (r == 3);
      a = r & 7;
      do {
	for (r = rand32() | 0xC0000000; r != 3 && ((r&7) == 0 || (r&7) == 7 || (r&7) == a); r >>= 3) ;
      } while (r == 3);
      b = r & 7;
      do {
	for (r = rand32() | 0xC0000000; r != 3 && ((r&7) == 0 || (r&7) == 7 || (r&7) == a || (r&7) == b); r >>= 3) ;
      } while (r == 3);
      c = r & 7;
      assert(a != b && a != c && b != c);
      bp.buz.table[sha_buz + a - 1] |= mask;
      bp.buz.table[sha_buz + b - 1] |= mask;
      bp.buz.table[sha_buz + c - 1] |= mask;
    }

  for (int bit = 0; bit < 8 * szptr; bit++)
    {
      const uintptr_t mask = (uintptr_t)1u << bit;
      int count = 0;
      for (int i = 0; i < countof(bp.buz.table); ++i)
	count += !!(bp.buz.table[i] & mask);
      assert(count == countof(bp.buz.table) / 2);
    }

  // And, finally. buz.init
  bp.buz.init = randptr();
  unsigned int count = popcountptr(bp.buz.init);
  const int shift = sizeof(uintptr_t) == 8 ? 6 : 5;
  const u32 shmask = (1u << shift) - 1;
  if (count < sizeof(uintptr_t) * 4)
    {
      int todo = sizeof(uintptr_t) * 4 - count;
      while (todo)
	{
	  u32 r = rand32() >> 2;
	  for (int i = 0; i < 30 / shift && todo; ++i)
	    {
	      const int bit = r & shmask;
	      const uintptr_t need1 = (uintptr_t)1 << bit;
	      r >>= shift;
	      if (!(bp.buz.init & need1))
	      {
		  bp.buz.init |= need1;
		  todo--;
	      }
	    }
	}
    }
  else if (count > sizeof(uintptr_t) * 4)
    {
      int todo = count - sizeof(uintptr_t) * 4;
      while (todo)
	{
	  u32 r = rand32() >> 2;
	  for (int i = 0; i < 30 / shift && todo; ++i)
	    {
	      const int bit = r & shmask;
	      const uintptr_t need0 = (uintptr_t)1 << bit;
	      r >>= shift;
	      if (bp.buz.init & need0)
	      {
		  bp.buz.init &= ~need0;
		  todo--;
	      }
	    }
	}
    }
  assert(popcountptr(bp.buz.init) == sizeof(uintptr_t) * 4);
}

static u8 buz_ldh_map(u8 c)
{
  const u8 cl = c | 0x20;
  if (0x61 <= cl && cl <= 0x7a) /* [a-z] */
    return cl - 0x61;
  else if (0x30 <= c && c <= 0x39) /* [0-9] */
    return c - 0x30 + 26;
  else if (c == 0x2d || c == 0x2e) /* [-.] */
    return c - 0x2d + 36;
  else if (c == 0x5f)
    return c - 0x5f + 36; /* '_' = '-' */
  else
    return c % countof(bp.buz.table);
  /* Non-LDHu characters are close-to-impossible in DNS, so balance
   * of probabilities for those characters does not matter enough
   * to get them special treatment. */
}

uintptr_t bp_hash(const char *name)
{
  uintptr_t ret = bp.buz.init;
  while (*name)
    {
      const u8 ldh = buz_ldh_map((u8)*name++);
      ret = rotleftptr(ret, 23) ^ bp.buz.table[ldh] ^ bp.pearson[((u8)(ret) ^ ldh) & PEARSON_MASK];
    }
  return ret;
}

struct worm_bsearch* wormb_alloc(int partbits, size_t nmemb)
{
  assert(0 <= partbits && partbits < PTRBITS);
  const size_t sz = max_size(
      sizeof(struct worm_bsearch),
      offsetof(struct worm_bsearch, tabluint) + sizeof(void*) * (nmemb + (1u << partbits)));
  struct worm_bsearch * const ret = whine_malloc(sz);
  if (ret)
    {
      ret->partbits = partbits;
      ret->tabluint[wormb_npart(ret) - 1] = (uintptr_t)(ret->tabluint + wormb_npart(ret) + nmemb);
    }
  return ret;
}

int rr_on_list(struct rrlist *list, unsigned short rr)
{
  while (list)
    {
      if (list->rr != 0 && list->rr == rr)
	return 1;

      list = list->next;
    }

  return 0;
}

/* returns 1 if name is OK and ascii printable
 * returns 2 if name should be processed by IDN */
static int check_name(char *in)
{
  /* remove trailing . 
     also fail empty string and label > 63 chars */
  size_t dotgap = 0, l = strlen(in);
  char c;
  int nowhite = 0;
  int idn_encode = 0;
  int hasuscore = 0;
  int hasucase = 0;
  
  if (l == 0 || l > MAXDNAME) return 0;
  
  if (in[l-1] == '.')
    {
      in[l-1] = 0;
      nowhite = 1;
    }

  for (; (c = *in); in++)
    {
      if (c == '.')
        dotgap = 0;
      else if (++dotgap > MAXLABEL)
        return 0;
      else if (isascii((unsigned char)c) && iscntrl((unsigned char)c)) 
        /* iscntrl only gives expected results for ascii */
        return 0;
      else if (!isascii((unsigned char)c))
#if !defined(HAVE_IDN) && !defined(HAVE_LIBIDN2)
        return 0;
#else
        idn_encode = 1;
#endif
      else if (c != ' ')
        {
          nowhite = 1;
#if defined(HAVE_LIBIDN2) && (!defined(IDN2_VERSION_NUMBER) || IDN2_VERSION_NUMBER < 0x02000003)
          if (c == '_')
            hasuscore = 1;
#else
          (void)hasuscore;
#endif

#if defined(HAVE_IDN) || defined(HAVE_LIBIDN2)
          if (c >= 'A' && c <= 'Z')
            hasucase = 1;
#else
          (void)hasucase;
#endif
        }
    }

  if (!nowhite)
    return 0;

#if defined(HAVE_LIBIDN2) && (!defined(IDN2_VERSION_NUMBER) || IDN2_VERSION_NUMBER < 0x02000003)
  /* Older libidn2 strips underscores, so don't do IDN processing
     if the name has an underscore unless it also has non-ascii characters. */
  idn_encode = idn_encode || (hasucase && !hasuscore);
#else
  idn_encode = idn_encode || hasucase;
#endif

  return (idn_encode) ? 2 : 1;
}

/* Hostnames have a more limited valid charset than domain names
   so check for legal char a-z A-Z 0-9 - _ 
   Note that this may receive a FQDN, so only check the first label 
   for the tighter criteria. */
int legal_hostname(char *name)
{
  char c;
  int first;

  if (!check_name(name))
    return 0;

  for (first = 1; (c = *name); name++, first = 0)
    /* check for legal char a-z A-Z 0-9 - _ . */
    {
      if ((c >= 'A' && c <= 'Z') ||
	  (c >= 'a' && c <= 'z') ||
	  (c >= '0' && c <= '9'))
	continue;

      if (!first && (c == '-' || c == '_'))
	continue;
      
      /* end of hostname part */
      if (c == '.')
	return 1;
      
      return 0;
    }
  
  return 1;
}
  
char *canonicalise(char *in, int *nomem)
{
  char *ret = NULL;
  int rc;
  
  if (nomem)
    *nomem = 0;
  
  if (!(rc = check_name(in)))
    return NULL;
  
#if defined(HAVE_IDN) || defined(HAVE_LIBIDN2)
  if (rc == 2)
    {
#  ifdef HAVE_LIBIDN2
      rc = idn2_to_ascii_lz(in, &ret, IDN2_NONTRANSITIONAL);
#  else
      rc = idna_to_ascii_lz(in, &ret, 0);
#  endif
      if (rc != IDNA_SUCCESS)
	{
	  if (ret)
	    free(ret);
	  
	  if (nomem && (rc == IDNA_MALLOC_ERROR || rc == IDNA_DLOPEN_ERROR))
	    {
	      my_syslog(LOG_ERR, _("failed to allocate memory"));
	      *nomem = 1;
	    }
	  
	  return NULL;
	}
      
      return ret;
    }
#else
  (void)rc;
#endif
  
  if ((ret = whine_malloc(strlen(in)+1)))
    strcpy(ret, in);
  else if (nomem)
    *nomem = 1;

  return ret;
}

unsigned char *do_rfc1035_name(unsigned char *p, char *sval, char *limit)
{
  int j;
  
  while (sval && *sval)
    {
      unsigned char *cp = p++;

      if (limit && p > (unsigned char*)limit)
        return NULL;

      for (j = 0; *sval && (*sval != '.'); sval++, j++)
	{
          if (limit && p + 1 > (unsigned char*)limit)
            return NULL;

	  if (*sval == NAME_ESCAPE)
	    *p++ = (*(++sval))-1;
	  else
	    *p++ = *sval;
	}
      
      *cp  = j;
      if (*sval)
	sval++;
    }
  
  return p;
}

/* for use during startup */
void *safe_malloc(size_t size)
{
  void *ret = calloc(1, size);
  
  if (!ret)
    die(_("could not get memory"), NULL, EC_NOMEM);
      
  return ret;
}

/* Ensure limited size string is always terminated.
 * Can be replaced by (void)strlcpy() on some platforms */
void safe_strncpy(char *dest, const char *src, size_t size)
{
  if (size != 0)
    {
      dest[size-1] = '\0';
      strncpy(dest, src, size-1);
    }
}

void safe_pipe(int *fd, int read_noblock)
{
  if (pipe(fd) == -1 || 
      !fix_fd(fd[1]) ||
      (read_noblock && !fix_fd(fd[0])))
    die(_("cannot create pipe: %s"), NULL, EC_MISC);
}

struct tmarena {
  uintptr_t **chunk; // each chunk is PTRBITS of ${objsz}-byte objects
  uint32_t chunksz;
  uint32_t allocated;
  uint32_t free_hint;
  u8 objsz;
  u8 chunks_unused;
};

static struct tmarena *tmars;
static unsigned int tmarssz;

void tiny_malloc_init(const u8 *size, u8 count)
{
  assert(!tmars);
  tmars = safe_malloc(sizeof(struct tmarena) * count);
  for (int i = 0; i < count; i++)
    tmars[i].objsz = size[i];
  tmarssz = count;
}

static int ptrcmp_qsort(const void *pa, const void *pb)
{
  const uintptr_t *a = pa, *b = pb;
  return (ptrdiff_t)(*a - *b);
}

void *tiny_malloc(u8 size)
{
  struct tmarena *ar = NULL;
  for (unsigned int i = 0; i < tmarssz && !ar; ++i)
    if (tmars[i].objsz == size)
      ar = tmars + i;
  if (!ar)
    return NULL;

  if (ar->allocated == ar->chunksz * PTRBITS)
    {
      if (ar->chunks_unused == 0)
	{
	  u8 chunks_unused = (ar->chunksz >= 16) ? 16 : 4;
	  uintptr_t **c = whine_realloc(ar->chunk, (ar->chunksz + chunks_unused) * sizeof(uintptr_t));
	  if (!c)
	    return NULL;
	  ar->chunk = c;
	  ar->chunks_unused = chunks_unused;
	}
      uintptr_t *ch = whine_malloc(sizeof(uintptr_t) + PTRBITS * ar->objsz);
      if (!ch)
	return NULL;
      // my_syslog(LOG_INFO, "requested: %zu, got: %zu", sizeof(uintptr_t) + PTRBITS * ar->objsz, malloc_usable_size(ch));
      ar->chunk[ar->chunksz] = ch;
      ar->chunks_unused--;
      ar->chunksz++;
      qsort(ar->chunk, ar->chunksz, sizeof(ar->chunk[0]), ptrcmp_qsort);
      uintptr_t free_hint = 0;
      while (ar->chunk[free_hint] != ch)
	free_hint++;
      ar->free_hint = free_hint;
    }

  if (ar->free_hint == UINT_MAX)
    {
      ar->free_hint = 0;
      while (ar->chunk[ar->free_hint][0] == UINTPTR_MAX)
	ar->free_hint++;
      assert(ar->free_hint < ar->chunksz);
    }

  assert(ar->free_hint != UINT_MAX && ar->free_hint < ar->chunksz && ar->chunk[ar->free_hint][0] != UINTPTR_MAX);

  const int ndx = ctzptr(~(ar->chunk[ar->free_hint][0]));
  assert(0 <= ndx && ndx < PTRBITS);
  void* begin = ar->chunk[ar->free_hint] + 1;
  void* obj = begin + ndx * ar->objsz;
  const uintptr_t mask = UINTPTR_C(1) << ndx;
  ar->chunk[ar->free_hint][0] |= mask;
  if (ar->chunk[ar->free_hint][0] == UINTPTR_MAX)
    ar->free_hint = UINT_MAX;
  ar->allocated++;
  return obj;
}

void tiny_free(void *obj, u8 size)
{
  struct tmarena *ar = NULL;
  for (unsigned int i = 0; i < tmarssz && !ar; ++i)
    if (tmars[i].objsz == size)
      ar = tmars + i;
  assert(ar);
  // TODO: bsearch
  for (uint32_t i = 0; i < ar->chunksz; i++)
    {
      const void *begin = ar->chunk[i] + 1;
      const void *end = begin + PTRBITS * sizeof(ar->objsz);
      if (begin <= obj && obj < end)
	{
	  const int ndx = (obj - begin) / sizeof(ar->objsz);
	  const uintptr_t mask = UINTPTR_C(1) << ndx;
	  ar->chunk[i][0] &= ~mask;
	  if (ar->free_hint == UINT_MAX ||
	      popcountptr(ar->chunk[i][0]) > popcountptr(ar->chunk[ar->free_hint][0])
	  )
	    ar->free_hint = i;
	  return;
	}
    }
  abort();
}

void *whine_malloc(size_t size)
{
  void *ret = calloc(1, size);

  if (!ret)
    my_syslog(LOG_ERR, _("failed to allocate %d bytes"), (int) size);
  
  return ret;
}

void *whine_realloc(void *ptr, size_t size)
{
  void *ret = realloc(ptr, size);

  if (!ret)
    my_syslog(LOG_ERR, _("failed to reallocate %d bytes"), (int) size);

  return ret;
}

int sockaddr_isequal(const union mysockaddr *s1, const union mysockaddr *s2)
{
  if (s1->sa.sa_family == s2->sa.sa_family)
    { 
      if (s1->sa.sa_family == AF_INET &&
	  s1->in.sin_port == s2->in.sin_port &&
	  s1->in.sin_addr.s_addr == s2->in.sin_addr.s_addr)
	return 1;
      
      if (s1->sa.sa_family == AF_INET6 &&
	  s1->in6.sin6_port == s2->in6.sin6_port &&
	  s1->in6.sin6_scope_id == s2->in6.sin6_scope_id &&
	  IN6_ARE_ADDR_EQUAL(&s1->in6.sin6_addr, &s2->in6.sin6_addr))
	return 1;
    }
  return 0;
}

int sockaddr_isnull(const union mysockaddr *s)
{
  if (s->sa.sa_family == AF_INET &&
      s->in.sin_addr.s_addr == 0)
    return 1;
  
  if (s->sa.sa_family == AF_INET6 &&
      IN6_IS_ADDR_UNSPECIFIED(&s->in6.sin6_addr))
    return 1;
  
  return 0;
}

int sa_len(union mysockaddr *addr)
{
#ifdef HAVE_SOCKADDR_SA_LEN
  return addr->sa.sa_len;
#else
  if (addr->sa.sa_family == AF_INET6)
    return sizeof(addr->in6);
  else
    return sizeof(addr->in); 
#endif
}

/* don't use strcasecmp and friends here - they may be messed up by LOCALE */
int hostname_order(const char *a, const char *b)
{
  unsigned int c1, c2;
  bench_count(BENCH_HOSTNAME_ORDER, 1);
  
  do {
    c1 = (unsigned char) *a++;
    c2 = (unsigned char) *b++;
    
    if (c1 >= 'A' && c1 <= 'Z')
      c1 += 'a' - 'A';
    if (c2 >= 'A' && c2 <= 'Z')
      c2 += 'a' - 'A';
    
    if (c1 < c2)
      return -1;
    else if (c1 > c2)
      return 1;
    
  } while (c1);
  
  return 0;
}

int hostname_isequal(const char *a, const char *b)
{
  return hostname_order(a, b) == 0;
}

/* is b equal to or a subdomain of a return 2 for equal, 1 for subdomain */
int hostname_issubdomain(char *a, char *b)
{
  char *ap, *bp;
  unsigned int c1, c2;
  
  /* move to the end */
  for (ap = a; *ap; ap++); 
  for (bp = b; *bp; bp++);

  /* a shorter than b or a empty. */
  if ((bp - b) < (ap - a) || ap == a)
    return 0;

  do
    {
      c1 = (unsigned char) *(--ap);
      c2 = (unsigned char) *(--bp);
  
       if (c1 >= 'A' && c1 <= 'Z')
	 c1 += 'a' - 'A';
       if (c2 >= 'A' && c2 <= 'Z')
	 c2 += 'a' - 'A';

       if (c1 != c2)
	 return 0;
    } while (ap != a);

  if (bp == b)
    return 2;

  if (*(--bp) == '.')
    return 1;

  return 0;
}
 
static time_t dnsmasq_time__(void);
time_t dnsmasq_time(void)
{
  struct benchts start;
  bench_start(&start);
  time_t ret = dnsmasq_time__();
  bench_sample(BENCH_DNSMASQ_TIME, &start);
  return ret;
}
static time_t dnsmasq_time__(void)
{
#ifdef HAVE_BROKEN_RTC
  struct timespec ts;

  if (clock_gettime(CLOCK_MONOTONIC, &ts) < 0)
    die(_("cannot read monotonic clock: %s"), NULL, EC_MISC);

  return ts.tv_sec;
#else
  return time(NULL);
#endif
}

u32 dnsmasq_milliseconds(void)
{
  struct timeval tv;

  gettimeofday(&tv, NULL);

  return (tv.tv_sec) * 1000 + (tv.tv_usec / 1000);
}

#ifdef HAVE_DEVTOOLS
struct bench {
  double monosum, monosq;
  unsigned int count;
};

static struct bench bench[__BENCH_MAX];

void bench_start(struct benchts *ts)
{
#ifdef CLOCK_MONOTONIC_RAW
  clockid_t clock = CLOCK_MONOTONIC_RAW;
#else
  clockid_t clock = CLOCK_MONOTONIC;
#endif
  if (clock_gettime(clock, &ts->mono) < 0)
    die(_("cannot read monotonic clock for benchmarking: %s"), NULL, EC_MISC);
}

void bench_sample(enum bench_metrics m, struct benchts *start)
{
  struct benchts now;
  bench_start(&now);
  double mono = (now.mono.tv_nsec - start->mono.tv_nsec) * 1e-9 + (now.mono.tv_sec - start->mono.tv_sec);
  bench[m].monosum += mono;
  bench[m].monosq += mono * mono;
  bench[m].count++;
}

void bench_count(enum bench_metrics m, unsigned int count)
{
  bench[m].monosum = NAN;
  bench[m].monosq = NAN;
  bench[m].count += count;
}

void bench_loop(enum bench_metrics m, struct benchts *start, unsigned int count)
{
  struct benchts now;
  bench_start(&now);
  double mono = (now.mono.tv_nsec - start->mono.tv_nsec) * 1e-9 + (now.mono.tv_sec - start->mono.tv_sec);
  bench[m].monosum += mono;
  bench[m].monosq = NAN;
  bench[m].count += count;
}

void bench_log(enum bench_metrics m, const char *msg)
{
  const unsigned int cu = bench[m].count;
  const double cd = bench[m].count;
  double monoavg = cu ? (bench[m].monosum / cd) : NAN;
  double monostdev = (cu > 1 && !isnan(bench[m].monosq))
    ? sqrt((bench[m].monosq - bench[m].monosum * bench[m].monosum / cd) / (cd - 1))
    : (cu == 1) ? 0.0 : NAN;

  double scale = monoavg;
  char *suffix;
  if (scale < 1e-6) { scale = 1e9; suffix = "ns"; }
  else if (scale < 1e-3) { scale = 1e6; suffix = "us"; }
  else if (scale < 1.0) { scale = 1e3; suffix = "ms"; }
  else { scale = 1.0; suffix = "s"; }
  if (!isnan(monostdev) && fpclassify(monostdev) != FP_ZERO)
    my_syslog(LOG_INFO, _("benchmark %s\tCount: %u\tavg %g %s\tstdev %g"), msg, cu, monoavg*scale, suffix, monostdev*scale);
  else if (!isnan(monoavg))
    my_syslog(LOG_INFO, _("benchmark %s\tCount: %u\tavg %g %s"), msg, cu, monoavg*scale, suffix);
  else
    my_syslog(LOG_INFO, _("benchmark %s\tCount: %u"), msg, cu);
}

void statm_log(const char *suffix)
{
  size_t vmsize, vmrss, shared, text, data;
  FILE *fd = fopen("/proc/self/statm", "r");
  if (!fd)
    {
      my_syslog(LOG_ERR, _("failed to open /proc/self/statm"));
      return;
    }
  if (!suffix)
    suffix = "";

  if (fscanf(fd, "%zu %zu %zu %zu 0 %zu 0", &vmsize, &vmrss, &shared, &text, &data) == 5)
    my_syslog(LOG_INFO, _("statm%s: VmSize: %zu kB, VmRSS: %zu kB, data+stack: %zu kB, RssFile+RssShmem: %zu kB, text: %zu kB"),
	suffix, 4 * vmsize, 4 * vmrss, 4 * data, 4 * shared, 4 * text);
  else
    my_syslog(LOG_ERR, _("failed to parse /proc/self/statm"));
  fclose(fd);
}
#endif

int netmask_length(struct in_addr mask)
{
  int zero_count = 0;

  while (0x0 == (mask.s_addr & 0x1) && zero_count < 32) 
    {
      mask.s_addr >>= 1;
      zero_count++;
    }
  
  return 32 - zero_count;
}

int is_same_net(struct in_addr a, struct in_addr b, struct in_addr mask)
{
  return (a.s_addr & mask.s_addr) == (b.s_addr & mask.s_addr);
}

int is_same_net_prefix(struct in_addr a, struct in_addr b, int prefix)
{
  struct in_addr mask;

  mask.s_addr = htonl(~((1 << (32 - prefix)) - 1));

  return is_same_net(a, b, mask);
}


int is_same_net6(struct in6_addr *a, struct in6_addr *b, int prefixlen)
{
  int pfbytes = prefixlen >> 3;
  int pfbits = prefixlen & 7;

  if (memcmp(&a->s6_addr, &b->s6_addr, pfbytes) != 0)
    return 0;

  if (pfbits == 0 ||
      (a->s6_addr[pfbytes] >> (8 - pfbits) == b->s6_addr[pfbytes] >> (8 - pfbits)))
    return 1;

  return 0;
}

/* return least significant 64 bits if IPv6 address */
u64 addr6part(struct in6_addr *addr)
{
  int i;
  u64 ret = 0;

  for (i = 8; i < 16; i++)
    ret = (ret << 8) + addr->s6_addr[i];

  return ret;
}

void setaddr6part(struct in6_addr *addr, u64 host)
{
  int i;

  for (i = 15; i >= 8; i--)
    {
      addr->s6_addr[i] = host;
      host = host >> 8;
    }
}


/* returns port number from address */
int prettyprint_addr(union mysockaddr *addr, char *buf)
{
  int port = 0;
  
  if (addr->sa.sa_family == AF_INET)
    {
      inet_ntop(AF_INET, &addr->in.sin_addr, buf, ADDRSTRLEN);
      port = ntohs(addr->in.sin_port);
    }
  else if (addr->sa.sa_family == AF_INET6)
    {
      char name[IF_NAMESIZE];
      inet_ntop(AF_INET6, &addr->in6.sin6_addr, buf, ADDRSTRLEN);
      if (addr->in6.sin6_scope_id != 0 &&
	  if_indextoname(addr->in6.sin6_scope_id, name) &&
	  strlen(buf) + strlen(name) + 2 <= ADDRSTRLEN)
	{
	  strcat(buf, "%");
	  strcat(buf, name);
	}
      port = ntohs(addr->in6.sin6_port);
    }
  
  return port;
}

void prettyprint_time(char *buf, unsigned int t)
{
  if (t == 0xffffffff)
    sprintf(buf, _("infinite"));
  else
    {
      unsigned int x, p = 0;
       if ((x = t/86400))
	p += sprintf(&buf[p], "%ud", x);
       if ((x = (t/3600)%24))
	p += sprintf(&buf[p], "%uh", x);
      if ((x = (t/60)%60))
	p += sprintf(&buf[p], "%um", x);
      if ((x = t%60))
	sprintf(&buf[p], "%us", x);
    }
}


/* in may equal out, when maxlen may be -1 (No max len). 
   Return -1 for extraneous no-hex chars found. */
int parse_hex(char *in, unsigned char *out, int maxlen, 
	      unsigned int *wildcard_mask, int *mac_type)
{
  int done = 0, mask = 0, i = 0;
  char *r;
    
  if (mac_type)
    *mac_type = 0;
  
  while (!done && (maxlen == -1 || i < maxlen))
    {
      for (r = in; *r != 0 && *r != ':' && *r != '-' && *r != ' '; r++)
	if (*r != '*' && !isxdigit((unsigned char)*r))
	  return -1;
      
      if (*r == 0)
	done = 1;
      
      if (r != in )
	{
	  if (*r == '-' && i == 0 && mac_type)
	   {
	      *r = 0;
	      *mac_type = strtol(in, NULL, 16);
	      mac_type = NULL;
	   }
	  else
	    {
	      *r = 0;
	      if (strcmp(in, "*") == 0)
		{
		  mask = (mask << 1) | 1;
		  i++;
		}
	      else
		{
		  int j, bytes = (1 + (r - in))/2;
		  for (j = 0; j < bytes; j++)
		    { 
		      char sav;
		      if (j < bytes - 1)
			{
			  sav = in[(j+1)*2];
			  in[(j+1)*2] = 0;
			}
		      /* checks above allow mix of hexdigit and *, which
			 is illegal. */
		      if (strchr(&in[j*2], '*'))
			return -1;
		      out[i] = strtol(&in[j*2], NULL, 16);
		      mask = mask << 1;
		      if (++i == maxlen)
			break; 
		      if (j < bytes - 1)
			in[(j+1)*2] = sav;
		    }
		}
	    }
	}
      in = r+1;
    }
  
  if (wildcard_mask)
    *wildcard_mask = mask;

  return i;
}

/* return 0 for no match, or (no matched octets) + 1 */
int memcmp_masked(unsigned char *a, unsigned char *b, int len, unsigned int mask)
{
  int i, count;
  for (count = 1, i = len - 1; i >= 0; i--, mask = mask >> 1)
    if (!(mask & 1))
      {
	if (a[i] == b[i])
	  count++;
	else
	  return 0;
      }
  return count;
}

/* _note_ may copy buffer */
int expand_buf(struct iovec *iov, size_t size)
{
  void *new;

  if (size <= (size_t)iov->iov_len)
    return 1;

  if (!(new = whine_malloc(size)))
    {
      errno = ENOMEM;
      return 0;
    }

  if (iov->iov_base)
    {
      memcpy(new, iov->iov_base, iov->iov_len);
      free(iov->iov_base);
    }

  iov->iov_base = new;
  iov->iov_len = size;

  return 1;
}

char *print_mac(char *buff, unsigned char *mac, int len)
{
  char *p = buff;
  int i;
   
  if (len == 0)
    sprintf(p, "<null>");
  else
    for (i = 0; i < len; i++)
      p += sprintf(p, "%.2x%s", mac[i], (i == len - 1) ? "" : ":");
  
  return buff;
}

/* rc is return from sendto and friends.
   Return 1 if we should retry.
   Set errno to zero if we succeeded. */
int retry_send(ssize_t rc)
{
  static int retries = 0;
  struct timespec waiter;
  
  if (rc != -1)
    {
      retries = 0;
      errno = 0;
      return 0;
    }
  
  /* Linux kernels can return EAGAIN in perpetuity when calling
     sendmsg() and the relevant interface has gone. Here we loop
     retrying in EAGAIN for 1 second max, to avoid this hanging 
     dnsmasq. */

  if (errno == EAGAIN || errno == EWOULDBLOCK)
     {
       waiter.tv_sec = 0;
       waiter.tv_nsec = 10000;
       nanosleep(&waiter, NULL);
       if (retries++ < 1000)
	 return 1;
     }
  
  retries = 0;
  
  if (errno == EINTR)
    return 1;
  
  return 0;
}

int read_write(int fd, unsigned char *packet, int size, int rw)
{
  ssize_t n, done;
  
  for (done = 0; done < size; done += n)
    {
      do { 
	if (rw)
	  n = read(fd, &packet[done], (size_t)(size - done));
	else
	  n = write(fd, &packet[done], (size_t)(size - done));
	
	if (n == 0)
	  return 0;
	
      } while (retry_send(n) || errno == ENOMEM || errno == ENOBUFS);

      if (errno != 0)
	return 0;
    }
     
  return 1;
}

/* close all fds except STDIN, STDOUT and STDERR, spare1, spare2 and spare3 */
void close_fds(long max_fd, int spare1, int spare2, int spare3) 
{
  /* On Linux, use the /proc/ filesystem to find which files
     are actually open, rather than iterate over the whole space,
     for efficiency reasons. If this fails we drop back to the dumb code. */
#ifdef HAVE_LINUX_NETWORK 
  DIR *d;
  
  if ((d = opendir("/proc/self/fd")))
    {
      struct dirent *de;

      while ((de = readdir(d)))
	{
	  long fd;
	  char *e = NULL;
	  
	  errno = 0;
	  fd = strtol(de->d_name, &e, 10);
	  	  
      	  if (errno != 0 || !e || *e || fd == dirfd(d) ||
	      fd == STDOUT_FILENO || fd == STDERR_FILENO || fd == STDIN_FILENO ||
	      fd == spare1 || fd == spare2 || fd == spare3)
	    continue;
	  
	  close(fd);
	}
      
      closedir(d);
      return;
  }
#endif

  /* fallback, dumb code. */
  for (max_fd--; max_fd >= 0; max_fd--)
    if (max_fd != STDOUT_FILENO && max_fd != STDERR_FILENO && max_fd != STDIN_FILENO &&
	max_fd != spare1 && max_fd != spare2 && max_fd != spare3)
      close(max_fd);
}

/* Basically match a string value against a wildcard pattern.  */
int wildcard_match(const char* wildcard, const char* match)
{
  while (*wildcard && *match)
    {
      if (*wildcard == '*')
        return 1;

      if (*wildcard != *match)
        return 0; 

      ++wildcard;
      ++match;
    }

  return *wildcard == *match;
}

/* The same but comparing a maximum of NUM characters, like strncmp.  */
int wildcard_matchn(const char* wildcard, const char* match, int num)
{
  while (*wildcard && *match && num)
    {
      if (*wildcard == '*')
        return 1;

      if (*wildcard != *match)
        return 0; 

      ++wildcard;
      ++match;
      --num;
    }

  return (!num) || (*wildcard == *match);
}

#if HAVE_DEVTOOLS
static int qsort_init_ctx qcomp(const void *av, const void *bv, void *ctx);

static int qsort_init_cmp qcomp(const void *av, const void *bv, void *ctx)
{
  const u32 *a = av;
  const u32 *b = bv;
  assert((*a ^ *b) == (0x8BADF00D ^ 0xF00DBABE));
  assert(ctx == qsort_init_ctx);
  return *a < *b ? -1 : 1;
}

static int qsort_init_ctx qcomp(const void *av, const void *bv, void *ctx)
{
  return qsort_init_cmp(av, bv, ctx);
}

void qsort_init()
{
  u32 arr[2] = { 0x8BADF00D, 0xF00DBABE };
  qsort_arr(arr, countof(arr), sizeof(arr[0]), qsort_init_cmp, qsort_init_ctx);
}
#endif

void qsort_arr(void *base, size_t nmemb, size_t width, qsort_cmp fn, void *ctx)
{

#if defined(HAVE_QSORT_X_GNU)
  qsort_r(base, nmemb, width, fn, ctx);
#elif defined(HAVE_QSORT_X_BSD)
  qsort_r(base, nmemb, width, ctx, fn);
#else
# error Does this platform have qsort_r(), qsort_s() or something alike?...
#endif
}

#ifdef HAVE_LINUX_NETWORK
int kernel_version(void)
{
  struct utsname utsname;
  int version;
  char *split;
  
  if (uname(&utsname) < 0)
    die(_("failed to find kernel version: %s"), NULL, EC_MISC);
  
  split = strtok(utsname.release, ".");
  version = (split ? atoi(split) : 0);
  split = strtok(NULL, ".");
  version = version * 256 + (split ? atoi(split) : 0);
  split = strtok(NULL, ".");
  return version * 256 + (split ? atoi(split) : 0);
}
#endif
