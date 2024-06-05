#define BPD_PTROPS_SOURCE 1
#include "bpdhash.h"
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>

// Both bpd.table and bpd.pearson are a bit biased due to coexistence,
// but dieharder test suite is reasonably happy with bh_hash():
// 86/17/11 PASSED/WEAK/FAILED tests. cache_hash() in 2.90 was 1/0/113.
//
// PEARSON_LEN is 128 on 32-bit machine to 1) make initialization code uniform
// across 32-bit and 64-bit platforms making bpd.pearson shorter than buz.table,
// 2) save 100 bytes of RAM.
//
// uintptr_t is used as a hash value type as keymask for a hashtable might
// be as long as 44 bits for 100k servers sample on x86_64.  So let's fill
// all the available bits in void* with entropy.
//
// https://www.dcs.gla.ac.uk/~hamer/cakes-talk.pdf
// http://www.serve.net/buz/Notes.1st.year/HTML/C6/rand.011.html
// http://www.serve.net/buz/Notes.1st.year/HTML/C6/rand.012.html

#ifndef RAND32
#  define RAND32 rand32
#endif
#ifndef RAND64
#  define RAND64 rand64
#endif
uint32_t RAND32(void);
uint64_t RAND64(void);

#define countof(x) (sizeof(x) / sizeof(x[0]))
static inline uintptr_t randptr() { return (PTRBITS == 32) ? RAND32() : RAND64(); }

#if PTRBITS == 32
#  define PEARSON_LEN 128
#  define PEARSON_BITS 7
#  define PEARSON_MASK 0x7F
#elif PTRBITS == 64
#  define PEARSON_LEN 256
#  define PEARSON_BITS 8
#  define PEARSON_MASK 0xFF
#else
#  error NotImplementedError: what an unusual PTRBITS and sizeof(void*)!
#endif

static union bptable {
  // BUZ hash table. It should be balanced, each bit in all the words should
  // have equal number of ones and zeros.  uint[256] is not really a balanced
  // table for LDH input, so it's trimmed down to LDH alphabet.
  struct {
    uintptr_t table[39], init;
  } buz;
  // Pearson hash random permutation of bytes for random walk. Full byte is
  // used for both values of PEARSON_LEN to share entropy between BUZ and
  // Pearson tables while maintaining their invariants to some extent.
  uint8_t pearson[PEARSON_LEN];
} bpd;

// BUZTABLE_SHARED is defined as a macro as -O0 sometimes fails to expand
// `const` variables for static_assert.
#define BUZTABLE_NONLDH 8
#define BUZTABLE_SHARED (sizeof(bpd.pearson) / sizeof(bpd.buz.table[0]))
#define BPD_PEAR_PER_BUZ (sizeof(bpd.buz.table[0]) / sizeof(bpd.pearson[0]))
static_assert(sizeof(bpd.pearson) % sizeof(bpd.buz.table[0]) == 0);

struct permutel {
    uint16_t index;
    uint8_t value;
    uint8_t used;
};

static int cmp16(const void *a, const void *b)
{
  return (int)(((struct permutel*)a)->index) - (int)(((struct permutel*)b)->index);
}

void bpd_init()
{
  struct permutel permutation[256];
  memset(permutation, 0, sizeof(permutation));
  for (unsigned int i = 0; i < countof(permutation); i += 2)
    {
      uint32_t rand = RAND32();
      permutation[i].index = rand & 0xFFFF;
      permutation[i].value = i;
      permutation[i+1].index = rand >> 16;
      permutation[i+1].value = i+1;
    }
  qsort(permutation, countof(permutation), sizeof(permutation[0]), cmp16);

  // Let's initialize Pearson table first.  Meanwhile, the beginning of the BUZ
  // table is filled with pairs of bytes: value and ~value to keep it balanced.
  static_assert(sizeof(bpd.pearson) < sizeof(bpd.buz.table));
  const size_t szptr = sizeof(bpd.buz.table[0]);
  uint8_t filled[sizeof(bpd.pearson)];
  memset(filled, 0, sizeof(filled));
  for (int done = 0; done < PEARSON_LEN / 2; done++)
    {
      ptrdiff_t out = memchr(filled + done, 0, sizeof(filled) - done) - (void*)filled;
      unsigned int in = 0;
      for (; permutation[in].used; in++)
	assert(in < countof(permutation));

      permutation[in].used = filled[out] = 1;
      bpd.pearson[out] = permutation[in].value;

      const uint8_t notValue = ~permutation[in].value;
      for (; permutation[in].value != notValue; in++)
	assert(in < countof(permutation));

      // Keep offset of the byte within BUZ word.
      for (out = (RAND32() % BUZTABLE_SHARED) * szptr + (out % szptr); filled[out]; out = (out + szptr) % sizeof(bpd.pearson))
	;

      permutation[in].used = filled[out] = 1;
      bpd.pearson[out] = permutation[in].value;
    }

  {
    int count = 0;
    for (unsigned int i = 0; i < countof(permutation); i++)
      count += permutation[i].used;
    assert(count == sizeof(bpd.pearson));
    for (unsigned int i = 0; i < PEARSON_LEN; i++)
      assert(filled[i]);
    for (unsigned int bit = 0; bit < 8 * szptr; bit++)
      {
	const uintptr_t mask = ((uintptr_t)1u) << bit;
	int count = 0;
	for (unsigned int i = 0; i < BUZTABLE_SHARED; ++i)
	  count += !!(bpd.buz.table[i] & mask);
	assert(count == BUZTABLE_SHARED / 2);
      }
  }

  // Fill the rest of BUZ words.
  static_assert(BUZTABLE_NONLDH < BUZTABLE_SHARED);
  static_assert(countof(bpd.buz.table) - BUZTABLE_SHARED == 7);
  memset(bpd.buz.table + BUZTABLE_SHARED, 0, 7 * szptr);
  for (int bit = 0; bit < PTRBITS; bit++)
    {
      const uintptr_t mask = (uintptr_t)1u << bit;
      unsigned int a, b, c;
      uint32_t r;
      do { // Unif[1,6]
	for (r = RAND32() | 0xC0000000; r != 3 && ((r&7) == 0 || (r&7) == 7); r >>= 3) ;
      } while (r == 3);
      a = r & 7;
      do {
	for (r = RAND32() | 0xC0000000; r != 3 && ((r&7) == 0 || (r&7) == 7 || (r&7) == a); r >>= 3) ;
      } while (r == 3);
      b = r & 7;
      do {
	for (r = RAND32() | 0xC0000000; r != 3 && ((r&7) == 0 || (r&7) == 7 || (r&7) == a || (r&7) == b); r >>= 3) ;
      } while (r == 3);
      c = r & 7;
      assert(a != b && a != c && b != c);
      bpd.buz.table[BUZTABLE_SHARED + a - 1] |= mask;
      bpd.buz.table[BUZTABLE_SHARED + b - 1] |= mask;
      bpd.buz.table[BUZTABLE_SHARED + c - 1] |= mask;
    }
  bpd.buz.table[countof(bpd.buz.table) - 1] = bpd.buz.table[BUZTABLE_NONLDH];

  // It's not that the code should care that much for non-LDH input for BUZ
  // hash, but let's shuffle bpd.buz.table[BUZTABLE_NONLDH] a bit for the sake
  // of completeness. All in all, it's impossible to have a balanced table
  // of 39 elements anyway :-)
  while (bpd.buz.table[countof(bpd.buz.table) - 1] == bpd.buz.table[BUZTABLE_NONLDH])
    {
      static_assert(BPD_PEAR_PER_BUZ % 2 == 0);
      uint8_t* const nonldh = (uint8_t*)&bpd.buz.table[BUZTABLE_NONLDH];
      for (unsigned int i = 0; i < BPD_PEAR_PER_BUZ; i += 2)
	{
	  uint32_t rand = RAND32();
	  permutation[i].index = rand & 0xFFFF;
	  permutation[i].value = nonldh[i];
	  permutation[i+1].index = rand >> 16;
	  permutation[i+1].value = nonldh[i+1];
	}
      qsort(permutation, BPD_PEAR_PER_BUZ, sizeof(permutation[0]), cmp16);
      for (unsigned int i = 0; i < BPD_PEAR_PER_BUZ; i++)
	nonldh[i] = permutation[i].value;
    }

  for (unsigned int bit = 0; bit < 8 * szptr; bit++)
    {
      const uintptr_t mask = (uintptr_t)1u << bit;
      int count = 0;
      for (unsigned int i = 0; i < countof(bpd.buz.table); ++i)
	if (i != BUZTABLE_NONLDH)
	  count += !!(bpd.buz.table[i] & mask);
      assert(count == (countof(bpd.buz.table) - 1) / 2);
    }

  // And, finally. buz.init
  bpd.buz.init = randptr();
  unsigned int count = popcountptr(bpd.buz.init);
  const int shift = sizeof(uintptr_t) == 8 ? 6 : 5;
  const uint32_t shmask = (1u << shift) - 1;
  if (count < sizeof(uintptr_t) * 4)
    {
      int todo = sizeof(uintptr_t) * 4 - count;
      while (todo)
	{
	  uint32_t r = RAND32() >> 2;
	  for (int i = 0; i < 30 / shift && todo; ++i)
	    {
	      const int bit = r & shmask;
	      const uintptr_t need1 = (uintptr_t)1 << bit;
	      r >>= shift;
	      if (!(bpd.buz.init & need1))
	      {
		  bpd.buz.init |= need1;
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
	  uint32_t r = RAND32() >> 2;
	  for (int i = 0; i < 30 / shift && todo; ++i)
	    {
	      const int bit = r & shmask;
	      const uintptr_t need0 = (uintptr_t)1 << bit;
	      r >>= shift;
	      if (bpd.buz.init & need0)
	      {
		  bpd.buz.init &= ~need0;
		  todo--;
	      }
	    }
	}
    }
  assert(popcountptr(bpd.buz.init) == sizeof(uintptr_t) * 4);
  static_assert(('A' ^ 0x80) == 0xC1 && ('a' ^ 0x80) == 0xE1);
  assert(bpdldhhs("A") == bpdldhhs("a"));
  assert(bpdldhhs("A") != bpdldhhs("\xC1"));
  assert(bpdldhhs("A") != bpdldhhs("\xE1"));
  assert(bpdldhhs("\xC1") != bpdldhhs("\xE1"));
  static_assert('0' == 0x30);
  assert(bpdldhhs("0") != bpdldhhs("\x10"));
  assert(bpdldhhs("abc") != bpdldhhs("bca"));
  assert(bpdldhhs("aaa") != bpdldhhs("a"));
  assert(bpdldhhs("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") == bpdldhhs("aa"));
#if 0
  assert(bpdldhhs("A") == (rotleftptr(bpd.buz.init, 7) ^ bpd.buz.table['a' % 39] ^ bpd.pearson[(bpd.buz.init ^ 'a') & PEARSON_MASK]));
  assert(bpdldhhs("a") == (rotleftptr(bpd.buz.init, 7) ^ bpd.buz.table['a' % 39] ^ bpd.pearson[(bpd.buz.init ^ 'a') & PEARSON_MASK]));
  assert(bpdldhhs("0") == (rotleftptr(bpd.buz.init, 7) ^ bpd.buz.table['0' % 39] ^ bpd.pearson[(bpd.buz.init ^ '0') & PEARSON_MASK]));
#endif
}

/* Non-LDHu characters are close-to-impossible in DNS, so balance
 * of probabilities for those characters does not matter enough
 * to get them special treatment.
 */
#define BPD_X20(in) (('A' <= in && in <= 'Z') ? (in | 0x20) : in)
static_assert(
    BPD_X20('-') % 39 ==  6 &&
    BPD_X20('.') % 39 ==  7 &&
    BUZTABLE_NONLDH  ==  8 &&
    BPD_X20('0') % 39 ==  9 &&
    BPD_X20('9') % 39 == 18 &&
    BPD_X20('A') % 39 == 19 &&
    BPD_X20('T') % 39 == 38 &&
    BPD_X20('U') % 39 ==  0 &&
    BPD_X20('Z') % 39 ==  5 &&
    BPD_X20('a') % 39 == 19 &&
    BPD_X20('t') % 39 == 38 &&
    BPD_X20('u') % 39 ==  0 &&
    BPD_X20('z') % 39 ==  5 &&
    39 == countof(bpd.buz.table)
);

#define MULBUZ 1450543
#define MULSHI 107
#define SHIMOD 58

uintptr_t bpdldhhs(const char *src)
{
  uintptr_t ret = bpd.buz.init;
  for (; *src; src++)
    {
      uint8_t in = *(uint8_t*)src;
#if 0
      const u8 lc = in - 'A';
      const u8 h3 = lc & (0x80|0x40|0x20);
      const u8 is_az = ((UINT32_C(0x1ffffff) << 5) >> (lc & 0x1f));
      const u8 mask = ((!h3) << 5) & is_az;
      in |= mask;
#elif 0
      const u8 msb20 = (in & 0x80) >> 2;
      const u8 mask = (0xFF ^ 0x20) | msb20;
      in &= mask;
#else
      if ('A' <= in && in <= 'Z')
        in |= 0x20;
#endif
      const unsigned int buz = (in * MULBUZ) % 39;
      const unsigned int shi = 1 + ((in * MULSHI) % SHIMOD);
      if (PEARSON_BITS == 7)
	in &= 0x7F;
      ret = rotleftptr(ret, shi) ^ bpd.buz.table[buz] /* ^ bpd.pearson[(ret >> (PTRBITS - PEARSON_BITS)) ^ in] */;
    }
  return ret;
}

uintptr_t bpdbinhm(const void *src, unsigned int n)
{
  return bpdbinh3(src, n, bpd.buz.init);
}

uintptr_t bpdbinh3(const void *src, unsigned int n, uintptr_t seed)
{
  uintptr_t ret = seed;
  for (; n; src++, n--)
    {
      uint8_t in = *(uint8_t*)src;
      const unsigned int buz = (in * MULBUZ) % 39;
      const unsigned int shi = 1 + ((in * MULSHI) % SHIMOD);
      if (PEARSON_BITS == 7)
	in &= 0x7F;
      ret = rotleftptr(ret, shi) ^ bpd.buz.table[buz] /* ^ bpd.pearson[(ret >> (PTRBITS - PEARSON_BITS)) ^ in] */;
    }
  return ret;
}

