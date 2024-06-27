#include "dnsmasq.h"

#include <stdalign.h>

#define XXH_NO_STREAM
#define XXH_NO_XXH3
#define XXH_INLINE_ALL
// 1) there is no need to keep hashes consistent across platforms
// 2) XXH_get64bits and XXH_get32bits are defined as readLE, only hashFromCanonical uses readBE.
// 3) Enforcing LE and aligned access saves some opcodes in XXH.
// 4) XXH_FORCE_ALIGN_CHECK=0 does not matter as XXH64() and XXH32() are not used :-)
#define XXH_CPU_LITTLE_ENDIAN 1
#define XXH_FORCE_MEMORY_ACCESS 2
#include "xxhash.h"

static uintptr_t dnseed;

struct dneedle {
  u8 b;
  u8 bx[];
};

struct dneedle_aligned {
  union {
    struct dneedle d;
    uintptr_t align;
  };
};

// https://graphics.stanford.edu/~seander/bithacks.html#ZeroInWord might make it SIMD.
static size_t memcount(const char *s, char c, size_t n)
{
  size_t ret = 0;
  for (; n; n--, s++)
    if (*s == c)
      ret++;
  return ret;
}

static u8 dn_special(u8 c)
{
  static_assert(NAME_ESCAPE != '\0');
  assert(c == '\0' || c == '.' || c == NAME_ESCAPE);
  if (c == '\0')
    return 'Z';
  else if (c == '.')
    return 'D';
  else if (c == NAME_ESCAPE)
    return NAME_ESCAPE;
  return c;
}

// http://www.azillionmonkeys.com/qed/asmexample.html might make it SIMD.
static u8 dn_label(u8 c)
{
  if ('A' <= c && c <= 'Z')
    c |= 0x20;
  return c;
}

// dneetoa() writes to static buffer like itoa(), that's suitable for logging, but not more.
const char *dneetoa(const struct dneedle *d)
{
  // len(lable) < 64, and label separator is not escaped, so it's a bit more than needed.
  static char buf[DNEEDLE_LEN_MAX * 4 + 1];
  if (!d)
    return strcpy(buf, "<NULL>");
  static_assert(offsetof(struct dneedle, b) == 0);
  const u8 *src = &d->b;
  u8 *dst = (u8*)buf;
  size_t todo = strlen((const char*)src);
  if (DNEEDLE_LEN_MAX < todo) // TODO: carefully test edge cases
    {
      src = src + todo - 1 - DNEEDLE_LEN_MAX;
      todo = DNEEDLE_LEN_MAX;
    }
  else
    src = src + todo - 1;

  // non-LDHu is escaped to \ddd per https://datatracker.ietf.org/doc/html/rfc4343#section-2.1
  for (; todo; src--, dst++, todo--)
    if (*src == 'D')
      *dst = '\\', dst++, *dst = '.';
    else if (*src == '\\')
      *dst = '\\', dst++, *dst = '\\';
    else if (0x21 <= *src && *src <= 0x7E) // '!' ... '~'
      *dst = *src;
    else
      sprintf((char*)dst, "\\%03d", *src), dst += 3;
  if (src+1 == (const u8*)d)
    *dst = '\0';
  else
    {
      dst[-3] = dst[-2] = dst[-1] = '.';
      *dst = '\0';
    }
  return buf;
}

int do_dneedle(void *dst, const char *presentation, size_t n)
{
  const size_t plen = strlen(presentation);
  const size_t escapes = memcount(presentation, NAME_ESCAPE, plen);
  const size_t dneedlen = plen - escapes;
  if (n < dneedlen + 1) // + '\0'
    return -1;
  u8 *d = dst;
  d[dneedlen] = 0;
  const u8 *src = (const u8*)presentation;
  // `d` points right before '\0', it is out of bounds for "" and it's okay as *src == '\0'
  for (d = d + dneedlen - 1; *src; src++, d--)
    if (*src == NAME_ESCAPE)
      src++, *d = dn_special(*src - 1);
    else
      *d = dn_label(*src);
  return dneedlen;
}

void dn_init()
{
  dnseed = randptr();
  // Some platforms execute XXH(badptr, XXH_aligned) faster than
  // memcpy(good, bad)+XXH(goodptr, XXH_aligned). Other deliver SIGBUS.
  // Moreover, ARM platforms might have the behavior configurable in runtime
  // via /proc/cpu/alignment.
  //
  // TODO: it might be benificial to do a start-up check for the best dn_hash().
  // - https://stackoverflow.com/questions/1496848/does-unaligned-memory-access-always-cause-bus-errors
  // - https://stackoverflow.com/questions/11837550/prohibit-unaligned-memory-accesses-on-x86-x86-64
  // - https://stackoverflow.com/questions/16548059/how-to-trap-unaligned-memory-access
  // - https://stackoverflow.com/questions/19352232/unaligned-memory-access
  // - https://stackoverflow.com/questions/35494490/any-way-to-stop-unaligned-access-from-c-standard-library-on-x86-64
  // - https://stackoverflow.com/questions/69765617/why-does-x86-allows-for-unaligned-accesses-and-how-unaligned-accesses-can-be-de
  // - https://mjmwired.net/kernel/Documentation/arm/mem_alignment
  // - https://fastcompression.blogspot.com/2015/08/accessing-unaligned-memory.html
  //
  // Some architectures are not capable of unaligned memory access, but will
  // silently perform a different memory access to the one that was requested,
  // resulting in a subtle code bug that is hard to detect!
  // -- https://www.kernel.org/doc/html/latest/core-api/unaligned-memory-access.html
}

uintptr_t dn_hazh(const struct dneedle *p)
{
  return dn_hash(p, strlen((const char *)p));
}

uintptr_t dn_hash(const struct dneedle *p, size_t len)
{
  if (((uintptr_t)p & (alignof(uintptr_t) - 1)) == 0)
    return dna_hash((const struct dneedle_aligned*)p, len);
  union {
    struct dneedle_aligned dna;
    uintptr_t align[(len + sizeof(uintptr_t) - 1) / sizeof(uintptr_t)];
  } u;
  memcpy(&u.dna, p, len);
  return dna_hash(&u.dna, len);
}

uintptr_t dna_hash(const struct dneedle_aligned *p, size_t len)
{
  assert(len <= DNEEDLE_LEN_MAX);
#if PTRBITS == 32
#  define XXFN XXH32_endian_align
#elif PTRBITS == 64
#  define XXFN XXH64_endian_align
#endif
  static_assert(offsetof(struct dneedle_aligned, d.b) == 0);
  return XXFN(&p->d.b, len, dnseed, XXH_aligned);
}
