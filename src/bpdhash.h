#ifndef BPD_HASH_H
#define BPD_HASH_H

#include <stdint.h>

#ifdef BPD_PTROPS_SOURCE

#include <limits.h>

#ifndef PTRBITS
#  if UINTPTR_MAX == UINT32_C(0xFFFFFFFF)
#    define PTRBITS 32
#  elif UINTPTR_MAX == UINT64_C(0xFFFFFFFFFFFFFFFF)
#    define PTRBITS 64
#  else
#    error NotImplementedError: uintptr_t is neither 32- nor 64-bit per UINTPTR_MAX definition
#  endif
#endif /* PTRBITS */

#if (PTRBITS != 32) && (PTRBITS != 64)
#  error: NotImplementedError: PTRBITS aka sizeof(void*) is neither 32 nor 64
#endif

#if PTRBITS == 32
#  define builtin_rotleftptr  __builtin_rotateleft32
#  define builtin_rotrightptr __builtin_rotateright32
#elif PTRBITS == 64
#  define builtin_rotleftptr  __builtin_rotateleft64
#  define builtin_rotrightptr __builtin_rotateright64
#endif

#if defined __has_builtin && __has_builtin(builtin_rotleftptr) && __has_builtin(builtin_rotrightptr)
inline static uintptr_t rotleftptr(uintptr_t p, int b)  { return builtin_rotleftptr(p, b); }
inline static uintptr_t rotrightptr(uintptr_t p, int b) { return builtin_rotrightptr(p, b); }
#else
// GCC is known to have no __builtin_rotate, let's emit a warning for other compilers.
#  ifndef __GNUC__
#    warning No __builtin_rotate*
#  endif
inline static uintptr_t rotleftptr(uintptr_t p, int b)  { return (p << b) | (p >> (PTRBITS - b)); }
inline static uintptr_t rotrightptr(uintptr_t p, int b) { return (p >> b) | (p << (PTRBITS - b)); }
#endif

// Generic __builtin_popcountg is clang-19+ and gcc-14+. OpenWRT 23.x SDK is using gcc-12.
// https://gcc.gnu.org/onlinedocs/gcc/Other-Builtins.html
// https://clang.llvm.org/docs/LanguageExtensions.html
#if UINTPTR_MAX == UINT_MAX
#  define builtin_popcount_ptr __builtin_popcount
#elif UINTPTR_MAX == ULONG_MAX
#  define builtin_popcount_ptr __builtin_popcountl
#elif UINTPTR_MAX == ULLONG_MAX
#  define builtin_popcount_ptr __builtin_popcountll
#else
#  error UINTPTR_MAX is not in {UINT_MAX, ULONG_MAX, ULLONG_MAX}
#endif

#if defined __has_builtin  && __has_builtin(builtin_popcount_ptr)
inline static int popcountptr(uintptr_t x) { return builtin_popcount_ptr(x); }
#else
#  warning No __builtin_popcount**
// https://en.wikipedia.org/wiki/Hamming_weight#Efficient_implementation
inline static int popcountptr(uintptr_t x)
{
  if (PTRBITS == 64) {
    const uint64_t m1 = UINT64_C(0x5555555555555555);
    const uint64_t m2 = UINT64_C(0x3333333333333333);
    const uint64_t m4 = UINT64_C(0x0f0f0f0f0f0f0f0f);
    const uint64_t h01 = UINT64_C(0x0101010101010101);
    x -= (x >> 1) & m1;
    x = (x & m2) + ((x >> 2) & m2);
    x = (x + (x >> 4)) & m4;
    return (x * h01) >> 56;
  } else {
    const uint64_t m1 = UINT64_C(0x55555555);
    const uint64_t m2 = UINT64_C(0x33333333);
    const uint64_t m4 = UINT64_C(0x0f0f0f0f);
    const uint64_t h01 = UINT64_C(0x01010101);
    x -= (x >> 1) & m1;
    x = (x & m2) + ((x >> 2) & m2);
    x = (x + (x >> 4)) & m4;
    return (x * h01) >> 24;
  }
}
#endif

#endif // BPD_PTROPS_SOURCE
#endif // BPD_HASH_H
