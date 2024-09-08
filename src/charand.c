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
#include "config.h"
#include "charand.h"

#include <sys/types.h>
#include <unistd.h>
#include <limits.h>
#include <string.h>
#include <time.h>
#include <sys/auxv.h>
#if !defined(HAVE_GETENTROPY) && defined(RANDFILE)
# include <stdio.h>
#endif

// ChaCha8-based random number generator. That's NOT Golang's chacha8rand
// described at https://github.com/C2SP/C2SP/blob/main/chacha8rand.md
// as the most popular OpenWRT boxes are not that rich to have SIMD :-)

// Non-standard libc getentropy() might use getrandom() avoiding filesystem access, that's great
// for jails and chroots.  However, a fallback implemetation is required for older systems that have
// no getentropy() in libc.  Also, getentropy() might block if the kernel has not initialized random
// pool yet.  However, dnsmasq is never started that early during the OpenWRT boot process (at least).

#if !defined(HAVE_GETENTROPY) && defined(RANDFILE)

static int getentropy_fallback(void *buffer, size_t length)
{
  FILE *fd = fopen(RANDFILE, "r")
  if (!fd)
    return -1;
  const size_t done = fread(fd, buffer, 1, length);
  fclose(fd);
  return done == length ? 0 : -1;
}

#define getentropy(a, b) getentropy_fallback(a, b)

#endif // !defined(HAVE_GETENTROPY)

static void chacha8(void);

static uint32_t CHA[16] = { 0x61707865, 0x3320646e, 0x79622d32, 0x6b206574 };
static uint32_t CHAO[16];
static unsigned int CHAOBYEs = 0;

static void nonce_time(void) { CHA[14] = (uint32_t)time(NULL); };
static void nonce_proc(void) { CHA[15] = getpid(); };

int charand_init(void)
{
  if (getentropy(CHA + 4, 8 * sizeof(uint32_t)))
    return -1;
  // Overflowing 32-bit counter is trivial, overflowing 64-bit counter takes 146 years at 4 GHz rate.
  // So, counter is never reset during the process lifetime.
  CHA[12] = CHA[13] = 0;
  nonce_time();
  nonce_proc();
  chacha8();
  return 0;
}

bool charand_isinit(void)
{
  return CHA[15] != 0;
}

void charand_rekey(void)
{
  if (CHAOBYEs < 32)
    chacha8();
  for (int i = 0; i < 8; i++)
    CHA[4+i] ^= CHAO[i];
  nonce_time();
  chacha8();
}

// This atfork handler avoids getentropy() call to preserve system entropy pool.
void charand_atfork_child(void)
{
  const uint32_t *r32x4 =
#ifdef AT_RANDOM
    (const uint32_t*)getauxval(AT_RANDOM); // Use the entropy OS provides. Hopefully, ptr is aligned :-)
#else
#   warning No getauxval(AT_RANDOM) available
    NULL;
#endif
  if (r32x4)
    for (unsigned int i = 0; i < 16 / sizeof(uint32_t); i++)
      CHA[4+i] ^= r32x4[i]; // scramble 256-bit key with 128-bit process-wide random
  nonce_proc();
  chacha8();
  charand_rekey();
}

static inline uint32_t rotl32(uint32_t x, unsigned b) { return (x << b) | (x >> (32 - b)); }

#define QUARTERROUND(a, b, c, d) do { \
    CHAO[a] += CHAO[b]; CHAO[d] ^= CHAO[a]; CHAO[d] = rotl32(CHAO[d], 16); \
    CHAO[c] += CHAO[d]; CHAO[b] ^= CHAO[c]; CHAO[b] = rotl32(CHAO[b], 12); \
    CHAO[a] += CHAO[b]; CHAO[d] ^= CHAO[a]; CHAO[d] = rotl32(CHAO[d],  8); \
    CHAO[c] += CHAO[d]; CHAO[b] ^= CHAO[c]; CHAO[b] = rotl32(CHAO[b],  7); \
} while (0)

// These are two options for the ChaCha8 quarter-round implementation of different size and speed.
// There is also a obvious middleground:
//  static void chaqround(int a, int b, int c, int d) { QUARTERROUND(a, b, c, d); }
// But it takes 3654 cycles and 130 opcodes, so it's kinda pointless.

#ifdef __OPTIMIZE_SIZE__

// 4086 cycles, 100 opcodes for `gcc-13.2.0 -Os -mips32r2 -mtune=24kc -mips16`
# define quarterround(a, b, c, d) quarterround_1arg((a) | ((b) << 4) | ((c) << 8) | ((d) << 12))

static void quarterround_1arg(unsigned ndx)
{
  const unsigned a = 0x0F & ndx;
  const unsigned b = 0x0F & (ndx >> 4);
  const unsigned c = 0x0F & (ndx >> 8);
  const unsigned d = ndx >> 12;
  QUARTERROUND(a, b, c, d);
}

#else

// 1944 cycles, 320 opcodes for the same MIPS32r2 machine
# define quarterround(a, b, c, d) QUARTERROUND(a, b, c, d)

#endif // __OPTIMIZE_SIZE__

static void chacha8(void)
{
  CHA[12]++;
  CHA[13] += !CHA[12];

  memcpy(CHAO, CHA, sizeof(CHAO));

  for (unsigned i = 4; i; i--) {
      quarterround(0, 4,  8, 12);
      quarterround(1, 5,  9, 13);
      quarterround(2, 6, 10, 14);
      quarterround(3, 7, 11, 15);
      quarterround(0, 5, 10, 15);
      quarterround(1, 6, 11, 12);
      quarterround(2, 7,  8, 13);
      quarterround(3, 4,  9, 14);
  }

  for (unsigned i = 0; i < 16; i++)
    CHAO[i] += CHA[i];

  CHAOBYEs = sizeof(CHAO);
}

// rand16() is the most popular in rand*() functions family, it is called once per ≈ every DNS request,
// so it should not waste generated entropy.
// TODO: count real-world stats for an OpenWRT box.
uint16_t charand16(void)
{
  // CHAOBYEs is always aligned at uint16_t boundary
  if (!CHAOBYEs) chacha8();
  CHAOBYEs -= sizeof(uint16_t);
  return *(uint16_t*)(((uint8_t*)CHAO) + CHAOBYEs);
}

uint32_t charand32(void)
{
  CHAOBYEs &= (UINT_MAX - 3); // skip some to make read aligned
  if (!CHAOBYEs) chacha8();
  CHAOBYEs -= sizeof(uint32_t);
  return *(uint32_t*)(((uint8_t*)CHAO) + CHAOBYEs);
}

uint64_t charand64(void)
{
  CHAOBYEs &= (UINT_MAX - 7); // skip some to make read aligned
  if (!CHAOBYEs) chacha8();
  CHAOBYEs -= sizeof(uint64_t);
  return *(uint64_t*)(((uint8_t*)CHAO) + CHAOBYEs);
}
