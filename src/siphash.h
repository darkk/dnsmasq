/*
   SipHash reference C implementation

   Copyright (c) 2012-2021 Jean-Philippe Aumasson
   <jeanphilippe.aumasson@gmail.com>
   Copyright (c) 2012-2014 Daniel J. Bernstein <djb@cr.yp.to>

   To the extent possible under law, the author(s) have dedicated all copyright
   and related and neighboring rights to this software to the public domain
   worldwide. This software is distributed without any warranty.

   You should have received a copy of the CC0 Public Domain Dedication along
   with
   this software. If not, see
   <http://creativecommons.org/publicdomain/zero/1.0/>.
 */
#ifndef SIPHASH_H
#define SIPHASH_H

#include <inttypes.h>
#include <string.h>

#ifdef SIPHASH_STATIC
#  define SIPHASH_MAYBE_STATIC static inline
#else
#  define SIPHASH_MAYBE_STATIC
#endif
SIPHASH_MAYBE_STATIC
int siphash(const void *in, const size_t inlen, const void *k, uint8_t *out,
            const size_t outlen);
SIPHASH_MAYBE_STATIC
int siphashal64hbo(const uint64_t *in, const size_t inlen, const uint64_t *k,
                   uint64_t *out, const size_t outlen);

#endif // SIPHASH_H
