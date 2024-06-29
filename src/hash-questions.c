/* Copyright (c) 2012-2023 Simon Kelley

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


/* Hash the question section. This is used to safely detect query 
   retransmission and to detect answers to questions we didn't ask, which 
   might be poisoning attacks. Note that we decode the name rather 
   than CRC the raw bytes, since replies might be compressed differently. 
   We ignore case in the names and order of questions for the same reason.

   The hash used is SHA-256. If we're building with DNSSEC support,
   we use the Nettle cypto library. If not, we prefer not to
   add a dependency on Nettle, and use a stand-alone implementation. 
*/

#include "dnsmasq.h"

#if defined(HAVE_DNSSEC) || defined(HAVE_CRYPTOHASH)

static const struct nettle_hash *hash;
static void *ctx;
static unsigned char *digest;

void hash_questions_init(void)
{
  if (!(hash = hash_find("sha256")))
    die(_("Failed to create SHA-256 hash object"), NULL, EC_MISC);

  ctx = safe_malloc(hash->context_size);
  digest = safe_malloc(hash->digest_size);
  assert(hash->digest_size == HASH_SIZE);
}

unsigned char *hash_questions(struct dns_header *header, size_t plen, char *name)
{
  int q;
  unsigned char *p = (unsigned char *)(header+1);

  hash->init(ctx);

  for (q = ntohs(header->qdcount); q != 0; q--) 
    {
      char *cp, c;

      if (!extract_name(header, plen, &p, name, 1, 4))
	return NULL; /* bad packet */

      for (cp = name; (c = *cp); cp++)
	 if (c >= 'A' && c <= 'Z')
	   *cp += 'a' - 'A';

      hash->update(ctx, cp - name, (unsigned char *)name);
      /* CRC the class and type as well */
      hash->update(ctx, 4, p);

      p += 4;
      if (!CHECK_LEN(header, p, plen, 0))
	return NULL; /* bad packet */
    }
  
  hash->digest(ctx, hash->digest_size, digest);
  return digest;
}

#else /* HAVE_DNSSEC  || HAVE_CRYPTOHASH */

#define SIPHASH_STATIC 1
#include "siphash.h"

// Siphash secret is always [16], digest might be [16] and [8]. We use [16].
union shhh {
  unsigned char bytes[16];
  uintptr_t p[16 / (PTRBITS / 8)];
  uint64_t u64[16 / sizeof(uint64_t)];
};

static union shhh secret;
static union shhh digest;

void hash_questions_init(void)
{
  static_assert(sizeof(secret.bytes) == 16 && sizeof(secret.p) == 16);
  static_assert(sizeof(digest) == HASH_SIZE);
  for (unsigned i = 0; i < countof(secret.p); i++)
    secret.p[i] = randptr();
}

unsigned char *hash_questions(struct dns_header *header, size_t plen, char *name)
{
  int q;
  unsigned char *p = (unsigned char *)(header+1);

  memset(&digest, 0, sizeof(digest));

  // `qdcount > 1` is nonexistent. Unbound, Knot Resolver, Bind do not supports
  // that, so I don't think it matters if order of questions is ignored or not.
  // TODO: link to tags instead of commits
  // https://github.com/NLnetLabs/unbound/blob/7fbc061846ace7295fb8ab117411daf32aa282fc/util/data/msgparse.c#L584-L590
  // https://github.com/CZ-NIC/knot/blob/faa39eede4cd6fab0149dac282fcd21ed861bc32/src/libknot/packet/pkt.c#L587-L591
  // https://github.com/isc-projects/bind9/blob/392e7199df266fb2daefde6ec5bf0b843f60b4b8/lib/dns/resolver.c#L4852-L4855
  // https://github.com/isc-projects/bind9/blob/392e7199df266fb2daefde6ec5bf0b843f60b4b8/lib/dns/xfrin.c#L1766-L1778
  for (q = ntohs(header->qdcount); q != 0; q--) 
    {
      if (!extract_name(header, plen, &p, name, 1, 4))
	return NULL; /* bad packet */

      const int dlen = do_dneedle(daemon->dneebuff, name, DNEEDLE_SIZEOF_MAX);
      if (dlen < 0)
	return NULL;
      static_assert(DNEEDLE_SIZEOF_MAX + 4 <= DNEEBUFF_SIZEOF);
      unsigned char * const dna = (unsigned char *)daemon->dneebuff;
      memcpy(dna + dlen, p, 4);

      union shhh qhash;
      // dneedle_aligned is malloc()'ed, so it's aligned
      siphashal64hbo((uint64_t*)dna, dlen + 4, secret.u64, qhash.u64, sizeof(qhash));
      for (unsigned i = 0; i < countof(qhash.p); i++)
	digest.p[i] ^= qhash.p[i];

      p += 4;
      if (!CHECK_LEN(header, p, plen, 0))
	return NULL; /* bad packet */
    }
  
  return digest.bytes;
}

#include "siphash.c"
#endif
