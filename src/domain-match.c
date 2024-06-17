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

#if 0
static int order(char *qdomain, size_t qlen, struct server *serv);
static int order_qsort(const void *a, const void *b);
static int order_servers(struct server *s, struct server *s2);
#endif
static struct server* server_alloc(u16 flags, const char *domain);

#ifdef HAVE_LOOP
# define server_loops(serv) (0) // (serv->flags & SERV_LOOP)
#else
# define server_loops(serv) (0)
#endif

static inline uintptr_t worm_mask(void* ptr, uintptr_t key, const struct worm_bsearch *w)
{
  const uintptr_t srot = rotrightptr((uintptr_t)ptr ^ w->ptrxor, w->ptrwrotr);
  assert((srot & w->keymask) == 0);
  return srot | (key & w->keymask);
}

static inline void* worm_unmask(uintptr_t val, const struct worm_bsearch *w)
{
  return (void*)(rotleftptr(val & ~(w->keymask), w->ptrwrotr) ^ w->ptrxor);
}

// It's possible to fit it into single cache-lne using some bits of ptrxor for mask :-)
struct serv_bfind_ctx {
  struct worm_bsearch w;
  uintptr_t hash;
  const char *qdomain;
};

static int server_bfind_cmp(const void *ctxv, const void *val)
{
  const struct serv_bfind_ctx *ctx = ctxv;
  const uintptr_t *p = val;
  const uintptr_t ctx_masked = ctx->hash & ctx->w.keymask;
  const uintptr_t hash_masked = *p & ctx->w.keymask;
  const int log_cmp = 0;

  bench_count(BENCH_SERVCMP_INLINE, 1);
  if (log_cmp) {
    const struct server *useless = worm_unmask(*p, &ctx->w);
    my_syslog(LOG_INFO, "cmp: %s. (%p) <^_^> (%p) %s.", ctx->qdomain, bp_hash(ctx->qdomain), bp_hash(server_domain(useless)), server_domain(useless));
  }
  if (ctx_masked < hash_masked)
    return -1;
  if (ctx_masked > hash_masked)
    return 1;

  bench_count(BENCH_SERVCMP_DEREF, 1);
  const struct server *s = worm_unmask(*p, &ctx->w);
  const int lobits = MIN(ctzptr(ctx->w.keymask), 16);
  const uintptr_t lomask = ~(UINTPTR_MAX << lobits);
  if (log_cmp)
    my_syslog(LOG_INFO, "cmp: %s. (%p) <o-o> (%p) %s.", ctx->qdomain, bp_hash(ctx->qdomain), bp_hash(server_domain(s)), server_domain(s));
  if ((ctx->hash & lomask) < s->domhash16)
    return -1;
  if ((ctx->hash & lomask) > s->domhash16)
    return 1;

  if (log_cmp)
    my_syslog(LOG_INFO, "cmp: %s. (%p) <0-@> (%p) %s.", ctx->qdomain, bp_hash(ctx->qdomain), bp_hash(server_domain(s)), server_domain(s));
  return hostname_order(ctx->qdomain, server_domain(s));
}

static size_t server_bfind(struct worm_bsearch *w, uintptr_t hash, const char *qdomain)
{
  if (*qdomain == '\0')
    return w->zero;
  const size_t partition = w->partbits ? (hash >> (PTRBITS - w->partbits)) : 0;
  uintptr_t *table = wormb_data_begin(w);
  uintptr_t *begin = wormb_part_begin(w, partition);
  size_t nelem = wormb_part_end(w, partition) - begin;

  struct serv_bfind_ctx ctx;
  memcpy(&ctx.w, w, sizeof(*w));
  ctx.hash = hash;
  ctx.qdomain = qdomain;
  uintptr_t *p = bsearch(&ctx, begin, nelem, sizeof(void*), server_bfind_cmp);
  if (!p)
    return SIZE_MAX;
  assert(hostname_order(server_domain(worm_unmask(*p, w)), qdomain) == 0);
  return p - table;
}

static bool server_same_domain(struct worm_bsearch *w, size_t a, size_t b)
{
  assert(a < wormb_capacity(w) && b < wormb_capacity(w));
  const uintptr_t *const begin = wormb_data_begin(w);
  if ((w->keymask & begin[a]) != (w->keymask & begin[b]))
    return false;

  // TODO: should I mask domhash16 ?..
  // const int lobits = MIN(ctzptr(w->keymask), 16);
  // const uintptr_t lomask = ~(UINTPTR_MAX << lobits);

  const struct server *pa = worm_unmask(begin[a], w);
  const struct server *pb = worm_unmask(begin[b], w);
  if (pa->domhash16 != pb->domhash16)
    return false;

  return hostname_order(server_domain(pa), server_domain(pb)) == 0;
}

struct server* server_get(struct worm_bsearch *w, size_t n)
{
  assert(n < wormb_capacity(w));
  const uintptr_t *const begin = wormb_data_begin(w);
  return worm_unmask(begin[n], w);
}

static bool server_same_group(struct worm_bsearch *w, size_t a, size_t b)
{
  if (!server_same_domain(w, a, b))
    return false;
  const uintptr_t *const begin = wormb_data_begin(w);
  const struct server *pa = worm_unmask(begin[a], w);
  const struct server *pb = worm_unmask(begin[b], w);
  const uint16_t mask = SERV_WILDCARD | SERV_FOR_NODOTS;
  return (pa->flags & mask) == (pb->flags & mask);
}

// `mask` is a bitmask of constant bits in the pointer values for WORM data
// structure. 16 bits of hash are available in the structure itself in a
// cacheline far far away so those bits of entropy should be used as the least
// significant bits for last-resort comparison.
u8 bestrotright(const uintptr_t cnst, const int partbits)
{
  int retval = 0;
  const int possible = popcountptr(cnst);
  const uintptr_t mpart = UINTPTR_MAX >> partbits;
  for (int bestpop = -1, bestt0 = -1, rot = 0; bestpop < possible && rot < PTRBITS; rot++)
    {
      const uintptr_t rotcnst = rotrightptr(cnst, rot) & mpart;
      const int pop = popcountptr(rotcnst);
      const int t0 = ctzptr(rotcnst);
      if (bestpop < pop || (bestpop == pop && bestt0 < t0))
	{
	  retval = rot;
	  bestpop = pop;
	  bestt0 = t0;
	}
    }
  return retval;
}

static int count_hash = 0;

static int wormb_order qcomp(const void *av, const void *bv, void *ctxv)
{
  const uintptr_t *au = av;
  const uintptr_t *bu = bv;
  const struct worm_bsearch *w = ctxv;
  const struct server *as = worm_unmask(*au, w); // (const struct server *)(rotleftptr(*au & ~(w->keymask), w->ptrwrotr) ^ w->ptrxor);
  const struct server *bs = worm_unmask(*bu, w); // (const struct server *)(rotleftptr(*bu & ~(w->keymask), w->ptrwrotr) ^ w->ptrxor);
  bench_count(BENCH_SERVCMP_DEREF, 1);
  uintptr_t ah = as->hash4qsort;
  uintptr_t bh = bs->hash4qsort;
  count_hash += 2;

  assert((ah & w->keymask) == (*au & w->keymask) && (bh & w->keymask) == (*bu & w->keymask));

  const int lobits = MIN(ctzptr(w->keymask), 16); // low bits usable for domhash16
  const uintptr_t lomask = ~(UINTPTR_MAX << lobits);
  assert((ah & lomask) == as->domhash16 && (bh & lomask) == bs->domhash16);
  const uintptr_t sortmask = ~(UINTPTR_MAX >> w->partbits) | w->keymask | lomask;

  ah &= sortmask;
  bh &= sortmask;

  // TODO: SERV_WILDCARD, SERV_FOR_NODOTS, SERV_LITERAL_ADDRESS etc

  if (ah < bh)
    return -1;
  else if (ah > bh)
    return 1;

  return hostname_order(server_domain(as), server_domain(bs));
}

static void build_server_array__(void);
void build_server_array(void)
{
  struct benchts start;
  bench_start(&start);
  build_server_array__();
  bench_sample(BENCH_BUILD_SERVER_ARRAY, &start);
}
static void build_server_array__(void)
{
  struct server *serv;
  uintptr_t count = 0; // TODO: consider `uint` and definition of clzui()
  uintptr_t ptr0 = ~(uintptr_t)0;
  uintptr_t ptr1 = ~(uintptr_t)0;

  // serv->next might be shuffled around, so `serial` does not always represent
  // the position in the config file, however it still reflect ordering
  // of servers within the same domain/prefix correctly and that's what matters.
  int serial = 1;
  for (serv = daemon->servers; serv; serv = serv->next)
    {
      serv->serial = serial;
      serial++;
      if (!server_loops(serv))
	{
	  serv->last_server = -1;
	  ptr0 &= ~(uintptr_t)serv;
	  ptr1 &= (uintptr_t)serv;
	  count++;
	  if (serv->flags & SERV_WILDCARD)
	    daemon->server_has_wildcard = 1;
	}
    }
  for (serv = daemon->local_domains; serv; serv = serv->next)
    {
      ptr0 &= ~(uintptr_t)serv;
      ptr1 &= (uintptr_t)serv;
      count++;
      if (serv->flags & SERV_WILDCARD)
	daemon->server_has_wildcard = 1;
    }

  assert(count); // TODO: implement a short-cut for a dnsmasq-without-upstreams, e.g. DHCP/TFTP

  // This kind of optimisation is not so useful in case of pointer
  // authentication, but ARMv8.3 is far far away from me and my ancient
  // OpenWRT-capable routers.

  // Magic number `3` comes from assumption that the machine has 8 (1<<3) pointers per cacheline.
  // Partiion that does nothing to save an extra cachemiss is a total waste of RAM.
  const int maxpartbits = MAX(PTRBITS - clzptr(count) - 3, 0);
  const int defpartbits = maxpartbits / 2;
  const int config_partbits = -1;
  const int partbits = config_partbits >= 0 ? MIN(config_partbits, maxpartbits) : defpartbits;
  const u8 rotr = bestrotright(ptr0 | ptr1, partbits);
  const uintptr_t keymask = rotrightptr(ptr0 | ptr1, rotr) & (UINTPTR_MAX >> partbits);
  const int lobits = MIN(ctzptr(keymask), 16); // low bits usable for domhash16
  const uintptr_t lomask = ~(UINTPTR_MAX << lobits);

  struct worm_bsearch* w = wormb_alloc(partbits, count);
  daemon->serverhash = w;
  w->ptrxor = ptr1;
  w->keymask = keymask;
  w->ptrwrotr = rotr;

  assert(wormb_data_end(w) - wormb_data_begin(w) == (ptrdiff_t)count);
  uintptr_t *p = wormb_data_begin(w);
  struct server *next = NULL;
  for (serv = daemon->servers; serv && p != wormb_data_end(w); p++, serv = next)
    {
      next = serv->next; // union with hash4qsort
      const uintptr_t hash = bp_hash(server_domain(serv));
      serv->domhash16 = hash & lomask;
      serv->hash4qsort = hash;
      *p = worm_mask(serv, hash, w);
    }
  assert(!serv);
  assert(!daemon->local_domains || p != wormb_data_end(w));
  for (serv = daemon->local_domains; serv && p != wormb_data_end(w); p++, serv = next)
    {
      next = serv->next; // union with hash4qsort
      const uintptr_t hash = bp_hash(server_domain(serv));
      serv->domhash16 = hash & lomask;
      serv->hash4qsort = hash;
      *p = worm_mask(serv, hash, w);
    }
  assert(!serv);
  assert(p == wormb_data_end(w));
  assert(wormb_data_end(w) - wormb_data_begin(w) == (ptrdiff_t)count);
  qsort_arr(wormb_data_begin(w), count, sizeof(void*), wormb_order, w);

#if 0
  daemon->serverarray = whine_malloc(count * sizeof(void*));
  daemon->serverarraysz = count;
#endif

  // FIXME: server_loops is not handled correctly here
  daemon->servers = daemon->local_domains = NULL;
  struct server **tserv = &daemon->servers;
  struct server **tlocal = &daemon->local_domains;
  size_t i;
  w->zero = SIZE_MAX;
  for (p = wormb_data_begin(w), i = 0; p != wormb_data_end(w); p++, i++)
    {
      serv = worm_unmask(*p, w);
     //  daemon->serverarray[i] = serv;
      if (server_sizeof(serv->flags) == sizeof(struct server))
	serv->arrayposn = i;
      if (w->zero == SIZE_MAX && server_domain_empty(serv))
	w->zero = i;
      if (partbits)
	{
	  size_t partition = serv->hash4qsort >> (PTRBITS - partbits);
	  if (partition != ~(SIZE_MAX << partbits))
	    w->tabluint[partition] = (uintptr_t)(p+1);
	}
      struct server ***dest = serv->flags & SERV_IS_LOCAL ? &tlocal : &tserv;
      **dest = serv;
      *dest = &serv->next;
    }
  assert(i == count);
  daemon->servers_tail = daemon->servers ? container_of(tserv, struct server, next) : NULL;
  *tserv = NULL;
  *tlocal = NULL;

#if 0

  struct hworm *ht = daemon->serverhash;
  if (worm_capacity(daemon->serverhash) < worm_expected_capacity(count))
    {
      /* It should be at the very least count+3 to handle MAXNS `nameservers`
	 from resolv.conf without re-allocating the table. */
      ht = worm_alloc(count+10);
      if (ht)
	{
	  if (daemon->serverhash)
	    free(daemon->serverhash);
	  daemon->serverhash = ht;
	}
      else if (count < worm_capacity(daemon->serverhash))
        {
	  /* Let's assume that degraded performance is better than crash.
	   * TODO(?): fallback to bsearch instead of hashtable? */
	  const u8 capapow = daemon->serverhash->capapow;
	  memset(daemon->serverhash, 0, worm_sizeof(capapow));
	  daemon->serverhash->capapow = capapow;
	  ht = daemon->serverhash;
        }
      else
	abort();
    }

  ht->keymask = (ptr0 | ptr1);
  ht->ptrxor = (uintptr_t)server_null;

  /* Servers are correctly sorted within each and every domain "cluster"
   * as hashtable insertion preserves order. */
  /* servers need the location in the array to find all the whole
     set of equivalent servers from a pointer to a single one. */
  for (serv = daemon->servers; serv; serv = serv->next)
    serv->arrayposn = worm_set(ht, bp_hash(server_domain(serv)), serv);
  for (serv = daemon->local_domains; serv; serv = serv->next)
    worm_set(ht, bp_hash(server_domain(serv)), serv);

  // I suspect following common scenarios for domain name and/or suffix being reused:
  // 0) --server=192.0.2.53 --server=192.0.2.54 # both from resolv.conf
  // 1) --server=/corp.example.com/192.0.2.53 --server=/corp.example.com/192.0.2.54
  // 2) --server=/example.net/# --local=/*example.net/
  // 3) --local=/example.org/ --address=/example.org/192.0.2.1
  // 4) --local=/example.org/ --address=/example.org/192.0.2.1 --address=/example.org/2001:db8::1
  // XXX(?): should (domain_len == 0) be a special case with a special chain?
  const size_t first_run = !ht->table[0]
    ? worm_find_ptr(ht, 0)
    : worm_find_ptr(ht, worm_find_null(ht, 0));
  size_t max_run = 0, off = first_run;
  do {
    size_t end = worm_find_null(ht, off);
    size_t cur_run = off < end ? end - off : worm_capacity(ht) - off + end;
    max_run = max_size(max_run, cur_run);
    off = worm_find_ptr(ht, end);
  } while (off != first_run);
  fprintf(stderr, "max_run: %lu (%lu bytes)\n", max_run, max_run * sizeof(void*));
#endif
}

/* we're looking for the server whose domain is the longest exact match
   to the RH end of qdomain, or a local address if the flags match.
   Add '.' to the LHS of the query string so
   server=/.example.com/ works.

   A flag of F_SERVER returns an upstream server only.
   A flag of F_DNSSECOK returns a DNSSEC capable server only and
   also disables NODOTS servers from consideration.
   A flag of F_DOMAINSRV returns a domain-specific server only.
   A flag of F_CONFIG returns anything that generates a local
   reply of IPv4 or IPV6.
   return 0 if nothing found, 1 otherwise.
*/
static int lookup_domain__(char *domain, int flags, int *lowout, int *highout);
int lookup_domain(char *domain, int flags, int *lowout, int *highout)
{
  struct benchts start;
  bench_start(&start);
  int ret = lookup_domain__(domain, flags, lowout, highout);
  bench_sample(BENCH_LOOKUP_DOMAIN, &start);
  return ret;
}
static int lookup_domain__(char *domain, int flags, int *lowout, int *highout)
{
  int rc, crop_query, nodots;
  ssize_t qlen;
  int try = 0, high = 0, low = 0;
  (void)high;
  (void)low;
  int nlow = 0, nhigh = 0;
  char *cp, *qdomain = domain;

  /* may be no configured servers. */
  // FIXME: no-servers is not supported yet
  if (wormb_capacity(daemon->serverhash) == 0)
    return 0;
  
  /* find query length and presence of '.' */
  for (cp = qdomain, nodots = 1, qlen = 0; *cp; qlen++, cp++)
    if (*cp == '.')
      nodots = 0;

  /* Handle empty name, and searches for DNSSEC queries without
     diverting to NODOTS servers. */
  if (qlen == 0 || flags & F_DNSSECOK)
    nodots = 0;

  /* Search shorter and shorter RHS substrings for a match */
  while (qlen >= 0)
    {
      crop_query = 1;
#if 0
      /* Note that when we chop off a label, all the possible matches
	 MUST be at a larger index than the nearest failing match with one more
	 character, since the array is sorted longest to smallest. Hence 
	 we don't reset low to zero here, we can go further below and crop the 
	 search string to the size of the largest remaining server
	 when this match fails. */
      high = daemon->serverarraysz;
      crop_query = 1;
      
      /* binary search */
      while (1) 
	{
	  try = (low + high)/2;

	  if ((rc = order(qdomain, qlen, daemon->serverarray[try])) == 0)
	    break;
	  
	  if (rc < 0)
	    {
	      if (high == try)
		{
		  /* qdomain is longer or same length as longest domain, and try == 0 
		     crop the query to the longest domain. */
		  crop_query = qlen - daemon->serverarray[try]->domain_len;
		  break;
		}
	      high = try;
	    }
	  else
	    {
	      if (low == try)
		{
		  /* try now points to the last domain that sorts before the query, so 
		     we know that a substring of the query shorter than it is required to match, so
		     find the largest domain that's shorter than try. Note that just going to
		     try+1 is not optimal, consider searching bbb in (aaa,ccc,bb). try will point
		     to aaa, since ccc sorts after bbb, but the first domain that has a chance to 
		     match is bb. So find the length of the first domain later than try which is
		     is shorter than it. 
		     There's a nasty edge case when qdomain sorts before _any_ of the 
		     server domains, where try _doesn't point_ to the last domain that sorts
		     before the query, since no such domain exists. In that case, the loop 
		     exits via the rc < 0 && high == try path above and this code is
		     not executed. */
		  ssize_t len, old = daemon->serverarray[try]->domain_len;
		  while (++try != daemon->serverarraysz)
		    {
		      if (old != (len = daemon->serverarray[try]->domain_len))
			{
			  crop_query = qlen - len;
			  break;
			}
		    }
		  break;
		}
	      low = try;
	    }
	};
#endif
      uintptr_t hash = bp_hash(qdomain);
      size_t ndx = server_bfind(daemon->serverhash, hash, qdomain);
      if (ndx != SIZE_MAX)
      {
	rc = 0;
	try = ndx;
	// assert(hostname_order(server_domain(daemon->serverarray[ndx]), qdomain) == 0);
      }
      else
	rc = -1;

      if (rc == 0)
	{
	  int found = 1;

	  if (daemon->server_has_wildcard)
	    {
	      /* if we have example.com and *example.com we need to check against *example.com, 
		 but the binary search may have found either. Use the fact that example.com is sorted before *example.com
		 We favour example.com in the case that both match (ie www.example.com) */
	      // FIXME: handle SERV_FOR_NODOTS, it was order()
	      while (try != 0 && server_same_domain(daemon->serverhash, try, try-1))
		try--;
	      
	      if (!(qdomain == domain || *qdomain == 0 || *(qdomain-1) == '.'))
		{
		  // FIXME: handle SERV_FOR_NODOTS, it was order()
		  while (try < (int)wormb_capacity(daemon->serverhash) - 1 && server_same_domain(daemon->serverhash, try, try+1))
		    try++;
		  
		  if (!(server_get(daemon->serverhash, try)->flags & SERV_WILDCARD))
		     found = 0;
		}
	    }
	  
	  if (found && filter_servers(try, flags, &nlow, &nhigh))
	    /* We have a match, but it may only be (say) an IPv6 address, and
	       if the query wasn't for an AAAA record, it's no good, and we need
	       to continue generalising */
	    {
	      /* We've matched a setting which says to use servers without a domain.
		 Continue the search with empty query. We set the F_SERVER flag
		 so that --address=/#/... doesn't match. */
	      if (server_get(daemon->serverhash, nlow)->flags & SERV_USE_RESOLV)
		{
		  crop_query = qlen;
		  flags |= F_SERVER;
		}
	      else
		break;
	    }
	}
      
      /* crop_query must be at least one always. */
      if (crop_query == 0)
	crop_query = 1;

      /* strip chars off the query based on the largest possible remaining match,
	 then continue to the start of the next label unless we have a wildcard
	 domain somewhere, in which case we have to go one at a time. */
      qlen -= crop_query;
      qdomain += crop_query;
      if (!daemon->server_has_wildcard)
	while (qlen > 0 &&  (*(qdomain-1) != '.'))
	  qlen--, qdomain++;
    }

  /* domain has no dots, and we have at least one server configured to handle such,
     These servers always sort to the very end of the array. 
     A configured server eg server=/lan/ will take precdence. */
  // FIXME: that's now how SERV_FOR_NODOTS works now
  if (nodots &&
      (server_get(daemon->serverhash, wormb_capacity(daemon->serverhash) - 1)->flags & SERV_FOR_NODOTS) &&
      (nlow == nhigh || server_domain_empty(server_get(daemon->serverhash, nlow))))
    filter_servers(wormb_capacity(daemon->serverhash) - 1, flags, &nlow, &nhigh);
  
  if (lowout)
    *lowout = nlow;
  
  if (highout)
    *highout = nhigh;

  /* qlen == -1 when we failed to match even an empty query, if there are no default servers. */
  if (nlow == nhigh || qlen == -1)
    return 0;
  
  return 1;
}

/* Return first server in group of equivalent servers; this is the "master" record. */
int server_samegroup(struct server *a, struct server *b)
{
  // FIXME: it was (order_servers(a, b) == 0);
  const uint16_t mask = SERV_WILDCARD | SERV_FOR_NODOTS;
  return a->domhash16 == b->domhash16
    && (a->flags & mask) == (b->flags & mask)
    && hostname_order(server_domain(a), server_domain(b)) == 0;
}

int filter_servers(int seed, int flags, int *lowout, int *highout)
{
  int nlow = seed, nhigh = seed;
  int i;
  
  /* expand nlow and nhigh to cover all the records with the same domain 
     nlow is the first, nhigh - 1 is the last. nlow=nhigh means no servers,
     which can happen below. */
  // TODO: handle SERV_FOR_NODOTS, it was order_servers()
  while (nlow > 0 && server_same_group(daemon->serverhash, nlow-1, nlow))
    nlow--;
  
  // TODO: handle SERV_FOR_NODOTS, it was order_servers()
  while (nhigh < (int)wormb_capacity(daemon->serverhash) - 1 && server_same_group(daemon->serverhash, nhigh, nhigh+1))
    nhigh++;
  
  nhigh++;
  
  if (flags & F_CONFIG)
    {
      /* We're just lookin for any matches that return an RR. */
      for (i = nlow; i < nhigh; i++)
	if (server_get(daemon->serverhash, i)->flags & SERV_LOCAL_ADDRESS)
	  break;
      
      /* failed, return failure. */
      if (i == nhigh)
	nhigh = nlow;
    }
  else
    {
      /* Now the servers are on order between low and high, in the order
	 IPv6 addr, IPv4 addr, return zero for both, resolvconf servers, send upstream, no-data return.
	 
	 See which of those match our query in that priority order and narrow (low, high) */
      
      for (i = nlow; i < nhigh && ((server_get(daemon->serverhash, i)->flags & SERV_ADDR_MASK) == SERV_X_6ADDR); i++);
      
      if (!(flags & F_SERVER) && i != nlow && (flags & F_IPV6))
	nhigh = i;
      else
	{
	  nlow = i;
	  
	  for (i = nlow; i < nhigh && ((server_get(daemon->serverhash, i)->flags & SERV_ADDR_MASK) == SERV_X_4ADDR); i++);
	  
	  if (!(flags & F_SERVER) && i != nlow && (flags & F_IPV4))
	    nhigh = i;
	  else
	    {
	      nlow = i;
	      
	      for (i = nlow; i < nhigh && ((server_get(daemon->serverhash, i)->flags & SERV_ADDR_MASK) == SERV_X_ZEROS); i++);
	      
	      if (!(flags & F_SERVER) && i != nlow && (flags & (F_IPV4 | F_IPV6)))
		nhigh = i;
	      else
		{
		  nlow = i;
		  
		  /* Short to resolv.conf servers */
		  for (i = nlow; i < nhigh && (server_get(daemon->serverhash, i)->flags & SERV_USE_RESOLV); i++);
		  
		  if (i != nlow)
		    nhigh = i;
		  else
		    {
		      /* now look for a server */
		      for (i = nlow; i < nhigh && !(server_get(daemon->serverhash, i)->flags & SERV_LITERAL_ADDRESS); i++);
		      
		      if (i != nlow)
			{
			  /* If we want a server that can do DNSSEC, and this one can't, 
			     return nothing, similarly if were looking only for a server
			     for a particular domain. */
			  if ((flags & F_DNSSECOK) && !(server_get(daemon->serverhash, nlow)->flags & SERV_DO_DNSSEC))
			    nlow = nhigh;
			  else if ((flags & F_DOMAINSRV) && server_domain_empty(server_get(daemon->serverhash, nlow)))
			    nlow = nhigh;
			  else
			    nhigh = i;
			}
		      else
			{
			  /* --local=/domain/, only return if we don't need a server. */
			  if (flags & (F_DNSSECOK | F_DOMAINSRV | F_SERVER))
			    nhigh = i;
			}
		    }
		}
	    }
	}
    }

  *lowout = nlow;
  *highout = nhigh;
  
  return (nlow != nhigh);
}

int is_local_answer(time_t now, int first, char *name)
{
  int flags = 0;
  int rc = 0;
  
  if ((flags = server_get(daemon->serverhash, first)->flags) & SERV_LITERAL_ADDRESS)
    {
      if ((flags & SERV_ADDR_MASK) == SERV_X_4ADDR)
	rc = F_IPV4;
      else if ((flags & SERV_ADDR_MASK) == SERV_X_6ADDR)
	rc = F_IPV6;
      else if ((flags & SERV_ADDR_MASK) == SERV_X_ZEROS)
	rc = F_IPV4 | F_IPV6;
      else
	{
	  /* argument first is the first struct server which matches the query type;
	     now roll back to the server which is just the same domain, to check if that 
	     provides an answer of a different type. */

	  // XXX: handle SERV_FOR_NODOTS, it was order_servers()
	  for (;first > 0 && server_same_group(daemon->serverhash, first-1, first); first--);
	  
	  if ((server_get(daemon->serverhash, first)->flags & SERV_LOCAL_ADDRESS) ||
	      check_for_local_domain(name, now))
	    rc = F_NOERR;
	  else
	    rc = F_NXDOMAIN;
	}
    }

  return rc;
}

size_t make_local_answer(int flags, int gotname, size_t size, struct dns_header *header, char *name, char *limit, int first, int last, int ede)
{
  int trunc = 0, anscount = 0;
  unsigned char *p;
  int start;
  union all_addr addr;
  
  if (flags & (F_NXDOMAIN | F_NOERR))
    log_query(flags | gotname | F_NEG | F_CONFIG | F_FORWARD, name, NULL, NULL, 0);
	  
  setup_reply(header, flags, ede);
	  
  if (!(p = skip_questions(header, size)))
    return 0;
	  
  if (flags & gotname & F_IPV4)
    for (start = first; start != last; start++)
      {
	struct serv_addr4 *srv = (struct serv_addr4 *)server_get(daemon->serverhash, start);

	if ((srv->flags & SERV_ADDR_MASK) == SERV_X_ZEROS)
	  memset(&addr, 0, sizeof(addr));
	else
	  addr.addr4 = srv->addr;
	
	if (add_resource_record(header, limit, &trunc, sizeof(struct dns_header), &p, daemon->local_ttl, NULL, T_A, C_IN, "4", &addr))
	  anscount++;
	log_query((flags | F_CONFIG | F_FORWARD) & ~F_IPV6, name, (union all_addr *)&addr, NULL, 0);
      }
  
  if (flags & gotname & F_IPV6)
    for (start = first; start != last; start++)
      {
	struct serv_addr6 *srv = (struct serv_addr6 *)server_get(daemon->serverhash, start);

	if ((srv->flags & SERV_ADDR_MASK) == SERV_X_ZEROS)
	  memset(&addr, 0, sizeof(addr));
	else
	  addr.addr6 = srv->addr;
	
	if (add_resource_record(header, limit, &trunc, sizeof(struct dns_header), &p, daemon->local_ttl, NULL, T_AAAA, C_IN, "6", &addr))
	  anscount++;
	log_query((flags | F_CONFIG | F_FORWARD) & ~F_IPV4, name, (union all_addr *)&addr, NULL, 0);
      }

  if (trunc)
    header->hb3 |= HB3_TC;
  header->ancount = htons(anscount);
  
  return p - (unsigned char *)header;
}

#ifdef HAVE_DNSSEC
int dnssec_server(struct server *server, char *keyname, int *firstp, int *lastp)
{
  int first, last, index;

  /* Find server to send DNSSEC query to. This will normally be the 
     same as for the original query, but may be another if
     servers for domains are involved. */		      
  if (!lookup_domain(keyname, F_DNSSECOK, &first, &last))
    return -1;

  for (index = first; index != last; index++)
    if (server_get(daemon->serverhash, index) == server)
      break;
	      
  /* No match to server used for original query.
     Use newly looked up set. */
  if (index == last)
    index =  server_get(daemon->serverhash, first)->last_server == -1 ?
      first : server_get(daemon->serverhash, first)->last_server;

  if (firstp)
    *firstp = first;

  if (lastp)
    *lastp = last;
   
  return index;
}
#endif

#if 0
/* order by size, then by dictionary order */
static int order(char *qdomain, size_t qlen, struct server *serv)
{
  size_t dlen = 0;
    
  /* servers for dotless names always sort last 
     searched for name is never dotless. */
  if (serv->flags & SERV_FOR_NODOTS)
    return -1;

  dlen = serv->domain_len;
  
  if (qlen < dlen)
    return 1;
  
  if (qlen > dlen)
    return -1;

  return hostname_order(qdomain, server_domain(serv));
}

static int order_servers(struct server *s1, struct server *s2)
{
  int rc;
  bench_count(BENCH_ORDER_SERVERS, 1);

  /* need full comparison of dotless servers in 
     order_qsort() and filter_servers() */

  if (s1->flags & SERV_FOR_NODOTS)
     return (s2->flags & SERV_FOR_NODOTS) ? 0 : 1;
   
  if ((rc = order(server_domain(s1), s1->domain_len, s2)) != 0)
    return rc;

  /* For identical domains, sort wildcard ones first */
  if (s1->flags & SERV_WILDCARD)
    return (s2->flags & SERV_WILDCARD) ? 0 : 1;

  (void)&order_qsort;
  return (s2->flags & SERV_WILDCARD) ? -1 : 0;
}
  
static int order_qsort(const void *a, const void *b)
{
  int rc;
  
  struct server *s1 = *((struct server **)a);
  struct server *s2 = *((struct server **)b);
  
  rc = order_servers(s1, s2);

  /* Sort all literal NODATA and local IPV4 or IPV6 responses together,
     in a very specific order. We flip the SERV_LITERAL_ADDRESS bit
     so the order is IPv6 literal, IPv4 literal, all-zero literal, 
     unqualified servers, upstream server, NXDOMAIN literal. */
  if (rc == 0)
    rc = ((s2->flags & (SERV_LITERAL_ADDRESS | SERV_USE_RESOLV | SERV_ADDR_MASK)) ^ SERV_LITERAL_ADDRESS) -
      ((s1->flags & (SERV_LITERAL_ADDRESS | SERV_USE_RESOLV | SERV_ADDR_MASK)) ^ SERV_LITERAL_ADDRESS);

  /* Finally, order by appearance in /etc/resolv.conf etc, for --strict-order */
  if (rc == 0)
    if (!(s1->flags & SERV_LITERAL_ADDRESS))
      rc = s1->serial - s2->serial;

  return rc;
}
#endif


/* When loading large numbers of server=.... lines during startup,
   there's no possibility that there will be server records that can be reused, but
   searching a long list for each server added grows as O(n^2) and slows things down.
   This flag is set only if is known there may be free server records that can be reused.
   There's a call to mark_servers(0) in read_opts() to reset the flag before
   main config read. */

static int maybe_free_servers = 0;

/* Must be called before  add_update_server() to set daemon->servers_tail */
void mark_servers(int flag)
{
  struct server *serv, *next, **up;
  assert((flag & (~SERV_FROM_MASK)) == 0);

  maybe_free_servers = !!flag;
  
  daemon->servers_tail = NULL;
  
  /* mark everything with argument flag */
  for (serv = daemon->servers; serv; serv = serv->next)
    {
      if (flag && (serv->flags & SERV_FROM_MASK) == flag)
	serv->flags |= SERV_MARK;
      else
	serv->flags &= ~SERV_MARK;

      daemon->servers_tail = serv;
    }
  
  /* --address etc is different: since they are expected to be 
     1) numerous and 2) not reloaded often. We just delete 
     and recreate. */
  if (flag)
    for (serv = daemon->local_domains, up = &daemon->local_domains; serv; serv = next)
      {
	next = serv->next;

	if (flag && (serv->flags & SERV_FROM_MASK) == flag)
	  {
	    *up = next;
	    // free(serv->domain);
	    free(serv);
	  }
	else 
	  up = &serv->next;
      }
}

void cleanup_servers(void)
{
  struct server *serv, *tmp, **up;

  /* unlink and free anything still marked. */
  for (serv = daemon->servers, up = &daemon->servers, daemon->servers_tail = NULL; serv; serv = tmp) 
    {
      tmp = serv->next;
      if (serv->flags & SERV_MARK)
       {
         server_gone(serv);
         *up = serv->next;
	 // free(serv->domain);
	 free(serv);
       }
      else 
	{
	  up = &serv->next;
	  daemon->servers_tail = serv;
	}
    }
}

static struct server* server_alloc(u16 flags, const char *domain)
{
  if (!domain)
    domain = "";

  /* .domain == domain, for historical reasons. */
  if (*domain == '.')
    while (*domain == '.') domain++;
  else if (*domain == '*')
    domain++;

  const size_t servsz = server_sizeof(flags);
  const size_t domoff = server_offsetof_domain(flags);
  struct server *ret = NULL;

  if (*domain != 0)
    {
      char *alloc_domain = canonicalise((char *)domain, NULL);
      if (!alloc_domain)
	return NULL;
      const size_t domsz = strlen(alloc_domain) + 1;
      const size_t total = max_size(domoff + domsz, servsz);
      ret = whine_realloc(alloc_domain, total);
      if (!ret)
        {
	  free(alloc_domain);
	  return NULL;
        }
      memmove(((char*)ret) + domoff, ret, domsz); /* server_domain needs ->flags */
      memset(ret, 0, domoff);
      ret->flags = flags;
    }
  else
    {
      const size_t domsz = strlen(domain) + 1;
      const size_t total = max_size(domoff + domsz, servsz);
      ret = whine_malloc(total);
      if (!ret)
	return NULL;
      ret->flags = flags;
      memcpy(server_domain(ret), domain, domsz);
    }
  return ret;
}

int add_update_server(int flags,
		      union mysockaddr *addr,
		      union mysockaddr *source_addr,
		      const char *interface,
		      const char *domain,
		      union all_addr *local_addr)
{
  struct server *serv = NULL;
  struct server *alloc_serv = NULL;

  if (domain && domain[0] == '*' && domain[1] != '\0')
    flags |= SERV_WILDCARD;

  alloc_serv = server_alloc(flags, domain);
  if (!alloc_serv)
    return 0;

  // TODO: make `serial` in-sync with addition to servers_tail in case of structure reuse.
  // NB: `domain` is not modified.
  // server_domain(alloc_serv) == alloc_domain
  
  if (flags & SERV_IS_LOCAL)
    {
      serv = alloc_serv;
      serv->next = daemon->local_domains;
      daemon->local_domains = serv;
      
      if ((flags & SERV_ADDR_MASK) == SERV_X_4ADDR)
	((struct serv_addr4*)serv)->addr = local_addr->addr4;
      
      if ((flags & SERV_ADDR_MASK) == SERV_X_6ADDR)
	((struct serv_addr6*)serv)->addr = local_addr->addr6;
    }
  else
    { 
      /* Upstream servers. See if there is a suitable candidate, if so unmark
	 and move to the end of the list, for order. The entry found may already
	 be at the end. */
      struct server **up, *tmp;

      serv = NULL;
      
      if (maybe_free_servers)
	for (serv = daemon->servers, up = &daemon->servers; serv; serv = tmp)
	  {
	    tmp = serv->next;
	    if ((serv->flags & SERV_MARK) &&
		hostname_isequal(server_domain(alloc_serv), server_domain(serv)))
	      {
		/* Need to move down? */
		if (serv->next)
		  {
		    *up = serv->next;
		    daemon->servers_tail->next = serv;
		    daemon->servers_tail = serv;
		    serv->next = NULL;
		  }
		break;
	      }
	    else
	      up = &serv->next;
	  }
      
      if (serv)
	{
	  free(alloc_serv);
	  alloc_serv = NULL;
	}
      else
	{
	  serv = alloc_serv;
	  /* Add to the end of the chain, for order */
	  if (daemon->servers_tail)
	    daemon->servers_tail->next = serv;
	  else
	    daemon->servers = serv;
	  daemon->servers_tail = serv;
	}
      
#ifdef HAVE_LOOP
      serv->uid = rand32();
#endif      
	  
      if (interface)
	safe_strncpy(serv->interface, interface, sizeof(serv->interface));
      if (addr)
	serv->addr = *addr;
      if (source_addr)
	serv->source_addr = *source_addr;
    }
    
  serv->flags = flags;
  serv->domain_len = strlen(server_domain(serv));
  
  return 1;
}

