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
/* This code is heavily inspired by Chromium Public Suffix List lookup code,
   namely chromium/net/base/lookup_string_in_fixed_set.cc
   that is licensed under the BSD 3-Clause "New" or "Revised" License.

   Copyright 2015 The Chromium Authors
   Use of this source code is governed by a BSD-style license that can be
   found in the LICENSE file at https://github.com/chromium/chromium/
*/

#include "dnsmasq.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <ctype.h>
#include <unistd.h>
#include <sys/mman.h>
#include <string.h>

struct dnt_file
{
  void *begin;
  void *end;
  void *mm;
  size_t mmlen;
  char *path;
  dev_t st_dev;
  ino_t st_ino;
  int ref;
};

static struct dnt_file *dnt = NULL;
static size_t dnt_size = 0;

/* Unfortunately, following are well-known to be an ambiguous file-or-TLD
 * specification: /dev/x/, /home/x/, /lib/x/, /media/x/, /run/x/.
 * If file exists, we assume that it's the file the user wants us to read. If
 * the file does not exist, but the leading component of the path exists, let's
 * warn the user that the file was not read (e.g. due to permissions) and the
 * path is interpreted as a list of domains.
 */
int is_like_fs_path(const char *path)
{
  if (access(path, R_OK) == 0)
    return 1;
  char *head = safe_malloc(strlen(path) + 1);
  strcpy(head, path);
  char *nonslash = head;
  while (*nonslash && *nonslash == '/')
    nonslash++;
  char *delim = strchr(nonslash, '/');
  if (delim)
    *delim = '\0';
  int status = access(head, F_OK);
  free(head);
  return status == 0 ? 1 : 0;
}

#define U6_MIN 1
#define U6_MAX 0b111110
#define U13_MIN (U6_MAX + 1)
#define U13_MAX (U13_MIN + 0x1FFF)
#define U21_MIN (U13_MAX + 1)
#define U21_MAX (U21_MIN + 0x1FFFFF)
#define U24_MIN (U21_MAX + 1)
#define U24_MAX (U24_MIN + 0xFFFFFF)

static u8 ldhu_label_char(u8 c)
{
  c = (c & 0x5F)|0x20;
  if (c == 0x7F)
    c = 0x5f; // \x7f -> '_'
  return c;
}

static void* mmap_dnt(const char *path, size_t *mmlen, struct dnt_file *xf)
{
  char *duppath = NULL;
  if (xf)
    {
      duppath = whine_malloc(strlen(path) + 1);
      if (!duppath)
	return NULL;
      strcpy(duppath, path);
    }

  int fd = open(path, O_RDONLY);
  if (fd == -1)
    goto fail;

  char head[9];
  head[8] = '\0';
  const ssize_t len = read(fd, head, 8);
  if (len != 8)
    goto fail;
  if (memcmp(head, "#DNT", 4) != 0)
    goto fail;
  const char v = head[4];
  if (!isascii(v) || !(isalnum(v) || v == '-' || v == '_')) // 6 bits for flags
    goto fail;

  if (v != '0')
    goto fail; // the only supported revision so far

  char *p;
  const size_t comment = strtoul(head + 5, &p, 16);
  if (*p != '\0')
    goto fail;
  if (comment > 0xFFF)
    goto fail;

  struct stat st;
  if (fstat(fd, &st) == -1)
    goto fail;

  void *mm = mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
  if (!mm)
    goto fail;

  close(fd);

  if (mmlen)
    *mmlen = st.st_size;
  if (xf)
    {
      xf->begin = mm + 8 + comment;
      xf->end = mm + st.st_size;
      xf->mm = mm;
      xf->mmlen = st.st_size;
      xf->path = duppath;
      xf->st_dev = st.st_dev;
      xf->st_ino = st.st_ino;
    }

  return mm;

fail:
  free(duppath);
  if (fd != -1)
    close(fd);
  return NULL;
}

int is_dnt(const char* path)
{
  size_t len;
  void *mm = mmap_dnt(path, &len, NULL);
  if (mm)
    munmap(mm, len);
  return (mm != NULL);
}

#define check(p) do { if ((p) < begin || end <= (p)) { return -1; } } while(0)

inline static ssize_t off_step(const u8 **poff, const u8 *begin, const u8 *end)
{
  const u8 *const off = *poff;
  const u8 b7 = *off & 0x7F;
  if (b7 == 0) {
    check(off + 3);
    *poff += 4;
    return U24_MIN + ((off[1] << 16) | (off[2] << 8) | off[3]);
  } else if (b7 == 0x3F) {
    check(off + 4);
    *poff += 5;
    return ((off[1] << 24) | (off[2] << 16) | (off[3] << 8) | off[4]);
  } else if ((b7 & 0x40) == 0) {
    *poff += 1;
    return b7;
  } else if ((b7 & 0x20) == 0) {
    check(off + 1);
    *poff += 2;
    return U13_MIN + (((b7 & 0x1F) << 8) | off[1]);
  } else {
    check(off + 2);
    *poff += 3;
    return U21_MIN + (((b7 & 0x1F) << 16) | (off[1] << 8) | off[2]);
  }
}

static int ldhu_search(const char *domain, const u8* const begin, const u8* const end)
{
  const size_t len = strlen(domain);
  u8 reversed[len+1];
  for (size_t i = len; i; i--)
    reversed[len-i] = domain[i-1];
  reversed[len] = domain[len]; // TODO: check 0x20

  const u8 *needle = reversed;
  const u8 *node = begin;
  while (*needle) {
    check(node);
    const u8 *off = node;
    const u8 *label = node;
    int is_end = 0;
    // seeking for the next node that has label matching *needle
    while (!is_end) {
      check(off);
      is_end = (*off & 0x80);
      ssize_t dlabel = off_step(&off, begin, end);
      if (dlabel == -1)
        return -1;
      label += dlabel;
      check(label);
      // TODO: label: value-check
      //printf("> %c == %c ?\n", *needle, ldhu_label_char(*label));
      if (*needle == ldhu_label_char(*label)) {
        is_end = 0xff; // we don't know if whole label matches or not, but it's The Node to go to.
        while (*needle == ldhu_label_char(*label)) {
          const int has_child = (*label & 0x80);
          const int is_cut = (*label & 0x20);
          //printf("? %c == %c ? has_child:%d, is_cut:%d\n", *needle, ldhu_label_char(*label), has_child, is_cut);
          needle++;
          if (is_cut) { // possible match, not the shortest one, but good enough for benchmark
            if (*needle == '\0' || *needle == '.') {
              return needle - reversed;
            } else if (has_child) {
              node = label + 1;
              check(node);
              break;
            } else {
              return 0;
            }
          } else if (has_child) {
            node = label + 1;
            check(node);
            break;
          } else {
            label++;
            check(label);
          }
        }
      }
    }
    if (is_end != 0xff) {
      return 0;
    }
  }
  return 0;
}

struct dns_iter_ctx {
  u8 name[260];
  const u8 *begin;
  const u8 *end;
  dnt_name_cb cb;
  int count;
};

static int dns_iter_node(const u8 *node, const int ndx, struct dns_iter_ctx *ctx)
{
  const u8* const begin = ctx->begin;
  const u8* const end = ctx->end;

  check(node);
  int node_end = 0;
  const u8 *child = node;
  while (!node_end)
    {
      check(node);
      node_end = !!(*node & 0x80);
      ssize_t dlabel = off_step(&node, begin, end);
      if (dlabel == -1)
        return -1;
      child += dlabel;

      const u8 *label = child;
      int chndx = ndx;
      int child_end = 0;
      while (!child_end)
        {
          check(label);
          const u8 b = *label;
          int has_child = (b & 0x80);
          int is_cut = (b & 0x20);
          child_end = (has_child || is_cut);
          // A-Z -> a-z, \x7F -> _
          const u8 c = (b & 0x5F) != 0x5F ? (b & 0x5F)|0x20 : 0x7F;
          chndx--;
          if (chndx < 0)
            return -1;
          ctx->name[chndx] = c;
          if (is_cut) {
            if (ctx->cb)
              ctx->cb((const char*) ctx->name + chndx);
            ctx->count++;
          }
          label++;
          if (has_child && dns_iter_node(label, chndx, ctx) == -1)
            return -1;
        }
    }
  return 0;
}

#define check_xd(i) do { if ((i) < 0 || (size_t)(i) >= dnt_size || !dnt[i].mm) return -1; } while (0)

static int xd_alloc()
{
  if (dnt_size == 0x7FFF) // dnt descriptor is stored in u16 domain_len
    return -1;
  for (size_t i = 0; i < dnt_size; ++i)
    if (dnt[i].mm == NULL)
      return i;
  struct dnt_file *p = whine_realloc(dnt, dnt_size + sizeof(dnt[0]));
  if (!p)
    return -1;
  dnt = p;
  memset(dnt + dnt_size, 0, sizeof(dnt[0]));
  dnt_size++;
  return dnt_size - 1;
}

int dnt_open(const char *path)
{
  const int xd = xd_alloc();
  if (xd == -1)
    return -1;
  struct dnt_file xf;
  memset(&xf, 0, sizeof(xf));
  if (mmap_dnt(path, NULL, &xf) == NULL)
    return -1;
  memcpy(dnt + xd, &xf, sizeof(xf));
  dnt[xd].ref = 1;
  return xd;
}

int dnt_close(int xd)
{
  check_xd(xd);
  if (dnt[xd].ref > 1) // TODO: implement
    return -1;
  int ret = munmap(dnt[xd].mm, dnt[xd].mmlen);
  memset(dnt + xd, 0, sizeof(dnt[xd]));
  return ret;
}

int dnt_walk(int xd, dnt_name_cb cb)
{
  check_xd(xd);
  struct dns_iter_ctx ctx;
  memset(&ctx, 0, sizeof(ctx));
  ctx.begin = dnt[xd].begin;
  ctx.end = dnt[xd].end;
  ctx.cb = cb;
  dns_iter_node(ctx.begin, sizeof(ctx.name)-2, &ctx);
  return ctx.count;
}

int dnt_find(int xd, const char *domain)
{
  check_xd(xd);
  return ldhu_search(domain, dnt[xd].begin, dnt[xd].end);
}
