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
#ifndef CHARAND_H_C3BD69196178
#define CHARAND_H_C3BD69196178

#if !defined(HAVE_GETENTROPY) && !defined(RANDFILE)
# define RANDFILE "/dev/urandom"
#endif

#include <stdint.h>
#include <stdbool.h>

int charand_init(void);
bool charand_isinit(void);
void charand_rekey(void);
void charand_atfork_child(void);

uint16_t charand16(void);
uint32_t charand32(void);
uint64_t charand64(void);

static inline uintptr_t charandptr(void)
{
  const unsigned szp = sizeof(void*);
  _Static_assert(szp == 4 || szp == 8, "void* is neither 32-bit nor 64-bit");
  return szp == 4 ? charand32() : charand64();
}

#endif // CHARAND_H_C3BD69196178
