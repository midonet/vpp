/*
 * Copyright (c) 2016 Midokura SARL.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "fip64_pool.h"

#include <assert.h>
#include <vppinfra/hash.h>

u8 *
format_pool_range (u8 * s, va_list * va)
{
  fip64_pool_t *pool = va_arg (*va, fip64_pool_t *);

  ip4_address_t start, end;
  start.as_u32 = clib_host_to_net_u32 (pool->start_address);
  end.as_u32 = clib_host_to_net_u32 (pool->end_address);

  s = format (s, "%U - %U",
	      format_ip4_address, &start,
              format_ip4_address, &end);
  return s;
}

fip64_pool_t*
fip64_pool_alloc (ip4_address_t start, ip4_address_t end)
{
  u32 a = clib_net_to_host_u32 (start.as_u32),
      b = clib_net_to_host_u32 (end.as_u32);

  fip64_pool_t *pool = clib_mem_alloc(sizeof(fip64_pool_t));
  pool->start_address = a;
  pool->end_address = b;
  pool->num_free = pool->size = b - a + 1;
  if (pool->start_address > pool->end_address || pool->size == 0)
    {
      clib_warning("fip64_pool_alloc: invalid range: %U",
                  format_pool_range, pool);
      return NULL;
    }

  clib_bitmap_alloc (pool->used_map, pool->size);

  return pool;
}

ip4_address_t
fip64_pool_get (fip64_pool_t *pool, ip6_address_t *ip6)
{
  ip4_address_t result;

  // availability should've been checked before calling this method
  // in order to expire mappings if needed.
  if (!fip64_pool_available(pool))
    {
      result.as_u32 = 0;
      return result;
    }

  uword *bitmap = pool->used_map;

  uword index = hash_memory(ip6->as_u8, sizeof(ip6->as_u8), 0)
                  % pool->size;

  if (clib_bitmap_get(bitmap, index) != 0)
    {
      uword prev = index;
      index = clib_bitmap_next_clear(bitmap, prev);
      /* clib_bitmap_next_clear can return a bit after the end some times,
       * as it takes full words and forgets about the exact number of bits.
       * Because of this, two conditions have to be checked for error
       */
      if (index >= pool->size || index == prev)
        {
          index = clib_bitmap_first_clear(bitmap);
          CLIB_ERROR_ASSERT (index < pool->size
                              && clib_bitmap_get(bitmap, index) == 0);
        }
    }

  -- pool->num_free;
  bitmap = clib_bitmap_set(bitmap, index, 1);
  result.as_u32 = clib_host_to_net_u32(pool->start_address + index);

  return result;
}

bool
fip64_pool_release (fip64_pool_t *pool, ip4_address_t address)
{
  uword index = clib_net_to_host_u32 (address.as_u32) - pool->start_address;

  if (index < pool->size && clib_bitmap_get(pool->used_map, index) == 1)
    {
      pool->used_map = clib_bitmap_set(pool->used_map, index, 0);
      ++ pool->num_free;
      return true;
    }

  clib_warning("fip64_pool_release: Address %U not in use for pool %U",
               format_ip4_address, &address,
               format_pool_range, pool);
  return false;
}

void
fip64_pool_free (fip64_pool_t *pool)
{
  clib_bitmap_free (pool->used_map);
  clib_mem_free (pool);
}

