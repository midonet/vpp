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

fip64_pool_t*
fip64_pool_alloc (ip4_address_t net, int prefix)
{
  if (prefix < 0 || prefix == 31 || prefix > 32)
    {
      clib_warning("fip64_pool_alloc: network prefix %d not valid", prefix);
      return NULL;
    }

  fip64_pool_t *pool = clib_mem_alloc(sizeof(fip64_pool_t));
  pool->network = clib_net_to_host_u32(net.as_u32) & ~((1 << (32 - prefix))-1);

  u32 count = (prefix < 32)? 1 << (32 - prefix) : 1;

  pool->num_addresses = count;

  clib_bitmap_alloc (pool->used_map, count);
  //clib_bitmap_zero (pool->used_map);

  if (count > 1)
    {
      // reserve net and broadcast addresses
      pool->free_addresses = count - 2;
      pool->used_map = clib_bitmap_set (pool->used_map, 0, 1);
      pool->used_map = clib_bitmap_set (pool->used_map, count - 1, 1);
    }
  else
    {
      pool->free_addresses = count;
    }

  return pool;
}

ip4_address_t
fip64_pool_get (fip64_pool_t *pool, ip6_address_t *ip6)
{
  ip4_address_t result;

  // availability should've been checked before calling this method
  // in order to expire mappings if needed.
  if( !fip64_pool_available(pool) )
    {
      result.as_u32 = 0;
      return result;
    }

  uword *bitmap = pool->used_map;

  uword index = hash_memory(ip6->as_u8, sizeof(ip6->as_u8), 0)
                  % pool->num_addresses;

  if (clib_bitmap_get(bitmap, index) != 0)
    {
      uword prev = index;
      index = clib_bitmap_next_clear(bitmap, prev);
      /* clib_bitmap_next_clear can return a bit after the end some times,
       * as it takes full words and forgets about the exact number of bits.
       * Because of this, two conditions have to be checked for error
       */
      if ( index >= pool->num_addresses || index == prev )
        {
          index = clib_bitmap_first_clear(bitmap);
          CLIB_ERROR_ASSERT (index < pool->num_addresses
                              && clib_bitmap_get(bitmap, index) == 0);
        }
    }

  bitmap = clib_bitmap_set(bitmap, index, 1);
  -- pool->free_addresses;
  result.as_u32 = clib_host_to_net_u32(pool->network | index);
  return result;
}

void
fip64_pool_release (fip64_pool_t *pool, ip4_address_t address)
{
  CLIB_ERROR_ASSERT ( fip64_pool_available(pool) < pool->num_addresses );

  uword index = clib_net_to_host_u32(address.as_u32) - pool->network;
  // fails if address doesn't belong to network
  CLIB_ERROR_ASSERT ( index < pool->num_addresses );

  // don't release network and broadcast address
  CLIB_ERROR_ASSERT (pool->num_addresses == 1
      || (index != 0 && index != pool->num_addresses-1));

  CLIB_ERROR_ASSERT( clib_bitmap_get(pool->used_map, index) == 1);
  pool->used_map = clib_bitmap_set(pool->used_map, index, 0);
  ++ pool->free_addresses;
}

void
fip64_pool_free (fip64_pool_t *pool)
{
  clib_bitmap_free (pool->used_map);
  clib_mem_free (pool);
}

