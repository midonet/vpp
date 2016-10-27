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

#ifndef included_fip64_pool_h
#define included_fip64_pool_h

#include <vppinfra/bitmap.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vnet/ip/ip4.h>

/* Pool structure to manage a subnet of IPv4 addresses. It will try to return
 * the same mapping for a given IPv6 address as long as it is available.
 */
typedef struct fip64_pool_t {
  u32 network;
  u32 num_addresses;
  u32 free_addresses;
  clib_bitmap_t *used_map;;
} fip64_pool_t;

/* fip64_pool_alloc(net, prefix)
 * allocates a new pool for the given network.
 */
fip64_pool_t*
fip64_pool_alloc (ip4_address_t net, int prefix);

/* fip64_pool_free(pool)
 * releases the memory allocated to the pool
 */
void
fip64_pool_free (fip64_pool_t* pool);

/* fip64_pool_get(pool, ip6)
 * returns an ipv4 mapping for the address ip6.
 * If there are no addresses left, returns the zero address.
 */
ip4_address_t
fip64_pool_get (fip64_pool_t* pool, ip6_address_t *ip6);

/* fip64_pool_release(pool, ip4)
 * marks the ip4 address as available.
 */
void
fip64_pool_release (fip64_pool_t* pool, ip4_address_t ip4);

/* fip64_pool_available(pool)
 * returns the number of addresses available in the pool
 */
#define fip64_pool_available(pool) (pool->free_addresses)

#endif // included_fip64_pool_h
