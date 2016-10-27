/*
 * Copyright (c) 2016 Cisco and/or its affiliates.
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

#include <vnet/fip64/fip64_pool.h>
#include <time.h>

#define _assert(e)                    \
  error = CLIB_ERROR_ASSERT (e);      \
  if (error)                          \
    goto done;

/* test_pool_single_host
 * make sure that the pool works as expected with a single address
 */
static clib_error_t *
test_pool_single_host ()
{
  clib_error_t * error = 0;
  fip64_pool_t *pool = 0;

  u32 address = 0x0a090807; // 10.9.8.7 address
  ip4_address_t net;
  net.as_u32 = clib_host_to_net_u32(address);

  ip6_address_t ip6 = {0};
  ip6.as_u8[0] = 0x20;
  ip6.as_u8[1] = 0x16;
  ip6.as_u8[15] = 1; // 2016::1

  _assert( (pool=fip64_pool_alloc (net, 32)) != 0 );
  _assert( pool->network == address);
  _assert( pool->num_addresses == 1);
  _assert( pool->free_addresses == 1);
  _assert( fip64_pool_available(pool) == 1);
  _assert( fip64_pool_get(pool, &ip6).as_u32 == net.as_u32 );
  _assert( fip64_pool_available(pool) == 0);

  fip64_pool_free(pool);

 done:
  return error;
}

/* test_pool_two_hosts
 * tests the pool with a /30 subnet
 */
static
clib_error_t *
test_pool_two_hosts ()
{
  clib_error_t * error = 0;
  fip64_pool_t *pool = 0;

  u32 address = 0x0a090807;
  ip4_address_t net;
  net.as_u32 = clib_host_to_net_u32(address);

  ip6_address_t ip6 = {0};
  ip6.as_u8[0] = 0x20;
  ip6.as_u8[1] = 0x16;
  ip6.as_u8[15] = 1; // 2016::1

  _assert( (pool=fip64_pool_alloc (net, 30)) != 0 );
  _assert( pool->network == (address & ~3) );
  _assert( pool->num_addresses == 4);
  _assert( pool->free_addresses == 2);
  _assert( fip64_pool_available(pool) == 2);

  u32 a = clib_net_to_host_u32(fip64_pool_get(pool, &ip6).as_u32);
  ip6.as_u8[15] ++;
  u32 b = clib_net_to_host_u32(fip64_pool_get(pool, &ip6).as_u32);

  u32 min_addr = a < b? a : b;
  u32 max_addr = a < b? b : a;

  _assert( min_addr == (address&~3)+1 );
  _assert( max_addr == (address&~3)+2 );
  _assert( fip64_pool_available(pool) == 0);

  fip64_pool_free (pool);

 done:
  return error;
}

/* test_pool_with_prefix(n)
 * stresses a pool serving a /n subnet. All the addresses are allocated
 * and then freed. Making sure no address is returned while still in use,
 * and that special addresses are never returned.
 *
 * Prints the worst lookup time to standard error.
 */
static
clib_error_t *
test_pool_with_prefix (u32 prefix)
{
  clib_error_t *error = 0;

  // try not to allocate that much memory
  _assert(prefix >= 8 && prefix<31);
#define FLAG_SEEN (1<<0)
#define FLAG_BANNED (1<<1)

  u32 size = 1 << (32 - prefix);
  char *used = calloc(size, 1);
  used[0] = used[size-1] = FLAG_BANNED;

  fip64_pool_t *pool = 0;

  u32 net_addr = 0x0affffff & ~(size - 1); // 10.255.x.x
  ip4_address_t net;
  net.as_u32 = clib_host_to_net_u32(net_addr);

  ip6_address_t ip6 = {0};
  ip6.as_u8[0] = 0x20;
  ip6.as_u8[1] = 0x16; // 2016::x

  _assert( (pool=fip64_pool_alloc(net, prefix)) != 0 );
  _assert( pool->num_addresses == size );
  _assert( pool->free_addresses == size-2 );

  clock_t worst = 0;

  for (u32 i=1;i<size-1;++i)
    {
      ip6.as_u32[3] ++;
      clock_t start = clock();
      u32 index = clib_net_to_host_u32(fip64_pool_get(pool, &ip6).as_u32)
                    & (size - 1);
      clock_t took = clock() - start;
      if (took > worst) worst = took;

      _assert(index >= 0 && index < size);
      _assert( ! (used[index] & FLAG_BANNED) );
      _assert( ! (used[index] & FLAG_SEEN) );
      used[index] |= FLAG_SEEN;
    }
  _assert(fip64_pool_available(pool) == 0);

  for (u32 i=1;i<size-1;++i)
    {
      _assert( used[i] == FLAG_SEEN );
      ip4_address_t addr;
      addr.as_u32 = clib_host_to_net_u32( net_addr | i);
      fip64_pool_release (pool, addr);
    }
  _assert(fip64_pool_available(pool) == size - 2);
  fip64_pool_free(pool);

  fprintf(stderr,"fip64_pool test with network prefix %u. "
                 "Worst lookup time: %lf ms.\n",
          prefix,
          (double)worst*1000 / CLOCKS_PER_SEC);

#undef FLAG_SEEN
#undef FLAG_BANNED
done:
  free(used);
  return error;
}

static
clib_error_t *
test_pool_bad_prefix ()
{
  clib_error_t * error = 0;
  fip64_pool_t *pool = 0;
  ip4_address_t net;

  _assert( (pool=fip64_pool_alloc (net, 31)) == 0 );
  _assert( (pool=fip64_pool_alloc (net, 33)) == 0 );
  _assert( (pool=fip64_pool_alloc (net, -1)) == 0 );

 done:
  return error;
}

clib_error_t *
test_pool()
{
  clib_error_t *error = 0;

#define TEST(NAME,ARGS...) error = error? error : test_pool_ ## NAME (ARGS);
  TEST(single_host);
  TEST(two_hosts);
  TEST(bad_prefix);

  for (u32 prefix = 30; prefix >= 10 ; --prefix)
    {
      TEST(with_prefix, prefix);
    }
#undef TEST

  return error;
}

#undef _assert
/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * indent-tabs-mode: nil
 * End:
 */
