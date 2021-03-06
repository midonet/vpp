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

static
ip4_address_t address_from_u32(u32 value)
{
  ip4_address_t retval;
  retval.as_u32 = clib_host_to_net_u32(value);
  return retval;
}

/* test_pool_single_host
 * make sure that the pool works as expected with a single address
 */
static clib_error_t *
test_pool_single_host ()
{
  clib_error_t * error = 0;
  fip64_pool_t *pool = 0;

  u32 address = 0x0a090807; // 10.9.8.7 address
  ip4_address_t net = address_from_u32(address);

  ip6_address_t ip6;
  memset(&ip6, 0, sizeof(ip6_address_t));

  fip64_ip6_ip4_value_t ip4_value, ip4_value1;
  memset(&ip4_value, 0, sizeof(ip4_value));
  memset(&ip4_value, 0xff, sizeof(ip4_value1));

  ip6.as_u8[0] = 0x20;
  ip6.as_u8[1] = 0x16;
  ip6.as_u8[15] = 1; // 2016::1

  _assert ((pool=fip64_pool_alloc (net, net)) != 0);
  _assert (pool->start_address == address);
  _assert (pool->size == 1);
  _assert (pool->num_free == 1);
  _assert (fip64_pool_available(pool) == 1);

  fip64_pool_get(pool, &ip6, &ip4_value);
  _assert (ip4_value.ip4_src.as_u32 == net.as_u32);
  _assert (ip4_value.lru_position == 1);
  _assert (fip64_pool_available(pool) == 0);

  ++ip6.as_u8[15]; // 2016::2
  fip64_pool_get(pool, &ip6, &ip4_value1);
  _assert (ip4_value1.ip4_src.as_u32 == net.as_u32);
  _assert (pool->size == 1);
  _assert (pool->num_free == 0);

  _assert (fip64_pool_release(pool, ip4_value) == true);
  _assert (fip64_pool_release(pool, ip4_value) == false);

 done:
  fip64_pool_free(pool);
  return error;
}

static
clib_error_t *
test_pool_two_hosts ()
{
  clib_error_t * error = 0;
  fip64_pool_t *pool = 0;

  u32 address = 0x0a090807;
  ip4_address_t start = address_from_u32(address),
                end   = address_from_u32(address + 1);

  ip6_address_t ip6;
  memset(&ip6, 0, sizeof(ip6_address_t));

  fip64_ip6_ip4_value_t ip4_value, a_ip4_value, b_ip4_value;
  memset(&ip4_value, 0, sizeof(ip4_value));
  memset(&a_ip4_value, 0, sizeof(a_ip4_value));
  memset(&b_ip4_value, 0, sizeof(b_ip4_value));

  ip6.as_u8[0] = 0x20;
  ip6.as_u8[1] = 0x16;
  ip6.as_u8[15] = 1; // 2016::1

  _assert ((pool=fip64_pool_alloc (start, end)) != 0);
  _assert (pool->start_address == address);
  _assert (pool->end_address == address+1);
  _assert (pool->size == 2);
  _assert (pool->num_free == 2);
  _assert (fip64_pool_available(pool) == 2);

  fip64_pool_get(pool, &ip6, &a_ip4_value);
  u32 a = clib_net_to_host_u32(a_ip4_value.ip4_src.as_u32);
  ip6.as_u8[15] ++;
  fip64_pool_get(pool, &ip6, &b_ip4_value);
  u32 b = clib_net_to_host_u32(b_ip4_value.ip4_src.as_u32);

  u32 min_addr = a < b? a : b;
  u32 max_addr = a < b? b : a;

  _assert (min_addr == address);
  _assert (max_addr == address+1);
  _assert (fip64_pool_available(pool) == 0);
  _assert (fip64_pool_get(pool, &ip6, &ip4_value) == true);
  _assert (ip4_value.ip4_src.as_u32 == clib_host_to_net_u32(a));
  _assert (fip64_pool_available(pool) == 0);
  _assert (fip64_pool_release(pool, a_ip4_value) == true);
  _assert (fip64_pool_available(pool) == 1);
  _assert (fip64_pool_release(pool, b_ip4_value) == true);
  _assert (fip64_pool_available(pool) == 2);
  fip64_pool_free (pool);

 done:
  return error;
}

/* test_pool_fill(start, end)
 * stresses a pool by allocating all the addresses twice and then freeing them.
 * Making sure no address is returned while still in use.
 *
 * Prints the worst lookup time to standard error.
 */
static
clib_error_t *
test_pool_fill (u32 start, u32 end)
{
  clib_error_t *error = 0;

  fip64_pool_t *pool = 0;
  bool *used = 0;

  pool = fip64_pool_alloc(address_from_u32(start),
                                        address_from_u32(end));
  _assert (pool != 0);

  used = calloc(pool->size, 1);
  _assert (used != 0);

  fip64_ip6_ip4_value_t ip4_value, ip4_first_value;
  ip6_address_t ip6;
  memset(&ip6, 0, sizeof(ip6_address_t));
  memset(&ip4_first_value, 0, sizeof(ip4_first_value));
  ip6.as_u8[0] = 0x20;
  ip6.as_u8[1] = 0x16; // 2016::x

  clock_t worst = 0;
  u32 i = 0;

  for (;i<pool->size;++i)
    {
      ip6.as_u32[3] ++;

      clock_t start = clock();
      fip64_pool_get(pool, &ip6, &ip4_value);
      if (i == 0)
        {
          ip4_first_value = ip4_value;
        }
      u32 index = clib_net_to_host_u32(ip4_value.ip4_src.as_u32) - pool->start_address;
      clock_t took = clock() - start;

      if (took > worst) worst = took;

      _assert(index < pool->size);
      _assert (used[index] == false);
      used[index] = true;
    }
  _assert(fip64_pool_available(pool) == 0);
  _assert (fip64_pool_get(pool, &ip6, &ip4_value) == 1);
  _assert (ip4_value.ip4_src.as_u32 == ip4_first_value.ip4_src.as_u32);

  for (i=0;i<pool->size;++i)
    {
      _assert (used[i] == true);
      ip4_value.ip4_src = address_from_u32 (pool->start_address + i);
      ip4_value.lru_position = i + 1;
      fip64_pool_release (pool, ip4_value);
    }
  _assert(fip64_pool_available(pool) == pool->size);

  fprintf(stderr,"fip64_pool test for range of size %u. "
                 "Worst lookup time: %lf ms.\n",
          pool->size,
          (double)worst*1000 / CLOCKS_PER_SEC);

done:
  if (pool) fip64_pool_free(pool);
  free(used);
  return error;
}

/* test_pool_reuse(start, end)
 * stresses a pool by allocating all the addresses 3 times
 * Making sure no address is returned while still in use.
 */
static
clib_error_t *
test_pool_reuse (u32 start, u32 end)
{
  clib_error_t *error = 0;

  fip64_pool_t *pool = 0;
  bool *used = 0;

  pool = fip64_pool_alloc(address_from_u32(start),
                          address_from_u32(end));
  CLIB_ERROR_ASSERT(pool != 0);
  u32 assigned_ips[pool->size];

  used = calloc(pool->size, 1);
  _assert (used != 0);

  fip64_ip6_ip4_value_t ip4_value, ip4_first_value;
  ip6_address_t ip6;
  memset(&ip6, 0, sizeof(ip6_address_t));
  memset(&ip4_first_value, 0, sizeof(ip4_first_value));
  ip6.as_u8[0] = 0x20;
  ip6.as_u8[1] = 0x16; // 2016::x

  u32 i = 0;
  u32 step = 0;

  for (step = 0; step < 3; ++step)
    {
      for (i = 0;i<pool->size;++i)
        {
          ip6.as_u32[3] ++;

          bool removed_old = fip64_pool_get(pool, &ip6, &ip4_value);
          if (i == 0)
            {
              ip4_first_value = ip4_value;
            }
          _assert(step == 0 || removed_old);
          if (step > 0)
            {
              _assert(ip4_value.ip4_src.as_u32 == assigned_ips[i]);
            }
          assigned_ips[i] = ip4_value.ip4_src.as_u32;
          u32 index = clib_net_to_host_u32(ip4_value.ip4_src.as_u32) - pool->start_address;

          _assert(index < pool->size);
          _assert (step || used[index] == false);
          used[index] = true;
        }
    }
  _assert(fip64_pool_available(pool) == 0);
  _assert (fip64_pool_get(pool, &ip6, &ip4_value) == 1);
  _assert (ip4_value.ip4_src.as_u32 == ip4_first_value.ip4_src.as_u32);

  for (i=0;i<pool->size;++i)
    {
      _assert (used[i] == true);
      ip4_value.ip4_src = address_from_u32 (pool->start_address + i);
      ip4_value.lru_position = i + 1;
      fip64_pool_release (pool, ip4_value);
    }
  _assert(fip64_pool_available(pool) == pool->size);

done:
  if (pool) fip64_pool_free(pool);
  free(used);
  return error;
}

static
clib_error_t *
test_pool_bad_range (u32 start, u32 end)
{
  clib_error_t * error = 0;
  fip64_pool_t *pool = 0;

  _assert ((pool=fip64_pool_alloc (address_from_u32(start),
                                   address_from_u32(end))) == 0);

 done:
  if (pool) fip64_pool_free(pool);
  return error;
}

clib_error_t *
test_pool()
{
  clib_error_t *error = 0;

#define TEST(NAME,ARGS...) error = error? error : test_pool_ ## NAME (ARGS);
  TEST(single_host);
  TEST(two_hosts);
  TEST(bad_range, 1, 0);
  TEST(bad_range, 0xffffffff, 0);
  TEST(bad_range, 0, 0xffffffff);
  TEST(fill, 0x0aff0001, 0x0afffffe);
  TEST(fill, 0x0affff01, 0x0afffffe);
  TEST(fill, 0x0af00001, 0x0afffffe);
  TEST(reuse, 0x0affff01, 0x0afffffe);
  TEST(reuse, 0x0af00001, 0x0afffffe);
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
