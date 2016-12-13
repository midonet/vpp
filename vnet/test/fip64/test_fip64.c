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

#include <vnet/vnet.h>
#include <vppinfra/error.h>
#include <vlibapi/api.h>

#include <vnet/fip64/fip64.h>
#include <vnet/fip64/flowstate.h>

extern clib_error_t *test_pool();

#define _assert(e)                    \
  error = CLIB_ERROR_ASSERT (e);      \
  if (error)                          \
    goto done;

static void init_ip_mains(ip6_main_t * ip6_main,
                          ip4_main_t * ip4_main) {
  ip4_main->flow_hash_seed = 0xdeadbeef;
  ip4_main->host_config.ttl = 64;
  ip6_main->flow_hash_seed = 0xdeadbeef;
  ip4_main->host_config.ttl = 64;
}

#define MAKE_IPV4(A,B,C,D) clib_host_to_net_u32((A) << 24 | (B) << 16 | C << 8 | D)
#define SAME_IPV6(A, B) ( (A)->as_u64[0] == (B)->as_u64[0] && \
                          (A)->as_u64[1] == (B)->as_u64[1])

static clib_error_t *
test_flowstate ()
{
  u32 vni = 0x123456,
      table_id = 1;
  clib_error_t * error = 0;
  ip4_main_t ip4_main;
  ip6_main_t ip6_main;
  fip64_main_t fip64_main;
  fip64_ip4_t mapped4;
  ip4_address_t fixed4, pool_start, pool_end;

  struct {
    ip6_address_t src_address;
    ip6_address_t dst_address;
  } ip6, output_ip6;

  init_ip_mains(&ip6_main, &ip4_main);
  fip64_main_init(NULL, &fip64_main, &ip6_main, &ip4_main);

  // disable adjacencies under testing (causing crash)
  fip64_main.testing = true;

  ip6.src_address.as_u64[0] = clib_host_to_net_u64(0x2001);
  ip6.src_address.as_u64[1] = clib_host_to_net_u64(0x1);
  ip6.dst_address.as_u64[0] = clib_host_to_net_u64(0x4001);
  ip6.dst_address.as_u64[1] = clib_host_to_net_u64(0x100);

  pool_start.as_u32 = MAKE_IPV4(192, 168, 0, 1);
  pool_end.as_u32 = MAKE_IPV4(192, 168, 0, 254);
  fixed4.as_u32 = MAKE_IPV4(10, 0, 0, 2);
  mapped4.dst_address = fixed4;
  mapped4.src_address.as_u32 = MAKE_IPV4(192, 168, 255, 1);
  mapped4.table_id = table_id;

  _assert(0 == fip64_add(&fip64_main,
                         &ip6.dst_address,
                         fixed4,
                         pool_start,
                         pool_end,
                         table_id,
                         vni));

  /* nothing mapped */
  _assert( 0 == fip64_lookup_ip4_to_ip6 (&fip64_main,
                                         &mapped4,
                                         &output_ip6.src_address,
                                         &output_ip6.dst_address));


  /*
   * wrong messages
   */
  fip64_flowstate_msg_t msg;
  memset (&msg, 0, sizeof(msg));
  msg.version = 1;
  fip64_flowstate_set_op (&msg, FLOWSTATE_OP_ADD);
  msg.vni = clib_host_to_net_u32 (vni);
  msg.client_ipv6.as_u64[0] = clib_host_to_net_u64 (0xbbbb000000000000L);
  msg.client_ipv6.as_u64[1] = clib_host_to_net_u64 (0xb);
  msg.allocated_ipv4 = mapped4.src_address;
  msg.fixed_ipv4 = mapped4.dst_address;

  // bad version
  msg.version --;
  _assert (! fip64_flowstate_message (&fip64_main, (u8*)&msg, sizeof(msg)));
  msg.version ++;

  // bad vni
  msg.vni --;
  _assert (! fip64_flowstate_message (&fip64_main, (u8*)&msg, sizeof(msg)));
  msg.vni ++;

  // bad fixed_ipv4
  msg.fixed_ipv4.as_u32 --;
  _assert (! fip64_flowstate_message (&fip64_main, (u8*)&msg, sizeof(msg)));
  msg.fixed_ipv4.as_u32 ++;

  // too large
  _assert (! fip64_flowstate_message (&fip64_main, (u8*)&msg, sizeof(msg) - 1));

  // too small
  _assert (! fip64_flowstate_message (&fip64_main, (u8*)&msg, sizeof(msg) + 1));

  // correct mapping
  _assert (fip64_flowstate_message (&fip64_main, (u8*)&msg, sizeof(msg)));

  // repeated mapping
  _assert (!fip64_flowstate_message (&fip64_main, (u8*)&msg, sizeof(msg)));

  // check mapping
  _assert( 0 != fip64_lookup_ip4_to_ip6 (&fip64_main,
          &mapped4,
          &output_ip6.src_address,
          &output_ip6.dst_address));

  _assert ( SAME_IPV6(&msg.client_ipv6, &output_ip6.src_address) );
  _assert ( SAME_IPV6(&ip6.dst_address, &output_ip6.dst_address) );

  // dest delete
  fip64_flowstate_set_op (&msg, FLOWSTATE_OP_DEL);
  _assert (fip64_flowstate_message (&fip64_main, (u8*)&msg, sizeof(msg)));

  _assert( 0 == fip64_lookup_ip4_to_ip6 (&fip64_main,
          &mapped4,
          &output_ip6.src_address,
          &output_ip6.dst_address));

done:
  return error;
}

static clib_error_t *
test_lookup ()
{
  clib_error_t * error = 0;
  ip4_main_t ip4_main;
  ip6_main_t ip6_main;
  fip64_main_t fip64_main;
  fip64_ip4_t output_ip4;
  ip4_address_t fixed4, pool_start, pool_end, expected;

  struct {
    ip6_address_t src_address;
    ip6_address_t dst_address;
  } ip6, output_ip6;

  init_ip_mains(&ip6_main, &ip4_main);
  fip64_main_init(NULL, &fip64_main, &ip6_main, &ip4_main);

  // disable adjacencies under testing (causing crash)
  fip64_main.testing = true;

  ip6.src_address.as_u64[0] = clib_host_to_net_u64(0x2001);
  ip6.src_address.as_u64[1] = clib_host_to_net_u64(0x1);
  ip6.dst_address.as_u64[0] = clib_host_to_net_u64(0x4001);
  ip6.dst_address.as_u64[1] = clib_host_to_net_u64(0x100);

  pool_start.as_u32 = clib_host_to_net_u32(192 << 24 | 168 << 16 | 1);
  pool_end.as_u32 = clib_host_to_net_u32(192 << 24 | 168 << 16 | 254);
  expected.as_u32 = clib_host_to_net_u32(192 << 24 | 168 << 16 | 245);
  fixed4.as_u32 = clib_host_to_net_u32(10 << 24 | 1);

  // add mapping, look it up, delete mapping, look up again
  //_assert(fip64_add_mapping(&fip64_main, &ip6, &ip4) == 0);
  _assert(0 == fip64_add(&fip64_main,
                         &ip6.dst_address,
                         fixed4,
                         pool_start,
                         pool_end,
                         0,
                         0));

  // lookup using ip6 params
  _assert(fip64_lookup_ip6_to_ip4(&fip64_main,
                                  &ip6.src_address, &ip6.dst_address,
                                  &output_ip4));
  _assert(expected.as_u32 == output_ip4.src_address.as_u32);
  _assert(fixed4.as_u32 == output_ip4.dst_address.as_u32);

  // lookup using ip4 params
  _assert(fip64_lookup_ip4_to_ip6(&fip64_main,
                                  &output_ip4,
                                  &output_ip6.src_address,
                                  &output_ip6.dst_address));
  _assert(ip6.src_address.as_u64[0] == output_ip6.src_address.as_u64[0]);
  _assert(ip6.src_address.as_u64[1] == output_ip6.src_address.as_u64[1]);
  _assert(ip6.dst_address.as_u64[0] == output_ip6.dst_address.as_u64[0]);
  _assert(ip6.dst_address.as_u64[1] == output_ip6.dst_address.as_u64[1]);

  // remove the mapping
  _assert(0 == fip64_delete(&fip64_main, &ip6.dst_address));

  // lookups should fail
  _assert(!fip64_lookup_ip6_to_ip4(&fip64_main,
                                   &ip6.src_address, &ip6.dst_address,
                                   &output_ip4));
  _assert(!fip64_lookup_ip4_to_ip6(&fip64_main,
                                   &output_ip4,
                                   &output_ip6.src_address,
                                   &output_ip6.dst_address));
 done:
  return error;
}

/*
 * Performs 2 * pool_size lookups and chechs that lru expiration
 * works fine.
 */
static clib_error_t *
test_reuse_impl (u32 start, u32 end)
{
  ip4_address_t pool_start, pool_end;

  clib_error_t * error = 0;
  ip4_main_t ip4_main;
  ip6_main_t ip6_main;
  fip64_main_t fip64_main;
  fip64_ip4_t output_ip4;
  ip4_address_t fixed4;
  u32 pool_size = end - start + 1;
  u32 assigned_ips[pool_size];

  struct {
    ip6_address_t src_address;
    ip6_address_t dst_address;
  } ip6, output_ip6;

  ip6_address_t ip6_start_src_address;
  init_ip_mains(&ip6_main, &ip4_main);
  fip64_main_init(NULL, &fip64_main, &ip6_main, &ip4_main);

  // disable adjacencies under testing (causing crash)
  fip64_main.testing = true;

  pool_start.as_u32 = clib_host_to_net_u32(start);
  pool_end.as_u32 = clib_host_to_net_u32(end);
  ip6.src_address.as_u64[0] = clib_host_to_net_u64(0x2001);
  ip6.src_address.as_u64[1] = clib_host_to_net_u64(0x1);
  ip6.dst_address.as_u64[0] = clib_host_to_net_u64(0x4001);
  ip6.dst_address.as_u64[1] = clib_host_to_net_u64(0x100);
  ip6_start_src_address.as_u64[0] = ip6.src_address.as_u64[0];
  ip6_start_src_address.as_u64[1] = ip6.src_address.as_u64[1];

  fixed4.as_u32 = clib_host_to_net_u32(10 << 24 | 1);
  // add mapping, look it up, delete mapping, look up again
  //_assert(fip64_add_mapping(&fip64_main, &ip6, &ip4) == 0);
  _assert(0 == fip64_add(&fip64_main,
                         &ip6.dst_address,
                         fixed4,
                         pool_start,
                         pool_end,
                         2,
                         0));

  u32 step = 0;
  for (step = 0; step < 3; ++step)
    {
      u32 i = 0;
      for (; i < pool_size; ++i)
        {
          // lookup using ip6 params
          _assert(fip64_lookup_ip6_to_ip4(&fip64_main,
                                          &ip6.src_address, &ip6.dst_address,
                                          &output_ip4));

          if (step) {
            _assert(output_ip4.src_address.as_u32 == assigned_ips[i]);
          }
          assigned_ips[i] = output_ip4.src_address.as_u32;
          _assert(fixed4.as_u32 == output_ip4.dst_address.as_u32);
          _assert(output_ip4.table_id == 2)

          // lookup using ip4 params
          _assert(fip64_lookup_ip4_to_ip6(&fip64_main,
                                          &output_ip4,
                                          &output_ip6.src_address,
                                          &output_ip6.dst_address));
          _assert(ip6.dst_address.as_u64[0] == output_ip6.dst_address.as_u64[0]);
          _assert(ip6.dst_address.as_u64[1] == output_ip6.dst_address.as_u64[1]);
          _assert(ip6.src_address.as_u64[0] == output_ip6.src_address.as_u64[0]);
          _assert(ip6.src_address.as_u64[1] == output_ip6.src_address.as_u64[1]);
          ++ip6.src_address.as_u32[3];
        }
  }
  // remove the mapping
  _assert(0 == fip64_delete(&fip64_main, &ip6.dst_address));

  // lookups should fail
  _assert(!fip64_lookup_ip6_to_ip4(&fip64_main,
                                   &ip6_start_src_address,
                                   &ip6.dst_address,
                                   &output_ip4));
  _assert(!fip64_lookup_ip4_to_ip6(&fip64_main,
                                   &output_ip4,
                                   &output_ip6.src_address,
                                   &output_ip6.dst_address));
 done:
  return error;
}

static clib_error_t *
test_reuse()
{
  clib_error_t *error = 0;
#define TEST(NAME,ARGS...) error = error? error : test_## NAME (ARGS);
  TEST(reuse_impl, 0xc0a80001, 0xc0a80002);
  TEST(reuse_impl, 0xc0b80001, 0xc0b800ff);
  return error;
}

#define foreach_test_case                 \
  _(reuse)                                \
  _(lookup)                               \
  _(pool)                                 \
  _(flowstate)

int run_tests (void)
{
  clib_error_t * error;

#define _(_test_name)                   \
  error = test_ ## _test_name ();       \
  if (error)                            \
    {                                   \
      clib_error_report (error);        \
      return 0;                         \
    }

  foreach_test_case
#undef _

  return 0;
}

int main()
{
  return run_tests ();
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
