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

#include <stdbool.h>
#include <vppinfra/error.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vlib/vlib.h>

#include "fip64_pool.h"

typedef struct {
  ip4_address_t src_address;
  ip4_address_t dst_address;
  // Id of the corresponding VRF table
  u32 table_id;
} fip64_ip4_t;

typedef struct {
  u32 table_id;
  ip4_address_t pool_start,
                pool_end;
  fip64_pool_t *pool;
  u32 num_references;
} fip64_tenant_t;

typedef struct {
  ip4_address_t fixed;
  u32 table_id;
} fip64_ip4key_t;

typedef struct {
  ip6_address_t fip6;
  fip64_ip4key_t ip4;
  fip64_tenant_t *tenant;
  uword *ip6_ip4_hash; /* ip6 (src,dst) address to ip4 (src,dst) address map */
  uword *ip4_ip6_hash; /* ip4 (src,dst) address to ip6 (src,dst) address map */
} fip64_mapping_t;

typedef struct {
  ip6_main_t *ip6_main;
  ip4_main_t *ip4_main;
  uword *vrf_tenant_hash; /* vrf id to pool mapping */
  uword *fixed4_mapping_hash; /* fixed4/vrf to fip64 mapping */
  uword *fip6_mapping_hash; /* fip6 to fip64 mapping */
  bool testing;
} fip64_main_t;

typedef enum
{
  FIP64_SENDER,
  FIP64_RECEIVER
} fip64_dir_e;

/**
 * Initial fip64 main structure. Visible for unit tests.
 */
extern clib_error_t *
fip64_main_init(fip64_main_t * fip64_main, ip6_main_t * ip6_main, ip4_main_t * ip4_main);

/**
 * Add an IP6 mapping for a fixed IP4
 *
 * @param[in] fip6 The IP6 FIP address
 * @param[in] fixed4 The fixed IP4 address
 * @param[in] pool_start first address for IP4 source allocation
 * @param[in] pool_end last address for IP4 source allocation
 * @param[in] table_id VRF table id
 */
extern clib_error_t *
fip64_add(fip64_main_t *fip64_main,
          ip6_address_t *fip6,
          ip4_address_t fixed4,
          ip4_address_t pool_start,
          ip4_address_t pool_end,
          u32 table_id);

/**
 * Remove an IP6 mapping
 *
 * @param[in] fip6 The IP6 FIP address
 */
extern clib_error_t *
fip64_delete(fip64_main_t *fip64_main, ip6_address_t *fip6);

/**
 * Lookup IP4 (src,dst) addresses for a given IP6 (src,dst) addresses.
 *
 * The output parameter should be valid memory regions where this function
 * will write the results.
 *
 * @param[in] ip6_src Reference to the source IP6 address.
 * @param[in] ip6_dst Reference to the destination IP6 address.
 * @param[out] ip4 Pointer where to copy the source, destination IP4 addresses
 *             and VRF table id for ip4 adjacency
 */
extern bool
fip64_lookup_ip6_to_ip4(fip64_main_t * fip64_main,
                        ip6_address_t * ip6_src, ip6_address_t * ip6_dst,
                        fip64_ip4_t * ip4);

/**
 * Lookup IP6 (src,dst) addresses for a given IP4 (src,dst) addresses.
 *
 * The output parameters should be valid memory regions where this function
 * will write the results.
 *
 * @param[in] ip4 Reference to the source, destination IP4 address and
 *            VRF table id for the ip4 adjacency
 * @param[out] ip6_src Pointer where to copy the source IP6 address.
 * @param[out] ip6_dst Pointer where to copy the destination IP6 address.
 */
extern bool
fip64_lookup_ip4_to_ip6(fip64_main_t * fip64_main,
                        fip64_ip4_t * ip4,
                        ip6_address_t * ip6_src, ip6_address_t * ip6_dst);

/*
 * MAP Error counters/messages
 */
#define foreach_fip64_error                             \
/* Must be first. */                                    \
_(NONE, "valid FIP64 packets")                          \
_(BAD_PROTOCOL, "bad protocol")                         \
_(SEC_CHECK, "security check failed")                   \
_(ICMP, "unable to translate ICMP")                     \
_(ICMP_RELAY, "unable to relay ICMP")                   \
_(UNKNOWN, "unknown")                                   \
_(FRAGMENTED, "packet is a fragment")                   \
_(FRAGMENT_MEMORY, "could not cache fragment")          \
_(FRAGMENT_MALFORMED, "fragment has unexpected format") \
_(FRAGMENT_DROPPED, "dropped cached fragment")          \
_(MALFORMED, "malformed packet")                        \
_(DF_SET, "can't fragment, DF set")                     \
_(NO46MAP, "there is no mapping for v4->v6 path")

#define u8_ptr_add(ptr, index) (((u8 *)ptr) + index)
#define u16_net_add(u, val) clib_host_to_net_u16(clib_net_to_host_u16(u) + (val))
#define frag_id_6to4(id) ((id) ^ ((id) >> 16))

typedef enum {
#define _(sym,str) FIP64_ERROR_##sym,
  foreach_fip64_error
#undef _
  FIP64_N_ERROR,
} fip64_error_t;

typedef enum {
  IP6_FIP64_TRACE,
  IP4_FIP64_TRACE
} fip64_trace_op_t;

typedef struct {
  fip64_trace_op_t op;
  fip64_ip4_t ip4;

  struct {
    ip6_address_t src_address,
                  dst_address;
  } ip6;
} fip64_trace_t;

//This is used to pass information within the buffer data.
//Buffer structure being too small to contain big structures like this.
typedef CLIB_PACKED (struct {
  ip6_address_t daddr;
  ip6_address_t saddr;
  //IPv6 header + Fragmentation header will be here
  //sizeof(ip6) + sizeof(ip_frag) - sizeof(ip4)
  u8 unused[28];
}) ip4_fip64_pseudo_header_t;

u8 *format_fip64_trace (u8 * s, va_list * args);

extern vlib_node_registration_t ip4_fip64_node;
extern vlib_node_registration_t ip4_fip64_icmp_node;
extern vlib_node_registration_t ip4_fip64_tcp_udp_node;

extern vlib_node_registration_t ip6_fip64_node;
extern vlib_node_registration_t ip6_fip64_icmp_node;
extern ip4_main_t ip4_main;

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * indent-tabs-mode: nil
 * End:
 */
