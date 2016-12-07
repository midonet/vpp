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
#ifndef included_fip64_typesl_h
#define included_fip64_typesl_h

#include <stdbool.h>
#include <vppinfra/bitmap.h>
#include <vppinfra/dlist.h>
#include <vnet/vnet.h>
#include <vnet/ip/ip.h>
#include <vlib/vlib.h>

typedef struct {
  u64 msb, lsb;
} fip64_uuid_t;

/* Pool structure to manage a subnet of IPv4 addresses. It will try to return
 * the same mapping for a given IPv6 address as long as it is available.
 */
typedef struct {
  u32 start_address,
      end_address,
      size,
      num_free;
  clib_bitmap_t *used_map;
  dlist_elt_t *list_pool; // list of recently used addresses. The least recently used
                         // is the head of the pool
} fip64_pool_t;

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
  uword *ip6_ip4_hash; /* ip6 src address to fip64_ip6_ip4_value_t map */
  uword *ip4_ip6_hash; /* ip4 (src,dst) address to ip6 (src,dst) address map */
  fip64_uuid_t uuid; /* Midolman virtual device id */
} fip64_tenant_t;

typedef struct {
  ip4_address_t fixed;
  u32 table_id;
} fip64_ip4key_t;

/*
 * value stored in ip6_ip4_hash
 */
typedef struct {
  ip4_address_t ip4_src; // Comes from tenant pool
  u32 lru_position; // Position of this client in lru list
} fip64_ip6_ip4_value_t;

/*
 * value stored in ip4_ip6_hash
 */
typedef struct {
  ip6_address_t ip6_src; // The address of ipv6 client
  u32 lru_position; // Position of this client in lru list
} fip64_ip4_ip6_value_t;

typedef struct {
  ip6_address_t fip6;
  fip64_ip4key_t ip4;
  fip64_tenant_t *tenant;
} fip64_mapping_t;

typedef struct {
  ip6_main_t *ip6_main;
  ip4_main_t *ip4_main;
  uword *vrf_tenant_hash; /* vrf id to pool mapping */
  uword *fixed4_mapping_hash; /* fixed4/vrf to fip64 mapping */
  uword *fip6_mapping_hash; /* fip6 to fip64 mapping */
  uword *uuid_tenant_hash; /* uuid to tenant hash */
  bool testing;
} fip64_main_t;

typedef enum
{
  FIP64_SENDER,
  FIP64_RECEIVER
} fip64_dir_e;

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


/* return value < 0 if id1 is lexicographically  less than id2
 * return value > 0 if id1 is lexicographically  greater than id2
 * return value = 0 if id1 is equal to id2
 */
extern int
fip64_uuidcmp(fip64_uuid_t id1, fip64_uuid_t id2);

/* Assumes UUID in canonical form:
 *  88888888-4444-4444-4444-cccccccccccc
 */
extern u8*
fip64_format_uuid(u8 * s, va_list * args);

#endif // included_fip64_types_h
