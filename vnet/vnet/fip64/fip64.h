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

typedef struct {
  ip6_address_t src;
  ip6_address_t dst;
} fip64_ip6_t;

typedef struct {
  ip4_address_t src;
  ip4_address_t dst;
} fip64_ip4_t;

typedef struct {
  uword *ip6_ip4_hash; /* ip6 (src,dst) address to ip4 (src,dst) address map */
  uword *ip4_ip6_hash; /* ip4 (src,dst) address to ip6 (src,dst) address map */
  // TODO: add maps for ref counting adjacencies added for dst_ip6 and src_ip4
} fip64_main_t;

typedef enum
{
  FIP64_SENDER,
  FIP64_RECEIVER
} fip64_dir_e;

/**
 * Lookup IP4 (src,dst) addresses for a given IP6 (src,dst) addresses.
 *
 * The output parameters should be valid memory regions where this function
 * will write the results.
 *
 * @param[in] ip6_src Reference to the source IP6 address.
 * @param[in] ip6_dst Reference to the destination IP6 address.
 * @param[out] ip4_src Pointer where to copy the source IP4 address.
 * @param[out] ip4_dst Pointer where to copy the destination IP4 address.
 */
extern bool
fip64_lookup_ip6_to_ip4(ip6_address_t * ip6_src, ip6_address_t * ip6_dst,
                        ip4_address_t * ip4_src, ip4_address_t * ip4_dst);

/**
 * Lookup IP6 (src,dst) addresses for a given IP4 (src,dst) addresses.
 *
 * The output parameters should be valid memory regions where this function
 * will write the results.
 *
 * @param[in] ip4_src Reference to the source IP4 address.
 * @param[in] ip4_dst Reference to the destination IP4 address.
 * @param[out] ip6_src Pointer where to copy the source IP6 address.
 * @param[out] ip6_dst Pointer where to copy the destination IP6 address.
 */
extern bool
fip64_lookup_ip4_to_ip6(ip4_address_t * ip4_src, ip4_address_t * ip4_dst,
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
_(FRAGMENT_MEMORY, "could not cache fragment")	        \
_(FRAGMENT_MALFORMED, "fragment has unexpected format") \
_(FRAGMENT_DROPPED, "dropped cached fragment")          \
_(MALFORMED, "malformed packet")                        \
_(DF_SET, "can't fragment, DF set")

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
  struct {
    ip4_address_t src_address,
                  dst_address;
  } ip4;

  struct {
    ip6_address_t src_address,
                  dst_address;
  } ip6;
} fip64_trace_t;

u8 *format_fip64_trace (u8 * s, va_list * args);

extern vlib_node_registration_t ip4_fip64_node;
extern vlib_node_registration_t ip4_fip64_icmp_node;
extern vlib_node_registration_t ip4_fip64_tcp_udp_node;

extern vlib_node_registration_t ip6_fip64_node;
extern vlib_node_registration_t ip6_fip64_icmp_node;
