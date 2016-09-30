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
#include "fip64.h"

typedef enum
{
  IP4_FIP64_NEXT_MAPT_TCP_UDP,
  IP4_FIP64_NEXT_MAPT_ICMP,
  IP4_FIP64_NEXT_MAPT_FRAGMENTED,
  IP4_FIP64_NEXT_DROP,
  IP4_FIP64_N_NEXT
} ip4_fip64_next_t;

static_always_inline void
ip4_fip64_classify (vlib_buffer_t * p0, ip4_header_t * ip40,
                    u16 ip4_len0, i32 * dst_port0,
                    u8 * error0, ip4_fip64_next_t * next0)
{
  /*if (PREDICT_FALSE (ip4_get_fragment_offset (ip40)))
  {
    *next0 = IP4_MAPT_NEXT_MAPT_FRAGMENTED;
  }
  else if (PREDICT_TRUE (ip40->protocol == IP_PROTOCOL_TCP))
  {
    vnet_buffer (p0)->map_t.checksum_offset = 36;
    *next0 = IP4_MAPT_NEXT_MAPT_TCP_UDP;
    *error0 = ip4_len0 < 40 ? MAP_ERROR_MALFORMED : *error0;
    *dst_port0 = (i32) * ((u16 *) u8_ptr_add (ip40, sizeof (*ip40) + 2));
  }
  else if (PREDICT_TRUE (ip40->protocol == IP_PROTOCOL_UDP))
  {
    vnet_buffer (p0)->map_t.checksum_offset = 26;
    *next0 = IP4_MAPT_NEXT_MAPT_TCP_UDP;
    *error0 = ip4_len0 < 28 ? MAP_ERROR_MALFORMED : *error0;
    *dst_port0 = (i32) * ((u16 *) u8_ptr_add (ip40, sizeof (*ip40) + 2));
  }
  else if (ip40->protocol == IP_PROTOCOL_ICMP)
  {
    *next0 = IP4_MAPT_NEXT_MAPT_ICMP;
    if (d0->ea_bits_len == 0 && d0->rules)
      *dst_port0 = 0;
    else if (((icmp46_header_t *) u8_ptr_add (ip40, sizeof (*ip40)))->code
             == ICMP4_echo_reply
             || ((icmp46_header_t *)
                 u8_ptr_add (ip40,
                             sizeof (*ip40)))->code == ICMP4_echo_request)
      *dst_port0 = (i32) * ((u16 *) u8_ptr_add (ip40, sizeof (*ip40) + 6));
  }
  else
  {
    *error0 = FIP64_ERROR_BAD_PROTOCOL;
  }*/
  *error0 = FIP64_ERROR_BAD_PROTOCOL;
}

static uword
ip4_fip64 (vlib_main_t * vm, vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  u32 n_left_from, *from, next_index, *to_next, n_left_to_next;
  vlib_node_runtime_t *error_node =
  vlib_node_get_runtime (vm, ip4_fip64_node.index);
  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;
  //vlib_combined_counter_main_t *cm = map_main.domain_counters;
  //u32 cpu_index = os_get_cpu_number ();
  
  while (n_left_from > 0)
  {
    vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);
    
    while (n_left_from > 0 && n_left_to_next > 0)
    {
      u32 pi0;
      vlib_buffer_t *p0;
      ip4_header_t *ip40;
      //map_domain_t *d0;
      ip4_fip64_next_t next0;
      u16 ip4_len0;
      u8 error0;
      i32 dst_port0;
      //ip4_mapt_pseudo_header_t *pheader0;
      
      pi0 = to_next[0] = from[0];
      from += 1;
      n_left_from -= 1;
      to_next += 1;
      n_left_to_next -= 1;
      error0 = FIP64_ERROR_NONE;
      
      p0 = vlib_get_buffer (vm, pi0);
      ip40 = vlib_buffer_get_current (p0);
      ip4_len0 = clib_host_to_net_u16 (ip40->length);
      if (PREDICT_FALSE (p0->current_length < ip4_len0 ||
                         ip40->ip_version_and_header_length != 0x45))
      {
        error0 = FIP64_ERROR_UNKNOWN;
        next0 = IP4_FIP64_NEXT_DROP;
      }
      
      //vnet_buffer (p0)->
      
      //d0 = ip4_map_get_domain (vnet_buffer (p0)->ip.adj_index[VLIB_TX],
      //                         &vnet_buffer (p0)->map_t.map_domain_index);
      
      //vnet_buffer (p0)->map_t.mtu = d0->mtu ? d0->mtu : ~0;
      
      dst_port0 = -1;
      ip4_fip64_classify (p0, ip40, ip4_len0, &dst_port0, &error0, &next0);
      
      //Add MAP-T pseudo header in front of the packet
      //vlib_buffer_advance (p0, -sizeof (*pheader0));
      //pheader0 = vlib_buffer_get_current (p0);
      
      //Save addresses within the packet
      //ip4_map_t_embedded_address (d0, &pheader0->saddr,
      //                            &ip40->src_address);
      //pheader0->daddr.as_u64[0] =
      //map_get_pfx_net (d0, ip40->dst_address.as_u32, (u16) dst_port0);
      //pheader0->daddr.as_u64[1] =
      //map_get_sfx_net (d0, ip40->dst_address.as_u32, (u16) dst_port0);
      
      //It is important to cache at this stage because the result might be necessary
      //for packets within the same vector.
      //Actually, this approach even provides some limited out-of-order fragments support
      /*
      if (PREDICT_FALSE
          (ip4_is_first_fragment (ip40) && (dst_port0 != -1)
           && (d0->ea_bits_len != 0 || !d0->rules)
           && ip4_map_fragment_cache (ip40, dst_port0)))
      {
        error0 = MAP_ERROR_UNKNOWN;
      }
      
      if (PREDICT_TRUE
          (error0 == MAP_ERROR_NONE && next0 != IP4_MAPT_NEXT_MAPT_ICMP))
      {
        vlib_increment_combined_counter (cm + MAP_DOMAIN_COUNTER_TX,
                                         cpu_index,
                                         vnet_buffer (p0)->map_t.
                                         map_domain_index, 1,
                                         clib_net_to_host_u16 (ip40->
                                                               length));
      }*/
      
      next0 = (error0 != FIP64_ERROR_NONE) ? IP4_FIP64_NEXT_DROP : next0;
      p0->error = error_node->errors[error0];
      vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
                                       to_next, n_left_to_next, pi0,
                                       next0);
    }
    vlib_put_next_frame (vm, node, next_index, n_left_to_next);
  }
  return frame->n_vectors;
}

static char *fip64_error_strings[] = {
#define _(sym,string) string,
  foreach_fip64_error
#undef _
};

/* *INDENT-OFF* */
VLIB_REGISTER_NODE(ip4_fip64_node) = {
  .function = ip4_fip64,
  .name = "ip4-fip64",
  .vector_size = sizeof(u32),
  .format_trace = format_fip64_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  
  .n_errors = FIP64_N_ERROR,
  .error_strings = fip64_error_strings,
  
  .n_next_nodes = IP4_FIP64_N_NEXT,
  .next_nodes = {
    [IP4_FIP64_NEXT_MAPT_TCP_UDP] = "ip4-map-t-tcp-udp",
    [IP4_FIP64_NEXT_MAPT_ICMP] = "ip4-map-t-icmp",
    [IP4_FIP64_NEXT_MAPT_FRAGMENTED] = "ip4-map-t-fragmented",
    [IP4_FIP64_NEXT_DROP] = "error-drop",
  },
};
/* *INDENT-ON* */
