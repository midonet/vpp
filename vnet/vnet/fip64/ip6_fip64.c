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

/*
static uword
ip6_map_t (vlib_main_t * vm, vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  u32 n_left_from, *from, next_index, *to_next, n_left_to_next;
  vlib_node_runtime_t *error_node =
  vlib_node_get_runtime (vm, ip6_map_t_node.index);
  vlib_combined_counter_main_t *cm = map_main.domain_counters;
  u32 cpu_index = os_get_cpu_number ();
  
  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;
  next_index = node->cached_next_index;
  while (n_left_from > 0)
  {
    vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);
    
    while (n_left_from > 0 && n_left_to_next > 0)
    {
      u32 pi0;
      vlib_buffer_t *p0;
      ip6_header_t *ip60;
      u8 error0;
      u32 l4_len0;
      i32 src_port0;
      map_domain_t *d0;
      ip6_frag_hdr_t *frag0;
      ip6_mapt_next_t next0 = 0;
      u32 saddr;
      
      pi0 = to_next[0] = from[0];
      from += 1;
      n_left_from -= 1;
      to_next += 1;
      n_left_to_next -= 1;
      error0 = MAP_ERROR_NONE;
      
      p0 = vlib_get_buffer (vm, pi0);
      ip60 = vlib_buffer_get_current (p0);
      //Save saddr in a different variable to not overwrite ip.adj_index
      saddr = map_get_ip4 (&ip60->src_address);
      d0 = ip6_map_get_domain (vnet_buffer (p0)->ip.adj_index[VLIB_TX],
                               (ip4_address_t *) & saddr,
                               &vnet_buffer (p0)->map_t.map_domain_index,
                               &error0);
      
      //FIXME: What if d0 is null
      vnet_buffer (p0)->map_t.v6.saddr = saddr;
      vnet_buffer (p0)->map_t.v6.daddr =
      ip6_map_t_embedded_address (d0, &ip60->dst_address);
      vnet_buffer (p0)->map_t.mtu = d0->mtu ? d0->mtu : ~0;
      
      if (PREDICT_FALSE (ip6_parse (ip60, p0->current_length,
                                    &(vnet_buffer (p0)->map_t.
                                      v6.l4_protocol),
                                    &(vnet_buffer (p0)->map_t.
                                      v6.l4_offset),
                                    &(vnet_buffer (p0)->map_t.
                                      v6.frag_offset))))
      {
        error0 = MAP_ERROR_MALFORMED;
        next0 = IP6_MAPT_NEXT_DROP;
      }
      
      src_port0 = -1;
      l4_len0 = (u32) clib_net_to_host_u16 (ip60->payload_length) +
      sizeof (*ip60) - vnet_buffer (p0)->map_t.v6.l4_offset;
      frag0 =
      (ip6_frag_hdr_t *) u8_ptr_add (ip60,
                                     vnet_buffer (p0)->map_t.
                                     v6.frag_offset);
      
      
      if (PREDICT_FALSE (vnet_buffer (p0)->map_t.v6.frag_offset &&
                         ip6_frag_hdr_offset (frag0)))
      {
        src_port0 = ip6_map_fragment_get (ip60, frag0, d0);
        error0 = (src_port0 != -1) ? error0 : MAP_ERROR_FRAGMENT_MEMORY;
        next0 = IP6_MAPT_NEXT_MAPT_FRAGMENTED;
      }
      else
        if (PREDICT_TRUE
            (vnet_buffer (p0)->map_t.v6.l4_protocol == IP_PROTOCOL_TCP))
        {
          error0 =
          l4_len0 <
          sizeof (tcp_header_t) ? MAP_ERROR_MALFORMED : error0;
          vnet_buffer (p0)->map_t.checksum_offset =
          vnet_buffer (p0)->map_t.v6.l4_offset + 16;
          next0 = IP6_MAPT_NEXT_MAPT_TCP_UDP;
          src_port0 =
          (i32) *
          ((u16 *)
           u8_ptr_add (ip60, vnet_buffer (p0)->map_t.v6.l4_offset));
        }
        else
          if (PREDICT_TRUE
              (vnet_buffer (p0)->map_t.v6.l4_protocol == IP_PROTOCOL_UDP))
          {
            error0 =
            l4_len0 <
            sizeof (udp_header_t) ? MAP_ERROR_MALFORMED : error0;
            vnet_buffer (p0)->map_t.checksum_offset =
            vnet_buffer (p0)->map_t.v6.l4_offset + 6;
            next0 = IP6_MAPT_NEXT_MAPT_TCP_UDP;
            src_port0 =
            (i32) *
            ((u16 *)
             u8_ptr_add (ip60, vnet_buffer (p0)->map_t.v6.l4_offset));
          }
          else if (vnet_buffer (p0)->map_t.v6.l4_protocol ==
                   IP_PROTOCOL_ICMP6)
          {
            error0 =
            l4_len0 <
            sizeof (icmp46_header_t) ? MAP_ERROR_MALFORMED : error0;
            next0 = IP6_MAPT_NEXT_MAPT_ICMP;
            if (((icmp46_header_t *)
                 u8_ptr_add (ip60,
                             vnet_buffer (p0)->map_t.v6.l4_offset))->code ==
                ICMP6_echo_reply
                || ((icmp46_header_t *)
                    u8_ptr_add (ip60,
                                vnet_buffer (p0)->map_t.v6.
                                l4_offset))->code == ICMP6_echo_request)
              src_port0 =
              (i32) *
              ((u16 *)
               u8_ptr_add (ip60,
                           vnet_buffer (p0)->map_t.v6.l4_offset + 6));
          }
          else
          {
            //TODO: In case of 1:1 mapping, it might be possible to do something with those packets.
            error0 = MAP_ERROR_BAD_PROTOCOL;
          }
      
      //Security check
      if (PREDICT_FALSE
          ((src_port0 != -1)
           && (ip60->src_address.as_u64[0] !=
               map_get_pfx_net (d0, vnet_buffer (p0)->map_t.v6.saddr,
                                src_port0)
               || ip60->src_address.as_u64[1] != map_get_sfx_net (d0,
                                                                  vnet_buffer
                                                                  (p0)->map_t.v6.saddr,
                                                                  src_port0))))
      {
        //Security check when src_port0 is not zero (non-first fragment, UDP or TCP)
        error0 = MAP_ERROR_SEC_CHECK;
      }
      
      //Fragmented first packet needs to be cached for following packets
      if (PREDICT_FALSE (vnet_buffer (p0)->map_t.v6.frag_offset &&
                         !ip6_frag_hdr_offset ((ip6_frag_hdr_t *)
                                               u8_ptr_add (ip60,
                                                           vnet_buffer
                                                           (p0)->map_t.
                                                           v6.frag_offset)))
          && (src_port0 != -1) && (d0->ea_bits_len != 0 || !d0->rules)
          && (error0 == MAP_ERROR_NONE))
      {
        ip6_map_fragment_cache (ip60,
                                (ip6_frag_hdr_t *) u8_ptr_add (ip60,
                                                               vnet_buffer
                                                               (p0)->map_t.
                                                               v6.frag_offset),
                                d0, src_port0);
      }
      
      if (PREDICT_TRUE
          (error0 == MAP_ERROR_NONE && next0 != IP6_MAPT_NEXT_MAPT_ICMP))
      {
        vlib_increment_combined_counter (cm + MAP_DOMAIN_COUNTER_RX,
                                         cpu_index,
                                         vnet_buffer (p0)->
                                         map_t.map_domain_index, 1,
                                         clib_net_to_host_u16
                                         (ip60->payload_length));
      }
      
      next0 = (error0 != MAP_ERROR_NONE) ? IP6_MAPT_NEXT_DROP : next0;
      p0->error = error_node->errors[error0];
      vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
                                       to_next, n_left_to_next, pi0,
                                       next0);
    }
    vlib_put_next_frame (vm, node, next_index, n_left_to_next);
  }
  return frame->n_vectors;
}*/


/* *INDENT-OFF* */
/*VLIB_REGISTER_NODE(ip6_map_t_node) = {
    .function = ip6_fip64_t,
    .name = "ip6-fip64-t",
    .vector_size = sizeof(u32),
    .format_trace = format_fip64_trace,
    .type = VLIB_NODE_TYPE_INTERNAL,
  
    .n_errors = FIP64_N_ERROR,
    .error_strings = fip64_t_error_strings,
  
    .n_next_nodes = IP6_FIP64_N_NEXT,
    .next_nodes = {
        [IP6_MAPT_NEXT_MAPT_TCP_UDP] = "ip6-map-t-tcp-udp",
        [IP6_MAPT_NEXT_MAPT_ICMP] = "ip6-map-t-icmp",
        [IP6_MAPT_NEXT_MAPT_FRAGMENTED] = "ip6-map-t-fragmented",
        [IP6_MAPT_NEXT_DROP] = "error-drop",
    },
};*/
/* *INDENT-ON* */
