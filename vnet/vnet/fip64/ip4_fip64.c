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

#define IP6_DST_ADDRESS_HI 0x2001000000000000L
#define IP6_DST_ADDRESS_LO 1L

#define IP6_SRC_ADDRESS_HI 0x200F000000000000L
#define IP6_SRC_ADDRESS_LO 1L

#define frag_id_4to6(id) (id)

typedef enum
{
  IP4_FIP64_NEXT_FIP64_ICMP,
  IP4_FIP64_NEXT_FIP64_TCP_UDP,
  IP4_FIP64_NEXT_DROP,
  IP4_FIP64_N_NEXT
} ip4_fip64_next_t;

typedef enum
{
  IP4_FIP64_ICMP_NEXT_IP6_LOOKUP,
  IP4_FIP64_ICMP_NEXT_DROP,
  IP4_FIP64_ICMP_N_NEXT
} ip4_fip64_icmp_next_t;

typedef enum
{
  IP4_FIP64_TCP_UDP_NEXT_IP6_LOOKUP,
  IP4_FIP64_TCP_UDP_NEXT_DROP,
  IP4_FIP64_TCP_UDP_N_NEXT
} ip4_fip64_tcp_udp_next_t;


//TODO: Find the right place in memory for this.
/* *INDENT-OFF* */
static u8 icmp_to_icmp6_updater_pointer_table[] =
{ 0, 1, 4, 4, ~0,
  ~0, ~0, ~0, 7, 6,
  ~0, ~0, 8, 8, 8,
  8, 24, 24, 24, 24
};
/* *INDENT-ON* */

static i32
ip4_get_port (ip4_header_t * ip, fip64_dir_e dir, u16 buffer_len)
{
  //TODO: use buffer length
  if (ip->ip_version_and_header_length != 0x45 ||
      ip4_get_fragment_offset (ip))
    return -1;

  if (PREDICT_TRUE ((ip->protocol == IP_PROTOCOL_TCP) ||
                    (ip->protocol == IP_PROTOCOL_UDP)))
  {
    udp_header_t *udp = (void *) (ip + 1);
    return (dir == FIP64_SENDER) ? udp->src_port : udp->dst_port;
  }
  else if (ip->protocol == IP_PROTOCOL_ICMP)
  {
    icmp46_header_t *icmp = (void *) (ip + 1);
    if (icmp->type == ICMP4_echo_request || icmp->type == ICMP4_echo_reply)
    {
      return *((u16 *) (icmp + 1));
    }
    else if (clib_net_to_host_u16 (ip->length) >= 64)
    {
      ip = (ip4_header_t *) (icmp + 2);
      if (PREDICT_TRUE ((ip->protocol == IP_PROTOCOL_TCP) ||
                        (ip->protocol == IP_PROTOCOL_UDP)))
      {
        udp_header_t *udp = (void *) (ip + 1);
        return (dir == FIP64_SENDER) ? udp->dst_port : udp->src_port;
      }
      else if (ip->protocol == IP_PROTOCOL_ICMP)
      {
        icmp46_header_t *icmp = (void *) (ip + 1);
        if (icmp->type == ICMP4_echo_request ||
            icmp->type == ICMP4_echo_reply)
        {
          return *((u16 *) (icmp + 1));
        }
      }
    }
  }
  return -1;
}

/* 
 * Statelessly translates an ICMP packet into ICMPv6.
 *
 * Warning: The checksum will need to be recomputed.
 */
static_always_inline int
ip4_icmp_to_icmp6_in_place (icmp46_header_t * icmp, u32 icmp_len,
                            i32 * receiver_port, ip4_header_t ** inner_ip4)
{
  *inner_ip4 = NULL;
  switch (icmp->type)
  {
    case ICMP4_echo_reply:
      *receiver_port = ((u16 *) icmp)[2];
      icmp->type = ICMP6_echo_reply;
      break;
    case ICMP4_echo_request:
      *receiver_port = ((u16 *) icmp)[2];
      icmp->type = ICMP6_echo_request;
      break;
    case ICMP4_destination_unreachable:
      *inner_ip4 = (ip4_header_t *) (((u8 *) icmp) + 8);
      *receiver_port = ip4_get_port (*inner_ip4, FIP64_SENDER, icmp_len - 8);

      switch (icmp->code)
      {
      case ICMP4_destination_unreachable_destination_unreachable_net: //0
      case ICMP4_destination_unreachable_destination_unreachable_host: //1
        icmp->type = ICMP6_destination_unreachable;
        icmp->code = ICMP6_destination_unreachable_no_route_to_destination;
        break;
      case ICMP4_destination_unreachable_protocol_unreachable: //2
        icmp->type = ICMP6_parameter_problem;
        icmp->code = ICMP6_parameter_problem_unrecognized_next_header;
        break;
      case ICMP4_destination_unreachable_port_unreachable: //3
        icmp->type = ICMP6_destination_unreachable;
        icmp->code = ICMP6_destination_unreachable_port_unreachable;
        break;
      case ICMP4_destination_unreachable_fragmentation_needed_and_dont_fragment_set: //4
        icmp->type =
        ICMP6_packet_too_big;
        icmp->code = 0;
        {
        u32 advertised_mtu = clib_net_to_host_u32 (*((u32 *) (icmp + 1)));
        if (advertised_mtu)
          advertised_mtu += 20;
        else
          advertised_mtu = 1000; //FIXME ! (RFC 1191 - plateau value)

        //FIXME: = minimum(advertised MTU+20, MTU_of_IPv6_nexthop, (MTU_of_IPv4_nexthop)+20)
        *((u32 *) (icmp + 1)) = clib_host_to_net_u32 (advertised_mtu);
        }
        break;

      case ICMP4_destination_unreachable_source_route_failed: //5
      case ICMP4_destination_unreachable_destination_network_unknown: //6
      case ICMP4_destination_unreachable_destination_host_unknown: //7
      case ICMP4_destination_unreachable_source_host_isolated: //8
      case ICMP4_destination_unreachable_network_unreachable_for_type_of_service: //11
      case ICMP4_destination_unreachable_host_unreachable_for_type_of_service: //12
        icmp->type =
        ICMP6_destination_unreachable;
        icmp->code = ICMP6_destination_unreachable_no_route_to_destination;
        break;
      case ICMP4_destination_unreachable_network_administratively_prohibited: //9
      case ICMP4_destination_unreachable_host_administratively_prohibited: //10
      case ICMP4_destination_unreachable_communication_administratively_prohibited: //13
      case ICMP4_destination_unreachable_precedence_cutoff_in_effect: //15
        icmp->type = ICMP6_destination_unreachable;
        icmp->code =
        ICMP6_destination_unreachable_destination_administratively_prohibited;
        break;
      case ICMP4_destination_unreachable_host_precedence_violation: //14
      default:
        return -1;
      }
      break;

    case ICMP4_time_exceeded: //11
      *inner_ip4 = (ip4_header_t *) (((u8 *) icmp) + 8);
      *receiver_port = ip4_get_port (*inner_ip4, FIP64_SENDER, icmp_len - 8);
      icmp->type = ICMP6_time_exceeded;
      //icmp->code = icmp->code //unchanged
      break;

    case ICMP4_parameter_problem:
      *inner_ip4 = (ip4_header_t *) (((u8 *) icmp) + 8);
      *receiver_port = ip4_get_port (*inner_ip4, FIP64_SENDER, icmp_len - 8);

      switch (icmp->code)
      {
      case ICMP4_parameter_problem_pointer_indicates_error:
      case ICMP4_parameter_problem_bad_length:
        icmp->type = ICMP6_parameter_problem;
        icmp->code = ICMP6_parameter_problem_erroneous_header_field;
        {
          u8 ptr =
            icmp_to_icmp6_updater_pointer_table[*((u8 *) (icmp + 1))];
          if (ptr == 0xff)
            return -1;
        
          *((u32 *) (icmp + 1)) = clib_host_to_net_u32 (ptr);
        }
        break;
      default:
        //All other codes cause dropping the packet
        return -1;
      }
      break;
    default:
      //All other types cause dropping the packet
      return -1;
      break;
  }
  return 0;
}

static_always_inline void
_ip4_fip64_icmp (vlib_buffer_t * p, u8 * error)
{
  ip4_header_t *ip4, *inner_ip4;
  ip6_header_t *ip6;
  u32 ip_len;
  icmp46_header_t *icmp;
  i32 recv_port;
  ip_csum_t csum;

  // skip hidden v6 addresses
  ip4_mapt_pseudo_header_t *pheader = vlib_buffer_get_current (p);
  vlib_buffer_advance (p, sizeof (*pheader));

  ip4 = vlib_buffer_get_current (p);
  ip_len = clib_net_to_host_u16 (ip4->length);
  ASSERT (ip_len <= p->current_length);

  icmp = (icmp46_header_t *) (ip4 + 1);
  if (ip4_icmp_to_icmp6_in_place (icmp, ip_len - sizeof (*ip4),
                                  &recv_port, &inner_ip4))
  {
    *error = FIP64_ERROR_ICMP;
    return;
  }

  vlib_buffer_advance (p, sizeof (*ip4) - sizeof (*ip6));
  ip6 = vlib_buffer_get_current (p);
  ip6->payload_length =
    clib_host_to_net_u16 (clib_net_to_host_u16 (ip4->length) -
                          sizeof (*ip4));

  //Translate outer IPv6
  ip6->ip_version_traffic_class_and_flow_label =
  clib_host_to_net_u32 ((6 << 28) + (ip4->tos << 20));

  ip6->hop_limit = ip4->ttl;
  ip6->protocol = IP_PROTOCOL_ICMP6;

  ip6->src_address = pheader->saddr;
  ip6->dst_address = pheader->daddr;

  //Truncate when the packet exceeds the minimal IPv6 MTU
  if (p->current_length > 1280)
  {
    ip6->payload_length = clib_host_to_net_u16 (1280 - sizeof (*ip6));
    p->current_length = 1280;  //Looks too simple to be correct...
  }

  //TODO: We could do an easy diff-checksum for echo requests/replies
  //Recompute ICMP checksum
  icmp->checksum = 0;
  csum = ip_csum_with_carry (0, ip6->payload_length);
  csum = ip_csum_with_carry (csum, clib_host_to_net_u16 (ip6->protocol));
  csum = ip_csum_with_carry (csum, ip6->src_address.as_u64[0]);
  csum = ip_csum_with_carry (csum, ip6->src_address.as_u64[1]);
  csum = ip_csum_with_carry (csum, ip6->dst_address.as_u64[0]);
  csum = ip_csum_with_carry (csum, ip6->dst_address.as_u64[1]);
  csum =
  ip_incremental_checksum (csum, icmp,
                           clib_net_to_host_u16 (ip6->payload_length));
  icmp->checksum = ~ip_csum_fold (csum);
}

static uword
ip4_fip64_icmp (vlib_main_t * vm,
                vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  u32 n_left_from, *from, next_index, *to_next, n_left_to_next;
  vlib_node_runtime_t *error_node =
  vlib_node_get_runtime (vm, ip4_fip64_icmp_node.index);
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
      ip4_fip64_icmp_next_t next0;
      u8 error0;

      next0 = IP4_FIP64_ICMP_NEXT_IP6_LOOKUP;
      pi0 = to_next[0] = from[0];
      from += 1;
      n_left_from -= 1;
      to_next += 1;
      n_left_to_next -= 1;
      error0 = FIP64_ERROR_NONE;

      p0 = vlib_get_buffer (vm, pi0);
      _ip4_fip64_icmp (p0, &error0);

      if (PREDICT_FALSE (error0 != FIP64_ERROR_NONE))
      {
        next0 = IP4_FIP64_ICMP_NEXT_DROP;
      }
      p0->error = error_node->errors[error0];
      vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
                                       to_next, n_left_to_next, pi0,
                                       next0);
    }
    vlib_put_next_frame (vm, node, next_index, n_left_to_next);
  }
  return frame->n_vectors;
}

static uword
ip4_fip64_tcp_udp (vlib_main_t * vm,
                   vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  u32 n_left_from, *from, next_index, *to_next, n_left_to_next;
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
      ip4_header_t *ip40;
      ip6_header_t *ip60;
      ip_csum_t csum0;
      u16 *checksum0;
      ip6_frag_hdr_t *frag0;
      u32 frag_id0;
      ip4_fip64_tcp_udp_next_t next0;

      pi0 = to_next[0] = from[0];
      from += 1;
      n_left_from -= 1;
      to_next += 1;
      n_left_to_next -= 1;

      next0 = IP4_FIP64_TCP_UDP_NEXT_IP6_LOOKUP;
      p0 = vlib_get_buffer (vm, pi0);

      ip4_mapt_pseudo_header_t *pheader = vlib_buffer_get_current (p0);
      vlib_buffer_advance (p0, sizeof (*pheader));

      //Accessing ip4 header
      ip40 = vlib_buffer_get_current (p0);
      checksum0 = (u16 *) u8_ptr_add (ip40,
                                      vnet_buffer (p0)->fip64.checksum_offset);

      //UDP checksum is optional over IPv4 but mandatory for IPv6
      //We do not check udp->length sanity but use our safe computed value instead
      if (PREDICT_FALSE (!*checksum0 && ip40->protocol == IP_PROTOCOL_UDP))
      {
        u16 udp_len = clib_host_to_net_u16 (ip40->length) - sizeof (*ip40);
        udp_header_t *udp = (udp_header_t *) u8_ptr_add (ip40, sizeof (*ip40));
        ip_csum_t csum;
        csum = ip_incremental_checksum (0, udp, udp_len);
        csum = ip_csum_with_carry (csum, clib_host_to_net_u16 (udp_len));
        csum = ip_csum_with_carry (csum,
                                   clib_host_to_net_u16 (IP_PROTOCOL_UDP));
        csum = ip_csum_with_carry (csum, *((u64 *) (&ip40->src_address)));
        *checksum0 = ~ip_csum_fold (csum);
      }

      csum0 = ip_csum_sub_even (*checksum0, ip40->src_address.as_u32);
      csum0 = ip_csum_sub_even (csum0, ip40->dst_address.as_u32);

      // Deal with fragmented packets
      if (PREDICT_FALSE (ip40->flags_and_fragment_offset &
                         clib_host_to_net_u16
                         (IP4_HEADER_FLAG_MORE_FRAGMENTS)))
      {
        ip60 = (ip6_header_t *) u8_ptr_add (ip40,
                                            sizeof (*ip40) - sizeof (*ip60) -
                                            sizeof (*frag0));
        frag0 = (ip6_frag_hdr_t *) u8_ptr_add (ip40,
                                               sizeof (*ip40) -
                                               sizeof (*frag0));
        frag_id0 = frag_id_4to6 (ip40->fragment_id);
        vlib_buffer_advance (p0,
                             sizeof (*ip40) - sizeof (*ip60) - sizeof (*frag0));
      }
      else
      {
        ip60 =
        (ip6_header_t *) (((u8 *) ip40) + sizeof (*ip40) -
                          sizeof (*ip60));
        vlib_buffer_advance (p0, sizeof (*ip40) - sizeof (*ip60));
        frag0 = NULL;
      }

      ip60->ip_version_traffic_class_and_flow_label =
      clib_host_to_net_u32 ((6 << 28) + (ip40->tos << 20));
      ip60->payload_length = u16_net_add (ip40->length, -sizeof (*ip40));
      ip60->hop_limit = ip40->ttl;
      ip60->protocol = ip40->protocol;
      
      if (PREDICT_FALSE (frag0 != NULL))
      {
        frag0->next_hdr = ip60->protocol;
        frag0->identification = frag_id0;
        frag0->rsv = 0;
        frag0->fragment_offset_and_more =
          ip6_frag_hdr_offset_and_more (0, 1);
        ip60->protocol = IP_PROTOCOL_IPV6_FRAGMENTATION;
        ip60->payload_length =
          u16_net_add (ip60->payload_length, sizeof (*frag0));
      }
      
      //Finally copying the address
      ip60->src_address = pheader->saddr;
      ip60->dst_address = pheader->daddr;
      
      csum0 = ip_csum_add_even (csum0, ip60->src_address.as_u64[0]);
      csum0 = ip_csum_add_even (csum0, ip60->src_address.as_u64[1]);
      csum0 = ip_csum_add_even (csum0, ip60->dst_address.as_u64[0]);
      csum0 = ip_csum_add_even (csum0, ip60->dst_address.as_u64[1]);
      *checksum0 = ip_csum_fold (csum0);
      
      vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
                                       to_next, n_left_to_next, pi0,
                                       next0);
    }
    vlib_put_next_frame (vm, node, next_index, n_left_to_next);
  }
  
  return frame->n_vectors;
}

static_always_inline void
ip4_fip64_classify (vlib_buffer_t * p0, ip4_header_t * ip40,
                    u16 ip4_len0, i32 * dst_port0,
                    u8 * error0, ip4_fip64_next_t * next0)
{
  if (PREDICT_TRUE (ip40->protocol == IP_PROTOCOL_TCP))
  {
    vnet_buffer (p0)->fip64.checksum_offset = 36;
    *next0 = IP4_FIP64_NEXT_FIP64_TCP_UDP;
    *error0 = ip4_len0 < 40 ? FIP64_ERROR_MALFORMED : *error0;
    *dst_port0 = (i32) * ((u16 *) u8_ptr_add (ip40, sizeof (*ip40) + 2));
  }
  else if (PREDICT_TRUE (ip40->protocol == IP_PROTOCOL_UDP))
  {
    vnet_buffer (p0)->fip64.checksum_offset = 26;
    *next0 = IP4_FIP64_NEXT_FIP64_TCP_UDP;
    *error0 = ip4_len0 < 28 ? FIP64_ERROR_MALFORMED : *error0;
    *dst_port0 = (i32) * ((u16 *) u8_ptr_add (ip40, sizeof (*ip40) + 2));
  }
  else if (ip40->protocol == IP_PROTOCOL_ICMP)
  {
    *next0 = IP4_FIP64_NEXT_FIP64_ICMP;
  }
  else
  {
    *error0 = FIP64_ERROR_BAD_PROTOCOL;
  }
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

  while (n_left_from > 0)
  {
    vlib_get_next_frame (vm, node, next_index, to_next, n_left_to_next);

    while (n_left_from > 0 && n_left_to_next > 0)
    {
      u32 pi0;
      vlib_buffer_t *p0;
      ip4_header_t *ip40;
      ip4_fip64_next_t next0;
      u16 ip4_len0;
      u8 error0;
      i32 dst_port0;
      fip64_ip4_t ip4key;
      bool        lookup_success = false;

      pi0 = to_next[0] = from[0];
      from += 1;
      n_left_from -= 1;
      to_next += 1;
      n_left_to_next -= 1;
      error0 = FIP64_ERROR_NONE;

      p0 = vlib_get_buffer (vm, pi0);

      ip40 = vlib_buffer_get_current (p0);
      ip4_len0 = clib_host_to_net_u16 (ip40->length);
      if (PREDICT_FALSE (p0->current_length < ip4_len0
                      || ip40->ip_version_and_header_length != 0x45))
      {
        error0 = FIP64_ERROR_UNKNOWN;
        next0 = IP4_FIP64_NEXT_DROP;
      }
      // Send src and dst ip6 address to next nodes
      // MITODO: Why we always can write to this memory?
      vlib_buffer_advance (p0, -sizeof (ip4_mapt_pseudo_header_t));
      ip4_mapt_pseudo_header_t *pheader0 = vlib_buffer_get_current(p0);

      // Inverse order, since the key is defined by v6->v4 mapping
      ip4key.dst = ip40->src_address;
      ip4key.src = ip40->dst_address;

      // Get VRF of the transmitting interface
      u32 src_sw_if_index = vnet_buffer (p0)->sw_if_index[VLIB_RX];
      u32 fib_index = vec_elt (ip4_main.fib_index_by_sw_if_index, src_sw_if_index);
      ip4_fib_t * fib = vec_elt_at_index (ip4_main.fibs, fib_index);
      ip4key.table_id = fib->table_id;

      // Force ip6_lookup to look VRF 0
      vnet_buffer (p0)->sw_if_index[VLIB_TX] = 0;
      lookup_success = fip64_lookup_ip4_to_ip6(&ip4key, &pheader0->daddr,
                                               &pheader0->saddr);
      if (!lookup_success)
      {
        error0 = FIP64_ERROR_NO46MAP;
        next0 = IP4_FIP64_NEXT_DROP;
      }
      if (PREDICT_FALSE ( (p0->flags & VLIB_BUFFER_IS_TRACED) ) )
      {
        fip64_trace_t *trace = vlib_add_trace(vm, node, p0, sizeof(*trace));
        trace->op = IP4_FIP64_TRACE;
        trace->ip6.src_address = pheader0->saddr;
        trace->ip6.dst_address = pheader0->daddr;
        trace->ip4.src_address = ip40->src_address;
        trace->ip4.dst_address = ip40->dst_address;
        trace->ip4.table_id = ip4key.table_id;
      }
      dst_port0 = -1;
      ip4_fip64_classify (p0, ip40, ip4_len0, &dst_port0, &error0, &next0);

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
VLIB_REGISTER_NODE(ip4_fip64_tcp_udp_node) = {
  .function = ip4_fip64_tcp_udp,
  .name = "ip4-fip64-tcp-udp",
  .vector_size = sizeof(u32),
  .format_trace = format_fip64_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = FIP64_N_ERROR,
  .error_strings = fip64_error_strings,

  .n_next_nodes = IP4_FIP64_TCP_UDP_N_NEXT,
  .next_nodes = {
    [IP4_FIP64_TCP_UDP_NEXT_IP6_LOOKUP] = "ip6-lookup",
    [IP4_FIP64_TCP_UDP_NEXT_DROP] = "error-drop",
  },
};
/* *INDENT-ON* */

/* *INDENT-OFF* */
VLIB_REGISTER_NODE(ip4_fip64_icmp_node) = {
  .function = ip4_fip64_icmp,
  .name = "ip4-fip64-icmp",
  .vector_size = sizeof(u32),
  .format_trace = format_fip64_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,
  
  .n_errors = FIP64_N_ERROR,
  .error_strings = fip64_error_strings,
  
  .n_next_nodes = IP4_FIP64_ICMP_N_NEXT,
  .next_nodes = {
    [IP4_FIP64_ICMP_NEXT_IP6_LOOKUP] = "ip6-lookup",
    [IP4_FIP64_ICMP_NEXT_DROP] = "error-drop",
  },
};
/* *INDENT-ON* */

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
    [IP4_FIP64_NEXT_FIP64_ICMP] = "ip4-fip64-icmp",
    [IP4_FIP64_NEXT_FIP64_TCP_UDP] = "ip4-fip64-tcp-udp",
    [IP4_FIP64_NEXT_DROP] = "error-drop",
  },
};
/* *INDENT-ON* */
