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

#define u8_ptr_add(ptr, index) (((u8 *)ptr) + index)
#define frag_id_6to4(id) ((id) ^ ((id) >> 16))
#define u16_net_add(u, val) clib_host_to_net_u16(clib_net_to_host_u16(u) + (val))

extern fip64_main_t _fip64_main;

typedef enum
{
  IP6_FIP64_NEXT_MAPT_TCP_UDP,
  IP6_FIP64_NEXT_MAPT_ICMP,
  IP6_FIP64_NEXT_MAPT_FRAGMENTED,
  IP6_FIP64_NEXT_DROP,
  IP6_FIP64_N_NEXT
} fip64_ip6_next_t;

typedef enum
{
  IP6_FIP64_ICMP_NEXT_IP4_LOOKUP,
  // MIDOTODO: removed -- IP6_FIP64_ICMP_NEXT_IP4_FRAG,
  IP6_FIP64_ICMP_NEXT_DROP,
  IP6_FIP64_ICMP_N_NEXT
} ip6_fip64_icmp_next_t;

typedef enum
{
  IP6_FIP64_FRAGMENTED_NEXT_IP4_LOOKUP,
  IP6_FIP64_FRAGMENTED_N_NEXT
} ip6_fip64_fragmented_next_t;

static_always_inline
int ip6_parse(const ip6_header_t *ip6, u32 buff_len,
              u8 *l4_protocol, u16 *l4_offset, u16 *frag_hdr_offset)
{
  if (ip6->protocol == IP_PROTOCOL_IPV6_FRAGMENTATION) {
    *l4_protocol = ((ip6_frag_hdr_t *)(ip6 + 1))->next_hdr;
    *frag_hdr_offset = sizeof(*ip6);
    *l4_offset = sizeof(*ip6) + sizeof(ip6_frag_hdr_t);
  } else {
    *l4_protocol = ip6->protocol;
    *frag_hdr_offset = 0;
    *l4_offset = sizeof(*ip6);
  }

  return (buff_len < (*l4_offset + 4)) ||
      (clib_net_to_host_u16(ip6->payload_length) < (*l4_offset + 4 - sizeof(*ip6)));
}

/* sample function to generate an ip4 udp packet
 * src: 172.16.0.2 port 11111
 * dst: 172.16.0.1 port 11111
 * payload: "Hello world!"
 */
static u16
build_report_packet(u8 *data, void *context)
{
  // TODO
  // void **context_array = (void**)context;
  // ip6_address_t *ip6 = (ip6_address_t*) context_array[0];
  // ip4_address_t *ip4 = (ip4_address_t*) context_array[1];

  //ethernet_header_t *eth = (ethernet_header_t *) data;
  ip4_header_t *ip = (ip4_header_t*) data;
  udp_header_t *udp = (udp_header_t*) &ip[1];
  u8 *body = (u8*) &udp[1];

  memset(data, 0, body - data);

  //eth->type = clib_host_to_net_u16(0x0800);
  //memset (eth->dst_address, 0xff, 6);

  // TODO: This is crashing, maybe format() doesn't like a static buffer
  // u8 *payload = format(body, "Hey! There's a mapping from %U to %U",
  //                format_ip6_address, ip6,
  //                format_ip4_address, ip4);
  // *(payload++) = 0; // zero-terminate string in packet, as it is printed at the other end
  //size_t payload_length = payload - body;

  char *payload = "Hello world!";
  size_t payload_length = strlen(payload) + 1; // +1 to include terminator
  memcpy(body, payload, payload_length);

  ip->ip_version_and_header_length = 0x45;
  ip->ttl = 254;
  ip->protocol = IP_PROTOCOL_UDP;
  ip->src_address.as_u32 = clib_host_to_net_u32(0xAC100002);
  ip->dst_address.as_u32 = clib_host_to_net_u32(0xAC100001);

  udp->src_port = clib_host_to_net_u16 (FIP64_CONTROL_PORT_NUMBER);
  udp->dst_port = clib_host_to_net_u16 (FIP64_CONTROL_PORT_NUMBER);

  size_t length = payload_length + sizeof(*udp);
  udp->length = clib_host_to_net_u16 (length);

  clib_memcpy (body, payload, payload_length);

  ip_csum_t csum;
  csum = ip_incremental_checksum (0, udp, length);
  csum = ip_csum_with_carry (csum, udp->length);
  csum = ip_csum_with_carry (csum,
                             clib_host_to_net_u16 (IP_PROTOCOL_UDP));
  csum = ip_csum_with_carry (csum, *((u64 *) (&ip->src_address)));
  udp->checksum = ~ip_csum_fold (csum);

  length += sizeof(*ip);
  ip->length = clib_host_to_net_u16 (length);
  ip->checksum = ip4_header_checksum (ip);
  return length /* + sizeof(*eth)*/;
}

static uword
ip6_fip64 (vlib_main_t * vm, vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  bool packets_injected = false;
  pkinject_t *injector = _fip64_main.pkinject;
  u32 n_left_from, *from, next_index, *to_next, n_left_to_next;
  vlib_node_runtime_t *error_node = vlib_node_get_runtime (vm,
                                                           ip6_fip64_node.index);
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
          ip6_frag_hdr_t *frag0;
          fip64_ip6_next_t next0 = 0;

          pi0 = to_next[0] = from[0];
          from += 1;
          n_left_from -= 1;
          to_next += 1;
          n_left_to_next -= 1;
          error0 = FIP64_ERROR_NONE;

          p0 = vlib_get_buffer (vm, pi0);
          ip60 = vlib_buffer_get_current (p0);

          bool is_traced = p0->flags & VLIB_BUFFER_IS_TRACED;

          ip6_header_t *ip6 = vlib_buffer_get_current (p0);
          fip64_ip4_t ip4_mapping;
          fip64_lookup_result_t result = fip64_lookup_ip6_to_ip4(&_fip64_main,
                                                            &ip6->src_address,
                                                            &ip6->dst_address,
                                                            &ip4_mapping);

          switch (result)
          {
            case FIP64_LOOKUP_FAILED:
              /* if lookup fails, map to zero address */
              memset(&ip4_mapping, 0, sizeof(ip4_mapping));
              break;

            case FIP64_LOOKUP_IN_CACHE:
              // TODO:   break;
              // currently falling back to ALLOCATED branch
              // to send a packet every time.
              // otherwise the first packet is dropped because
              // of address resolution.
            case FIP64_LOOKUP_ALLOCATED:
              if (injector != 0)
              {
                void *context[2];
                context[0] = &ip6->src_address;
                context[1] = &ip4_mapping.src_address;
                pkinject_by_callback (injector,
                                      build_report_packet,
                                      context,
                                      is_traced? PKINJECT_FLAG_TRACE : 0);
                packets_injected = true;
              }
              break;
          }

          // Send mapping to all fip64 specific nodes
          vnet_buffer (p0)->map_t.v6.saddr = ip4_mapping.src_address.as_u32;
          vnet_buffer (p0)->map_t.v6.daddr = ip4_mapping.dst_address.as_u32;
          // To make ip4_lookup search the correct VRF
          vnet_buffer (p0)->sw_if_index[VLIB_TX] = ip4_mapping.table_id;
          vnet_buffer (p0)->map_t.mtu = ~0;

          if (PREDICT_FALSE ( is_traced ))
            {
              fip64_trace_t *trace = vlib_add_trace(vm,
                                                    node,
                                                    p0,
                                                    sizeof(fip64_trace_t));
              trace->op = IP6_FIP64_TRACE;
              trace->ip6.src_address = ip6->src_address;
              trace->ip6.dst_address = ip6->dst_address;
              trace->ip4.src_address = ip4_mapping.src_address;
              trace->ip4.dst_address = ip4_mapping.dst_address;
              trace->ip4.table_id = ip4_mapping.table_id;
            }

          if (PREDICT_FALSE (ip6_parse (ip60, p0->current_length,
                                        &(vnet_buffer (p0)->map_t.
                                          v6.l4_protocol),
                                        &(vnet_buffer (p0)->map_t.
                                          v6.l4_offset),
                                        &(vnet_buffer (p0)->map_t.
                                          v6.frag_offset))))
            {
              error0 = FIP64_ERROR_MALFORMED;
              next0 = IP6_FIP64_NEXT_DROP;
              clib_warning ("ip6_parse returned error, drop the packet");
            }

          l4_len0 = (u32) clib_net_to_host_u16 (ip60->payload_length) +
            sizeof (*ip60) - vnet_buffer (p0)->map_t.v6.l4_offset;
          frag0 =
            (ip6_frag_hdr_t *) u8_ptr_add (ip60,
                                           vnet_buffer (p0)->map_t.
                                           v6.frag_offset);

          if (PREDICT_FALSE (vnet_buffer (p0)->map_t.v6.frag_offset &&
                             ip6_frag_hdr_offset (frag0)))
            {
              next0 = IP6_FIP64_NEXT_MAPT_FRAGMENTED;
            }
          else
            if (PREDICT_TRUE
                (vnet_buffer (p0)->map_t.v6.l4_protocol == IP_PROTOCOL_TCP))
            {
              error0 =
                l4_len0 <
                sizeof (tcp_header_t) ? FIP64_ERROR_MALFORMED : error0;
              vnet_buffer (p0)->map_t.checksum_offset =
                vnet_buffer (p0)->map_t.v6.l4_offset + 16;
              next0 = IP6_FIP64_NEXT_MAPT_TCP_UDP;
            }
          else
            if (PREDICT_TRUE
                (vnet_buffer (p0)->map_t.v6.l4_protocol == IP_PROTOCOL_UDP))
            {
              error0 =
                l4_len0 <
                sizeof (udp_header_t) ? FIP64_ERROR_MALFORMED : error0;
              vnet_buffer (p0)->map_t.checksum_offset =
                vnet_buffer (p0)->map_t.v6.l4_offset + 6;
              next0 = IP6_FIP64_NEXT_MAPT_TCP_UDP;
            }
          else if (vnet_buffer (p0)->map_t.v6.l4_protocol ==
                   IP_PROTOCOL_ICMP6)
            {
              error0 =
                l4_len0 <
                sizeof (icmp46_header_t) ? FIP64_ERROR_MALFORMED : error0;
              next0 = IP6_FIP64_NEXT_MAPT_ICMP;
            }
          else
            {
              //TODO: In case of 1:1 mapping, it might be possible to do something with those packets.
              error0 = FIP64_ERROR_BAD_PROTOCOL;
            }

          // MIDOTODO: Deal with fragmentation (see ip6_map_t.c)

          // MIDOTODO: Counters (see ip6_map_t.c)

          next0 = (error0 != FIP64_ERROR_NONE) ? IP6_FIP64_NEXT_DROP : next0;
          p0->error = error_node->errors[error0];
          vlib_validate_buffer_enqueue_x1 (vm, node, next_index,
                                           to_next, n_left_to_next, pi0,
                                           next0);
        }
      vlib_put_next_frame (vm, node, next_index, n_left_to_next);
    }
  if (packets_injected)
  {
    pkinject_flush (injector);
  }

  return frame->n_vectors;
}

static_always_inline u8
ip6_translate_tos (const ip6_header_t * ip6)
{
  return (clib_net_to_host_u32 (ip6->ip_version_traffic_class_and_flow_label)
           & 0x0ff00000) >> 20;
}

//TODO: Find right place in memory for that
/* *INDENT-OFF* */
static u8 icmp6_to_icmp_updater_pointer_table[] =
  { 0, 1, ~0, ~0,
    2, 2, 9, 8,
    12, 12, 12, 12,
    12, 12, 12, 12,
    12, 12, 12, 12,
    12, 12, 12, 12,
    24, 24, 24, 24,
    24, 24, 24, 24,
    24, 24, 24, 24,
    24, 24, 24, 24
  };

static i32
ip6_get_port (ip6_header_t * ip6, fip64_dir_e dir, u16 buffer_len)
{
  u8 l4_protocol;
  u16 l4_offset;
  u16 frag_offset;
  u8 *l4;

  if (ip6_parse (ip6, buffer_len, &l4_protocol, &l4_offset, &frag_offset))
    return -1;

  //TODO: Use buffer length

  if (frag_offset &&
      ip6_frag_hdr_offset (((ip6_frag_hdr_t *)
			    u8_ptr_add (ip6, frag_offset))))
    return -1;			//Can't deal with non-first fragment for now

  l4 = u8_ptr_add (ip6, l4_offset);
  if (l4_protocol == IP_PROTOCOL_TCP || l4_protocol == IP_PROTOCOL_UDP)
    {
      return (dir ==
	      FIP64_SENDER) ? ((udp_header_t *) (l4))->src_port : ((udp_header_t
								  *)
								 (l4))->dst_port;
    }
  else if (l4_protocol == IP_PROTOCOL_ICMP6)
    {
      icmp46_header_t *icmp = (icmp46_header_t *) (l4);
      if (icmp->type == ICMP6_echo_request)
	{
	  return (dir == FIP64_SENDER) ? ((u16 *) (icmp))[2] : -1;
	}
      else if (icmp->type == ICMP6_echo_reply)
	{
	  return (dir == FIP64_SENDER) ? -1 : ((u16 *) (icmp))[2];
	}
    }
  return -1;
}

static_always_inline int
ip6_icmp_to_icmp6_in_place (icmp46_header_t * icmp, u32 icmp_len,
			    i32 * sender_port, ip6_header_t ** inner_ip6)
{
  *inner_ip6 = NULL;
  switch (icmp->type)
    {
    case ICMP6_echo_request:
      *sender_port = ((u16 *) icmp)[2];
      icmp->type = ICMP4_echo_request;
      break;
    case ICMP6_echo_reply:
      *sender_port = ((u16 *) icmp)[2];
      icmp->type = ICMP4_echo_reply;
      break;
    case ICMP6_destination_unreachable:
      *inner_ip6 = (ip6_header_t *) u8_ptr_add (icmp, 8);
      *sender_port = ip6_get_port (*inner_ip6, FIP64_RECEIVER, icmp_len);

      switch (icmp->code)
	{
	case ICMP6_destination_unreachable_no_route_to_destination:	//0
	case ICMP6_destination_unreachable_beyond_scope_of_source_address:	//2
	case ICMP6_destination_unreachable_address_unreachable:	//3
	  icmp->type = ICMP4_destination_unreachable;
	  icmp->code =
	    ICMP4_destination_unreachable_destination_unreachable_host;
	  break;
	case ICMP6_destination_unreachable_destination_administratively_prohibited:	//1
	  icmp->type =
	    ICMP4_destination_unreachable;
	  icmp->code =
	    ICMP4_destination_unreachable_communication_administratively_prohibited;
	  break;
	case ICMP6_destination_unreachable_port_unreachable:
	  icmp->type = ICMP4_destination_unreachable;
	  icmp->code = ICMP4_destination_unreachable_port_unreachable;
	  break;
	default:
	  return -1;
	}
      break;
    case ICMP6_packet_too_big:
      *inner_ip6 = (ip6_header_t *) u8_ptr_add (icmp, 8);
      *sender_port = ip6_get_port (*inner_ip6, FIP64_RECEIVER, icmp_len);

      icmp->type = ICMP4_destination_unreachable;
      icmp->code = 4;
      {
	u32 advertised_mtu = clib_net_to_host_u32 (*((u32 *) (icmp + 1)));
	advertised_mtu -= 20;
	//FIXME: = minimum(advertised MTU-20, MTU_of_IPv4_nexthop, (MTU_of_IPv6_nexthop)-20)
	((u16 *) (icmp))[3] = clib_host_to_net_u16 (advertised_mtu);
      }
      break;

    case ICMP6_time_exceeded:
      *inner_ip6 = (ip6_header_t *) u8_ptr_add (icmp, 8);
      *sender_port = ip6_get_port (*inner_ip6, FIP64_RECEIVER, icmp_len);

      icmp->type = ICMP4_time_exceeded;
      break;

    case ICMP6_parameter_problem:
      *inner_ip6 = (ip6_header_t *) u8_ptr_add (icmp, 8);
      *sender_port = ip6_get_port (*inner_ip6, FIP64_RECEIVER, icmp_len);

      switch (icmp->code)
	{
	case ICMP6_parameter_problem_erroneous_header_field:
	  icmp->type = ICMP4_parameter_problem;
	  icmp->code = ICMP4_parameter_problem_pointer_indicates_error;
	  u32 pointer = clib_net_to_host_u32 (*((u32 *) (icmp + 1)));
	  if (pointer >= 40)
	    return -1;

	  ((u8 *) (icmp + 1))[0] =
	    icmp6_to_icmp_updater_pointer_table[pointer];
	  break;
	case ICMP6_parameter_problem_unrecognized_next_header:
	  icmp->type = ICMP4_destination_unreachable;
	  icmp->code = ICMP4_destination_unreachable_port_unreachable;
	  break;
	case ICMP6_parameter_problem_unrecognized_option:
	default:
	  return -1;
	}
      break;
    default:
      return -1;
      break;
    }
  return 0;
}

static_always_inline void
_ip6_fip64_icmp (vlib_main_t *vm,
                 vlib_node_runtime_t *node,
                 vlib_buffer_t * p,
                 u8 * error)
{
  ip6_header_t *ip6, *inner_ip6;
  ip4_header_t *ip4, *inner_ip4;
  u32 ip6_pay_len;
  icmp46_header_t *icmp;
  i32 sender_port;
  ip_csum_t csum;

  ip6 = vlib_buffer_get_current (p);
  ip6_pay_len = clib_net_to_host_u16 (ip6->payload_length);
  icmp = (icmp46_header_t *) (ip6 + 1);
  ASSERT (ip6_pay_len + sizeof (*ip6) <= p->current_length);

  if (ip6->protocol != IP_PROTOCOL_ICMP6)
    {
      //No extensions headers allowed here
      //TODO: SR header
      *error = FIP64_ERROR_MALFORMED;
      if (ip6->protocol == IP_PROTOCOL_IPV6_FRAGMENTATION) {
        clib_warning("First fragment of ICMP is unhandled, fixme");
      }
      return;
    }

  //There are no fragmented ICMP messages, so no extension header for now

  if (ip6_icmp_to_icmp6_in_place
      (icmp, ip6_pay_len, &sender_port, &inner_ip6))
    {
      //TODO: In case of 1:1 mapping it is not necessary to have the sender port
      *error = FIP64_ERROR_ICMP;
      return;
    }

  // MIDOTODO: check port
  sender_port = 0;

  if (inner_ip6)
    {
      u16 *inner_L4_checksum, inner_l4_offset, inner_frag_offset,
	inner_frag_id;
      u8 *inner_l4, inner_protocol;

      //We have two headers to translate
      //   FROM
      //   [   IPv6   ]<- ext ->[IC][   IPv6   ]<- ext ->[L4 header ...
      // Handled cases:
      //                     [   IPv6   ][IC][   IPv6   ][L4 header ...
      //                 [   IPv6   ][IC][   IPv6   ][Fr][L4 header ...
      //    TO
      //                               [ IPv4][IC][ IPv4][L4 header ...

      //TODO: This was already done deep in ip6_icmp_to_icmp6_in_place
      //We shouldn't have to do it again
      if (ip6_parse (inner_ip6, ip6_pay_len - 8,
		     &inner_protocol, &inner_l4_offset, &inner_frag_offset))
	{
	  *error = FIP64_ERROR_MALFORMED;
	  return;
	}

      inner_l4 = u8_ptr_add (inner_ip6, inner_l4_offset);
      inner_ip4 =
	(ip4_header_t *) u8_ptr_add (inner_l4, -sizeof (*inner_ip4));
      if (inner_frag_offset)
	{
	  ip6_frag_hdr_t *inner_frag =
	    (ip6_frag_hdr_t *) u8_ptr_add (inner_ip6, inner_frag_offset);
	  inner_frag_id = frag_id_6to4 (inner_frag->identification);
	}
      else
	{
	  inner_frag_id = 0;
	}

      //Do the translation of the inner packet
      if (inner_protocol == IP_PROTOCOL_TCP)
	{
	  inner_L4_checksum = (u16 *) u8_ptr_add (inner_l4, 16);
	}
      else if (inner_protocol == IP_PROTOCOL_UDP)
	{
	  inner_L4_checksum = (u16 *) u8_ptr_add (inner_l4, 6);
	}
      else if (inner_protocol == IP_PROTOCOL_ICMP6)
	{
	  icmp46_header_t *inner_icmp = (icmp46_header_t *) inner_l4;
	  csum = inner_icmp->checksum;
	  csum = ip_csum_sub_even (csum, *((u16 *) inner_icmp));
	  //It cannot be of a different type as ip6_icmp_to_icmp6_in_place succeeded
	  inner_icmp->type = (inner_icmp->type == ICMP6_echo_request) ?
	    ICMP4_echo_request : ICMP4_echo_reply;
	  csum = ip_csum_add_even (csum, *((u16 *) inner_icmp));
	  inner_icmp->checksum = ip_csum_fold (csum);
	  inner_protocol = IP_PROTOCOL_ICMP;	//Will be copied to ip6 later
	  inner_L4_checksum = &inner_icmp->checksum;
	}
      else
	{
	  *error = FIP64_ERROR_BAD_PROTOCOL;
	  return;
	}

      csum = *inner_L4_checksum;
      csum = ip_csum_sub_even (csum, inner_ip6->src_address.as_u64[0]);
      csum = ip_csum_sub_even (csum, inner_ip6->src_address.as_u64[1]);
      csum = ip_csum_sub_even (csum, inner_ip6->dst_address.as_u64[0]);
      csum = ip_csum_sub_even (csum, inner_ip6->dst_address.as_u64[1]);

      //Sanity check of the outer destination address
      if (ip6->dst_address.as_u64[0] != inner_ip6->src_address.as_u64[0] &&
	  ip6->dst_address.as_u64[1] != inner_ip6->src_address.as_u64[1])
	{
	  *error = FIP64_ERROR_SEC_CHECK;
	  return;
	}

      inner_ip4->dst_address.as_u32 = vnet_buffer(p)->map_t.v6.daddr;
      inner_ip4->src_address.as_u32 = vnet_buffer(p)->map_t.v6.saddr;
      //ip6_map_t_embedded_address (d, &inner_ip6->src_address);
      inner_ip4->ip_version_and_header_length =
	IP4_VERSION_AND_HEADER_LENGTH_NO_OPTIONS;
      inner_ip4->tos = ip6_translate_tos (inner_ip6);
      inner_ip4->length =
	u16_net_add (inner_ip6->payload_length,
		     sizeof (*ip4) + sizeof (*ip6) - inner_l4_offset);
      inner_ip4->fragment_id = inner_frag_id;
      inner_ip4->flags_and_fragment_offset =
	clib_host_to_net_u16 (IP4_HEADER_FLAG_MORE_FRAGMENTS);
      inner_ip4->ttl = inner_ip6->hop_limit;
      inner_ip4->protocol = inner_protocol;
      inner_ip4->checksum = ip4_header_checksum (inner_ip4);

      if (inner_ip4->protocol == IP_PROTOCOL_ICMP)
	{
	  //Remove remainings of the pseudo-header in the csum
	  csum =
	    ip_csum_sub_even (csum, clib_host_to_net_u16 (IP_PROTOCOL_ICMP6));
	  csum =
	    ip_csum_sub_even (csum, inner_ip4->length - sizeof (*inner_ip4));
	}
      else
	{
	  //Update to new pseudo-header
	  csum = ip_csum_add_even (csum, inner_ip4->src_address.as_u32);
	  csum = ip_csum_add_even (csum, inner_ip4->dst_address.as_u32);
	}
      *inner_L4_checksum = ip_csum_fold (csum);

      //Move up icmp header
      ip4 = (ip4_header_t *) u8_ptr_add (inner_l4, -2 * sizeof (*ip4) - 8);
      clib_memcpy (u8_ptr_add (inner_l4, -sizeof (*ip4) - 8), icmp, 8);
      icmp = (icmp46_header_t *) u8_ptr_add (inner_l4, -sizeof (*ip4) - 8);
    }
  else
    {
      //Only one header to translate
      ip4 = (ip4_header_t *) u8_ptr_add (ip6, sizeof (*ip6) - sizeof (*ip4));
    }
  vlib_buffer_advance (p, (u32) (((u8 *) ip4) - ((u8 *) ip6)));

  ip4->dst_address.as_u32 = vnet_buffer(p)->map_t.v6.daddr;
  ip4->src_address.as_u32 = vnet_buffer(p)->map_t.v6.saddr;
  ip4->ip_version_and_header_length =
    IP4_VERSION_AND_HEADER_LENGTH_NO_OPTIONS;
  ip4->tos = ip6_translate_tos (ip6);
  ip4->fragment_id = 0;
  ip4->flags_and_fragment_offset = 0;
  ip4->ttl = ip6->hop_limit;
  ip4->protocol = IP_PROTOCOL_ICMP;
  //TODO fix the length depending on offset length
  ip4->length = u16_net_add (ip6->payload_length,
			     (inner_ip6 ==
			      NULL) ? sizeof (*ip4) : (2 * sizeof (*ip4) -
						       sizeof (*ip6)));
  ip4->checksum = ip4_header_checksum (ip4);

  //TODO: We could do an easy diff-checksum for echo requests/replies
  //Recompute ICMP checksum
  icmp->checksum = 0;
  csum =
    ip_incremental_checksum (0, icmp,
			     clib_net_to_host_u16 (ip4->length) -
			     sizeof (*ip4));
  icmp->checksum = ~ip_csum_fold (csum);
}

static uword
ip6_fip64_icmp (vlib_main_t * vm,
		vlib_node_runtime_t * node, vlib_frame_t * frame)
{
  u32 n_left_from, *from, next_index, *to_next, n_left_to_next;
  vlib_node_runtime_t *error_node =
    vlib_node_get_runtime (vm, ip6_fip64_icmp_node.index);
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
	  u8 error0;
	  ip6_fip64_icmp_next_t next0;

	  pi0 = to_next[0] = from[0];
	  from += 1;
	  n_left_from -= 1;
	  to_next += 1;
	  n_left_to_next -= 1;
	  error0 = FIP64_ERROR_NONE;
	  next0 = IP6_FIP64_ICMP_NEXT_IP4_LOOKUP;

	  p0 = vlib_get_buffer (vm, pi0);
	  _ip6_fip64_icmp (vm, node, p0, &error0);

	  if (PREDICT_FALSE(error0 != FIP64_ERROR_NONE))
	    {
	      next0 = IP6_FIP64_ICMP_NEXT_DROP;
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

static char *fip64_error_strings[] = {
#define _(sym,string) string,
  foreach_fip64_error
#undef _
};

/* *INDENT-OFF* */
VLIB_REGISTER_NODE(ip6_fip64_icmp_node) = {
  .function = ip6_fip64_icmp,
  .name = "ip6-fip64-icmp",
  .vector_size = sizeof (u32),
  .format_trace = format_fip64_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = FIP64_N_ERROR,
  .error_strings = fip64_error_strings,

  .n_next_nodes = IP6_FIP64_ICMP_N_NEXT,
  .next_nodes = {
      [IP6_FIP64_ICMP_NEXT_IP4_LOOKUP] = "ip4-lookup",
      // MIDOTODO -- removed [IP6_FIP64_ICMP_NEXT_IP4_FRAG] = "IP4_FRAG_NODE_NAME,
      [IP6_FIP64_ICMP_NEXT_DROP] = "error-drop",
  },
};
/* *INDENT-ON* */

/* *INDENT-OFF* */
VLIB_REGISTER_NODE(ip6_fip64_node) = {
  .function = ip6_fip64,
  .name = "ip6-fip64",
  .vector_size = sizeof(u32),
  .format_trace = format_fip64_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = FIP64_N_ERROR,
  .error_strings = fip64_error_strings,

  .n_next_nodes = IP6_FIP64_N_NEXT,
  .next_nodes = {
      [IP6_FIP64_NEXT_MAPT_TCP_UDP] = "ip6-map-t-tcp-udp",
      [IP6_FIP64_NEXT_MAPT_ICMP] = "ip6-fip64-icmp",
      [IP6_FIP64_NEXT_MAPT_FRAGMENTED] = "ip6-map-t-fragmented",
      [IP6_FIP64_NEXT_DROP] = "error-drop",
  },
};
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * indent-tabs-mode: nil
 * End:
 */
