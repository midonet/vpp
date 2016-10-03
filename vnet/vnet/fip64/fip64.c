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

#define IP4_NET_ADDRESS 0x64000000
#define IP4_NET_PREFIX 24

u64
fip64_error_counter_get (u32 node_index, fip64_error_t fip64_error)
{
  vlib_main_t *vm = vlib_get_main ();
  vlib_node_runtime_t *error_node = vlib_node_get_runtime (vm, node_index);
  vlib_error_main_t *em = &vm->error_main;
  vlib_error_t e = error_node->errors[fip64_error];
  vlib_node_t *n = vlib_get_node (vm, node_index);
  u32 ci;

  ci = vlib_error_get_code (e);
  ASSERT (ci < n->n_errors);
  ci += n->error_heap_index;

  return (em->counters[ci]);
}

/*
 * Packet trace format function.
 */
u8 *
format_fip64_trace (u8 * s, va_list * args)
{
  CLIB_UNUSED (vlib_main_t * vm) = va_arg (*args, vlib_main_t *);
  CLIB_UNUSED (vlib_node_t * node) = va_arg (*args, vlib_node_t *);
  fip64_trace_t *trace = va_arg(*args,  fip64_trace_t *);

  if (trace->op == IP6_FIP64_TRACE)
    {
      s = format(s, "source: %U -> %U\n",
              format_ip6_address, &trace->ip6.src_address,
              format_ip4_address, trace->ip4.src_address.data);
      s = format(s, "  dest:   %U -> %U",
              format_ip6_address, &trace->ip6.dst_address,
              format_ip4_address, trace->ip4.dst_address.data);
    }
  else
    {
      s = format(s, "source: %U -> %U\n",
              format_ip4_address, trace->ip4.src_address.data,
              format_ip6_address, &trace->ip6.src_address);
      s = format(s, "  dest:   %U -> %U",
              format_ip4_address, trace->ip4.dst_address.data,
              format_ip6_address, &trace->ip6.dst_address);
    }
  return s;
}

/*
 * FIP64 command function. It configures the adjancency to the IPv4 by adding
 * a FIP entry for the configured IPv4 subnet.
 */
static clib_error_t*
fip64_command_fn (vlib_main_t * vm, unformat_input_t * input,
                  vlib_cli_command_t * cmd)
{
  ip4_address_t ip4_addr = {
    .as_u32 = clib_host_to_net_u32(IP4_NET_ADDRESS)
  };

  vlib_cli_output (vm, "FIP64 IPv4 adjacency configured for %U/%u",
                   format_ip4_address, ip4_addr.as_u8, IP4_NET_PREFIX);
  
  ip4_main_t *im4 = &ip4_main;
  ip4_add_del_route_args_t args4;
  ip_adjacency_t adj;
  
  // Init IP adjancency.
  memset(&adj, 0, sizeof(adj));
  adj.explicit_fib_index = ~0;
  adj.lookup_next_index = IP_LOOKUP_NEXT_FIP64;
  
  // Create IPv4 adjancency.
  memset(&args4, 0, sizeof(args4));
  args4.table_index_or_table_id = 0;
  args4.flags = IP4_ROUTE_FLAG_ADD;
  args4.dst_address.as_u32 = ip4_addr.as_u32;
  args4.dst_address_length = IP4_NET_PREFIX;
  args4.adj_index = ~0;
  args4.add_adj = &adj;
  args4.n_add_adj = 1;
  ip4_add_del_route (im4, &args4);
  
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND(fip64_command, static) = {
  .path = "fip64",
  .function = fip64_command_fn,
};
/* *INDENT-ON* */
