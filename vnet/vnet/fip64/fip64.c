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
#include <vnet/ip/lookup.h>

#define IP4_NET_ADDRESS 0xA000000
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
  return (u8*) "FIP64 trace not available";
}

/*
 * Create/Delete/Lookup functions for ip6-ip4 mappings
 */
clib_error_t*
fip64_add_mapping(ip6_address_t * ip6, ip4_address_t * ip4)
{
  // TODO: implement
  return 0;
}

clib_error_t*
fip64_delete_mapping(ip6_address_t * ip6)
{
  // TODO: implement
  return 0;
}

clib_error_t*
fip64_lookup_ip6_to_ip4(ip6_address_t * ip6, ip4_address_t * ip4_out)
{
  // TODO: implement
  return 0;
}

clib_error_t* 
fip64_lookup_ip4_to_ip6(ip4_address_t * ip4, ip6_address_t * ip6_out)
{
  // TODO: implement
  return 0;
}

static void
fip64_add_del_ip4_adjacency(ip4_address_t * ip4nh, u32 add_del_flag)
{
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
  args4.flags = add_del_flag;
  args4.dst_address = *ip4nh;
  args4.dst_address_length = 32;
  args4.adj_index = ~0;
  args4.add_adj = &adj;
  args4.n_add_adj = 1;
  ip4_add_del_route (im4, &args4);
}

static void
fip64_add_del_ip6_adjacency(ip6_address_t * ip6nh, u32 add_del_flag)
{
  ip6_main_t *im6 = &ip6_main;
  ip6_add_del_route_args_t args6;
  ip_adjacency_t adj;
  
  // Init IP adjancency.
  memset(&adj, 0, sizeof(adj));
  adj.explicit_fib_index = ~0;
  adj.lookup_next_index = IP_LOOKUP_NEXT_FIP64;
  
  // Create IPv4 adjancency.
  memset(&args6, 0, sizeof(args6));
  args6.table_index_or_table_id = 0;
  args6.flags = add_del_flag;
  args6.dst_address = *ip6nh;
  args6.dst_address_length = 128;
  args6.adj_index = ~0;
  args6.add_adj = &adj;
  args6.n_add_adj = 1;
  ip6_add_del_route (im6, &args6);
}

static clib_error_t*
fip64_add_command_fn (vlib_main_t * vm, unformat_input_t * input,
                      vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  ip4_address_t ip4nh;
  ip6_address_t ip6nh;
  u8 ip4 = 0, ip6 = 0;

  memset (&ip4nh, 0, sizeof (ip4nh));
  memset (&ip6nh, 0, sizeof (ip6nh));

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%U", unformat_ip6_address, &ip6nh)) 
        {
          ip6 = 1;
        }
      else if (unformat (line_input, "%U", unformat_ip4_address, &ip4nh))
        {
          ip4 = 1;
        }
      else
        {
	      unformat_free (line_input);
	      return clib_error_return (0, "invalid input");
	    }
    }
  unformat_free (line_input);

  if (!ip6 || !ip4)
    return clib_error_return (0, "must specify a valid ip6 and ip4 addresses");

  fip64_add_del_ip6_adjacency(&ip6nh, IP6_ROUTE_FLAG_ADD);
  fip64_add_del_ip4_adjacency(&ip4nh, IP4_ROUTE_FLAG_ADD);
  fip64_add_mapping(&ip6nh, &ip4nh);
  return 0;
}

static clib_error_t*
fip64_del_command_fn (vlib_main_t * vm, unformat_input_t * input,
                      vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  ip4_address_t ip4nh;
  ip6_address_t ip6nh;
  u8 ip6 = 0;

  memset (&ip6nh, 0, sizeof (ip6nh));

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
    {
      if (unformat (line_input, "%U", unformat_ip6_address, &ip6nh)) 
        {
          ip6 = 1;
        }
      else
        {
	      unformat_free (line_input);
	      return clib_error_return (0, "invalid input");
	    }
    }
  unformat_free (line_input);

  if (!ip6)
    return clib_error_return (0, "must specify a valid ip6 address");

  memset (&ip4nh, 0, sizeof (ip4nh));
  fip64_lookup_ip6_to_ip4(&ip6nh, &ip4nh);
  //if (!ip4nh) {
  //  return clib_error_return (0, "does not exist the mapping from the ip6 address");
  //}

  fip64_add_del_ip6_adjacency(&ip6nh, IP6_ROUTE_FLAG_DEL);
  //fip64_add_del_ip4_adjacency(&ip4nh, IP4_ROUTE_FLAG_DEL);
  fip64_delete_mapping(&ip6nh);
  return 0;
}

static clib_error_t*
fip64_show_command_fn (vlib_main_t * vm, unformat_input_t * input,
                      vlib_cli_command_t * cmd)
{
  vlib_cli_output (vm, "FIP64 show command\n"); 
  return 0;
}

/* *INDENT-OFF* */
VLIB_CLI_COMMAND(fip64_show_command, static) = {
  .path = "fip64 show",
  .function = fip64_show_command_fn,
};
/* *INDENT-ON* */

/* *INDENT-OFF* */
VLIB_CLI_COMMAND(fip64_add_command, static) = {
  .path = "fip64 add",
  .short_help = "<ip6 address> <ip4 address>",
  .function = fip64_add_command_fn,
};
/* *INDENT-ON* */

/* *INDENT-OFF* */
VLIB_CLI_COMMAND(fip64_del_command, static) = {
  .path = "fip64 del",
  .short_help = "<ip6 address>",
  .function = fip64_del_command_fn,
};
/* *INDENT-ON* */
