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

#define IP4_NET_ADDRESS 0x64000000
#define IP4_NET_PREFIX 24

fip64_main_t fip64_main;

static clib_error_t *
fip64_init (vlib_main_t * vm)
{
  fip64_main.ip6_ip4_hash = hash_create_mem(0, sizeof(fip64_ip6_t), sizeof(fip64_ip4_t));
  fip64_main.ip4_ip6_hash = hash_create_mem(0, sizeof(fip64_ip4_t), sizeof(fip64_ip6_t));
  fip64_main.ip6_adj_refs = hash_create_mem(0, sizeof(ip6_address_t), sizeof(unsigned int));
  fip64_main.ip6_adj_refs = hash_create_mem(0, sizeof(ip4_address_t), sizeof(unsigned int));
  return 0;
}

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
 * Create/Delete/Lookup functions for ip6-ip4 mappings
 */
clib_error_t *
fip64_add_mapping(fip64_ip6_t * ip6_input, fip64_ip4_t * ip4_input)
{
  fip64_ip6_t * ip6 = clib_mem_alloc(sizeof(fip64_ip6_t));
  fip64_ip4_t * ip4 = clib_mem_alloc(sizeof(fip64_ip4_t));
  clib_memcpy(ip6, ip6_input, sizeof(fip64_ip6_t));
  clib_memcpy(ip4, ip4_input, sizeof(fip64_ip4_t));
  hash_set_mem(fip64_main.ip6_ip4_hash, ip6, ip4);
  hash_set_mem(fip64_main.ip4_ip6_hash, ip4, ip6);
  return 0;
}

clib_error_t *
fip64_del_mapping(fip64_ip6_t * ip6)
{
  fip64_ip4_t * stored_ip4 = (fip64_ip4_t*) *hash_get_mem(fip64_main.ip6_ip4_hash, ip6);
  fip64_ip6_t * stored_ip6 = (fip64_ip6_t*) *hash_get_mem(fip64_main.ip4_ip6_hash, stored_ip4);
  hash_unset(fip64_main.ip6_ip4_hash, stored_ip6);
  hash_unset(fip64_main.ip4_ip6_hash, stored_ip4);
  clib_mem_free(stored_ip4);
  clib_mem_free(stored_ip6);
  return 0;
}

bool
fip64_lookup_ip6_to_ip4(ip6_address_t * ip6_src, ip6_address_t * ip6_dst,
                        ip4_address_t * ip4_src, ip4_address_t * ip4_dst)
{
  fip64_ip6_t ip6;
  ip6.src = *ip6_src;
  ip6.dst = *ip6_dst;
  uword * p = hash_get_mem(fip64_main.ip6_ip4_hash, &ip6);
  if (p)
  {
    fip64_ip4_t * ip4 = (fip64_ip4_t *) *p;
    *ip4_src = ip4->src;
    *ip4_dst = ip4->dst;
    return true;
  }
  else
    return false;
}

bool
fip64_lookup_ip4_to_ip6(ip4_address_t * ip4_src, ip4_address_t * ip4_dst,
                        ip6_address_t * ip6_src, ip6_address_t * ip6_dst)
{
  fip64_ip4_t ip4;
  ip4.src = *ip4_src;
  ip4.dst = *ip4_dst;
  uword * p = hash_get_mem(fip64_main.ip4_ip6_hash, &ip4);
  if (p)
  {
    fip64_ip6_t * ip6 = (fip64_ip6_t *) *p;
    *ip6_src = ip6->src;
    *ip6_dst = ip6->dst;
    return true;
  }
  else
    return false;
})

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

  uword * p = hash_get_mem(fip64_main.ip4_adj_refs, ip4nh);
  // check if it's an add or a delete
  if (add_del_flag == IP4_ROUTE_FLAG_ADD) {
    if (p) (*p)++;
    else 
    {
      unsigned int * refs;
      clib_mem_alloc(refs);
      *refs = 1;
      hash_set_mem(fip64_main.ip4_adj_refs, ip4nh, refs);
      ip4_add_del_route(im4, &args4);
    }
  } 
  else // add_del_flag == IP4_ROUTE_FLAG_DEL
  {
    if (p && --(*p) == 0) 
    {
      hash_unset_mem(fip64_main.ip4_adj_refs, p);
      clib_mem_free(p);
      ip4_add_del_route(im4, &args4);
    }
  }
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

/*
 * Update a mapping:
 *
 *  - If old mapping to IP4 exists, deletes it (return non-zero)
 *  - If new mapping is IP4 is given, add it
 *
 * Returns 0 if no old mapping is found
 */
static bool
fip64_update_mapping(fip64_ip6_t * ip6_input, fip64_ip4_t * ip4_input)
{
  /* Remove old mapping and adjacencies if it already exists */
  fip64_ip4_t old_ip4;
  bool exists_mapping = fip64_lookup_ip6_to_ip4(&ip6_input->src, &ip6_input->dst,
                                                &old_ip4.src, &old_ip4.dst);
  if (exists_mapping)
  {
    // TODO: handle reference counting for adjacencies
    fip64_add_del_ip6_adjacency(&ip6_input->dst, IP4_ROUTE_FLAG_DEL);
    fip64_add_del_ip4_adjacency(&old_ip4.src, IP4_ROUTE_FLAG_DEL);
    fip64_del_mapping(ip6_input);
  }

  /* Add new mapping and adjacency if ip4_input not null */
  if(ip4_input)
  {
    // TODO: handle reference counting for adjacencies
    fip64_add_del_ip6_adjacency(&ip6_input->dst, IP6_ROUTE_FLAG_ADD);
    fip64_add_del_ip4_adjacency(&ip4_input->src, IP4_ROUTE_FLAG_ADD);
    fip64_add_mapping(ip6_input, ip4_input);
  }

  return exists_mapping;
}

static clib_error_t*
fip64_add_command_fn (vlib_main_t * vm, unformat_input_t * input,
                      vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  fip64_ip6_t ip6;
  fip64_ip4_t ip4;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
  {
    if (  !unformat (line_input, "%U", unformat_ip6_address, &ip6.src)
       || !unformat (line_input, "%U", unformat_ip6_address, &ip6.dst)
       || !unformat (line_input, "%U", unformat_ip4_address, &ip4.src)
       || !unformat (line_input, "%U", unformat_ip4_address, &ip4.dst))
    {
      unformat_free (line_input);
      return clib_error_return (0, "invalid input: expected <src_ip6> <dst_ip6> <src_ip4> <dst_ip4>");
    }
  }
  unformat_free (line_input);

  fip64_update_mapping(&ip6, &ip4);
  return 0;
}

static clib_error_t*
fip64_del_command_fn (vlib_main_t * vm, unformat_input_t * input,
                      vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  fip64_ip6_t ip6;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
  {
      if (  !unformat (line_input, "%U", unformat_ip6_address, &ip6.src)
         || !unformat (line_input, "%U", unformat_ip6_address, &ip6.dst))
      {
        unformat_free (line_input);
        return clib_error_return (0, "invalid input: expected <src_ip6> <dst_ip6>");
      }
  }
  unformat_free (line_input);

  if (!fip64_update_mapping(&ip6, 0))
  {
    return clib_error_return (0, "warning: mapping not found");
  }
  return 0;
}

static clib_error_t*
fip64_show_command_fn (vlib_main_t * vm, unformat_input_t * input,
                      vlib_cli_command_t * cmd)
{
  vlib_cli_output (vm, "IP6 <-> IP4 mappings\n");
  vlib_cli_output (vm, "%-40s%-40s%-16s%-16s\n",
                   "SRC IP6", "DST IP6", "SRC IP4", "DST IP4");
  uword k, v;
  hash_foreach(k, v, fip64_main.ip6_ip4_hash,                                 \
    u8 * s = 0;                                                               \
    fip64_ip6_t * ip6 = (fip64_ip6_t*) k;                                     \
    fip64_ip4_t * ip4 = (fip64_ip4_t*) v;                                     \
    s = format (s, "%-40U%-40U%-16U%-16U\n",                                  \
                   format_ip6_address, &ip6->src,                             \
                   format_ip6_address, &ip6->dst,                             \
                   format_ip4_address, &ip4->src,                             \
                   format_ip4_address, &ip4->dst);                            \
    vlib_cli_output(vm, (char*) s);                                           \
    vec_free(s);
  );
  vlib_cli_output (vm, "\nDEBUG\n");
  vlib_cli_output (vm, "IP4 <-> IP6 mappings\n");
  vlib_cli_output (vm, "%-16s%-16s%-40s%-40s\n",
                   "SRC IP4", "DST IP4", "SRC IP6", "DST IP6");

  hash_foreach(k, v, fip64_main.ip4_ip6_hash,                                 \
    u8 * s = 0;                                                               \
    fip64_ip4_t * ip4 = (fip64_ip4_t*) k;                                     \
    fip64_ip6_t * ip6 = (fip64_ip6_t*) v;                                     \
    s = format (s, "%-16U%-16U%-40U%-40U\n",                                  \
                   format_ip4_address, &ip4->src,                             \
                   format_ip4_address, &ip4->dst,                             \
                   format_ip6_address, &ip6->src,                             \
                   format_ip6_address, &ip6->dst);                            \
    vlib_cli_output(vm, (char*) s);                                           \
    vec_free(s);
  );

  return 0;
}

/**
 * Show the current ip6 to ip4 mappins (and reverse lookup for debugging)
 *
 * This command show the mapping from an ip6 address to an ip4
 * address and also the ip4 to ip6 mappings corresponding to the two
 * hash maps in the current implementation.
 */
/* *INDENT-OFF* */
VLIB_CLI_COMMAND(fip64_show_command, static) = {
  .path = "fip64 show",
  .short_help = "",
  .function = fip64_show_command_fn,
};
/* *INDENT-ON* */

/**
 * Adds an ip6 to ip4 mapping.
 *
 * This command adds the mapping from an ip6 address to an ip4
 * address and also adds the corresponding adjacencies to the ip6
 * and ip4 routing tables.
 * WARNING: we do not keep track of reference counts on the adjacencies
 * added. We will add support for this in later stages.
 */
/* *INDENT-OFF* */
VLIB_CLI_COMMAND(fip64_add_command, static) = {
  .path = "fip64 add",
  .short_help = "<src_ip6> <dst_ip6> <src_ip4> <dst_ip4>",
  .function = fip64_add_command_fn,
};
/* *INDENT-ON* */

/**
 * Deletes an ip6 to ip4 mapping.
 *
 * This command removes the mapping from an ip6 address to an ip4
 * address and also removes the corresponding adjacencies from the ip6
 * and ip4 routing tables.
 * WARNING: we do not keep track of reference counts on the adjacencies
 * added. We will add support for this in later stages.
 */
/* *INDENT-OFF* */
VLIB_CLI_COMMAND(fip64_del_command, static) = {
  .path = "fip64 del",
  .short_help = "<src_ip6> <dst_ip6>",
  .function = fip64_del_command_fn,
};
/* *INDENT-ON* */

/* *INDENT-OFF* */
VLIB_INIT_FUNCTION(fip64_init)
/* *INDENT-ON* */
