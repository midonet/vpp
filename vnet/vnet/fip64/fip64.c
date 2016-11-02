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

fip64_main_t _fip64_main;

static clib_error_t *
fip64_init (vlib_main_t * vm)
{
  return fip64_main_init(&_fip64_main, &ip6_main, &ip4_main);
}

clib_error_t *
fip64_main_init(fip64_main_t * fip64_main, ip6_main_t * ip6_main, ip4_main_t * ip4_main)
{
  fip64_main->testing = false;
  fip64_main->ip6_main = ip6_main;
  fip64_main->ip4_main = ip4_main;
  fip64_main->fip6_mapping_hash = hash_create_mem(0, sizeof(ip6_address_t), sizeof(fip64_mapping_t));
  fip64_main->fixed4_mapping_hash = hash_create_mem(0, sizeof(fip64_ip4key_t), sizeof(fip64_mapping_t));
  fip64_main->vrf_tenant_hash = hash_create_mem(0, sizeof(u32), sizeof(fip64_tenant_t));
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
      s = format(s, "    dest: %U -> %U\n",
              format_ip6_address, &trace->ip6.dst_address,
              format_ip4_address, trace->ip4.dst_address.data);
      s = format(s, "table_id: %d", trace->ip4.table_id);
    }
  else
    {
      s = format(s, "source: %U -> %U\n",
              format_ip4_address, trace->ip4.src_address.data,
              format_ip6_address, &trace->ip6.src_address);
      s = format(s, "    dest: %U -> %U\n",
              format_ip4_address, trace->ip4.dst_address.data,
              format_ip6_address, &trace->ip6.dst_address);
      s = format(s, "table_id: %d", trace->ip4.table_id);
    }
  return s;
}

/*
 * Create/Delete/Lookup functions for ip6-ip4 mappings
 */
clib_error_t *
fip64_add_mapping(fip64_mapping_t * mapping,
                  ip6_address_t * ip6_input, ip4_address_t ip4_input)
{
  ip6_address_t *ip6 = clib_mem_alloc(sizeof(ip6_address_t));
  ip4_address_t *ip4 = clib_mem_alloc(sizeof(ip4_address_t));
  clib_memcpy(ip6, ip6_input, sizeof(ip6_address_t));
  clib_memcpy(ip4, &ip4_input, sizeof(ip4_address_t));
  hash_set_mem(mapping->ip6_ip4_hash, ip6, ip4);
  hash_set_mem(mapping->ip4_ip6_hash, ip4, ip6);
  return 0;
}

static void
cleanup_entry(fip64_mapping_t *mapping, ip6_address_t *ip6, ip4_address_t *ip4)
{
    fip64_pool_release(mapping->tenant->pool, *ip4);
    hash_unset(mapping->ip6_ip4_hash, ip6);
    hash_unset(mapping->ip4_ip6_hash, ip4);
    clib_mem_free(ip4);
    clib_mem_free(ip6);
}

clib_error_t *
fip64_del_all_mappings(fip64_mapping_t * mapping)
{

  uword k, v;
  hash_foreach(k, v, mapping->ip6_ip4_hash,                                \
    ip6_address_t * ip6 = (ip6_address_t*) k;                              \
    ip4_address_t * ip4 = (ip4_address_t*) v;                              \
    cleanup_entry(mapping, ip6, ip4));
  return 0;
}

bool
fip64_lookup_ip6_to_ip4(fip64_main_t * fip64_main,
                        ip6_address_t * ip6_src, ip6_address_t * ip6_dst,
                        fip64_ip4_t * ip4)
{
  // search dest ip6 in configured FIPs
  uword *p = hash_get_mem(fip64_main->fip6_mapping_hash, ip6_dst);
  if (!p)
  {
    // no such fip configured
    return false;
  }

  fip64_mapping_t *mapping = (fip64_mapping_t*) *p;
  fip64_tenant_t *tenant = mapping->tenant;

  ip4->dst_address = mapping->ip4.fixed;
  ip4->table_id    = mapping->ip4.table_id;

  // lookup for existing mapping
  p = hash_get_mem(mapping->ip6_ip4_hash, ip6_src);
  if (p)
  {
    ip4->src_address = *(ip4_address_t*) *p;
    return true;
  }

  // allocate new mapping
  if (!fip64_pool_available(tenant->pool))
  {
    // TODO: expire mappings to free up some addresses
    return false;
  }

  ip4->src_address = fip64_pool_get(tenant->pool, ip6_src);

  if (!ip4->src_address.as_u32)
  {
    // no address available even after expiration
    return false;
  }

  if (NULL != fip64_add_mapping(mapping, ip6_src, ip4->src_address))
  {
    // failed when saving 4 <-> 6 mapping, return ip4 address to pool
    fip64_pool_release(tenant->pool, ip4->src_address);
    return false;
  }
  return true;
}

bool
fip64_lookup_ip4_to_ip6(fip64_main_t * fip64_main,
                        fip64_ip4_t * ip4,
                        ip6_address_t * ip6_src, ip6_address_t * ip6_dst)
{
  fip64_ip4key_t key;
  key.fixed = ip4->dst_address;
  key.table_id = ip4->table_id;

  // search mapping in configured FIPs
  uword *p = hash_get_mem(fip64_main->fixed4_mapping_hash, &key);
  if (!p)
  {
    // no such fip configured
    return false;
  }

  fip64_mapping_t *mapping = (fip64_mapping_t*) *p;
  p = hash_get_mem(mapping->ip4_ip6_hash, &ip4->src_address);
  if (p)
  {
    *ip6_dst = mapping->fip6;
    *ip6_src = *(ip6_address_t*) *p;
    return true;
  }
  return false;
}

static void
fip64_add_del_ip4_adjacency(fip64_main_t * fip64_main,
                            ip4_address_t * ip4nh,
                            u32 prefix,
                            u32 add_del_flag, u32 table_id)
{
  if (fip64_main->testing) return;

  ip4_add_del_route_args_t args4;
  ip_adjacency_t adj;

  // Init IP adjancency.
  memset(&adj, 0, sizeof(adj));
  adj.explicit_fib_index = ~0;
  adj.lookup_next_index = IP_LOOKUP_NEXT_FIP64;

  // Create IPv4 adjancency.
  memset(&args4, 0, sizeof(args4));
  args4.table_index_or_table_id = table_id;
  args4.flags = add_del_flag;
  args4.dst_address = *ip4nh;
  args4.dst_address_length = prefix;
  args4.adj_index = ~0;
  args4.add_adj = &adj;
  args4.n_add_adj = 1;
  ip4_add_del_route (fip64_main->ip4_main, &args4);
}

static void
fip64_add_del_ip6_adjacency(fip64_main_t * fip64_main,
                            ip6_address_t * ip6nh, u32 add_del_flag)
{
  if (fip64_main->testing) return;

  ip6_add_del_route_args_t args6;
  ip_adjacency_t adj;

  // Init IP adjancency.
  memset(&adj, 0, sizeof(adj));
  adj.explicit_fib_index = ~0;
  adj.lookup_next_index = IP_LOOKUP_NEXT_FIP64;

  // Create IPv6 adjancency.
  memset(&args6, 0, sizeof(args6));
  args6.table_index_or_table_id = 0;
  args6.flags = add_del_flag;
  args6.dst_address = *ip6nh;
  args6.dst_address_length = 128;
  args6.adj_index = ~0;
  args6.add_adj = &adj;
  args6.n_add_adj = 1;
  ip6_add_del_route (fip64_main->ip6_main, &args6);
}

static u8
derive_net_prefix_from_range(ip4_address_t start, ip4_address_t end)
{
  u32 diff = clib_net_to_host_u32(end.as_u32)
           ^ clib_net_to_host_u32(start.as_u32);
  if (diff)
  {
    u32 msb = __builtin_clz(diff);
    return msb != 31? msb : 30;
  }
  return 32;
}

/**
* Deletes existing fip6
*
* Removes ipv6 adjacency for the fip. If the fip6 is the last one for given
* tenant, then also deletes ipv4 adjacency of the tenant
*/
clib_error_t *
fip64_delete(fip64_main_t *fip64_main,
             ip6_address_t *fip6)
{
  uword *p = hash_get_mem(fip64_main->fip6_mapping_hash, fip6);
  if (p == 0) {
    return clib_error_return (0, "Non-existing FIP64: %U", format_ip6_address, fip6);
  }

  fip64_mapping_t *old_mapping = (fip64_mapping_t*) *p;
  fip64_tenant_t *tenant = old_mapping->tenant;
  CLIB_ERROR_ASSERT( tenant != NULL );

  hash_unset(fip64_main->fip6_mapping_hash, fip6);

  hash_unset(fip64_main->fixed4_mapping_hash, &old_mapping->ip4);

  fip64_del_all_mappings(old_mapping);
  clib_mem_free(old_mapping);

  fip64_add_del_ip6_adjacency(fip64_main,
                  &old_mapping->fip6, IP4_ROUTE_FLAG_DEL);

  if (! --tenant->num_references)
  {
    fip64_add_del_ip4_adjacency(fip64_main,
                      &tenant->pool_start,
                      derive_net_prefix_from_range(tenant->pool_start,
                                                   tenant->pool_end),
                      IP4_ROUTE_FLAG_DEL,
                      tenant->table_id);

    hash_unset (fip64_main->vrf_tenant_hash, &tenant->table_id);
    clib_warning ("Removed pool[%d] %U",
                  tenant->table_id,
                  format_pool_range, tenant->pool);
    fip64_pool_free (tenant->pool);
    clib_mem_free (tenant);
  }

  return 0;
}

/*
 * Update a mapping:
 *
 *  - If old mapping to IP4 exists, deletes it (return non-zero)
 *  - If new mapping is IP4 is given, add it
 *
 * Returns 0 if no old mapping is found
 */
clib_error_t *
fip64_add(fip64_main_t *fip64_main,
          ip6_address_t *fip6,
          ip4_address_t fixed4,
          ip4_address_t pool_start,
          ip4_address_t pool_end,
          u32 table_id)
{
  /* check that tenant can be created beforehand */
  uword *p = hash_get_mem(fip64_main->vrf_tenant_hash, &table_id);
  fip64_tenant_t *tenant = p? (fip64_tenant_t*)*p : 0;
  bool pool_passed = pool_end.as_u32 != 0;

  // If creating a tenant, it needs a pool
  if (!tenant && !pool_passed)
  {
    return clib_error_return (0, "VRF table %u has no pool associated"
                                 " and none was specified.", table_id);
  }

  // a FIP6 must be unique. Can't be used twice even for different tenants
  if (0 != hash_get_mem(fip64_main->fip6_mapping_hash, fip6))
  {
    return clib_error_return (0, "Address %U is already mapped."
                                 " Delete it first", format_ip6_address, fip6);
  }

  /* a (fixed4, table_id) pair must be unique. Can't associate a fixed ip
   * to two or more fips on the same tenant.
   * It's technically possible, but will make 4->6 translation more complicated.
   */
  fip64_ip4key_t ip4key;
  ip4key.fixed = fixed4;
  ip4key.table_id = table_id;
  if (0 != hash_get_mem(fip64_main->fixed4_mapping_hash, &ip4key))
  {
    return clib_error_return (0, "Address %U is already mapped"
                                 " in VRF table %u. Delete it first",
                                 format_ip4_address, &fixed4,
                                 table_id);
  }

  /* Add new mapping and adjacency */

  fip64_mapping_t *mapping = clib_mem_alloc(sizeof(fip64_mapping_t));
  memset(mapping, 0, sizeof(fip64_mapping_t));

  mapping->fip6 = *fip6;
  mapping->ip4.fixed = fixed4;
  mapping->ip4.table_id = table_id;

  if (tenant == NULL)
  {
    // create new tenant

    tenant = (fip64_tenant_t*) clib_mem_alloc(sizeof(fip64_tenant_t));
    memset(tenant, 0, sizeof(fip64_tenant_t));
    tenant->table_id = table_id;
    tenant->num_references = 1;
    tenant->pool_start = pool_start;
    tenant->pool_end = pool_end;
    tenant->pool = fip64_pool_alloc(pool_start, pool_end);
    CLIB_ERROR_ASSERT (tenant->pool != NULL);
    hash_set_mem(fip64_main->vrf_tenant_hash, &tenant->table_id, tenant);

    fip64_add_del_ip4_adjacency(fip64_main,
                                &tenant->pool_start,
                                derive_net_prefix_from_range(tenant->pool_start,
                                                           tenant->pool_end),
                                IP4_ROUTE_FLAG_ADD,
                                tenant->table_id);
  }
  else
  {
    // existing tenant

    tenant->num_references ++;
    fip64_pool_t *pool = tenant->pool;

    if (pool_passed
        && (clib_net_to_host_u32(pool_start.as_u32) != pool->start_address
          || clib_net_to_host_u32(pool_end.as_u32) != pool->end_address))
      {
        clib_warning ("Passed pool parameters don't match previously created "
                      "pool for table %d (%U). Ignoring",
                      tenant->table_id,
                      format_pool_range, pool);
      }
  }

  mapping->tenant = tenant;

 clib_warning ("Using pool[%d] = %U", tenant->table_id,
              format_pool_range, tenant->pool);

  mapping->ip6_ip4_hash = hash_create_mem(0, sizeof(ip6_address_t), sizeof(ip4_address_t));
  mapping->ip4_ip6_hash = hash_create_mem(0, sizeof(ip4_address_t), sizeof(ip6_address_t));
  hash_set_mem(fip64_main->fip6_mapping_hash, &mapping->fip6, mapping);

  fip64_add_del_ip6_adjacency(fip64_main, &mapping->fip6, IP6_ROUTE_FLAG_ADD);
  hash_set_mem(fip64_main->fixed4_mapping_hash, &mapping->ip4, mapping);

  return 0;
}

static clib_error_t*
fip64_add_command_fn (vlib_main_t * vm, unformat_input_t * input,
                      vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  ip6_address_t fip6;
  ip4_address_t fixed4,
                pool_start,
                pool_end;
  u32 host_pool_start = 0,
      host_pool_end = 0;

  u32 table_id = 0;
  pool_start.as_u32 = 0;
  pool_end.as_u32 = 0;

  bool got_ips = unformat (line_input, "%U %U", unformat_ip6_address, &fip6,
                           unformat_ip4_address, &fixed4);
  unformat (line_input, "pool %U %U", unformat_ip4_address,
                                      &pool_start,
                                      unformat_ip4_address,
                                      &pool_end);
  unformat (line_input, "table %d", &table_id);
  bool at_end = unformat_check_input (line_input) == UNFORMAT_END_OF_INPUT;

  unformat_free (line_input);

  if (!got_ips || !at_end)
  {
    return clib_error_return (0, "invalid input: expected <ip6_fip6> <ip4_fixed4> [pool <ip4_pool_start> <ip4_pool_end>] [table <n>]");
  }

  host_pool_start = clib_net_to_host_u32(pool_start.as_u32);
  host_pool_end = clib_net_to_host_u32(pool_end.as_u32);
  if (host_pool_end && host_pool_end < host_pool_start) {
      return clib_error_return_code(0, 1, 0, "Pool end must be at least pool \
start, got: %U - %U", format_ip4_address, &host_pool_start,
                      format_ip4_address, &host_pool_end);
  }
  return fip64_add(&_fip64_main,
                   &fip6,
                   fixed4,
                   pool_start,
                   pool_end,
                   table_id);
}

static clib_error_t*
fip64_del_command_fn (vlib_main_t * vm, unformat_input_t * input,
                      vlib_cli_command_t * cmd)
{
  unformat_input_t _line_input, *line_input = &_line_input;
  ip6_address_t fip6;

  if (!unformat_user (input, unformat_line_input, line_input))
    return 0;

  while (unformat_check_input (line_input) != UNFORMAT_END_OF_INPUT)
  {
      if ( !unformat (line_input, "%U", unformat_ip6_address, &fip6))
      {
        unformat_free (line_input);
        return clib_error_return (0, "invalid input: expected  <ip6_fip6>");
      }

      clib_error_t *error = fip64_delete(&_fip64_main, &fip6);
      if (error != 0)
      {
        clib_warning("Error deleting %U: %U",
                     format_ip6_address, &fip6,
                     format_clib_error, error);
      }

  }
  unformat_free (line_input);

  return 0;
}

static clib_error_t*
fip64_show_command_fn (vlib_main_t * vm, unformat_input_t * input,
                      vlib_cli_command_t * cmd)
{
  vlib_cli_output (vm, "VRF pools\n");
  vlib_cli_output (vm, "%-10s%-32s%-20s%-10s\n",
                   "TABLE ID", "SRC IP4 POOL", "ADDRESSES LEFT", "REF COUNT");
  uword k, v;
  hash_foreach(k, v, _fip64_main.vrf_tenant_hash,                             \
    u8 * s = 0;                                                               \
    u32 table_id = *(u32*) k;                                                 \
    fip64_tenant_t * tenant = (fip64_tenant_t*) v;                            \
    s = format (s, "%-10u%-32U%-20u%-10u\n",                                  \
                   table_id,                                                  \
                   format_pool_range, tenant->pool,                           \
                   fip64_pool_available(tenant->pool),                        \
                   tenant->num_references);                                   \
    vlib_cli_output(vm, (char*) s);                                           \
    vec_free(s);
  );

  vlib_cli_output (vm, "\nDestination IP6\n");
  vlib_cli_output (vm, "%-10s%-40s%-32s\n",
                   "TABLE ID", "DST IP6", "DST IP4");
  hash_foreach(k, v, _fip64_main.fip6_mapping_hash,                           \
    u8 * s = 0;                                                               \
    ip6_address_t *fip = (ip6_address_t*) k;                                  \
    fip64_mapping_t * mapping  = (fip64_mapping_t*) v;                        \
    s = format (s, "%-10u%-40U%-32U\n",                                       \
                   mapping->tenant->table_id,                                 \
                   format_ip6_address, fip,                                   \
                   format_ip4_address, &mapping->ip4.fixed);                  \
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
 * hash maps in the current implementation. Some information can be obtained
 * from 'show ip fib' and 'show ip6 fib' commands
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
 * and ip4 routing tables. It also allows to specify the VRF table for v4
 * adjacency
 * WARNING: we do not keep track of reference counts on the adjacencies
 * added. We will add support for this in later stages.
 */
/* *INDENT-OFF* */
VLIB_CLI_COMMAND(fip64_add_command, static) = {
  .path = "fip64 add",
  .short_help = "<ip6_fip6> <ip4_fixed4> [pool <ip4_pool_start> <ip4_pool_end>] [table <n>]\n\
\t\t\t\t pool can be omitted if there is already one specified for given table; default table is 0",
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
  .short_help = "<ip6_fip6>",
  .function = fip64_del_command_fn,
};
/* *INDENT-ON* */

/* *INDENT-OFF* */
VLIB_INIT_FUNCTION(fip64_init)
/* *INDENT-ON* */

/*
 * fd.io coding-style-patch-verification: ON
 *
 * Local Variables:
 * eval: (c-set-style "gnu")
 * indent-tabs-mode: nil
 * End:
 */
