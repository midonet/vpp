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
#include "flowstate.h"

extern fip64_main_t _fip64_main;


typedef enum
{
  CONTROL_FIP64_NEXT_DROP,
  CONTROL_FIP64_N_NEXT,
} lisp_cp_lookup_next_t;


static char*
validate_message (fip64_flowstate_msg_t *msg, u16 length)
{
  if (length != sizeof(fip64_flowstate_msg_t))
  {
    return "Wrong size";
  }

  if (msg->version < FLOWSTATE_VERSION_MIN)
  {
    return "Version too old";
  }

  if (msg->version > FLOWSTATE_VERSION_MAX)
  {
    return "Version too new";
  }

  int operation = fip64_flowstate_get_op(msg);

  if (operation != FLOWSTATE_OP_ADD && operation != FLOWSTATE_OP_DEL)
  {
    return "Unsupported operation";
  }

  return NULL;
}

static void
log_mapping (char *label, fip64_flowstate_msg_t *msg, u32 id)
{
  u8 operation = fip64_flowstate_get_op (msg);
  u32 vni = clib_net_to_host_u32 (msg->vni);

  clib_warning ("[context:%u] %s [%s %U -> %U for %U vni %X]",
    id, label,
    operation == FLOWSTATE_OP_ADD? "add" : "del",
    format_ip6_address, &msg->client_ipv6,
    format_ip4_address, &msg->allocated_ipv4,
    format_ip4_address, &msg->fixed_ipv4,
    vni);
}

static bool
flowstate_add_mapping (fip64_main_t *main,
                       fip64_flowstate_msg_t *msg,
                       fip64_tenant_t *tenant,
                       u32 context)
{
  uword *p = hash_get_mem(tenant->ip6_ip4_hash, &msg->client_ipv6);
  if (p)
  {
    /* already mapped. Overwrite if it's a remote mapping, fail if
       it's mapped locally. */
    fip64_ip6_ip4_value_t *existing4 = (fip64_ip6_ip4_value_t*)*p;

    if (existing4->ip4_src.as_u32 == msg->allocated_ipv4.as_u32)
    {
      log_mapping ("Already mapped", msg, context);
      return false;
    }

    if (!fip64_pool_contains (tenant->pool, existing4->ip4_src))
    {
      /* remove existing mapping */
      log_mapping ("Overwrite existing IPv6", msg, context);
      p = hash_get_mem(tenant->ip4_ip6_hash, &existing4->ip4_src);
      fip64_ip4_ip6_value_t *existing6 = (fip64_ip4_ip6_value_t*)*p;

      /* We should never be removing a mapping inside the LRU */
      CLIB_ERROR_ASSERT (existing4->lru_position == ~0);
      CLIB_ERROR_ASSERT (existing6->lru_position == ~0);

      fip64_remove_mapping (tenant, existing6, existing4);
    }
    else
    {
      /* ipv6 client has been mapped locally. */
      log_mapping ("Client mapped to local pool", msg, context);
      return false;
    }
  }

  /* check if we have a different mapping using that IPv4 address */
  p = hash_get_mem(tenant->ip4_ip6_hash, &msg->allocated_ipv4);
  if (p)
  {
    fip64_ip4_ip6_value_t *conflict6 = (fip64_ip4_ip6_value_t*)*p;
    p = hash_get_mem(tenant->ip6_ip4_hash, &conflict6->ip6_src);
    fip64_ip6_ip4_value_t *conflict4 = (fip64_ip6_ip4_value_t*)*p;

    /* this mapping can't be in the LRU because we've checked already that
       the mapped address is outside of our pool */
    CLIB_ERROR_ASSERT (conflict4->lru_position == ~0);
    CLIB_ERROR_ASSERT (conflict6->lru_position == ~0);

    fip64_remove_mapping (tenant, conflict6, conflict4);

    log_mapping("Overwrite existing IPv4", msg, context);
  }

  /* add the mapping */

  fip64_ip6_ip4_value_t ip6_value;
  fip64_ip4_ip6_value_t ip4_value;

  ip6_value.ip4_src = msg->allocated_ipv4;
  ip4_value.ip6_src = msg->client_ipv6;
  ip6_value.lru_position = ip4_value.lru_position = ~0;

  clib_error_t *err;
  if ( (err=fip64_add_mapping (tenant, &ip4_value, &ip6_value)) != NULL)
  {
    log_mapping("Failed saving", msg, context);
    return false;
  }

  log_mapping ("Saved mapping", msg, context);
  return true;
}

static bool
flowstate_del_mapping (fip64_main_t *main,
                       fip64_flowstate_msg_t *msg,
                       fip64_tenant_t *tenant,
                       u32 context)
{
  uword *p = hash_get_mem(tenant->ip6_ip4_hash, &msg->client_ipv6);
  if (!p)
  {
    /* not mapped. Nothing to delete */
    log_mapping ("Not mapped", msg, context);
    return false;
  }

  /*
   * mapping exists. Validate fields
   */

  fip64_ip6_ip4_value_t *existing4 = (fip64_ip6_ip4_value_t*)*p;

  if (existing4->ip4_src.as_u32 != msg->allocated_ipv4.as_u32)
  {
    log_mapping ("Mapped address doesn't match", msg, context);
    return false;
  }

  /* remove existing mapping */
  p = hash_get_mem(tenant->ip4_ip6_hash, &existing4->ip4_src);
  fip64_ip4_ip6_value_t *existing6 = (fip64_ip4_ip6_value_t*)*p;

  /* Removed mapping should never be inside the LRU */
  CLIB_ERROR_ASSERT (existing4->lru_position != ~0);
  CLIB_ERROR_ASSERT (existing6->lru_position != ~0);

  fip64_remove_mapping (tenant, existing6, existing4);

  log_mapping ("Removed mapping", msg, context);
  return true;
}

bool
fip64_flowstate_message (fip64_main_t *main, u8 *data, u16 length)
{
  static u32 context = 0;
  ++ context;

  fip64_flowstate_msg_t *msg = (fip64_flowstate_msg_t*) data;
  char *error = validate_message (msg, length);
  if (error)
  {
    clib_warning ("Discarded flowstate message: %s", error);
    return false;
  }

  log_mapping("Received mapping", msg, context);

  int operation = fip64_flowstate_get_op(msg);
  u32 vni = clib_net_to_host_u32 (msg->vni);

  // search for tenant by VNI
  uword *p = hash_get_mem(main->vni_tenant_hash, &vni);
  if (!p)
  {
    // no such VNI
    log_mapping("Unknown VNI", msg, context);
    return false;
  }

  fip64_tenant_t *tenant = (fip64_tenant_t*) *p;

  // Check that fixed IPv4 belongs to this tenant
  fip64_ip4key_t ip4key;
  memset(&ip4key, 0, sizeof(ip4key));
  ip4key.fixed = msg->fixed_ipv4;
  ip4key.table_id = tenant->table_id;

  p = hash_get_mem (main->fixed4_mapping_hash, &ip4key);

  if (p == 0 || ((fip64_mapping_t*)*p)->tenant != tenant)
  {
    log_mapping ("Wrong fixed IPv4", msg, context);
    return false;
  }

  if (fip64_pool_contains (tenant->pool, msg->allocated_ipv4))
  {
    // message from self?
    log_mapping("Allocated address is in local pool", msg, context);
    return false;
  }

  switch (operation)
  {
    case FLOWSTATE_OP_ADD:
      return flowstate_add_mapping(main, msg, tenant, context);

    case FLOWSTATE_OP_DEL:
      return flowstate_del_mapping(main, msg, tenant, context);

    default:
      /* validate_message should check for all supported operations */
      CLIB_ERROR_ASSERT (false);
  }

  return false;
}

static uword
flowstate_fip64 (vlib_main_t *vm, vlib_node_runtime_t *node, vlib_frame_t *frame)
{
  u32 n_left_from, next_index, * from, * to_next;
  from = vlib_frame_vector_args (frame);
  n_left_from = frame->n_vectors;

  next_index = node->cached_next_index;

  while (n_left_from > 0)
    {
      u32 n_left_to_next;

      vlib_get_next_frame (vm, node, next_index,
                           to_next, n_left_to_next);

      while (n_left_from > 0 && n_left_to_next > 0)
      {
        u32 bi0;
        vlib_buffer_t * b0;
        u8 * h0;

        bi0 = from[0];
        to_next[0] = bi0;
        from += 1;
        to_next += 1;
        n_left_from -= 1;
        n_left_to_next -= 1;

        b0 = vlib_get_buffer (vm, bi0);
        h0 = vlib_buffer_get_current (b0);

        fip64_flowstate_message (&_fip64_main, h0, b0->current_length);

        // discard packet
        vlib_buffer_free (vm, &bi0, 1);
      }
    }

  return frame->n_vectors;
}

static char *fip64_error_strings[] = {
#define _(sym,string) string,
  foreach_fip64_error
#undef _
};

/* *INDENT-OFF* */
VLIB_REGISTER_NODE(flowstate_fip64_node) = {
  .function = flowstate_fip64,
  .name = "flowstate-fip64",
  .vector_size = sizeof(u32),
  .format_trace = format_fip64_trace,
  .type = VLIB_NODE_TYPE_INTERNAL,

  .n_errors = FIP64_N_ERROR,
  .error_strings = fip64_error_strings,

  .n_next_nodes = CONTROL_FIP64_N_NEXT,
  .next_nodes = {
    [CONTROL_FIP64_NEXT_DROP] = "error-drop",
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
