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
  IP4_FIP64_NEXT_DROP,
  IP4_FIP64_N_NEXT
} ip4_fip64_next_t;

static_always_inline void
ip4_fip64_classify (vlib_buffer_t * p0, ip4_header_t * ip40,
                    u16 ip4_len0, i32 * dst_port0,
                    u8 * error0, ip4_fip64_next_t * next0)
{
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
    [IP4_FIP64_NEXT_DROP] = "error-drop",
  },
};
/* *INDENT-ON* */
