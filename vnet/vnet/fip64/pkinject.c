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

#include "pkinject.h"

#include <assert.h>

pkinject_t*
pkinject_alloc (vlib_main_t *vm,
                u32 target_node_index,
                u32 rx_if_index,
                u32 tx_if_index)
{
  pkinject_t *p = clib_mem_alloc(sizeof(pkinject_t));

  p->vm = vm;
  p->target_node_index = target_node_index;
  p->sw_if_index[VLIB_RX] = rx_if_index;
  p->sw_if_index[VLIB_TX] = tx_if_index;
  p->current_frame = 0;
  return p;
}

void
pkinject_release (pkinject_t *p)
{
  if (p->current_frame)
  {
    /* I don't know how to release a frame that's been allocated
     * by vlib_get_frame_to_node.
     * there is vlib_frame_free, but it requires a node runtime.
     * Maybe this whole code shouldn't be run outside a node runtime
     * anyway.
     */
    // two choices:
    //clib_warning ("pkinject_release: Leaking packets. Flush them before releasing");
    // -or-
    //pkinject_flush (p);
    /* it doesn't matter much, as nodes are not freed, so this function will 
     * never be called in common usage */
  }
  clib_mem_free (p);
}

static void
pkinject_buffer (pkinject_t *p,
                 u32 buffer_index,
                 vlib_buffer_t *buffer,
                 u8 flags)
{
  vlib_main_t *vm = p->vm;
  vnet_buffer (buffer)->sw_if_index[VLIB_RX] = p->sw_if_index[VLIB_RX];
  vnet_buffer (buffer)->sw_if_index[VLIB_TX] = p->sw_if_index[VLIB_TX];

  if (flags & PKINJECT_FLAG_TRACE)
    buffer->flags |= VLIB_BUFFER_IS_TRACED;

  vlib_frame_t *frame = p->current_frame;
  if (frame == 0)
  {
    frame = vlib_get_frame_to_node (vm, p->target_node_index);
    CLIB_ERROR_ASSERT (frame != 0);

    frame->n_vectors = 0;
    p->current_frame = frame;
  }

  u16 index = frame->n_vectors ++;
  CLIB_ERROR_ASSERT (index <= VLIB_FRAME_SIZE );

  u32 *to_next = vlib_frame_vector_args (frame);
  to_next[index] = buffer_index;

  if ( (flags & PKINJECT_FLAG_FLUSH) || frame->n_vectors == VLIB_FRAME_SIZE )
  {
    pkinject_flush (p);
  }
}


void
pkinject_flush(pkinject_t *p)
{
  if (p->current_frame)
  {
    /* frame will be freed by target node */
    vlib_put_frame_to_node (p->vm, p->target_node_index, p->current_frame);
    p->current_frame = 0;
  }
}

void
pkinject_by_index (pkinject_t *p,
                   u32 buffer_index,
                   u8 flags)
{
  vlib_main_t *vm = p->vm;
  vlib_buffer_t *buffer = vlib_get_buffer (vm, buffer_index);
  CLIB_ERROR_ASSERT (buffer != 0);

  pkinject_buffer (p, buffer_index, buffer, flags);
}
void
pkinject_by_callback (pkinject_t *p,
                      pkinject_generator_t callback,
                      void *context,
                      u8 flags)
{
  vlib_main_t *vm = p->vm;
  u32 buffer_index,
      n_alloc_buffers = vlib_buffer_alloc (vm, &buffer_index, 1);

  /* buffer will be freed when processed by target node */
  CLIB_ERROR_ASSERT (n_alloc_buffers == 1);

  vlib_buffer_t *buffer = vlib_get_buffer (vm, buffer_index);

  u16 packet_size = (*callback) (vlib_buffer_get_current (buffer), context);
  buffer->current_length = packet_size;

  CLIB_ERROR_ASSERT (packet_size != 0);

  pkinject_buffer (p, buffer_index, buffer, flags);
}

