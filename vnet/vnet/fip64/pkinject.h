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

#ifndef included_pkinject_h
#define included_pkinject_h

#include <vnet/vnet.h>

typedef struct {
  vlib_main_t *vm; /* whatever this is, is needed everywhere */
  u32 target_node_index; /* index for the node receiving the packets */
  u32 sw_if_index[VLIB_N_RX_TX]; /* source and dest devices (or table ids) */
  vlib_frame_t *current_frame; /* to store packets until flushed */
} pkinject_t;

#define PKINJECT_FLAG_FLUSH (1 << 0)
#define PKINJECT_FLAG_TRACE (1 << 1)

/* prototype packet generation callback
 * @param buffer   buffer where to write the packet.
 *                 must include ip header and everything else.
 * @param context  opaque context passed to pkinject_by_callback
 *
 * @return the size of the packet generated, max 64k.
 */
typedef u16 ( * pkinject_generator_t ) ( u8 *buffer, void *context );

/* pkinject_alloc
 * allocates a packet injector
 * @param target_node_index index of node which will receive the packets.
 *                    (see vlib_get_node_by_name or vnet_get_sup_hw_interface)
 * @param rx_if_index index of interface the packet was received from?
 *                    Or table id. Zero seems good.
 * @param tx_if_index vrf table id the packets will be routed to.
 *
 * @return a pkinject_t object, or NULL if there is a failure
 */
pkinject_t*
pkinject_alloc (vlib_main_t *vm,
                u32 target_node_index,
                u32 rx_if_index,
                u32 tx_if_index);

/* pkinject_by_index
 * Store a packet for injection given it's buffer index.
 *
 * @param buffer_index the vlib_buffer index (see vlib_buffer_alloc).
 * @param flags see PKINJECT_FLAGs
 */
void
pkinject_by_index (pkinject_t *p,
                   u32 buffer_index,
                   u8 flags);

/* pkinject_by_callback
 * Generate a packet by using the supplied callback, and store it
 * for injection.
 *
 * @param callback function to generate the packet.
 * @param context Opaque context passed to the generator.
 * @param flags see PKINJECT_FLAG_xxx
 */
void
pkinject_by_callback(pkinject_t *p,
                     pkinject_generator_t callback,
                     void *context,
                     u8 flags);

/* pkinject_flush
 * inject all pending packets
 */
void
pkinject_flush(pkinject_t *p);

/* pkinject_release
 * frees the pkinject structure.
 * Warning: unflushed packets are dropped
 */
void
pkinject_release (pkinject_t* p);

#endif // included_pkinject_h
