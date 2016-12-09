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

#ifndef included_fip64_flowstate_h
#define included_fip64_flowstate_h

struct _fip64_flowstate_msg_t {
  u8 version;
  u8 flags[3];
  u32 vni;
  ip6_address_t client_ipv6;
  ip4_address_t allocated_ipv4;
  ip4_address_t fixed_ipv4;
} __attribute__((__packed__));

#define FLOWSTATE_VERSION_MIN 1
#define FLOWSTATE_VERSION_MAX 1

#define FLOWSTATE_OP_ADD 0
#define FLOWSTATE_OP_DEL 1

#define fip64_flowstate_get_op(MSG) ( ((MSG)->flags[0] >> 6) )
#define fip64_flowstate_set_op(MSG, OP) ( (MSG)->flags[0] = ((OP) << 6) )

typedef struct _fip64_flowstate_msg_t fip64_flowstate_msg_t;

extern bool
fip64_flowstate_message (fip64_main_t*, u8*, u16);

#endif // included_fip64_flowstate_h
