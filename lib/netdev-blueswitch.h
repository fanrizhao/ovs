/*
 * Copyright (c) 2014 SRI International.
 *
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

#include "ofproto/ofproto-provider.h"

#define BLUESWITCH_OVS_CONFIG
#include "nf10_cfg.h"
#include "blueswitch_table_cfg.h"

bool is_netdev_blueswitch(const struct netdev *netdev);
struct netdev_blueswitch *netdev_blueswitch_cast(const struct netdev *netdev);

void netdev_blueswitch_set_ofport(struct netdev_blueswitch *netdev, ofp_port_t ofp_port);
