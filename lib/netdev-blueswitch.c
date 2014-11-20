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

#include <config.h>

#include "netdev-blueswitch.h"

#include <errno.h>

#include "packets.h"
#include "netdev-provider.h"
#include "vlog.h"

#include "nf10_cfg.h"

#define PORT_TYPE "netfpga"

VLOG_DEFINE_THIS_MODULE(netdev_netfpga);

struct netdev_blueswitch {
    struct netdev up;

    char *kernel_name;

    /* Protects all members below. */
    struct ovs_mutex mutex;

    uint8_t etheraddr[ETH_ADDR_LEN];
    struct in_addr in4;
    struct in_addr netmask;
    struct in6_addr in6;

    /* Switch config handles. */
    struct bs_info *bswitch;
};

static void netdev_blueswitch_run(void);

static bool
is_netdev_blueswitch_class(const struct netdev_class *netdev_class)
{
    return netdev_class->run == netdev_blueswitch_run;
}

static struct netdev_blueswitch *
netdev_blueswitch_cast(const struct netdev *netdev)
{
    ovs_assert(is_netdev_blueswitch_class(netdev_get_class(netdev)));

    return CONTAINER_OF(netdev, struct netdev_blueswitch, up);
}

static void
netdev_blueswitch_run(void)
{
}

static struct netdev *
netdev_blueswitch_alloc(void)
{
    struct netdev_blueswitch *netdev = xzalloc(sizeof *netdev);
    return &netdev->up;
}

static void netdev_blueswitch_dealloc(struct netdev *netdev_)
{
    struct netdev_blueswitch *netdev = netdev_blueswitch_cast(netdev_);
    free(netdev);
}

static int
netdev_blueswitch_construct(struct netdev *netdev_)
{
    VLOG_WARN("netdev_construct(netdev(name=%s))", netdev_get_name(netdev_));

    struct netdev_blueswitch *netdev = netdev_blueswitch_cast(netdev_);
    ovs_mutex_init(&netdev->mutex);

    /* TODO: open this somehow. */
    netdev->bswitch = NULL;

    return 0;
}

static void
netdev_blueswitch_destruct(struct netdev *netdev_)
{
    VLOG_WARN("netdev_destruct(netdev(name=%s))", netdev_get_name(netdev_));
    struct netdev_blueswitch *netdev = netdev_blueswitch_cast(netdev_);

    /* TODO: close/free this somehow */
    netdev->bswitch = NULL;

    ovs_mutex_destroy(&netdev->mutex);
}

static int
netdev_blueswitch_set_etheraddr(struct netdev *netdev_,
                                const uint8_t mac[ETH_ADDR_LEN] OVS_UNUSED)
{
    VLOG_WARN("netdev_set_etheraddr(netdev(name=%s))", netdev_get_name(netdev_));
    return EOPNOTSUPP;
}

static int
netdev_blueswitch_get_etheraddr(const struct netdev *netdev_,
                                uint8_t mac[ETH_ADDR_LEN] OVS_UNUSED)
{
    VLOG_WARN("netdev_get_etheraddr(netdev(name=%s))", netdev_get_name(netdev_));
    return EOPNOTSUPP;
}

static int
netdev_blueswitch_get_mtu(const struct netdev *netdev_, int *mtup OVS_UNUSED)
{
    VLOG_WARN("netdev_get_mtu(netdev(name=%s))", netdev_get_name(netdev_));
    return EOPNOTSUPP;
}

static int
netdev_blueswitch_get_carrier(const struct netdev *netdev_, bool *carrier OVS_UNUSED)
{
    VLOG_WARN("netdev_get_carrier(netdev(name=%s))", netdev_get_name(netdev_));
    return EOPNOTSUPP;
}

static int
netdev_blueswitch_get_stats(const struct netdev *netdev_, struct netdev_stats *stats OVS_UNUSED)
{
    VLOG_WARN("netdev_get_stats(netdev(name=%s))", netdev_get_name(netdev_));
    return EOPNOTSUPP;
}

static int
netdev_blueswitch_get_features(const struct netdev *netdev_,
                               enum netdev_features *current OVS_UNUSED, uint32_t *advertised OVS_UNUSED,
                               enum netdev_features *supported OVS_UNUSED, uint32_t *peer OVS_UNUSED)
{
    VLOG_WARN("netdev_get_features(netdev(name=%s))", netdev_get_name(netdev_));
    return EOPNOTSUPP;
}

static int
netdev_blueswitch_get_in4(const struct netdev *netdev_, struct in_addr *in4 OVS_UNUSED,
                          struct in_addr *netmask OVS_UNUSED)
{
    VLOG_WARN("netdev_get_in4(netdev(name=%s))", netdev_get_name(netdev_));
    return EOPNOTSUPP;
}

static int
netdev_blueswitch_set_in4(struct netdev *netdev_, struct in_addr addr OVS_UNUSED,
                          struct in_addr mask OVS_UNUSED)
{
    VLOG_WARN("netdev_set_in4(netdev(name=%s))", netdev_get_name(netdev_));
    return EOPNOTSUPP;
}

static int
netdev_blueswitch_get_in6(const struct netdev *netdev_, struct in6_addr *in6 OVS_UNUSED)
{
    VLOG_WARN("netdev_get_in6(netdev(name=%s))", netdev_get_name(netdev_));
    return EOPNOTSUPP;
}


static int
update_flags(struct netdev *netdev, enum netdev_flags off,
             enum netdev_flags on, enum netdev_flags *old_flags)
{
    VLOG_WARN("update_flags(netdev=%s): off=%d, on=%d", netdev_get_name(netdev), off, on);
    *old_flags = NETDEV_UP;
    return 0;
}

const struct netdev_class netdev_blueswitch_class =
{
    .type                   = PORT_TYPE,

    /* Top-Level Functions */

    .init                   = NULL,
    .run                    = netdev_blueswitch_run,
    .wait                   = NULL,

    /* netdev Functions */

    .alloc                  = netdev_blueswitch_alloc,
    .construct              = netdev_blueswitch_construct,
    .destruct               = netdev_blueswitch_destruct,
    .dealloc                = netdev_blueswitch_dealloc,

    .get_config             = NULL,
    .set_config             = NULL,
    .get_tunnel_config      = NULL,
    .get_numa_id            = NULL,
    .set_multiq             = NULL,

    .send                   = NULL,
    .send_wait              = NULL,

    .set_etheraddr          = netdev_blueswitch_set_etheraddr,
    .get_etheraddr          = netdev_blueswitch_get_etheraddr,
    .get_mtu                = netdev_blueswitch_get_mtu,
    .set_mtu                = NULL,
    .get_ifindex            = NULL,
    .get_carrier            = netdev_blueswitch_get_carrier,

    .get_carrier_resets     = NULL,
    .set_miimon_interval    = NULL,
    .get_stats              = netdev_blueswitch_get_stats,
    .get_features           = netdev_blueswitch_get_features,

    .set_advertisements     = NULL,
    .set_policing           = NULL,
    .get_qos_types          = NULL,
    .get_qos_capabilities   = NULL,
    .get_qos                = NULL,
    .set_qos                = NULL,
    .get_queue              = NULL,
    .set_queue              = NULL,
    .delete_queue           = NULL,
    .get_queue_stats        = NULL,
    .queue_dump_start       = NULL,
    .queue_dump_next        = NULL,
    .queue_dump_done        = NULL,
    .dump_queue_stats       = NULL,

    .get_in4                = netdev_blueswitch_get_in4,
    .set_in4                = netdev_blueswitch_set_in4,
    .get_in6                = netdev_blueswitch_get_in6,

    .add_router             = NULL,
    .get_next_hop           = NULL,
    .get_status             = NULL,
    .arp_lookup             = NULL,
    .update_flags           = update_flags,

    /* netdev_rxq Functions */

    .rxq_alloc              = NULL,
    .rxq_construct          = NULL,
    .rxq_destruct           = NULL,
    .rxq_dealloc            = NULL,
    .rxq_recv               = NULL,
    .rxq_wait               = NULL,
    .rxq_drain              = NULL,
};
