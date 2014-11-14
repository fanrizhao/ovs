/*-
 * Copyright (c) 2014 Jong Hun Han
 * Copyright (c) 2014 SRI International
 * All rights reserved.
 *
 * This software was developed by SRI International and the University of
 * Cambridge Computer Laboratory under DARPA/AFRL contract FA8750-11-C-0249
 * ("MRC2"), as part of the DARPA MRC research programme.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/* This file contains the ofproto implementation for the Blueswitch
 * hardware. */

#include <errno.h>
#include <config.h>

#include "shash.h"
#include "vlog.h"
#include "ofproto/ofproto-provider.h"
#include "nf10_cfg.h"

#define SINGLE_TABLE
#include "table_cfg.h"

#define DATAPATH_TYPE "blueswitch"

VLOG_DEFINE_THIS_MODULE(blueswitch);

const struct ofproto_class ofproto_blueswitch_class;

struct ofproto_blueswitch {
    struct hmap_node all_ofproto_dpifs_node; /* In 'all_ofproto_dpifs'. */
    struct ofproto up;

    /* top-level switch configuration */
    struct bs_info *bs_info;
};

static inline struct ofproto_blueswitch *
ofproto_blueswitch_cast(const struct ofproto *ofproto)
{
    ovs_assert(ofproto->ofproto_class == &ofproto_blueswitch_class);
    return CONTAINER_OF(ofproto, struct ofproto_blueswitch, up);
}

/* Factory functions. */

static void
init(const struct shash *iface_hints)
{
    struct shash_node *node;

    SHASH_FOR_EACH(node, iface_hints) {
        const struct iface_hint *hint = node->data;

        VLOG_WARN("iface_hint:  name:%s  type:%s  port:%d",
                  hint->br_name, hint->br_type, hint->ofp_port);
    }
}

static void
enumerate_types(struct sset *types)
{
    VLOG_WARN("enumerate_types: adding %s:", DATAPATH_TYPE);
    sset_add(types, DATAPATH_TYPE);
}

static int
enumerate_names(const char *type, struct sset *names)
{
    VLOG_WARN("enumerate_names(type=%s):", type);
    /* TODO */
    return 0;
}

static const char *
port_open_type(const char *datapath_type, const char *port_type)
{
    VLOG_WARN("port_open_type(datapath_type=%s,port_type=%s)", datapath_type, port_type);
    return NULL;
}

/* Type functions. */

static int
del(const char *type, const char *name)
{
    VLOG_WARN("del(type=%s,name=%s)", type, name);
    return -1;
}

static struct ofproto *
alloc(void)
{
    struct ofproto_blueswitch *ofp = xmalloc(sizeof *ofp);
    return &ofp->up;
}

static void
dealloc(struct ofproto *ofproto)
{
    struct ofproto_blueswitch *ofp = ofproto_blueswitch_cast(ofproto);
    free(ofp);
}

static int
construct(struct ofproto *ofproto_)
{
    struct ofproto_blueswitch *ofproto = ofproto_blueswitch_cast(ofproto_);
    ofproto->bs_info = &bsi_table;
}

static void
destruct(struct ofproto *ofproto_)
{
    struct ofproto_blueswitch *ofproto = ofproto_blueswitch_cast(ofproto_);
}

const struct ofproto_class ofproto_blueswitch_class = {
    /* Factory Functions */

    .init = init,
    .enumerate_types = enumerate_types,
    .enumerate_names = enumerate_names,
    .del = del,
    .port_open_type = port_open_type,

    /* Top-Level type Functions */

    .type_run = NULL,
    .type_wait = NULL,

    /* Top-level ofproto Functions */

    /* construction/destruction */
    .alloc = alloc,
    .construct = construct,
    .destruct = destruct,
    .dealloc = dealloc,

    .run = NULL,
    .wait = NULL,
    .get_memory_usage = NULL,
    .type_get_memory_usage = NULL,
    .flush = NULL,

    /* ofport Functions */

    .port_alloc = NULL,
    .port_construct = NULL,
    .port_destruct = NULL,
    .port_dealloc = NULL,
    .port_modified = NULL,
    .port_reconfigured = NULL,
    .port_query_by_name = NULL,
    .port_add = NULL,
    .port_del = NULL,
    .port_get_stats = NULL,

    /* Port iteration functions */
    .port_dump_start = NULL,
    .port_dump_next = NULL,
    .port_dump_done = NULL,

    .port_poll = NULL,
    .port_poll_wait = NULL,
    .port_is_lacp_current = NULL,

    /* OpenFlow Rule Functions */

    .rule_choose_table = NULL,

    /* Rule lifecycle functions */
    .rule_alloc = NULL,
    .rule_construct = NULL,
    .rule_insert = NULL,
    .rule_delete = NULL,
    .rule_destruct = NULL,
    .rule_dealloc = NULL,

    .rule_get_stats = NULL,

    .rule_execute = NULL,
    .rule_premodify_actions = NULL,
    .rule_modify_actions = NULL,

    .set_frag_handling = NULL,

    .packet_out = NULL,

    /* OFPP_NORMAL configuration */

    .set_netflow = NULL,
    .get_netflow_ids = NULL,
    .set_sflow = NULL,
    .set_ipfix = NULL,

    /* connectivity fault management */
    .set_cfm = NULL,
    .cfm_status_changed = NULL,
    .get_cfm_status = NULL,

    .set_bfd = NULL,
    .bfd_status_changed = NULL,
    .get_bfd_status = NULL,

    /* spanning tree protocol (STP) */
    .set_stp = NULL,
    .get_stp_status = NULL,
    .set_stp_port = NULL,
    .get_stp_port_status = NULL,
    .get_stp_port_stats = NULL,

    /* rapid STP */
    .set_rstp = NULL,
    .get_rstp_status = NULL,
    .set_rstp_port = NULL,
    .get_rstp_port_status = NULL,

    /* QoS */
    .set_queues = NULL,

    /* bundles (OVSDB Ports) */
    .bundle_set = NULL,
    .bundle_remove = NULL,

    /* mirrors */
    .mirror_set = NULL,
    .mirror_get_stats = NULL,

    .set_flood_vlans = NULL,
    .is_mirror_output_bundle = NULL,
    .forward_bpdu_changed = NULL,
    .set_mac_table_config = NULL,
    .set_mcast_snooping = NULL,
    .set_mcast_snooping_port = NULL,

    .set_realdev = NULL,

    /* OpenFlow meter functions */

    .meter_get_features = NULL,
    .meter_set = NULL,
    .meter_get = NULL,
    .meter_del = NULL,

    /* OpenFlow 1.1+ groups */

    .group_alloc = NULL,
    .group_construct = NULL,
    .group_destruct = NULL,
    .group_dealloc = NULL,
    .group_modify = NULL,
    .group_get_stats = NULL,

    /* Datapath information */

    .get_datapath_version = NULL,
};
