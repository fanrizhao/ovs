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

#include "vlog.h"
#include "dpif.h"
#include "ofproto/ofproto-provider.h"

#include "blueswitch-util.h"

#define BLUESWITCH_OVS_CONFIG
#define SINGLE_TABLE
#include "nf10_cfg.h"
#include "blueswitch_table_cfg.h"

#define DATAPATH_TYPE "blueswitch"
#define PORT_TYPE     "netfpga"

VLOG_DEFINE_THIS_MODULE(blueswitch);

const struct ofproto_class ofproto_blueswitch_class;

struct ofproto_blueswitch {
    struct hmap_node all_ofproto_dpifs_node; /* In 'all_ofproto_dpifs'. */
    struct ofproto  up;

    /* OVS ports indexed by their netdev name.  */
    struct shash    ports_by_name;
    /* TODO: FIXME: differentiate between dma and phys ports! */
    ofp_port_t      next_port;

    /* top-level switch configuration */
    struct bs_info  *bs_info;

    /* hardware switch state */
    struct s_state  s_state;
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
    sset_add(types, DATAPATH_TYPE);
}

static int
enumerate_names(const char *type OVS_UNUSED, struct sset *names OVS_UNUSED)
{
    /* TODO */
    return 0;
}

static int
del(const char *type, const char *name)
{
    VLOG_WARN("del(type=%s,name=%s)", type, name);
    return -1;
}

static const char *
port_open_type(const char *datapath_type, const char *port_type)
{
    VLOG_WARN("port_open_type(datapath_type=%s,port_type=%s)",
              datapath_type, port_type);
    return PORT_TYPE;
}

/* Top-level ofproto Functions */

static struct ofproto *
alloc(void)
{
    struct ofproto_blueswitch *ofp = xmalloc(sizeof *ofp);
    return &ofp->up;
}

static int
construct(struct ofproto *ofproto)
{
    int ret;
    struct ofproto_blueswitch *bswitch = ofproto_blueswitch_cast(ofproto);

    shash_init(&bswitch->ports_by_name);
    bswitch->next_port = 1;

    /* Read in switch configuration. */
    bswitch->bs_info = &bsi_table;

    /* Initialize handle to switch driver. */
    ret = open_switch(bswitch->bs_info);
    if (ret < 0) return ret;

    /* Configure number of switch ports. */
    ofproto_init_max_ports(ofproto, bswitch->bs_info->num_ports);

    /* Allocate space for tables. */
    ofproto_init_tables(ofproto, bswitch->bs_info->num_tcams);

    /* Allocate and initialize the table states. */

    bsw_initialize_switch_state(bswitch->bs_info, &bswitch->s_state);

    /* TODO:
     *
     * Each flow table will be initially empty, so ->construct() should delete
     * flows from the underlying datapath, if necessary, rather than populating
     * the tables.
     */

    return 0;
}

static void
destruct(struct ofproto *ofproto)
{
    struct ofproto_blueswitch *bswitch = ofproto_blueswitch_cast(ofproto);

    /* TODO:
     *
     * ->destruct() must also destroy all remaining rules in the ofproto's
     * tables, by passing each remaining rule to ofproto_rule_delete().
     */

    bsw_destroy_switch_state(&bswitch->s_state);

    close_switch(bswitch->bs_info);
    bswitch->bs_info = NULL;

    shash_destroy(&bswitch->ports_by_name);
}

static void
dealloc(struct ofproto *ofproto)
{
    struct ofproto_blueswitch *ofp = ofproto_blueswitch_cast(ofproto);
    free(ofp);
}

static int
run(struct ofproto *ofproto OVS_UNUSED)
{
     /* Performs any periodic activity required by 'ofproto'.  It should:
     *
     *   - Call connmgr_send_packet_in() for each received packet that missed
     *     in the OpenFlow flow table or that had a OFPP_CONTROLLER output
     *     action.
     *
     *   - Call ofproto_rule_expire() for each OpenFlow flow that has reached
     *     its hard_timeout or idle_timeout, to expire the flow.
     *
     * Returns 0 if successful, otherwise a positive errno value. */
    return 0;
}

static void
wait(struct ofproto *ofproto)
{
    /* Causes the poll loop to wake up when 'ofproto''s 'run' function needs to
     * be called, e.g. by calling the timer or fd waiting functions in
     * poll-loop.h.  */
    struct ofproto_blueswitch *ofp = ofproto_blueswitch_cast(ofproto);
    (void) ofp;
}

/* Table features */

static void
query_tables(struct ofproto *ofproto,
             struct ofputil_table_features *features,
             struct ofputil_table_stats *stats OVS_UNUSED)
{
    struct ofproto_blueswitch *ofp = ofproto_blueswitch_cast(ofproto);
    struct bs_info *bsi = ofp->bs_info;
    ovs_assert(ofproto->n_tables == bsi->num_tcams);
    for (int i = 0; i < ofproto->n_tables; i++) {
        struct tcam_info *tci = &bsi->tcams[i];
        struct ofputil_table_features *f = &features[i];
        f->metadata_match = tci->features.metadata_match;
        f->metadata_write = tci->features.metadata_write;
        f->miss_config    = tci->features.miss_config;
        f->max_entries    = tci->num_entries;

        /* Inherit the default .next for nonmiss and miss. */
        f->nonmiss.instructions = tci->features.nonmiss.instructions;
        f->miss.instructions    = tci->features.miss.instructions;
        f->nonmiss.write        = tci->features.nonmiss.write;
        f->miss.write           = tci->features.miss.write;
        f->nonmiss.apply        = tci->features.nonmiss.apply;
        f->miss.apply           = tci->features.miss.apply;

        ovs_assert(tci->num_fields < BLUESWITCH_MAX_TCAM_FIELDS);
        /* All Blueswitch tcam fields are matchable, maskable, and
         * wildcardable. */
        struct mf_bitmap fields = MF_BITMAP_INITIALIZER;
        for (int j = 0; j < tci->num_fields; j++) {
            bitmap_set1(fields.bm, tci->mf_fields[j]);
        }
        f->match = f->mask = f->wildcard = fields;
    }
}

/* ofport Functions */

static struct ofport *
port_alloc(void)
{
    struct ofport *p = xmalloc(sizeof(*p));
    return p;
}

static int
port_construct(struct ofport *ofport OVS_UNUSED)
{
    return 0;
}

static void
port_destruct(struct ofport *ofport OVS_UNUSED)
{
}

static void
port_dealloc(struct ofport *ofport)
{
    free(ofport);
}

static int
port_query_by_name(const struct ofproto *ofproto,
                   const char *devname, struct ofproto_port *port)
{
    VLOG_WARN("port_query_by_name(ofp=%s, devname=%s)",
              ofproto->name, devname);

    struct ofproto_blueswitch *s = ofproto_blueswitch_cast(ofproto);
    struct ofproto_port *p =
        (struct ofproto_port *) shash_find_data(&s->ports_by_name, devname);
    if (!p) return 1;

    port->name = xstrdup(p->name);
    port->type = xstrdup(p->type);
    port->ofp_port = p->ofp_port;

    return 0;
}

static int
port_add(struct ofproto *ofproto, struct netdev *netdev)
{
    VLOG_WARN("port_add: adding netdev %s of type %s",
              netdev_get_name(netdev), netdev_get_type(netdev));

    struct ofproto_blueswitch *bswitch = ofproto_blueswitch_cast(ofproto);
    struct ofproto_port *p = (struct ofproto_port *)xmalloc(sizeof *p);
    if (!p) return 1;

    p->name     = xstrdup(netdev_get_name(netdev));
    p->type     = xstrdup(netdev_get_type(netdev));
    p->ofp_port = (!strcmp(ofproto->name, p->name)
                   ? OFPP_LOCAL : bswitch->next_port++);

    shash_add(&bswitch->ports_by_name, p->name, p);
    return 0;
}

static int
port_del(struct ofproto *ofproto, ofp_port_t ofp_port)
{
    VLOG_WARN("port_del: deleting port %d", ofp_port);
    struct ofproto_blueswitch *bswitch = ofproto_blueswitch_cast(ofproto);

    struct shash_node *node, *next;
    SHASH_FOR_EACH_SAFE(node, next, &bswitch->ports_by_name) {
        struct ofproto_port *p = node->data;
        if (p->ofp_port == ofp_port) {
            free(p->name);
            free(p->type);
            free(p);
            shash_delete(&bswitch->ports_by_name, node);
        }
    }
    return 0;
}

static int
port_get_stats(const struct ofport *port,
                   struct netdev_stats *stats OVS_UNUSED)
{
    VLOG_WARN("port_get_stats: name:%s type:%s",
              netdev_get_name(port->netdev),
              netdev_get_type(port->netdev));
    return 0;
}

/* Port iteration functions */

struct port_dump_state {
    struct hmap_node *next;
    int count;
};

static int
port_dump_start(const struct ofproto *ofproto, void **statep)
{
    struct ofproto_blueswitch *bswitch = ofproto_blueswitch_cast(ofproto);
    struct port_dump_state *state = xzalloc(sizeof(struct port_dump_state));
    state->next = hmap_first(&bswitch->ports_by_name.map);
    *statep = state;
    return 0;
}

static int
port_dump_next(const struct ofproto *ofproto, void *state_,
               struct ofproto_port *port)
{
    struct ofproto_blueswitch *bswitch = ofproto_blueswitch_cast(ofproto);
    struct port_dump_state *state = state_;
    VLOG_WARN("port_dump_next(%d)", state->count);
    if (state->next == NULL) {
        return EOF;
    }

    struct shash_node *node = CONTAINER_OF(state->next, struct shash_node, node);
    struct ofproto_port *p = node->data;
    /* We retain ownership of p's fields, according ofproto-provider API. */
    *port = *p;

    state->next = hmap_next(&bswitch->ports_by_name.map, state->next);
    state->count++;
    return 0;
}

static int
port_dump_done(const struct ofproto *ofproto OVS_UNUSED, void *state_)
{
    struct port_dump_state *state = state_;
    free(state);
    return 0;
}

/* OpenFlow Rule Functions */

static enum ofperr
rule_choose_table(const struct ofproto *ofproto OVS_UNUSED,
                  const struct match *match OVS_UNUSED,
                  uint8_t *table_idp OVS_UNUSED)
{
    VLOG_WARN("rule_choose_table: match=%s",
              match_to_string(match, OFP_DEFAULT_PRIORITY));

    /* TODO: Convert the features supported by the tcams into the match form.
       Then compare that match to the one provided in order to select the table.

       In effect, we currently only support controllers that can explicitly
       specify the table for each rule.
    */
    return OFPERR_OFPFMFC_BAD_TABLE_ID;
}

struct rule_blueswitch {
    struct rule up;

    struct ovs_mutex stats_mutex;
    struct dpif_flow_stats stats OVS_GUARDED;
};

static struct rule_blueswitch *rule_blueswitch_cast(const struct rule *rule)
{
    return rule ? CONTAINER_OF(rule, struct rule_blueswitch, up) : NULL;
}

static struct rule *
rule_alloc(void) {
    struct rule_blueswitch *rule = xmalloc(sizeof *rule);
    return &rule->up;
}

static enum ofperr
rule_construct(struct rule *rule_)
    OVS_NO_THREAD_SAFETY_ANALYSIS
{
    struct rule_blueswitch *rule = rule_blueswitch_cast(rule_);
    ovs_mutex_init_adaptive(&rule->stats_mutex);
    rule->stats.n_packets = 0;
    rule->stats.n_bytes = 0;
    rule->stats.used = rule->up.modified;

    return 0;
}

static enum ofperr
rule_insert(struct rule *rule)
    OVS_REQUIRES(ofproto_mutex)
{
    ovs_mutex_lock(&rule->mutex);

    struct ofproto_blueswitch *bswitch = ofproto_blueswitch_cast(rule->ofproto);
    struct bs_info *bsi                = bswitch->bs_info;
    struct s_state *s_state            = &bswitch->s_state;

    ovs_assert(rule->table_id < bsi->num_tcams);

    const struct tcam_info *tcam = &bsi->tcams[rule->table_id];
    struct t_state *t_state      = s_state->table_states[rule->table_id];
    struct t_update *t_update    = s_state->table_updates[rule->table_id];

    /* Expand the compressed minimatch.  We can't directly use the compressed
       match, since the Blueswitch tables might use fields in a different order
       from the canonical order in minimatch.
    */
    struct match match;
    minimatch_expand(&rule->cr.match, &match);

    enum ofperr ret;
    struct t_entry_update *ent_update;
    ret = bsw_allocate_tcam_ent_update(t_update, TEM_UPDATE, &ent_update);
    if (ret) goto error;

    ret = bsw_extract_tcam_key(tcam, &match, &ent_update->key);
    if (ret) goto error;

    ret = bsw_extract_instruction(tcam, rule_get_actions(rule), &ent_update->instr);
    if (ret) goto error;

    /* XXX: TODO: Now program the darn switch.  Need to allocate an index for
     * the rule.
     */

error:
    ovs_mutex_unlock(&rule->mutex);
    return ret;
}

static void
rule_delete(struct rule *rule_)
    OVS_REQUIRES(ofproto_mutex)
{
    struct rule_blueswitch *rule = rule_blueswitch_cast(rule_);
    (void)rule;
}

static void
rule_destruct(struct rule *rule_)
{
    struct rule_blueswitch *rule = rule_blueswitch_cast(rule_);
    ovs_mutex_destroy(&rule->stats_mutex);
}

static void
rule_dealloc(struct rule *rule_)
{
    struct rule_blueswitch *rule = rule_blueswitch_cast(rule_);
    free(rule);
}

static void
rule_get_stats(struct rule *rule_, uint64_t *packet_count,
               uint64_t *byte_count, long long int *used)
    OVS_EXCLUDED(ofproto_mutex)
{
    struct rule_blueswitch *rule = rule_blueswitch_cast(rule_);
    ovs_mutex_lock(&rule->stats_mutex);
    *packet_count = rule->stats.n_packets;
    *byte_count = rule->stats.n_bytes;
    *used = rule->stats.used;
    ovs_mutex_unlock(&rule->stats_mutex);
}

const struct ofproto_class ofproto_blueswitch_class = {
    /* Factory Functions */

    .init = init,
    .enumerate_types = enumerate_types,
    .enumerate_names = enumerate_names,
    .del             = del,
    .port_open_type  = port_open_type,

    /* Top-Level type Functions */

    .type_run  = NULL,
    .type_wait = NULL,

    /* Top-level ofproto Functions */

    /* construction/destruction */
    .alloc     = alloc,
    .construct = construct,
    .destruct  = destruct,
    .dealloc   = dealloc,

    .run = run,
    .wait = wait,
    .get_memory_usage = NULL,
    .type_get_memory_usage = NULL,
    .flush = NULL,

    /* Table Features */
    .query_tables       = query_tables,

    /* ofport Functions */

    .port_alloc         = port_alloc,
    .port_construct     = port_construct,
    .port_destruct      = port_destruct,
    .port_dealloc       = port_dealloc,
    .port_modified      = NULL,
    .port_reconfigured  = NULL,
    .port_query_by_name = port_query_by_name,
    .port_add           = port_add,
    .port_del           = port_del,
    .port_get_stats     = port_get_stats,

    /* Port iteration functions */
    .port_dump_start = port_dump_start,
    .port_dump_next  = port_dump_next,
    .port_dump_done  = port_dump_done,

    .port_poll = NULL,
    .port_poll_wait = NULL,
    .port_is_lacp_current = NULL,

    /* OpenFlow Rule Functions */

    .rule_choose_table = rule_choose_table,

    /* Rule lifecycle functions */
    .rule_alloc = rule_alloc,
    .rule_construct = rule_construct,
    .rule_insert = rule_insert,
    .rule_delete = rule_delete,
    .rule_destruct = rule_destruct,
    .rule_dealloc = rule_dealloc,

    .rule_get_stats = rule_get_stats,

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
