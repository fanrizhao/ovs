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

#include "blueswitch-util.h"

#include "dynamic-string.h"
#include "meta-flow.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(blueswitch_util);

enum t_entry_state {
  TE_EMPTY = 0,
  TE_OCCUPIED,
};

struct t_state {
    uint32_t                n_entries;
    enum t_entry_state      entries[];
};

struct t_update {
    struct t_state *        t_working;
    uint32_t                cmd_queue_len;
    uint32_t                next_cmd;           /* currently unused */
    struct t_entry_update   cmds[];
};

static void
bsw_tcam_key_init(struct bsw_tcam_key *key)
{
    memset(key, 0, sizeof *key);
}

enum ofperr
bsw_extract_tcam_key(const struct tcam_info *tcam,
                     const struct match *match,
                     struct bsw_tcam_key *key)
{
    {   struct ds ds;
        ds_init(&ds);
        match_format(match, &ds, 3);
        VLOG_DBG("   processing match:  %s", ds_cstr(&ds));
        ds_destroy(&ds);
    }

    ovs_assert(BLUESWITCH_MAX_TCAM_KEYLEN >= tcam->key_size);

    bsw_tcam_key_init(key);

    /* This is based on meta-flow.c:mf_get_value(). */

    for (int i = 0; i < tcam->num_fields; i++) {

        /* Ensure there is sufficient space. */
        enum mf_field_id id = tcam->mf_fields[i];
        const struct mf_field *f = mf_from_id(id);
        ovs_assert(key->n_valid_bytes + f->n_bytes <= 4 * tcam->key_size);

        VLOG_DBG("   extracting %d: %s for key", i, f->name);
        {   union mf_value v, m;
            mf_get(f, match, &v, &m);

            struct ds ds;
            ds_init(&ds);
            mf_format(f, &v, &m, &ds);
            VLOG_DBG("   field: %s", ds_cstr(&ds));
            ds_destroy(&ds);
        }
        /* TODO: XXX: Check endianness of all fields! */

        switch (id) {
        case MFF_ETH_SRC:
            ovs_assert(f->n_bytes == ETH_ADDR_LEN);

            memcpy(&key->key_buf[key->n_valid_bytes], match->flow.dl_src, ETH_ADDR_LEN);
            memcpy(&key->msk_buf[key->n_valid_bytes], match->wc.masks.dl_src, ETH_ADDR_LEN);
            key->n_valid_bytes += ETH_ADDR_LEN;
            break;

        case MFF_ETH_DST:
            ovs_assert(f->n_bytes == ETH_ADDR_LEN);

            memcpy(&key->key_buf[key->n_valid_bytes], match->flow.dl_dst, ETH_ADDR_LEN);
            memcpy(&key->msk_buf[key->n_valid_bytes], match->wc.masks.dl_dst, ETH_ADDR_LEN);
            key->n_valid_bytes += ETH_ADDR_LEN;
            break;

        case MFF_IPV4_SRC:
        {
            uint32_t *cursor;
            ovs_assert(f->n_bytes == sizeof *cursor);

            cursor = (uint32_t *)&key->key_buf[key->n_valid_bytes];
            *cursor = match->flow.nw_src;
            cursor = (uint32_t *)&key->msk_buf[key->n_valid_bytes];
            *cursor = match->wc.masks.nw_src;

            key->n_valid_bytes += f->n_bytes;
        }
        break;

        case MFF_IPV4_DST:
        {
            uint32_t *cursor;
            ovs_assert(f->n_bytes == sizeof *cursor);

            cursor = (uint32_t *)&key->key_buf[key->n_valid_bytes];
            *cursor = match->flow.nw_dst;
            cursor = (uint32_t *)&key->msk_buf[key->n_valid_bytes];
            *cursor = match->wc.masks.nw_dst;

            key->n_valid_bytes += f->n_bytes;
        }
        break;

        case MFF_TCP_SRC:
        case MFF_UDP_SRC:
        case MFF_SCTP_SRC:
        {
            uint16_t *cursor;
            ovs_assert(f->n_bytes == sizeof *cursor);

            cursor = (uint16_t *)&key->key_buf[key->n_valid_bytes];
            *cursor = match->flow.tp_src;
            cursor = (uint16_t *)&key->msk_buf[key->n_valid_bytes];
            *cursor = match->wc.masks.tp_src;

            key->n_valid_bytes += f->n_bytes;
        }
        break;

        case MFF_TCP_DST:
        case MFF_UDP_DST:
        case MFF_SCTP_DST:
        {
            uint16_t *cursor;
            ovs_assert(f->n_bytes == sizeof *cursor);

            cursor = (uint16_t *)&key->key_buf[key->n_valid_bytes];
            *cursor = match->flow.tp_dst;
            cursor = (uint16_t *)&key->msk_buf[key->n_valid_bytes];
            *cursor = match->wc.masks.tp_dst;

            key->n_valid_bytes += f->n_bytes;
        }
        break;

        case MFF_DP_HASH:
        case MFF_RECIRC_ID:

        case MFF_TUN_ID:
        case MFF_TUN_SRC:
        case MFF_TUN_DST:
        case MFF_TUN_FLAGS:
        case MFF_TUN_TOS:
        case MFF_TUN_TTL:
        case MFF_TUN_GBP_ID:
        case MFF_TUN_GBP_FLAGS:

        case MFF_METADATA:
        case MFF_IN_PORT:
        case MFF_IN_PORT_OXM:

        case MFF_ACTSET_OUTPUT:
        case MFF_SKB_PRIORITY:
        case MFF_PKT_MARK:
        CASE_MFF_REGS:
        CASE_MFF_XREGS:

        case MFF_ETH_TYPE:

        case MFF_VLAN_TCI:
        case MFF_DL_VLAN:
        case MFF_VLAN_VID:
        case MFF_DL_VLAN_PCP:
        case MFF_VLAN_PCP:

        case MFF_MPLS_LABEL:
        case MFF_MPLS_TC:
        case MFF_MPLS_BOS:

        case MFF_ARP_SPA:
        case MFF_ARP_TPA:
        case MFF_ARP_OP:
        case MFF_ARP_SHA:
        case MFF_ARP_THA:

        case MFF_IPV6_SRC:
        case MFF_IPV6_DST:
        case MFF_IPV6_LABEL:

        case MFF_IP_PROTO:
        case MFF_IP_DSCP:
        case MFF_IP_DSCP_SHIFTED:
        case MFF_IP_ECN:
        case MFF_IP_TTL:
        case MFF_IP_FRAG:

        case MFF_ND_SLL:
        case MFF_ND_TLL:
        case MFF_ND_TARGET:

        case MFF_ICMPV4_TYPE:
        case MFF_ICMPV6_TYPE:
        case MFF_ICMPV4_CODE:
        case MFF_ICMPV6_CODE:

        case MFF_CONJ_ID:

        case MFF_TCP_FLAGS:

            VLOG_DBG("   unsupported field %d: %s for key", i, f->name);
            return OFPERR_OFPBMC_BAD_FIELD;

        case MFF_N_IDS:
        default:
            OVS_NOT_REACHED();
        }
    }

    return 0;
}

struct instr_cursor {
    uint32_t next_apply_action;
    uint32_t next_write_action;
};

static enum ofperr
bsw_extract_action(const struct bs_info *bsi,
                   const struct ofpact *act,
                   struct instr_encoding *instr,
                   struct instr_cursor *cursor,
                   bool as_write_action)
{
    switch (act->type) {
    case OFPACT_GOTO_TABLE:
    {
        struct ofpact_goto_table *gt = ofpact_get_GOTO_TABLE(act);

        if (instr->flags & INSTR_GOTOTABLE) {
            VLOG_ERR("%s: repeated Goto-Table detected! (already set to %d)",
                     __func__, instr->table_id);
            return OFPERR_OFPBIC_UNSUP_INST;
        }
        instr->flags |= INSTR_GOTOTABLE;
        instr->table_id = gt->table_id;
        VLOG_DBG("   instr        += GOTO_TABLE %d", gt->table_id);
    }
    break;

    case OFPACT_CLEAR_ACTIONS:
        instr->flags |= INSTR_CLEARACTIONS;
        VLOG_DBG("   instr        += CLEAR_ACTIONS");
        break;

    case OFPACT_OUTPUT:
    {
        struct ofpact_output *out = ofpact_get_OUTPUT(act);

        /* Remap the software-intercept port to the DMA port.  Currently, OvS is
         * not hooked up to the DMA port, so that is effectively a /dev/null.
         */
        if (out->port == OFPP_NORMAL) {
            out->port = bsi->dma_port;
        }
        /* Check if the output port is within range. */
        if (out->port >= bsi->num_ports) {
            VLOG_ERR("%s: output port is out-of-range (%d exceeds num_ports %d)",
                     __func__, out->port, bsi->num_ports);
            return OFPERR_OFPBAC_BAD_OUT_PORT;
        }
        action_encoding_t a = make_output_action(PORT_NORMAL, out->port);

        if (as_write_action) {
            if (cursor->next_write_action >= NUM_WRITE_ACTIONS) {
                VLOG_ERR("%s: write action buffer overflow when processing %s",
                         __func__, ofpact_name(act->type));
                return OFPERR_OFPBAC_TOO_MANY;
            }
            instr->write_actions[cursor->next_write_action++] = a;
            instr->flags |= INSTR_WRITEACTIONS;
            VLOG_DBG("   instr[write] += OUTPUT %d", out->port);
        } else {
            if (cursor->next_apply_action >= NUM_APPLY_ACTIONS) {
                VLOG_ERR("%s: apply action buffer overflow when processing %s",
                         __func__, ofpact_name(act->type));
                return OFPERR_OFPBAC_TOO_MANY;
            }
            instr->apply_actions[cursor->next_apply_action++] = a;
            instr->flags |= INSTR_APPLYACTIONS;
            VLOG_DBG("   instr[apply] += OUTPUT %d", out->port);
        }
    }
    break;

    case OFPACT_WRITE_METADATA:
    {
        struct ofpact_metadata *meta = ofpact_get_WRITE_METADATA(act);
        if (meta->mask >> 32) {
            VLOG_ERR("%s: Blueswitch only supports 32-bit metadata (asked for mask of %"PRIu64")",
                     __func__,  meta->mask);
            return OFPERR_OFPBIC_UNSUP_METADATA_MASK;
        }
        instr->metadata_value = (uint32_t) meta->metadata;
        instr->metadata_mask  = (uint32_t) meta->mask;
        instr->flags         |= INSTR_SETMETADATA;
        VLOG_DBG("   instr        += WRITE-METADATA %x/%x", instr->metadata_value, instr->metadata_mask);
    } break;

    case OFPACT_SET_FIELD:
    case OFPACT_REG_MOVE:
    case OFPACT_SET_ETH_DST:
    case OFPACT_SET_ETH_SRC:
    case OFPACT_SET_IP_DSCP:
    case OFPACT_SET_IP_ECN:
    case OFPACT_SET_IP_TTL:
    case OFPACT_SET_IPV4_DST:
    case OFPACT_SET_IPV4_SRC:
    case OFPACT_SET_L4_DST_PORT:
    case OFPACT_SET_L4_SRC_PORT:
    case OFPACT_SET_MPLS_LABEL:
    case OFPACT_SET_MPLS_TC:
    case OFPACT_SET_MPLS_TTL:
    case OFPACT_SET_QUEUE:
    case OFPACT_SET_TUNNEL:
    case OFPACT_SET_VLAN_PCP:
    case OFPACT_SET_VLAN_VID:
    case OFPACT_BUNDLE:
    case OFPACT_CONTROLLER:
    case OFPACT_DEC_MPLS_TTL:
    case OFPACT_DEC_TTL:
    case OFPACT_ENQUEUE:
    case OFPACT_EXIT:
    case OFPACT_FIN_TIMEOUT:
    case OFPACT_GROUP:
    case OFPACT_LEARN:
    case OFPACT_METER:
    case OFPACT_MULTIPATH:
    case OFPACT_NOTE:
    case OFPACT_OUTPUT_REG:
    case OFPACT_POP_MPLS:
    case OFPACT_POP_QUEUE:
    case OFPACT_PUSH_MPLS:
    case OFPACT_PUSH_VLAN:
    case OFPACT_RESUBMIT:
    case OFPACT_SAMPLE:
    case OFPACT_STACK_POP:
    case OFPACT_STACK_PUSH:
    case OFPACT_STRIP_VLAN:
    case OFPACT_CONJUNCTION:
        VLOG_ERR("%s: unsupported action %s", __func__, ofpact_name(act->type));
        return OFPERR_OFPBIC_UNSUP_INST;

    case OFPACT_WRITE_ACTIONS:
        /* Write-Actions are not handled directly, so we should not see them
           here.  See below.
        */
        OVS_NOT_REACHED();
    }

    return 0;
}

/* Extract the match-action instruction-set for a Blueswitch match-table with
   configuration 'tcam' into 'key' from the OvS 'rule'. */

enum ofperr
bsw_extract_instruction(const struct bs_info *bsi,
                        const struct tcam_info *tcam OVS_UNUSED,
                        const struct rule_actions *actions,
                        struct instr_encoding *instr)
{
    enum ofperr ret;
    const struct ofpact *act;
    struct instr_cursor cursor;
    memset(&cursor, 0, sizeof(struct instr_cursor));

    memset(instr, 0, sizeof *instr);

    for (act = actions->ofpacts;
         act < ofpact_end(actions->ofpacts, actions->ofpacts_len);
         act = ofpact_next(act)) {

        /* OvS uses nested actions for Write-Actions, so process that
         * separately.
         */
        if (act->type == OFPACT_WRITE_ACTIONS) {
            struct ofpact_nest *nest = ofpact_get_WRITE_ACTIONS(act);
            size_t nest_action_len = ofpact_nest_get_action_len(nest);
            const struct ofpact *nact;

            for (nact = nest->actions;
                 nact < ofpact_end(nest->actions, nest_action_len);
                 nact = ofpact_next(nact)) {

                if ((ret = bsw_extract_action(bsi, nact, instr, &cursor, true)) != 0)
                    return ret;
            }
        } else {
            /* Process this as in an Apply-Action instruction. */
            if ((ret = bsw_extract_action(bsi, act, instr, &cursor, false)) != 0)
                return ret;
        }
    }

   return 0;
}

static struct t_state *
bsw_init_empty_table_state(uint32_t n_entries)
{
    struct t_state *t;
    size_t sz = sizeof(*t) + n_entries * sizeof(t->entries[0]);
    t = (struct t_state *)xzalloc(sz);
    if (t)
        t->n_entries = n_entries;
    return t;
}

static struct t_state *
bsw_init_table_state(struct t_state *s)
{
    struct t_state *t;
    size_t sz = sizeof(*t) + s->n_entries * sizeof(t->entries[0]);
    t = (struct t_state *)xzalloc(sz);
    if (t)
        memcpy(t, s, sz);
    return t;
}

/* In the current configuration model, we have a command queue of the same
   length as the number of tcam entries.  Each command is inserted into the
   queue at the position of the TCAM entry to which it applies.

   This could be changed for a pure double-buffered model, where the number of
   commands in the queue could be much smaller than the number of tcam entries.
 */
static struct t_update *
bsw_init_table_update(struct t_state *initial, uint32_t cmd_queue_len)
{
    struct t_update *u;
    size_t sz = sizeof(*u) + cmd_queue_len * sizeof(u->cmds[0]);
    u = (struct t_update *)xzalloc(sz);
    if (u) {
        u->t_working     = bsw_init_table_state(initial);
        u->cmd_queue_len = cmd_queue_len;
    }
    return u;
}

void
bsw_initialize_switch_state(const struct bs_info *bsi, struct s_state *s)
{
    s->n_tables = bsi->num_tcams;
    s->table_states  = (struct t_state **)xmalloc(bsi->num_tcams
                                                  * sizeof(s->table_states[0]));
    s->table_updates = (struct t_update **)xmalloc(bsi->num_tcams
                                                   * sizeof(s->table_updates[0]));
    for (int i = 0; i < bsi->num_tcams; i++) {
        const struct tcam_info *tci = &bsi->tcams[i];
        struct t_state *t   = bsw_init_empty_table_state(tci->num_entries);
        s->table_states[i]  = t;
        s->table_updates[i] = bsw_init_table_update(t, tci->num_entries);
    }
}

void
bsw_destroy_switch_state(struct s_state *s)
{
    for (int i = 0; i < s->n_tables; i++) {
        free(s->table_states[i]);
        free(s->table_updates[i]);
    }
    free(s->table_states);
    free(s->table_updates);
}

enum ofperr
bsw_allocate_tcam_ent_update(struct t_update *table, enum t_entry_update_type t,
                             struct t_entry_update **ent, int *cmd_idx, int *tcam_idx)
{
    int idx;
    struct t_entry_update *u;
    struct t_state *state = table->t_working;

    ovs_assert(cmd_idx && tcam_idx);

    /* Ensure we haven't changed our configuration model. */
    ovs_assert(state->n_entries == table->cmd_queue_len);

    /* In this mode, if we are trying to delete or update an existing entry, we
     * know which slot to use: the same slot in the cmd_queue as the index of
     * the TCAM entry.
     */
    if (t == TEM_DELETE || t == TEM_UPDATE) {
        const char *cmd = t == TEM_DELETE ? "DELETE" : "UPDATE";
        /* We should be deleting an existing entry. */
        if (*tcam_idx < 0) {
            VLOG_WARN("cannot %s a rule not (yet?) in table!", cmd);
            return OFPERR_OFPFMFC_UNSUPPORTED;
        }

        ovs_assert(*tcam_idx < state->n_entries);

        /* Warn if we are deleting or updating an empty entry. */
        if (state->entries[*tcam_idx] == TE_EMPTY)
            VLOG_WARN("%s-ing an empty entry!", cmd);

        /* If we are updating, ensure that the entry is marked as occupied. */
        if (t == TEM_UPDATE)
            state->entries[*tcam_idx] = TE_OCCUPIED;

        u = &table->cmds[*tcam_idx];
        u->type       = t;
        u->tcam_idx_p = tcam_idx;

        *ent          = u;
        *cmd_idx      = *tcam_idx;
        return 0;
    }

    /* To add a new entry to the TCAM, we need to search for an empty slot. */
    for (idx = 0; idx < state->n_entries; idx++) {
        enum t_entry_state s = state->entries[idx];

        if (s == TE_EMPTY) {
            u = &table->cmds[idx];
            ovs_assert(u->type == 0);
            break;
        }
    }
    if (idx >= state->n_entries)
        return OFPERR_OFPFMFC_TABLE_FULL;

    state->entries[idx] = TE_OCCUPIED;
    u->type       = t;
    u->tcam_idx_p = tcam_idx;

    *ent          = u;
    *cmd_idx      = idx;
    return 0;
}

void
bsw_convert_update_to_delete(struct t_update *table, int cmd_idx, int *tcam_idx)
{
    struct t_state *state = table->t_working;

    ovs_assert(cmd_idx > 0 && cmd_idx < table->cmd_queue_len);
    ovs_assert(tcam_idx && *tcam_idx >= 0 && *tcam_idx < state->n_entries);

    struct t_entry_update *u = &table->cmds[cmd_idx];

    /* This should be called for an existing entry. */
    ovs_assert(state->entries[*tcam_idx] == TE_OCCUPIED);

    /* We should have a valid update pending for this entry. */
    ovs_assert(u->type != 0);
    ovs_assert(u->tcam_idx_p == NULL || u->tcam_idx_p == tcam_idx);

    /* Mark the entry for delete, and remove the back-pointer. */
    u->type = TEM_DELETE;
    u->tcam_idx_p = NULL;
}

static enum ofperr
bsw_update_table(struct bs_info *bsi, struct s_state *state, uint8_t table_id)
{
    ovs_assert(table_id < bsi->num_tcams);

    struct tcam_cfg tcfg;
    init_tcam_cfg(&tcfg, bsi->dev, bsi, table_id);
    VLOG_DBG(" initialized tcam config of table %d: key_size=%d val_size=%d",
             table_id, tcfg.key_size, tcfg.val_size);

    tcam_cmd_status_t res;
    struct t_update *table = state->table_updates[table_id];
    for (uint32_t i = 0; i < table->cmd_queue_len; i++) {
        struct t_entry_update *cmd = &table->cmds[i];
        switch (cmd->type) {
        case TEM_DELETE:
        {
            /* Currently the index of the entry is the same as the index of the
             * cmd in the cmd queue.  Note that cmd->tcam_idx_p may be invalid
             * since the rule may be deleted and freed.
             */
            VLOG_DBG(" deleting entry %d from TCAM %d", i, table_id);
            res = tcam_del_entry(&tcfg, i);
            if (res != TCAM_CMDST_CLEAR) goto error;

            table->t_working->entries[i] = TE_EMPTY;
        }
        break;

        case TEM_UPDATE:
        {
            ovs_assert(cmd->tcam_idx_p && i == *cmd->tcam_idx_p);
            ovs_assert(table->t_working->entries[i] == TE_OCCUPIED);

            VLOG_DBG(" updating entry %d in TCAM %d", i, table_id);
            VLOG_DBG("    [exp] key_buflen=%d val_buflen=%d",
                     4*tcfg.key_size, 4*tcfg.val_size);
            VLOG_DBG("    [in] key_buflen=%u val_buflen=%lu",
                     cmd->key.n_valid_bytes, sizeof(cmd->instr));
            res = tcam_set_entry(&tcfg, i, cmd->key.key_buf, cmd->key.n_valid_bytes, cmd->key.msk_buf,
                                 (uint32_t *)&cmd->instr, sizeof(cmd->instr));
            if (res != TCAM_CMDST_CLEAR) goto error;
        }
        break;

        case TEM_ADD:
        {
            ovs_assert(table->t_working->entries[i] == TE_OCCUPIED);

            VLOG_DBG(" adding entry %d to TCAM %d", i, table_id);
            VLOG_DBG("    [exp] key_buflen=%d val_buflen=%d",
                     4*tcfg.key_size, 4*tcfg.val_size);
            VLOG_DBG("    [in] key_buflen=%u val_buflen=%lu",
                     cmd->key.n_valid_bytes, sizeof(cmd->instr));
            res = tcam_set_entry(&tcfg, i, cmd->key.key_buf, cmd->key.n_valid_bytes, cmd->key.msk_buf,
                                 (uint32_t *)&cmd->instr, sizeof(cmd->instr));
            if (res != TCAM_CMDST_CLEAR) goto error;

            /* Store the tcam entry index back into the rule. */
            *cmd->tcam_idx_p = i;
        }
        break;

        default:
            OVS_NOT_REACHED();
        }
    }

    VLOG_DBG(" ending config txn fo table %d", table_id);
    res = tcam_end_txn(&tcfg);
    if (res != TCAM_CMDST_CLEAR) goto error;

    return 0;

error:
    VLOG_ERR(" tcam cmd failed: %s", status_str(res));
    return OFPERR_OFPFMFC_UNKNOWN;
}

static enum ofperr
bsw_commit(struct bs_info *bsi)
{
    tcam_cmd_status_t res;

    /* Sanity check */
    for (int table_id = 0; table_id < bsi->num_tcams; table_id++) {
        struct tcam_cfg tcfg;
        init_tcam_cfg(&tcfg, bsi->dev, bsi, table_id);

        int flag = 0;
        res = tcam_get_primed(&tcfg, &flag);
        if (TCAM_CMDST_CLEAR != res) {
            VLOG_ERR(" unable to ensure tcam %d is primed: %s", table_id, status_str(res));
            return OFPERR_OFPFMFC_UNKNOWN;
        } else if (!flag) {
            VLOG_ERR(" tcam %d is not primed!", table_id);
            return OFPERR_OFPFMFC_UNKNOWN;
        }
    }
    VLOG_DBG(" activating committed config");

    activate_pipeline(bsi);
    int flag = is_pipeline_activated(bsi);
    if (!flag) {
        VLOG_ERR(" unable to activate pipeline!");
        return OFPERR_OFPFMFC_UNKNOWN;
    }

    return 0;
}

enum ofperr
bsw_commit_updates(struct bs_info *bsi, struct s_state *state)
{
    enum ofperr ret;

    for (int table_id = bsi->num_tcams - 1; table_id >= 0; table_id--) {
        ret = bsw_update_table(bsi, state, (uint8_t)table_id);
        if (ret) break;
    }

    if (!ret)
        ret = bsw_commit(bsi);

    state->txn_counter++;
    for (int table_id = 0; table_id < bsi->num_tcams; table_id++) {
        struct t_update *u = state->table_updates[table_id];

        /* Update the current table state */
        if (!ret) {
            struct t_state *s = state->table_states[table_id];
            for (int i = 0; i < s->n_entries; i++)
                s->entries[i] = u->t_working->entries[i];
        }

        /* Reset the command queue. */
        u->next_cmd = 0;
        memset(&u->cmds[0], 0, u->cmd_queue_len * sizeof(u->cmds[0]));
    }

    return ret;
}

static void
print_tcam_cfg(const struct tcam_cfg *cfg)
{
    VLOG_DBG("\t\t Key-Size:%d", cfg->key_size);
    VLOG_DBG("\t\t Val-Size:%d", cfg->val_size);
    VLOG_DBG("\t\t Num-Entries:%d", cfg->num_entries);
}
static void
print_tcam_info(const struct tcam_info *nfo)
{
    VLOG_DBG("\t\t Key-Size:%d", nfo->key_size);
    VLOG_DBG("\t\t Val-Size:%d", nfo->val_size);
    VLOG_DBG("\t\t Num-Entries:%d", nfo->num_entries);
}

void
print_bsi_config(const struct bs_info *bsi)
{
    VLOG_DBG("Blueswitch config:");
    VLOG_DBG("\t # Ports: %d", bsi->num_ports);
    VLOG_DBG("\t DMA port: %d", bsi->dma_port);
    VLOG_DBG("\t # Tables: %d", bsi->num_tcams);
    for (int i = 0; i < bsi->num_tcams; i++) {
        VLOG_DBG("\t Table %d:", i);
        print_tcam_info(&bsi->tcams[i]);
        VLOG_DBG("");
    }
}
