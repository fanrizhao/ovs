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

#include "meta-flow.h"
#include "vlog.h"

VLOG_DEFINE_THIS_MODULE(blueswitch_util);

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
    ovs_assert(BLUESWITCH_MAX_TCAM_KEYLEN >= tcam->key_size);

    bsw_tcam_key_init(key);

    /* This is based on meta-flow.c:mf_get_value(). */

    for (int i = 0; i <= tcam->num_fields; i++) {

        /* Ensure there is sufficient space. */
        enum mf_field_id id = tcam->mf_fields[i];
        const struct mf_field *f = mf_from_id(id);
        ovs_assert(key->n_valid_bytes + f->n_bytes <= 4 * tcam->key_size);

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

        case MFF_TCP_FLAGS:
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
bsw_extract_action(const struct ofpact *act,
                   struct instr_encoding *instr,
                   struct instr_cursor *cursor,
                   bool as_write_action)
{

#define ADD_ACTION(a) \
  do {                                                                          \
    if (as_write_action) {                                                      \
        if (cursor->next_write_action >= NUM_WRITE_ACTIONS) {                   \
            VLOG_ERR("%s: write action buffer overflow when processing %s",     \
                     __func__, ofpact_name(act->type));                         \
            return OFPERR_OFPBAC_TOO_MANY;                                      \
        }                                                                       \
        instr->write_actions[cursor->next_write_action++] = a;                  \
    } else {                                                                    \
        if (cursor->next_apply_action >= NUM_APPLY_ACTIONS) {                   \
            VLOG_ERR("%s: apply action buffer overflow when processing %s",     \
                     __func__, ofpact_name(act->type));                         \
            return OFPERR_OFPBAC_TOO_MANY;                                      \
        }                                                                       \
        instr->apply_actions[cursor->next_apply_action++] = a;                  \
    }                                                                           \
  } while (0)

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
    }
    break;

    case OFPACT_CLEAR_ACTIONS:
        instr->flags |= INSTR_CLEARACTIONS;
        break;

    case OFPACT_OUTPUT:
    {
        struct ofpact_output *out = ofpact_get_OUTPUT(act);

        /* TODO: check port-mapping with ofproto layer */
        action_encoding_t a = make_output_action(PORT_NORMAL, out->port);

        ADD_ACTION(a);
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
        VLOG_ERR("%s: unsupported action %s", __func__, ofpact_name(act->type));
        return OFPERR_OFPBIC_UNSUP_INST;

    case OFPACT_WRITE_ACTIONS:
        OVS_NOT_REACHED();
    }

    return 0;
}

/* Extract the match-action instruction-set for a Blueswitch match-table with
   configuration 'tcam' into 'key' from the OvS 'rule'. */

enum ofperr
bsw_extract_instruction(const struct tcam_info *tcam OVS_UNUSED,
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

                if ((ret = bsw_extract_action(nact, instr, &cursor, true)) != 0)
                    return ret;
            }
        } else {
            /* Process this as in an Apply-Action instruction. */
            if ((ret = bsw_extract_action(act, instr, &cursor, false)) != 0)
                return ret;
        }
    }

   return 0;
}
