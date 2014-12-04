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

int
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
        if (key->n_valid_bytes + f->n_bytes >= 4 * tcam->key_size) {
            VLOG_ERR("%s: insufficient space to extract tcam key for %s",
                     __func__, f->name);
            return -1;
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

        case MFF_N_IDS:
        default:
            OVS_NOT_REACHED();
        }
    }

    return 0;
}

/* Extract the match-action instruction-set for a Blueswitch match-table with
   configuration 'tcam' into 'key' from the OvS 'rule'. */

int
bsw_extract_instruction(const struct tcam_info *tcam OVS_UNUSED,
                        const struct rule_actions *actions OVS_UNUSED,
                        struct instr_encoding *instr OVS_UNUSED)
{
    return 0;
}
