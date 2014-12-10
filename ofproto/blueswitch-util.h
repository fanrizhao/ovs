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

#ifndef BLUESWITCH_UTIL_H
#define BLUESWITCH_UTIL_H

#define BLUESWITCH_OVS_CONFIG
#include "nf10_cfg.h"
#include "ofproto/ofproto-provider.h"

#define BLUESWITCH_MAX_TCAM_KEYLEN      4      /* in 32-bit words */

struct bsw_tcam_key {
  uint8_t key_buf[4 * BLUESWITCH_MAX_TCAM_KEYLEN];
  uint8_t msk_buf[4 * BLUESWITCH_MAX_TCAM_KEYLEN];
  uint32_t n_valid_bytes;
};

/* Extract the key/mask/value fields for a Blueswitch TCAM with configuration
   'tcam' into 'key' from the OvS 'match'.  This overwrites any earlier
   information in 'key'.*/

enum ofperr bsw_extract_tcam_key(const struct tcam_info *tcam,
				 const struct match *match,
				 struct bsw_tcam_key *key);

/* Extract the match-action instruction-set for a Blueswitch match-table with
   configuration 'tcam' into 'key' from the OvS 'actions'.  This overwrites any
   earlier information in 'instr'. */

enum ofperr bsw_extract_instruction(const struct tcam_info *tcam,
				    const struct rule_actions *actions,
				    struct instr_encoding *instr);

/* tcam table state */

enum t_entry_state {
  TE_EMPTY = 0,
  TE_OCCUPIED,
};

struct t_state;

struct t_state *bsw_init_table_state(uint32_t n_entries);

/* tcam table modifications */

enum t_entry_update_type {
  TEM_NOCHANGE = 0,
  TEM_DELETE,
  TEM_UPDATE,
};

struct t_entry_update {
    enum t_entry_update_type   type;
    struct bsw_tcam_key        key;
    struct instr_encoding      instr;
};

struct t_update;

struct t_update *bsw_init_table_update(struct t_state *table, uint32_t cmd_queue_len);

enum ofperr bsw_allocate_tcam_ent_update(struct t_update *table, enum t_entry_update_type t,
					 struct t_entry_update **ent);

struct s_state {
  uint32_t          n_tables;

  /* array of table tcam state */
  struct t_state    **table_states;

  /* array of table tcam update state */
  struct t_update   **table_updates;
};

void bsw_initialize_switch_state(const struct bs_info *bsi, struct s_state *s);
void bsw_destroy_switch_state(struct s_state *s);

#endif /* BLUESWITCH_UTIL_H */
