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

#ifndef TABLE_CFG_H
#define TABLE_CFG_H

#ifdef SINGLE_TABLE
/* Basic address map for the onetable switch, from
   NetFPGAOneTableRegsNoArbSwitchTop.  */

#define DEVICE_BASE_ADDR    0x70010000
#define TCAM_BASE_OFFSET    (36 * 4)
#define PIPE_BASE_OFFSET    ((36 + 46) * 4)

#ifdef BLUESWITCH_OVS_CONFIG
/* Supported instructions */
#define BLUESWITCH_INSTRUCTIONS             \
  ( (1u << OVSINST_OFPIT11_APPLY_ACTIONS)   \
  | (1u << OVSINST_OFPIT11_WRITE_ACTIONS)   \
  | (1u << OVSINST_OFPIT11_CLEAR_ACTIONS)   \
  | (1u << OVSINST_OFPIT11_GOTO_TABLE)      \
  )

/* Supported actions */
#define BLUESWITCH_ACTIONS                  \
  ( (UINT64_C(1) << OFPACT_OUTPUT)          \
  | (UINT64_C(1) << OFPACT_CLEAR_ACTIONS)   \
  | (UINT64_C(1) << OFPACT_WRITE_ACTIONS)   \
  | (UINT64_C(1) << OFPACT_GOTO_TABLE)      \
  )
#endif

bs_info_t bsi_table = {
  .dev                  = -1,
  .device_base_addr     = DEVICE_BASE_ADDR,
  .stats_base_addr      = DEVICE_BASE_ADDR,
  .pipeline_base_addr   = DEVICE_BASE_ADDR + PIPE_BASE_OFFSET,
  .num_ports            = 8,   /* TestPipeline in testlib */
  .num_tcams            = 1,
  .tcams = {
    { .base_addr        = DEVICE_BASE_ADDR + TCAM_BASE_OFFSET,
      .num_entries      = 10,  /* NumEntries in OneTableRegsSwitchPipeline */
      .key_size         = 1,
      .val_size         = 19,
#ifdef BLUESWITCH_OVS_CONFIG
      .features = {
        .table_id = 0,
        .metadata_match = 0,
        .metadata_write = 0,
        .miss_config    = OFPUTIL_TABLE_MISS_DROP,
        .max_entries    = 0,         /* REDUNDANT: use num_entries above */
        .nonmiss = {
          .instructions = BLUESWITCH_INSTRUCTIONS,
          .write = {
            .ofpacts    = BLUESWITCH_ACTIONS
          },
          .apply = {
            .ofpacts    = BLUESWITCH_ACTIONS
          },
        },
        .miss = {
          .instructions = BLUESWITCH_INSTRUCTIONS,
          .write = {
            .ofpacts    = BLUESWITCH_ACTIONS
          },
          .apply = {
            .ofpacts    = BLUESWITCH_ACTIONS
          },
        },
      },
      .num_fields = 1,
      .mf_fields  = { [0] = MFF_IPV4_SRC },
#endif
    }
  }
};

tcam_cfg_t cfg = {
  .dev          = -1,
  .base_addr    = NULL,
  .status_ofs   = 0,                    /*        status ofs */
  .set_ofs      = 1,                    /*       setRegs ofs */
  .get_ofs      = 1 + 22,               /*       getRegs ofs */
  .trig_ofs     = 1 + (2 * 22),         /*       trigger ofs */

  .key_size     = 1,                    /*          key size */
  .val_size     = 19,                   /*  encoded val size */
};
#endif // SINGLE_TABLE

#ifdef MULTI_TABLE
/* Address map for the multitable switch, from
   NetFPGAMultiTableRegsSwitchTop.  */

#define DEVICE_BASE_ADDR    0x70010000
#define TCAM_BASE_OFFSET    (12 * 4)
#define PIPE_BASE_OFFSET    ((12 + 142) * 4)

bs_info_t bsi_table = {
  .dev                  = -1,
  .device_base_addr     = DEVICE_BASE_ADDR,
  .stats_base_addr      = DEVICE_BASE_ADDR,
  .pipeline_base_addr   = DEVICE_BASE_ADDR + PIPE_BASE_OFFSET,
  .num_ports            = 2,
  .num_tcams            = 3,
  .tcams = {
    { .base_addr          = DEVICE_BASE_ADDR + TCAM_BASE_OFFSET,
      .num_entries        = 10,
      .key_size           = 1,
      .val_size           = 19,
#ifdef BLUESWITCH_OVS_CONFIG
      .features = {
        .table_id = 0,
        .metadata_match = 0,
        .metadata_write = 0,
        .miss_config    = OFPUTIL_TABLE_MISS_CONTINUE,
        .max_entries    = 0,         /* REDUNDANT: use num_entries above */
        .nonmiss = {
          .instructions = BLUESWITCH_INSTRUCTIONS,
          .write = {
            .ofpacts    = BLUESWITCH_ACTIONS
          },
          .apply = {
            .ofpacts    = BLUESWITCH_ACTIONS
          },
        },
        .miss = {
          .instructions = BLUESWITCH_INSTRUCTIONS,
          .write = {
            .ofpacts    = BLUESWITCH_ACTIONS
          },
          .apply = {
            .ofpacts    = BLUESWITCH_ACTIONS
          },
        },
        .num_fields = 2,
        .mf_fields  = { [0] = MFF_TCP_SRC,
                        [1] = MFF_TCP_DST },
        },
      }
#endif
    },
    { .base_addr          = DEVICE_BASE_ADDR + TCAM_BASE_OFFSET + 46,
      .num_entries        = 10,
      .key_size           = 1,
      .val_size           = 19,
#ifdef BLUESWITCH_OVS_CONFIG
      .features = {
        .table_id = 1,
        .metadata_match = 0,
        .metadata_write = 0,
        .miss_config    = OFPUTIL_TABLE_MISS_CONTINUE,
        .max_entries    = 0,         /* REDUNDANT: use num_entries above */
        .nonmiss = {
          .instructions = BLUESWITCH_INSTRUCTIONS,
          .write = {
            .ofpacts    = BLUESWITCH_ACTIONS
          },
          .apply = {
            .ofpacts    = BLUESWITCH_ACTIONS
          },
        },
        .miss = {
          .instructions = BLUESWITCH_INSTRUCTIONS,
          .write = {
            .ofpacts    = BLUESWITCH_ACTIONS
          },
          .apply = {
            .ofpacts    = BLUESWITCH_ACTIONS
          },
        },
      },
      .num_fields = 1,
      .mf_fields  = { [0] = MFF_IPV4_DST },
#endif
    },
    { .base_addr          = DEVICE_BASE_ADDR + TCAM_BASE_OFFSET + 46 + 46,
      .num_entries        = 10,
      .key_size           = 2,
      .val_size           = 19,
#ifdef BLUESWITCH_OVS_CONFIG
      .features = {
        .table_id = 2,
        .metadata_match = 0,
        .metadata_write = 0,
        .miss_config    = OFPUTIL_TABLE_MISS_DROP,
        .max_entries    = 0,         /* REDUNDANT: use num_entries above */
        .nonmiss = {
          .instructions = BLUESWITCH_INSTRUCTIONS,
          .write = {
            .ofpacts    = BLUESWITCH_ACTIONS
          },
          .apply = {
            .ofpacts    = BLUESWITCH_ACTIONS
          },
        },
        .miss = {
          .instructions = BLUESWITCH_INSTRUCTIONS,
          .write = {
            .ofpacts    = BLUESWITCH_ACTIONS
          },
          .apply = {
            .ofpacts    = BLUESWITCH_ACTIONS
          },
        },
      },
      .num_fields = 1,
      .mf_fields  = { [0] = MFF_ETH_DST },
#endif
    }
  }
};
#endif // MULTI_TABLE

#endif // TABLE_CFG_H
