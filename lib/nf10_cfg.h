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

#ifndef NF10_CFG_H
#define NF10_CFG_H

/* This file contains a simple program to configure the single table
   switch in this directory with the same test configuration as the
   one used in simulation, but using the register interface.
*/

#include <stdint.h>

/* Specify tcams as OvS tables if in OvS context. */
#ifdef BLUESWITCH_OVS_CONFIG
#include "ofp-util.h"
#endif

/** Device interface **/

#define DEVICE_FILE         "/dev/nf10"
#define IOCTL_WRITE_REG     (SIOCDEVPRIVATE+1)
#define IOCTL_READ_REG      (SIOCDEVPRIVATE+2)

int open_device(void);
uint32_t read_register(int dev, uint32_t addr);
void write_register(int dev, uint32_t addr, uint32_t val);
void read_buffer(int dev, uint32_t start_addr, uint32_t *buf, uint32_t buf_size /* in words */);
void write_buffer(int dev, uint32_t start_addr, uint32_t *buf, uint32_t buf_size /* in words */);

/** TCAM interface **/

/* reflects CmdEnum in GenericTTCAMConfig */
typedef enum {
  TCAM_CMD_END_TXN          = 0x00,

  TCAM_CMD_ENT_UPDATE       = 0x01,
  TCAM_CMD_ENT_DELETE       = 0x02,

  TCAM_CMD_MISS_VAL_SET     = 0x03,
  TCAM_CMD_MISS_VAL_CLR     = 0x04,

  TCAM_CMD_NOKEY_VAL_SET    = 0x05,
  TCAM_CMD_NOKEY_VAL_CLR    = 0x06,

  TCAM_CMD_PRIMED_GET       = 0x07,
  TCAM_CMD_MISS_VAL_GET     = 0x08,
  TCAM_CMD_NOKEY_VAL_GET    = 0x09,
  TCAM_CMD_ENTRY_GET        = 0x0a,
  TCAM_CMD_CLR_STATUS       = 0x0b,
} tcam_cmd_type_t;

/* reflects CmdStatus in GenericTTCAMConfig */
typedef enum {
  TCAM_CMDST_PENDING                = 0x01,
  TCAM_CMDST_CLEAR                  = 0x02,
  TCAM_CMDST_ERROR_CMD              = 0x03,
  TCAM_CMDST_ERROR_VAL              = 0x04,
  TCAM_CMDST_ERROR_COMMIT_PENDING   = 0x05,
} tcam_cmd_status_t;

const char *status_str(tcam_cmd_status_t st);

typedef struct tcam_cfg {
  int       dev;
  uint32_t  *base_addr;

  /* all offsets and sizes measured in 32-bit words */
  uint32_t  status_ofs;
  uint32_t  set_ofs;
  uint32_t  get_ofs;
  uint32_t  trig_ofs;

  /* used for sanity checks */
  uint32_t  key_size;   /* in 32-bit words */
  uint32_t  val_size;   /* in 32-bit words */
  uint32_t  num_entries;
} tcam_cfg_t;

typedef struct tcam_cmd_buf {
  uint8_t   cmd;
  uint8_t   prio;
  uint16_t  idx;
  uint32_t  buf[];
} tcam_cmd_buf_t;
/* assert(sizeof(tcam_cmd_buf_t) == 4) */

uint32_t *key_of_buf(const tcam_cfg_t *cfg, tcam_cmd_buf_t *cmd);
uint32_t *mask_of_buf(const tcam_cfg_t *cfg, tcam_cmd_buf_t *cmd);
uint32_t *val_of_buf(const tcam_cfg_t *cfg, tcam_cmd_buf_t *cmd);

/* sanity check the config, in order to hopefully catch unexpected
   layout changes.  returns 1 on success, 0 on failure. */
int tcam_check_cfg(const tcam_cfg_t *cfg);

/* utilities */
tcam_cmd_buf_t *tcam_alloc_cmd_buf(const tcam_cfg_t *cfg);
void tcam_reset_cmd_buf(const tcam_cfg_t *cfg, tcam_cmd_buf_t *cmd);

/* retrieve whether the tcam has been primed (i.e. an ended
   transaction is awaiting activation) */
tcam_cmd_status_t tcam_get_primed(const tcam_cfg_t *cfg, int *is_primed);

/* retrieve the value to use when a lookup misses. */
tcam_cmd_status_t tcam_get_miss_val(const tcam_cfg_t *cfg, uint32_t *val_buf, uint32_t val_buflen /* in bytes */);

/* retrieve the default value to use when no key is present */
tcam_cmd_status_t tcam_get_nokey_val(const tcam_cfg_t *cfg, uint32_t *val_buf, uint32_t val_buflen /* in bytes */);

/* retrieve the tcam entry at a particular index */
tcam_cmd_status_t tcam_get_entry(const tcam_cfg_t *cfg, uint16_t idx,
                                 int *is_valid,     /* whether there is a valid entry at that index */
                                 uint32_t *key_buf, uint32_t key_buflen /* in bytes */,
                                 uint32_t *mask_buf,/* must be of size key_buflen */
                                 uint32_t *val_buf, uint32_t val_buflen /* in bytes */);

/* set the tcam entry at a particular index */
tcam_cmd_status_t tcam_set_entry(const tcam_cfg_t *cfg, uint16_t idx,
                                 uint32_t *key_buf, uint32_t key_buflen /* in bytes */,
                                 uint32_t *mask_buf,/* must be of size key_buflen */
                                 uint32_t *val_buf, uint32_t val_buflen /* in bytes */);

/* remove a tcam entry at a particular index */
tcam_cmd_status_t tcam_del_entry(const tcam_cfg_t *cfg, uint16_t idx);

/* end current transaction */
tcam_cmd_status_t tcam_end_txn(const tcam_cfg_t *cfg);

/* get the status of the last tcam config command */
tcam_cmd_status_t tcam_get_status(const tcam_cfg_t *cfg);

/* clear the tcam command status register */
tcam_cmd_status_t tcam_clr_status(const tcam_cfg_t *cfg);

/** Match Table / Instruction interface **/

#define NUM_WRITE_ACTIONS   4
#define NUM_APPLY_ACTIONS   4

typedef enum {
  ACT_NONE              = 0x00,
  ACT_OUTPUT            = 0x01,
} action_type_t;

typedef enum {
  PORT_NORMAL           = 0x00000000,   // The specified physical port.
  PORT_INPUT_PORT       = 0xfffffff8,   // Physical port the packet came in on.
  PORT_FLOOD_PORT       = 0xfffffffb,   // All physical ports in the VLAN, except the input port.
  PORT_ALL_PORTS        = 0xfffffffc,   // All physical ports except the input port.
  PORT_CONTROLLER_PORT  = 0xfffffffd,   // Send to controller.
  PORT_LOCAL_PORT       = 0xfffffffe,   // Send to local network stack on switch CPU.
  PORT_ANY_PORT         = 0xffffffff,   // Wildcard port, used only for port matching.
} port_t;

typedef struct __attribute__ ((__packed__)) action_output {
  uint8_t   port_num;
  uint32_t  port_type;
  uint16_t  pad;
} action_output_t;

typedef struct __attribute__ ((__packed__)) action_encoding {
  uint8_t   act_type;
  union {
    action_output_t     output;
  } act_val;
} action_encoding_t;
/* assert(sizeof(action_encoding_t) == 4 * 2) */

action_encoding_t make_output_action(port_t typ, uint8_t port);

/* reflects InstrType in InstructionConfig */
typedef enum {
  INSTR_GOTOTABLE       = 0x01,
  INSTR_SETMETADATA     = 0x02,
  INSTR_WRITEACTIONS    = 0x04,
  INSTR_APPLYACTIONS    = 0x08,
  INSTR_CLEARACTIONS    = 0x10,
} instr_type_t;

typedef struct __attribute__ ((__packed__)) instr_encoding {
  uint8_t   flags;
  uint16_t  reserved;
  uint8_t   table_id;

  uint32_t  metadata_value;
  uint32_t  metadata_mask;

  action_encoding_t apply_actions[NUM_APPLY_ACTIONS];
  action_encoding_t write_actions[NUM_WRITE_ACTIONS];
} instr_encoding_t;
/* assert(sizeof(instr_encoding_t) == 4 * 19) */

/* utilities for common cases */

instr_encoding_t make_apply_action_instr(const action_encoding_t act);
instr_encoding_t make_write_action_instr(const action_encoding_t act);
instr_encoding_t make_goto_instr(uint8_t table);

void print_instruction(instr_encoding_t *instr);

/** Pipeline management interface **/

typedef struct tcam_info {
  uint32_t base_addr;
  uint32_t num_entries;
  uint32_t key_size;
  uint32_t val_size;

#ifdef BLUESWITCH_OVS_CONFIG
#define BLUESWITCH_MAX_TCAM_FIELDS 2
  struct ofputil_table_features features;
  uint32_t                      num_fields;
  enum mf_field_id              mf_fields[BLUESWITCH_MAX_TCAM_FIELDS];
#endif
} tcam_info_t;

typedef struct bs_info {
  int           dev;
  uint32_t      device_base_addr;
  uint32_t      stats_base_addr;
  uint32_t      pipeline_base_addr;
  uint32_t      num_ports;
  uint32_t      dma_port;
  uint32_t      num_tcams;
  uint32_t      dummy;
  tcam_info_t   tcams[];
} bs_info_t;

/* Initialize the config handle a particular tcam from the switch config. */
void init_tcam_cfg(tcam_cfg_t *cfg, int dev, const bs_info_t *bsi, int ntcam);

int is_pipeline_activated(const bs_info_t *bsi);
void activate_pipeline(const bs_info_t *bsi);

/* Switch interface helpers */

int open_switch(bs_info_t *bsi);
void close_switch(bs_info_t *bsi);

/* Stats interface */

struct port_stats {
  uint32_t rx_bytes;
  uint32_t rx_pkts;
  uint32_t tx_bytes;
  uint32_t tx_pkts;
};

int get_port_stats(const bs_info_t *bsi, uint32_t port, struct port_stats *stats);

#endif /* NF10_CFG_H */
