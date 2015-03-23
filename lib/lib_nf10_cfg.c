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

/* This file contains a library functions to configure a multi-table
   switch using the register interface. */

#include <stdint.h>
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#include <config.h>
#include "nf10_config.h"
#include "nf10_cfg.h"

#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(lib_nf10);

#define ERRBUF_LEN 256

/** Device interface **/

static int do_log = 0;
static int do_rw  = 1;

static void log_read(uint32_t addr, uint32_t val) {
  if (do_log)
    VLOG_DBG("rd: [0x%x] -> 0x%x", addr, val);
}

static void log_write(uint32_t addr, uint32_t val) {
  if (do_log)
    VLOG_DBG("wr: [0x%x] <- 0x%x", addr, val);
}

const char *status_str(tcam_cmd_status_t st) {
  switch (st) {
  case TCAM_CMDST_PENDING:
    return "Pending";
  case TCAM_CMDST_CLEAR:
    return "Clear";
  case TCAM_CMDST_ERROR_CMD:
    return "Error_Cmd";
  case TCAM_CMDST_ERROR_VAL:
    return "Error_Val";
  case TCAM_CMDST_ERROR_COMMIT_PENDING:
    return "Error_Commit_Pending";
  default:
    return "UNKNOWN";
  }
}

static void log_status(tcam_cmd_status_t st) {
  if (do_log)
    VLOG_DBG("st: %s [0x%x]", status_str(st), st);
}

int open_device(void) {
  char errbuf[ERRBUF_LEN];
  int dev = open(DEVICE_FILE, O_RDWR);

  if (do_rw && (dev < 0)) {
    errbuf[0] = 0;
    (void) strerror_r(errno, errbuf, ERRBUF_LEN);
    VLOG_DBG("Error opening %s: %s", DEVICE_FILE, errbuf);
  }
  return dev;
}

uint32_t read_register(int dev, uint32_t addr) {
  uint32_t val;
  char errbuf[ERRBUF_LEN];
  uint64_t daddr = addr;

  if (do_rw && (ioctl(dev, IOCTL_READ_REG, &daddr) < 0)) {
    errbuf[0] = 0;
    (void) strerror_r(errno, errbuf, ERRBUF_LEN);
    VLOG_DBG("error reading %s [0x%x]: %s",
             DEVICE_FILE, addr, errbuf);
    exit(1);
  }
  val = (uint32_t)(daddr & 0xFFFFFFFF);
  log_read(addr, val);
  return val;
}

void write_register(int dev, uint32_t addr, uint32_t val) {
  char errbuf[ERRBUF_LEN];
  uint64_t darg = ((uint64_t)addr << 32) + val;
  log_write(addr, val);
  if (do_rw && (ioctl(dev, IOCTL_WRITE_REG, darg) < 0)) {
    errbuf[0] = 0;
    (void)strerror_r(errno, errbuf, ERRBUF_LEN);
    VLOG_DBG("error writing %s [0x%x <- %x]: %s",
             DEVICE_FILE, addr, val, errbuf);
    exit(1);
  }
}

void read_buffer(int dev, uint32_t start_addr, uint32_t *buf, uint32_t buf_size /* in words */) {
  int idx;
  for (idx = 0; idx < buf_size; idx++)
    buf[idx] = read_register(dev, start_addr + (idx * 4));
}

void write_buffer(int dev, uint32_t start_addr, uint32_t *buf, uint32_t buf_size /* in words */) {
  int idx;
  for (idx = 0; idx < buf_size; idx++)
    write_register(dev, start_addr + (idx * 4), buf[idx]);
}

/** TCAM interface **/

/* measured in words */
static inline uint32_t cmd_buf_size(const tcam_cfg_t *cfg) {
  return 2 * cfg->key_size + cfg->val_size;
}

uint32_t *key_of_buf(const tcam_cfg_t *cfg, tcam_cmd_buf_t *cmd) {
  return &(cmd->buf[0]);
}

uint32_t *mask_of_buf(const tcam_cfg_t *cfg, tcam_cmd_buf_t *cmd) {
  return &(cmd->buf[cfg->key_size]);
}

uint32_t *val_of_buf(const tcam_cfg_t *cfg, tcam_cmd_buf_t *cmd) {
  return &(cmd->buf[2 * cfg->key_size]);
}

int tcam_check_cfg(const tcam_cfg_t *cfg) {
  /* The address map layout is currently:
        base_addr   -> status       [32-bit]
        + set_ofs   -> set_regs     [cmd_size * 32-bit]
        + get_ofs   -> get_regs     [cmd_size * 32-bit]
        + trig_ofs  -> trigger      [32-bit]
      where cmd_size = (1 + key_size + key_size + val_size) words
  */
  uint32_t cmd_size = 1 + cmd_buf_size(cfg);
  if (cfg->status_ofs != 0) {
    VLOG_DBG("Unexpected tcam status_offset %d (expected 0).", cfg->status_ofs);
    return 0;
  }
  if (cfg->set_ofs != 1) {
    VLOG_DBG("Unexpected tcam set_offset %d (expected 1).", cfg->set_ofs);
    return 0;
  }
  if (cfg->get_ofs  - cfg->set_ofs != cmd_size) {
    VLOG_DBG("tcam {get,set}_offset {%d,%d} gives unexpected cmd_size %d (expected %d).",
             cfg->get_ofs, cfg->set_ofs, cfg->get_ofs  - cfg->set_ofs, cmd_size);
    return 0;
  }
  if (cfg->trig_ofs - cfg->get_ofs != cmd_size) {
    VLOG_DBG("tcam {trig,get}_offset {%d,%d} gives unexpected cmd_size %d (expected %d).",
             cfg->trig_ofs, cfg->get_ofs, cfg->trig_ofs  - cfg->get_ofs, cmd_size);
    return 0;
  }
  return 1;
}

tcam_cmd_buf_t *tcam_alloc_cmd_buf(const tcam_cfg_t *cfg) {
  uint32_t buf_size = 4 * cmd_buf_size(cfg);
  tcam_cmd_buf_t *cb = (tcam_cmd_buf_t *)calloc(1, sizeof(tcam_cmd_buf_t) + buf_size);
  return cb;
}

void tcam_reset_cmd_buf(const tcam_cfg_t *cfg, tcam_cmd_buf_t *cmd) {
  uint32_t buf_size = 4 * cmd_buf_size(cfg);
  memset(cmd, 0, sizeof(tcam_cmd_buf_t) + buf_size);
}

/*  This is the main TCAM interaction function that performs the
    reads/writes using the device interface. */
static tcam_cmd_status_t do_tcam_cmd(const tcam_cfg_t *cfg, tcam_cmd_buf_t *cmd) {
  tcam_cmd_status_t st;

  /* Write the command buffer to the SetRegs. */
  uint32_t cmd_size = (sizeof(tcam_cmd_buf_t) + 4 * cmd_buf_size(cfg)) / 4;
  uint32_t *cb = (uint32_t *)cmd;
  write_buffer(cfg->dev, (uint32_t)(uintptr_t)(&cfg->base_addr[cfg->set_ofs]), cb, cmd_size);

  /* Write the trigger register. */
  write_register(cfg->dev, (uint32_t)(uintptr_t)(&cfg->base_addr[cfg->trig_ofs]), 1);

  /* Read the status register until it returns a non-pending value.
     FIXME: add a timeout here. */
  do {
    st = tcam_get_status(cfg);
    log_status(st);
    /* Do not loop if we are trying to clear the status. */
  } while (TCAM_CMDST_PENDING == st && TCAM_CMD_CLR_STATUS != cmd->cmd);

  /* Copy out the result, even in case of error, since it might
     contain more error information. */
  read_buffer(cfg->dev, (uint32_t)(uintptr_t)(&cfg->base_addr[cfg->get_ofs]), cb, cmd_size);

  return st;
}

tcam_cmd_status_t tcam_get_primed(const tcam_cfg_t *cfg, int *is_primed) {
  tcam_cmd_status_t st;
  tcam_cmd_buf_t *c = tcam_alloc_cmd_buf(cfg);

  c->cmd = TCAM_CMD_PRIMED_GET;
  st = do_tcam_cmd(cfg, c);

  if (TCAM_CMDST_CLEAR == st)
    *is_primed = c->cmd;

  free(c);
  return st;
}

tcam_cmd_status_t tcam_get_miss_val(const tcam_cfg_t *cfg, uint32_t *val_buf, uint32_t val_buflen) {
  ASSERT(val_buflen >= 4 * cfg->val_size);

  tcam_cmd_status_t st;
  tcam_cmd_buf_t *c = tcam_alloc_cmd_buf(cfg);

  c->cmd = TCAM_CMD_MISS_VAL_GET;
  st = do_tcam_cmd(cfg, c);

  if (TCAM_CMDST_CLEAR == st)
    memcpy(val_buf, val_of_buf(cfg, c), 4*cfg->val_size);

  free(c);
  return st;
}

tcam_cmd_status_t tcam_get_nokey_val(const tcam_cfg_t *cfg, uint32_t *val_buf, uint32_t val_buflen) {
  ASSERT(val_buflen >= 4 * cfg->val_size);

  tcam_cmd_status_t st;
  tcam_cmd_buf_t *c = tcam_alloc_cmd_buf(cfg);

  c->cmd = TCAM_CMD_NOKEY_VAL_GET;
  st = do_tcam_cmd(cfg, c);

  if (TCAM_CMDST_CLEAR == st)
    memcpy(val_buf, val_of_buf(cfg, c), 4*cfg->val_size);

  free(c);
  return st;
}

tcam_cmd_status_t tcam_get_entry(const tcam_cfg_t *cfg, uint16_t idx,
                                 int *is_valid,
                                 uint32_t *key_buf, uint32_t key_buflen  /* in bytes */,
                                 uint32_t *mask_buf, /* must be of size key_buflen */
                                 uint32_t *val_buf, uint32_t val_buflen  /* in bytes */) {

  ASSERT(key_buflen >= 4 * cfg->key_size);
  ASSERT(val_buflen >= 4 * cfg->val_size);

  tcam_cmd_status_t st;
  tcam_cmd_buf_t *c = tcam_alloc_cmd_buf(cfg);

  c->cmd = TCAM_CMD_ENTRY_GET;
  c->idx = idx;
  st = do_tcam_cmd(cfg, c);

  if (TCAM_CMDST_CLEAR == st) {
    *is_valid = c->cmd;
    if (c->idx != idx) {
      VLOG_DBG("Entry-Get got unexpected index %x, expected %x! (check alignment)",
               c->idx, idx);
    }
    memcpy(key_buf,  key_of_buf(cfg, c),  4*cfg->key_size);
    memcpy(mask_buf, mask_of_buf(cfg, c), 4*cfg->key_size);
    memcpy(val_buf,  val_of_buf(cfg, c),  4*cfg->val_size);
  }

  free(c);
  return st;
}

tcam_cmd_status_t tcam_set_entry(const tcam_cfg_t *cfg, uint16_t idx,
                                 uint32_t *key_buf, uint32_t key_buflen  /* in bytes */,
                                 uint32_t *mask_buf, /* must be of size key_buflen */
                                 uint32_t *val_buf, uint32_t val_buflen  /* in bytes */) {

  ASSERT(key_buflen >= 4 * cfg->key_size);
  ASSERT(val_buflen >= 4 * cfg->val_size);

  tcam_cmd_status_t st;
  tcam_cmd_buf_t *c = tcam_alloc_cmd_buf(cfg);

  c->cmd = TCAM_CMD_ENT_UPDATE;
  c->idx = idx;

  memcpy(key_of_buf(cfg, c),  key_buf,  4*cfg->key_size);
  memcpy(mask_of_buf(cfg, c), mask_buf, 4*cfg->key_size);
  memcpy(val_of_buf(cfg, c),  val_buf,  4*cfg->val_size);

  st = do_tcam_cmd(cfg, c);
  free(c);
  return st;
}

tcam_cmd_status_t tcam_del_entry(const tcam_cfg_t *cfg, uint16_t idx) {
  tcam_cmd_status_t st;
  tcam_cmd_buf_t *c = tcam_alloc_cmd_buf(cfg);
  c->cmd = TCAM_CMD_ENT_DELETE;
  c->idx = idx;
  st = do_tcam_cmd(cfg, c);
  free(c);
  return st;
}

tcam_cmd_status_t tcam_end_txn(const tcam_cfg_t *cfg) {
  tcam_cmd_status_t st;
  tcam_cmd_buf_t *c = tcam_alloc_cmd_buf(cfg);
  c->cmd = TCAM_CMD_END_TXN;
  st = do_tcam_cmd(cfg, c);
  free(c);
  return st;
}

tcam_cmd_status_t tcam_get_status(const tcam_cfg_t *cfg) {
  return read_register(cfg->dev, (uint32_t)(uintptr_t)(&cfg->base_addr[cfg->status_ofs]));
}

tcam_cmd_status_t tcam_clr_status(const tcam_cfg_t *cfg) {
  tcam_cmd_status_t st;
  tcam_cmd_buf_t *c = tcam_alloc_cmd_buf(cfg);
  c->cmd = TCAM_CMD_CLR_STATUS;
  st = do_tcam_cmd(cfg, c);
  free(c);
  return st;
}

/** Match Table / Instruction interface **/

static const char *port_type_str(uint32_t p) {
  switch (p) {
  case PORT_NORMAL:
    return "normal";
    break;
  case PORT_INPUT_PORT:
    return "i/p port";
  case PORT_FLOOD_PORT:
    return "flood";
  case PORT_ALL_PORTS:
    return "all";
  case PORT_CONTROLLER_PORT:
    return "controller";
  case PORT_LOCAL_PORT:
    return "local";
  case PORT_ANY_PORT:
    return "any";
  }
  return "UNKNOWN";
}

static void print_action(int i, action_encoding_t action) {
  switch (action.act_type) {
  case ACT_NONE:
    VLOG_DBG("\t\t action[%d]: none", i);
    break;
  case ACT_OUTPUT:
    VLOG_DBG("\t\t action[%d]: output port=%x port-type=%s (%x) (pad=%x)",
             i, action.act_val.output.port_num,
             port_type_str(action.act_val.output.port_type), action.act_val.output.port_type,
             action.act_val.output.pad);
    break;
  default:
    VLOG_DBG("\t\t action[%d]: unknown type %x (check alignment and/or endianness)",
             i, action.act_type);
  }
}

void print_instruction(instr_encoding_t *instr) {
  int i;
  /* fprintf(stdout, "\t flags: 0x%x\n", instr->flags); */
  if (INSTR_GOTOTABLE & instr->flags)
    VLOG_DBG("\t goto-table: %u", instr->table_id);
  if (INSTR_SETMETADATA & instr->flags)
    VLOG_DBG("\t set-metadata: value=%x  mask=%x",
             instr->metadata_value, instr->metadata_mask);
  if (INSTR_WRITEACTIONS & instr->flags) {
    VLOG_DBG("\t write-actions:");
    for (i = 0; i < NUM_WRITE_ACTIONS; i++)
      print_action(i, instr->write_actions[i]);
  }
  if (INSTR_APPLYACTIONS & instr->flags) {
    VLOG_DBG("\t apply-actions:");
    for (i = 0; i < NUM_APPLY_ACTIONS; i++)
      print_action(i, instr->apply_actions[i]);
  }
  if (INSTR_CLEARACTIONS & instr->flags)
    VLOG_DBG("\t clear-actions");
}

action_encoding_t make_output_action(port_t typ, uint8_t port) {
  action_encoding_t r;
  memset(&r, 0, sizeof(r));
  r.act_type = ACT_OUTPUT;
  r.act_val.output.port_num = port;
  r.act_val.output.port_type = typ;
  return r;
}

instr_encoding_t make_apply_action_instr(const action_encoding_t act) {
  instr_encoding_t i;
  memset(&i, 0, sizeof(i));
  i.flags = INSTR_APPLYACTIONS;
  i.apply_actions[0] = act;
  return i;
}

instr_encoding_t make_write_action_instr(const action_encoding_t act) {
  instr_encoding_t i;
  memset(&i, 0, sizeof(i));
  i.flags = INSTR_WRITEACTIONS;
  i.write_actions[0] = act;
  return i;
}

instr_encoding_t make_goto_instr(uint8_t table) {
  instr_encoding_t i;
  memset(&i, 0, sizeof(i));
  i.flags = INSTR_GOTOTABLE;
  i.table_id = table;
  return i;
}

/** Pipeline management interface **/

void init_tcam_cfg(tcam_cfg_t *cfg, int dev, const bs_info_t *bsi, int ntcam) {
  cfg->dev = dev;
  VLOG_DBG("Initializing cfg for tcam %d ...\n", ntcam);

  struct tcam_info tci = bsi->tcams[ntcam];
  cfg->base_addr  = (uint32_t *)(uintptr_t)tci.base_addr;
  cfg->status_ofs = 0;
  cfg->set_ofs    = cfg->status_ofs + 1;
  cfg->get_ofs    = cfg->set_ofs + 22;
  cfg->trig_ofs   = cfg->get_ofs + 22;

  cfg->key_size   = tci.key_size;
  cfg->val_size   = tci.val_size;
  cfg->num_entries = tci.num_entries;

  ASSERT(tcam_check_cfg(cfg));
}

int is_pipeline_activated(const bs_info_t *bsi) {
  return (0 != read_register(bsi->dev, bsi->pipeline_base_addr));
}

void activate_pipeline(const bs_info_t *bsi) {
  write_register(bsi->dev, bsi->pipeline_base_addr, 1);
}

/* Switch interface helpers */

int open_switch(bs_info_t *bsi) {
  if (bsi->dev < 0)
    bsi->dev = open_device();
  return bsi->dev;
}

void close_switch(bs_info_t *bsi) {
  if (bsi->dev >= 0)
    close(bsi->dev);
}
