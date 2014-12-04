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

#include "vlog.h"

VLOG_DEFINE_THIS_MODULE(blueswitch_util);

int
bsw_extract_tcam_key(const struct tcam_info *tcam OVS_UNUSED,
                     const struct match *match OVS_UNUSED,
                     struct bsw_tcam_key *key OVS_UNUSED)
{
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
