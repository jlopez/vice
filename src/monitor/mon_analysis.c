/*
 * mon_analysis.c - The VICE built-in monitor, deep analysis functions.
 *
 * Written by
 *  Jesus Lopez <jesus@jesusla.com>
 *
 * This file is part of VICE, the Versatile Commodore Emulator.
 * See README for copyright notice.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA
 *  02111-1307  USA.
 *
 */

#include "vice.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif

#include "log.h"
#include "lib.h"
#include "machine.h"
#include "mon_disassemble.h"
#include "mon_analysis.h"
#include "monitor.h"
#include "montypes.h"
#include "screenshot.h"
#include "types.h"


/* Globals */


#ifdef FEATURE_DEEPANALYSIS

/* Defines */
#define MAX_REFERENCES 65536

/* Types */
typedef enum
{
    Direct,
    Indirect
} addressing_mode_t;

struct reference_s
{
    uint32_t count;
    uint32_t pc;
    uint8_t op;
    uint8_t access;
    CLOCK first_access;
    CLOCK last_access;
    struct reference_s *next;
};
typedef struct reference_s reference_t;

/* Deep analysis variables */
static reference_t *references[MAX_REFERENCES];
static reference_t reference_pool[1048576] = { { 0 } };
static uint32_t next_available_reference = 0;

static void update_reference(uint32_t pc, uint32_t address, CLOCK clock, uint8_t op, uint8_t access)
{
    if (access == ACCESS_NONE || address >= MAX_REFERENCES)
        return;
    reference_t **ptr = references + address;
    while (*ptr) {
        if ((*ptr)->pc == pc) {
            (*ptr)->last_access = clock;
            (*ptr)->count++;
            return;
        }
        ptr = &(*ptr)->next;
    }
    if (next_available_reference == 1048576)
        return;
    *ptr = reference_pool + next_available_reference++;
    (*ptr)->count = 1;
    (*ptr)->pc = pc;
    (*ptr)->op = op;
    (*ptr)->access = access;
    (*ptr)->first_access = (*ptr)->last_access = clock;
    (*ptr)->next = 0;
    if (!(next_available_reference & 0x3FFF))
        log_message(LOG_DEFAULT, "Allocated 0x%X references", next_available_reference);
}

void mon_analysis_init(void)
{
}

void mon_analysis_shutdown(void)
{
}

void monitor_analysis_hook(CLOCK clock, uint16_t pc, uint8_t op, uint16_t addr1, uint16_t addr2, opcode_analysis_info_t info)
{
    update_reference(pc, addr1, clock, op, info.operand1_access);
    update_reference(pc, addr2, clock, op, info.operand2_access);
}

void mon_analysis_info(void)
{
    mon_out("Allocated Blocks: $%04X\n", next_available_reference);
}

void mon_analysis_list(uint32_t start_addr, uint32_t end_addr) {
    long len = mon_evaluate_address_range(&start_addr, &end_addr, FALSE, 8);
    MON_ADDR mem = addr_memspace(start_addr);
    MON_ADDR addr = addr_location(start_addr);
    for (int i = 0; i < len; ++i) {
        reference_t *ptr = references[addr + i];
        for (int j = 0; ptr; ++j, ptr = ptr->next) {
            mon_out(j ? "      " : ":%04X ", addr + i);
            mon_out("%04X %02X %2d %d %d %d\n", ptr->pc, ptr->op, ptr->access, ptr->count,
                    ptr->first_access, ptr->last_access);
        }
    }
}

#else /* !FEATURE_DEEPANALYSIS */

/* stubs */
static void mon_analysis_stub(void)
{
    mon_out("Disabled. configure with --enable-deepanalysis and recompile.\n");
}

void mon_analysis_init(void)
{
}

void mon_analysis_shutdown(void)
{
}

void mon_analysis_info(void)
{
    mon_analysis_stub();
}

#endif
