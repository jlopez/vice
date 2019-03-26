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
#include <console.h>

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
#define MAX_EPOCHS 32

#define EPOCH_MAGIC "epoch-64"
#define EPOCH_FILE_VERSION 1
#define EPOCH_FILE_PATTERN "/Users/jlopez/Downloads/epochs/epoch-%02d-%08X.era"

#define CHECK_ACCESS(access, flags) ((access) & flags)

/* Types */
struct reference_s
{
    uint32_t count;
    uint32_t pc;
    uint32_t op;
    uint8_t access;
    CLOCK first_access;
    CLOCK last_access;
    struct reference_s *next;
};
typedef struct reference_s reference_t;

/* Deep analysis variables */
static reference_t *references[MAX_REFERENCES] = { 0 };
static reference_t reference_pool[1048576] = { { 0 } };
static bool reference_disabled = FALSE;
static uint32_t next_available_reference = 0;
struct {
    int epoch;
    CLOCK epoch_start;
    CLOCK epoch_end;
    uint32_t starting_address;
} current_epoch = { 0 };

static reference_t *get_reference(uint32_t addr)
{
    return (addr & 0xFFFF) < MAX_REFERENCES ? references[addr & 0xFFFF] : NULL;
}

static void reference_reset()
{
    next_available_reference = 0;
    memset(references, 0, sizeof(references));
}

static inline void write32(long datum, FILE *f)
{
    fwrite(&datum, 4, 1, f);
}

static void epoch_save()
{
    char buffer[128];
    snprintf(buffer, sizeof(buffer), EPOCH_FILE_PATTERN,
            current_epoch.epoch, current_epoch.epoch_start);
    FILE *f = fopen(buffer, "wb");
    if (!f)
    {
        log_error(LOG_DEFAULT, "Unable to write epoch file %s", buffer);
        return;
    }
    fwrite(EPOCH_MAGIC, sizeof(EPOCH_MAGIC) - 1, 1, f);
    write32(EPOCH_FILE_VERSION, f);
    write32(MAX_REFERENCES, f);
    long ptr = ftell(f) + MAX_REFERENCES * 4;
    for (int i = 0; i < MAX_REFERENCES; ++i)
        write32(references[i] - reference_pool + ptr, f);
    for (int i = 0; i < next_available_reference; ++i)
    {
        reference_t *ref = reference_pool + i;
        fwrite(ref, sizeof(reference_t) - 4, 1, f);
        write32(ref->next - reference_pool + ptr, f);
    }
    fclose(f);
}

static void epoch_start(uint32_t pc, CLOCK clock)
{
    current_epoch.epoch++;
    current_epoch.epoch_start = clock;
    current_epoch.starting_address = pc;
    if (current_epoch.epoch >= MAX_EPOCHS)
    {
        reference_disabled = TRUE;
        log_message(LOG_DEFAULT, "Epoch count %d exceeded. Disabling analytics", MAX_EPOCHS);
    }
    else
        log_message(LOG_DEFAULT, "Starting epoch #%d: pc=$%04X clk=%d",
                current_epoch.epoch, pc, clock);
}

static void epoch_end(CLOCK clock)
{
    current_epoch.epoch_end = clock;
}

static bool epoch_is_open()
{
    return current_epoch.epoch;
}

static void epoch_enter_new(uint32_t pc, CLOCK clock)
{
    if (epoch_is_open())
    {
        epoch_end(clock);
        epoch_save();
    }
    epoch_start(pc, clock);
    reference_reset();
}

static void update_reference(uint32_t pc, uint32_t address, CLOCK clock, uint32_t op, int access)
{
    if (access == ACCESS_NONE || address >= MAX_REFERENCES || reference_disabled)
        return;
    reference_t **ptr = references + address;
    bool is_exec = CHECK_ACCESS(access, ACCESS_EXECUTE);
    bool should_start_epoch = is_exec && !epoch_is_open();
    while (*ptr) {
        if ((*ptr)->pc == pc) {
            (*ptr)->last_access = clock;
            (*ptr)->count++;
            return;
        }
        if (is_exec)
            should_start_epoch |= CHECK_ACCESS((*ptr)->access, ACCESS_WRITE);
        ptr = &(*ptr)->next;
    }
    if (should_start_epoch)
    {
        epoch_enter_new(pc, clock);
        // Try again in the new epoch
        return update_reference(pc, address, clock, op, access);
    }
    if (next_available_reference == 1048576)
        return;
    *ptr = reference_pool + next_available_reference++;
    (*ptr)->count = 1;
    (*ptr)->pc = pc;
    (*ptr)->op = op;
    (*ptr)->access = (uint8_t)access;
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

void monitor_analysis_hook(CLOCK clock, uint16_t pc, uint32_t op, uint16_t addr1, uint16_t addr2, opcode_analysis_info_t info)
{
    update_reference(pc, pc, clock, op, ACCESS_EXECUTE_BYTES(info.opcode_size));
    update_reference(pc, addr1, clock, op, info.operand1_access);
    update_reference(pc, addr2, clock, op, info.operand2_access);
}

void mon_analysis_info(void)
{
    mon_out("Allocated Blocks: $%04X\n", next_available_reference);
}

static const char *access_to_string(uint8_t access)
{
    static char buf[6];
    buf[0] = 'r';
    buf[0] = (char)((access & ACCESS_READ) ? 'r' : '-');
    buf[1] = (char)((access & ACCESS_WRITE) ? 'w' : '-');
    buf[2] = (char)((access & ACCESS_EXECUTE) ? 'x' : '-');
    buf[3] = (char)((access & ACCESS_FORMAT_INDEXED) ? 't' :
                   (access & ACCESS_FORMAT_INDIRECT) ? 'i' : '-');
    buf[4] = " 234"[access & ACCESS_BYTES_MASK];
    buf[5] = 0;
    return buf;
}

static const char *reference_disassemble_referrer(reference_t *ref)
{
    uint32_t o = ref->op;
    return mon_disassemble_to_string_ex(
            addr_memspace(ref->pc),
            addr_location(ref->pc),
            o & 0xff, (o >> 8) & 0xff, (o >> 16) & 0xff, (o >> 24) & 0xff,
            TRUE, NULL);
}

static int console_height(int suggestion)
{
    static int last_known_height = 0;
    if (console_log)
        last_known_height = console_log->console_yres;
    return last_known_height ? last_known_height : suggestion;
}

void mon_analysis_list(uint32_t start_addr, uint32_t end_addr) {
    static int desired_lines = 24;
    int lines = end_addr == BAD_ADDR ? console_height(desired_lines) - 1 : 0;
    long len = mon_evaluate_address_range(&start_addr, &end_addr, FALSE, 8);
    MEMSPACE mem = addr_memspace(start_addr);
    dot_addr[mem] = start_addr;

    for (int i = 0, l = 0; i <= len || (lines && l < lines); ++i) {
        MON_ADDR addr = dot_addr[mem];
        reference_t *ptr = get_reference(addr);
        for (int j = 0; ptr; ++j, ptr = ptr->next, ++l) {
            mon_out(j ? "      " : ":%04X ", addr & 0xFFFF);
            mon_out("%04X %-12.12s %s %8d %15d %15d\n",
                    ptr->pc, reference_disassemble_referrer(ptr) + 12,
                    access_to_string(ptr->access), ptr->count,
                    ptr->first_access, ptr->last_access);
            if (mon_stop_output)
                return;
        }
        mon_inc_addr_location(dot_addr + mem, 1);
        desired_lines = l;
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
