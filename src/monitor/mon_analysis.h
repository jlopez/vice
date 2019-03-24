/*
 * mon_analysis.h - The VICE built-in monitor, deep analysis functions.
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

#ifndef VICE_MON_ANALYSIS_H
#define VICE_MON_ANALYSIS_H

#include "montypes.h"
#include "types.h"

extern void mon_analysis_init(void);
extern void mon_analysis_shutdown(void);

extern void mon_analysis_info(void);
extern void mon_analysis_list(uint32_t start_addr, uint32_t end_addr);

#endif
