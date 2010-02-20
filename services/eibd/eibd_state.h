/*
 * Copyright (c) 2009 by Mike Pieper mike@pieper-family.de
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 * For more information on the GPL, please go to:
 * http://www.gnu.org/copyleft/gpl.html
 */

#ifndef HAVE_EIBD_STATE_H
#define HAVE_EIBD_STATE_H

enum {
    EIBD_INIT,

    EIBD_OPEN_GROUPCON,
    /* send: EIB_OPEN_GROUPCON */
    /* expect: length 2 */

    EIBD_OPEN_GROUPCON_ANSW,
    /* expect: 0x0026 */

    EIBD_CONNECTED,
};

enum {
	EIBD_ACTION_NONE,
	EIBD_ACTION_WRITE,
};
#include <inttypes.h>
#include "protocols/ecmd/via_tcp/ecmd_state.h"

#define TARGET_BUDDY_MAXLEN 40

struct eibd_connection_state_t {
    uint8_t stage;
    uint8_t sent;
    uint8_t action;
};

#endif  /* HAVE_EIBD_STATE_H */
