/*
 * Copyright (c) 2009 by Mike Pieper mike@pieper-family.de
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
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

#include <avr/io.h>
#include <avr/pgmspace.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <util/delay.h>

#include "config.h"
#include "eibd.h"
#include "protocols/ecmd/ecmd-base.h"

int16_t parse_cmd_eibd_send(char *cmd, char *output, uint16_t len) 
{
  return eibd_send_request(cmd, output, len);
}

/*
-- Ethersex META --
block([[eibd communication]])
ecmd_feature(eibd_send, "eibsend",, Send events to group addresses)
ecmd_feature(eibd_port, "eibdport",, Shows or set the eibd port)
#ifdef DNS_SUPPORT
ecmd_feature(eibd_host, "eibdhost",, Shows or set the eibd host)
#else
ecmd_feature(eibd_ip, "eibdip",, Shows or set the eibd ip address)
#endif
*/
