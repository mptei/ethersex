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

#ifndef HAVE_EIBD_H
#define HAVE_EIBD_H

/* Convert a group address into 2 bytes */
#define EIBGA(g,m,e) (uint16_t)((g)<<11 | (m)<<8 | (e))

int16_t
eibd_send_request(char *cmd, char *output, uint16_t len);

int16_t
eibd_port_request(char *cmd, char *output, uint16_t len);

int16_t
eibd_host_request(char *cmd, char *output, uint16_t len);

void
eibd_init(void);

void
eibd_periodic(void);

int16_t
eibd_send_telegram (uint16_t dst, const uint8_t *buf, uint8_t len);

/* Function to convert into a real value */
/* The input value is multiplied by 10 */
uint16_t
eibd_encode_dpt9 (int16_t val10);

/* Convert DPT9 value into uint16_t. The result
 * is multiplied by 10. 
 * The buffer must contain 2 bytes             */
int16_t
eibd_decode_dpt9 (const uint8_t *buf);

/* Send a DPT1 value */
void
eibd_sendDPT1(uint8_t mode, uint16_t dst, uint8_t onoff);

/* Send a DPT9 value. The input value is multiplied by 10 */
void
eibd_sendDPT9(uint8_t mode, uint16_t dst, uint16_t val10);

/* Send a DPT10 (Time) value. The input value are seconds of the day */
void
eibd_sendDPT10SecOfDay(uint8_t mode, uint16_t dst, uint32_t secOfDay);

/* Send a DPT10 (Time) value. The input values are already splitted */
void 
eibd_sendDPT10HMS(uint8_t mode, uint16_t dst, uint8_t hour, uint8_t min, uint8_t sec);

int16_t
eibd_read_request (uint16_t dst);

#define EIBD_MODE_READ	0
#define EIBD_MODE_RESPONSE 1
#define EIBD_MODE_WRITE 2

/* Type of callback functions for EIB receiption */
typedef void (eibd_callback_t)(uint8_t mode, uint16_t src, uint16_t dst,
			       uint8_t len, const uint8_t*buf);

uint8_t eibd_add_receive_listener (eibd_callback_t *callback);
uint8_t eibd_remove_receive_listener (eibd_callback_t *callback);

#include "config.h"
#ifdef DEBUG_EIBDCOM
# include "core/debug.h"
# define EIBDCOMDEBUG(a...)  debug_printf("eibd: " a)
#else
# define EIBDCOMDEBUG(a...)
#endif
#ifdef DEBUG_EIBD
# include "core/debug.h"
# define EIBDDEBUG(a...)  debug_printf("eibd: " a)
#else
# define EIBDDEBUG(a...)
#endif

#endif  /* HAVE_EIBD_H */
