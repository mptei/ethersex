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

#include <avr/pgmspace.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "config.h"
#include "protocols/uip/uip.h"
#include "protocols/dns/resolv.h"
#include "core/eeprom.h"

#include "eibd.h"
#include "eibd_state.h"
#include "protocols/ecmd/ecmd-base.h"

static const unsigned char PROGMEM eibd_open_groupcon[] =
	{ /* size */ 0x00, 0x05,
	/* EIB_OPEN_GROUPCON */ 0x00, 0x26, 0x00, 0x00, 0x00 };

static uip_conn_t *eibd_conn;

/* Buffer to allow buffering of some eib commands. */
#define QUEUELEN 10
static struct {
	uint16_t dst;
	uint8_t len;
	uint8_t buf[18];
} sendBuf[QUEUELEN];
static uint8_t head = 0;
static uint8_t tail = 0;

#define EIBD_MAXLISTENERS 10
static eibd_callback_t *listeners[EIBD_MAXLISTENERS];

#define STATE (&uip_conn->appstate.eibd)

#define EIBD_SEND(str) do {			  \
	memcpy_P (uip_sappdata, str, sizeof (str));     \
	uip_send (uip_sappdata, sizeof (str));      \
	EIBDCOMDEBUG("sent bytes: %d\n", sizeof(str)); \
    } while(0)

static void
eibd_send_data (uint8_t send_state, uint8_t action)
{
    EIBDCOMDEBUG ("send_data: %d action: %d\n", send_state, action);

    switch (send_state) {
    case EIBD_OPEN_GROUPCON:
	EIBD_SEND (eibd_open_groupcon);
	break;
    case EIBD_OPEN_GROUPCON_ANSW:
    	/* Send nothing */
	break;
    case EIBD_CONNECTED:
	switch (action) {
	case EIBD_ACTION_NONE:
	case EIBD_ACTION_WRITE:
	  if (head != tail) {
	    ((unsigned char *)uip_sappdata)[2]=0x00;
	    ((unsigned char *)uip_sappdata)[3]=0x27;
	    ((unsigned char *)uip_sappdata)[4]=sendBuf[tail].dst>>8;
	    ((unsigned char *)uip_sappdata)[5]=sendBuf[tail].dst&0xff;
	    memcpy (uip_sappdata+6, sendBuf[tail].buf, sendBuf[tail].len);
	    uip_slen = 4+sendBuf[tail].len;
	    ((unsigned char *)uip_sappdata)[0]=uip_slen>>8;
	    ((unsigned char *)uip_sappdata)[1]=uip_slen&0xff;
	    uip_slen += 2;
	    EIBDCOMDEBUG ("Sending %d bytes\n", uip_slen);
	    tail = (tail+1)%QUEUELEN;
	  }
	  break;
	default:
	    EIBDCOMDEBUG ("idle, don't know what to send right now ...\n");
        }
	break;

    default:
	EIBDCOMDEBUG ("eeek, what?\n");
	uip_abort ();
	break;
    }

    STATE->sent = send_state;
}


/*
 * Handle group send command via ecmd
 */
int16_t
eibd_send_request(char *cmd, char *output, uint16_t len){
  uint16_t addr;

  EIBDDEBUG ("groups\n");

  if (((head+1)%QUEUELEN) == tail) {
    return ECMD_FINAL(snprintf_P(output, len, PSTR("EIBD request buffer full")));
  }

  // Skip leading space
  while (' ' == *cmd && *cmd) ++cmd;

  {
    uint8_t a;
    uint8_t b;
    uint8_t c;
    if (3 != sscanf_P(cmd, PSTR("%u/%u/%u"), &a, &b, &c)) {
      return ECMD_FINAL(snprintf_P(output, len, PSTR("Bad EIB address %s"), cmd));
    }
    addr = a<<11 | b<<8 | c;
  }

  // Skip address
  while (' ' != *cmd && *cmd) ++cmd;
  // Skip space
  while (' ' == *cmd && *cmd) ++cmd;

  {
    uint8_t buf[2];
    buf[0] = 0x00;
    if (0 == strcmp_P(cmd,PSTR("on"))) {
      buf[1] = 0x81;
    } else if (0 == strcmp_P(cmd,PSTR("off"))) {
      buf[1] = 0x80;
    } else {
      return ECMD_FINAL(snprintf_P(output, len, PSTR("Wrong state: %s"), cmd));
    }
    eibd_send_telegram (addr, buf, 2);
  }

  return ECMD_FINAL_OK;
}

int16_t
eibd_send_telegram (uint16_t dst, const uint8_t *buf, uint8_t len)
{
  if (((head+1)%QUEUELEN) == tail) {
  	EIBDDEBUG("Send buffer is full\n");
	return -1;
  }
  sendBuf[head].dst = dst;
  sendBuf[head].len = len;
  memcpy (sendBuf[head].buf, buf, len);
  head = (head+1)%QUEUELEN;
  return 0;
}

void eibd_sendDPT1(uint8_t mode, uint16_t dst, uint8_t onoff)
{
        uint8_t buf[2] = { 0x00, mode<<6 | (onoff?0x01:0x00) };
        eibd_send_telegram (dst, buf, sizeof(buf));
}

uint16_t
eibd_encode_dpt9 (int16_t val10)
{
  uint16_t sign = val10<0?0x8000:0;
  uint8_t exp = 0;
  uint32_t mant;

  mant = val10*10;
  while (abs(mant) > 2047) {
    mant = mant >> 1;
    exp++;
  }

  return sign | (exp << 11) | (mant & 0x07ff);
}

int16_t
eibd_decode_dpt9 (const uint8_t *buf)
{
	// buf[0]   buf[1]
	// MEEEEMMM MMMMMMMM
	// Val = 2^E * (M/100) (standard)
	// Val = 2^E * (M/10) (return value is multiplied by 10)
	// in M the bits of EEEE are filled with MSB M (0xf800 if MSB M is 1)
	return ((1<<((buf[0]>>3)&0x0f)) * (int16_t)(((buf[0]&0x07)<<8|buf[1])|((buf[0]&0x80)?0xf800:0)) / 10);
}

void eibd_sendDPT9(uint8_t mode, uint16_t dst, uint16_t val10)
{
        uint8_t buf[4] = { 0x00, mode<<6 };
        uint16_t real = eibd_encode_dpt9(val10);
        buf[2] = real>>8;
        buf[3] = real&0xff;
        eibd_send_telegram (dst, buf, sizeof(buf));
}

void eibd_sendDPT10SecOfDay(uint8_t mode, uint16_t dst, uint32_t secOfDay)
{
        uint8_t buf[5] = { 0x00, mode<<6 };
	buf[4] = secOfDay%60;
        buf[3] = (secOfDay/=60)%60;
        buf[2] = secOfDay/60;
        eibd_send_telegram (dst, buf, sizeof(buf));
}

void eibd_sendDPT10HMS(uint8_t mode, uint16_t dst, uint8_t hour, uint8_t min, uint8_t sec)
{
        uint8_t buf[5] = { 0x00, mode<<6 };
        buf[2] = hour;
        buf[3] = min;
	buf[4] = sec;
        eibd_send_telegram (dst, buf, sizeof(buf));
}

int16_t eibd_read_request (uint16_t dst)
{
        uint8_t buf[2] = { 0x00, EIBD_MODE_READ<<6 };
        return eibd_send_telegram (dst, buf, sizeof(buf));
}

static uint8_t
eibd_parse (void)
{
    EIBDCOMDEBUG ("eibd_parse stage=%d (action %d)\n", STATE->stage, STATE->action);

    unsigned char *data = (unsigned char*)uip_appdata;

    switch (STATE->stage) {
    case EIBD_OPEN_GROUPCON:
    	if (uip_len != 2 || data[0] != 0 || data[1] != 0x2) {
	  EIBDCOMDEBUG ("Expected 0x0002 (length), but got 0x%02x%02x\n", 
	  	     data[0], data[1]);
	  return 1;
	}
	break;
    case EIBD_OPEN_GROUPCON_ANSW:
    	if (uip_len != 2 || data[0] != 0 || data[1] != 0x26) {
	  EIBDCOMDEBUG ("Expected answer 0x0026, but got 0x%02x%02x\n", 
	  	     data[0], data[1]);
	  return 1;
	}
	break;
    case EIBD_CONNECTED:
    	if (uip_len >= 8 && data[0] == 0 && data[1] == 0x27) {
		//  we got a valid packet
		uint16_t src = (data[2]<<8) | data[3];
		uint16_t dst = (data[4]<<8) | data[5];
		if (0 == (data[6] & 0x03) && (data[7]&0xC0) != 0xC0) {
			uint8_t mode = data[7]>>6;
			data[7] &= 0x3F;
			EIBDDEBUG ("Got request: %02x for %d/%d/%d\n",
				   mode, dst>>11,(dst&0x07FF)>>8,(dst&0xFF));
			// Now we can call the listeners
			{
				int len = 1;
				uint8_t *buf = &data[7];
				if (uip_len > 8) {
					len = uip_len-8;
					buf = &data[8];
				}
				int i;
				for (i = 0; i < EIBD_MAXLISTENERS; ++i) {
					if (0 != listeners[i]) {
						EIBDDEBUG ("Calling listener %p\n", listeners[i]);
						listeners[i](mode, src, dst, len, buf);
					}
				}
			}
		}
	} else {
		EIBDCOMDEBUG ("ignoring EIB data: %02x %02x %02x %02x\n",
			   data[0], data[1], data[2], data[3]);
	}
	break;
    default:
	EIBDDEBUG ("in wrong state: %d!\n", STATE->stage);
	return 1;
    }

    /* Jippie, let's enter next stage if we haven't reached connected. */
    if (STATE->stage != EIBD_CONNECTED)
	STATE->stage ++;
    return 0;
}

static void
eibd_main(void)
{
    if (uip_aborted() || uip_timedout()) {
	EIBDCOMDEBUG ("connection aborted\n");
        eibd_conn = NULL;
    }

    if (uip_closed()) {
	EIBDCOMDEBUG ("connection closed\n");
        eibd_conn = NULL;
    }
    if (uip_connected()) {
	EIBDCOMDEBUG ("new connection\n");
	STATE->stage = EIBD_OPEN_GROUPCON;
	STATE->sent = EIBD_INIT;
    }

    if (uip_acked() && STATE->stage == EIBD_CONNECTED) {
      /* FIXME: Here incrementing tail? */
    }
    if (uip_newdata() && uip_len) {
	EIBDCOMDEBUG ("received data: %d\n", uip_len);
	if (eibd_parse ()) {
	    uip_close ();		/* Parse error */
	    return;
	}
    }

    if (uip_rexmit())
	eibd_send_data (STATE->stage, STATE->action);
    else if ((STATE->stage > STATE->sent || STATE->stage == EIBD_CONNECTED)
	     && (uip_newdata()
		 || uip_acked()
		 || uip_connected()))
	eibd_send_data (STATE->stage, STATE->action);
    else if (STATE->stage == EIBD_CONNECTED && uip_poll() && (STATE->action || tail!=head))
	eibd_send_data (STATE->stage, STATE->action);
}

void
eibd_connect(uip_ipaddr_t *eibdserver)
{
  EIBDDEBUG ("connecting to %d.%d.%d.%d\n",
  		uip_ipaddr1(eibdserver), uip_ipaddr2(eibdserver),
		uip_ipaddr3(eibdserver),uip_ipaddr4(eibdserver));

  if (eibd_conn != NULL)
    uip_close();

  uint16_t port;
  eeprom_restore_int(eibd_port, &port);
  eibd_conn = uip_connect(eibdserver, HTONS(port), eibd_main);
  if (! eibd_conn) {
    EIBDCOMDEBUG ("no uip_conn available.\n");
    return;
  }
}

#ifdef DNS_SUPPORT
void
eibd_dns_query_cb(char *name, uip_ipaddr_t *ipaddr)
{
  if (!ipaddr) {
  	EIBDDEBUG ("Name resolution failed for \"%s\"\n",
		   name);
  } else {
  	EIBDDEBUG ("DNS returned %u.%u.%u.%u for \"%s\"\n",
  		uip_ipaddr1(ipaddr), uip_ipaddr2(ipaddr),
		uip_ipaddr3(ipaddr),uip_ipaddr4(ipaddr), name);

  	eibd_connect(ipaddr);
  }
}
#endif

static void eibd_getip_connect ()
{
#ifdef DNS_SUPPORT
    uip_ipaddr_t *eibdIP;
    char host[16];
    eeprom_restore (eibd_host, host, 16);
    if(!(eibdIP = resolv_lookup(host)))
      resolv_query(host,eibd_dns_query_cb);
    else
      eibd_connect(eibdIP);

#else /* ! DNS_SUPPORT */
    uip_ipaddr_t ip;
    eeprom_restore_ip (eibd_ip, &ip);
    eibd_connect(&ip);
#endif
}

void
eibd_periodic(void)
{
  if (!eibd_conn) {
	eibd_getip_connect();
  }
}

void
eibd_init(void)
{
    EIBDDEBUG ("initializing eibd client\n");
    eibd_conn = NULL;
    {
    	int i;
	for (i=0;i<EIBD_MAXLISTENERS;++i) listeners[i]=0;
    }
}

int16_t
parse_cmd_eibd_port(char *cmd, char *output, uint16_t len)
{
    while (*cmd == ' ') cmd++;

    uint16_t port;

    if (*cmd != '\0') {
        /* try to parse port num */
	if (sscanf_P(cmd, PSTR("%i"), &port) != 1)
            return ECMD_ERR_PARSE_ERROR;

        eeprom_save_int(eibd_port, port);
        eeprom_update_chksum();

        return ECMD_FINAL_OK;
    }
    else
    {
	uint16_t port;
	eeprom_restore_int (eibd_port, &port);

        return ECMD_FINAL(snprintf_P(output, len, PSTR("%d"), port));
    }
}

int16_t
parse_cmd_eibd_host(char *cmd, char *output, uint16_t len)
{
#ifdef DNS_SUPPORT
    while (*cmd == ' ') cmd++;

    if (*cmd != '\0') {

        eeprom_save(eibd_host, cmd, 16);
        eeprom_update_chksum();

        return ECMD_FINAL_OK;
    }
    else
    {
	char host[16];
	eeprom_restore (eibd_host, host, 16);

        return ECMD_FINAL(snprintf_P(output, len, PSTR("%s"), host));
    }
#else
	return ECMD_FINAL(snprintf_P(outpuf, len, PSTR("DNS support is not active")));
#endif
}

int16_t
parse_cmd_eibd_ip(char *cmd, char *output, uint16_t len)
{
#ifndef DNS_SUPPORT
    while (*cmd == ' ') cmd++;

    if (*cmd != '\0') {
    	 uip_ipaddr_t eibaddr;

        /* try to parse ip */
        if (parse_ip (cmd, &eibaddr))
	    return ECMD_ERR_PARSE_ERROR;

        eeprom_save(eibd_ip, &eibaddr, IPADDR_LEN);
        eeprom_update_chksum();

        return ECMD_FINAL_OK;
    }
    else
    {
    	uip_ipaddr_t ip;
	eeprom_restore_ip (eibd_ip, &ip);

        return ECMD_FINAL(print_ipaddr(&ip, output, len));
    }
#else
	return ECMD_FINAL(snprintf_P(output, len, PSTR("DNS is active; no ip configuration")));
#endif
}

uint8_t eibd_add_receive_listener (eibd_callback_t *callback)
{
	EIBDDEBUG ("Adding receive listener %p\n", callback);

	int i;
	for (i=0;i<EIBD_MAXLISTENERS;++i) {
		if (0 == listeners[i]) {
			listeners[i] = callback;
			EIBDDEBUG ("Added listener %p on %d\n", listeners[i], i);
			return i;
		}
	}
	return 0xff;
}

uint8_t eibd_remove_receive_listener (eibd_callback_t *callback)
{
	int i;
	for (i=0;i<EIBD_MAXLISTENERS;++i) {
		if (callback == listeners[i]) {
			listeners[i] = 0;
			return i;
		}
	}
	return 0xff;
}

/*
  -- Ethersex META --
  header(services/eibd/eibd.h)
  timer(500,eibd_periodic())
  net_init(eibd_init)

  state_header(services/eibd/eibd_state.h)
  state_tcp(struct eibd_connection_state_t eibd)
*/
