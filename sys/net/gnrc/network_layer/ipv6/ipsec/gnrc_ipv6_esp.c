/*
 * Copyright (C) 2018 Maximilian Malkus <malkus@cip.ifi.lmu.de>
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#include "net/ipv6/addr.h"
#include "net/gnrc.h"
#include "thread.h"
#include "net/gnrc/ipv6/hdr.h"
#include "net/gnrc/ipv6/ext.h"
#include "net/gnrc/ipv6/ipsec/ipsec.h"

#include "limits.h"

#include "net/gnrc/ipv6/ipsec/esp.h"

#define ENABLE_DEBUG    (1)
#include "debug.h"

/**
 * @brief       builds esp header - including ecryption of the payload
 *
 * @param[in] pkt   pkt at ipv6 header
 *
 * @return  pkt at ipv6 header with esp encasulated payload
 */
gnrc_pktsnip_t *esp_header_build(gnrc_pktsnip_t *pkt, 
		const ipsec_sa_t *sa_entry) {
	/*TODO: First check if TUNNEL OR TRANSPORT in sad_entry
	 * if tunnel, there could be an ESP packet inside
	 */
	/* TODO: Demux different sp and sa infos */
	DEBUG("ipsec_esp: OUTGOING ESP PACKET:\nSA MODE: %i\n", sa_entry->mode);
	uint16_t size = 16; // TODO: bit or byte? Going for byte
	/* For now we simply add the header as the last ext header, since RIOT does not build 
	 * ext headers anyway. But this should be considered. Also what about the 
	 * case of ESP tunneled ESP traffic? One would have two ESP headers in the
	 * outer IPv6 packet.
	 */

	gnrc_pktsnip_t *prev = NULL;
	gnrc_pktsnip_t *next = NULL;
	gnrc_pktsnip_t *esp = NULL;
	gnrc_pktsnip_t *ipv6 = NULL;
	gnrc_pktsnip_t *snip = NULL;
	ipv6_esp_hdr_t *esp_h = NULL;
	int nh;

	/* Since we do not now what is the payload, we only supporting UDP for now */
	/* TODO: how do we find what snip is the payload? */
	
	LL_SEARCH_SCALAR(pkt, next, type, GNRC_NETTYPE_UDP);
	if(next == NULL) {
		DEBUG("ipsec_esp: No supported payload found\n");
		return NULL;
	}
	nh = gnrc_nettype_from_protnum(PROTNUM_UDP);

	/* Get preceeding pktsnip */
	/* Note: The first next isn't a variable in this call*/
	LL_SEARCH_SCALAR(pkt, prev, next, next);
	if(prev == NULL) {
		DEBUG("ipsec_esp: Couldn't get leading pktsnip\n");
		return NULL;
	}

	/* compress payload before alocating the buffe */
	(void)snip;

	/* TODO: padding
	(size / IPV6_EXT_LEN_UNIT)
	if (size < IPV6_EXT_LEN_UNIT) {
		return NULL;
	}
	*/

	gnrc_pktbuf_start_write(next);
	/* malloc new snip with next as next snip */
	//TODO: merge data of payload and put it in here. increase the size. Delete old next packet after that*/
	esp = gnrc_pktbuf_add(NULL, NULL, size, GNRC_NETTYPE_IPV6_EXT_ESP);

	if (esp == NULL) {
		return NULL;
	}

	/* TODO: encode data from next and fill esp_h fields */
	esp_h = esp->data;
	esp_h->dummy2 = UINT16_MAX;
	esp_h->dummy = UINT32_MAX;
	esp_h->nh = UINT8_MAX;
	esp_h->pl = UINT8_MAX;
	esp_h->sn.u32 = UINT32_MAX;
	esp_h->spi.u32 = UINT32_MAX;
	(void)esp_h;
	(void)nh;

	/* attach esp pkt snip */
	if (prev != NULL) {
		prev->next = esp;
	}

	//TODO: correct the payload length in ipv6 header dynamically
	LL_SEARCH_SCALAR(pkt, ipv6, type, GNRC_NETTYPE_IPV6);
	((ipv6_hdr_t*)ipv6->data)->len.u16 = size;

	//TODO: remove next snip from pktbuf??

	if(prev->type == GNRC_NETTYPE_IPV6) {
		((ipv6_hdr_t*)prev->data)->nh = PROTNUM_IPV6_EXT_ESP;
	} else {
		/* prev header is ext header */ 
		((ipv6_ext_t*)prev->data)->nh = PROTNUM_IPV6_EXT_ESP;
	}
	
	//TODO: adding ext header reduces maximum payload size. What if packet is to big afterwards?

	return pkt;
}

gnrc_pktsnip_t *esp_header_process(gnrc_pktsnip_t *pkt) {
	/*TODO: First check if TUNNEL OR TRANSPORT in sad_entry
	 *
	 */
	DEBUG("ipsec_esp: INCOMMING ESP PACKET:\nHERE BE DRAGONS\n");
	return pkt;
}