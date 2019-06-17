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
		const ipsec_sa_t *sa_entry, uint8_t protnum_payload) {
	/*TODO: First check if TUNNEL OR TRANSPORT in sad_entry
	 * if tunnel, there could be an ESP packet inside
	 */
	/* TODO: Demux different sp and sa infos */
	DEBUG("ipsec_esp: OUTGOING ESP PACKET:\nSA MODE: %i\n", sa_entry->mode);
	
	uint16_t payload_size;
	uint16_t esp_size; 
	uint8_t padding_size;

	uint8_t *padding;
	uint8_t *payload;
	
	/* TODO: For now we simply add the header as the last ext header, since RIOT does not build 
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
	ipv6_esp_trl_t *esp_trl = NULL;
	int nh;

	/* Since we do not now what is the payload, we only supporting UDP for now */
	/* TODO: how do we find what snip is the payload? Get nh from IP snip*/
	
	LL_SEARCH_SCALAR(pkt, next, type, GNRC_NETTYPE_UDP);
	if(next == NULL) {
		DEBUG("ipsec_esp: No supported payload found\n");
		return NULL;
	}
	nh = PROTNUM_UDP;

	/* Get preceeding pktsnip */
	/* Note: The first next isn't a variable in this call*/
	LL_SEARCH_SCALAR(pkt, prev, next, next);
	if(prev == NULL) {
		DEBUG("ipsec_esp: Couldn't get leading pktsnip\n");
		return NULL;
	}

	/* TODO: TMP - Copy and measure following snips data to tmp variable 
	 * use gnrc_pktbuf_merge() ?*/
	payload_size = 0;
	snip = next;
	while(snip != NULL) {
		payload_size += snip->size;
		snip = snip->next;
	}
	payload = malloc(payload_size);
	int c = 0;
	snip = next;
	while(snip != NULL) {
		memcpy((payload + c), (uint8_t*)(snip->data), snip->size);
		c += snip->size;
		snip = snip->next;
	}

	/* TODO: Create and compress payload */
	
	/* calculate size plus padding_size*/
	esp_size = 8 + payload_size + 2 + 8;
	int mod_payl = (payload_size + 2) % IPV6_EXT_LEN_UNIT;
	if( mod_payl == 0) {
		padding_size = 0;
	} else {
		padding_size = (uint8_t)IPV6_EXT_LEN_UNIT - mod_payl;
	}
	esp_size += padding_size;
	/* TODO: Here we remove the old payload from pktbuf, or will it get freed in the end anyway? */
	gnrc_pktbuf_release(next->next);
	gnrc_pktbuf_start_write(next);
	/* malloc new snip with next as next snip */
	//TODO: merge data of payload and put it in here. increase the size. Delete old next packet after that*/
	esp = gnrc_pktbuf_add(NULL, NULL, esp_size, GNRC_NETTYPE_IPV6_EXT_ESP);	

	if (esp == NULL) {
		return NULL;
	}

	/* TODO: encode data from next and fill esp_h fields */
	esp_h = esp->data;
	/* Setting pointer to the last 2 bytes of the data sector */
	esp_trl = (ipv6_esp_trl_t*)(((uint8_t*)esp->data) + esp_size - 10);
	esp_h->sn.u32 = UINT32_MAX;
	esp_h->spi.u32 = UINT32_MAX;

	padding = calloc(padding_size, sizeof(uint8_t));
	memcpy(((uint8_t*)esp->data) + 8, payload, payload_size);
	memcpy(((uint8_t*)esp->data) + 8 + payload_size, padding, padding_size);
	free(payload);

	esp_trl->nh = nh;
	esp_trl->pl = padding_size;
	esp_trl->icv = htonll(0xabababababababab);

	/* attach esp pkt snip */
	if (prev != NULL) {
		prev->next = esp;
	}

	//TODO: calculate the length of preceeding ext headers and add them to size.
	LL_SEARCH_SCALAR(pkt, ipv6, type, GNRC_NETTYPE_IPV6);
	((ipv6_hdr_t*)ipv6->data)->len.u16 = htons(esp_size);	

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

	uint8_t ESP_HEADER_SIZE = 8;
	uint8_t ESP_TRL_SIZE = 10;
	uint8_t padding_size;
	uint8_t nh;
	uint64_t *icv;
	uint8_t *data;
	uint8_t data_size;
	uint8_t *end_of_pkt;
	gnrc_pktsnip_t *next_snip;
	
	DEBUG("ipsec_esp: Rx ESP packet\n");

	/*TODO: check if TUNNEL OR TRANSPORT in sad_entry
	if (_mark_extension_header(pkt) == NULL) {
                // header couldn't be marked
                return NULL;
    }
	*/
	end_of_pkt = (uint8_t*)pkt->data + (pkt->size - 1);
	icv = (uint64_t*)(end_of_pkt - 7);
	(void)icv;
	nh = *(end_of_pkt - 8);
	padding_size = *(end_of_pkt - 9);
	data_size = pkt->size - ESP_HEADER_SIZE - ESP_TRL_SIZE - padding_size;
	data = malloc(data_size);
	memcpy(data, ((uint8_t*)pkt->data) + ESP_HEADER_SIZE, data_size);
	next_snip = pkt->next;
	gnrc_pktbuf_start_write(pkt);
	gnrc_pktbuf_remove_snip(pkt, pkt);
	pkt = gnrc_pktbuf_add(next_snip, data, data_size, gnrc_nettype_from_protnum(nh));
	free(data);	
	/* set ipv6 threads nh protnum to the recieved pkt type */
	if(next_snip->type == GNRC_NETTYPE_IPV6) {
		((ipv6_hdr_t*)next_snip->data)->nh = nh;
	} else {
		/* prev header is ext header */ 
		((ipv6_ext_t*)next_snip->data)->nh = nh;
	}
	gnrc_ipsec_show_pkt(pkt);
	return pkt;
}