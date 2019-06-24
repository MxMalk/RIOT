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

gnrc_pktsnip_t *esp_header_build(gnrc_pktsnip_t *pkt,
		const ipsec_sa_t *sa_entry, ipsec_ts_t *ts) {
	gnrc_pktsnip_t *prev = NULL;
	gnrc_pktsnip_t *next = NULL;
	gnrc_pktsnip_t *ipv6 = NULL;
	gnrc_pktsnip_t *esp;
	gnrc_pktsnip_t *snip;
	ipv6_hdr_t	   *ipv6_h;
	ipv6_esp_hdr_t *esp_h;
	ipv6_esp_trl_t *esp_trl;
	uint16_t payload_size;
	uint16_t esp_size; 
	uint16_t itm_size; 		//size of intermediate headers
	uint8_t padding_size;
	uint8_t *padding;
	uint8_t *payload;
	int nh;	

	DEBUG("ipsec_esp: Tx ESP header creation. ID:%i\n", sa_entry->id);

	LL_SEARCH_SCALAR(pkt, ipv6, type, GNRC_NETTYPE_IPV6);
	if(ipv6 == NULL){
		DEBUG("ipsec_esp: ERROR No IPv6 header found\n");
		gnrc_pktbuf_release(pkt);
	}
	ipv6_h = ipv6->data;

	if(sa_entry->mode == 1) {
		DEBUG("ipsec_esp: TUNNEL mode\n");
		//TODO TUNNELING!!!
		//TODO: If tunnel address is same as TS -> _build_self_enc()

		/* we simply take the whole packet for tunnel mode */
		(void)ipv6;	
		//TODO: wrap pkt in esp header, put ipv6 header on it, swap addresses 
		//	for tunnels and return it to the ipv6 thread as a sending message
		if (gnrc_netapi_dispatch_send(GNRC_NETTYPE_IPV6,
							GNRC_NETREG_DEMUX_CTX_ALL, pkt) == 0 ) {
			DEBUG("ipsec_esp: ERROR unable netapi send packet\n");
			gnrc_pktbuf_release(pkt);
		}
	}
	/* in transport mode we should have all snips to iterate over */
	nh = ts->prot;
	LL_SEARCH_SCALAR(pkt, next, type, gnrc_nettype_from_protnum(nh));
	if(next == NULL) {
		DEBUG("ipsec_esp: Payload snip not found. Protnum:%i\n", nh);
		return NULL;
	}

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
	/* calculate size of intermediate headers */
	itm_size = byteorder_ntohs(ipv6_h->len) - ipv6->size - payload_size;

	payload = malloc(payload_size);
	int c = 0;
	snip = next;
	while(snip != NULL) {
		memcpy((payload + c), (uint8_t*)(snip->data), snip->size);
		c += snip->size;
		snip = snip->next;
	}
	
	/* calculate size plus padding_size*/
	esp_size = 8 + payload_size + 2 + 8;
	int mod_payl = (payload_size + 2) % IPV6_EXT_LEN_UNIT;
	if( mod_payl == 0) {
		padding_size = 0;
	} else {
		padding_size = (uint8_t)IPV6_EXT_LEN_UNIT - mod_payl;
	}
	esp_size += padding_size;
	/* we remove the old payload from the buffer */
	gnrc_pktbuf_release(next->next);
	gnrc_pktbuf_start_write(next);

	/* malloc new snip with next as next snip */
	esp = gnrc_pktbuf_add(NULL, NULL, esp_size, GNRC_NETTYPE_IPV6_EXT_ESP);	
	if (esp == NULL) {
		DEBUG("ipsec_esp: could not add pkt tp buffer\n");
		free(payload);
		return NULL;
	}
	prev->next = esp;

	/* TODO: encode data from next and fill esp_h fields */
	esp_h = esp->data;
	/* Setting pointer to the last 2 bytes of the data sector */
	esp_trl = (ipv6_esp_trl_t*)(((uint8_t*)esp->data) + esp_size - 10);
	esp_h->sn = byteorder_htonl(sa_entry->sn);
	if(!ipsec_increment_sn(sa_entry->spi)){
		DEBUG("ipsec_esp: sequence number incrementation rejected\n");
		free(payload);
		return NULL;
	}
	esp_h->spi = byteorder_htonl(sa_entry->spi);

	padding = calloc(padding_size, sizeof(uint8_t));
	// TODO: htonl payload???
	memcpy(((uint8_t*)esp->data) + 8, payload, payload_size);
	memcpy(((uint8_t*)esp->data) + 8 + payload_size, padding, padding_size);
	free(payload);
	free(padding);

	esp_trl->nh = nh;
	esp_trl->pl = padding_size;
	esp_trl->icv = htonll(0xcafecafecafecafe);			

	// writing esp length plus length of preceeding snips in ipv6 header
	((ipv6_hdr_t*)ipv6->data)->len = byteorder_htons(esp_size + itm_size);	

	if(prev->type == GNRC_NETTYPE_IPV6) {
		((ipv6_hdr_t*)prev->data)->nh = PROTNUM_IPV6_EXT_ESP;
	} else {
		/* prev header is ext header */ 
		((ipv6_ext_t*)prev->data)->nh = PROTNUM_IPV6_EXT_ESP;
	}

	/* TODO: what about PMTU and the possibly increased pkt size? */
	return pkt;
}

gnrc_pktsnip_t *esp_header_process(gnrc_pktsnip_t *pkt) {
	gnrc_pktsnip_t *next_snip;
	const ipsec_sa_t *sa;
	uint8_t *last_byte;
	uint8_t *data;

	uint64_t icv;
	uint32_t spi;
	uint32_t sn;
	uint8_t nh;
	uint8_t padding_size;
	uint8_t data_size;

	uint8_t ESP_HEADER_SIZE = 8;
	uint8_t ESP_TRL_SIZE = 10;
	
	DEBUG("ipsec_esp: Rx ESP packet\n");
	DEBUG("ipsec_esp: TEST Rx wrapped packet:\n");
	ipsec_show_pkt(pkt);

	spi = byteorder_ntohl(*(network_uint32_t*)pkt->data);
	sn = byteorder_ntohl(*(network_uint32_t*)((uint8_t*)pkt->data + 4));

	DEBUG("ipsec_esp: TEST Rx spi: %i  sn: %i\n", (int)spi, (int)sn);

	sa = ipsec_get_sa_by_spi(spi);
	if(sa == NULL) {
		DEBUG("ipsec_esp: Rx sa by spi not found. spi: %i\n", (int)spi);
		return NULL;
	}
	DEBUG("ipsec_esp: TEST Rx sa id: %i\n", (int)sa->id);
	DEBUG("ipsec_esp: TEST Rx sa id: %i\n", (int)sa->sn);
	if(!ipsec_increment_sn(sa->spi)){
		DEBUG("ipsec_esp: Rx SN incrementation rejected\n");
		return NULL;
	};

	//TODO: check if TUNNEL OR TRANSPORT in sad_entry
	//?? _mark_extension_header(pkt)

	//TODO: unauth and unencrypt

	/* TODO: This is mockup code to test traffic filtering and sa retrieval */	
	last_byte = (uint8_t*)pkt->data + (pkt->size - 1);
	icv = byteorder_ntohll(*(network_uint64_t*)(last_byte - 7));
	DEBUG("ipsec_esp: TEST Rx ICV: %" PRIu64 "\n", icv);
	nh = *(last_byte - 8);
	padding_size = *(last_byte - 9);

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
	DEBUG("ipsec_esp: TEST Rx unwrapped packet:\n");
	ipsec_show_pkt(pkt);	
	return pkt;
}