/*
 * Copyright (C) 2018 Maximilian Malkus <malkus@cip.ifi.lmu.de>
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */


#include "thread.h"
#include "limits.h"
#include "net/ipv6/addr.h"
#include "crypto/chacha20poly1305.h"
#include "net/gnrc.h"
#include "net/gnrc/ipv6/hdr.h"
#include "net/gnrc/ipv6/ext.h"
#include "net/gnrc/ipv6/ipsec/ipsec.h"

#include "net/gnrc/ipv6/ipsec/esp.h"

#define ENABLE_DEBUG    (1)
#include "debug.h"

uint8_t chacha_nonce[CHACHA20POLY1305_NONCE_BYTES];

int _encrypt_comb(gnrc_pktsnip_t *esp, const ipsec_sa_t *sa) {
	
	//TODO protect and authenticate
	network_uint64_t *trl_icv = 
			(network_uint64_t*)((uint8_t*)esp->data + esp->size - 8);
	*trl_icv = byteorder_htonll(0xcafecafecafecafe);	

	switch(sa->cyph_info.cypher) {
		case IPSEC_CYPHER_MOCK:
			break;
		case IPSEC_CYPHER_CHACHA_POLY:
			//TODO: do stuff
			break;
		default:
			return 0;
	}

	return 1;

}

int _decrypt_comb(gnrc_pktsnip_t *esp, int *sn, const ipsec_sa_t *sa) {		
	switch(sa->cyph_info.cypher) {
		case IPSEC_CYPHER_CHACHA_POLY:
			/** TODO: in the absence of a better value we use the uncompressed
			 * SN as the nonce for now. This should be changed to a propper 
			 * salt and nonce negotiation over IKEv2 as described in RFC7634. 
			 * Until this is addressed, this experimental code is not 
			 * cryptographicaly secure */
			memset(chacha_nonce, 0, CHACHA20POLY1305_NONCE_BYTES);
			*(uint32_t*)((uint8_t*)chacha_nonce + 8) = sn;	
			if(!chacha20poly1305_decrypt()) {
				DEBUG("ipsec_esp: ERROR Authentication failed\n");
				return 0;
			}
			break;
		case IPSEC_CYPHER_MOCK:
			break;
		default:
			DEBUG("ipsec_esp: ERROR undefined cypher\n");
			return 0;			
	}
	return 1;
}

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
	uint8_t nh;
	void *payload;

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
	/* in transport mode we should have all snips marked to iterate over */
	nh = ts->prot;
	LL_SEARCH_SCALAR(pkt, next, type, gnrc_nettype_from_protnum(nh));
	if(next == NULL) {
		DEBUG("ipsec_esp: Payload snip not found. Protnum:%i\n", nh);
		return NULL;
	}

	/* Get preceeding pktsnip */
	/* Note: The first 'next' argument isn't a variable in this call */
	LL_SEARCH_SCALAR(pkt, prev, next, next);
	if(prev == NULL) {
		DEBUG("ipsec_esp: Couldn't get leading pktsnip\n");
		return NULL;
	}
	/* get payload size */
	payload_size = 0;
	snip = next;
	while(snip != NULL) {
		payload_size += snip->size;
		snip = snip->next;
	}

	/* On using DietESP: About here we'd need to calculate the final DietEsp
	 * packet size. It should be easy to calculate the size reduction from 
	 * the negotiated compression rulesets. In the final */
	
	/* calculating padding, ignoring all fields that add up to 8 byte anyway */
	int mod_payload = (payload_size + 2) % IPV6_EXT_LEN_UNIT;
	if( mod_payload == 0) {
		padding_size = 0;
	} else {
		padding_size = (uint8_t)IPV6_EXT_LEN_UNIT - mod_payload;
	}

	/* calculate esp size */
	esp_size = 8 + payload_size + padding_size + 2 + 8;
	/* add pkt to pktbuf */
	esp = gnrc_pktbuf_add(NULL, NULL, esp_size, GNRC_NETTYPE_IPV6_EXT_ESP);	
	if (esp == NULL) {
		DEBUG("ipsec_esp: could not add pkt tp buffer\n");
		gnrc_pktbuf_release(pkt);
		return NULL;
	}
	esp_h = esp->data;
	//TODO: Do we increment first and then add it or visa vi? What about missing packets?
	if(!ipsec_increment_sn(sa_entry->spi)){
		DEBUG("ipsec_esp: sequence number incrementation rejected\n");
		gnrc_pktbuf_release(pkt);
		return NULL;
	}
	esp_h->sn = byteorder_htonl(sa_entry->sn);
	esp_h->spi = byteorder_htonl(sa_entry->spi);
	payload = (uint8_t*)esp_h + 8;
	/* nulling the bits in padding*/
	memset(((uint8_t*)esp_h + payload_size), 0, padding_size);
	esp_trl = (ipv6_esp_trl_t*)(((uint8_t*)esp->data) + esp->size - 10);
	esp_trl->nh = nh;
	esp_trl->pl = padding_size;
	

	/* On using DietESP: We can't simply merge and copy the data but will 
	 * send the two packets to a subroutine, where every single field of 
	 * the esp header and the payloads headers will be copied and 
	 * modified one after another according to the rules. When building the
	 * DietESP header filling routine, the plain ESP header filling can be 
	 * moved there, too.*/
	gnrc_pktbuf_start_write(next);
	gnrc_pktbuf_merge(next);
	memcpy(payload, next->data, next->size);
	gnrc_pktbuf_release(next);
	prev->next = esp;

	_encrypt_comb(esp, sa_entry);		

	/* writing new packet details into original ipv6 header */
	/* calculate intermediate headers between ipv6 and esp header */
	itm_size = byteorder_ntohs(ipv6_h->len) - ipv6->size - payload_size;
	((ipv6_hdr_t*)ipv6->data)->len = byteorder_htons(esp->size + itm_size
												+ sizeof(ipv6_hdr_t));
	if(prev->type == GNRC_NETTYPE_IPV6) {
		((ipv6_hdr_t*)prev->data)->nh = PROTNUM_IPV6_EXT_ESP;
	} else {
		/* prev header is ext header */ 
		((ipv6_ext_t*)prev->data)->nh = PROTNUM_IPV6_EXT_ESP;
	}

	/* check on pmtu size */
	gnrc_pktbuf_merge(pkt);
	if( (sizeof(ethernet_hdr_t) + pkt->size) > sa_entry->pmtu ) {
		DEBUG("ipsec_esp: finished ESP packet exceeded PMTU\n");
		gnrc_pktbuf_release(pkt);
		return NULL;
	}
	
	return pkt;
}

gnrc_pktsnip_t *esp_header_process(gnrc_pktsnip_t *esp, uint8_t protnum) {
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

	assert(protnum == PROTNUM_IPV6_EXT_ESP);
	DEBUG("ipsec_esp: Rx ESP packet\n");

	/** Regarding DietESP: We run into a problem here. The SPI is used for
	 * identification at this stage, but we do not know the size of the SPI 
	 * reduction to the LSB to grab it from the packet. Would this be a system
	 * wide setting so we could get some kind of global variable for this? We
	 * then could extract the other details from the negotiated infos.
	 * 
	 * draft-mglt-ipsecme-diet-esp-07 section 8.2 states to match the packet
	 * with the SA to check for DietESP EHC strategy and then index the SA with
	 * the sufficient LSB. This seems overly convoluted. Either we have a way
	 * to reliably address the packet's SA or we can't get the SA in the first
	 * place.
	 * 
	 * The draft even supports an sn and spi lsb width of zero, so we need a 
	 * whole other way to identify the packet. Thus we will assume a leading
	 * method restoring SPI and SN in any way seen fit by the EHC definitions.
	 * 
	 * 		pkt = ehc_restore_identifiers(pkt) /@return NULL if no match
	 * 
	 * Then probably directly followed by:
	 * 
	 * 		pkt = ehc_restore_esp(pkt)
	 * 
	 * Or one simply routes the pkt to the EHC routines for processing, before
	 * continuing here as if it was a regular ESP packet.
	 */
	
	spi = byteorder_ntohl(*(network_uint32_t*)esp->data);
	sn = byteorder_ntohl(*(network_uint32_t*)((uint8_t*)esp->data + 4));

	printf("ipsec_esp: TEST Rx spi: %i  sn: %i\n", (int)spi, (int)sn);

	sa = ipsec_get_sa_by_spi(spi);
	if(sa == NULL) {
		DEBUG("ipsec_esp: Rx sa by spi not found. spi: %i\n", (int)spi);
		/* pkt will be released by caller */
		return NULL;
	}
	printf("ipsec_esp: TEST Rx sa id:   %i\n", (int)sa->id);
	printf("ipsec_esp: TEST Rx sa sn:   %i\n", (int)sa->sn);
	printf("ipsec_esp: TEST Rx sa mode: %i\n", (int)sa->mode);

	/* TODO: Send SN toAnti Replay Window processing
	 * pkt = _check_arpw() /@return NULL if no match
	 */	

	// TODO: IMPLICIT IV ??

	/* Decrypt ESP packet */
	if(sa->c_mode == IPSEC_CYPHER_M_COMB) {	
		_decrypt_comb(esp, &sn, sa);
	} else { 
		DEBUG("ipsec_esp: ERROR Cypher mode not supported\n");
		return NULL;
	}
			

	/* Process ESP contents */
	if((int)sa->mode == 1) {
		//TODO: TRANSPORT processing
	}

	

	/* TODO: This is mockup code to test traffic filtering and sa retrieval */	
	last_byte = (uint8_t*)esp->data + (esp->size - 1);
	icv = byteorder_ntohll(*(network_uint64_t*)(last_byte - 7));
	DEBUG("ipsec_esp: TEST Rx ICV: %" PRIu64 "\n", icv);
	nh = *(last_byte - 8);
	padding_size = *(last_byte - 9);

	data_size = esp->size - ESP_HEADER_SIZE - ESP_TRL_SIZE - padding_size;
	data = malloc(data_size);
	memcpy(data, ((uint8_t*)esp->data) + ESP_HEADER_SIZE, data_size);
	next_snip = esp->next;
	gnrc_pktbuf_start_write(esp);
	gnrc_pktbuf_remove_snip(esp, esp);
	esp = gnrc_pktbuf_add(next_snip, data, data_size, gnrc_nettype_from_protnum(nh));
	free(data);	
	/* set ipv6 threads nh protnum to the recieved pkt type */
	if(next_snip->type == GNRC_NETTYPE_IPV6) {
		((ipv6_hdr_t*)next_snip->data)->nh = nh;
	} else {
		/* prev header is ext header */ 
		((ipv6_ext_t*)next_snip->data)->nh = nh;
	}
	DEBUG("ipsec_esp: TEST Rx unwrapped packet:\n");

	//TODO at EOP no remainders of this ESP header should be left in the pkt

	ipsec_show_pkt(esp);	
	return esp;
}