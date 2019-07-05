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
#include "net/gnrc.h"
#include "net/gnrc/ipv6/hdr.h"
#include "net/gnrc/ipv6/ext.h"
#include "net/gnrc/ipv6/ipsec/ipsec.h"
#include "net/gnrc/ipv6/ipsec/ts.h"

#include "net/gnrc/ipv6/ipsec/esp.h"

#define ENABLE_DEBUG    (1)
#include "debug.h"

static int _encrypt(gnrc_pktsnip_t *esp, const ipsec_sa_t *sa) {

	/* On using DietESP: On en- and decryption some negotiated DietESP rules
	need to be checked and possibly resolved, like e.g. Implicit IV */

	switch(sa->crypt_info.cipher) {
		case IPSEC_CIPHER_MOCK: {
			network_uint64_t *trl_icv = (network_uint64_t*)((uint8_t*)esp->data
											+ esp->size - 8);
			*trl_icv = byteorder_htonll(0xcafecafecafecafe);	
			network_uint64_t *iv = (network_uint64_t*)((uint8_t*)esp->data 
											+ sizeof(ipv6_esp_hdr_t));
			*iv = byteorder_htonll(0xbeefbeefbeefbeef);
			break;
		}
		case IPSEC_CIPHER_CHACHA_POLY:
		case IPSEC_CIPHER_AES_CTR:
		default:
			DEBUG("ipsec_esp: ERROR unsupported cypher\n");
			return 0;
	}

	return 1;

}

static int _decrypt(gnrc_pktsnip_t *esp, const ipsec_sa_t *sa) {	

	/* On using DietESP: On en- and decryption some negotiated DietESP rules
	need to be checked and minded for all ciphers, like e.g. Implicit IV */

	switch(sa->crypt_info.cipher) {		
		case IPSEC_CIPHER_MOCK: {
			network_uint64_t *trl_icv = (network_uint64_t*)((uint8_t*)esp->data
											+ esp->size - 8);
			DEBUG("ipsec_esp: Rx icv: 0x%" PRIx64 "\n", byteorder_ntohll(*trl_icv));	
			network_uint64_t *iv = (network_uint64_t*)((uint8_t*)esp->data 
											+ sizeof(ipv6_esp_hdr_t));
			DEBUG("ipsec_esp: Rx  iv: 0x%" PRIx64 "\n", byteorder_ntohll(*iv));
			break;
		}
		case IPSEC_CIPHER_CHACHA_POLY:
			/*
			memset(chacha_nonce, 0, CHACHA20POLY1305_NONCE_BYTES);
			chacha_nonce = _create_chacha_nonce(sa);
			if(!chacha20poly1305_decrypt()) {
				DEBUG("ipsec_esp: ERROR Authentication failed\n");
				return 0;
			} 
			break;*/
		case IPSEC_CIPHER_AES_CTR:
			/*sa->cyph_info.iv
			break;*/
		default:
			DEBUG("ipsec_esp: ERROR unsupported cypher\n");
			return 0;			
	}
	return 1;
}

static void _calc_padding(uint8_t *padding_size, int plaintext_size,
						uint8_t block_size) {
	
	uint8_t mod_payload = (uint8_t)((plaintext_size) % (int)block_size);
	if( mod_payload == 0) {
		*padding_size = 0;
	} else {
		*padding_size = block_size - mod_payload;
	}
}

static int _calc_fields(const ipsec_sa_t *sa, uint8_t *iv_size, uint8_t *icv_size,
						uint8_t *block_size) {

	/* On using DietESP: If Implicit IV is used, that has to be minded here */

	switch(sa->crypt_info.cipher) {		
		case IPSEC_CIPHER_MOCK:
				*block_size = (uint8_t)IPV6_EXT_LEN_UNIT;
				*iv_size = 8;
				*icv_size = 8;
			break;
		case IPSEC_CIPHER_CHACHA_POLY:
		case IPSEC_CIPHER_AES_CTR:
			// 16U blocks
		default:
			DEBUG("ipsec_esp: ERROR unsupported cipher\n");
			return 0;			
	}
	return 1;
}

gnrc_pktsnip_t *esp_header_build(gnrc_pktsnip_t *pkt,
		const ipsec_sa_t *sa, ipsec_ts_t *ts) {
	gnrc_pktsnip_t *prev = NULL;
	gnrc_pktsnip_t *next = NULL;
	gnrc_pktsnip_t *ipv6 = NULL;
	gnrc_pktsnip_t *esp;
	ipv6_hdr_t	   *ipv6_h;
	ipv6_esp_hdr_t *esp_h;
	ipv6_esp_trl_t *esp_trl;
	uint16_t data_size;
	uint16_t esp_size; 
	uint16_t itm_size; 		//size of intermediate headers
	uint8_t block_size;
	uint8_t iv_size;
	uint8_t icv_size;
	uint8_t padding_size;
	uint8_t nh;
	void *payload;

	DEBUG("ipsec_esp: Tx ESP header creation. ID:%i\n", sa->id);

	LL_SEARCH_SCALAR(pkt, ipv6, type, GNRC_NETTYPE_IPV6);
	if(ipv6 == NULL){
		DEBUG("ipsec_esp: ERROR No IPv6 header found\n");
		gnrc_pktbuf_release(pkt);
	}
	ipv6_h = ipv6->data;
	nh = ts->prot;

	if(sa->mode == GNRC_IPSEC_M_TUNNEL) {
		if( ipv6_addr_equal(&ts->dst, &sa->tun_dst) && 
								ipv6_addr_equal(&ts->src, &sa->tun_src) ) {
			DEBUG("ipsec_esp: TUNNEL self encapsulation mode\n");
			gnrc_pktsnip_t *tmp_pkt;	
			tmp_pkt = gnrc_pktbuf_duplicate_upto(ipv6, 255);
			gnrc_pktbuf_merge(tmp_pkt);
			ipv6 = gnrc_pktbuf_replace_snip(ipv6, ipv6->next, tmp_pkt);
		} else {
			DEBUG("ipsec_esp: TUNNEL mode\n");
			/* TODO: process foreign tunneled traffic.
			 * the main difference to the transport processing ist, that the
			 * data is the whole packet and after encryption, it is not sent
			 * to the interface but a fresh ipv6 header is initialized and the
			 * paket is send to the ipv6 thread again and thus an ESP tunnel
			 * bypassing SPD-O rule is needed.  */
		}
		next = ipv6->next;
	} else {	
		/* in transport mode we should have all snips marked to iterate over */
		LL_SEARCH_SCALAR(pkt, next, type, gnrc_nettype_from_protnum(nh));
		if(next == NULL) {
			DEBUG("ipsec_esp: Payload snip not found. Protnum:%i\n", nh);
			return NULL;
		}
	}

	/* Get preceeding pktsnip */
	/* Note: The first 'next' argument isn't a variable in this call */
	LL_SEARCH_SCALAR(pkt, prev, next, next);
	if(prev == NULL) {
		DEBUG("ipsec_esp: Couldn't get leading pktsnip\n");
		return NULL;
	}

	gnrc_pktsnip_t *snip;
	data_size = 0;
	snip = next;
	while(snip != NULL) {
		data_size += snip->size;
		snip = snip->next;
	}

	_calc_fields(sa, &iv_size, &icv_size, &block_size);
	_calc_padding(&padding_size, (data_size+2), block_size);

	esp_size = sizeof(ipv6_esp_hdr_t) + iv_size + data_size + padding_size 
				+ sizeof(ipv6_esp_trl_t) + icv_size;
	esp = gnrc_pktbuf_add(NULL, NULL, esp_size, GNRC_NETTYPE_IPV6_EXT_ESP);	
	if (esp == NULL) {
		DEBUG("ipsec_esp: could not add pkt tp buffer\n");
		gnrc_pktbuf_release(pkt);
		return NULL;
	}
	esp_h = esp->data;
	if(!ipsec_increment_sn(sa->spi)){
		DEBUG("ipsec_esp: sequence number incrementation rejected\n");
		gnrc_pktbuf_release(pkt);
		return NULL;
	}
	esp_h->sn = byteorder_htonl(sa->sn);
	esp_h->spi = byteorder_htonl(sa->spi);
	payload = (uint8_t*)esp_h + sizeof(ipv6_esp_hdr_t);
	/* nulling the bits in padding*/
	memset(((uint8_t*)payload + iv_size + data_size), 0, padding_size);
	esp_trl = (ipv6_esp_trl_t*)(((uint8_t*)esp_h) + esp->size 
									- icv_size - sizeof(ipv6_esp_trl_t));
	esp_trl->nh = nh;
	esp_trl->pl = padding_size;
	

	/* On using DietESP: We can't simply merge and copy the data since we need 
	 * the fields for payload compression. Instead we will send the two packets
	 * to a subroutine, where the payloads header andalso the esp header fields
	 * will be compressed and copied to a smaller pktsnip, one after another, 
	 * according to the given EHC rules. The new diet_esp packet is returned to
	 * be encrypted */

	gnrc_pktbuf_start_write(next);
	gnrc_pktbuf_merge(next);
	memcpy((uint8_t*)payload + iv_size, next->data, next->size);
	gnrc_pktbuf_release(next);
	prev->next = esp;	

	/* All relevant space for the encryption should be available at this point,
	 * so we can work directly on the packet while encrypting. ICV and IV are 
	 * filled inside the ecryption*/

	switch(sa->c_mode) {
		case IPSEC_CIPHER_M_COMB:
			_encrypt(esp, sa);
			break;
		case IPSEC_CIPHER_M_ENC_N_AUTH:
			/* _hash(esp, sa);
			_encrypt(esp, sa); 
			break;*/
		case IPSEC_CIPHER_M_AUTH_ONLY:
			/* _hash(esp, sa); 
			break; */
		default:
			DEBUG("ipsec_esp: ERROR Cypher mode not supported\n");
			return NULL;
	}		

	
	if(sa->mode == GNRC_IPSEC_M_TUNNEL) {		
		if( ! (ipv6_addr_equal(&ts->dst, &sa->tun_dst) && 
								ipv6_addr_equal(&ts->src, &sa->tun_src)) ) {
			/* TODO: 
			 * initialize fresh ipv6 header from sa tunnel data and send it to
			 * the ipv6 thread*/
			/*
			if (gnrc_netapi_dispatch_send(GNRC_NETTYPE_IPV6,
							GNRC_NETREG_DEMUX_CTX_ALL, pkt) == 0 ) {
			DEBUG("ipsec_esp: ERROR unable netapi send packet\n");
			gnrc_pktbuf_release(pkt);
			*/
		}
	}

	/* calculate intermediate headers between ipv6 and original data */
	itm_size = byteorder_ntohs(ipv6_h->len) - ipv6->size - data_size;
	/* adding packet to original ipv6 header */
	((ipv6_hdr_t*)ipv6->data)->len = byteorder_htons(esp->size + itm_size
												+ sizeof(ipv6_hdr_t));
	if(prev->type == GNRC_NETTYPE_IPV6) {
		((ipv6_hdr_t*)prev->data)->nh = PROTNUM_IPV6_EXT_ESP;
	} else {
		/* prev header is ext header */ 
		((ipv6_ext_t*)prev->data)->nh = PROTNUM_IPV6_EXT_ESP;
	}	

	/* TODO: sending a merged pkt so the interface results in jibberish beein 
	 * sent out. I couldn't figure why. This needs to be investigated or we 
	 * neeed a workarround
	 * 
	 * check regarding pmtu: 	
	gnrc_pktbuf_merge(pkt);
	if( (sizeof(ethernet_hdr_t) + pkt->size) > sa->pmtu ) {
		DEBUG("ipsec_esp: finished ESP packet exceeded PMTU\n");
		gnrc_pktbuf_release(pkt);
		return NULL;
	}
	*/
	
	return pkt;
}

/* send out newly created independed gnrc_pktsnip_t */
static int _rx_relay_tunnel(gnrc_pktsnip_t *data_snip) {
	if (gnrc_netapi_dispatch_receive(GNRC_NETTYPE_IPV6,
                                     GNRC_NETREG_DEMUX_CTX_ALL,
                                     data_snip) == 0) {
        return 0;
    }
	return 1;
}  

/* check if inner and outer ipv6 addresses are the same */
static int _is_self_encap(gnrc_pktsnip_t *outer_snip, gnrc_pktsnip_t *inner_ipv6) {
	gnrc_pktsnip_t *outer_ipv6;
	ipv6_hdr_t *outer_ipv6_h;
	ipv6_hdr_t *inner_ipv6_h;
	LL_SEARCH_SCALAR(outer_snip, outer_ipv6, type, GNRC_NETTYPE_IPV6);
	inner_ipv6_h = (ipv6_hdr_t*)inner_ipv6->data;
	outer_ipv6_h = (ipv6_hdr_t*)outer_ipv6->data;
	if (ipv6_addr_equal(&inner_ipv6_h->dst, &outer_ipv6_h->dst) &&
		 		ipv6_addr_equal(&inner_ipv6_h->src, &outer_ipv6_h->src) ) {
		return 1;
	}
	return 0;
}

/* gets inner payload. old data_snip will be released */
static gnrc_pktsnip_t *_extract_inner_pl(gnrc_pktsnip_t *data_snip) {
	gnrc_pktsnip_t *tmp_snip;
	size_t snip_size;
	uint8_t protnum;
	void* pl_pointer;
	find_payload_in_umarked(data_snip, &protnum, &pl_pointer);
	snip_size = (size_t)abs((int)pl_pointer - (int)data_snip->data);
	tmp_snip = gnrc_pktbuf_add(NULL, NULL, snip_size, 
									gnrc_nettype_from_protnum(protnum));
	memcpy(tmp_snip->data, pl_pointer, tmp_snip->size);
	gnrc_pktbuf_release(data_snip);
	return tmp_snip;
}

gnrc_pktsnip_t *esp_header_process(gnrc_pktsnip_t *esp, uint8_t protnum) {
	gnrc_pktsnip_t *data_snip;
	const ipsec_sa_t *sa;
	uint8_t *nh;

	uint8_t iv_size;
	uint8_t icv_size;
	uint32_t spi;
	uint32_t sn;
	uint8_t padding_size;
	uint8_t data_size;
	uint8_t blocksize;

	assert(protnum == PROTNUM_IPV6_EXT_ESP);
	DEBUG("ipsec_esp: Rx ESP packet\n");

	/** On using DietESP: We run into a problem here. The SPI is used for
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

	DEBUG("ipsec_esp: Rx pkt spi: %i  sn: %i\n", (int)spi, (int)sn);

	sa = ipsec_get_sa_by_spi(spi);
	if(sa == NULL) {
		DEBUG("ipsec_esp: Rx sa by spi not found. spi: %i\n", (int)spi);
		/* pkt will be released by caller */
		return NULL;
	}

	/* TODO: Send SN toAnti Replay Window processing
	 * pkt = _check_arpw() /@return NULL if no match
	 */	

	/* Authenticate and Decrypt ESP packet */
	switch(sa->c_mode) {
		case IPSEC_CIPHER_M_COMB:
			_decrypt(esp, sa);
			break;
		case IPSEC_CIPHER_M_ENC_N_AUTH:
			/* _verify(esp, sa);
			_decrypt(esp, sa); 
			break;*/
		case IPSEC_CIPHER_M_AUTH_ONLY:
			/* _verify(esp, sa); 
			break; */
		default:
			DEBUG("ipsec_esp: ERROR Cypher mode not supported\n");
			return NULL;
	}
	
	/** On using DietESP: At this stange we send the decrypted packet to the 
	 * EHC routines to decompress it */

	/* we do not need blocksize here, but else we'd need two methods */
	_calc_fields(sa, &iv_size, &icv_size, &blocksize);
	nh = (uint8_t*)esp->data + esp->size - (icv_size + 1);
	padding_size = *(nh - 1);
	data_size = esp->size - 
		(sizeof(ipv6_esp_hdr_t) + sizeof(ipv6_esp_trl_t) + padding_size
		 + icv_size + iv_size);
	data_snip = gnrc_pktbuf_add(NULL, NULL, data_size, gnrc_nettype_from_protnum(*nh));
	memcpy(data_snip->data, 
		(((uint8_t*)esp->data) + sizeof(ipv6_esp_hdr_t) + iv_size), data_size);
		
	if((int)sa->mode == GNRC_IPSEC_M_TUNNEL) {
		/* check if self encapsulated */
		if( _is_self_encap(esp->next, data_snip) ) {
			// TODO: assert equality of ipv6 headers
			esp = _extract_inner_pl(data_snip);
		} else {
			if(!_rx_relay_tunnel(data_snip)) {
				DEBUG("ipsec_esp: ERROR tunneled packet could not be sent\n");
				gnrc_pktbuf_release(data_snip);
			} else {
				DEBUG("ipsec_esp: Tunneled packet relayed. Original pkt consumed.\n");
			}
			return NULL;
		}		
	}	
	esp = gnrc_pktbuf_replace_snip(esp, esp, data_snip);

	if(esp->next->type == GNRC_NETTYPE_IPV6) {
		((ipv6_hdr_t*)esp->next->data)->nh = gnrc_nettype_to_protnum(esp->type);
	} else {	/* prev header is ext header */		 
		((ipv6_ext_t*)esp->next->data)->nh = gnrc_nettype_to_protnum(esp->type);
	}

	return esp;
}