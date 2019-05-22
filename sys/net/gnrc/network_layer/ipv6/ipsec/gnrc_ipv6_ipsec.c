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
#include "net/gnrc/ipv6/ipsec/spd_api_mockup.h"
#include "net/gnrc/ipv6/ipsec/thread_test.h"

#include "net/gnrc/ipv6/ipsec/ipsec.h"

#define ENABLE_DEBUG    (1)
#include "debug.h"

/* TODO: returns pkt at ipv6 header */
gnrc_pktsnip_t *esp_header_build(gnrc_pktsnip_t *pkt, const sp_cache_t *spd_entry) {
	/*TODO: First check if TUNNEL OR TRANSPORT in sad_entry
	 *
	 */
	DEBUG("OUTGOING ESP PACKET:\nSA MODE: %i\nSP STATUS: %i\n", spd_entry->sa->mode, spd_entry->rule);
	/* TODO: Demux different sp and sa infos */
	int size = 8; /* TODO: bit or byte? Going for byte */
	gnrc_pktsnip_t *next = pkt->next;
	ipv6_hdr_t *ipv6 = pkt->data;
	gnrc_pktsnip_t *ext = NULL;
	ext = gnrc_ipv6_ext_build(pkt, next, ipv6->nh, size);
	if(ext == NULL) {
		DEBUG("ESP: Couldn't build EXT Header\n");
		return NULL;
	}
	ipv6->nh = PROTNUM_IPV6_EXT_ESP;

	DEBUG("ESP: EXT Header build. PROTNUM of ipv6-nh %i; PROTNUM of nh: %i\n", ipv6->nh, ((ipv6_ext_t *)ext->data)->nh);

	return pkt;
}
gnrc_pktsnip_t *esp_header_process(gnrc_pktsnip_t *pkt) {
	/*TODO: First check if TUNNEL OR TRANSPORT in sad_entry
	 *
	 */
	DEBUG("INCOMMING ESP PACKET:\nHERE BE DRAGONS\n");
	return pkt;
}

void gnrc_ipsec_show_pkt(gnrc_pktsnip_t *pkt) {
    gnrc_pktsnip_t *snip = pkt;
    int i = 0;

    while(snip != NULL) {
        printf("snip %i: protnum: %i size: %i\n", i, gnrc_nettype_to_protnum(snip->type), snip->size);
		snip = snip->next;
        i++;
    }
}