/*
 * Copyright (C) 2018 Maximilian Malkus <malkus@cip.ifi.lmu.de>
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#include "net/gnrc/ipv6/ipsec/ipsec.h"
#include "net/ipv6/addr.h"
#include "net/gnrc.h"
#include "thread.h"
#include "net/gnrc/ipv6/hdr.h"
#include "net/gnrc/ipv6/ipsec/spd_api_mockup.h"

#define ENABLE_DEBUG    (1)
#include "debug.h"

gnrc_pktsnip_t *esp_header_build(gnrc_pktsnip_t *payload, const sp_cache_t *spd_entry) {
	/*TODO: First check if TUNNEL OR TRANSPORT in sad_entry
	 *
	 */
	DEBUG("OUTGOING ESP PACKET:\nSA MODE: %i\nSP STATUS: %i\n", spd_entry->sa->mode, spd_entry->status);
	return payload;
}

gnrc_pktsnip_t *esp_header_handler(gnrc_pktsnip_t *payload) {
	/*TODO: First check if TUNNEL OR TRANSPORT in sad_entry
	 *
	 */
	DEBUG("INCOMMING ESP PACKET:\nHERE BE DRAGONS\n");
	return payload;
}