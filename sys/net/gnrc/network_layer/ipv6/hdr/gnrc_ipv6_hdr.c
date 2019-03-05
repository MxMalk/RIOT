/*
 * Copyright (C) 2015 Martine Lenders <mlenders@inf.fu-berlin.de>
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @{
 *
 * @file
 */

#include "net/ipv6/addr.h"
#include "net/gnrc/ipv6/hdr.h"
#include "net/gnrc/nettype.h"
#include "net/gnrc/pktbuf.h"
#include "net/protnum.h"
#include "net/gnrc/ipv6/ipsec/ipsec.h"
#include "net/gnrc/ipv6/ipsec/spd_api_mockup.h"

#define ENABLE_DEBUG    (0)
#include "debug.h"

#if defined(MODULE_IPV6_ADDR)
static char addr_str[IPV6_ADDR_MAX_STR_LEN];
#endif

/* For independent testing */
#ifdef MODULE_GNRC_IPV6
#define HDR_NETTYPE (GNRC_NETTYPE_IPV6)
#else
#define HDR_NETTYPE (GNRC_NETTYPE_UNDEF)
#endif

gnrc_pktsnip_t *gnrc_ipv6_hdr_build(gnrc_pktsnip_t *payload, const ipv6_addr_t *src,
                                    const ipv6_addr_t *dst)
{
    #ifdef MODULE_GNRC_IPV6_IPSEC
        int mode = -1; //ESP MODE: (1)TRANSPORT, (2)TUNNEL  is -1 because compiler error in switch case
        int rounds; //(1)Transport (2)TUNNEL;
        sp_cache_t *sp_entry;

        //TODO: analyse payload and fill nh, dp, so
        uint8_t nh = 0;
        uint8_t dp = 0;
        uint8_t sp = 0;
        sp_entry = get_spd_entry(dst, src, nh, dp, sp);

        switch(sp_entry->status) {
            case 0: DEBUG("Discarding IPV6 packet: No SPD rule.\n");
                    gnrc_pktbuf_release(payload);
                    return NULL;
                    break;
            case 1: mode = sp_entry->sa->mode;
                    if(mode == 0) { //in (0)Transport mode we only do one round of IPv6 building.
                    rounds = 1;
                    payload = esp_header_build(payload, sp_entry);
                    } else {
                        rounds = 2;
                    }
                    break;
            case 2: rounds = 1;
                    break;
            case 3: DEBUG("Discarding IPV6 packet based on SPD rule.\n");
                    gnrc_pktbuf_release(payload);
                    return NULL;
                    break;
            default: DEBUG("get_spd_status returned invalid value: %i\n", mode);
                    return NULL;
                    break;
        }
    #endif /* MODULE_GNRC_IPV6_IPSEC */

    gnrc_pktsnip_t *ipv6;
    ipv6_hdr_t *hdr;

    #ifdef MODULE_GNRC_IPV6_IPSEC

        //alternative would be a goto statement... closing brackets at end of function
        for(uint8_t i = 0; i < rounds; i++) {
            if( i == 1 ) {
                //Here the firstly build IPV6 Packet gets compressed in tunnel mode
                payload = esp_header_build(ipv6, sp_entry);
            }

    #endif /* MODULE_GNRC_IPV6_IPSEC */

    ipv6 = gnrc_pktbuf_add(payload, NULL, sizeof(ipv6_hdr_t), HDR_NETTYPE);

    if (ipv6 == NULL) {
        DEBUG("ipv6_hdr: no space left in packet buffer\n");
        return NULL;
    }

    hdr = (ipv6_hdr_t *)ipv6->data;

    if (src != NULL) {
#ifdef MODULE_IPV6_ADDR
        DEBUG("ipv6_hdr: set packet source to %s\n",
              ipv6_addr_to_str(addr_str, (ipv6_addr_t *)src,
                               sizeof(addr_str)));
#endif
        memcpy(&hdr->src, src, sizeof(ipv6_addr_t));
    }
    else {
        DEBUG("ipv6_hdr: set packet source to ::\n");
        ipv6_addr_set_unspecified(&hdr->src);
    }

    if (dst != NULL) {
#ifdef MODULE_IPV6_ADDR
        DEBUG("ipv6_hdr: set packet destination to %s\n",
              ipv6_addr_to_str(addr_str, (ipv6_addr_t *)dst,
                               sizeof(addr_str)));
#endif
        memcpy(&hdr->dst, dst, sizeof(ipv6_addr_t));
    }
    else {
        DEBUG("ipv6_hdr: set packet destination to ::1\n");
        ipv6_addr_set_loopback(&hdr->dst);
    }

    hdr->v_tc_fl = byteorder_htonl(0x60000000); /* set version, tc and fl in one go*/
    hdr->nh = PROTNUM_RESERVED;
    hdr->hl = 0;

    #ifdef MODULE_GNRC_IPV6_IPSEC //end of ESP for loop
        }
    #endif

    return ipv6;
}

/** @} */
