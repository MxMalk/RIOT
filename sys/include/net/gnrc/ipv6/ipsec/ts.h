/*
 * Copyright (C) Maximilian Malkus <malkus@cip.ifi.lmu.de> 2019
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 * 
 */

/**
 * @brief   IPsec Traffic Selector methods
 *
 * @author  Maximilian Malkus <malkus@cip.ifi.lmu.de>
 */

#ifndef NET_GNRC_IPV6_IPSEC_TS
#define NET_GNRC_IPV6_IPSEC_TS

#include "net/ipv6/addr.h"
#include "kernel_types.h"
#include "net/gnrc/pkt.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Traffic Selector for IPsec database information
 */
typedef struct __attribute__((__packed__)) {
    ipv6_addr_t dst;
    ipv6_addr_t src;
    int dst_port; //NULL when -1
    int src_port; //NULL when -1
    uint8_t prot;
} ipsec_ts_t;

/**
 * @brief   TODO: 
 * 
 * mode is like this because of circular dependency
 *
 * @param[in] pkt   IPv6 containing packet
 * @param[in] mode  0 for RCV
 * @param[in] mode  1 for SND
 *
 * @return  
 */
ipsec_ts_t* ipsec_ts_from_pkt(gnrc_pktsnip_t *pkt, ipsec_ts_t *ts,
                                int t_mode);


/**
 * @brief   TODO: 
 *
 * @param[in] 
 *
 * @return  
 */
ipsec_ts_t* ipsec_ts_from_info(ipv6_addr_t, ipv6_addr_t, uint8_t, 
                network_uint16_t*, network_uint16_t*, ipsec_ts_t*);


#ifdef __cplusplus
}
#endif

#endif /* NET_GNRC_IPV6_IPSEC_TS */