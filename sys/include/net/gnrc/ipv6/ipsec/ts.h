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
 * @brief   generates Traffic Selector(TS) from marked or unmarked pkt for
 *          RX and TX traffic alike.
 * 
 * mode is hardcoded to avoid circular dependency
 *
 * @param[in] pkt   IPv6 containing packet
 * @param[in] mode  0 for RCV
 * @param[in] mode  1 for SND
 * @param[in] ts    TS allocated by callee
 * @param[out] ts   filled TS struct
 *
 * @return  *ts Pointer to Traffic Selector(TS)
 * @return  NULL on error
 */
ipsec_ts_t* ipsec_ts_from_pkt(gnrc_pktsnip_t *pkt, ipsec_ts_t *ts,
                                int t_mode);


/**
 * @brief   Build Traffic Selector(TS) from arguments information
 *
 * @param[in] ts    TS allocated by callee
 * @param[out] ts   filled TS struct
 *
 * @return  *ts Pointer to Traffic Selector(TS)
 * @return  NULL on error
 */
ipsec_ts_t* ipsec_ts_from_info(ipv6_addr_t dst, ipv6_addr_t src, 
        uint8_t protnum, network_uint16_t *dst_port, 
        network_uint16_t *src_port, ipsec_ts_t *ts);


#ifdef __cplusplus
}
#endif

#endif /* NET_GNRC_IPV6_IPSEC_TS */