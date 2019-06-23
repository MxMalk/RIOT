/*
 * Copyright (C) Maximilian Malkus <malkus@cip.ifi.lmu.de>
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 * 
 */

/**
 * @defgroup    net_gnrc_ipv6_ipsec IPsec
 * @ingroup     net_gnrc_ipv6_ipsec
 * @brief       IPsec
 * 
 * @{
 *
 * @file
 * @brief   IPsec thread and methods
 * 
 * Incomming esp traffic handling is done by function calls from
 * gnrc_ipv6.c.
 * Outgoing PROTECTED packets are handed to the ipsec thread where esp header
 * is build, filled and merged into a new IPv6 packet that gets send diectly
 * from this thread.
 *
 * @author  Maximilian Malkus <malkus@cip.ifi.lmu.de>
 */

#ifndef NET_GNRC_IPV6_IPSEC
#define NET_GNRC_IPV6_IPSEC

#include "net/ipv6/addr.h"
#include "kernel_types.h"
#include "net/gnrc/pkt.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief   Traffic type flag
 */
typedef enum TrafficMode {
    GNRC_IPSEC_RCV = 0,
    GNRC_IPSEC_SND = 1
}TrafficMode_t;

/**
 * @brief   Tunnel mode
 */
typedef enum TunnelMode {
    GNRC_IPSEC_M_TRANSPORT	= 0,
    GNRC_IPSEC_M_TUNNEL		= 1
}TunnelMode_t;

/**
 * @brief   IPsec firewall rule
 */
typedef enum FilterRule {
    GNRC_IPSEC_F_DISCARD	= 0,
    GNRC_IPSEC_F_BYPASS	= 1,
    GNRC_IPSEC_F_PROTECT	= 2,
    GNRC_IPSEC_F_ERR      = 3
}FilterRule_t;

/**
 * @defgroup    net_gnrc_ipv6_ipsec  
 * @ingroup     net_gnrc_ipv6
 * @ingroup     config
 * @{
 */
/**
 * @brief   Default stack size to use for the IPsec thread
 */
#ifndef GNRC_IPSEC_STACK_SIZE
#define GNRC_IPSEC_STACK_SIZE        (THREAD_STACKSIZE_DEFAULT)
#endif

/**
 * @brief   Default priority for the IPsec thread
 */
#ifndef GNRC_IPSEC_PRIO
#define GNRC_IPSEC_PRIO             (THREAD_PRIORITY_MAIN - 3)
#endif

/**
 * @brief   Default message queue size to use for the IPsec thread.
 */
#ifndef GNRC_IPSEC_MSG_QUEUE_SIZE
#define GNRC_IPSEC_MSG_QUEUE_SIZE   (8U)
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
 * @brief   Initialization of the IPsec thread.
 *
 * @return  The PID to the IPsec thread, on success.
 * @return  a negative errno on error.
 * @return  -EOVERFLOW, if there are too many threads running already
 * @return  -EEXIST, if IPsec was already initialized.
 */
kernel_pid_t ipsec_init(void);

/**
 * @brief   TODO: 
 *
 * @param[in] pkt   IPv6 containing packet
 * @param[in] mode  Flag for incomming or outgoing traffic
 *
 * @return  
 */
ipsec_ts_t* ipsec_ts_from_pkt(gnrc_pktsnip_t *pkt, ipsec_ts_t *ts,
                TrafficMode_t t_mode);

/**
 * @brief   TODO: 
 *
 * @param[in] 
 *
 * @return  
 */
ipsec_ts_t* ipsec_ts_from_info(ipv6_addr_t, ipv6_addr_t, uint8_t, 
                network_uint16_t*, network_uint16_t*, ipsec_ts_t*);

/**
 * @ brief: TODO: SPD-I and SPD-O and SPD checking without triggering SAD creation
 * 
 *          This enables the ipv6 thread to check on SPD rules without beeing
 *          blocked by network traffic like IKEv2 negotiations.
 *
 * @param[in] mode  Flag for incomming or outgoing traffic
 * @param[in] ts    Traffic selector generated from pkt
 * 
 */
FilterRule_t ipsec_get_filter_rule(TrafficMode_t mode, ipsec_ts_t* ts);

/**
 * @brief   ESP header handler for incomming ESP traffic
 *
 * @param[in] pkt   IPv6 packet containing ESP header
 *
 * @return ESP processed IPv6 packet with pkt snip pointer to previous header
 */
gnrc_pktsnip_t *ipsec_handle_esp(gnrc_pktsnip_t *pkt);

//TODO: move or remove after DEV
void ipsec_show_pkt(gnrc_pktsnip_t *pkt);

#ifdef __cplusplus
}
#endif

#endif /* NET_GNRC_IPV6_IPSEC */
