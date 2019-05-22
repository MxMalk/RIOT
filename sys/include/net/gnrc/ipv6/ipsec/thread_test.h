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
 * @brief       IPsec thread and definitions
 *
 * Incomming esp traffic (esp handlicht) is done by function calls from
 * gnrc_ipv6.c.
 * Outgoing PROTECTED packets are handed to the esp thread where esp header
 * is build, filled and merged into a new IPv6 packet.
 * 
 * @{
 *
 * @file
 * @brief   IPv6 ESP structures and fuctions
 *
 * @author  Maximilian Malkus <malkus@cip.ifi.lmu.de>
 */

#ifndef NET_GNRC_IPV6_IPSEC_TEST
#define NET_GNRC_IPV6_IPSEC_TEST


#include "kernel_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief   Traffic type flag
 */
typedef enum TrafficMode {
    GNRC_IPSEC_RCV,
    GNRC_IPSEC_SND
}TrafficMode_t;

/**
 * @brief   Tunnel mode
 */
typedef enum TunnelMode {
    GNRC_IPSEC_TUNNEL,
    GNRC_IPSEC_TRANSPORT
}TunnelMode_t;

/**
 * @brief   IPsec firewall rule
 */
typedef enum FilterRule {
    GNRC_IPSEC_DISCARD,
    GNRC_IPSEC_BYPASS,
    GNRC_IPSEC_PROTECT
}FilterRule_t;

/**
 * @defgroup    net_gnrc_ipv6_ipsec  
 * @ingroup     net_gnrc_ipv6
 * @ingroup     config
 * @{
 */
/**
 * @brief   Default stack size to use for the IPSEC thread
 */
#ifndef GNRC_IPSEC_STACK_SIZE
#define GNRC_IPSEC_STACK_SIZE        (THREAD_STACKSIZE_DEFAULT)
#endif

/**
 * @brief   Default priority for the IPSEC thread
 */
#ifndef GNRC_IPSEC_PRIO
#define GNRC_IPSEC_PRIO             (THREAD_PRIORITY_MAIN - 4)
#endif

/**
 * @brief   Default message queue size to use for the IPSEC thread.
 */
#ifndef GNRC_IPSEC_MSG_QUEUE_SIZE
#define GNRC_IPSEC_MSG_QUEUE_SIZE   (8U)
#endif


/**
 * @brief   Initialization of the IPsec thread.
 *
 * @return  The PID to the IPsec thread, on success.
 * @return  a negative errno on error.
 * @return  -EOVERFLOW, if there are too many threads running already
 * @return  -EEXIST, if IPv6 was already initialized.
 */
kernel_pid_t gnrc_ipsec_init(void);

/**
 * @brief   SPD-I and SPD-O and SPD checking without triggering SAD creation
 * 
 *          This enables the ipv6 thread to check on SPD rules without beeing
 *          blocked by network traffic like IKEv2 negotiations.
 *
 * @param[in] pkt   IPv6 packet
 * @param[in] mode  Flag for incomming or outgoing traffic
 *
 * @return  
 */
FilterRule_t gnrc_ipsec_spd_check(gnrc_pktsnip_t *pkt, TrafficMode_t mode);

/**
 * @brief   ESP header handler for incomming ESP traffic
 *
 * @param[in] pkt   IPv6 packet containing ESP header
 *
 * @return ESP processed IPv6 packet with pkt snip pointer to previous header
 */
gnrc_pktsnip_t *gnrc_ipsec_handle_esp(gnrc_pktsnip_t *pkt);

#ifdef __cplusplus
}
#endif

#endif /* NET_GNRC_IPV6_IPSEC_TEST */
