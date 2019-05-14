/*
 * Copyright (C)
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#ifndef NET_GNRC_IPV6_IPSEC_TEST
#define NET_GNRC_IPV6_IPSEC_TEST


#include "kernel_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief   Message recieve flag
 */
#ifndef GNRC_IPSEC_RCV   
#define GNRC_IPSEC_RCV   0
#endif
/**
 * @brief   Message send flag
 */
#ifndef GNRC_IPSEC_SND
#define GNRC_IPSEC_SND   1
#endif

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
 * @brief   Default message queue size to use for the 6LoWPAN thread.
 */
#ifndef GNRC_IPSEC_MSG_QUEUE_SIZE
#define GNRC_IPSEC_MSG_QUEUE_SIZE   (8U)
#endif

kernel_pid_t gnrc_ipsec_init(void);

/**
* @brief   build esp header
*
* @param[in] pkt head after ipv6 header build, accompanying spd_entry
*
* @return  pktsnip at IPv6 with ESP
*/
bool gnrc_ipsec_filter(gnrc_pktsnip_t *pkt, uint8_t mode);

#ifdef __cplusplus
}
#endif

#endif /* NET_GNRC_IPV6_IPSEC_TEST */
