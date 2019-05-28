/*
 * sa_t must contain:
 * SPI Security Parameter Index
 * SN Sequence Number (counter)
 * SN Overflow permission (flag)
 * Replay window counter
 * ESP combined mode algorithm, key(s), etc. ??
 * max_lifetime_time
 * max_lifetime_bytecount (number of bytes esp is used on)
 * lifetime_time
 * lifetime_bytecount
 * Flag to determine if sa should be replaced or terminated after endOfLife
 * possibly another two HARD_lifetimes to terminate even on "replace" if sa does not get renewed
 * tunnel or transport? flag
 * observed path mtu and aging variable
 * tunnel header ip source, dest, version
 */

/*
 * spd entry identified by dest, src, nh? How does the spi fit in here???
 * spd_entry_t must contain:
 * 
 */

/*
 * Copyright (C) 2018 Maximilian Malkus <malkus@cip.ifi.lmu.de>
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

 /**
  * @defgroup    SPD API dummy module for ESP testing
  * @ingroup     net_gnrc_ipv6_ipsec
  * @{
  *
  * @file
  * @brief   Dummy SPD API
  *
  * @author  Maximilian Malkus <malkus@cip.ifi.lmu.de>
  */

 #ifndef NET_GNRC_IPV6_IPSEC_KEYENGINE
 #define NET_GNRC_IPV6_IPSEC_KEYENGINE

#include "kernel_types.h"
#include "net/ipv6/addr.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @defgroup    net_gnrc_ipv6_ipsec_keyengine 
 * @ingroup     net_gnrc_ipv6
 * @ingroup     config
 * @{
 */
/**
 * @brief   Default stack size to use for the IPsec Keyengine thread
 */
#ifndef GNRC_IPSEC_STACK_SIZE
#define GNRC_IPSEC_STACK_SIZE        (THREAD_STACKSIZE_DEFAULT)
#endif

/**
 * @brief   Default priority for the IPsec Keyengine thread
 */
#ifndef GNRC_IPSEC_PRIO
#define GNRC_IPSEC_PRIO             (THREAD_PRIORITY_MAIN - 3)
#endif

/**
 * @brief   Default message queue size to use for the IPsec Keyengine thread.
 */
#ifndef GNRC_IPSEC_MSG_QUEUE_SIZE
#define GNRC_IPSEC_MSG_QUEUE_SIZE   (8U)
#endif


/**
 * @brief   Initialization of the IPsec Keyengine thread.
 *
 * @return  The PID to the IPsec Keyengine thread, on success.
 * @return  a negative errno on error.
 * @return  -EOVERFLOW, if there are too many threads running already
 * @return  -EEXIST, if Thread was already initialized.
 */
kernel_pid_t gnrc_ipsec_keyengine_init(void);


typedef struct __attribute__((__packed__)) {
    uint32_t spi; //security parameter index
    uint64_t sn; //sequence number
    uint8_t sn_of; //sequence number overflow flag
    uint64_t rp_c; //replay window counter
    //TODO: bitmap to check for a replay??
    uint8_t encr_cyph; //cypher type
    uint8_t auth_cyph; //cypher type
    uint8_t comb_cyph; //cypher type
    //TODO: +key. mode, iv etc. Eigenen Typ verlinken, oder lauter Felder anlegen?? Größe relevant. Tobi hats sich einfach gemacht und garkeine Typen/Klassen verwendet.
    uint32_t re_lt; //renegotiate after lifetime (ms)
    uint32_t re_bc; //renegotiate after bytecount
    uint32_t max_lt; //max. lifetime (ms)
    uint32_t max_bc; //max. bytecount
    uint8_t rn; //renegotiation flag on maxing out (0)RENEGOTIATE (1)TERMINATE
    uint8_t mode; // (0)TRANSPORT mode, (1)TUNNEL mode
    uint32_t pmtu; //observed path MTU
    ipv6_addr_t tunnel_src; //tunnel destination ipv6
    ipv6_addr_t tunnel_dst; //tunnel source ipv6
} ipsec_sa_t;

typedef struct __attribute__((__packed__)) {
    uint8_t rule; //int STATUS: (1)PROTECT (2)BYPASS, (3)DISCARD
    /* TODO: sp_type:
     * (0)SPD-I (incomming DISCARD or BYPASS)
     * (1)SPD-O (outgoing DISCARD or BYPASS)
     * (2)SPD-S (outgoing PROTECT) */
    uint8_t sp_type; 
    ipv6_addr_t dest;
    ipv6_addr_t src;
    uint8_t nh;
    uint8_t dest_port;    
    uint8_t src_port;
    ipsec_sa_t *sa;

} ipsec_sp_cache_t;

/**
* @brief   spd entry retrieval
*
* @param[in] dest, src, nh, dest_port, src_port
*
* @return (0) error, 
*/
ipsec_sp_cache_t *get_spd_entry(const ipv6_addr_t *dst, const ipv6_addr_t *src, uint8_t nh, uint8_t dest_port, uint8_t src_port);


#ifdef __cplusplus
}
#endif 


#endif /*NET_GNRC_IPV6_IPSEC_KEYENGINE*/