/*
 * Copyright (C) 2018 Maximilian Malkus <malkus@cip.ifi.lmu.de>
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

 /**
  * @defgroup    net_gnrc_ipv6_ipsec_keyengine 
  * @ingroup     net_gnrc_ipv6
  * @ingroup     config
  * 
  * @brief IPsec key engine
  * 
  * Holds, maintains and gives access to the IPsec related databases:
  * Security Policy Database (SPD)
  * Security Policy Database cache for incomming traffic (SPD-I) 
  * Security Policy Database cache for outgoing traffic (SPD-O)
  * Security Assiciation Database (SAD)
  * 
  * The SPD entries aka. rules are administered. The chaches are derived from 
  * those rules on demand for specific connections.
  * 
  * The content of the SAD entries is normally negotiated by the IKEv2 routine
  * but for this initial implementation we will work with mockup entries set 
  * by hand via the commandline tool dbfrm contained in the example 
  * gnrc_networking_ipsec.
  * 
  * For further details on the architecture nad hierachy of the databases 
  * please consult RFC 4301 section 4.4
  * 
  * @author  Maximilian Malkus <malkus@cip.ifi.lmu.de>
  */

 #ifndef NET_GNRC_IPV6_IPSEC_KEYENGINE
 #define NET_GNRC_IPV6_IPSEC_KEYENGINE

#include "kernel_types.h"
#include "net/ipv6/addr.h"
#include "net/gnrc/ipv6/ipsec/ipsec.h"

#ifdef __cplusplus
extern "C" {
#endif

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
 * @brief   size of  type size ipsec_cypher_key_t
 */
#define IPSEC_MAX_KEY_SIZE      (512U)

/**
 *  @brief  Maximum Memory use of IPsec Database in bytes
 * 
 * Since the content of SPD is compiled into the code we do not need 
 * to programmatically limit it. * 
 */
#define MAX_IPSEC_DB_MEMORY     (4096U)
#define MAX_SPD_CACHE_SIZE      (30 * sizeof(ipsec_sp_chache_t))
#define MAX_SPD_O_CACHE_SIZE    (30 * sizeof(ipsec_sp_chache_t))
#define MAX_SPD_I_CACHE_SIZE    (30 * sizeof(ipsec_sp_chache_t))
#define MAX_SAD_CACHE_SIZE      (20 * sizeof(ipsec_sa_t))

/**
 * @brief   Dynamic IPsec databases
 */
typedef enum ipsec_dbtype {
    IPSEC_DB_SPD,
    IPSEC_DB_SPD_I,
    IPSEC_DB_SPD_O,
    IPSEC_DB_SAD
}ipsec_dbtype_t;

/**
 * @brief   Supported ESP cyphers
 */
typedef enum {
    IPSEC_CYPHER_NONE   = 0,
    IPSEC_CYPHER_SHA	= 1,
    IPSEC_CYPHER_CHACHA	= 2
}ESP_cypher_t;

typedef struct __attribute__((__packed__)) {
#if IPSEC_MAX_KEY_SIZE == 128
    uint16_t key;
#endif
#if IPSEC_MAX_KEY_SIZE == 256
    uint32_t key;
#endif
#if IPSEC_MAX_KEY_SIZE == 512
    uint64_t key;
#endif
#if IPSEC_MAX_KEY_SIZE == 1024
    uint128_t key;
#endif
} ipsec_cypher_key_t;

/**
 * @brief   Security Assiciation Database (SAD) entry type 
 */
typedef struct __attribute__((__packed__)) {
    uint32_t spi;           /**< security parameter index */
    uint64_t sn;            /**< sequence number */
    uint8_t sn_of;          /**< overflow permission flag for sequence number */
    uint64_t rp_c;          /**< replay window counter */
    //TODO: bitmap to check for a replay??
    //TODO: dynamically choose key size depending on cyphers used? like MAX_KEY_SIZE or link to cypher type
    ipsec_cypher_key_t encr_cyph;      /**< encryption cypher type */
    ipsec_cypher_key_t auth_cyph;      /**< authentication cypher type */
    ipsec_cypher_key_t comb_cyph;      /**< combined auth and enc cypher type */
    //TODO: +iv ??
    uint32_t re_lt;         /**< renegotiation after milliseconds */
    uint32_t re_bc;         /**< renegotiation after bytecount */
    uint32_t max_lt;        /**< maximum lifetime in milliseconds */
    uint32_t max_bc;        /**< maximum lifetime in bytecount */
    uint8_t rn;             /**< lifetime flag to (0)RENEGOTIATE or (1)TERMINATE on end of lifetime */
    uint8_t mode;           /**< (0)TRANSPORT mode, (1)TUNNEL mode */
    uint32_t pmtu;          /**< observed path MTU */
    ipv6_addr_t tunnel_src; /**< tunnel destination ipv6 address */
    ipv6_addr_t tunnel_dst; /**< tunnel source ipv6 address */
} ipsec_sa_t;

/**
 * @brief   Security Policy Database (SPD) entry type 
 * 
 * rudimentary implementation not supporting ranges or wildcards, omitting
 * not needed fields like AH/ESP flag, Bypass DF bit. Consult RFC 4301 for 
 * more information.
 * 
 * We only support combined mode cypher, so only one field is needed. * 
 */
typedef struct __attribute__((__packed__)) ipsec_sp_chache {
    ipv6_addr_t dst;
    ipv6_addr_t src;
    uint8_t nh;
    uint16_t dst_port;    
    uint16_t src_port;
    FilterRule_t rule; 
    TunnelMode_t tun_mode;
    ESP_cypher_t encr_cypher;
    ESP_cypher_t auth_cypher;
    ESP_cypher_t comb_cypher;
    ipv6_addr_t tunnel_src;
    ipv6_addr_t tunnel_dst;
    ipsec_sa_t *sa;
} ipsec_sp_chache_t;

/**
 * @brief   Security Policy Database CACHE (SPD chache) entry type 
 *  
 */
typedef struct __attribute__((__packed__)) ipsec_sp {
    ipv6_addr_t dst;
    ipv6_addr_t src;

    uint8_t nh;
    uint16_t dst_port;    
    uint16_t src_port;

    FilterRule_t rule; 
    TunnelMode_t tun_mode;
    ESP_cypher_t encr_cypher;

    ESP_cypher_t auth_cypher;
    ESP_cypher_t comb_cypher;
    ipv6_addr_t tunnel_src;

    ipv6_addr_t tunnel_dst;
    /* ranges fields. If these are not NULL, distance between the coresponding
     * fields should be treated as a range value */
    ipv6_addr_t dst_range;
    ipv6_addr_t src_range;

    uint16_t dst_port_range;    
    uint16_t src_port_range;
} ipsec_sp_t;

/**
 * @brief   Initialization of the IPsec Keyengine thread.
 *
 * @return  The PID to the IPsec Keyengine thread, on success.
 * @return  a negative errno on error.
 * @return  -EOVERFLOW, if there are too many threads running already
 * @return  -EEXIST, if Thread was already initialized.
 */
kernel_pid_t gnrc_ipsec_keyengine_init(void);

/**
* @brief   spd cache entry retrieval
*
* returns sp entry based os TS and generates it from SPD rules if needed
*
* @return ipsec_sp_chache_t
*/
const ipsec_sp_chache_t *get_sp_entry(TrafficMode_t traffic_mode,
                        ipsec_traffic_selector_t ts);


#ifdef __cplusplus
}
#endif 


#endif /*NET_GNRC_IPV6_IPSEC_KEYENGINE*/