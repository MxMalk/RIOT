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
  * The SPD entries aka. rules are administered. The caches are derived from 
  * those rules on demand for specific connections.
  * 
  * The content of the SAD entries is normally negotiated by the IKEv2 routine
  * but for this initial implementation we will work with mockup entries set 
  * by hand via the commandline tool dbfrm contained in the example 
  * gnrc_networking_ipsec.
  * 
  * For inter process communication PF_KEY is used. Every message is replied to
  * so all messages go by the msg_send_reply() routine.
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
#ifndef GNRC_IPSEC_KEYENGINE_STACK_SIZE
#define GNRC_IPSEC_KEYENGINE_STACK_SIZE        (THREAD_STACKSIZE_DEFAULT)
#endif

/**
 * @brief   Default priority for the IPsec Keyengine thread
 */
#ifndef GNRC_IPSEC_KEYENGINE_PRIO
#define GNRC_IPSEC_KEYENGINE_PRIO             (THREAD_PRIORITY_MAIN - 3)
#endif

/**
 * @brief   size of fixed cypher key memory in byte
 */
#define IPSEC_MAX_HASH_SIZE      (32U)

/**
 * @brief   size of fixed cypher key memory in byte
 */
#define IPSEC_MAX_KEY_SIZE      (32U)

/**
 * @brief   size of fixed cypher nounce memory in byte
 */
#define IPSEC_MAX_IV_SIZE      (12U)


/**
 * @brief   sliding window size for anti replay
 */
#define IPSEC_ANTI_R_WINDOW_SIZE      (3)

/**
 *  @brief  Maximum Memory use of IPsec Database in bytes
 * 
 * Since the content of SPD is compiled into the code we do not need 
 * to programmatically limit it. * 
 */
#define MAX_IPSEC_DB_MEMORY     (4096U)
#define MAX_SPD_CACHE_SIZE      (30 * sizeof(ipsec_sp_cache_t))
#define MAX_SPD_O_CACHE_SIZE    (30 * sizeof(ipsec_sp_cache_t))
#define MAX_SPD_I_CACHE_SIZE    (30 * sizeof(ipsec_sp_cache_t))
#define MAX_SADB_SIZE      (20 * sizeof(ipsec_sa_t))

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
 * @brief   Supported ESP hashes
 */
typedef enum {
    IPSEC_HASH_NONE	= 0, 
    IPSEC_HASH_SHA2_512_256	= 1,    
}ESP_hash_t;

/**
 * @brief   Supported ESP ciphers
 */
typedef enum {
    IPSEC_CIPHER_NONE	        = 0,    
    IPSEC_CIPHER_MOCK	        = 1,    /* mockup debug cipher */
    IPSEC_CIPHER_AES_CTR        = 2,
    IPSEC_CIPHER_CHACHA_POLY	= 3     /* chacha20_poly1305 AEAD cipher RFC7634 */
}ESP_cipher_t;

/**
 * @brief   Possible ESP cipher modes
 */
typedef enum {
    IPSEC_CIPHER_M_NONE         = 0,    /* NONE mustn't go with PROTECTED traffic */
    IPSEC_CIPHER_M_AUTH_ONLY    = 1,    
    IPSEC_CIPHER_M_ENC_N_AUTH   = 2,  
    IPSEC_CIPHER_M_COMB	        = 3
}ESP_crypto_mode_t;

/** 
 * @brief   ESP cryptography details.
 * 
 * @note TODO: find a generalized solution to the keysize problem
 */
typedef struct __attribute__((__packed__)) {
    ESP_cipher_t cipher;
    ESP_hash_t hash;
    uint8_t key[IPSEC_MAX_KEY_SIZE];
    uint8_t hash_key[IPSEC_MAX_HASH_SIZE];
    uint8_t iv[IPSEC_MAX_IV_SIZE];
} ipsec_crypto_info_t;

/* TODO: replay window management and assertion must added. Probably best
 * positioned inte keyengine management alongside SN incrementation. 
 * -> Replay window management is the receiver side of SN incrementation*/

/**
 * @brief   Security Assiciation Database (SAD) entry type 
 */
typedef struct __attribute__((__packed__)) {
    uint16_t id;            /**< security parameter identifier */
    uint32_t spi;           /**< security parameter index */
    uint64_t sn;            /**< sequence number */
    uint8_t sn_of;          /**< overflow permission flag for sequence number.
                            (1) overflow allowed */
    uint64_t rp_l_bound;    /**< replay window lower bound */
    uint64_t rp_u_bound;    /**< replay window upper bound */
    uint64_t rp_window[IPSEC_ANTI_R_WINDOW_SIZE];   /**< replay window content */
    ESP_crypto_mode_t c_mode;                       /**< cryptographic mode */
    ipsec_crypto_info_t crypt_info;                  /**< cypher key, mode, etc. */
    uint32_t re_lt;         /**< renegotiation after milliseconds */
    uint32_t re_bc;         /**< renegotiation after bytecount */
    uint32_t max_lt;        /**< maximum lifetime in milliseconds */
    uint32_t max_bc;        /**< maximum lifetime in bytecount */
    uint8_t rn;             /**< lifetime flag to (0)RENEGOTIATE or (1)TERMINATE 
                            on end of lifetime */
    uint8_t mode;           /**< (0)TRANSPORT mode, (1)TUNNEL mode */
    uint32_t pmtu;          /**< observed path MTU */
    ipv6_addr_t tunnel_dst; /**< tunnel destination ipv6 address */
    ipv6_addr_t tunnel_src; /**< tunnel source ipv6 address */
} ipsec_sa_t;

/**
 * @brief   Security Policy Database (SPD) entry type 
 * 
 * rudimentary implementation not supporting ranges or wildcards, omitting
 * not needed fields like AH/ESP flag, Bypass DF bit. Consult RFC 4301 section
 * 4.4.1.1. for more information.
 *   
 */
typedef struct __attribute__((__packed__)) ipsec_sp_cache {
    ipv6_addr_t dst;            /**< destination ipv6 address */
    ipv6_addr_t src;            /**< source ipv6 address */
    uint8_t nh;                 /**< payloads IP protocoll number */
    uint16_t dst_port;          /**< Traffic Selector(TS) destination port 
                                number for UDP/TCP */  
    uint16_t src_port;          /**< Traffic Selector(TS) source port number 
                                for UDP/TCP */
    FilterRule_t rule;          /**< firewall filter rule */
    TunnelMode_t tun_mode;      /**< (0)TRANSPORT mode, (1)TUNNEL mode */
    ESP_crypto_mode_t c_mode;   /**< cypher mode */
    ipv6_addr_t tunnel_dst;     /**< tunnel destination ipv6 address */
    ipv6_addr_t tunnel_src;     /**< tunnel source ipv6 address */
    uint32_t sa;                /**< 0 if not associated with a SAD entry */
} ipsec_sp_cache_t;

/**
 * @brief   Security Policy Database CACHE (SPD cache) entry type 
 *  
 */
typedef struct __attribute__((__packed__)) ipsec_sp {        
    ipv6_addr_t dst;            /**< destination ipv6 address */
    ipv6_addr_t src;            /**< source ipv6 address */
    uint8_t pfp_flag;           /**< populate spd details from packet flag*/
    uint8_t nh;                 /**< payloads IP protocoll number */
    uint16_t dst_port;          /**< Traffic Selector(TS) destination port 
                                number for UDP/TCP */  
    uint16_t src_port;          /**< Traffic Selector(TS) source port number 
                                for UDP/TCP */
    FilterRule_t rule;          /**< firewall filter rule */
    TunnelMode_t tun_mode;      /**< (0)TRANSPORT mode, (1)TUNNEL mode */
    ESP_crypto_mode_t c_mode;   /**< cypher mode */
    ipv6_addr_t tunnel_dst;     /**< tunnel destination ipv6 address */
    ipv6_addr_t tunnel_src;     /**< tunnel source ipv6 address */

    /* ranges fields: If these are set, use range between both coresponding
     * struct values */
    ipv6_addr_t dst_range;      /**< dst range field. ignore if null */
    ipv6_addr_t src_range;      /**< src range field. ignore if null */
    uint16_t dst_port_range;    /**< dst_port range field. ignore if null */
    uint16_t src_port_range;    /**< src_port range field. ignore if null */
} ipsec_sp_t;

/**
 * @brief   Initialization of the IPsec Keyengine thread.
 *
 * @return  The PID to the IPsec Keyengine thread, on success.
 * @return  a negative errno on error.
 * @return  -EOVERFLOW, if there are too many threads running already
 * @return  -EEXIST, if Thread was already initialized.
 */
kernel_pid_t ipsec_keyengine_init(void);

/**
* @brief   spd cache entry retrieval
*
* returns sp entry based on TS and generates it from SPD rules if needed
*
* @return ipsec_sp_cache_t
*/
const ipsec_sp_cache_t *ipsec_get_sp_entry(TrafficMode_t traffic_mode,
                        ipsec_ts_t* ts);

/**
* @brief   sa entry retrieval
*
* returns sa entry based on SPI
*
* @return ipsec_sa_t
*/
const ipsec_sa_t *ipsec_get_sa_by_spi(uint32_t spi);

/**
* @brief   inject spd and sa entries
*
* temporary solution for PoC and testing until pfkey or other message 
* communication is established.
*
* @param[in] sp sp_chache entry to inject
* @param[in] sa corresponding ipsec_sa_t or NULL
*
* @return  1 on success
* @return -1 on failure
*/
int ipsec_inject_db_entries(ipsec_sp_cache_t* sp, ipsec_sa_t* sa);

/**
* @brief   increments sequence number of SA
*
* @return  1 if incrementation is accepted
* @return -1 if pkt should not be send
*/
int ipsec_increment_sn(uint32_t spi);

#ifdef __cplusplus
}
#endif 


#endif /*NET_GNRC_IPV6_IPSEC_KEYENGINE*/