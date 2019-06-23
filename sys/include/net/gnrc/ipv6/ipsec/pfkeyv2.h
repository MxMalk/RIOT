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
 * @ingroup     net_gnrc_ipv6_ipsec *
 *
 * @{
 *
 * @file
 * @brief   PF_KEY message types
 *
 * message types for security association management as defined in
 * RFC2367 (1998)
 *
 * @author  Maximilian Malkus <malkus@cip.ifi.lmu.de>
 */
#ifndef PFKEY_V2_H
#define PFKEY_V2_H

#include "kernel_types.h"

#define PFKEYV2_REVISION    199806L

#ifdef __cplusplus
extern "C" {
#endif

/*
   This file defines structures and symbols for the PF_KEY Version 2
   key management interface. It was written at the U.S. Naval Research
   Laboratory. This file is in the public domain. The authors ask that
   you leave this credit intact on any copies of this file.
   */

   #define PF_KEY_V2 2
   #define PFKEYV2_REVISION        199806L

   #define SADB_RESERVED    (0x6600U)
   #define SADB_GETSPI      (0x6601U)
   #define SADB_UPDATE      (0x6602U)
   #define SADB_ADD         (0x6603U)
   #define SADB_DELETE      (0x6604U)
   #define SADB_GET         (0x6605U)
   #define SADB_ACQUIRE     (0x6606U)
   #define SADB_REGISTER    (0x6607U)
   #define SADB_EXPIRE      (0x6608U)
   #define SADB_FLUSH       (0x6609U)
   #define SADB_DUMP        (0x660aU)
   #define SADB_X_PROMISC   (0x660bU)
   #define SADB_X_PCHANGE   (0x660cU)
   #define SADB_MAX         (0x660dU)

   typedef struct {
     uint8_t sadb_msg_version;
     uint8_t sadb_msg_type;
     uint8_t sadb_msg_errno;
     uint8_t sadb_msg_satype;
     uint16_t sadb_msg_len;
     uint16_t sadb_msg_reserved;
     uint32_t sadb_msg_seq;
     uint32_t sadb_msg_pid;
   } pfkey_sadb_msg_t;

   typedef struct {
     uint16_t sadb_ext_len;
     uint16_t sadb_ext_type;
   } pfkey_sadb_ext_t;

   typedef struct {
     uint16_t sadb_sa_len;
     uint16_t sadb_sa_exttype;
     uint32_t sadb_sa_spi;
     uint8_t sadb_sa_replay;
     uint8_t sadb_sa_state;
     uint8_t sadb_sa_auth;
     uint8_t sadb_sa_encrypt;
     uint32_t sadb_sa_flags;
   } pfkey_sadb_sa_t;

   struct sadb_lifetime {
     uint16_t sadb_lifetime_len;
     uint16_t sadb_lifetime_exttype;
     uint32_t sadb_lifetime_allocations;
     uint64_t sadb_lifetime_bytes;
     uint64_t sadb_lifetime_addtime;
     uint64_t sadb_lifetime_usetime;
   };

   struct sadb_address {
     uint16_t sadb_address_len;
     uint16_t sadb_address_exttype;
     uint8_t sadb_address_proto;
     uint8_t sadb_address_prefixlen;
     uint16_t sadb_address_reserved;
   };

   struct sadb_key {
     uint16_t sadb_key_len;
     uint16_t sadb_key_exttype;
     uint16_t sadb_key_bits;
     uint16_t sadb_key_reserved;
   };

   struct sadb_ident {
     uint16_t sadb_ident_len;
     uint16_t sadb_ident_exttype;
     uint16_t sadb_ident_type;
     uint16_t sadb_ident_reserved;
     uint64_t sadb_ident_id;
   };

   struct sadb_sens {
     uint16_t sadb_sens_len;
     uint16_t sadb_sens_exttype;
     uint32_t sadb_sens_dpd;
     uint8_t sadb_sens_sens_level;
     uint8_t sadb_sens_sens_len;
     uint8_t sadb_sens_integ_level;
     uint8_t sadb_sens_integ_len;
    uint32_t sadb_sens_reserved;
   };

   struct sadb_prop {
     uint16_t sadb_prop_len;
     uint16_t sadb_prop_exttype;
     uint8_t sadb_prop_replay;
     uint8_t sadb_prop_reserved[3];
   };

   struct sadb_comb {
     uint8_t sadb_comb_auth;
     uint8_t sadb_comb_encrypt;
     uint16_t sadb_comb_flags;
     uint16_t sadb_comb_auth_minbits;
     uint16_t sadb_comb_auth_maxbits;
     uint16_t sadb_comb_encrypt_minbits;
     uint16_t sadb_comb_encrypt_maxbits;
     uint32_t sadb_comb_reserved;
     uint32_t sadb_comb_soft_allocations;
     uint32_t sadb_comb_hard_allocations;
     uint64_t sadb_comb_soft_bytes;
     uint64_t sadb_comb_hard_bytes;
     uint64_t sadb_comb_soft_addtime;
     uint64_t sadb_comb_hard_addtime;
     uint64_t sadb_comb_soft_usetime;
     uint64_t sadb_comb_hard_usetime;
   };

   struct sadb_supported {
     uint16_t sadb_supported_len;
     uint16_t sadb_supported_exttype;
     uint32_t sadb_supported_reserved;
   };

   struct sadb_alg {
     uint8_t sadb_alg_id;
     uint8_t sadb_alg_ivlen;
     uint16_t sadb_alg_minbits;
     uint16_t sadb_alg_maxbits;
     uint16_t sadb_alg_reserved;
   };

   struct sadb_spirange {
     uint16_t sadb_spirange_len;
     uint16_t sadb_spirange_exttype;
     uint32_t sadb_spirange_min;
     uint32_t sadb_spirange_max;
     uint32_t sadb_spirange_reserved;
   };

   struct sadb_x_kmprivate {
     uint16_t sadb_x_kmprivate_len;
     uint16_t sadb_x_kmprivate_exttype;
     uint32_t sadb_x_kmprivate_reserved;
   };

#define SADB_EXT_RESERVED             0
#define SADB_EXT_SA                   1
#define SADB_EXT_LIFETIME_CURRENT     2
#define SADB_EXT_LIFETIME_HARD        3
#define SADB_EXT_LIFETIME_SOFT        4
#define SADB_EXT_ADDRESS_SRC          5
#define SADB_EXT_ADDRESS_DST          6
#define SADB_EXT_ADDRESS_PROXY        7
#define SADB_EXT_KEY_AUTH             8
#define SADB_EXT_KEY_ENCRYPT          9
#define SADB_EXT_IDENTITY_SRC         10
#define SADB_EXT_IDENTITY_DST         11
#define SADB_EXT_SENSITIVITY          12
#define SADB_EXT_PROPOSAL             13
#define SADB_EXT_SUPPORTED_AUTH       14
#define SADB_EXT_SUPPORTED_ENCRYPT    15
#define SADB_EXT_SPIRANGE             16
#define SADB_X_EXT_KMPRIVATE          17
#define SADB_EXT_MAX                  17
#define SADB_SATYPE_UNSPEC    0
#define SADB_SATYPE_AH        2
#define SADB_SATYPE_ESP       3
#define SADB_SATYPE_RSVP      5
#define SADB_SATYPE_OSPFV2    6
#define SADB_SATYPE_RIPV2     7
#define SADB_SATYPE_MIP       8
#define SADB_SATYPE_MAX       8

#define SADB_SASTATE_LARVAL   0
#define SADB_SASTATE_MATURE   1
#define SADB_SASTATE_DYING    2
#define SADB_SASTATE_DEAD     3
#define SADB_SASTATE_MAX      3

#define SADB_SAFLAGS_PFS      1

#define SADB_AALG_NONE        0
#define SADB_AALG_MD5HMAC     2
#define SADB_AALG_SHA1HMAC    3
#define SADB_AALG_MAX         3

#define SADB_EALG_NONE        0
#define SADB_EALG_DESCBC      2
#define SADB_EALG_3DESCBC     3
#define SADB_EALG_NULL        11
#define SADB_EALG_MAX         11

#define SADB_IDENTTYPE_RESERVED   0
#define SADB_IDENTTYPE_PREFIX     1
#define SADB_IDENTTYPE_FQDN       2
#define SADB_IDENTTYPE_USERFQDN   3
#define SADB_IDENTTYPE_MAX        3

#ifdef __cplusplus
}
#endif

#define SADB_KEY_FLAGS_MAX 0
#endif /* __PFKEY_V2_H */