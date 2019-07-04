/*
 * Copyright (C) 2018 Maximilian Malkus <malkus@cip.ifi.lmu.de>
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

 /**
  * @ingroup     net_gnrc_ipv6_ipsec
  * @brief       IPsec ESP header definitions and routines
  * 
  * @details Following is the general strucutre of the ESP header. 
  * Programatically we split it into an header and a trailer type.
  * 
  * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ {.unparsed}
  *  0                   1                   2                   3
  *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ ----
  * |                Security Parameters Index (SPI)                | ^Int.
  * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |Cov-
  * |                       Sequence Number                         | |ered
  * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ | ----
  * |                  Payload Data* (variable)                     | | ^
  * ~                                                               ~ | |
  * |                                                               | |Conf.
  * +               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |Cov-
  * |               |    Padding (0-255 bytes)                      | |ered*
  * +-+-+-+-+-+-+-+-+               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ | |
  * |                               |  Pad Length   |   Next Header | v v
  * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ ------
  * |            Integrity Check Value-ICV (variable)               |
  * ~                                                               ~
  * |                                                               |
  * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
  *
  *
  * @file
  * @brief		IPv6 ESP header structs and methods
  *
  * @author  Maximilian Malkus <malkus@cip.ifi.lmu.de>
  */

#ifndef NET_GNRC_IPV6_IPSEC_ESP
#define NET_GNRC_IPV6_IPSEC_ESP

#include "byteorder.h"
#include "net/ipv6/addr.h"
#include "net/gnrc/pkt.h"
#include <stdint.h>

#include "net/gnrc/ipv6/ipsec/keyengine.h"


#ifdef __cplusplus
extern "C" {
#endif

/**
* @brief Data type to represent an ESP packet header.
*/
typedef struct __attribute__((packed)) {
	network_uint32_t spi;
	network_uint32_t sn;
} ipv6_esp_hdr_t;

/**
 * @brief Data type to represent an ESP packet trailer.
 * TODO: maybe remove trl alltougether.
*/
typedef struct __attribute__((packed)) {
	uint8_t pl;
	uint8_t nh;
} ipv6_esp_trl_t;

/**
* @brief   Build ESP header for sending
*
* @param[in] pkt   head after IPv6 header build
* @param[in] sa_entry   Database pointer to according Security
*            Association (SA) entry
* @param[in] ts   Pointer to Traffic Selector (TS) of pkt
*
* @return  pktsnip at IPv6 with ESP
*/
gnrc_pktsnip_t *esp_header_build(gnrc_pktsnip_t *pkt, 
                            const ipsec_sa_t *sa_entry,
                            ipsec_ts_t *ts);

/**
* @brief   Marks, Decrypts and returns pkt at next header. If the ipsec rules
             dictate tunnel mode, packet is consumed and processed.
*
* @param[in] pktsnip at ESP EXT header
*
* @return  processed ESP pkt at next header poisition
* @return  NULL on tunnel mode
*/
gnrc_pktsnip_t *esp_header_process(gnrc_pktsnip_t *pkt, uint8_t protnum);

#ifdef __cplusplus
}
#endif

#endif /* NET_GNRC_IPV6_IPSEC_ESP */