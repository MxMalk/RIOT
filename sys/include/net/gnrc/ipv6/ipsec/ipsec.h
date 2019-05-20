/*
 * Copyright (C) 2018 Maximilian Malkus <malkus@cip.ifi.lmu.de>
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

 /**
  * @defgroup    net_gnrc_ipv6_ipsec_esp_hdr Esp Header
  * @ingroup     net_gnrc_ipv6_ipsec
  * @brief       IPsec ESP header definitions and routines
  * 
  * @{
  *
  * @file
  * @brief   IPv6 ESP structures and fuctions
  *
  * @author  Maximilian Malkus <malkus@cip.ifi.lmu.de>
  */

#ifndef NET_GNRC_IPV6_IPSEC_H
#define NET_GNRC_IPV6_IPSEC_H

#include "byteorder.h"
#include "net/ipv6/addr.h"
#include "net/gnrc/pkt.h"
#include <stdint.h>
#include "net/gnrc/ipv6/ipsec/spd_api_mockup.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
* @brief Data type to represent an ESP packet header.
*
* @details The structure of the header is as follows:
*
*
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
*/
typedef struct __attribute__((packed)) {
	network_uint32_t spi;
	network_uint32_t sn;
	/* TODO */
	uint8_t pl;
	uint8_t nh;
} ipv6_esp_hdr_t;

/**
* @brief   build esp header
*
* @param[in] pkt head after ipv6 header build, accompanying spd_entry
*
* @return  pktsnip at IPv6 with ESP
*/
gnrc_pktsnip_t *esp_header_build(gnrc_pktsnip_t *pkt, const sp_cache_t *spd_entry);

/**
* @brief   handle esp header
*
* @param[in] 
*
* @return  
*/
gnrc_pktsnip_t *esp_header_process(gnrc_pktsnip_t *pkt);

/**
 * encrypt_data(gnrc_pktsnip_t *payload);
 * 
 */

//TODO: move or remove after DEV
void gnrc_ipsec_show_pkt(gnrc_pktsnip_t *pkt);


#ifdef __cplusplus
}
#endif

#endif /* NET_GNRC_IPV6_IPSEC_H */