/*
 * Copyright (C) Maximilian Malkus <malkus@cip.ifi.lmu.de> 2019
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

//#include "kernel_types.h"
//#include "net/gnrc.h"
#include "utlist.h"
#include "net/gnrc/nettype.h"
#include "net/gnrc/ipv6/hdr.h"
#include "net/gnrc/ipv6/ext.h"
#include "net/udp.h"
#include "net/gnrc/ipv6/ipsec/ipsec.h"

#include "net/gnrc/ipv6/ipsec/ts.h"

#define ENABLE_DEBUG    (0)
#define EXTENDED_DEBUG  (0)
#include "debug.h"

static uint8_t PrevHeaders[6] = {
    0, //PROTNUM_IPV6_EXT_HOPOPT
    41, //PROTNUM_IPV6
    43, //PROTNUM_IPV6_EXT_RH
    44, //PROTNUM_IPV6_EXT_FRAG
    60, //PROTNUM_IPV6_EXT_DST
    135, //PROTNUM_IPV6_EXT_MOB
};

bool _is_prev_hdr(uint8_t prot) {
    for(int i=0; i < (int)sizeof(PrevHeaders); i++) {
        if(prot == PrevHeaders[i]) {
            return true;
        }
    }
    return false;
}

/* finds last snip in pkt and fills argument pointers if it is a payload */
gnrc_pktsnip_t *_find_last_snip(gnrc_pktsnip_t *snip, uint8_t *ph_protnum, 
                    void **payload_h) {
    uint8_t tmp_protnum;
    bool iterate = true;
    bool prev;

    DEBUG("ipsec_ts:: searching marked snips\n");

    while(iterate) {
        prev = false;
        iterate = false;
        tmp_protnum = gnrc_nettype_to_protnum(snip->type);
        /* find ipv6 and all pre payload headers */
        if(_is_prev_hdr(tmp_protnum)) {
            if(snip->next == NULL || snip->next->type == 255) {
                prev = true;            
            } else {
                snip = snip->next;
                iterate = true;
            }
        }
    }
    if(!prev){
        *payload_h = snip->data;
        *ph_protnum = gnrc_nettype_to_protnum(snip->type);
        iterate = false;
    }
    return snip;
}

/* gets handed the last snip with type != 255 and iterates over data of
 * last snip in search of payload */
int _find_payload_in_umarked(gnrc_pktsnip_t *snip, uint8_t *ph_protnum, 
                                void **payload_h) {
    void* data_pointer;
    uint8_t tmp_protnum;
    tmp_protnum = gnrc_nettype_to_protnum(snip->type);
    data_pointer = snip->data;

    DEBUG("ipsec_ts: searching unmarked pkt area\n");
    while(*payload_h == NULL) {
        /* check nh field in data and iterate */
        if( tmp_protnum == PROTNUM_IPV6 ) {
            tmp_protnum = (int)((ipv6_hdr_t *)data_pointer)->nh;
            data_pointer = (uint8_t*)data_pointer + sizeof(ipv6_hdr_t);
        } else if (_is_prev_hdr(tmp_protnum)) {
                tmp_protnum = ((ipv6_ext_t *)data_pointer)->nh;
                data_pointer = (uint8_t*)data_pointer + sizeof(ipv6_ext_t);
        } else {
            /* in this case we should have our payload field*/
            *payload_h = data_pointer;
            *ph_protnum = tmp_protnum;
        }
    }
    return 1;    
}

ipsec_ts_t *ipsec_ts_from_info(ipv6_addr_t dst,
        ipv6_addr_t src, uint8_t protnum, network_uint16_t *dst_port, 
        network_uint16_t *src_port, ipsec_ts_t *ts) {

    ts->dst = dst;
    ts->src = src;
    ts->prot = protnum;
    if(dst_port!=NULL) {
        ts->dst_port = byteorder_ntohs(*dst_port);
    } else {
        ts->dst_port = -1;
    }
    if(src_port!=NULL) {
        ts->src_port = byteorder_ntohs(*src_port);
    } else {
        ts->src_port = -1;
    }
    return ts;
}

ipsec_ts_t* ipsec_ts_from_pkt(gnrc_pktsnip_t *pkt, ipsec_ts_t *ts, int t_mode)
{
    gnrc_pktsnip_t *snip;
    gnrc_pktsnip_t *last_snip;
    ipv6_hdr_t *ipv6;
    void *payload_h;            /* pointer to payload data */
    uint8_t ph_protnum;         /* payload protocol number */

    DEBUG("ipsec_ts: searching for payload\n");
    
    /* ipv6 existance assured before calling this function */
    LL_SEARCH_SCALAR(pkt, snip, type, GNRC_NETTYPE_IPV6);
    ipv6 = snip->data;

    /* iterate through all snips and search for a payload packet 
     * if none is found, snip is last snip after this loop*/
    payload_h = NULL;
    ph_protnum = 255;
    if( t_mode == (int)GNRC_IPSEC_SND) {
         last_snip = _find_last_snip(snip, &ph_protnum, &payload_h);
         if(payload_h == NULL) {
             _find_payload_in_umarked(last_snip, &ph_protnum, &payload_h);
         }
    } else {
        /* ipv6 is "last" snip, since called from Rx (reversed order) */
        _find_payload_in_umarked(snip, &ph_protnum, &payload_h);
    }

    assert(payload_h != NULL);
    /* some payload types need special handling*/
    switch(ph_protnum) {
        /* Add UDP/TCP port numbers. Pointers are the same for UDP/TCP */
        case PROTNUM_UDP:
        case PROTNUM_TCP:
            ts = ipsec_ts_from_info(ipv6->dst, ipv6->src, ph_protnum,
                    &((udp_hdr_t*)payload_h)->dst_port,
                    &((udp_hdr_t*)payload_h)->src_port, ts);
            break;
        default:                
            ts = ipsec_ts_from_info( ipv6->dst, ipv6->src, ph_protnum,
                                            NULL, NULL, ts);        
    }

    DEBUG("ipsec_ts: ts build from pkt\n");
#if EXTENDED_DEBUG == 1
    char c[50];
    printf("ipsec_ts: dst:%s\n", ipv6_addr_to_str(c, &ts->dst, 50));
    printf("ipsec_ts: src:%s\n", ipv6_addr_to_str(c, &ts->src, 50));
    printf("ipsec_ts: dst_port:%i\n", ts->dst_port);
    printf("ipsec_ts: src_port:%i\n", ts->src_port);
#endif
    DEBUG("ipsec_ts: proto:%i\n", (int)ts->prot);

    return ts;
}