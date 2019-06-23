/*
 * Copyright (C) Maximilian Malkus <malkus@cip.ifi.lmu.de>
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#include "kernel_types.h"
#include "net/gnrc.h"
#include "thread.h"
#include "utlist.h"
#include "net/gnrc/nettype.h"
#include "net/gnrc/ipv6/hdr.h"
#include "net/gnrc/ipv6/ext.h"
#include "net/udp.h"


#include "net/gnrc/ipv6/ipsec/esp.h"
#include "net/gnrc/ipv6/ipsec/keyengine.h"
//#include "net/gnrc/ipv6/ipsec/crypt.h"
#include "net/gnrc/ipv6/ipsec/ipsec.h"

#define ENABLE_DEBUG    (1)
#include "debug.h"

static kernel_pid_t _pid = KERNEL_PID_UNDEF;


#if ENABLE_DEBUG
static char _stack[GNRC_IPSEC_STACK_SIZE + THREAD_EXTRA_STACKSIZE_PRINTF];
#else
static char _stack[GNRC_IPSEC_STACK_SIZE];
#endif

static uint8_t PrevHeaders[6] = {
    0, //PROTNUM_IPV6_EXT_HOPOPT
    41, //PROTNUM_IPV6
    43, //PROTNUM_IPV6_EXT_RH
    44, //PROTNUM_IPV6_EXT_FRAG
    60, //PROTNUM_IPV6_EXT_DST
    135, //PROTNUM_IPV6_EXT_MOB
};

/* Main event loop for IPsec */
static void *_event_loop(void *args);

kernel_pid_t ipsec_init(void) {
    if (_pid > KERNEL_PID_UNDEF) {
        return _pid;
    }

    _pid = thread_create(_stack, sizeof(_stack), GNRC_IPSEC_PRIO,
                         THREAD_CREATE_STACKTEST, _event_loop, NULL, "ipsec");

    return _pid;
}

//TODO: cleanup or clarify
/* Interim code to get the pf_key messages to the keyhandler */
static kernel_pid_t _key_pid = KERNEL_PID_UNDEF;
static void _set_keyhandler_pid(void) {
    _key_pid = ipsec_keyengine_init();
}

/*
static void _send_pfkey_msg(msg_t *msg) {
    msg_try_send(msg, _key_pid);
}
*/
/* End of interim code */

#ifdef ENABLE_DEBUG

static void _ipv6_print_info(gnrc_pktsnip_t *pkt)
{
    ipv6_hdr_t *ipv6 = ((ipv6_hdr_t *)pkt->data);
    static char addr_str[IPV6_ADDR_MAX_STR_LEN];    
    static char addr_str2[IPV6_ADDR_MAX_STR_LEN];
    ipv6_addr_to_str(addr_str, &ipv6->dst, sizeof(addr_str));
    ipv6_addr_to_str(addr_str2, &ipv6->src, sizeof(addr_str2));
    DEBUG("ipsec: PKT_INFO: SRC: %s   DST: %s\n", addr_str, addr_str2);
    DEBUG("ipsec: PKT_INFO: ipv6NH: %i", (int)ipv6->nh);
    if (pkt->next != NULL) {
        DEBUG(" snipNH: %i\n", gnrc_nettype_to_protnum(pkt->next->type));
    } else {
        DEBUG("\n");
    }
}

void ipsec_show_pkt(gnrc_pktsnip_t *pkt) {
	gnrc_pktsnip_t *snip = pkt;
	int i = 0;
    if(pkt->type == GNRC_NETTYPE_IPV6) {
        _ipv6_print_info(pkt);
    }
    
	while (snip != NULL) {
		printf("snip %i: protnum: %i size: %i\n", i, 
                gnrc_nettype_to_protnum(snip->type), snip->size);
		snip = snip->next;
		i++;
	}
}

#endif /* ENABLE_DEBUG */

/* Send to interface function identical with the last lines of the
 * sending process in ipv6 thread*/
static void _send_to_interface(gnrc_pktsnip_t *pkt) 
{
    gnrc_pktsnip_t *snip;
    gnrc_netif_t *netif;

    /* Interface should allready be set correctly. If not abort*/
    LL_SEARCH_SCALAR(pkt, snip, type, GNRC_NETTYPE_NETIF);
    if(snip == NULL) {
        //TODO: error message
        return;
    }
    netif = gnrc_netif_hdr_get_netif(snip->data);
    
#ifdef MODULE_NETSTATS_IPV6
    netif->ipv6.stats.tx_success++;
    netif->ipv6.stats.tx_bytes += gnrc_pkt_len(pkt->next);
#endif
    //TODO: remove ff
        DEBUG("ipsec: pre netapi send pkt:\n");
        ipsec_show_pkt(pkt);
        
    if (gnrc_netapi_send(netif->pid, pkt) < 1) {
            DEBUG("ipsec: unable to send packet\n");
            gnrc_pktbuf_release(pkt);
    }
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

gnrc_pktsnip_t *ipsec_handle_esp(gnrc_pktsnip_t *pkt) {
    /* TODO EXT header processing and stripping
     * gnrc_pktbuf_start_write(pkt)
     * gnrc_pktbuf_remove_snip(tmp_pkt, tmp_pkt); */
    return pkt;
}

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

ipsec_ts_t* ipsec_ts_from_pkt(gnrc_pktsnip_t *pkt, ipsec_ts_t *ts, TrafficMode_t t_mode)
{
    gnrc_pktsnip_t *snip;
    gnrc_pktsnip_t *last_snip;
    ipv6_hdr_t *ipv6;
    void *payload_h;            /* pointer to payload data */
    uint8_t ph_protnum;         /* payload protocol number */

    DEBUG("ipsec_ts: searching for payload\n");
    ipsec_show_pkt(pkt);
    
    /* ipv6 existance assured before calling this function */
    LL_SEARCH_SCALAR(pkt, snip, type, GNRC_NETTYPE_IPV6);
    ipv6 = snip->data;

    /* iterate through all snips and search for a payload packet 
     * if none is found, snip is last snip after this loop*/
    payload_h = NULL;
    ph_protnum = 255;
    if( t_mode == GNRC_IPSEC_SND) {
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
    DEBUG("ipsec_ts: ts built from pkt with proto:%i\n", (int)ts->prot);
    return ts;
}

FilterRule_t ipsec_get_filter_rule(TrafficMode_t mode, ipsec_ts_t *ts){
    const ipsec_sp_cache_t * sp;
    /* Rx ESP will be handled in ext_handling but has no spd-i entry */
    if(ts->prot == PROTNUM_IPV6_EXT_ESP && mode == GNRC_IPSEC_RCV){
        return GNRC_IPSEC_F_PROTECT;
    }
    sp = ipsec_get_sp_entry(mode, ts);
    if(sp != NULL) {
        return sp->rule;       
    }
    DEBUG("ipsec: No SP matched the traffic selector\n");
    return GNRC_IPSEC_F_DISCARD;
}



static void *_event_loop(void *args)
{
    gnrc_pktsnip_t *pkt;
    msg_t msg, msg_q[GNRC_IPSEC_MSG_QUEUE_SIZE];
    gnrc_netreg_entry_t me_reg = GNRC_NETREG_ENTRY_INIT_PID(GNRC_NETREG_DEMUX_CTX_ALL,
                                                            sched_active_pid);
    (void)args;
    msg_init_queue(msg_q, GNRC_IPSEC_MSG_QUEUE_SIZE);

    /* register interest in all IPV6 packets */
    gnrc_netreg_register(GNRC_NETTYPE_IPV6_EXT_ESP, &me_reg);
    _set_keyhandler_pid();
    
    DEBUG("ipsec: thread up and running\n");
    /* start event loop */
    while (1) {
        pkt = NULL;
        DEBUG("ipsec_thread: waiting for incoming message.\n");
        msg_receive(&msg);

        switch (msg.type) {
            case GNRC_NETAPI_MSG_TYPE_SND:
                DEBUG("ipsec_thread: GNRC_NETAPI_MSG_TYPE_SND\n");
#ifdef ENABLE_DEBUG
                ipsec_show_pkt(msg.content.ptr);
#endif

                /*TODO: Protect & tunnel*/
                /*if tunnel
                if (gnrc_netapi_dispatch_send(GNRC_NETTYPE_IPV6,
                                    GNRC_NETREG_DEMUX_CTX_ALL, pkt) == 0 ) {
                    DEBUG("ipv6: unable send packet\n");
                    gnrc_pktbuf_release(pkt);
                } */
                pkt = msg.content.ptr;
                ipsec_ts_t ts;
                if(ipsec_ts_from_pkt(pkt, &ts, GNRC_IPSEC_SND) == NULL){
                    DEBUG("ipsec_thread: couldn't create traffic selector\n");
                    break;           
                }
                uint32_t spi = ipsec_get_sp_entry(GNRC_IPSEC_SND, &ts)->sa;
                esp_header_build(pkt, ipsec_get_sa_by_spi(spi));
                _send_to_interface(pkt);
                break;
            case GNRC_NETAPI_MSG_TYPE_RCV:
                /* This shouldn't happen. Rx is handled by function calls 
                 * from ipv6 thread */ 
                DEBUG("ipsec_thread: unexpected code path\n");
                break;              
            default:
                DEBUG("ipsec_thread: netapi msg type not supported.\n");
                break;
        }
    }
    return NULL;
}
