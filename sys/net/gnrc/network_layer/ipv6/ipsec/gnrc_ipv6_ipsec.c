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
#include "net/gnrc/ipv6/ipsec/ts.h"
#include "net/gnrc/ipv6/ipsec/ipsec.h"

#define ENABLE_DEBUG    (1)
#include "debug.h"

static kernel_pid_t _pid = KERNEL_PID_UNDEF;


#if ENABLE_DEBUG
static char _stack[GNRC_IPSEC_STACK_SIZE + THREAD_EXTRA_STACKSIZE_PRINTF];
#else
static char _stack[GNRC_IPSEC_STACK_SIZE];
#endif


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
    if (gnrc_netapi_send(netif->pid, pkt) < 1) {
            DEBUG("ipsec: unable to send packet\n");
            gnrc_pktbuf_release(pkt);
    }
}

gnrc_pktsnip_t *ipsec_handle_esp(gnrc_pktsnip_t *pkt) {
    /* TODO EXT header processing and stripping
     * gnrc_pktbuf_start_write(pkt)
     * gnrc_pktbuf_remove_snip(tmp_pkt, tmp_pkt); */
    return pkt;
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
                DEBUG("ipsec_thread: Tx GNRC_NETAPI_MSG_TYPE_SND\n");
#ifdef ENABLE_DEBUG
                ipsec_show_pkt(msg.content.ptr);
#endif          
                pkt = msg.content.ptr;
                ipsec_ts_t ts;
                if(ipsec_ts_from_pkt(pkt, &ts, (int)GNRC_IPSEC_SND) == NULL){
                    DEBUG("ipsec_thread: Tx couldn't create traffic selector\n");
                    break;           
                }
                uint32_t spi = ipsec_get_sp_entry(GNRC_IPSEC_SND, &ts)->sa;
                if(!esp_header_build(pkt, ipsec_get_sa_by_spi(spi), &ts)){
                    gnrc_pktbuf_release(pkt);
                    DEBUG("ipsec_thread: Tx couldn't create esp header\n");
                    return NULL;
                }
                _send_to_interface(pkt);
                break;
            case GNRC_NETAPI_MSG_TYPE_RCV:
                /* This shouldn't happen. Rx is handled by function calls 
                 * from ipv6 thread */ 
                DEBUG("ipsec_thread: Tx unexpected code path\n");
                break;              
            default:
                DEBUG("ipsec_thread: Tx netapi msg type not supported.\n");
                break;
        }
    }
    return NULL;
}
