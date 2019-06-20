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

/* Main event loop for IPsec */
static void *_event_loop(void *args);

kernel_pid_t gnrc_ipsec_init(void) {
    if (_pid > KERNEL_PID_UNDEF) {
        return _pid;
    }

    _pid = thread_create(_stack, sizeof(_stack), GNRC_IPSEC_PRIO,
                         THREAD_CREATE_STACKTEST, _event_loop, NULL, "ipsec");

    return _pid;
}

/* Interim code to get the pf_key messages to the keyhandler */
static kernel_pid_t _key_pid = KERNEL_PID_UNDEF;
static void _set_keyhandler_pid(void) {
    _key_pid = gnrc_ipsec_keyengine_init();
}

static void _send_pfkey_msg(msg_t *msg) {
    msg_try_send(msg, _key_pid);
}
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

void gnrc_ipsec_show_pkt(gnrc_pktsnip_t *pkt) {
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
        gnrc_ipsec_show_pkt(pkt);
        
    if (gnrc_netapi_send(netif->pid, pkt) < 1) {
            DEBUG("ipsec: unable to send packet\n");
            gnrc_pktbuf_release(pkt);
    }
}

gnrc_pktsnip_t *gnrc_ipsec_handle_esp(gnrc_pktsnip_t *pkt) {
    /* TODO EXT header processing and stripping
     * gnrc_pktbuf_start_write(pkt)
     * gnrc_pktbuf_remove_snip(tmp_pkt, tmp_pkt); */
    return pkt;
}

FilterRule_t gnrc_ipsec_spd_check(gnrc_pktsnip_t *pkt, TrafficMode_t mode)
{
    gnrc_pktsnip_t *snip;
    DEBUG("ipsec: spd_check\n");

    if(mode == GNRC_IPSEC_RCV) {
        LL_SEARCH_SCALAR(pkt, snip, type, GNRC_NETTYPE_IPV6_EXT_ESP);
        if (snip != NULL) {
            DEBUG("ipsec: ESP header found\n");
        }
        (void)pkt;
    }
    if(mode == GNRC_IPSEC_SND) {
        LL_SEARCH_SCALAR(pkt, snip, type, GNRC_NETTYPE_UDP);
        if (snip != NULL) {
            DEBUG("ipsec: UDP Rx packet found\n");
            //return GNRC_IPSEC_F_BYPASS;
            return GNRC_IPSEC_F_PROTECT;
        }
        (void)pkt;
    }
#if 0
    return GNRC_IPSEC_F_DISCARD;
#endif
    return GNRC_IPSEC_F_BYPASS;
}

static const ipsec_sp_cache_t *_sp_from_packet(TrafficMode_t traffic_mode, 
                                                gnrc_pktsnip_t *pkt) {
    gnrc_pktsnip_t *snip = NULL;
    ipsec_traffic_selector_t ts;
    LL_SEARCH_SCALAR(pkt, snip, type, GNRC_NETTYPE_IPV6);
    ipv6_hdr_t *ipv6 = ((ipv6_hdr_t *)snip->data);
    // TODO: if nh = UDP/TCP: SEARCH SCALAR for it and add port, else:
    ts.dst = ipv6->dst;
    ts.src = ipv6->src;
    ts.dst_port = -1;
    ts.src_port = -1;
    return get_sp_entry(traffic_mode, ts);
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
                gnrc_ipsec_show_pkt(msg.content.ptr);
#endif

                /*TODO: Protect*/
                /*if tunnel
                if (gnrc_netapi_dispatch_send(GNRC_NETTYPE_IPV6,
                                    GNRC_NETREG_DEMUX_CTX_ALL, pkt) == 0 ) {
                    DEBUG("ipv6: unable send packet\n");
                    gnrc_pktbuf_release(pkt);
                } */
                pkt = msg.content.ptr;
                esp_header_build(pkt, _sp_from_packet(GNRC_IPSEC_SND, pkt)->sa);
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
