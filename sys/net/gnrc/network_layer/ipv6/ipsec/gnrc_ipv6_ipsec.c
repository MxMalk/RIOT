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

#ifdef ENABLE_DEBUG

static void _ipv6_print_info(gnrc_pktsnip_t *pkt)
{
    gnrc_pktsnip_t *snip = NULL;
    LL_SEARCH_SCALAR(pkt, snip, type, GNRC_NETTYPE_IPV6);
    ipv6_hdr_t *ipv6 = ((ipv6_hdr_t *)snip->data);
    static char addr_str[IPV6_ADDR_MAX_STR_LEN];    
    static char addr_str2[IPV6_ADDR_MAX_STR_LEN];
    ipv6_addr_to_str(addr_str, &ipv6->dst, sizeof(addr_str));
    ipv6_addr_to_str(addr_str2, &ipv6->src, sizeof(addr_str2));
    DEBUG("ipsec: PKT_INFO: SRC: %s   DST: %s\n", addr_str, addr_str2);
    DEBUG("ipsec: PKT_INFO: ipv6NH: %i", (int)ipv6->nh);
    if (snip->next != NULL) {
        DEBUG(" snipNH: %i\n", gnrc_nettype_to_protnum(snip->next->type));
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
		printf("snip %i: protnum: %i size: %i\n", i, gnrc_nettype_to_protnum(snip->type), snip->size);
		snip = snip->next;
		i++;
	}
}

/*Send to interface function identical with the last lines of the sending process in ipv6 thread*/
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

#endif /* ENABLE_DEBUG */

gnrc_pktsnip_t *gnrc_ipsec_handle_esp(gnrc_pktsnip_t *pkt) {
    /* TODO EXT header processing and stripping
     * gnrc_pktbuf_start_write(pkt)
     * gnrc_pktbuf_remove_snip(tmp_pkt, tmp_pkt); */
    return pkt;
}

static void _check_loop_WIP(void)
{
    /*
    int tunnel_mode = -1; //ESP MODE: (0)TRANSPORT, (1)TUNNEL
    int ip_rounds = 0; //(1)Transport (2)TUNNEL;
    int sp_rule = 0;
    sp_cache_t *sp_entry;

    //TODO: analyse payload and fill nh, dp, so
    uint8_t nh = 0;
    uint8_t dp = 0;
    uint8_t sp = 0;
    sp_entry = get_spd_entry(dst, src, nh, dp, sp);
    if (sp_entry == NULL) {
        sp_rule = 0;
    } else {
        sp_rule = sp_entry->rule;
    }

    switch(sp_rule) {
        case 0: DEBUG("Discarding IPV6 packet: No SPD rule.\n");
                gnrc_pktbuf_release(payload);
                return NULL;
                break;
        case 1: tunnel_mode = sp_entry->sa->mode;
                if(tunnel_mode == 0) { //in (0)Transport tunnel_mode we only do one round of IPv6 building.
                    ip_rounds = 1;
                } else {
                    ip_rounds = 2;
                }
                break;
        case 2: ip_rounds = 1;
                break;
        case 3: DEBUG("Discarding IPV6 packet based on SPD rule.\n");
                gnrc_pktbuf_release(payload);
                return NULL;
                break;
        default: DEBUG("get_spd_status returned invalid value: %i\n", tunnel_mode);
                return NULL;
                break;
    }
    */
   return;
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
            return GNRC_IPSEC_PROTECT;
        }
        (void)pkt;
    }
#if 0
    return GNRC_IPSEC_DISCARD;
#endif
    return GNRC_IPSEC_BYPASS;
}

static const ipsec_sp_cache_t *_sp_from_packet(gnrc_pktsnip_t *pkt) {
    gnrc_pktsnip_t *snip = NULL;
    LL_SEARCH_SCALAR(pkt, snip, type, GNRC_NETTYPE_IPV6);
    ipv6_hdr_t *ipv6 = ((ipv6_hdr_t *)snip->data);
    // TODO: if nh = UDP/TCP: SEARCH SCALAR for it and add port, else:
    int dst_p = -1;
    int src_p = -1;
    return get_spd_entry(&ipv6->dst, &ipv6->src, &ipv6->nh, dst_p, src_p);
}

static void *_event_loop(void *args)
{
    //TODO: check if packet if for self, if yes. Throw error and discard.
    //TODO: remove
    (void) _check_loop_WIP();
    gnrc_pktsnip_t *pkt;
    msg_t msg, msg_q[GNRC_IPSEC_MSG_QUEUE_SIZE];
    gnrc_netreg_entry_t me_reg = GNRC_NETREG_ENTRY_INIT_PID(GNRC_NETREG_DEMUX_CTX_ALL,
                                                            sched_active_pid);(void)args;
    msg_init_queue(msg_q, GNRC_IPSEC_MSG_QUEUE_SIZE);

    /* register interest in all IPV6 packets */
    gnrc_netreg_register(GNRC_NETTYPE_IPSEC, &me_reg);
    
    
    DEBUG("ipsec: thread up and running\n");
    /* start event loop */
    while (1) {
        pkt = NULL;
        DEBUG("ipsec_thread: waiting for incoming message.\n");
        msg_receive(&msg);

        switch (msg.type) {
            case GNRC_NETAPI_MSG_TYPE_RCV:
                /* This shouldn't happen. Rx is handled by function calls 
                 * from ipv6 thread. TODO: throw error 
                 */ 
                DEBUG("ipsec_thread: unexpected code path\n");
                break;
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
                esp_header_build(pkt, _sp_from_packet(pkt)->sa);
                _send_to_interface(pkt);
                break;                
            default:
                DEBUG("ipsec_thread: default/unknown received.\n");
                break;
        }
    }
    return NULL;
}
