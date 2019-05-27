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
#include "net/gnrc/ipv6/hdr.h"


#include "net/gnrc/ipv6/ipsec/esp.h"
#include "net/gnrc/ipv6/ipsec/key_engine.h"
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

/*IPv6 printing function*/
static void _ipv6_print_info(gnrc_pktsnip_t *pkt);

kernel_pid_t gnrc_ipsec_init(void) {
    if (_pid > KERNEL_PID_UNDEF) {
        return _pid;
    }

    _pid = thread_create(_stack, sizeof(_stack), GNRC_IPSEC_PRIO,
                         THREAD_CREATE_STACKTEST, _event_loop, NULL, "ipsec");

    return _pid;
}

void gnrc_ipsec_show_pkt(gnrc_pktsnip_t *pkt) {
	gnrc_pktsnip_t *snip = pkt;
	int i = 0;

	while (snip != NULL) {
		printf("snip %i: protnum: %i size: %i\n", i, gnrc_nettype_to_protnum(snip->type), snip->size);
		snip = snip->next;
		i++;
	}
}

gnrc_pktsnip_t *gnrc_ipsec_handle_esp(gnrc_pktsnip_t *pkt) {
    //TODO EXT header processing and stripping
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

FilterRule_t gnrc_ipsec_spd_check(gnrc_pktsnip_t *pkt, TrafficMode_t mode) {
    if(mode == GNRC_IPSEC_RCV) {
        (void)pkt;
    }
    if(mode == GNRC_IPSEC_SND) {
        (void)pkt;
    }
#if 0
    return GNRC_IPSEC_DISCARD;
#endif
    return GNRC_IPSEC_BYPASS;
}


static void _ipv6_print_info(gnrc_pktsnip_t *pkt)
{
    gnrc_pktsnip_t *snip;
    LL_SEARCH_SCALAR(pkt, snip, type, GNRC_NETTYPE_IPV6);
    ipv6_hdr_t *ipv6 = ((ipv6_hdr_t *)snip->data);
    static char addr_str[IPV6_ADDR_MAX_STR_LEN];
    static char addr_str2[IPV6_ADDR_MAX_STR_LEN];
    ipv6_addr_to_str(addr_str, &ipv6->dst, sizeof(addr_str));
    ipv6_addr_to_str(addr_str2, &ipv6->src, sizeof(addr_str2));
    DEBUG("ipsec: SRC: %s   DST: %s  ipv6NH: %i ", addr_str, addr_str2, (int)ipv6->nh);
    if (snip->next != NULL) {
        DEBUG("snipNH: %i\n", gnrc_nettype_to_protnum(snip->next->type));
    } else {
        DEBUG("\n");
    }
}


static void *_event_loop(void *args)
{
    //TODO: remove
    (void) _check_loop_WIP();
    msg_t msg, msg_q[GNRC_IPSEC_MSG_QUEUE_SIZE];
    gnrc_netreg_entry_t me_reg = GNRC_NETREG_ENTRY_INIT_PID(GNRC_NETREG_DEMUX_CTX_ALL,
                                                            sched_active_pid);(void)args;
    msg_init_queue(msg_q, GNRC_IPSEC_MSG_QUEUE_SIZE);
    gnrc_pktsnip_t *pkt=NULL;

    /* register interest in all IPV6 packets */
    gnrc_netreg_register(GNRC_NETTYPE_IPSEC, &me_reg);
    
    //TODO: remove
    DEBUG("ipsec_tread: up and running\n");
    /* start event loop */
    while (1) {
        pkt=NULL;
        //gnrc_pktsnip_t *tmp;
        msg_receive(&msg);

        switch (msg.type) {
            case GNRC_NETAPI_MSG_TYPE_RCV:
                DEBUG("ipsec_tread: GNRC_NETAPI_MSG_TYPE_RCV\n");
                _ipv6_print_info(msg.content.ptr);
                //_receive(msg.content.ptr);
                break;

            case GNRC_NETAPI_MSG_TYPE_SND:
                DEBUG("ipsec_tread: GNRC_NETAPI_MSG_TYPE_SND\n");
                _ipv6_print_info(msg.content.ptr);
                //_send(msg.content.ptr, true);
                break;
                
            default:
                DEBUG("ipsec_tread: default/unknown received.\n");
                break;
        }


        gnrc_pktbuf_release(pkt);
    }

    return NULL;
}