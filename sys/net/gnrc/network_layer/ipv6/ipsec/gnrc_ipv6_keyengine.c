/*
 * Copyright (C) 2019 Maximilian Malkus <malkus@cip.ifi.lmu.de>
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#include <stdio.h>
#include "net/gnrc/ipv6/ipsec/ipsec.h"
#include "net/ipv6/addr.h"

#include "net/gnrc/ipv6/ipsec/keyengine.h"

#define ENABLE_DEBUG    (1)
#include "debug.h"

#define COMBINED_DB_SIZE    (spd_size + spd_i_size + spd_o_size + sad_size)

/* TODO: Implemented databases work by stack (FILO) principle */

ipsec_sp_t *spd;
ipsec_sp_chache_t *spd_i;
ipsec_sp_chache_t *spd_o;
ipsec_sa_t *sad;
size_t spd_size;
size_t spd_i_size;
size_t spd_o_size;
size_t sad_size;

static kernel_pid_t _pid = KERNEL_PID_UNDEF;

#if ENABLE_DEBUG
static char _stack[GNRC_IPSEC_STACK_SIZE + THREAD_EXTRA_STACKSIZE_PRINTF];
#else
static char _stack[GNRC_IPSEC_STACK_SIZE];
#endif

/* Main event loop for keyengine */
static void *_event_loop(void*);
int _return_spd_conf(ipsec_sp_t*);
int _fill_sp_cache_entry(ipsec_sp_chache_t*, ipsec_sp_t*, ipsec_traffic_selector_t);

kernel_pid_t gnrc_ipsec_keyengine_init(void) {
    if (_pid > KERNEL_PID_UNDEF) {
        return _pid;
    }

    _pid = thread_create(_stack, sizeof(_stack), GNRC_IPSEC_PRIO,
                         THREAD_CREATE_STACKTEST, _event_loop, NULL, "keyengine");

    return _pid;
}

void _ipsec_parse_spd(ipsec_sp_t *db) {
    /* TODO: Comment on how this is not final */
    size_t tmp_db_size;
    tmp_db_size = _return_spd_conf(db);
    spd_size = tmp_db_size * sizeof(ipsec_sp_t);
    return;
}

int _db_init(void) {
    spd_size = 0;
    spd_i_size = 0;
    spd_o_size = 0;
    sad_size = 0;
    
    _ipsec_parse_spd(spd);
    if(spd == NULL) {
        DEBUG("ipsec_keyeng: ERROR parsing spd info into memory\n");
        return -1;
    }

    return 1;
}

ipsec_sp_chache_t* _add_sp_cache_entry(ipsec_sp_chache_t *sp, 
                            TrafficMode_t traffic_mode) {
    void *db;
    size_t db_s;
    size_t max_db_s;

    switch(traffic_mode) {
        case GNRC_IPSEC_RCV:
            db = spd_i;
            db_s = spd_i_size;
            max_db_s = MAX_SPD_I_CACHE_SIZE;
            break;
        case GNRC_IPSEC_SND:
            db = spd_o;
            db_s = spd_o_size;
            max_db_s = MAX_SPD_O_CACHE_SIZE;
            break;                
    }

    size_t newsize = db_s + sizeof(ipsec_sp_chache_t);
    if(newsize > MAX_IPSEC_DB_MEMORY && newsize > max_db_s) {
        DEBUG("ipsec_keyeng: ERROR: Limits reached\n");
        return NULL;
    }
    db = realloc(db, newsize);
    if(db != NULL){
        memcpy(((uint8_t*)(db) + db_s - 1), sp, sizeof(ipsec_sp_chache_t));
        db_s = newsize;
    } else {
        DEBUG("ipsec_keyeng: ERROR: HEAP space exhausted\n");
        return NULL;
    }

    return (ipsec_sp_chache_t*)(((uint8_t*)(db) + db_s - 1) 
                    + sizeof(ipsec_sp_chache_t));

}

const ipsec_sp_chache_t *_generate_sp_from_spd(TrafficMode_t traffic_mode, 
                                                ipsec_traffic_selector_t ts) {

    ipsec_sp_t *spd_result = NULL;;
    ipsec_sp_t *spd_rule;
    ipsec_sp_chache_t *return_handle;                       
    ipsec_sp_chache_t *sp_entry = NULL;

    for(size_t i=0; i < spd_size; i = i + sizeof(ipsec_sp_t)) {
        spd_rule = (ipsec_sp_t*)((uint8_t*)spd + i);
        /* TODO: handle and accept ranges, ignore if ranges are 0*/
        if(!(ipv6_addr_equal(&spd_rule->dst, &ipv6_addr_unspecified)
                        || ipv6_addr_equal(&spd_rule->src, &ts.src))){
            break;
        }
        if(!(ipv6_addr_equal(&spd_rule->src, &ipv6_addr_unspecified)
                        || ipv6_addr_equal(&spd_rule->src, &ts.src))){
            break;
        }
        if(!(spd_rule->nh == 255 || spd_rule->nh == ts.nh)){
            break;
        }
        if(!(spd_rule->dst_port == 0 || spd_rule->dst_port == ts.dst_port)){
            break;
        }
        if(!(spd_rule->src_port == 0 || spd_rule->dst_port == ts.src_port)){
            break;
        }
        spd_result = spd_rule;
    }
    if(spd_result == NULL) {
        DEBUG("ipsec_keyeng: ERROR: No SPD match for pkt . Ruleset faulty?\n");
        return NULL;
    }

    if(spd_rule->rule == GNRC_IPSEC_PROTECT) {
        if(traffic_mode == GNRC_IPSEC_RCV) {
            DEBUG("ipsec_keyeng: ERROR: Rx packet for uninitialized ESP connection\n");
            return NULL;
        }
    }
    //TODO: sourround with mem error catch code
    sp_entry = malloc(sizeof(ipsec_sp_chache_t));
    /* Call also generates SA for Tx traffic if needed */
    _fill_sp_cache_entry(sp_entry, spd_result, ts);
    return_handle = _add_sp_cache_entry(sp_entry, traffic_mode);
    free(sp_entry);

    if(return_handle == NULL) {
        DEBUG("ipsec_keyeng: Cache entry could not be generated from spd rule\n");
        return NULL;
    }

    return return_handle;    
}

int _fill_sp_cache_entry(ipsec_sp_chache_t *sp_entry, ipsec_sp_t *spd_rule, 
                            ipsec_traffic_selector_t ts) {
    sp_entry->dst = ts.dst;
    sp_entry->src = ts.src;
    sp_entry->nh = ts.nh;
    sp_entry->dst_port = ts.dst_port;
    sp_entry->src_port = ts.src_port;
    sp_entry->rule = spd_rule->rule;
    sp_entry->tun_mode = spd_rule->tun_mode;
    sp_entry->encr_cypher = spd_rule->encr_cypher;
    sp_entry->auth_cypher = spd_rule->auth_cypher;
    sp_entry->comb_cypher = spd_rule->comb_cypher;
    sp_entry->tunnel_src = spd_rule->tunnel_src;
    sp_entry->tunnel_dst = spd_rule->tunnel_dst;
    //TODO: check if SA is needed and generate it
    sp_entry->sa = NULL;
    if(sp_entry->sa == NULL) {
        DEBUG("ipsec_keyeng: SA could not be created\n");
        return -1;
    }

    return 1;
}

const ipsec_sp_chache_t *get_sp_entry(TrafficMode_t traffic_mode,
                            ipsec_traffic_selector_t ts) {    
    void *db;
    int db_s;
    switch(traffic_mode) {
        case GNRC_IPSEC_RCV:
            db_s = spd_i_size;
            db = spd_i;
            break;
        case GNRC_IPSEC_SND:
            db_s = spd_o_size;
            db = spd_o;
            break;                
    }

    if(db_s == 0) {
        DEBUG("ipsec_keyengine: Requested sp_db empty or uninitalized\n");
    } else {
        return NULL;
    }

    const ipsec_sp_chache_t *sp_entry;
    for(int i=0; i < db_s; i = i + sizeof(ipsec_sp_chache_t)) {
        sp_entry = (ipsec_sp_chache_t*)((uint8_t*)db + i);
        if(!(ipv6_addr_equal(&sp_entry->dst, &ipv6_addr_unspecified) 
                            || ipv6_addr_equal(&sp_entry->dst, &ts.dst))){
            break;
        }
        if(!(ipv6_addr_equal(&sp_entry->src, &ipv6_addr_unspecified) 
                            || ipv6_addr_equal(&sp_entry->src, &ts.src))){
            break;
        }
        if(!(sp_entry->nh == 255 || sp_entry->nh == ts.nh)){
            break;
        }
        if(!(sp_entry->dst_port == 0 || sp_entry->dst_port == ts.dst_port)){
            break;
        }
        if(!(sp_entry->src_port == 0 || sp_entry->dst_port == ts.src_port)){
            break;
        }
        return sp_entry;
    }

    /* No chache entries matched traffic slectors. Checking SPD rules */
   
    sp_entry = _generate_sp_from_spd(traffic_mode, ts);
    if(sp_entry == NULL) {
        if(traffic_mode == GNRC_IPSEC_SND) {
            DEBUG("ipsec_keyeng: Error in Tx SP generation\n");
        } else {
            DEBUG("ipsec_keyeng: Error in Rx SP generation\n");
        }
        return NULL;
    }

    return sp_entry;
}

int _return_spd_conf(ipsec_sp_t *spd) {
    /* TODO: WIP solution for SPD */
    ipsec_sp_t *spd_pointer;
    size_t size = 2 * sizeof(ipsec_sp_t);
    spd = malloc(size);
    spd_pointer = spd;

    /* SPD ENTRY NUMBER 1 */
    ipv6_addr_from_str(&spd_pointer->dst, "::1");
    ipv6_addr_from_str(&spd_pointer->src, "::1");
    spd_pointer->nh = 255;
    spd_pointer->dst_port = 0;    
    spd_pointer->src_port = 0;

    spd_pointer->rule = GNRC_IPSEC_BYPASS; 
    spd_pointer->tun_mode = GNRC_IPSEC_TRANSPORT;
    spd_pointer->encr_cypher = IPSEC_CYPHER_NONE;

    spd_pointer->auth_cypher = IPSEC_CYPHER_NONE;
    spd_pointer->comb_cypher = IPSEC_CYPHER_NONE;
    spd_pointer->tunnel_src = ipv6_addr_unspecified;

    spd_pointer->tunnel_dst = ipv6_addr_unspecified;
    spd_pointer->dst_range = ipv6_addr_unspecified;
    spd_pointer->src_range = ipv6_addr_unspecified;
    spd_pointer->dst_port_range = 0;
    spd_pointer->src_port_range = 0;
    

    /* SPD ENTRY NUMBER 2 */
    spd_pointer = spd_pointer + sizeof(ipsec_sp_t);    
    ipv6_addr_from_str(&spd_pointer->dst, "fe80::1c32:e6ff:fea2:27e9");
    ipv6_addr_from_str(&spd_pointer->src, "::1");
    spd_pointer->nh = 50;
    spd_pointer->dst_port = 666;    
    spd_pointer->src_port = 666;

    spd_pointer->rule = GNRC_IPSEC_PROTECT; 
    spd_pointer->tun_mode = GNRC_IPSEC_TRANSPORT;
    spd_pointer->encr_cypher = IPSEC_CYPHER_SHA;

    spd_pointer->auth_cypher = IPSEC_CYPHER_NONE;
    spd_pointer->comb_cypher = IPSEC_CYPHER_NONE;
    spd_pointer->tunnel_src = ipv6_addr_unspecified;

    spd_pointer->tunnel_dst = ipv6_addr_unspecified;
    spd_pointer->dst_range = ipv6_addr_unspecified;
    spd_pointer->src_range = ipv6_addr_unspecified;
    spd_pointer->dst_port_range = 0;
    spd_pointer->src_port_range = 0;

    return size;
}

static void *_event_loop(void *args) {

    //TODO: create waiting for msg()
    //TODO: Howto wait for ipsec AND pfkey requests/responses?
    assert(_db_init());

    DEBUG("ipsec_keyeng: Thread initialized\n");

    while (1) {
        /* TODO: register timer, check databases for limits, 
         * handle socket api requests */
        thread_sleep();
    }

    (void)args;

    return NULL;
}