/*
 * Copyright (C) 2019 Maximilian Malkus <malkus@cip.ifi.lmu.de>
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#include <stdio.h>
#include "net/ipv6/addr.h"
#include "net/gnrc/netif/internal.h"
#include "net/gnrc/ipv6/ipsec/ipsec.h"
#include "net/gnrc/ipv6/ipsec/pfkeyv2.h"

#include "net/gnrc/ipv6/ipsec/keyengine.h"

#define ENABLE_DEBUG    (0)
#include "debug.h"

#define COMBINED_DB_SIZE    (spd_size + spd_i_size + spd_o_size + sad_size)

/* Implemented databases work by FIFO principle (realloc) so the more
 * generalized entries should go into to db later than others. */

ipsec_sp_t *spd;
ipsec_sp_cache_t *spd_i;
ipsec_sp_cache_t *spd_o;
ipsec_sa_t *sad;
size_t spd_size;    //size in byte
size_t spd_i_size;  //etc
size_t spd_o_size;  
size_t sad_size;

static kernel_pid_t _pid = KERNEL_PID_UNDEF;

#if ENABLE_DEBUG
static char _stack[GNRC_IPSEC_KEYENGINE_STACK_SIZE + THREAD_EXTRA_STACKSIZE_PRINTF];
#else
static char _stack[GNRC_IPSEC_KEYENGINE_STACK_SIZE];
#endif

/* Main event loop for keyengine */
static void *_event_loop(void*);
int _return_spd_conf(ipsec_sp_t*);

/**
 * @brief: fills the sp chache entry. 
 * 
 * param[in] ipsec_sa_t NULL for unprotected traffic. For protected Tx traffic
 *              SA aquisition/generation is triggered.
 * param[in] ipsec_sa_t For protected Rx traffic sa must be handed
 * param[out] ipsec_sp_cache_t is filled by procedure
 * 
 */
int _fill_sp_cache_entry(ipsec_sp_cache_t*, ipsec_sp_t*, ipsec_ts_t*, 
                            TrafficMode_t, ipsec_sa_t*);

kernel_pid_t ipsec_keyengine_init(void) {
    if (_pid > KERNEL_PID_UNDEF) {
        return _pid;
    }

    _pid = thread_create(_stack, sizeof(_stack), GNRC_IPSEC_KEYENGINE_PRIO,
                         THREAD_CREATE_STACKTEST, _event_loop, NULL, "keyengine");

    return _pid;
}

void _ipsec_parse_spd(void) {
    /* TODO: WIP solution for hardcoded SPD ruleset. Should be replace by
     * dynamic parsing from e.g. an xml or equivalent source.
     * Since the SPD only gets checked if caches return no result, PROTECTED
     * entries to this table aren't required since they will be created when
     * injecting by dbfrm. When start to have real dynamic keying, we
     * need to add those entries here too and IKEv2 has to takecare of missing 
     * SA entries if needed*/
    ipsec_sp_t *spd_pointer;
    spd_size = 3 * sizeof(ipsec_sp_t);
    spd = malloc(spd_size);
    spd_pointer = spd;

/* HARDCODED SP rule set. blocking everything, but loopback and ICMP */

/* SPD ENTRY NUMBER 1: loopback traffic */
    ipv6_addr_from_str(&spd_pointer->dst, "::1");
    ipv6_addr_from_str(&spd_pointer->src, "::1");
    spd_pointer->pfp_flag = 1;
    spd_pointer->nh = 255;
    spd_pointer->dst_port = 0;    
    spd_pointer->src_port = 0;
    spd_pointer->rule = GNRC_IPSEC_F_BYPASS; 
    spd_pointer->tun_mode = GNRC_IPSEC_M_TRANSPORT;
    spd_pointer->c_mode = IPSEC_CIPHER_M_NONE;
    spd_pointer->tun_src = ipv6_addr_unspecified;
    spd_pointer->tun_dst = ipv6_addr_unspecified;
    spd_pointer->dst_range = ipv6_addr_unspecified;
    spd_pointer->src_range = ipv6_addr_unspecified;
    spd_pointer->dst_port_range = 0;
    spd_pointer->src_port_range = 0;

/* SPD ENTRY NUMBER 2: ICMP traffic */
    spd_pointer = (ipsec_sp_t*)( (uint8_t*)spd_pointer + sizeof(ipsec_sp_t) );    
    spd_pointer->dst = ipv6_addr_unspecified;
    spd_pointer->src = ipv6_addr_unspecified;
    spd_pointer->pfp_flag = 1;
    spd_pointer->nh = 58;
    spd_pointer->dst_port = 0;    
    spd_pointer->src_port = 0;
    spd_pointer->rule = GNRC_IPSEC_F_BYPASS; 
    spd_pointer->tun_mode = GNRC_IPSEC_M_TRANSPORT;
    spd_pointer->c_mode = IPSEC_CIPHER_M_NONE;
    spd_pointer->tun_src = ipv6_addr_unspecified;
    spd_pointer->tun_dst = ipv6_addr_unspecified;
    spd_pointer->dst_range = ipv6_addr_unspecified;
    spd_pointer->src_range = ipv6_addr_unspecified;
    spd_pointer->dst_port_range = 0;
    spd_pointer->src_port_range = 0;

 /* SPD ENTRY NUMBER 3: all other traffic */
    /* entry should use a range, but range detection is not implemented */
    spd_pointer = (ipsec_sp_t*)( (uint8_t*)spd_pointer + sizeof(ipsec_sp_t) );    
    spd_pointer->dst = ipv6_addr_unspecified;
    spd_pointer->src = ipv6_addr_unspecified;
    spd_pointer->pfp_flag = 1;
    spd_pointer->nh = 255;
    spd_pointer->dst_port = 0;    
    spd_pointer->src_port = 0;
    spd_pointer->rule = GNRC_IPSEC_F_DISCARD; 
    spd_pointer->tun_mode = GNRC_IPSEC_M_TRANSPORT;
    spd_pointer->c_mode = IPSEC_CIPHER_M_NONE;
    spd_pointer->tun_src = ipv6_addr_unspecified;
    spd_pointer->tun_dst = ipv6_addr_unspecified;
    spd_pointer->dst_range = ipv6_addr_unspecified;
    spd_pointer->src_range = ipv6_addr_unspecified;
    spd_pointer->dst_port_range = 0;
    spd_pointer->src_port_range = 0;

    return;
}

int _db_init(void) {
    spd_size = 0;
    spd_i_size = 0;
    spd_o_size = 0;
    sad_size = 0;
    
    _ipsec_parse_spd();
    if(spd == NULL) {
        DEBUG("ipsec_keyeng: ERROR parsing spd info into memory\n");
        return -1;
    }
    DEBUG("ipsec_keyeng: databases initialized\n"
            "spd_size = %i, c = %i\n", (int)spd_size, (int)(spd_size/sizeof(ipsec_sp_t)));

    return 1;
}

ipsec_sa_t* _add_sa_entry(ipsec_sa_t *sa) {
    if(ipsec_get_sa_by_spi(sa->spi) != NULL) {
        DEBUG("ipsec_keyeng: ERROR: spi allready in use\n");
        return NULL;
    }
    // TODO: check if id is unique
    size_t newsize;
    
    DEBUG("ipsec_keyeng: adding SA entry\n");
    newsize = (sad_size + sizeof(ipsec_sa_t));    
    if(newsize > MAX_IPSEC_DB_MEMORY && newsize > MAX_SADB_SIZE) {
        DEBUG("ipsec_keyeng: ERROR: Limits reached\n");
        return NULL;
    }
    if(sad_size == 0) {     /* is first entry */
        DEBUG("ipsec_keyeng: malloc newsize:%i\n", (int)newsize);
        sad = malloc(newsize);
    } else {
        DEBUG("ipsec_keyeng: realloc newsize:%i\n", (int)newsize);
        sad = realloc(sad, newsize);
    }    
    if(sad != NULL){
        memcpy(((uint8_t*)(sad) + sad_size), sa, sizeof(ipsec_sa_t));
        sad_size = newsize;
    } else {
        DEBUG("ipsec_keyeng: ERROR: HEAP space exhausted\n");
        // should throw error or terminate execution
        return NULL;
    }

    return (ipsec_sa_t*)((uint8_t*)(sad) + sad_size 
                                    - sizeof(ipsec_sa_t));

}

ipsec_sp_cache_t* _add_sp_cache_entry(ipsec_sp_cache_t *sp, 
                            TrafficMode_t traffic_mode) {
    ipsec_sp_cache_t **db;
    size_t *db_s;
    size_t max_db_s;
    size_t newsize;

    
    switch(traffic_mode) {
        case GNRC_IPSEC_RCV:
            db = &spd_i;
            db_s = &spd_i_size;
            max_db_s = MAX_SPD_I_CACHE_SIZE;
            DEBUG("ipsec_keyeng: adding SPD-I entry\n");
            break;
        case GNRC_IPSEC_SND:
            db = &spd_o;
            db_s = &spd_o_size;
            max_db_s = MAX_SPD_O_CACHE_SIZE;
            DEBUG("ipsec_keyeng: adding SPD-O entry\n");
            break;                
    }
    
    newsize = (*db_s + sizeof(ipsec_sp_cache_t));    
    if(newsize > MAX_IPSEC_DB_MEMORY && newsize > max_db_s) {
        DEBUG("ipsec_keyeng: ERROR: Limits reached\n");
        /* TODO: intended behaviour for now is to keep the db state and reject
         * new entries. Generally we can assume that the important connections
         * are established early in the devices lifetime. Still a configuration
         * flag for the behaviour would be nice. An interesting idea, would be
         * to only keep sp entries with negotiated SA's and BYPASS entries. */
        return NULL;
    }
    if(*db_s == 0) {         /* is first entry */
        DEBUG("ipsec_keyeng: malloc newsize:%i\n", (int)newsize);
        *db = malloc(newsize);
    } else {
        DEBUG("ipsec_keyeng: realloc newsize:%i\n", (int)newsize);
        *db = realloc(*db, newsize);
    }    
    if(*db != NULL){
        memcpy(((uint8_t*)(*db) + *db_s), sp, sizeof(ipsec_sp_cache_t));
        *db_s = newsize;
    } else {
        DEBUG("ipsec_keyeng: ERROR: HEAP space exhausted\n");
        // should throw error or terminate execution
        return NULL;
    }

    return (ipsec_sp_cache_t*)((uint8_t*)(*db) + *db_s 
                                    - sizeof(ipsec_sp_cache_t));                                    

}

const ipsec_sp_cache_t *_generate_sp_from_spd(TrafficMode_t traffic_mode, 
                                                ipsec_ts_t* ts) {

    ipsec_sp_t *spd_rule;
    ipsec_sp_t *spd_result = NULL;
    ipsec_sp_cache_t *return_handle = NULL;                      
    ipsec_sp_cache_t *sp_entry = NULL;

    for(int i=0; i < (int)(spd_size/sizeof(ipsec_sp_cache_t)); i++) {
        spd_rule = (ipsec_sp_t*)( (uint8_t*)spd + (i * sizeof(ipsec_sp_t)) );
        /* TODO: handle and accept ranges and subnets from spd entries. One
         * could also think about bending the RFC rules and not create an 
         * chache entry for every bypadd or discard rule bu to stick to
         * ranges on these, thus limiting memory usage*/
        if(!( ipv6_addr_equal(&spd_rule->dst, &ipv6_addr_unspecified)
                        || ipv6_addr_equal(&spd_rule->dst, &ts->dst) )){
            continue;
        }
        if(!( ipv6_addr_equal(&spd_rule->src, &ipv6_addr_unspecified)
                        || ipv6_addr_equal(&spd_rule->src, &ts->src) )){
            continue;
        }
        if(!( spd_rule->nh == 255 || spd_rule->nh == ts->prot )){
            continue;
        }
        if(!( spd_rule->dst_port == 0 || spd_rule->dst_port == ts->dst_port )){
            continue;
        }
        if(!( spd_rule->src_port == 0 || spd_rule->src_port == ts->src_port )){
            continue;
        }
        spd_result = spd_rule;
        break;
    }
    if(spd_result == NULL) {
        DEBUG("ipsec_keyeng: ERROR: No SPD match for pkt . Ruleset faulty?\n");
        return NULL;
    }

    if(spd_rule->rule == GNRC_IPSEC_F_PROTECT) {
        if(traffic_mode == GNRC_IPSEC_RCV) {
            DEBUG("ipsec_keyeng: ERROR: Rx packet for uninitialized ESP connection\n");
            return NULL;
        }
    }
    sp_entry  = malloc(sizeof(ipsec_sp_cache_t));
    if(sp_entry == NULL){        
        DEBUG("ipsec_keyeng: malloc failed\n");
        return NULL;
    }/* Call also generates SA for Tx traffic if needed */
    _fill_sp_cache_entry(sp_entry, spd_result, ts, traffic_mode, NULL);
    return_handle = _add_sp_cache_entry(sp_entry, traffic_mode);
    free(sp_entry);

    if(return_handle == NULL) {
        DEBUG("ipsec_keyeng: Cache entry could not be generated from spd rule\n");
        return NULL;
    }

    return return_handle;    
}

int _fill_sp_cache_entry(ipsec_sp_cache_t *sp_entry, ipsec_sp_t *spd_rule, 
                            ipsec_ts_t* ts, TrafficMode_t mode,
                            ipsec_sa_t* sa) {
    /* TODO: aknowledge pfflag and act accordingly. For now all entries are
    filled mainly from the packets ts information */
    sp_entry->dst = ts->dst;
    sp_entry->src = ts->src;
    sp_entry->nh = ts->prot;
    if(ts->dst_port == -1) {
        sp_entry->dst_port = 0;
    } else {
        sp_entry->dst_port = ts->dst_port;
    }
    if(ts->src_port == -1) {
        sp_entry->src_port = 0;
    } else {
        sp_entry->src_port = ts->src_port;
    }
    sp_entry->rule = spd_rule->rule;
    sp_entry->tun_mode = spd_rule->tun_mode;
    sp_entry->c_mode = spd_rule->c_mode;
    sp_entry->tun_src = spd_rule->tun_src;
    sp_entry->tun_dst = spd_rule->tun_dst;

    if(spd_rule->rule == GNRC_IPSEC_F_PROTECT) {
        if(mode == GNRC_IPSEC_SND){
            /**TODO: SA generation if traffic mode is SND
             * 
             * _request_sa_negotiation(ts);
             * 
             * If multiple SPs should share a SA, like for example in a 
             * PROTECTED multicast group or if protecting multiple protocols
             * with one SA, aquisition of existing SA should be triggered.
             */
        } else {
            if(sa != NULL) {
                sp_entry->sa = sa->spi;
            } else {
                DEBUG("ipsec_keyeng: sp generation: No SA given for PROTECTED Rx entry\n");
                return -1;
            }
        }       
    } else {
        sp_entry->sa = 0;
    }

    return 1;
}

const ipsec_sp_cache_t *ipsec_get_sp_entry(TrafficMode_t traffic_mode,
                            ipsec_ts_t* ts) {
    ipsec_sp_cache_t *db;
    size_t db_s;
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

    if(spd_size == 0) {
        DEBUG("ipsec_keyeng: ERROR SPD empty or uninitalized\n");
        return NULL;
    }

    const ipsec_sp_cache_t *sp_entry;
    for(int i=0; i < (int)(db_s/sizeof(ipsec_sp_cache_t)); i++) {
        sp_entry = (ipsec_sp_cache_t*)( (uint8_t*)db + (i * sizeof(ipsec_sp_cache_t)) );
        if( ! (ipv6_addr_equal(&sp_entry->dst, &ipv6_addr_unspecified) 
                            || ipv6_addr_equal(&sp_entry->dst, &ts->dst))){
            continue;
        }
        if( ! (ipv6_addr_equal(&sp_entry->src, &ipv6_addr_unspecified) 
                            || ipv6_addr_equal(&sp_entry->src, &ts->src))){
            continue;
        }
        if(sp_entry->nh != 255 && sp_entry->nh != ts->prot ){
            continue;
        }
        if(sp_entry->dst_port != 0 && sp_entry->dst_port != ts->dst_port){
            continue;
        }
        if(sp_entry->src_port != 0 && sp_entry->dst_port != ts->src_port){
            continue;
        }
        return sp_entry;
    }

    DEBUG("ipsec_keyeng: No cache entries matched traffic slectors. Checking SPD\n");
   
    sp_entry = _generate_sp_from_spd(traffic_mode, ts);
    if(sp_entry == NULL) {
        if(traffic_mode == GNRC_IPSEC_SND) {
            DEBUG("ipsec_keyeng: ERROR: Tx SP entry generation failed\n");
        } else {
            DEBUG("ipsec_keyeng: ERROR: Rx SP entry generation failed\n");
        }
        return NULL;
    }

    return sp_entry;
}

ipsec_sa_t *_unsecure_ipsec_get_sa_by_spi(uint32_t spi) {
    ipsec_sa_t* sa_entry;
    for(int i = 0; i < (int)(sad_size/sizeof(ipsec_sa_t)); i++) {
        sa_entry = (ipsec_sa_t*)( (uint8_t*)sad + ( i * sizeof(ipsec_sa_t)) );
        if(sa_entry->spi == spi) {
            return sa_entry;
        }
    }
    return NULL;
}

const ipsec_sa_t *ipsec_get_sa_by_spi(uint32_t spi) {
    return (const ipsec_sa_t*)_unsecure_ipsec_get_sa_by_spi(spi);
}

int ipsec_inject_db_entries(ipsec_sp_cache_t* sp, ipsec_sa_t* sa) { 
    TrafficMode_t traffic_mode;
    
    if(sp->rule == GNRC_IPSEC_F_PROTECT) {
        if(!_add_sa_entry(sa)) {
            DEBUG("ipsec_keyeng: injected sa entry could not be created\n");
        return 0;
        }
    }
    /* Determine traffic mode for SP entry */  
    if(gnrc_netif_get_by_ipv6_addr(&sp->src) == NULL) {
        if(gnrc_netif_get_by_ipv6_addr(&sp->dst) == NULL) {
            /* Traffic is routing traffic. Create SPD-O entry */
            traffic_mode = GNRC_IPSEC_SND;
        } else {
            //Traffic is Rx. Crerate SPD-I
            traffic_mode = GNRC_IPSEC_RCV;
        }
    } else {
        //Traffic is loopback or Tx. Create SPD-O entry
        traffic_mode = GNRC_IPSEC_SND;
    }

    if(!_add_sp_cache_entry(sp, traffic_mode)) {
        DEBUG("ipsec_keyeng: sp chache entry could not be created manually\n");
        return 0;
    }

    return 1;
}

int ipsec_increment_sn(uint32_t spi){
    ipsec_sa_t *sa = _unsecure_ipsec_get_sa_by_spi(spi);
    if(sa->sn + 1 < UINT64_MAX || sa->sn_of){
        sa->sn += 1;
        return 1;
    }
    return -1;    
}

/* TODO: The following are fragments of a possible pfkey communication.
 * Implementation of it could be beneficial but also very big. All code that
 * folows can be omitted if pfkey is decided against.
 * 
 * On PFKEY:
 * The procesing of the messages is very simplified here message 
 * queue and paket handling will be needed to make this compatible to 
 * the reference implementation. Maybe one could copy a fleshed out version 
 * from for example the openbsd kernel. */
static int _msg_add(pfkey_sadb_msg_t *sadb_msg){
    pfkey_sadb_sa_t *sa_ext;
    pfkey_sadb_ext_t *next_ext;
    if(sizeof(pfkey_sadb_msg_t) < sadb_msg->sadb_msg_len) {
        next_ext = (pfkey_sadb_ext_t*)( (uint8_t*)sadb_msg + sizeof(pfkey_sadb_msg_t) );
        if(next_ext->sadb_ext_type == SADB_EXT_SA) {
            sa_ext = (pfkey_sadb_sa_t*)next_ext;
            // TODO: _create_sa(sa_ext);
            (void)sa_ext;
        }
    }
    return 1;
}

static int _msg_update(pfkey_sadb_msg_t *sadb_msg){
    (void)sadb_msg;
    return -1;
}

static int _msg_get(pfkey_sadb_msg_t *sadb_msg, msg_t *reply_msg){
    (void)sadb_msg;
    (void)reply_msg;
    return -1;
}

static int _msg_dump(pfkey_sadb_msg_t *sadb_msg, msg_t *reply_msg){
    (void)sadb_msg;
    (void)reply_msg;
    return -1;
}

static void *_event_loop(void *args) {

    /* TODO: register timers with SADB_EXPIRE pf_key messages to the 
     * operation system */
    msg_t msg, reply;

    assert(_db_init());

    DEBUG("ipsec_keyeng: Thread initialized\n");

    /* This is a very simplified and non standart implementation of pf_key 
     * messaging.
     * For a propper implementation a message pool is essential, thus we 
     * are just following the basic priciples. The reply shemes
     * are not according to standart. Refer to RFC2367 section 3.1 for
     * correct messaging behaviour. */
    while (1) {
        msg_receive(&msg);
        switch (msg.type) {
            case SADB_ADD:
                _msg_add(msg.content.ptr);
                break;
            case SADB_UPDATE:
                _msg_update(msg.content.ptr);
                break;
            case SADB_GET:
                if(_msg_get(msg.content.ptr, &reply)) {
                    msg_reply(&msg, &reply);
                }
                break;
            case SADB_DUMP:
                if(_msg_dump(msg.content.ptr, &reply)) {
                    msg_reply(&msg, &reply);
                }   
                break;
            default:
                DEBUG("ipsec_keyeng: msg type unsuported %i: ", msg.type);
                break;
        }
    }
    (void)args;
    return NULL;
}