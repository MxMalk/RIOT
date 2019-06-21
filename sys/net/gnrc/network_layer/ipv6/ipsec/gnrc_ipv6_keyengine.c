/*
 * Copyright (C) 2019 Maximilian Malkus <malkus@cip.ifi.lmu.de>
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#include <stdio.h>
#include "net/ipv6/addr.h"
#include "net/gnrc/ipv6/ipsec/ipsec.h"
#include "net/gnrc/ipv6/ipsec/pfkeyv2.h"

#include "net/gnrc/ipv6/ipsec/keyengine.h"

#define ENABLE_DEBUG    (1)
#include "debug.h"

#define COMBINED_DB_SIZE    (spd_size + spd_i_size + spd_o_size + sad_size)

/* TODO: Implemented databases work by stack (FILO) principle */

ipsec_sp_t *spd;
ipsec_sp_cache_t *spd_i;
ipsec_sp_cache_t *spd_o;
ipsec_sa_t *sad;
size_t spd_size;
size_t spd_i_size;
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
int _fill_sp_cache_entry(ipsec_sp_cache_t*, ipsec_sp_t*, ipsec_ts_t);

kernel_pid_t gnrc_ipsec_keyengine_init(void) {
    if (_pid > KERNEL_PID_UNDEF) {
        return _pid;
    }

    _pid = thread_create(_stack, sizeof(_stack), GNRC_IPSEC_KEYENGINE_PRIO,
                         THREAD_CREATE_STACKTEST, _event_loop, NULL, "keyengine");

    return _pid;
}

void _ipsec_parse_spd(ipsec_sp_t *db) {
    /* TODO: Comment on how this is not final */
    /* TODO: WIP solution for hardcoded SPD ruleset. Since we do not check the SPD 
    * if there is a fitting chache entry, entries to this table aren't required
    * for manual key and spd_cache injection. At least rename it*/
    ipsec_sp_t *spd_pointer;
    spd_size = 2 * sizeof(ipsec_sp_t);
    spd = malloc(spd_size);
    spd_pointer = spd;

/* SPD ENTRY NUMBER 1 */
    ipv6_addr_from_str(&spd_pointer->dst, "::1");
    ipv6_addr_from_str(&spd_pointer->src, "::1");
    spd_pointer->nh = 255;
    spd_pointer->dst_port = 0;    
    spd_pointer->src_port = 0;

    spd_pointer->rule = GNRC_IPSEC_F_BYPASS; 
    spd_pointer->tun_mode = GNRC_IPSEC_M_TRANSPORT;
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

    spd_pointer->rule = GNRC_IPSEC_F_PROTECT; 
    spd_pointer->tun_mode = GNRC_IPSEC_M_TRANSPORT;
    spd_pointer->encr_cypher = IPSEC_CYPHER_SHA;

    spd_pointer->auth_cypher = IPSEC_CYPHER_NONE;
    spd_pointer->comb_cypher = IPSEC_CYPHER_NONE;
    spd_pointer->tunnel_src = ipv6_addr_unspecified;

    spd_pointer->tunnel_dst = ipv6_addr_unspecified;
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
    
    _ipsec_parse_spd(spd);
    if(spd == NULL) {
        DEBUG("ipsec_keyeng: ERROR parsing spd info into memory\n");
        return -1;
    }

    return 1;
}

ipsec_sp_cache_t* _add_sp_cache_entry(ipsec_sp_cache_t *sp, 
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

    size_t newsize = db_s + sizeof(ipsec_sp_cache_t);
    if(newsize > MAX_IPSEC_DB_MEMORY && newsize > max_db_s) {
        DEBUG("ipsec_keyeng: ERROR: Limits reached\n");
        return NULL;
    }
    db = realloc(db, newsize);
    if(db != NULL){
        memcpy(((uint8_t*)(db) + db_s), sp, sizeof(ipsec_sp_cache_t));
        db_s = newsize;
    } else {
        DEBUG("ipsec_keyeng: ERROR: HEAP space exhausted\n");
        return NULL;
    }

    return (ipsec_sp_cache_t*)((uint8_t*)(db) + db_s 
                                    - sizeof(ipsec_sp_cache_t));

}

ipsec_sa_t* _add_sa_entry(ipsec_sa_t *sa) {
    if(get_sa_by_spi(sa->spi) != NULL) {
        DEBUG("ipsec_keyeng: ERROR: spi allready in use\n");
        return NULL;
    }
    // TODO: check if id is unique

    size_t newsize = sad_size + sizeof(ipsec_sa_t);
    if(newsize > MAX_IPSEC_DB_MEMORY && newsize > MAX_SADB_SIZE) {
        DEBUG("ipsec_keyeng: ERROR: Limits reached\n");
        return NULL;
    }
    /* TODO: its bad that everything dies when the limits are reached
     * assure what real_realloc does and if we can avoid deletion of
     * spd if we do not redefine spd 
     * Also change for sp entry function is needed*/
    sad = realloc(sad, newsize);
    if(sad != NULL){
        memcpy(((uint8_t*)(sad) + sad_size), sa, sizeof(ipsec_sa_t));
        sad_size = newsize;
    } else {
        DEBUG("ipsec_keyeng: ERROR: HEAP space exhausted\n");
        return NULL;
    }

    return (ipsec_sa_t*)((uint8_t*)(sad) + sad_size - sizeof(ipsec_sa_t));
}

const ipsec_sp_cache_t *_generate_sp_from_spd(TrafficMode_t traffic_mode, 
                                                ipsec_ts_t ts) {

    ipsec_sp_t *spd_result = NULL;;
    ipsec_sp_t *spd_rule;
    ipsec_sp_cache_t *return_handle;                       
    ipsec_sp_cache_t *sp_entry = NULL;

    for(size_t i=0; i < spd_size; i = i + sizeof(ipsec_sp_t)) {
        spd_rule = (ipsec_sp_t*)((uint8_t*)spd + i);
        /* TODO: handle and accept ranges and subnets from spd entries*/
        if(!(ipv6_addr_equal(&spd_rule->dst, &ipv6_addr_unspecified)
                        || ipv6_addr_equal(&spd_rule->src, &ts.src))){
            break;
        }
        if(!(ipv6_addr_equal(&spd_rule->src, &ipv6_addr_unspecified)
                        || ipv6_addr_equal(&spd_rule->src, &ts.src))){
            break;
        }
        if(!(spd_rule->nh == 255 || spd_rule->nh == ts.prot)){
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

    if(spd_rule->rule == GNRC_IPSEC_F_PROTECT) {
        if(traffic_mode == GNRC_IPSEC_RCV) {
            DEBUG("ipsec_keyeng: ERROR: Rx packet for uninitialized ESP connection\n");
            return NULL;
        }
    }
    //TODO: sourround with mem error catch code
    sp_entry = malloc(sizeof(ipsec_sp_cache_t));
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

int _fill_sp_cache_entry(ipsec_sp_cache_t *sp_entry, ipsec_sp_t *spd_rule, 
                            ipsec_ts_t ts) {
    sp_entry->dst = ts.dst;
    sp_entry->src = ts.src;
    sp_entry->nh = ts.prot;
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

const ipsec_sp_cache_t *get_sp_entry(TrafficMode_t traffic_mode,
                            ipsec_ts_t ts) {    
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

    const ipsec_sp_cache_t *sp_entry;
    for(int i=0; i < db_s; i = i + sizeof(ipsec_sp_cache_t)) {
        sp_entry = (ipsec_sp_cache_t*)((uint8_t*)db + i);
        if( ! (ipv6_addr_equal(&sp_entry->dst, &ipv6_addr_unspecified) 
                            || ipv6_addr_equal(&sp_entry->dst, &ts.dst))){
            break;
        }
        if( ! (ipv6_addr_equal(&sp_entry->src, &ipv6_addr_unspecified) 
                            || ipv6_addr_equal(&sp_entry->src, &ts.src))){
            break;
        }
        if(sp_entry->nh != 255 && sp_entry->nh != ts.prot ){
            break;
        }
        if(sp_entry->dst_port != 0 && sp_entry->dst_port != ts.dst_port){
            break;
        }
        if(sp_entry->src_port != 0 && sp_entry->dst_port != ts.src_port){
            break;
        }
        return sp_entry;
    }

    /* No cache entries matched traffic slectors. Checking SPD rules */
   
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

const ipsec_sa_t *get_sa_by_spi(uint32_t spi) {
    sadb_sa_t* sa_entry;
    for(int i = 0; i < spd_size; i++) {
        sa_entry = (uint8_t*)spd + i * sizeof(sadb_sa_t);
        if(sa_entry->sadb_sa_spi == spi) {
            return sa_entry;
        }
    }
    return NULL;
}

int inject_db_entries(ipsec_sp_cache_t* sp, ipsec_sa_t* sa) { 
    TrafficMode_t traffic_mode;
    
    if(sp->rule == GNRC_IPSEC_F_PROTECT) {
        if(sa == NULL) {
            DEBUG("ipsec_keyeng: sa musn't be NULL on PROTECT rules\n");
            return -1;
        }

        // TODO: insert sa

    }

    /* Determine traffic mode for SP entry */  
    if(gnrc_netif_get_by_ipv6_addr(sp->src) == NULL) {
        if(gnrc_netif_get_by_ipv6_addr(sp->dst) == NULL) {
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
        DEBUG("ipsec_keyeng: sp chache entry could not be created\n");
        return 0;
    }

    return 1;
}

/* The procesing of the messages is very simplified here message queue and 
 * paket handling will be needed to make this compatible to the reference 
 * implementation. Maybe one could copy a fleshed out version from for example
 * the openbsd kernel. */
static int _msg_add(sadb_msg_t *sadb_msg){
    sadb_sa_t *sa_ext;
    sadb_ext_t *next_ext;
    if(sizeof(sadb_msg_t) < sadb_msg->sadb_msg_len) {
        next_ext = (uint8_t*)sadb_msg + sizeof(sadb_msg_t);
        if(next_ext->sadb_ext_type == SADB_EXT_SA) {
            sa_ext = next_ext;
            _create_sa(sa_ext);
        }
    }
    return 1;
}

static int _msg_update(sadb_msg_t *sadb_msg){
    (void)sadb_msg;
    return -1;
}

static int _msg_get(sadb_msg_t *sadb_msg, msg_t *reply_msg){
    (void)sadb_msg;
    (void)reply_msg;
    return -1;
}

static int _msg_dump(sadb_msg_t *sadb_msg, msg_t *reply_msg){
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

    /* This is avery simplified and non standart implementation of pf_key 
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

    (void)args;

    return NULL;
}