/*
 * Copyright (C) 2019 Maximilian Malkus <malkus@cip.ifi.lmu.de>
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @ingroup     examples
 * @{
 *
 * @file
 * @brief       IPsec database entry manual framework
 *
 * @author      Maximilian Malkus <malkus@cip.ifi.lmu.de>
 *
 * @}
 */


#include <stdio.h>
#include <assert.h>
#include "msg.h"
#include "net/gnrc/ipv6/ipsec/pfkeyv2.h"
#include "net/gnrc/ipv6/ipsec/keyengine.h"

static void _print_help(void) {
    printf("## dbfrm help:\n"
        "Unused optional fields must be NULL'ed\n"
        "{} fields can be NULL'ed when no SA is needed\n"
        "Input string: action  {id}  {spi}  dst  src  proto  [port_dst] "
        "[port_src] {mode}\n"
        "\t{auth} {auth_key} {enc} {enc_key} [t_src] [t_dst]\n\n"
        "action:\t\tprotect, bypass, discard\n"
        "id:\t\tunique sa id (uint16)\n"
        "spi:\t\tuint32\n"
        "dst:\t\tipv6 address\n"
        "src:\t\tipv6 address\n"
        "proto:\t\tIP protnum or 'any'\n"
        "port_dst:\tport/socket (uint16) or NULL\n"
        "port_src:\tport/socket (uint16) or NULL\n"
        "mode:\t\t'transport', 'tunnel'\n"
        "auth:\t\t'none', 'sha'\n"
        "auth_key:\t512bit key in lower case hex\n"
        "enc:\t\t'none', 'sha', 'chacha'\n"
        "enc_key:\t512bit key in lower case hex\n"
        "t_src:\t\tipv6 address or NULL\n"
        "t_dst:\t\tipv6 address or NULL\n");
}

bool _str_to_uint32(const char *str, uint32_t *res) {
    char *end;
    
    unsigned long val = strtoul(str, &end, 10);
    if (end == str || *end != '\0') {
        return false;
    }
    *res = (uint32_t)val;
    return true;
}

bool _str_to_uint16(const char *str, uint16_t *res) {
    char *end;
    long val = strtol(str, &end, 10);
    if (end == str || *end != '\0' || val < 0 || val >= (long)UINT16_MAX) {
        return false;
    }
    *res = (uint16_t)val;
    return true;
}

bool _str_to_uint8(const char *str, uint8_t *res) {
    char *end;
    long val = strtol(str, &end, 10);
    if (end == str || *end != '\0' || val < 0 || val >= (long)UINT8_MAX) {
        return false;
    }
    *res = (uint8_t)val;
    return true;
}

bool _hex_to_uint8(const char *str, uint8_t *res) {
    char *end;
    long val = strtol(str, &end, 16);
    if (end == str || *end != '\0' || val < 0 || val >= (long)UINT8_MAX) {
        return false;
    }
    *res = (uint8_t)val;
    return true;
}

/* little endian hex conversion */
bool _hex_str_to_ipsec_key(const char *str, ipsec_cypher_key_t *key) {
    /* 1 byte == 2 hex chars */
    assert( (strlen(str) <= IPSEC_MAX_KEY_SIZE*2) && (strlen(str) % 2 == 0) );
    /* check if string is valid hex */
    for(int i = 0; i < (int)strlen(str); i++) {
        char c = str[i];
        if(!( ((c > 47)&&(c < 58)) || 
                ((c > 96)&&(c < 103)) || 
                ((c > 64)&&(c < 71))  )) {
            printf("dbfrm: ERROR: Malformed hex string\n");
            return false;
        }
    }
    char* tmp_str;
    int empyt_bites = (int)IPSEC_MAX_KEY_SIZE*2 - (int)strlen(str);
    for(int i = 0; i < empyt_bites; i++) {
        tmp_str = "00";
        _hex_to_uint8(tmp_str, &key->key[i]);
    }
    for(int i = empyt_bites; i < (int)IPSEC_MAX_KEY_SIZE*2; i++) {        
        tmp_str = strncpy(tmp_str, str + i*2, 2);
        _hex_to_uint8(tmp_str, &key->key[i]);
    }
    return true;
}

/* ATM we do not handle combined cypher in this helper and we pass sa and spd 
 * information in the same call. For better usebility, splitting rule creation
 * and sa installation would be a good choice. For full compliance 
 * refer to RFC4301 section 4.4.1.1. */
static int _install_sa_hard(char *action, char *id, char *spi, char *dst, 
        char *src, char *proto,
        char *port_dst, char *port_src, char *mode, char *auth, char *auth_key,
        char *enc, char *enc_key, char *t_src, char *t_dst) {

    ipsec_sa_t *sa = NULL;
    ipsec_sp_cache_t *sp = NULL; 

    if(strcmp(action, "protect") == 0) {

        /* Create SA */
        sa = calloc(1, sizeof(ipsec_sa_t));
        /* everything not addressed was set zero by calloc */
        if( ! ( _str_to_uint16(id, &sa->id) && 
            _str_to_uint32(spi, &sa->spi) &&
            _hex_str_to_ipsec_key(enc_key, &sa->encr_key) &&
            _hex_str_to_ipsec_key(auth_key, &sa->auth_key) ) ) {
                printf("dbfrm: SA parsing unsuccessful\n");
                free(sa);
                return -1;
        }
        sa->rp_u_bound = IPSEC_ANTI_R_WINDOW_SIZE - 1;
        sa->re_lt =     86400000; /* 24h */
        sa->re_bc =     15728540; /* 15MB */
        sa->max_lt =    87000000;
        sa->max_bc =    16000000;
        sa->pmtu =      1500; /* Ethernet PMTU */
        if(strcmp("transport", mode) == 0) {
            sa->mode = GNRC_IPSEC_M_TRANSPORT;
        } else if (strcmp("tunnel", mode) == 0) {
            sa->mode = GNRC_IPSEC_M_TUNNEL;
        } else {
            printf("dbfrm: SA mode parsing unsuccessful\n");
            free(sa);
            return -1;
        }
        if(sa->mode == GNRC_IPSEC_M_TUNNEL){
            if((ipv6_addr_from_str(&sa->tunnel_dst, t_src) == NULL) ||
                (ipv6_addr_from_str(&sa->tunnel_src, t_dst) == NULL) ) {
                    printf("dbfrm: Tunnel address parsing unsuccessful\n");
                    free(sa);
                    return -1;
            }
        } else {
            sa->tunnel_dst = ipv6_addr_unspecified;
            sa->tunnel_src = ipv6_addr_unspecified;
        }
    }
    

    /* Create SP */

    sp = calloc(1, sizeof(ipsec_sp_t));
    /* everything not addressed was set zero by calloc */
    if((ipv6_addr_from_str(&sp->dst, dst) == NULL) ||
        (ipv6_addr_from_str(&sp->src, src) == NULL) ) {
            printf("dbfrm: SP IPv6 parsing unsuccessful\n");
            free(sp);
            return -1;
    }
    if(strcmp(proto, "any") == 0) {
        sp->nh = 255;
    } else {
        if( !_str_to_uint8(proto, &sp->nh)) {
            printf("dbfrm: SP proto parsing unsuccessful\n");
            free(sp);
            return -1;
        }
    }
    if( ! ( _str_to_uint16(port_dst, &sp->dst_port) && 
        _str_to_uint16(port_src, &sp->src_port) ) )  {
            printf("dbfrm: No valid ports given. Parsing NULL.\n");
            sp->src_port = 0;
            sp->dst_port = 0;
    }
    if(strcmp("discard", action) == 0) {
        sp->rule = GNRC_IPSEC_F_DISCARD;
    } else if (strcmp("bypass", action) == 0) {
        sp->rule = GNRC_IPSEC_F_BYPASS;
    } else if (strcmp("protect", action) == 0) {        
        sp->rule = GNRC_IPSEC_F_PROTECT;
    } else {
        printf("dbfrm: SP rule parsing unsuccessful\n");
        free(sp);
        return -1;
    }
    /* only for protected traffic */
    if( sp->rule == GNRC_IPSEC_F_PROTECT ) {
        if(strcmp("none", enc) == 0) {
            sp->encr_cypher = IPSEC_CYPHER_NONE;
        } else if (strcmp("sha", enc) == 0) {
            sp->encr_cypher = IPSEC_CYPHER_SHA;
        } else if (strcmp("chacha", enc) == 0) {        
            sp->encr_cypher = IPSEC_CYPHER_CHACHA;
        } else if (strcmp("mock", enc) == 0) {        
            sp->encr_cypher = IPSEC_CYPHER_MOCK;
        } else {
            printf("dbfrm: SP parsing unsuccessful\n");
            free(sp);
            return -1;
        }
        if(strcmp("none", auth) == 0) {
            sp->auth_cypher = IPSEC_CYPHER_NONE;
        } else if (strcmp("mock", auth) == 0) {
            sp->auth_cypher = IPSEC_CYPHER_MOCK;
        } else {
            printf("dbfrm: SP parsing unsuccessful\n");
            free(sp);
            return -1;
        }
        if(strcmp("transport", mode) == 0) {
            sp->tun_mode = GNRC_IPSEC_M_TRANSPORT;
            /* ports NULLed by calloc */
        } else if (strcmp("tunnel", mode) == 0) {
            sp->tun_mode = GNRC_IPSEC_M_TUNNEL;
            if((ipv6_addr_from_str(&sp->tunnel_dst, t_src) == NULL) ||
                (ipv6_addr_from_str(&sp->tunnel_src, t_dst) == NULL )) {
                    printf("dbfrm: Tunnel address faulty\n");
                    free(sp);
                    return -1;
                }
        } else {
            printf("dbfrm: SP mode parsing unsuccessful\n");
            free(sp);
            return -1;
        }
        if(sa != NULL) {
            sp->sa = sa->spi;
        }
        
    }

    /* instead of producing a very poor verison of the pf_key communication we
     * are taking a shortcut and insert the sp and sa directly into the
     * databases. Following code is kept for a pseudo reference on how a pf_key
     * call could be created and handled */

    /*     
    msg_t *msg, *rpl;
    sadb_msg_t *sadb_msg;
    uint16_t sadb_msg_length = sizeof(sadb_msg_t) + sizeof(sadb_sa_t) + keys, etc... );
    sadb_msg = malloc(sadb_msg_length);
    sadb_msg->sadb_msg_len = sadb_msg_length
        ...fill all fields
    msg = malloc(sizeof(msg_t));
    msg_send_receive(&msg, &rpl, ipsec_keyengine_init());
        ...process reply message
    free(msg);
    if(rpl != NULL) {
        free(rpl);
    } */


    /* sa may be NULL */
    if( ! ipsec_inject_db_entries(sp, sa)) {
        free(sp);
        free(sa);
        return -1;
    }
    free(sp);
    free(sa);
    return 1;
}

int ipsec_sad_frm(int argc, char **argv) {

    if(argc<2) {
        _print_help();
        return 0;
    }

    if(argc==16) {
        /* Some sanity checks on the input are needed*/
        int result = _install_sa_hard(argv[1],argv[2],argv[3],argv[4],argv[5],
            argv[6],argv[7],argv[8],argv[9], argv[10], argv[11], argv[12], 
            argv[13], argv[14], argv[15]);
        if(result < 1) {
            printf("dbfrm: No changes could be made. ERR_NR: %i\n", result);
        } else {
            printf("dbfrm: spi: %s was added/changed successfully.\n", argv[3]);
        }
    } else {
        printf("dbfrm: wrong number of aguments. argc = %i\n", argc);
    }

    return 0;
}
