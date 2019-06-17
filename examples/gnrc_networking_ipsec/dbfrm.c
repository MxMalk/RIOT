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
//#include "net/gnrc/ipv6/ipsec/pfkeyv2.h"
#include "net/gnrc/ipv6/ipsec/keyengine.h"

static void _print_help(void) {
    /*TODO*/
    printf("dbfrm: helper text\n");
}

bool _str_to_uint32(const char *str, uint32_t *res) {
    char *end;
    int errno = 0;
    long val = strtol(str, &end, 10);
    if (errno || end == str || *end != '\0' || val < 0 || val >= UINT32_MAX) {
        return false;
    }
    *res = (uint32_t)val;
    return true;
}

bool _str_to_uint16(const char *str, uint16_t *res) {
    char *end;
    int errno = 0;
    long val = strtol(str, &end, 10);
    if (errno || end == str || *end != '\0' || val < 0 || val >= UINT16_MAX) {
        return false;
    }
    *res = (uint16_t)val;
    return true;
}

bool _str_to_uint8(const char *str, uint8_t *res) {
    char *end;
    int errno = 0;
    long val = strtol(str, &end, 10);
    if (errno || end == str || *end != '\0' || val < 0 || val >= UINT8_MAX) {
        return false;
    }
    *res = (uint8_t)val;
    return true;
}

bool _hex_to_uint8(const char *str, uint8_t *res) {
    char *end;
    int errno = 0;
    long val = strtol(str, &end, 16);
    if (errno || end == str || *end != '\0' || val < 0 || val >= UINT8_MAX) {
        return false;
    }
    *res = (uint8_t)val;
    return true;
}

/* little endian hex conversion */
bool _hex_str_to_ipsec_key(const char *str, ipsec_cypher_key_t *key) {
    /* 1 byte == 2 hex chars */
    assert(strlen(str) == IPSEC_MAX_KEY_SIZE*2);
    /* check if string is valid hex */
    for(int i = 0; i < strlen(str); i++) {
        char c = str[i];
        if(!( ((c > 47)&&(c < 58)) || 
                ((c > 96)&&(c < 103)) || 
                ((c > 64)&&(c < 71))  )) {
            printf("dbfrm: ERROR: Malformed hex string\n");
            return false;
        }
    }
    for(int i = 0; i < IPSEC_MAX_KEY_SIZE; i++) {        
        char* tmp_str;
        strncpy(tmp_str, str + i*2, 2);
        _hex_str_to_ipsec_key(tmp_str, key->key[i]);
    }
    return true;
}

/* ATM we do not handle combined cypher in this helper and we pass sa and spd 
 * information in the same call. For better usebility, splitting rule creation
 * and sa installation would be a good choice */
static int _install_sa_hard(char *action, char *id, char *spi, char *dst, 
        char *src, char *proto,
        char *port_dst, char *port_src, char *mode, char *auth, char *auth_key,
        char *enc, char *enc_key, char *t_src, char *t_dst, char *pmtu) {

    ipsec_sa_t *sa = NULL;
    ipsec_sp_cache_t *sp = NULL;        

    if(strcmp(action, "protect")) {
        /* Create SA */
        sa = calloc(1, sizeof(ipsec_sa_t));
        /* everything not addressed was set zero by calloc */
        if( ! ( _str_to_uint16(id, &sa->id) && 
            _str_to_uint32(spi, &sa->spi) &&
            _str_to_ipsec_key(enc_key, &sa->encr_key) &&
            _str_to_ipsec_key(auth_key, &sa->auth_key)&&
            _str_to_uint32(pmtu, sa->pmtu) ) ) {
                printf("dbfrm: SA parsing unsuccessful\n");
                free(sa);
                return -1;
        }
        sa->rp_u_bound = IPSEC_ANTI_R_WINDOW_SIZE - 1;
        sa->re_lt =     86400000; /* 24h */
        sa->re_bc =     15728540; /* 15MB */
        sa->max_lt =    87000000;
        sa->max_bc =    16000000;
        if(strcmp("trans", mode)) {
            sa->mode = GNRC_IPSEC_M_TRANSPORT;
        } else if (strcmp("tun", mode)) {
            sa->mode = GNRC_IPSEC_M_TUNNEL;
        } else {
            printf("dbfrm: SA mode parsing unsuccessful\n");
            free(sa);
            return -1;
        }    
        if((ipv6_addr_from_str(&sa->tunnel_dst, t_src) == NULL) ||
        (ipv6_addr_from_str(&sa->tunnel_src, t_dst) == NULL) ) {
            sa->tunnel_dst = ipv6_addr_unspecified;
            sa->tunnel_src = ipv6_addr_unspecified;
        }
    }
    

    /* Create SP */

    sp = calloc(1, sizeof(ipsec_sp_t));
    /* everything not addressed was set zero by calloc */
    if((ipv6_addr_from_str(&sp->dst, t_src) == NULL) ||
        (ipv6_addr_from_str(&sp->src, t_dst) == NULL) ) {
            printf("dbfrm: SP IPv6 parsing unsuccessful\n");
            free(sp);
            return -1;
    }    
    /* TODO: What about the next header aka. Protocoll filter?? */
    if( ! ( _str_to_uint8(proto, &sp->nh) &&
        _str_to_uint16(port_dst, &sp->dst_port) && 
        _str_to_uint16(port_src, &sp->src_port) ) )  {
            printf("dbfrm: SP parsing unsuccessful\n");
            free(sp);
            return -1;
    }
    if(strcmp("discard", action)) {
        sp->rule = GNRC_IPSEC_F_DISCARD;
    } else if (strcmp("bypass", action)) {
        sp->rule = GNRC_IPSEC_F_BYPASS;
    } else if (strcmp("protect", action)) {        
        sp->rule = GNRC_IPSEC_F_PROTECT;
    } else {
        printf("dbfrm: SP rule parsing unsuccessful\n");
        free(sp);
        return -1;
    }
    if( sp->rule == GNRC_IPSEC_F_PROTECT ) {
        if(strcmp("none", enc)) {
            sp->encr_cypher = IPSEC_CYPHER_NONE;
        } else if (strcmp("sha", enc)) {
            sp->encr_cypher = IPSEC_CYPHER_SHA;
        } else if (strcmp("chacha", enc)) {        
            sp->encr_cypher = IPSEC_CYPHER_CHACHA;
        } else {
            printf("dbfrm: SP parsing unsuccessful\n");
            free(sp);
            return -1;
        }
        if(strcmp("none", auth)) {
            sp->auth_cypher = IPSEC_CYPHER_NONE;
        } else if (strcmp("sha", auth)) {
            sp->auth_cypher = IPSEC_CYPHER_SHA;
        } else {
            printf("dbfrm: SP parsing unsuccessful\n");
            free(sp);
            return -1;
        }
    }
    if(strcmp("trans", mode)) {
        sp->tun_mode = GNRC_IPSEC_M_TRANSPORT;
    } else if (strcmp("tun", mode)) {
        sp->tun_mode = GNRC_IPSEC_M_TUNNEL;
    } else {
        printf("dbfrm: SP mode parsing unsuccessful\n");
        free(sp);
        return -1;
    }
    if(strcmp(action, "protect"))
    if((ipv6_addr_from_str(&sp->tunnel_dst, t_src) == NULL) ||
        (ipv6_addr_from_str(&sp->tunnel_src, t_dst) == NULL )) {
            sp->tunnel_dst = ipv6_addr_unspecified;
            sp->tunnel_src = ipv6_addr_unspecified;
    }
    sp->sa = &sa;

    //TODO: add sp, register in system    

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
            argv[13], argv[14], argv[15], argv[16]);
        if(result!=0) {
            printf("dbfrm: No changes could be made. ERR_NR:%i\n", result);
        } else {
            printf("dbfrm: spi:%s was changed successfully.\n", argv[1]);
        }
    }

    return 0;
}
