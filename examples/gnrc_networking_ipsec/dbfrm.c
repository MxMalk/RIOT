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
        "{} fields can be NULL'ed when no SA is needed\n"
        "Input string: action {id}  {spi}  dst  src  proto  port_dst "
        "port_src {mode}\n"
        "\t{c_mode} {auth} {hash_key} {enc} {enc_key} {iv} {t_src} {t_dst}\n\n"
        "action:\t\tprotect, bypass, discard\n"
        "id:\t\tunique sa id (uint16)\n"
        "spi:\t\tuint32\n"
        "dst:\t\tipv6 address\n"
        "src:\t\tipv6 address\n"
        "proto:\t\tIP protnum or 'any'\n"
        "port_dst:\tport/socket (uint16) or NULL\n"
        "port_src:\tport/socket (uint16) or NULL\n"
        "mode:\t\t'transport', 'tunnel'\n"
        "c_mode:\t\t'auth', 'authenc', 'comb'\n"
        "auth:\t\t'none', 'sha'\n"
        "hash_key:\tKey in lower case hex or '0'\n"
        "enc:\t\t'none', 'aes', 'chacha', 'mockup'\n"
        "enc_key:\tKey in lower case hex or '0'\n"
        "iv:\tIV in lower case hex or '0'\n"
        "t_src:\t\tipv6 address or NULL\n"
        "t_dst:\t\tipv6 address or NULL\n");
}

int _str_to_uint32(const char *str, uint32_t *res) {
    char *end;
    
    unsigned long val = strtoul(str, &end, 10);
    if (end == str || *end != '\0') {
        return 0;
    }
    *res = (uint32_t)val;
    return 1;
}

int _str_to_uint16(const char *str, uint16_t *res) {
    char *end;
    long val = strtol(str, &end, 10);
    if (end == str || *end != '\0' || val < 0 || val >= (long)UINT16_MAX) {
        return 0;
    }
    *res = (uint16_t)val;
    return 1;
}

int _str_to_uint8(const char *str, uint8_t *res) {
    char *end;
    long val = strtol(str, &end, 10);
    if (end == str || *end != '\0' || val < 0 || val >= (long)UINT8_MAX) {
        return 0;
    }
    *res = (uint8_t)val;
    return 1;
}

int _hex_to_uint8(const char *str, uint8_t *res) {
    char *end;
    long val = strtol(str, &end, 16);
    if (end == str || *end != '\0' || val < 0 || val >= (long)UINT8_MAX) {
        return 0;
    }
    *res = (uint8_t)val;
    return 1;
}

/* hex to bytedata conversion */
int _hex_str_to_key(const char *str, uint8_t *key, size_t keylen) {
    if(strcmp(str, "0") == 0) {
        memset(key, 0, keylen);
        return 1;
    }
    /* 1 byte == 2 hex chars */
    if( ! (strlen(str) <= keylen*2) && (strlen(str) % 2 == 0) ) {
        printf("dbfrm: ERROR: errornous string length\n");
        return 0;
    }
    /* check if string is valid hex */
    for(int i = 0; i < (int)strlen(str); i++) {
        char c = str[i];
        if(!( ((c > 47)&&(c < 58)) || 
                ((c > 96)&&(c < 103)) || 
                ((c > 64)&&(c < 71))  )) {
            printf("dbfrm: ERROR: Malformed hex string\n");
            return 0;
        }
    }
    char* tmp_str;
    size_t empyt_bytes = (int)(keylen*2 - strlen(str));
    memset(key, 0, empyt_bytes);
    for(size_t i = empyt_bytes; i < keylen; i++) {        
        tmp_str = strncpy(tmp_str, str + i*2, 2);
        _hex_to_uint8(tmp_str, &key[i]);
    }
    return 1;
}

/* ATM we do not handle combined cypher in this helper and we pass sa and spd 
 * information in the same call. For better usebility, splitting rule creation
 * and sa installation would be a good choice. For full compliance 
 * refer to RFC4301 section 4.4.1.1. */
static int _install_sa_hard(char *action, char *id, char *spi, char *dst, 
        char *src, char *proto,
        char *port_dst, char *port_src, char *mode, char *c_mode, char *auth, 
        char *hash_key, char *enc, char *enc_key, char *iv, char *t_src, 
        char *t_dst, ipsec_sp_cache_t *sp, ipsec_sa_t *sa) {    

    if(strcmp(action, "protect") == 0) {

        /* Fill SA */
        /* everything not addressed was set zero by calloc */
        if(strcmp("auth", c_mode) == 0) {
            sa->c_mode = IPSEC_CIPHER_M_AUTH_ONLY;
            sp->c_mode = IPSEC_CIPHER_M_AUTH_ONLY;
        } else if (strcmp("authenc", c_mode) == 0) {
            sa->c_mode = IPSEC_CIPHER_M_ENC_N_AUTH;
            sp->c_mode = IPSEC_CIPHER_M_ENC_N_AUTH;
        } else if (strcmp("comb", c_mode) == 0) {            
            sa->c_mode = IPSEC_CIPHER_M_COMB;          
            sp->c_mode = IPSEC_CIPHER_M_COMB;
        } else {
            printf("dbfrm: unsupported crypto mode\n");
            return 0;
        }

        if(strcmp("sha", auth) == 0) {
            sa->crypt_info.hash = IPSEC_HASH_SHA2_512_256;
        } else if (strcmp("none", auth) == 0) {
            sa->crypt_info.hash = IPSEC_HASH_NONE;
        } else {
            printf("dbfrm: unsupported auth mode\n");
            return 0;
        }

        if(strcmp("chacha", enc) == 0) {
            sa->crypt_info.cipher = IPSEC_CIPHER_CHACHA_POLY;
        } else if (strcmp("aes", enc) == 0) {
            sa->crypt_info.cipher = IPSEC_CIPHER_AES_CTR;
        } else if (strcmp("mockup", enc) == 0) {
            sa->crypt_info.cipher = IPSEC_CIPHER_MOCK;
        } else if (strcmp("none", enc) == 0) {
            sa->crypt_info.cipher = IPSEC_CIPHER_NONE;
        } else {
            printf("dbfrm: unsupported cipher\n");
            return 0;
        }

        if( ! ( _str_to_uint16(id, &sa->id) && 
            _str_to_uint32(spi, &sa->spi) ) ) {
                printf("dbfrm: integer parsing unsuccessful\n");
                return 0;
        }

        /* We copy everything any way to ease error handling. No sanity checks
         * on keys are performed. Individual crypto methods would have to check
         * if the keys fit their needs. */
        if( ! ( _hex_str_to_key(iv, sa->crypt_info.iv, IPSEC_MAX_IV_SIZE) &&
            _hex_str_to_key(enc_key, sa->crypt_info.key, IPSEC_MAX_KEY_SIZE) &&
            _hex_str_to_key(hash_key, sa->crypt_info.hash_key, IPSEC_MAX_HASH_SIZE) ) ) {
                printf("dbfrm: hex parsing unsuccessful\n");
                return 0;
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
            return 0;
        }
        if(sa->mode == GNRC_IPSEC_M_TUNNEL){
            if((ipv6_addr_from_str(&sa->tunnel_dst, t_src) == NULL) ||
                (ipv6_addr_from_str(&sa->tunnel_src, t_dst) == NULL) ) {
                    printf("dbfrm: Tunnel address parsing unsuccessful\n");
                    return 0;
            }
        } else {
            sa->tunnel_dst = ipv6_addr_unspecified;
            sa->tunnel_src = ipv6_addr_unspecified;
        }
        /* finally link sa to spd by spi */
        sp->sa = sa->spi;
    } else {
        sp->c_mode = IPSEC_CIPHER_M_NONE;
    }
    

    /* Fill SP */
    /* everything not addressed was set zero by calloc */
    if((ipv6_addr_from_str(&sp->dst, dst) == NULL) ||
        (ipv6_addr_from_str(&sp->src, src) == NULL) ) {
            printf("dbfrm: SP IPv6 parsing unsuccessful\n");
            return -1;
    }
    if(strcmp(proto, "any") == 0) {
        sp->nh = 255;
    } else {
        if( !_str_to_uint8(proto, &sp->nh)) {
            printf("dbfrm: SP proto parsing unsuccessful\n");
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
        return 0;
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

    if( ! ipsec_inject_db_entries(sp, sa)) {
        return 0;
    }
    return 1;
}

int ipsec_sad_frm(int argc, char **argv) {

    ipsec_sa_t *sa = NULL;
    ipsec_sp_cache_t *sp = NULL; 

    if(argc<2) {
        _print_help();
        return 0;
    }

    if(argc==18) {

        sp = calloc(1, sizeof(ipsec_sp_t));
        sa = calloc(1, sizeof(ipsec_sa_t));
        
        /* Some sanity checks on the input are needed*/
        int result = _install_sa_hard(argv[1],argv[2],argv[3],argv[4],argv[5],
            argv[6],argv[7],argv[8],argv[9], argv[10], argv[11], argv[12], 
            argv[13], argv[14], argv[15], argv[16], argv[17], sp, sa);
        if(!result) {
            printf("dbfrm: No changes could be made. ERR_NR: %i\n", result);
        } else {
            printf("dbfrm: spi: %s was added/changed successfully.\n", argv[3]);
        }
        /* entries get copied into new form by the keyengine. That way we can
         * change the IPsec database representation more indipendently for 
         * future development*/
        free(sa);
        free(sp);
    } else {
        printf("dbfrm: wrong number of aguments. argc = %i\n", argc);
    }

    return 0;
}
