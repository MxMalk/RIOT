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

static void _print_help(void) {
    /*TODO*/
    printf("WIP: helper text\n");
}

static int _edit_entry(char *spi, char *src, char *dst, char *mode, char *auth,
        char *auth_key, char *enc, char *enc_key, char *t_src, char *t_dst) {
    (void)spi; /*security policy index*/
    (void)src; /*source*/
    (void)dst; /*destination*/
    (void)mode; /*tunnel/transport*/
    (void)auth; /*authentication type*/
    (void)auth_key; /*authentication key*/
    (void)enc; /*encryption type*/
    (void)enc_key; /*encryption key*/
    (void)t_src; /*tunnel src*/
    (void)t_dst; /*tunnel dst*/
    if(1) {
        return 1;
    }
    return 0;
}

int ipsec_sad_frm(int argc, char **argv) {

    if(argc<2) {
        _print_help();
        return 0;
    }

    if(argc==11) {
        int result = _edit_entry(argv[1],argv[2],argv[3],argv[4],argv[5],
            argv[6],argv[7],argv[8],argv[9],argv[10]);
        if(result!=0) {
            printf("dbfrm: No changes could be made. ERR_NR:%i\n", result);
        } else {
            printf("dbfrm: spi:%s was changed successfully.\n", argv[1]);
        }
    }

    return 0;
}
