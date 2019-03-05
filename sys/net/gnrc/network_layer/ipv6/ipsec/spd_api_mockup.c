/*
 * Copyright (C) 2019 Maximilian Malkus <malkus@cip.ifi.lmu.de>
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#include <stdio.h>
#include "net/gnrc/ipv6/ipsec/spd_api_mockup.h"

#define ENABLE_DEBUG    (0)
#include "debug.h"

#define SPD_SIZE (10)
#define SAD_SIZE (10)

sp_cache_t spd[SPD_SIZE];
sa_t sad[SAD_SIZE];
int spd_size = -1;

int spd_init(void) {
    //IKEv2 sa not needed
    sa_t sa1 = {0};
    sad[0] = sa1;
    sp_cache_t sp1 = {.status=1, .sa=&sad[0]};
    spd[0] = sp1;
    spd_size = 1;
    return 1;
}

sp_cache_t *get_spd_entry(const ipv6_addr_t *dst, const ipv6_addr_t *src, uint8_t nh, uint8_t dest_port, uint8_t src_port) {
    //TODO: RIOT sends some packets to itself. check that out.
    (void)dst;
    (void)src;
    (void)nh;
    (void)dest_port;
    (void)src_port;
    
    if(spd_size == -1) {        
        spd_init();
    } 
    
    return &spd[0];
}