/*
 * Copyright (C) 2019 Maximilian Malkus <malkus@cip.ifi.lmu.de>
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

#include <stdio.h>
#include "net/gnrc/ipv6/ipsec/keyengine.h"
#include "net/gnrc/ipv6/ipsec/ipsec.h"

#define ENABLE_DEBUG    (1)
#include "debug.h"

#define SPD_SIZE (10)
#define SAD_SIZE (10)

ipsec_sp_cache_t spd[SPD_SIZE];
ipsec_sa_t sad[SAD_SIZE];
int spd_size = -1;

static kernel_pid_t _pid = KERNEL_PID_UNDEF;

#if ENABLE_DEBUG
static char _stack[GNRC_IPSEC_STACK_SIZE + THREAD_EXTRA_STACKSIZE_PRINTF];
#else
static char _stack[GNRC_IPSEC_STACK_SIZE];
#endif

/* Main event loop for keyengine */
static void *_event_loop(void *args);

kernel_pid_t gnrc_ipsec_keyengine_init(void) {
    if (_pid > KERNEL_PID_UNDEF) {
        return _pid;
    }

    _pid = thread_create(_stack, sizeof(_stack), GNRC_IPSEC_PRIO,
                         THREAD_CREATE_STACKTEST, _event_loop, NULL, "keyengine");

    return _pid;
}

int _spd_init_mockup(void) {
    //IKEv2 sa not needed
    ipsec_sa_t sa1 = {0};
    sad[0] = sa1;
    ipsec_sp_cache_t sp1 = {.rule=1, .sa=&sad[0]};
    spd[0] = sp1;
    spd_size = 1;
    return 1;
}

const ipsec_sp_cache_t *get_spd_entry(const ipv6_addr_t *dst, const ipv6_addr_t *src, const uint8_t *nh, int dest_port, int src_port) {
    //TODO: RIOT sends some packets to itself. check that out.
    (void)dst;
    (void)src;
    (void)nh;
    (void)dest_port;
    (void)src_port;
   
    if(spd_size == -1) {
        DEBUG("ipsec_keyengine: SPD chache not initialized\n");
    } else {
        return &spd[0];
    }
    
    /* TODO: if no_entry return NULL */

    return &spd[0];
}


static void *_event_loop(void *args) {

    //TODO: create waiting for msg()
    //Howto wait for ipsec AND pfkey requests/responses?
    _spd_init_mockup();

    DEBUG("ipsec_keyengine: Thread initialized\n");

    while (1) {
        thread_sleep();
    }

    (void)args;

    return NULL;
}