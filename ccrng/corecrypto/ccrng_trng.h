/* Copyright (c) (2017,2019) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef __CCRNG_TRNG_H__
#define __CCRNG_TRNG_H__

#include <corecrypto/ccrng.h>

struct ccrng_trng_state {
    CCRNG_STATE_COMMON
    DriverHandle rng_driver;
    unsigned channel;
    uint32_t attempts;
};

/*
 * Init a ccrng state struct that utilizes the SEP TRNG to generate entropy.
 */
int ccrng_trng_init(struct ccrng_trng_state *rng, unsigned channel, uint32_t attempts);

#endif
