/* Copyright (c) (2014,2015,2016,2017,2018,2019) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include <corecrypto/ccn.h>
#include <corecrypto/ccec_priv.h>
#include <corecrypto/ccrng.h>
#include <corecrypto/ccrng_ecfips_test.h>

static int ecfips_test_generate(struct ccrng_state *rng, size_t entropy_size, void *entropy)
{
    struct ccrng_ecfips_test_state *thisrng = (struct ccrng_ecfips_test_state *)rng;
    cc_size n =ccn_nof_size(entropy_size);
    cc_unit t[n];
    uint8_t *e_bytes = (uint8_t *) t;
    if (thisrng->len==0) {
        return CCERR_CRYPTO_CONFIG;
    }
    for(size_t i=0; i<entropy_size; i++) {
        e_bytes[i] = thisrng->state[(thisrng->len - i - 1)%thisrng->len];
    }
    // Now doing some "tuning" because FIPS key gen add 1.
    ccn_sub1(n, t, t, 1);
    cc_memcpy((uint8_t *)entropy,t,entropy_size);
    return 0;
}

int ccrng_ecfips_test_init(struct ccrng_ecfips_test_state *rng, size_t len, uint8_t *array)
{
    rng->generate=ecfips_test_generate;
    rng->state=array;
    rng->len=len;
    return 0;
}
