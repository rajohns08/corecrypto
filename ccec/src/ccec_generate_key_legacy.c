/* Copyright (c) (2010,2011,2012,2013,2014,2015,2016,2017,2018,2019) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include <corecrypto/ccec_priv.h>
#include "ccec_internal.h"
#include <corecrypto/ccrng.h>
#include <corecrypto/cczp.h>

#include <corecrypto/ccrng_drbg.h>
#include <corecrypto/ccsha2.h>

#include <corecrypto/cc_macros.h>
#include "cc_debug.h"

// Use exactly
// 2 * ccn_sizeof(ccec_cp_order_bitlen(cp)) bytes of random in total.
// Half of the random for the actual generation, the other for the consistency check
// The consistency check may require more random, therefore a DRBG is set to cover
// this case.
int
ccec_generate_key_legacy(ccec_const_cp_t cp,  struct ccrng_state *rng, ccec_full_ctx_t key)
{
    int result;
    if((result = ccec_generate_key_internal_legacy(cp,  rng, key))) return result;
    {
        // Create an rng using a drbg.
        // Signature may use a non deterministic amount of random
        // while input rng may be limited (this is the case for PBKDF2).
        const char drbg_string[] = "ccec_generate_key_legacy ccec_pairwise_consistency_check";
        // Agnostic of DRBG
        struct ccrng_drbg_state rng_drbg;
        struct ccdrbg_info info;
        uint8_t drbg_init_salt[ccn_sizeof(ccec_cp_order_bitlen(cp))];
        cc_require((result = ccrng_generate(rng, sizeof(drbg_init_salt), drbg_init_salt))==0,errOut);

        // Set DRBG - NIST HMAC
        struct ccdrbg_nisthmac_custom custom = {
            .di = ccsha256_di(),
            .strictFIPS = 0,
        };
        ccdrbg_factory_nisthmac(&info, &custom);

        // Init the rng drbg
        uint8_t state[info.size];
        struct ccdrbg_state *drbg_state=(struct ccdrbg_state *)state;
        result = ccdrbg_init(&info, drbg_state,
                             sizeof(drbg_init_salt), drbg_init_salt,
                             sizeof(drbg_string), drbg_string,
                             0, NULL);
        cc_require(result==0,errOut);
        result = ccrng_drbg_init_withdrbg(&rng_drbg,&info,drbg_state);
        if(result == 0) {
            result = ccec_pairwise_consistency_check(key, (struct ccrng_state *)&rng_drbg) ? 0 : CCEC_GENERATE_KEY_CONSISTENCY;
        }
        // Close the rng drbg
        ccdrbg_done(&info, drbg_state);
    }
errOut:
    return result;
}
