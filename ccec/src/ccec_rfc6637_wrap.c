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

#include <corecrypto/ccec_priv.h>
#include "ccec_internal.h"
#include <corecrypto/ccaes.h>
#include <corecrypto/ccdigest.h>
#include <corecrypto/ccsha2.h>
#include <corecrypto/ccwrap.h>



size_t
ccec_rfc6637_wrap_pub_size(ccec_pub_ctx_t public_key,
                           unsigned long flags)
{
    size_t len;

    if (flags & CCEC_RFC6637_COMPACT_KEYS)
        len = ccec_compact_export_size(0, public_key);
    else
        len = ccec_export_pub_size(public_key);
    return len;
}

size_t
ccec_rfc6637_wrap_key_size(ccec_pub_ctx_t public_key,
                           unsigned long flags,
                           size_t key_len)
{
    size_t len;

    len=ccec_rfc6637_wrap_pub_size(public_key,flags);
    if (flags & CCEC_RFC6637_DEBUG_KEYS) {
        len += 2;
        len += key_len;
        len += ccec_cp_prime_size(ccec_ctx_cp(public_key));
    }
    return 2 + len + 1 + 48;
}

int
ccec_rfc6637_wrap_key(ccec_pub_ctx_t public_key,
                      void *wrapped_key,
                      unsigned long flags,
                      uint8_t symm_alg_id,
                      size_t key_len,
                      const void *key,
                      const struct ccec_rfc6637_curve *curve,
                      const struct ccec_rfc6637_wrap *wrap,
                      const uint8_t *fingerprint, /* 20 bytes */
                      struct ccrng_state *rng)
{
    int res;
    ccec_const_cp_t cp = ccec_ctx_cp(public_key);
    ccec_full_ctx_decl_cp(cp, ephemeral_key);

    /* Generate ephemeral key. We use the same generation method irrespective
        of compact format since the sign does not matter in wrapping operations */

    res = ccecdh_generate_key(cp, rng, ephemeral_key);
    if (res) {return res;}


    /*
     *  Perform wrapping
     */

    res = ccec_rfc6637_wrap_core(public_key,
                                 ephemeral_key,
                                 wrapped_key, flags,
                                 symm_alg_id, key_len,
                                 key,
                                 curve, wrap,
                                 fingerprint, rng);
    ccec_full_ctx_clear_cp(cp, ephemeral_key);
    return res;
}
