/* Copyright (c) (2015,2016,2017,2018,2019,2020) Apple Inc. All rights reserved.
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
#include <corecrypto/ccn.h>
#include <corecrypto/cczp.h>
#include <corecrypto/ccrng_drbg.h>
#include <corecrypto/ccrng_sequence.h>
#include "ccrng_sequence_non_repeat.h"
#include <corecrypto/ccsha2.h>
#include <corecrypto/cc_macros.h>
#include "cc_debug.h"

int ccec_generate_key_deterministic(ccec_const_cp_t cp,
                                    size_t entropy_len,         const uint8_t *entropy,
                                    struct ccrng_state *rng, // For masking and signature
                                    uint32_t flags,
                                    ccec_full_ctx_t key)
{
    int result=CCEC_GENERATE_KEY_DEFAULT_ERR;

    ccec_ctx_init(cp,key);

    //==========================================================================
    // Key generation
    //==========================================================================

    if ((CCEC_GENKEY_DETERMINISTIC_SECBKP&flags)==CCEC_GENKEY_DETERMINISTIC_SECBKP) {
        struct ccrng_sequence_state seq_rng;
        // Discard some bytes to be compatible with previous behavior of corecrypto
        // functions
        size_t discarded_len=ccn_sizeof(ccec_cp_prime_bitlen(cp)-1);
        entropy += discarded_len;
        entropy_len -= discarded_len;
        // Retry takes a non deterministic number of byte, to reduce the probability
        // of failure, we need extra bytes
        cc_require_action(entropy_len>=10*(ccn_sizeof(ccec_cp_order_bitlen(cp))),errOut,result=CCERR_OUT_OF_ENTROPY);
        cc_require((result = ccrng_sequence_non_repeat_init(&seq_rng,entropy_len, entropy))==0,errOut);
        cc_require((result = ccec_generate_scalar_fips_retry(cp,
                                                             (struct ccrng_state*)&seq_rng,
                                                             ccec_ctx_k(key)))==0,errOut);
    }
    else if ((CCEC_GENKEY_DETERMINISTIC_FIPS&flags)==CCEC_GENKEY_DETERMINISTIC_FIPS) {
        // Use entropy directly in the extrabits method, requires more bytes
        cc_require((result = ccec_generate_scalar_fips_extrabits(cp,
                                                                 entropy_len, entropy,
                                                                 ccec_ctx_k(key)))==0,errOut);
    }
    // Use entropy with the legacy method, to reconstruct previously generated
    // keys
    else if ((CCEC_GENKEY_DETERMINISTIC_LEGACY&flags)==CCEC_GENKEY_DETERMINISTIC_LEGACY) {
        cc_require((result = ccec_generate_scalar_legacy(cp,
                                                         entropy_len, entropy,
                                                         ccec_ctx_k(key)))==0,errOut);
    }
    // Use entropy as done in the PKA
    else if ((CCEC_GENKEY_DETERMINISTIC_PKA&flags)==CCEC_GENKEY_DETERMINISTIC_PKA) {
        cc_require((result = ccec_generate_scalar_pka(cp,
                                                         entropy_len, entropy,
                                                         ccec_ctx_k(key)))==0,errOut);
    } else {
        result=CCEC_GENERATE_NOT_SUPPORTED;
        goto errOut;
    }

    //==========================================================================
    // Calculate the public key for k
    //==========================================================================
    cc_require(((result=ccec_make_pub_from_priv(cp, rng,ccec_ctx_k(key),NULL,ccec_ctx_pub(key)))==0),errOut);

    //==========================================================================
    // Transform the key to support compact export/import format
    //==========================================================================
    if ((CCEC_GENKEY_DETERMINISTIC_COMPACT&flags)==CCEC_GENKEY_DETERMINISTIC_COMPACT) {
        cc_require(((result=ccec_compact_transform_key(key))==0),errOut);
    }

    //==========================================================================
    // Pairwise consistency check
    //==========================================================================
    result = ccec_pairwise_consistency_check(key, rng) ? 0 : CCEC_GENERATE_KEY_CONSISTENCY;
#if CCEC_DEBUG
    if (result) {
        uint8_t computed_x963_full_key[ccec_x963_export_size(1,ccec_ctx_pub(key))];
        ccec_x963_export(1, computed_x963_full_key, key);
        cc_print("exported_key: ",sizeof(computed_x963_full_key),computed_x963_full_key);
    }
#endif
errOut:
    return result;
}
