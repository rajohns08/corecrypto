/* Copyright (c) (2014-2020) Apple Inc. All rights reserved.
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
#include <corecrypto/cc_macros.h>
#include "cczp_internal.h"
#include "ccn_internal.h"
#include "ccec_internal.h"

int ccec_sign_internal(ccec_full_ctx_t key, size_t digest_len, const uint8_t *digest,
              cc_unit *r, cc_unit *s, struct ccrng_state *rng) {
    ccec_const_cp_t cp = ccec_ctx_cp(key) ;
    cczp_const_t zq = ccec_cp_zq(cp);
    int result;
    cc_size ne=ccn_nof_size(digest_len);
    cc_size n=ccec_cp_n(cp);
    cc_unit e[n];
    size_t qbitlen=ccec_cp_order_bitlen(cp);
    ccec_full_ctx_decl_cp(cp, tmpkey);

    cc_assert(cczp_n(zq)==ccec_cp_n(cp));

    // Process input hash to represent it has an number
    if (digest_len*8>qbitlen) {
        /* Case where the hash size is bigger than the curve size
         eg. SHA384 with P-256 */
        cc_unit e_big[ne];
        if ((result = ccn_read_uint(ne, e_big, digest_len, digest)) < 0) goto errOut;

        /* Keep the leftmost bits of the hash */
        ccn_shift_right_multi(ne,e_big,e_big,(digest_len*8-qbitlen));
        ccn_set(n,e,e_big);
    }
    else if ((result = ccn_read_uint(n, e, digest_len, digest)) < 0) {
        goto errOut;
    }
    cczp_modn(zq,e,n,e);

    // ECDSA signing core
    for (;;) {
        // Sanity check for private key
        cc_require((result = ccec_validate_scalar(cp,ccec_ctx_k(key))) ==0,errOut);

        // Ephemeral k (guarantees that the scalar is valid)
        cc_require((result = ccec_generate_key_internal_fips(cp, rng, tmpkey)) ==0,errOut);

        /* Compute r = pubx mod q */
        if (ccn_cmp(n, ccec_ctx_x(tmpkey), cczp_prime(zq)) >= 0) {
            ccn_sub(n, r, ccec_ctx_x(tmpkey), cczp_prime(zq));
        } else {
            ccn_set(n, r, ccec_ctx_x(tmpkey));
        }

        /* Compute the rest of the signature */
        if (!ccn_is_zero(n, r)) {
#if CCEC_MASKING
            cc_unit *mask=ccec_ctx_y(tmpkey);
            cc_require((result = ccn_random_bits(qbitlen-1, mask, rng)) ==0,errOut);
            ccn_set_bit(mask, qbitlen-2, 1);
            // Mask independently each intermediary variable
            cczp_mul(zq,ccec_ctx_k(tmpkey),ccec_ctx_k(tmpkey),mask); // (k*m)
            cczp_mul(zq,e,e,mask);                                   // (e*m)
            cczp_mul(zq,mask,ccec_ctx_k(key),mask);                  // (x*m)

            // instead of computing (e + xr) / k mod q
            // the masked variant computes ((e.m) + (x.m).r) / (k.m).

            /* find s = (e + xr) / k mod q */
            cczp_mul(zq, s, mask, r);                                    // s = xr mod q
#else
            cczp_mul(zq, s, ccec_ctx_k(key), r);                         // s = xr mod q
#endif
            cczp_add(zq, s, e, s);                                       // s = e + xr mod q
            cc_require((result = cczp_inv(zq, e, ccec_ctx_k(tmpkey)))==0,errOut); // k = k^-1 mod q
            cczp_mul(zq, s, e, s);                      // s = (e + xr)k^-1 mod q
            if (!ccn_is_zero(n, s)) {
                break;
            }
        }
    }
errOut:
    ccn_clear(n,e);
    ccec_full_ctx_clear_cp(cp, tmpkey);
    return result;
}
