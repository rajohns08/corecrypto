/* Copyright (c) (2012,2014,2015,2016,2017,2018,2019) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#include "ccsrp_priv.h"
#include "ccdh_internal.h"

/******************************************************************************
 *  Server Side Routines
 *****************************************************************************/

int ccsrp_server_generate_public_key(ccsrp_ctx_t srp,
                                     struct ccrng_state *rng,
                                     const void *verifier,
                                     void *B_bytes)
{
    int status = CCSRP_ERROR_DEFAULT;
    cc_size n = ccsrp_ctx_n(srp);
    cc_unit k[n]; // vla

    ccn_zero_multi(n, ccsrp_ctx_v(srp), k, NULL);
    ccsrp_import_ccn(srp, ccsrp_ctx_v(srp), verifier);

    SRP_FLG(srp).authenticated = false;

    // Create b (ccsrp_ctx_private)
    cc_require(
        (status = ccdh_generate_private_key(ccsrp_ctx_gp(srp), ccsrp_ctx_private(srp), rng)) == 0,
        errOut);

    // Generate parameter k
    if ((SRP_FLG(srp).variant & CCSRP_OPTION_VARIANT_MASK) == CCSRP_OPTION_VARIANT_SRP6a) {
        ccsrp_generate_k(srp, k);
    }

    /* B = kv + g^b */

    ccsrp_generate_server_pubkey(srp, k);
    ccsrp_export_ccn(srp, ccsrp_ctx_public(srp), B_bytes);
errOut:
    ccn_zero_multi(n, k, NULL);
    return status;
}

int ccsrp_server_compute_session(ccsrp_ctx_t srp,
                                 const char *username,
                                 size_t salt_len,
                                 const void *salt,
                                 const void *A_bytes)
{
    cc_size n = ccsrp_ctx_n(srp);
    cc_unit A[n], u[n]; // vla
    cc_unit *S = ccsrp_ctx_S(srp);
    int rc;

    if (ccn_is_zero(n, ccsrp_ctx_public(srp)))
        return CCSRP_PUBLIC_KEY_MISSING;

    // Import A and sanity check on it
    ccsrp_import_ccn(srp, A, A_bytes);
    cczp_modn(ccsrp_ctx_zp(srp), u, n, A);
    if (ccn_is_zero(n, u))
        return CCSRP_SAFETY_CHECK;

    /* u = H(A,B) */
    ccn_zero(n, u);
    ccsrp_generate_u(srp, u, A, ccsrp_ctx_public(srp));

    /* S = (A *(v^u)) ^ b */
    ccsrp_generate_server_S(srp, S, u, A);

    /* K = f(S) where f is a function which depends on the variant */
    rc = ccsrp_generate_K_from_S(srp, S);

    ccsrp_generate_M(srp, username, salt_len, salt, A, ccsrp_ctx_public(srp));
    ccsrp_generate_H_AMK(srp, A);

    ccn_zero_multi(n, A, u, NULL);

    return rc;
}

int ccsrp_server_start_authentication(ccsrp_ctx_t srp,
                                      struct ccrng_state *rng,
                                      const char *username,
                                      size_t salt_len,
                                      const void *salt,
                                      const void *verifier,
                                      const void *A_bytes,
                                      void *B_bytes)
{
    int status = CCSRP_ERROR_DEFAULT;
    SRP_RNG(srp) = rng;

    // Generate server public key B
    cc_require((status = ccsrp_server_generate_public_key(srp, rng, verifier, B_bytes)) == 0,
               errOut);
    /* We're done with that part of the handshake the rest now computes the remaining
     * handshake values K, M, and HAMK
     */

    // Generate session key material
    cc_require((status = ccsrp_server_compute_session(srp, username, salt_len, salt, A_bytes)) == 0,
               errOut);

errOut:
    return status;
}

bool ccsrp_server_verify_session(ccsrp_ctx_t srp, const void *user_M, void *HAMK_bytes)
{
    SRP_FLG(srp).authenticated =
        (cc_cmp_safe(ccsrp_ctx_M_HAMK_size(srp), ccsrp_ctx_M(srp), user_M) == 0) &&
        SRP_FLG(srp).sessionkey;

    if (SRP_FLG(srp).authenticated) {
        cc_memcpy(HAMK_bytes, ccsrp_ctx_HAMK(srp), ccsrp_ctx_M_HAMK_size(srp));
    }
    return SRP_FLG(srp).authenticated;
}
