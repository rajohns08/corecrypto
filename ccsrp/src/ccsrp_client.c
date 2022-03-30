/* Copyright (c) (2012,2013,2014,2015,2016,2017,2018,2019) Apple Inc. All rights reserved.
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
 *  Client Side Routines
 *****************************************************************************/

int ccsrp_client_start_authentication(ccsrp_ctx_t srp, struct ccrng_state *rng, void *A_bytes)
{
    int status = CCSRP_ERROR_DEFAULT;
    cc_require(
        (status = ccdh_generate_private_key(ccsrp_ctx_gp(srp), ccsrp_ctx_private(srp), rng)) == 0,
        errOut);
    ccsrp_generate_client_pubkey(srp);
    ccsrp_export_ccn(srp, ccsrp_ctx_public(srp), A_bytes);
    status = 0;
errOut:
    return status;
}

int ccsrp_client_process_challenge(ccsrp_ctx_t srp,
                                   const char *username,
                                   size_t password_len,
                                   const void *password,
                                   size_t salt_len,
                                   const void *salt,
                                   const void *B_bytes,
                                   void *M_bytes)
{
    cc_size n = ccsrp_ctx_n(srp);
    cc_unit B[n];                   // vla
    cc_unit u[n], x[n], k[n], v[n]; // vla
    cc_unit *S = ccsrp_ctx_S(srp);
    cc_unit tmp[n]; // vla
    ccn_zero_multi(n, B, u, x, k, v, tmp, NULL);
    int rc;

    if (8 * ccsrp_ctx_di(srp)->output_size > ccn_bitlen(ccsrp_ctx_n(srp), ccsrp_ctx_prime(srp))) {
        // u.x is of size hash output length * 2
        // this implementation requires sizeof(u)=sizeof(x)=hash_size <= sizeof(prime)
        return CCSRP_NOT_SUPPORTED_CONFIGURATION;
    }

    ccsrp_import_ccn(srp, B, B_bytes);
    cczp_modn(ccsrp_ctx_zp(srp), tmp, n, B);
    if (ccn_is_zero(n, tmp))
        return CCSRP_SAFETY_CHECK; // SRP-6a safety check

    ccsrp_generate_u(srp, u, ccsrp_ctx_public(srp), B);

    cczp_modn(ccsrp_ctx_zp(srp), tmp, n, u);
    if (ccn_is_zero(n, tmp))
        return CCSRP_SAFETY_CHECK; // SRP-6a safety check

    ccsrp_generate_x(srp, x, username, salt_len, salt, password_len, password);
    ccsrp_generate_k(srp, k);
    /* Ignoring cczp_power error code; arguments guaranteed to be valid. */
    cczp_mm_power(ccsrp_ctx_zp(srp), v, ccsrp_ctx_gp_g(srp), x);

    /* Client Side S = (B - k*(g^x)) ^ (a + ux) */
    ccsrp_generate_client_S(srp, S, k, x, u, B);

    /* K = f(S) where f is a function which depends on the variant */
    rc = ccsrp_generate_K_from_S(srp, S);

    ccsrp_generate_M(srp, username, salt_len, salt, ccsrp_ctx_public(srp), B);
    ccsrp_generate_H_AMK(srp, ccsrp_ctx_public(srp));
    cc_memcpy(M_bytes, ccsrp_ctx_M(srp), ccsrp_ctx_M_HAMK_size(srp));
    ccn_zero_multi(n, B, u, x, k, v, tmp, NULL);

    return rc;
}

bool ccsrp_client_verify_session(ccsrp_ctx_t srp, const uint8_t *HAMK_bytes)
{
    return SRP_FLG(srp).authenticated =
               (cc_cmp_safe(ccsrp_ctx_M_HAMK_size(srp), ccsrp_ctx_HAMK(srp), HAMK_bytes) == 0) &&
               SRP_FLG(srp).sessionkey;
}
