/* Copyright (c) (2018,2019) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */
#include <corecrypto/ccspake.h>
#include "ccspake_priv.h"
#include "ccec_internal.h"

const uint8_t CCSPAKE_STATE_INIT = 0b00001;
const uint8_t CCSPAKE_STATE_KEX_GENERATE = 0b00011;
const uint8_t CCSPAKE_STATE_KEX_PROCESS = 0b00101;
const uint8_t CCSPAKE_STATE_KEX_BOTH = 0b00111;
const uint8_t CCSPAKE_STATE_MAC_GENERATE = 0b01111;
const uint8_t CCSPAKE_STATE_MAC_VERIFY = 0b10111;
const uint8_t CCSPAKE_STATE_MAC_BOTH = 0b11111;

size_t ccspake_sizeof_w(ccspake_const_cp_t scp)
{
    return ccec_cp_order_size(ccspake_cp_ec(scp)) + 8;
}

size_t ccspake_sizeof_point(ccspake_const_cp_t scp)
{
    return 1 + 2 * ccec_cp_prime_size(ccspake_cp_ec(scp));
}

size_t ccspake_sizeof_ctx(ccspake_const_cp_t scp)
{
    return sizeof(struct ccspake_ctx) + ccec_ccn_size(ccspake_cp_ec(scp)) * 12;
}

int ccspake_generate_L(ccspake_const_cp_t scp,
                       size_t w1_len,
                       const uint8_t *w1,
                       size_t L_len,
                       uint8_t *L,
                       struct ccrng_state *rng)
{
    ccec_const_cp_t cp = ccspake_cp_ec(scp);
    int rv;

    ccec_full_ctx_decl_cp(cp, full);
    ccec_ctx_init(cp, full);

    if (w1_len != ccspake_sizeof_w(scp)) {
        return CCERR_PARAMETER;
    }

    if (L_len != ccspake_sizeof_point(scp)) {
        return CCERR_PARAMETER;
    }

    if ((rv = ccec_generate_key_deterministic(cp, w1_len, w1, rng, CCEC_GENKEY_DETERMINISTIC_FIPS, full))) {
        return rv;
    }

    ccec_export_pub(ccec_ctx_pub(full), L);

    return CCERR_OK;
}

int ccspake_cmp_pub_key(ccec_pub_ctx_t pub, const cc_unit *X)
{
    ccec_const_cp_t cp = ccec_ctx_cp(pub);
    cc_size n = ccec_cp_n(cp);
    int rv = 0;

    rv |= ccn_cmp(n, X, ccec_ctx_x(pub));
    rv |= ccn_cmp(n, X + n, ccec_ctx_y(pub));

    return rv;
}

void ccspake_store_pub_key(const ccec_pub_ctx_t pub, cc_unit *dest)
{
    ccec_const_cp_t cp = ccec_ctx_cp(pub);
    cc_size n = ccec_cp_n(cp);

    ccn_set(n, dest, ccec_ctx_x(pub));
    ccn_set(n, dest + n, ccec_ctx_y(pub));
}

int ccspake_import_pub(ccec_pub_ctx_t pub, size_t x_len, const uint8_t *x)
{
    ccec_const_cp_t cp = ccec_ctx_cp(pub);
    int rv;

    if ((rv = ccec_import_pub(cp, x_len, x, pub))) {
        return rv;
    }

    if (!ccec_validate_pub(pub)) {
        return CCERR_PARAMETER;
    }

    return CCERR_OK;
}
