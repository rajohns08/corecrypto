/* Copyright (c) (2014,2015,2016,2017,2018,2019,2020) Apple Inc. All rights reserved.
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
#include <corecrypto/cc_macros.h>
#include "cc_debug.h"

int ccec_sign_composite_msg(ccec_full_ctx_t key,
                            const struct ccdigest_info *di,
                            size_t msg_len,
                            const uint8_t *msg,
                            uint8_t *sig_r,
                            uint8_t *sig_s,
                            struct ccrng_state *rng)
{
    uint8_t digest[di->output_size];
    ccdigest(di, msg_len, msg, digest);
    return ccec_sign_composite(key, di->output_size, digest, sig_r, sig_s, rng);
}

int ccec_sign_composite(ccec_full_ctx_t key,
                        size_t digest_len,
                        const uint8_t *digest,
                        uint8_t *sig_r,
                        uint8_t *sig_s,
                        struct ccrng_state *rng)
{
    int result = -1;
    cc_unit r[ccec_ctx_n(key)], s[ccec_ctx_n(key)];

    cc_assert(ccec_ctx_size(key) == ccec_signature_r_s_size(ccec_ctx_pub(key)));

    // Doing the signature
    result = ccec_sign_internal(key, digest_len, digest, r, s, rng);
    cc_require((result == 0), errOut);

    // Exporting in byte/Big endian format, padded to the size of the key.
    ccn_write_uint_padded_ct(ccec_ctx_n(key), r, ccec_signature_r_s_size(ccec_ctx_pub(key)), sig_r);
    ccn_write_uint_padded_ct(ccec_ctx_n(key), s, ccec_signature_r_s_size(ccec_ctx_pub(key)), sig_s);

errOut:
    return result;
}
